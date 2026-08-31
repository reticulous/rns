/**
 * netgraph — routing truth locally, remote management for the rest.
 *
 * The graph has two sources and no others.
 *
 * WHAT THIS NODE KNOWS, FOR FREE. Its own path table and its own interface
 * state: every destination we hold a route to, the neighbour we route it
 * through, and every peer our radios hear whether or not routing uses it. No
 * protocol, no traffic, and the drawing changes the moment our state does.
 *
 * WHAT OTHER NODES KNOW, WHEN ASKED. Reticulum's own remote-management service
 * — `/path` and `/status` on `rnstransport.remote.management` — visited node by
 * node, once per crawl, started by a human. It works against stock Reticulum
 * installations, which is the whole point: it reaches the nodes whose software
 * we do not write, and it is the same facility we serve to them.
 *
 *   crawl (on demand, one Link per node, never automatic):
 *     us → node   LINK → IDENTIFY → /path ["table", nil, 1] → /status [true]
 *
 *   sync (on demand, over one Reticulum Channel between two nodes):
 *     I → R   DIGEST        every (origin, seq) I hold
 *     R → I   RECORD_PART*  records I lack or hold older
 *     R → I   WANT          origins R lacks or holds older
 *     I → R   RECORD_PART*  those records
 *     both    DONE          then the initiator closes the channel
 *
 * RECORDS ARE NEVER ANNOUNCED. A RECORD is one node's self-report about itself
 * and nothing else: its name, the destinations it announces, its interfaces,
 * its links. No node ever writes into another's, records replace wholesale
 * rather than merge, and newer seq wins — that is the entire conflict story.
 * The builder, the store, the resolver and the Channel server below all still
 * work, but a record flooded per node per announce beat does not scale on LoRa,
 * so the push path and the sync beat that depends on it are commented out at
 * their call sites. Records are one evidence class among four, not the
 * drawing's foundation. See plans/netgraph.md.
 *
 * Records are UNSIGNED. They travel over encrypted Links between community
 * members and carry no signature of their own. A member can fabricate, and a
 * signature never prevented that. The consequence is the rule: a record must
 * never be handed to a party that does not trust the whole community.
 *
 * CONFIGURATION GOES IN A RECORD, MEASUREMENTS DO NOT. Frequency, spreading
 * factor, interface names, whether a link exists: yes. RSSI, SNR, negotiated
 * budgets, counters: no — they change constantly and would keep every digest in
 * the community permanently mismatched. The test for a field is whether a
 * change to it deserves waking the whole mesh.
 *
 * Threading. Every store mutation happens on the netgraph task, which is
 * therefore free to read without the lock; the CLI reads from the cli task and
 * takes it. Same single-writer discipline as rnsd's directory.
 *
 * The pipe-text form is the specification and the packed form is a tokenization
 * of it — same lines, same fields, same order. See rns/README.md.
 */
#include "netgraph.h"
#include "rnsd.h"
#include "rnsd_peers.h"      /* rnsdIfaceWalk — the registered interface table */
#include "ports.h"
#include "cli.h"
#include "its.h"
#include "spangap.h"
#include "mem.h"

#include "esp_random.h"      /* sync-beat jitter */
#include "mbedtls/pkcs5.h"   /* the community key, derived from a passphrase */

/* MsgPack.h reaches µR's Log.h through Bytes.h, and that header declares free
 * functions named `info`, `warn` and so on inside namespace RNS — which
 * spangap's log.h has already defined as macros, corrupting the declarations on
 * parse. Suppress around the include and restore, exactly as rnsd.cpp does.
 * µR's Log.h also does `#define msg (msg)`, an Arduino-side format-mangling
 * wart, so that goes too or it poisons later parameter names. */
#pragma push_macro("info")
#pragma push_macro("warn")
#pragma push_macro("err")
#pragma push_macro("dbg")
#pragma push_macro("verb")
#undef info
#undef warn
#undef err
#undef dbg
#undef verb

#include "MsgPack.h"         /* the remote-management request and its answers */

#undef msg
#pragma pop_macro("verb")
#pragma pop_macro("dbg")
#pragma pop_macro("err")
#pragma pop_macro("warn")
#pragma pop_macro("info")

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cJSON.h>           /* the settings collection's add form submits JSON */

#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

static const char* TAG = "netgraph";

#define NG_ASPECT           "netgraph.discovery"
#define NG_TAGNAME          "ng"          /* rnsdChannelOpen tag prefix */

/* ── record format ── */
#define NG_MAGIC            0xF5          /* an invalid UTF-8 lead byte, so nothing
                                             sniffing app_data for a display name
                                             mistakes a record for text */
#define NG_HDR              22            /* magic 1 | origin 16 | seq 4 | flags 1 */
#define NG_FLAG_ABRIDGED    0x01
#define NG_TAG_N            0x01
#define NG_TAG_DT           0x02
#define NG_TAG_IF           0x03
#define NG_TAG_LN           0x04
/* An UPLINK: a standing connection to something outside the community. It gets
 * a line of its own rather than a cell on an `ln` line, because an `ln` cell
 * means "a community peer, joinable by its destination prefix" and an uplink is
 * the opposite of that — no prefix, no record, ever. Keeping the two apart is
 * what stops a resolver trying to join the outside world to a member. */
#define NG_TAG_UP           0x05
#define NG_TAG_DETAIL_MIN   0x20          /* 0x06-0x1f reserved for core lines */

/* ── sizes ── */
#define NG_MAX_RECORD       768           /* one packed record, hard cap */
#define NG_ANNOUNCE_MAX     400           /* what an abridged record may cost on the air */
#define NG_MAX_RECORDS      48            /* origins the store can hold */
#define NG_MAX_IFACES       8
#define NG_MAX_UNITS        32            /* link units tracked per interface — rnsd's
                                             own peer table is 32, so this is its
                                             ceiling rather than a second one */
#define NG_MAX_CELLS        NG_MAX_UNITS  /* cells per `ln` line in the FULL record.
                                             Equal by construction: the full record
                                             must never be abridged by a cap of ours,
                                             only by what rnsd could see */
#define NG_MAX_DT           8             /* own destinations named in `dt` */
#define NG_MAX_UPLINKS      4             /* ways out of the community, per node */
/* Sized against ~30 nodes of mean degree 4, which is what the traffic budget in
 * plans/netgraph.md contemplates. Both directions of an adjacency stay separate
 * rows, so 30 nodes at degree 4 is 240 directed edges before the crawl adds a
 * single one — the old 192 overflowed on the local half alone. All three tables
 * live in PSRAM. */
#define NG_MAX_VERTS        96
#define NG_MAX_LINKS        384
#define NG_MAX_PREFIXES     (NG_MAX_RECORDS * NG_MAX_DT)

/* ── channel ── */
#define NG_MT_DIGEST        0x4e00
#define NG_MT_WANT          0x4e01
#define NG_MT_PART          0x4e02
#define NG_MT_DONE          0x4e03
#define NG_CHAN_MDU         400           /* our send cap; the channel's own is ~428 */
#define NG_DIGEST_PER_MSG   19            /* 4 + 19*20 = 384 B */
#define NG_WANT_PER_MSG     20            /* 1 + 20*16 = 321 B */
#define NG_PART_PAYLOAD     (NG_CHAN_MDU - 22)
#define NG_INBOUND_MAX      2
#define NG_SESS_OUT         NG_INBOUND_MAX
#define NG_SESS_MAX         (NG_INBOUND_MAX + 1)
/* IDLE, not total: a backfill is tens of records and on a slow radio it may
 * legitimately take minutes. What must not happen is a session sitting wedged,
 * and silence is what says so. */
#define NG_SYNC_IDLE_MS     60000

/* ── cadences ── */
#define NG_SCAN_MS          30000         /* how often the composition is re-read.
                                             rnsd has no "the neighbourhood
                                             changed" hook, so this is a read of
                                             tables it already keeps — kept well
                                             under the rebuild floor, so it never
                                             delays a rebuild that is due */
#define NG_FETCH_BACKOFF_MS 300000        /* per-origin, after a targeted fetch */

/* ═══════════════════════════ small helpers ═══════════════════════════ */

namespace {

uint32_t nowUnix()  { return (uint32_t)std::time(nullptr); }
uint32_t nowMs()    { return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }

/** Is this device timestamp from after the clock was set?
 *
 * THE RULE FOR EVERY AGE TEST BELOW: both ends must be in the same era, and an
 * age says nothing when they are not. A node boots, hears its neighbours within
 * seconds, and stamps those observations with a clock counting from the epoch;
 * NTP then lands and the clock steps by decades. Every one of those stamps is
 * now older than any horizon, so a horizon applied across the step throws away
 * exactly the links the node just learned — and does not recover them until
 * each peer announces again, which on LoRa is half an hour of a graph with no
 * lines on it. The same step across two NODES is worse: a synced node rejects
 * the records of an unsynced one outright, and the two never see each other. */
bool     tsSane(uint32_t t) { return t > 1600000000u; }
bool     clockSane() { return tsSane(nowUnix()); }

void hex(char* out, const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[d[i] >> 4]; out[2*i+1] = H[d[i] & 0xF]; }
    out[2*n] = '\0';
}

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Exactly `n` bytes of hex, or nothing. A short hash is an operator typo and
 *  deriving an address from half of one would produce a plausible destination
 *  nobody is listening on — a failure that looks like a network problem. */
bool unhex(const char* s, uint8_t* out, size_t n) {
    if (!s) return false;
    for (size_t i = 0; i < n; i++) {
        int hi = hexNibble(s[2*i]), lo = hexNibble(s[2*i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return s[2*n] == '\0';
}

uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/** The interface CLASS behind a registered name: `lora/0` → `lora`,
 *  `tcp_in/1.2.3.4#0` → `tcp`. The same class word the status-line pills key
 *  on, and what the browser reads back from the published `cls` rows, so one
 *  vocabulary names a medium everywhere. */
void ifaceClass(const char* name, char* out, size_t outsz) {
    size_t i = 0;
    while (name[i] && name[i] != '/' && name[i] != '_' && i + 1 < outsz) { out[i] = name[i]; i++; }
    out[i] = '\0';
}

/** Freshness bucket, relative to the record's own timestamp: 0 ≤ 5 min,
 *  1 ≤ 1 h, 2 ≤ 6 h, 3 older. Coarse on purpose — a bucket that moved with the
 *  clock would rebuild the record for nothing. */
uint8_t freshBucket(uint32_t ts, uint32_t heard) {
    /* Undatable — one end of the comparison predates the clock being set. The
     * peer table only holds a row while it is current, so the row's existence
     * is itself the evidence, and "now" is the honest answer rather than
     * "ancient", which is what subtracting across the step would say. */
    if (!tsSane(heard) || !tsSane(ts)) return 0;
    if (heard >= ts) return 0;
    uint32_t age = ts - heard;
    if (age <= 300)   return 0;
    if (age <= 3600)  return 1;
    if (age <= 21600) return 2;
    return 3;
}

/* `|`, newline and control characters become spaces at build time. That
 * substitution is the entire escaping story, which is what lets every consumer
 * split on `|` unconditionally. */
void sanitizeField(const char* in, char* out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < outsz; i++) {
        uint8_t b = (uint8_t)in[i];
        out[o++] = (b == '|' || b < 0x20 || b == 0x7F) ? ' ' : in[i];
    }
    out[o] = '\0';
}

/** What this node calls itself.
 *
 *  THE HOSTNAME FIRST: a vertex on this graph is a DEVICE, and the hostname is
 *  what its operator called that device. An LXMF display name is what a person
 *  calls themselves, is the same on every device they run, and belongs to a
 *  destination rather than to a node — a decent last resort for a node with no
 *  hostname set, a poor label wherever there is one.
 *
 *  One answer, three users: the record's `n` line, this node's own vertex, and
 *  the name its management announce carries to everyone else. */
void ngOwnName(char* out, size_t outsz) {
    char raw[RNSD_PEER_NAME_MAX];
    storageGetStr("s.net.hostname", raw, sizeof raw, "");
    if (!raw[0]) storageGetStr("s.lxmf.id.0.display_name", raw, sizeof raw, "");
    sanitizeField(raw, out, outsz);
}

/* ═══════════════════════════ settings ═══════════════════════════ */

int cfgEnable()        { return storageGetInt("s.netgraph.enable", 1); }
int cfgHeardH()        { return storageGetInt("s.netgraph.heard_h", 3); }
int cfgRadius()        { return storageGetInt("s.netgraph.radius", 2); }
int cfgCrawlTimeoutS() { return storageGetInt("s.netgraph.crawl_timeout_s", 20); }
int cfgServe()         { return storageGetInt("s.netgraph.serve", 1); }
int cfgRebuildFloorS() { return storageGetInt("s.netgraph.rebuild_floor_s", 600); }
int cfgAnnounceCells() { return storageGetInt("s.netgraph.announce_cells", 8); }
int cfgLinkHorizonH()  { return storageGetInt("s.netgraph.link_horizon_h", 6); }
int cfgHorizonH()      { return storageGetInt("s.netgraph.horizon_h", 24); }
int cfgSyncMin()       { return storageGetInt("s.netgraph.sync_min", 30); }
int cfgStoreKb()       { return storageGetInt("s.netgraph.store_kb", 24); }

/* ═══════════════════════════ packed-record reading ═══════════════════════════
 *
 * header: magic:u8 | origin:16 | seq:u32 LE | flags:u8
 * lines:  repeated  len:u16 LE | tag:u8 | body   until the end of the payload,
 *         where `len` counts the tag byte AND the body — one number skips a
 *         line whether or not its tag is understood, which is what makes an
 *         unknown line carriable rather than fatal.
 */

typedef bool (*ng_line_cb)(uint8_t tag, const uint8_t* body, size_t n, void* ctx);

void ngForEachLine(const uint8_t* rec, size_t n, ng_line_cb cb, void* ctx) {
    size_t o = NG_HDR;
    while (o + 2 <= n) {
        size_t len = rd16(rec + o);
        o += 2;
        if (len == 0 || o + len > n) return;
        if (!cb(rec[o], rec + o + 1, len - 1, ctx)) return;
        o += len;
    }
}

bool ngLineCountCb(uint8_t, const uint8_t*, size_t, void* ctx) { (*(int*)ctx)++; return true; }

/** Shape check. Rejects anything whose lines do not tile the payload exactly —
 *  a record is applied whole or not at all, so a half-parsable one is not a
 *  partial update, it is a reject. */
bool ngValidate(const uint8_t* rec, size_t n) {
    if (!rec || n < NG_HDR || n > NG_MAX_RECORD) return false;
    if (rec[0] != NG_MAGIC) return false;
    size_t o = NG_HDR;
    while (o < n) {
        if (o + 2 > n) return false;
        size_t len = rd16(rec + o);
        o += 2;
        if (len == 0 || o + len > n) return false;
        o += len;
    }
    return o == n;
}

const uint8_t* ngOrigin(const uint8_t* rec)   { return rec + 1; }
uint32_t       ngSeq(const uint8_t* rec)      { return rd32(rec + 17); }
bool           ngAbridged(const uint8_t* rec) { return (rec[21] & NG_FLAG_ABRIDGED) != 0; }

/* ═══════════════════════════ packed-record writing ═══════════════════════════ */

struct Buf {
    uint8_t* p; size_t cap; size_t n; bool ovf;
    void u8(uint8_t b)  { if (n < cap) p[n++] = b; else ovf = true; }
    void u16(uint16_t v){ u8((uint8_t)v); u8((uint8_t)(v >> 8)); }
    void u32(uint32_t v){ u16((uint16_t)v); u16((uint16_t)(v >> 16)); }
    void raw(const uint8_t* d, size_t l) { for (size_t i = 0; i < l; i++) u8(d[i]); }
    void str(const char* s) {
        size_t l = std::strlen(s);
        if (l > 255) l = 255;
        u8((uint8_t)l);
        raw((const uint8_t*)s, l);
    }
    size_t lineBegin(uint8_t tag) { size_t at = n; u16(0); u8(tag); return at; }
    void   lineEnd(size_t at) {
        if (ovf || at + 2 > cap) return;
        uint16_t len = (uint16_t)(n - at - 2);
        p[at] = (uint8_t)len; p[at+1] = (uint8_t)(len >> 8);
    }
};

/* ═══════════════════════════ pipe-text rendering ═══════════════════════════ */

struct TextCtx { void (*emit)(const char*, void*); void* ctx; };

bool ngTextLine(uint8_t tag, const uint8_t* b, size_t n, void* vctx) {
    TextCtx* tc = (TextCtx*)vctx;
    char line[320];
    switch (tag) {
        case NG_TAG_N: {
            if (n < 2) break;
            uint8_t flags = b[0];
            size_t  nlen  = b[1];
            if (2 + nlen > n) break;
            char name[RNSD_PEER_NAME_MAX * 2];
            size_t c = nlen < sizeof(name) - 1 ? nlen : sizeof(name) - 1;
            std::memcpy(name, b + 2, c); name[c] = '\0';
            std::snprintf(line, sizeof line, "n|%s|%s", name, (flags & 1) ? "t" : "");
            tc->emit(line, tc->ctx);
            break;
        }
        case NG_TAG_DT: {
            if (n < 1) break;
            int cnt = b[0];
            if (1 + (size_t)cnt * 4 > n) break;
            int o = std::snprintf(line, sizeof line, "dt|%d|", cnt);
            for (int i = 0; i < cnt && o < (int)sizeof line - 10; i++)
                o += std::snprintf(line + o, sizeof line - o, "%s%02x%02x%02x%02x",
                                   i ? " " : "", b[1+4*i], b[2+4*i], b[3+4*i], b[4+4*i]);
            tc->emit(line, tc->ctx);
            break;
        }
        case NG_TAG_IF: {
            size_t c = n < sizeof(line) - 5 ? n : sizeof(line) - 5;
            std::snprintf(line, sizeof line, "if|%.*s", (int)c, (const char*)b);
            tc->emit(line, tc->ctx);
            break;
        }
        case NG_TAG_UP: {
            size_t c = n < sizeof(line) - 5 ? n : sizeof(line) - 5;
            std::snprintf(line, sizeof line, "up|%.*s", (int)c, (const char*)b);
            tc->emit(line, tc->ctx);
            break;
        }
        case NG_TAG_LN: {
            if (n < 1) break;
            size_t ilen = b[0];
            if (1 + ilen + 3 > n) break;
            char iface[RNSD_PEER_IFACE_MAX * 2];
            size_t c = ilen < sizeof(iface) - 1 ? ilen : sizeof(iface) - 1;
            std::memcpy(iface, b + 1, c); iface[c] = '\0';
            const uint8_t* q = b + 1 + ilen;
            uint16_t count = rd16(q);
            uint8_t  cells = q[2];
            q += 3;
            if ((size_t)(q - b) + (size_t)cells * 5 > n) break;
            int o = std::snprintf(line, sizeof line, "ln|%s|%u|", iface, (unsigned)count);
            for (int i = 0; i < cells && o < (int)sizeof line - 16; i++) {
                const uint8_t* cell = q + 5 * i;
                o += std::snprintf(line + o, sizeof line - o, "%s%02x%02x%02x%02x.%u%s",
                                   i ? " " : "", cell[0], cell[1], cell[2], cell[3],
                                   (unsigned)(cell[4] & 0x03), (cell[4] & 0x04) ? ".t" : "");
            }
            tc->emit(line, tc->ctx);
            break;
        }
        default: {
            if (tag >= NG_TAG_DETAIL_MIN) {
                size_t c = n < sizeof(line) - 1 ? n : sizeof(line) - 1;
                std::memcpy(line, b, c); line[c] = '\0';
                tc->emit(line, tc->ctx);
            } else {
                /* A reserved core tag this firmware does not speak. Shown as
                 * hex rather than guessed at, and carried untouched in the
                 * bytes — an unknown line is skipped, never dropped. */
                int o = std::snprintf(line, sizeof line, "?%02x|", tag);
                for (size_t i = 0; i < n && o < (int)sizeof line - 3; i++)
                    o += std::snprintf(line + o, sizeof line - o, "%02x", b[i]);
                tc->emit(line, tc->ctx);
            }
        }
    }
    return true;
}

void ngToText(const uint8_t* rec, size_t n, void (*emit)(const char*, void*), void* ctx) {
    TextCtx tc{ emit, ctx };
    ngForEachLine(rec, n, ngTextLine, &tc);
}

/* ═══════════════════════════ the record store ═══════════════════════════ */

struct Rec {
    bool     used;
    bool     mine;
    bool     abridged;
    uint8_t  origin[RNSD_IDENT_HASH_LEN];
    uint32_t seq;
    uint32_t received_at;
    uint8_t  dest[RNSD_DEST_HASH_LEN];   /* its netgraph.discovery destination */
    bool     have_dest;
    uint8_t  hops;
    uint16_t len;
    uint8_t* bytes;
};

Rec         s_recs[NG_MAX_RECORDS];
std::mutex  s_lock;
size_t      s_bytes      = 0;
bool        s_storeDirty = false;    /* something changed; re-resolve */
uint8_t     s_self[RNSD_IDENT_HASH_LEN];
bool        s_haveSelf   = false;

/** How far away a node is, given two pieces of evidence. The SHORTEST wins.
 *
 *  Keeping the latest instead is how `sync idle` happens on a healthy mesh: a
 *  relayed copy of an announce we also heard directly overwrites the 1 with a
 *  2, and a partner is by definition a neighbour, so the node is silently
 *  disqualified and the Channel exchange never runs at all. A hop count that
 *  stays optimistic after a peer moves away costs one sync attempt that
 *  succeeds anyway — Reticulum still routes it — which is the cheaper mistake
 *  by a wide margin. */
uint8_t hopsBest(uint8_t a, uint8_t b) {
    if (!a) return b;
    if (!b) return a;
    return a < b ? a : b;
}

int recFind(const uint8_t* origin) {
    for (int i = 0; i < NG_MAX_RECORDS; i++)
        if (s_recs[i].used &&
            std::memcmp(s_recs[i].origin, origin, RNSD_IDENT_HASH_LEN) == 0) return i;
    return -1;
}

void recFree(int i) {
    if (!s_recs[i].used) return;
    s_bytes -= s_recs[i].len;
    gp_free(s_recs[i].bytes);
    s_recs[i] = Rec{};
}

/** Stalest received_at first; our own record is never a candidate. Returns the
 *  slot freed, or -1 when there is nothing left to give. */
int recEvictOne() {
    int worst = -1;
    for (int i = 0; i < NG_MAX_RECORDS; i++) {
        if (!s_recs[i].used || s_recs[i].mine) continue;
        if (worst < 0 || s_recs[i].received_at < s_recs[worst].received_at) worst = i;
    }
    if (worst >= 0) recFree(worst);
    return worst;
}

/** Replace everything held for an origin in one step. A record is an atomic
 *  whole: there is no partial update, ever, which is what makes unsigned
 *  re-serialization by a relay safe and lets a record's internal references
 *  stay record-scoped. */
bool recStore(const uint8_t* rec, size_t n, const uint8_t* dest, uint8_t hops, bool mine) {
    const uint8_t* origin = ngOrigin(rec);
    uint32_t seq = ngSeq(rec);
    bool abridged = ngAbridged(rec);

    int i = recFind(origin);
    if (i >= 0) {
        /* Newer seq wins. An equal seq wins only when it upgrades an abridged
         * copy to the full record the announce could not carry. */
        if (seq < s_recs[i].seq) return false;
        if (seq == s_recs[i].seq && !(s_recs[i].abridged && !abridged)) {
            /* Nothing new to hold, but where it reached us from is still worth
             * having: that destination is how a targeted fetch finds it. */
            std::lock_guard<std::mutex> g(s_lock);
            if (dest) { std::memcpy(s_recs[i].dest, dest, RNSD_DEST_HASH_LEN); s_recs[i].have_dest = true; }
            s_recs[i].hops = hopsBest(s_recs[i].hops, hops);
            return false;
        }
    }

    uint8_t* copy = (uint8_t*)gp_alloc(n);
    if (!copy) { warn("store: no memory for a %zu B record", n); return false; }
    std::memcpy(copy, rec, n);

    std::lock_guard<std::mutex> g(s_lock);
    if (i < 0) {
        for (int k = 0; k < NG_MAX_RECORDS && i < 0; k++) if (!s_recs[k].used) i = k;
        if (i < 0) i = recEvictOne();
        if (i < 0) { gp_free(copy); return false; }
    } else {
        s_bytes -= s_recs[i].len;
        gp_free(s_recs[i].bytes);
    }

    Rec& r = s_recs[i];
    uint8_t keep_dest[RNSD_DEST_HASH_LEN];
    bool    keep_have = r.have_dest;
    if (keep_have) std::memcpy(keep_dest, r.dest, RNSD_DEST_HASH_LEN);
    uint8_t keep_hops = r.hops;

    r = Rec{};
    r.used = true;
    r.mine = mine;
    r.abridged = abridged;
    std::memcpy(r.origin, origin, RNSD_IDENT_HASH_LEN);
    r.seq = seq;
    r.received_at = nowUnix();
    r.bytes = copy;
    r.len = (uint16_t)n;
    if (dest)      { std::memcpy(r.dest, dest, RNSD_DEST_HASH_LEN); r.have_dest = true; }
    else if (keep_have) { std::memcpy(r.dest, keep_dest, RNSD_DEST_HASH_LEN); r.have_dest = true; }
    r.hops = hopsBest(keep_hops, hops);
    s_bytes += n;

    /* The byte cap is the real bound; the slot count is only its ceiling. */
    size_t cap = (size_t)cfgStoreKb() * 1024;
    while (s_bytes > cap && recEvictOne() >= 0) {}

    s_storeDirty = true;
    return true;
}

/** Ingest one record from the wire. Everything a hostile or broken sender can
 *  do is rejected here or nowhere. */
bool ngIngest(const uint8_t* rec, size_t n, const uint8_t* dest, uint8_t hops) {
    if (!ngValidate(rec, n)) return false;
    if (s_haveSelf && std::memcmp(ngOrigin(rec), s_self, RNSD_IDENT_HASH_LEN) == 0)
        return false;                      /* our own record comes from the builder */
    /* The seq is the SENDER's clock. Only date it when both clocks are set —
     * otherwise a node that has NTP silently refuses every record from one that
     * does not, and neither ever appears on the other's graph. */
    if (clockSane() && tsSane(ngSeq(rec))) {
        uint32_t horizon = (uint32_t)cfgHorizonH() * 3600u;
        if (ngSeq(rec) + horizon < nowUnix()) return false;  /* past the horizon: never
                                                                stored, never in a digest */
    }
    return recStore(rec, n, dest, hops, /*mine=*/false);
}

/** Drop everything past the horizon. Runs on the same slow beat as sync. */
int ngExpire() {
    if (!clockSane()) return 0;
    uint32_t horizon = (uint32_t)cfgHorizonH() * 3600u;
    uint32_t now = nowUnix();
    int dropped = 0;
    std::lock_guard<std::mutex> g(s_lock);
    for (int i = 0; i < NG_MAX_RECORDS; i++) {
        if (!s_recs[i].used || s_recs[i].mine) continue;
        if (!tsSane(s_recs[i].seq)) continue;      /* undatable; the byte cap bounds it */
        if (s_recs[i].seq + horizon < now) { recFree(i); dropped++; }
    }
    if (dropped) s_storeDirty = true;
    return dropped;
}

/* ═══════════════════════════ the record builder ═══════════════════════════ */

/* One thing at the far end of one interface. An rnsd node is one; so is an
 * unattributed peer on a shared radio, because on that medium a destination
 * heard out of the air is all a node is known to be. */
struct Unit {
    int      node;          /* rnsd node slot, -1 for an unattributed peer */
    uint8_t  prefix[4];
    bool     have_prefix;   /* it has announced — only then can it be a cell */
    uint32_t prefix_heard;  /* when the destination in `prefix` was last heard */
    uint32_t heard;         /* when anything at all was heard through it */
    bool     transport;
};

struct BIface {
    char  name[RNSD_PEER_IFACE_MAX];
    char  cls[16];
    char  detail[96];       /* the class's own configuration fields */
    Unit  units[NG_MAX_UNITS];
    int   nunits;
};

/* A way OUT of the community: a radius-0 point-to-point interface, whose far
 * end is a route rather than a neighbour. rnsd already takes this position —
 * it declares a node for one regardless of the radius, because "whether we
 * serve a peer's mesh is a policy; that there is somebody at the other end of
 * the wire is a fact". The record says the same thing to everyone else. */
struct BUplink {
    char cls[16];
    char name[RNSD_PEER_IFACE_MAX];
    char label[RNSD_NODE_LABEL_MAX];   /* the address, in an operator's terms */
    char detail[96];
    bool have_label;
};

struct Build {
    BIface  ifs[NG_MAX_IFACES];
    int     nifs;
    BUplink ups[NG_MAX_UPLINKS];
    int     nups;
    uint8_t dt[NG_MAX_DT][4];
    int     ndt;
};

/* Kilobytes of it, and the netgraph task is its only user — a stack frame, not
 * a heap allocation and not a local. */
PSRAM_BSS Build s_build;

/* Interface-detail contributors, by class. A plain static table with no
 * initialisation order of its own, so a straddle may register before or after
 * netgraph's own onInit. */
struct Contrib { const char* cls; netgraph_iface_detail_t cb; };
Contrib s_contrib[8];
int     s_ncontrib = 0;

int bifaceFind(Build* b, const char* name) {
    for (int i = 0; i < b->nifs; i++) if (std::strcmp(b->ifs[i].name, name) == 0) return i;
    return -1;
}

/* The class's own configuration fields for one interface, sanitized. */
void ifaceDetail(const char* name, const char* cls, char* out, size_t outsz) {
    out[0] = '\0';
    for (int i = 0; i < s_ncontrib; i++) {
        if (std::strcmp(s_contrib[i].cls, cls) != 0) continue;
        char raw[128];
        size_t got = s_contrib[i].cb(name, raw, sizeof raw);
        if (got) { raw[got < sizeof raw ? got : sizeof raw - 1] = '\0'; sanitizeField(raw, out, outsz); }
        break;
    }
}

void collectIface(const char* name, uint8_t radius, void* vctx) {
    Build* b = (Build*)vctx;
    char cls[16];
    ifaceClass(name, cls, sizeof cls);

    /* THE COMMUNITY RADIUS IS NOT A DISPLAY FILTER. It says how far to go
     * looking for nodes to serve — where to stop REACHING — and nothing about
     * what is worth drawing. It is used here only to decide WHAT THE FAR END
     * IS: rnsd keeps no peer rows for a radius-0 interface, so we can never
     * have destination-level evidence about what is over there, and it can only
     * ever be an address. That earns it an `up` line rather than an `if`/`ln`
     * pair — a box on the graph instead of a member — but it is drawn either
     * way, and the local overlay covers anything this misses. Which of us has a
     * way out is the most consequential thing on a community map after the
     * links themselves. The label arrives with the node below. */
    if (!radius) {
        if (b->nups >= NG_MAX_UPLINKS) return;
        BUplink& u = b->ups[b->nups++];
        u = BUplink{};
        safeStrncpy(u.name, name, sizeof u.name);
        safeStrncpy(u.cls, cls, sizeof u.cls);
        ifaceDetail(name, cls, u.detail, sizeof u.detail);
        return;
    }

    if (b->nifs >= NG_MAX_IFACES) return;
    BIface& f = b->ifs[b->nifs++];
    f = BIface{};
    safeStrncpy(f.name, name, sizeof f.name);
    safeStrncpy(f.cls, cls, sizeof f.cls);
    ifaceDetail(name, cls, f.detail, sizeof f.detail);
}

void collectNode(int idx, const rnsd_node_t* nd, void* vctx) {
    Build* b = (Build*)vctx;
    /* An uplink's far end is named by the node rnsd declared for it — the
     * transport address an operator dialled, which is the only name it will
     * ever have. */
    for (int i = 0; i < b->nups; i++) {
        if (std::strcmp(b->ups[i].name, nd->iface) != 0) continue;
        sanitizeField(nd->label, b->ups[i].label, sizeof b->ups[i].label);
        b->ups[i].have_label = b->ups[i].label[0] != '\0';
        return;
    }
    int fi = bifaceFind(b, nd->iface);
    if (fi < 0) return;
    BIface& f = b->ifs[fi];
    if (f.nunits >= NG_MAX_UNITS) return;
    Unit& u = f.units[f.nunits++];
    u = Unit{};
    u.node      = idx;
    u.heard     = nd->heard;
    u.transport = nd->transport;
}

void collectPeer(const rnsd_peer_t* p, void* vctx) {
    Build* b = (Build*)vctx;
    int fi = bifaceFind(b, p->iface);
    if (fi < 0) return;
    BIface& f = b->ifs[fi];
    if (p->node >= 0) {
        for (int i = 0; i < f.nunits; i++) {
            Unit& u = f.units[i];
            if (u.node != p->node) continue;
            /* A node's cell prefix is its FRESHEST announced destination — one
             * cell per node, however many aspects it announces on. Compared
             * against the destinations only: the node's own `heard` also moves
             * for traffic that files no peer row, and a prefix chosen against
             * that would never be set at all. */
            if (!u.have_prefix || p->heard >= u.prefix_heard) {
                std::memcpy(u.prefix, p->dest, 4);
                u.have_prefix = true;
                u.prefix_heard = p->heard;
            }
            if (p->heard > u.heard) u.heard = p->heard;
            return;
        }
        return;
    }
    /* No node attribution on this medium: the destination stands for a node of
     * its own, because that is all that is known about it. */
    if (f.nunits >= NG_MAX_UNITS) return;
    Unit& u = f.units[f.nunits++];
    u = Unit{};
    u.node = -1;
    std::memcpy(u.prefix, p->dest, 4);
    u.have_prefix = true;
    u.prefix_heard = p->heard;
    u.heard = p->heard;
}

void collectDest(const rnsd_hosted_dest_t* d, void* vctx) {
    Build* b = (Build*)vctx;
    if (b->ndt >= NG_MAX_DT) return;
    for (int i = 0; i < b->ndt; i++)
        if (std::memcmp(b->dt[i], d->dest, 4) == 0) return;
    std::memcpy(b->dt[b->ndt++], d->dest, 4);
}

/** Read the whole composition: what we announce, which interfaces we have, and
 *  what is on each of them. Everything here comes from tables rnsd already
 *  keeps, so no medium writes a line of code to appear on the graph. */
void ngCompose(Build* b) {
    *b = Build{};
    rnsdHostedDestsForEach(collectDest, b);
    rnsdIfaceWalk(collectIface, b);
    rnsdNodesForEach("", collectNode, b);
    rnsdPeersForEach("", collectPeer, b);

    /* Links older than the horizon leave the record. A node that is currently
     * ATTACHED but has never announced (heard == 0) is not stale — its lifetime
     * is the interface's statement that it is reachable, not an announce. */
    uint32_t cut = 0;
    if (clockSane()) {
        uint32_t h = (uint32_t)cfgLinkHorizonH() * 3600u;
        uint32_t now = nowUnix();
        cut = now > h ? now - h : 0;
    }
    for (int i = 0; i < b->nifs; i++) {
        BIface& f = b->ifs[i];
        int keep = 0;
        for (int k = 0; k < f.nunits; k++) {
            Unit& u = f.units[k];
            /* Only age out an observation this clock can actually date. */
            if (cut && tsSane(u.heard) && u.heard < cut) continue;
            f.units[keep++] = u;
        }
        f.nunits = keep;
        /* Freshest first, so an abridged record keeps the cells worth keeping. */
        for (int a = 0; a < f.nunits; a++)
            for (int c = a + 1; c < f.nunits; c++)
                if (f.units[c].heard > f.units[a].heard) {
                    Unit t = f.units[a]; f.units[a] = f.units[c]; f.units[c] = t;
                }
    }
}

/** Encode the composition as a packed record. `max_cells` caps the cells on any
 *  one `ln` line — the full record uses NG_MAX_CELLS, the announced form
 *  `s.netgraph.announce_cells`. `*cut` says whether anything was left out, which
 *  is what sets the abridged flag. With `sig` the freshness buckets are forced
 *  to 0 and the seq to 0, so the result hashes the COMPOSITION and nothing that
 *  merely moves with the clock. */
size_t ngEncode(const Build* b, uint8_t* out, size_t cap,
                uint32_t seq, int max_cells, bool sig, bool* cut) {
    Buf w{ out, cap, 0, false };
    if (cut) *cut = false;

    w.u8(NG_MAGIC);
    w.raw(s_self, RNSD_IDENT_HASH_LEN);
    w.u32(sig ? 0 : seq);
    size_t flags_at = w.n;
    w.u8(0);

    /* n — the display name this node announces, and whether it forwards. */
    {
        char name[RNSD_PEER_NAME_MAX];
        ngOwnName(name, sizeof name);
        size_t at = w.lineBegin(NG_TAG_N);
        w.u8(storageGetInt("s.rnsd.transport_enabled", 0) ? 0x01 : 0x00);
        w.str(name);
        w.lineEnd(at);
    }

    /* dt — our own announced destinations, as 4-byte prefixes. This is the join
     * evidence: another record's cell naming one of these is a link to us. */
    if (b->ndt) {
        size_t at = w.lineBegin(NG_TAG_DT);
        w.u8((uint8_t)b->ndt);
        for (int i = 0; i < b->ndt; i++) w.raw(b->dt[i], 4);
        w.lineEnd(at);
    }

    for (int i = 0; i < b->nifs; i++) {
        const BIface& f = b->ifs[i];
        {
            char text[160];
            std::snprintf(text, sizeof text, "%s|%s%s%s", f.cls, f.name,
                          f.detail[0] ? "|" : "", f.detail);
            size_t at = w.lineBegin(NG_TAG_IF);
            w.raw((const uint8_t*)text, std::strlen(text));
            w.lineEnd(at);
        }
        {
            int cells = f.nunits;
            if (cells > max_cells) cells = max_cells;
            if (cells > NG_MAX_CELLS) cells = NG_MAX_CELLS;
            /* Only identity-bearing units get a cell. One known only by its
             * transport address is COUNTED and not listed — no other node could
             * join it to anything anyway. */
            uint8_t packed[NG_MAX_CELLS][5];
            int np = 0;
            for (int k = 0; k < f.nunits && np < cells; k++) {
                const Unit& u = f.units[k];
                if (!u.have_prefix) continue;
                std::memcpy(packed[np], u.prefix, 4);
                packed[np][4] = (uint8_t)((sig ? 0 : freshBucket(seq, u.heard)) |
                                          (u.transport ? 0x04 : 0x00));
                np++;
            }
            int listable = 0;
            for (int k = 0; k < f.nunits; k++) if (f.units[k].have_prefix) listable++;
            if (np < listable && cut) *cut = true;

            size_t at = w.lineBegin(NG_TAG_LN);
            w.str(f.name);
            w.u16((uint16_t)f.nunits);      /* the TRUE link count */
            w.u8((uint8_t)np);
            for (int k = 0; k < np; k++) w.raw(packed[k], 5);
            w.lineEnd(at);
        }
    }

    /* Ways out of the community, last. Only one whose far end rnsd has named:
     * an interface with nobody at the other end of it is not a way anywhere. */
    for (int i = 0; i < b->nups; i++) {
        const BUplink& u = b->ups[i];
        if (!u.have_label) continue;
        /* cls + name + label + detail + three separators, all at their caps. */
        char text[sizeof u.cls + sizeof u.name + sizeof u.label + sizeof u.detail + 4];
        std::snprintf(text, sizeof text, "%s|%s|%s%s%s", u.cls, u.name, u.label,
                      u.detail[0] ? "|" : "", u.detail);
        size_t at = w.lineBegin(NG_TAG_UP);
        w.raw((const uint8_t*)text, std::strlen(text));
        w.lineEnd(at);
    }

    if (w.ovf) return 0;
    if (cut && *cut && flags_at < w.n) out[flags_at] |= NG_FLAG_ABRIDGED;
    return w.n;
}

/* ═══════════════════════════ the resolver ═══════════════════════════ */

/* ── the four evidence classes ──
 *
 * Line style states the evidence class and nothing else. There is no style for
 * "old": evidence expires and the line leaves.
 *
 *   route1  our path table holds a ONE-hop route to that node. Solid, in the
 *           interface class's colour. The only thing a solid line ever means.
 *   route2  our path table holds a TWO-hop route, so the node is adjacent to
 *           the next hop rather than to us — the edge hangs off the neighbour
 *           we see it behind. Thin and white: `iface` names the interface WE
 *           transmit on, not the one the via-node used, so we do not know that
 *           hop's medium and must not colour it as though we did.
 *   heard   an interface holds a connection to the peer or simply hears it,
 *           and no route1 covers it. Dashed. These are the nodes we could be
 *           one hop from and are not, and saying so is the one thing this
 *           device knows that no report will ever carry.
 *   record  a node's own self-report, over a sync Channel. Both ends named by
 *           construction.
 *
 * PRECEDENCE, strongest first, applied as a fold over `(a, b, cls)`: routing is
 * this node's operative truth, a record is a node's own statement about itself,
 * and `heard` is the weakest because it is DEFINED as the case routing does not
 * cover. One published row per triple, carrying the strongest class held for
 * it — publishing all of them would draw the dashed line over the solid one for
 * every neighbour we route through. */
enum { NG_EV_ROUTE1 = 0, NG_EV_ROUTE2 = 1, NG_EV_HEARD = 2, NG_EV_RECORD = 3 };
const char* const kEvName[] = { "route1", "route2", "heard", "record" };

uint8_t evStrength(uint8_t ev) {
    switch (ev) {
        case NG_EV_ROUTE1: return 3;
        case NG_EV_ROUTE2: return 2;
        case NG_EV_RECORD: return 1;
        default:           return 0;   /* heard */
    }
}

struct Vert {
    int      rec;                       /* store slot, -1 = not record-backed */
    /* THE PRIMARY KEY. Every source of evidence reduces to an identity: a
     * record is originated by one, a destination belongs to one (the directory
     * says which), and a point-to-point interface's far end is whichever node
     * answers on it. Only where no identity can be found at all does a vertex
     * fall back to its transport address — a peer that has never announced, or
     * a dialled uplink that never will. */
    uint8_t  id[RNSD_IDENT_HASH_LEN];
    bool     have_id;
    char     name[RNSD_PEER_NAME_MAX];
    char     label[RNSD_NODE_LABEL_MAX];
    bool     transport;
    /* Hops from us; 0 is us, NG_DIST_UNKNOWN is nothing joined it up. Solved by
     * a breadth-first walk of the resolved edges once they are all in, so a
     * node the crawl reached through two other nodes gets the distance those
     * edges imply rather than one asserted when it was added. */
    uint8_t  dist;
    /* Its remote-management announce carried a signature by the community key. */
    bool     member;
    uint32_t visited;                   /* unix seconds of the last crawl visit */
};

#define NG_DIST_UNKNOWN 255

struct Edge {
    int16_t  a, b;                      /* vertex indices; b = -1 unresolved */
    uint8_t  bref[4];
    bool     have_bref;
    char     cls[16];
    char     iface[RNSD_PEER_IFACE_MAX];
    uint8_t  ev;
    /* When this evidence was last refreshed, device unix-seconds. A peer row
     * carries its own last-heard; a route carries none, and its presence in the
     * table IS the refresh — rnsd expires the entry, so a route we can still
     * read is a route that still holds. */
    uint32_t seen;
    bool     transport;
    /* Whose statement this is. Empty for our own evidence; the crawled node's
     * identity where a visit produced it. `a` cannot answer this: for route2
     * the reporting side is the via-node even when we derived the row from our
     * own table, so a local route2 and a crawled one are otherwise
     * indistinguishable, and they are very different claims. */
    uint8_t  src[RNSD_IDENT_HASH_LEN];
    bool     have_src;
};

struct Resolved {
    Vert     verts[NG_MAX_VERTS];
    int      nverts;
    Edge     edges[NG_MAX_LINKS];
    int      nedges;
    /* prefix → vertex, over every record's dt set */
    struct { uint8_t p[4]; int16_t v; } pfx[NG_MAX_PREFIXES];
    int      npfx;
    /* Per-vertex `if` lines, kept as text for the browser's node panel. Three
     * per node across the whole store: nearly every node has one or two, and a
     * node that runs out loses only the panel detail, never a link. */
    struct { int16_t v; char cls[16]; char name[RNSD_PEER_IFACE_MAX]; char detail[96]; }
             ifs[NG_MAX_RECORDS * 3];
    int      nifs;
};

PSRAM_BSS Resolved s_res;

struct PfxCtx { Resolved* r; int v; };

bool collectPfxLine(uint8_t tag, const uint8_t* b, size_t n, void* vctx) {
    PfxCtx* c = (PfxCtx*)vctx;
    if (tag == NG_TAG_N) {
        if (n < 2) return true;
        c->r->verts[c->v].transport = (b[0] & 1) != 0;
        size_t nlen = b[1];
        if (2 + nlen > n) return true;
        size_t k = nlen < RNSD_PEER_NAME_MAX - 1 ? nlen : RNSD_PEER_NAME_MAX - 1;
        std::memcpy(c->r->verts[c->v].name, b + 2, k);
        c->r->verts[c->v].name[k] = '\0';
    } else if (tag == NG_TAG_DT) {
        if (n < 1) return true;
        int cnt = b[0];
        if (1 + (size_t)cnt * 4 > n) return true;
        for (int i = 0; i < cnt && c->r->npfx < NG_MAX_PREFIXES; i++) {
            std::memcpy(c->r->pfx[c->r->npfx].p, b + 1 + 4*i, 4);
            c->r->pfx[c->r->npfx].v = (int16_t)c->v;
            c->r->npfx++;
        }
    } else if (tag == NG_TAG_IF) {
        Resolved* r = c->r;
        if (r->nifs >= (int)(sizeof(r->ifs)/sizeof(r->ifs[0]))) return true;
        char text[192];
        size_t k = n < sizeof(text) - 1 ? n : sizeof(text) - 1;
        std::memcpy(text, b, k); text[k] = '\0';
        auto& e = r->ifs[r->nifs];
        e.v = (int16_t)c->v;
        e.cls[0] = e.name[0] = e.detail[0] = '\0';
        char* p1 = std::strchr(text, '|');
        if (!p1) return true;
        *p1 = '\0';
        safeStrncpy(e.cls, text, sizeof e.cls);
        char* p2 = std::strchr(p1 + 1, '|');
        if (p2) { *p2 = '\0'; safeStrncpy(e.detail, p2 + 1, sizeof e.detail); }
        safeStrncpy(e.name, p1 + 1, sizeof e.name);
        r->nifs++;
    }
    return true;
}

/* ── routing as evidence ──
 *
 * A stock RNS node announces its destinations and never a record, so routing is
 * the only evidence it exists and the only evidence of where it hangs off. What
 * a route can honestly place:
 *
 *   hops == 1  a direct neighbour — the far end is us. `route1`.
 *   hops == 2  reachable through a next hop we can name, so the destination
 *              really is ADJACENT to that node. `route2`, and the case that
 *              finds a link between two OTHER nodes when neither told us.
 *   hops > 2   it is out there and we know roughly how far, but not who it
 *              hangs off: the intermediate chain is not in our table. Drawing
 *              it to the next hop would assert an adjacency that is not in the
 *              data, so it is not drawn at all. Those nodes appear when
 *              something reports them.
 *
 * The join is the IDENTITY behind a destination, which is the same value a
 * record is originated by — so a routed node either lands on the vertex that
 * speaks for itself, or gets one of its own that says it does not. */

/* Every address this device has heard, not every node: thirty nodes announcing
 * four aspects each is 120 rows, and a walk that stopped at 96 would drop a
 * quarter of this node's OWN evidence before the resolver ever saw it. */
#define NG_MAX_DIR 256

/* rnsd's directory, flattened: every address this device has ever heard, and
 * the node it belongs to. This is what makes one unified view possible — it
 * turns any destination, from any source, into the same node key. */
/* ── what counts as a NODE ──
 *
 * A DEVICE HOSTS SEVERAL IDENTITIES. Its transport identity, LXMF's, one per
 * application — and the directory's "identity behind a destination" is the
 * owner of that ADDRESS, not the device. Keying vertices on it draws one
 * circle per identity: a three-node bench comes out as eight, three of them
 * the real devices and five their own LXMF and application addresses wearing
 * the display names their users chose.
 *
 * The aspect is what separates them. `rnstransport.*` is the node speaking as
 * a node — the probe responder, the management service — and those are the
 * destinations that ARE the device. An `lxmf.delivery` address belongs to a
 * person and is the same address on every device they run; drawing it as a
 * node asserts a device that does not exist.
 *
 * So an application destination is not a vertex. It is not lost — it is simply
 * not a node, and this is a graph of nodes. Where a device announces nothing
 * node-level it does not appear, which is the honest answer: we could not
 * address it as a node either. */
bool ngNodeAspect(const char* aspect) {
    if (!aspect || !*aspect) return false;    /* unknown: not evidence of a node */
    if (std::strncmp(aspect, "rnstransport.", 13) == 0) return true;
    if (std::strcmp(aspect, NG_ASPECT) == 0) return true;
    return false;
}

struct DirEnt {
    uint8_t  dest[RNSD_DEST_HASH_LEN];
    uint8_t  id[RNSD_IDENT_HASH_LEN];
    uint8_t  via[RNSD_DEST_HASH_LEN];
    char     iface[RNSD_PEER_IFACE_MAX];
    uint32_t at;            /* when the announce that made this path was heard */
    uint32_t expires;
    uint8_t  hops;
    bool     haveId, haveRoute;
    bool     isNode;        /* its aspect says this address IS a device */
};
PSRAM_BSS DirEnt s_dir[NG_MAX_DIR];
int s_ndir = 0;

/* ── our own addresses ──
 *
 * The directory holds what we have HEARD announced, and a node does not ingest
 * its own announces — so nothing in it points at us. That matters the moment a
 * crawled node reports its routes: every one of our neighbours routes to us,
 * and without this those rows resolve to nothing and the line from a neighbour
 * back to us is never drawn. It is the reciprocal half of every edge we have,
 * which is precisely what the reach rule needs to close a line. */
/* Every destination this node hosts, not just its node-level ones: rnsd's own
 * probe and management, plus one per consumer — lxmf, nomad, rlpg, netgraph. */
#define NG_MAX_OWN_DESTS 16
uint8_t s_ownDest[NG_MAX_OWN_DESTS][RNSD_DEST_HASH_LEN];
int     s_nOwnDest = 0;

void ngOwnDestCollect(const rnsd_hosted_dest_t* d, void*) {
    if (s_nOwnDest >= NG_MAX_OWN_DESTS) return;
    /* EVERY address of ours, whatever its aspect. The node-level rule exists to
     * stop an application identity being mistaken for a device — an
     * lxmf.delivery address belongs to a person and could be on any device. For
     * OUR OWN addresses there is no such ambiguity: every one of them is this
     * device, and a neighbour that routes to any of them is routing to us.
     *
     * Filtering these was why a crawled node's route back to us went missing
     * whenever the route it held was to one of our application addresses — the
     * one row that closes a line, dropped for answering a question nobody
     * needed to ask about it. */
    std::memcpy(s_ownDest[s_nOwnDest++], d->dest, RNSD_DEST_HASH_LEN);
}

bool ngIsOwnDest(const uint8_t* d) {
    for (int i = 0; i < s_nOwnDest; i++)
        if (std::memcmp(s_ownDest[i], d, RNSD_DEST_HASH_LEN) == 0) return true;
    return false;
}

/* ── the interfaces we actually have ──
 *
 * A ROUTE OUTLIVES THE INTERFACE THAT LEARNED IT. The path table holds an entry
 * until it expires — days, by `s.rnsd.path.ttl` — and switching a radio off
 * does not touch it. So "the path table says so" is not on its own a reason to
 * draw a line: an operator who turns an interface off and watches its lines
 * stay on the picture is being told something false about their own device.
 *
 * The registered interface table is the other half of that sentence, and it is
 * current by construction. A route over an interface that is no longer
 * registered is not drawn. */
#define NG_MAX_LIVE_IF 12
char s_liveIf[NG_MAX_LIVE_IF][RNSD_PEER_IFACE_MAX];
int  s_nLiveIf = 0;

void ngLiveIfCollect(const char* name, uint8_t, void*) {
    if (s_nLiveIf >= NG_MAX_LIVE_IF || !name || !*name) return;
    safeStrncpy(s_liveIf[s_nLiveIf++], name, RNSD_PEER_IFACE_MAX);
}

/** Is this interface still registered? An empty name is not an interface and
 *  cannot be checked — a crawled row names the REMOTE's interface, in the
 *  remote's own vocabulary, and none of this applies to it. */
bool ngIfaceLive(const char* iface) {
    if (!iface || !*iface) return false;
    for (int i = 0; i < s_nLiveIf; i++)
        if (std::strcmp(s_liveIf[i], iface) == 0) return true;
    return false;
}

void ngDirCollect(const rnsd_dir_entry_t* e, void*) {
    if (s_ndir >= NG_MAX_DIR || !e->have_identity) return;
    DirEnt& d = s_dir[s_ndir++];
    std::memcpy(d.dest, e->dest, RNSD_DEST_HASH_LEN);
    std::memcpy(d.id,   e->identity, RNSD_IDENT_HASH_LEN);
    std::memcpy(d.via,  e->via, RNSD_DEST_HASH_LEN);
    safeStrncpy(d.iface, e->iface, sizeof d.iface);
    d.at = e->timestamp;
    d.expires = e->expires;
    d.hops = e->hops;
    d.haveId = true;
    d.haveRoute = e->have_route;
    d.isNode = ngNodeAspect(e->aspect);
}

/** The node a 4-byte destination prefix belongs to — the join that no longer
 *  depends on the owner having listed it in its own `dt` line. */
const uint8_t* ngIdForPrefix(const uint8_t p[4]) {
    for (int i = 0; i < s_ndir; i++)
        if (std::memcmp(s_dir[i].dest, p, 4) == 0) return s_dir[i].id;
    return nullptr;
}

const uint8_t* ngIdForDest(const uint8_t* d) {
    for (int i = 0; i < s_ndir; i++)
        if (std::memcmp(s_dir[i].dest, d, RNSD_DEST_HASH_LEN) == 0) return s_dir[i].id;
    return nullptr;
}

/** The directory row for a destination, or -1. Separate from ngIdForDest
 *  because a caller sometimes needs the ASPECT as well as the identity — what
 *  kind of thing the address is, not just who owns it. */
int ngDirIndexForDest(const uint8_t* d) {
    for (int i = 0; i < s_ndir; i++)
        if (std::memcmp(s_dir[i].dest, d, RNSD_DEST_HASH_LEN) == 0) return i;
    return -1;
}

/** Who is at the far end of a point-to-point interface: whoever answers on it
 *  one hop away. This is what stops a Bluetooth peer being drawn as a MAC
 *  beside the very node it is. */
const uint8_t* ngIdOnIface(const char* iface) {
    if (!iface || !*iface) return nullptr;
    const uint8_t* found = nullptr;
    for (int i = 0; i < s_ndir; i++) {
        if (!s_dir[i].haveRoute || s_dir[i].hops != 1) continue;
        /* WHICH DEVICE answers, not which address. An application destination
         * routed over this interface belongs to whoever is at the far end; it
         * does not identify them, and taking it as the interface's node names
         * the far end after one of its users. */
        if (!s_dir[i].isNode) continue;
        if (std::strcmp(s_dir[i].iface, iface) != 0) continue;
        if (!found) { found = s_dir[i].id; continue; }
        /* Two different nodes answer here, so the interface does not name one.
         * A shared radio is the ordinary case; only a point-to-point link lets
         * "the far end" mean a single node. */
        if (std::memcmp(found, s_dir[i].id, RNSD_IDENT_HASH_LEN) != 0) return nullptr;
    }
    return found;
}

/** The vertex standing for this identity, or -1. Matches EVERY vertex that has
 *  one, not just the record-backed ones — which is what stops a node appearing
 *  once per source of evidence about it. */
int ngVertexOfIdentity(Resolved* r, const uint8_t* id) {
    for (int v = 0; v < r->nverts; v++)
        if (r->verts[v].have_id &&
            std::memcmp(r->verts[v].id, id, RNSD_IDENT_HASH_LEN) == 0) return v;
    return -1;
}

/** Find or create the vertex for a node, keyed on its identity. */
int ngVertFor(Resolved* r, const uint8_t* id) {
    int v = ngVertexOfIdentity(r, id);
    if (v >= 0) return v;
    if (r->nverts >= NG_MAX_VERTS) return -1;
    v = r->nverts++;
    Vert& vt = r->verts[v];
    vt = Vert{};
    vt.rec  = -1;
    vt.dist = NG_DIST_UNKNOWN;
    std::memcpy(vt.id, id, RNSD_IDENT_HASH_LEN);
    vt.have_id = true;
    hex(vt.label, id, 4);
    return v;
}

/** The vertex for something with no identity at all — a peer an interface holds
 *  but that has never announced. Keyed on the transport address rnsd labelled
 *  it by, which is the only name it will ever have. */
int ngVertForLabel(Resolved* r, const char* label) {
    for (int v = 0; v < r->nverts; v++)
        if (!r->verts[v].have_id && std::strcmp(r->verts[v].label, label) == 0) return v;
    if (r->nverts >= NG_MAX_VERTS) return -1;
    int v = r->nverts++;
    Vert& vt = r->verts[v];
    vt = Vert{};
    vt.rec  = -1;
    vt.dist = NG_DIST_UNKNOWN;
    safeStrncpy(vt.label, label, sizeof vt.label);
    return v;
}

int pfxLookup(Resolved* r, const uint8_t* p) {
    for (int i = 0; i < r->npfx; i++)
        if (std::memcmp(r->pfx[i].p, p, 4) == 0) return r->pfx[i].v;
    return -1;
}

/** THE FOLD. One edge per `(a, b, cls)`, carrying the strongest evidence class
 *  held for it.
 *
 *  Both DIRECTIONS stay separate — `(a,b)` and `(b,a)` are two independent
 *  statements, and until the far end has reported the reverse the renderer
 *  draws from `a` and stops short of `b`. What collapses here is corroboration
 *  of the SAME direction: a neighbour we route through is also a neighbour we
 *  hear, and publishing both would draw the dashed line over the solid one for
 *  every such peer. It also bounds the row count by adjacency rather than by
 *  how many classes happen to agree, which is what the caps are sized against.
 *
 *  Returns the edge, or nullptr when the table is full. */
/** Do these two class words describe the same line?
 *
 *  AN EMPTY CLASS IS AN ABSENCE OF A CLAIM, not a claim of a different medium.
 *  A two-hop route names no medium because we cannot know one, and a crawled
 *  edge names none unless the answering node happened to use our vocabulary —
 *  so treating "" as its own class drew a second arc beside the line already
 *  saying the same thing, and left a two-hop guess standing next to the one-hop
 *  fact that had superseded it. Two DIFFERENT named media are still two lines,
 *  which is the case worth seeing. */
bool ngClsCompatible(const char* a, const char* b) {
    return !a[0] || !b[0] || std::strcmp(a, b) == 0;
}

Edge* ngEdgeAdd(Resolved* r, int a, int b, const uint8_t* bref,
                const char* cls, const char* iface, uint8_t ev,
                uint32_t seen, bool transport, const uint8_t* src) {
    if (a < 0) return nullptr;
    for (int i = 0; i < r->nedges; i++) {
        Edge& e = r->edges[i];
        if (e.a != a || !ngClsCompatible(e.cls, cls)) continue;
        if (b >= 0) { if (e.b != b) continue; }
        else if (!(e.b < 0 && bref && e.have_bref &&
                   std::memcmp(e.bref, bref, 4) == 0)) continue;

        if (evStrength(ev) > evStrength(e.ev)) {
            /* A stronger class takes the row over, and brings its own interface
             * name and timestamp with it — the weaker one's were describing a
             * different observation of the same adjacency. */
            e.ev = ev;
            e.seen = seen;
            safeStrncpy(e.iface, iface, sizeof e.iface);
            if (src) { std::memcpy(e.src, src, RNSD_IDENT_HASH_LEN); e.have_src = true; }
            else       e.have_src = false;
        } else if (seen > e.seen) {
            e.seen = seen;      /* same class, fresher sighting */
        }
        /* Whichever side actually knew the medium names it — an edge that
         * arrived without one is not evidence that there is none. */
        if (!e.cls[0] && cls[0]) safeStrncpy(e.cls, cls, sizeof e.cls);
        if (transport) e.transport = true;
        return &e;
    }
    if (r->nedges >= NG_MAX_LINKS) return nullptr;
    Edge& e = r->edges[r->nedges++];
    e = Edge{};
    e.a = (int16_t)a;
    e.b = (int16_t)b;
    if (b < 0 && bref) { std::memcpy(e.bref, bref, 4); e.have_bref = true; }
    safeStrncpy(e.cls, cls, sizeof e.cls);
    safeStrncpy(e.iface, iface, sizeof e.iface);
    e.ev = ev;
    e.seen = seen;
    e.transport = transport;
    if (src) { std::memcpy(e.src, src, RNSD_IDENT_HASH_LEN); e.have_src = true; }
    return &e;
}

/** Is there already a route1 from `a` covering `b`? `heard` is DEFINED as the
 *  peers routing does not cover, so this is the whole of its guard. */
bool ngRoutedFrom(Resolved* r, int a, int b) {
    if (b < 0) return false;
    for (int i = 0; i < r->nedges; i++) {
        const Edge& e = r->edges[i];
        if (e.ev == NG_EV_ROUTE1 && e.a == a && e.b == b) return true;
    }
    return false;
}

struct EdgeCtx { Resolved* r; int v; uint32_t ts; };

bool collectEdgeLine(uint8_t tag, const uint8_t* b, size_t n, void* vctx) {
    if (tag != NG_TAG_LN) return true;
    EdgeCtx* c = (EdgeCtx*)vctx;
    Resolved* r = c->r;
    if (n < 1) return true;
    size_t ilen = b[0];
    if (1 + ilen + 3 > n) return true;
    char iface[RNSD_PEER_IFACE_MAX];
    size_t k = ilen < sizeof(iface) - 1 ? ilen : sizeof(iface) - 1;
    std::memcpy(iface, b + 1, k); iface[k] = '\0';
    const uint8_t* q = b + 1 + ilen;
    uint8_t cells = q[2];
    q += 3;
    if ((size_t)(q - b) + (size_t)cells * 5 > n) return true;

    char cls[16];
    ifaceClass(iface, cls, sizeof cls);
    for (int i = 0; i < cells; i++) {
        const uint8_t* cell = q + 5 * i;
        int to = pfxLookup(r, cell);
        if (to < 0) {
            /* Not in anybody's `dt`, but rnsd may still know whose address it
             * is — and if it does, this is that node, not a nameless stub. */
            const uint8_t* id = ngIdForPrefix(cell);
            if (id) to = ngVertFor(r, id);
        }
        if (to == c->v) continue;                       /* a record naming itself */
        ngEdgeAdd(r, c->v, to, cell, cls, iface, NG_EV_RECORD,
                  c->ts, (cell[4] & 0x04) != 0, nullptr);
    }
    return true;
}

/* ── route1 and route2: this node's own path table ──
 *
 * THE INVARIANT: anything rnsd says is reachable is on the graph. Not "should
 * be" — is. A status pill reading `B2` beside a picture with no Bluetooth line
 * is not a display quirk to be explained away; it is the graph contradicting
 * the node's own neighbour table, and the graph is the one that is wrong.
 *
 * These two passes cost nothing and need nobody's cooperation: the path table
 * is already there, and the drawing changes the moment it does. */
void ngRoutes(Resolved* r, int self) {
    uint32_t now = nowUnix();
    /* TWO PASSES, one-hop first. A two-hop route hangs off the vertex its via
     * created, and the directory hands rows out in its own order — so a single
     * pass reaches half the two-hop rows before the one-hop row that would have
     * placed their next hop, and drops them for a via that is about to exist. */
    for (int pass = 1; pass <= 2; pass++)
    for (int i = 0; i < s_ndir; i++) {
        const DirEnt& e = s_dir[i];
        if (!e.haveRoute) continue;
        if (e.hops != pass) continue;
        /* Past its own expiry. NOT a horizon of ours — Reticulum stamps every
         * path with when it stops being valid, and a route past that is dead by
         * the protocol's own definition rather than by a rule invented here. A
         * route that is merely OLD is still a route: on a quiet mesh the table
         * is the only thing that knows the way. */
        if (clockSane() && tsSane(e.expires) && e.expires < now) continue;
        /* Routes to an application address say where a PERSON can be reached,
         * not that there is a device there. Only node-level destinations get a
         * circle — see ngNodeAspect. */
        if (!e.isNode) continue;
        /* And not over an interface this device no longer has. The route may
         * still be in the table; the way to it is gone. */
        if (!ngIfaceLive(e.iface)) continue;

        char cls[16];
        ifaceClass(e.iface, cls, sizeof cls);

        if (e.hops == 1) {
            int v = ngVertFor(r, e.id);
            if (v < 0 || v == self) continue;
            /* The class colour is honest here and only here: `iface` is the
             * interface WE transmit on, and for a one-hop route that is also
             * the medium the link runs over. */
            ngEdgeAdd(r, self, v, nullptr, cls, e.iface, NG_EV_ROUTE1,
                      e.at, false, nullptr);
            continue;
        }
        if (e.hops != 2) continue;

        /* Who it hangs off. `via` IS AN IDENTITY HASH — upstream fills it from
         * `Transport.identity.hash` of the node that forwarded the announce,
         * not from any destination that node hosts. Looking it up as an address
         * therefore never matched, which is why no two-hop route was ever
         * placed and no node ever appeared behind the neighbour it sits behind.
         *
         * FIND, NEVER CREATE. The whole value of a two-hop route is that it
         * hangs the node off the neighbour we can see it behind; a via we have
         * never heard of is not a neighbour we can see, and standing one up
         * produces a pair of nameless circles joined to each other and to
         * nothing else — a component floating beside the graph, saying less
         * than drawing nothing would. That is the same case as `hops > 2`,
         * which the plan already declines to draw for exactly this reason.
         *
         * The interface remains a fallback for a route carrying no via: on a
         * point-to-point link whoever is one hop away IS the next hop, and
         * where several answer there it names nobody. */
        int other = -1;
        static const uint8_t kNoVia[RNSD_DEST_HASH_LEN] = {};
        if (std::memcmp(e.via, kNoVia, RNSD_DEST_HASH_LEN) != 0)
            other = ngVertexOfIdentity(r, e.via);
        if (other < 0) {
            const uint8_t* viaId = ngIdOnIface(e.iface);
            if (!viaId) continue;
            other = ngVertexOfIdentity(r, viaId);
        }
        if (other < 0) continue;

        int v = ngVertFor(r, e.id);
        if (v < 0 || v == other || v == self) continue;
        /* NO CLASS. This is somebody else's link and we have no idea what it
         * runs over — our `iface` names what WE transmit on, not what the
         * via-node used. Colourless and thin is the honest drawing, and it is
         * the same statement as "we did not measure this". */
        ngEdgeAdd(r, other, v, nullptr, "", e.iface, NG_EV_ROUTE2,
                  now, false, nullptr);
    }
}

/* ── heard: the peers routing does not use ──
 *
 * A peer an interface holds a connection to (auto, ble) or simply hears (lora),
 * and for which no route1 exists. These are the nodes we could be one hop from
 * and are not — a faster parallel link carries the route instead, or nothing
 * has routed through them yet — and saying so is the one thing this device
 * knows that no report will ever carry.
 *
 * A peer unheard for longer than `s.netgraph.heard_h` is not drawn at all.
 * There is no aged style: evidence expires and the line leaves. */
struct HeardCtx {
    Resolved* r;
    int       self;
    uint32_t  cut;        /* peers heard before this are past the horizon */
    /* Interfaces that have a declared node, and the ONE vertex each stands for.
     *
     * On such an interface the far end IS the interface — a point-to-point
     * medium cannot attribute a packet to a peer and does not need to — so every
     * peer row on it and the node row itself are the same thing seen from
     * different tables, and they must land on one circle. Memoising the choice
     * here is what guarantees that: whichever table reaches the interface first
     * picks the vertex, and the rest join it. */
    struct { char iface[RNSD_PEER_IFACE_MAX]; int v; bool decided;
             /* A node-level peer on this interface reached a vertex. The NODE
              * row is then redundant: on a shared medium it describes the same
              * far end the peers already placed, and inventing a circle for its
              * transport address puts the device on the picture twice — once
              * under the identity we route to, once under whatever rnsd
              * labelled the interface's node. */
             bool covered;
             /* ANY peer row at all, whatever its aspect. Something out there
              * has announced, so it is not the silent attachment hcNode exists
              * to draw, and its node-level address is on its way. */
             bool announced; }
              ifv[NG_MAX_IFACES];
    int       nifv;
};
PSRAM_BSS HeardCtx s_heard;

int hcSlot(HeardCtx* c, const char* iface) {
    for (int i = 0; i < c->nifv; i++)
        if (std::strcmp(c->ifv[i].iface, iface) == 0) return i;
    return -1;
}

void hcNoteNodeIface(int, const rnsd_node_t* nd, void* vctx) {
    HeardCtx* c = (HeardCtx*)vctx;
    if (c->nifv >= NG_MAX_IFACES || hcSlot(c, nd->iface) >= 0) return;
    auto& e = c->ifv[c->nifv++];
    safeStrncpy(e.iface, nd->iface, sizeof e.iface);
    e.v = -1;
    e.decided = false;
    e.covered = false;
    e.announced = false;
}

/** The class word for an interface name, but ONLY where that word names a
 *  medium this firmware actually knows — `out` is empty otherwise.
 *
 *  For a REMOTE node's interface name this is the whole question. `iface` in a
 *  crawled `/path` answer is whatever the answering node calls it, in its own
 *  vocabulary: a node running this firmware says `lora/0` or `ble/aa:bb`, and
 *  those split to a class word we can colour; a stock Reticulum node says
 *  `RNodeInterface[LoRa]` or `TCPInterface[wan0]`, which split to nothing we
 *  recognise and must stay colourless rather than be guessed at.
 *
 *  The test is the PILL REGISTRY, not a table of media kept here. Every
 *  interface straddle publishes `rns.pill.<class>.color` for the medium it
 *  implements, and that registry is already the one vocabulary naming media on
 *  every surface. Asking it keeps netgraph free of per-medium knowledge while
 *  still colouring the case that matters — a community of nodes running the
 *  same firmware, where the names really are ours. */
void ngKnownClass(const char* iface, char* out, size_t outsz) {
    out[0] = '\0';
    if (!iface || !*iface) return;
    char cls[16];
    ifaceClass(iface, cls, sizeof cls);
    if (!cls[0]) return;
    char key[48], colour[16];
    std::snprintf(key, sizeof key, "rns.pill.%s.color", cls);
    storageGetStr(key, colour, sizeof colour, "");
    if (!colour[0]) return;          /* no such medium here — do not invent one */
    safeStrncpy(out, cls, outsz);
}

/** Is anything node-level routed one hop over this interface? If so its far
 *  ends are already vertices, put there by ngRoutes. */
bool ngAnyNodeRouteOn(const char* iface) {
    if (!iface || !*iface) return false;
    for (int i = 0; i < s_ndir; i++)
        if (s_dir[i].haveRoute && s_dir[i].hops == 1 && s_dir[i].isNode &&
            std::strcmp(s_dir[i].iface, iface) == 0) return true;
    return false;
}

/** The vertex a heard DESTINATION belongs to, or -1 where nothing names one.
 *
 *  Two joins, in order of how much they claim. The directory is the strong one:
 *  it says which identity owns an address, for every address this device has
 *  heard. A record's `dt` line is the other — a node listing its own
 *  destinations — and it reaches the case the directory misses, a node whose
 *  record arrived over a sync but whose announce we never heard directly. */
int hcVertForDest(Resolved* r, const uint8_t* dest) {
    const uint8_t* id = ngIdForDest(dest);
    if (id) return ngVertFor(r, id);
    int v = pfxLookup(r, dest);          /* some record claims this prefix */
    return v;
}

/** The vertex for a node-bearing interface, chosen once and reused.
 *
 *  BEST EVIDENCE FIRST. Whoever answers on the interface, by identity, is the
 *  right key — it is the same value a record is originated by, so the node lands
 *  on the circle everything else about it already landed on. Failing that, an
 *  announced destination, joined the two ways above. The transport address is
 *  last, and a MAC on the drawing must mean exactly one thing: nobody has ever
 *  announced here. */
int hcIfaceVertex(HeardCtx* c, int slot, const char* iface,
                  const uint8_t* peerDest, const char* label) {
    if (slot >= 0 && c->ifv[slot].decided) return c->ifv[slot].v;

    int v = -1;
    const uint8_t* id = ngIdOnIface(iface);
    if (id) v = ngVertFor(c->r, id);
    if (v < 0 && peerDest) v = hcVertForDest(c->r, peerDest);
    if (v < 0 && peerDest) { char h4[2 * 4 + 1]; hex(h4, peerDest, 4);
                             v = ngVertForLabel(c->r, h4); }
    if (v < 0 && label && *label) v = ngVertForLabel(c->r, label);

    if (slot >= 0) { c->ifv[slot].v = v; c->ifv[slot].decided = v >= 0; }
    return v;
}

/* Peers first: one that has announced carries a destination the directory can
 * usually turn into an identity, which is the strongest key available. */
void hcPeer(const rnsd_peer_t* p, void* vctx) {
    HeardCtx* c = (HeardCtx*)vctx;
    Resolved* r = c->r;
    /* Only age out an observation this clock can actually date. */
    if (c->cut && tsSane(p->heard) && p->heard < c->cut) return;

    /* Something announced here, whatever it was. Recorded before the aspect
     * filter below, because it answers a different question: not "is this a
     * device" but "is anything out there talking at all" — which is what tells
     * hcNode this interface is not a silent attachment. */
    {
        int s = hcSlot(c, p->iface);
        if (s >= 0) c->ifv[s].announced = true;
    }

    /* ONLY A NODE-LEVEL ADDRESS IS EVIDENCE OF A DEVICE, whichever branch
     * below would place it. An lxmf.delivery heard on the radio is a person
     * reachable somewhere, not a device sitting there — see ngNodeAspect.
     *
     * This has to come first, before the interface is even considered. Guarding
     * only the shared-medium branch left the other one open: an interface with
     * a declared node took its vertex from whichever peer row happened to come
     * first, and where that was an application address the device arrived a
     * second time under its user's display name — one circle routed to, another
     * beside it merely heard. */
    if (!ngNodeAspect(p->aspect)) return;

    char cls[16];
    ifaceClass(p->iface, cls, sizeof cls);

    int slot = hcSlot(c, p->iface);
    int v;
    if (slot >= 0) {
        v = hcIfaceVertex(c, slot, p->iface, p->dest, nullptr);
    } else {
        /* No declared node: on a shared medium a destination heard out of the
         * air stands for a node of its own, because that is all it is known to
         * be. Two identities announced into the air are indistinguishable from
         * two nodes, and merging on a guess would put a wrong line on a graph. */
        v = hcVertForDest(r, p->dest);
        if (v < 0) { char h4[2 * 4 + 1]; hex(h4, p->dest, 4); v = ngVertForLabel(r, h4); }
    }
    if (v < 0 || v == c->self) return;
    /* Whatever happens to the edge below, this interface's far end is now on
     * the picture — hcNode must not add it again under its address. */
    if (slot >= 0) c->ifv[slot].covered = true;
    if (ngRoutedFrom(r, c->self, v)) return;
    ngEdgeAdd(r, c->self, v, nullptr, cls, p->iface, NG_EV_HEARD,
              p->heard, false, nullptr);
}

/* Then the nodes: an interface's far end exists from the moment it is
 * REACHABLE, not from its first announce, so one that has attached and said
 * nothing still gets a line — under the transport address rnsd labelled it by. */
void hcNode(int, const rnsd_node_t* nd, void* vctx) {
    HeardCtx* c = (HeardCtx*)vctx;
    Resolved* r = c->r;
    /* A node ATTACHED but never heard from (heard == 0) is not stale: its
     * lifetime is the interface's statement that it is reachable. */
    if (c->cut && tsSane(nd->heard) && nd->heard < c->cut) return;

    char cls[16];
    ifaceClass(nd->iface, cls, sizeof cls);

    int slot = hcSlot(c, nd->iface);

    /* THIS ROW EXISTS FOR ONE CASE: something attached that has never
     * announced. If anything node-level is routed over this interface, or a
     * peer already placed its far end, that is not the case — the device is on
     * the picture already and a second circle under rnsd's transport label is a
     * phantom.
     *
     * ngIdOnIface deliberately answers "nobody" when several nodes reply on one
     * interface, because then the interface does not name a single node. That
     * is the right answer to the question it is asked and the wrong reason to
     * invent a vertex: several nodes answering means several nodes are already
     * drawn, not that none is. A shared radio with two neighbours on it hit
     * exactly this and produced a circle labelled with rnsd's node label beside
     * the one it duplicated.
     *
     * A peer row of ANY aspect settles it too. A device that has announced
     * something is a device that announces, and its node-level address is on
     * its way; standing up a circle now, keyed on whatever the interface calls
     * it, means standing up a second one when that arrives. On a radio the
     * interface's label is not even an address — iface-lora names a declared
     * node after the display names its destinations announced — so the
     * placeholder turns up wearing a person's name and reads as a real node
     * rather than as the guess it is. */
    if ((slot >= 0 && (c->ifv[slot].covered || c->ifv[slot].announced)) ||
        ngAnyNodeRouteOn(nd->iface)) return;

    int v = hcIfaceVertex(c, slot, nd->iface, nullptr, nd->label);
    if (v < 0 || v == c->self) return;   /* no identity and no address is not a node */
    if (nd->transport) r->verts[v].transport = true;
    if (ngRoutedFrom(r, c->self, v)) return;
    ngEdgeAdd(r, c->self, v, nullptr, cls, nd->iface, NG_EV_HEARD,
              nd->heard, nd->transport, nullptr);
}

void ngHeard(Resolved* r, int self) {
    HeardCtx* c = &s_heard;
    c->r = r; c->self = self; c->nifv = 0; c->cut = 0;
    if (clockSane()) {
        uint32_t h = (uint32_t)cfgHeardH() * 3600u;
        uint32_t now = nowUnix();
        c->cut = now > h ? now - h : 0;
    }
    rnsdNodesForEach("", hcNoteNodeIface, c);
    rnsdPeersForEach("", hcPeer, c);
    rnsdNodesForEach("", hcNode, c);
}

/* ── distance ──
 *
 * Solved once, over the edges as resolved, rather than asserted as each one is
 * added: a node the crawl reached through two others gets the distance those
 * edges imply, and a node joined up by several routes gets the shortest. Edges
 * are walked UNDIRECTED here — an adjacency is a distance whichever end
 * reported it. */
void ngDistances(Resolved* r, int self) {
    for (int v = 0; v < r->nverts; v++) r->verts[v].dist = NG_DIST_UNKNOWN;
    if (self < 0) return;
    r->verts[self].dist = 0;
    /* The graph is tens of vertices, so relaxation to a fixed point costs less
     * than a queue would and cannot run away: each round either lowers some
     * distance or ends the walk. */
    for (int round = 0; round < NG_MAX_VERTS; round++) {
        bool moved = false;
        for (int i = 0; i < r->nedges; i++) {
            const Edge& e = r->edges[i];
            if (e.b < 0) continue;
            uint8_t da = r->verts[e.a].dist, db = r->verts[e.b].dist;
            if (da != NG_DIST_UNKNOWN && da + 1 < db) {
                r->verts[e.b].dist = (uint8_t)(da + 1); moved = true;
            } else if (db != NG_DIST_UNKNOWN && db + 1 < da) {
                r->verts[e.a].dist = (uint8_t)(db + 1); moved = true;
            }
        }
        if (!moved) break;
    }
}

/* ── what the crawl brought back ──
 *
 * A path-table row from another node is neither its signed record nor an
 * inference of ours: it is a third party's report about itself, pulled rather
 * than pushed, and stale from the moment it lands. Held here between crawls and
 * folded into the graph on every resolve, so a crawl that died half way still
 * leaves the picture better than it found it.
 *
 * Rows expire on `heard_h` like every other class of evidence. */
#define NG_MAX_CRAWL   192
#define NG_MAX_VISITED 64
#define NG_MAX_MEMBERS 48

/* Who announces the management service, and who proved membership while doing
 * it. Filled by the announce subscription further down and read by the resolver
 * here, which is why the table is declared with the other evidence rather than
 * beside the code that fills it. */
struct Member {
    bool     used;
    uint8_t  id[RNSD_IDENT_HASH_LEN];
    uint8_t  dest[RNSD_DEST_HASH_LEN];
    bool     member;        /* its app_data carried a valid community signature */
    bool     transport;     /* it forwards for others */
    /* What the device calls itself, out of the same announce. The only
     * device-level name there is: an LXMF display name belongs to a person and
     * sits on another identity entirely. */
    char     name[RNSD_PEER_NAME_MAX];
    uint32_t heard;
};
PSRAM_BSS Member s_members[NG_MAX_MEMBERS];

struct CrawlEdge {
    bool     used;
    uint8_t  from[RNSD_IDENT_HASH_LEN];   /* the visited node — both `a` and `src` */
    uint8_t  to[RNSD_DEST_HASH_LEN];      /* a destination it routes to in one hop */
    char     iface[RNSD_PEER_IFACE_MAX];  /* the interface IT named */
    uint32_t at;                          /* when we asked */
};
PSRAM_BSS CrawlEdge s_crawl[NG_MAX_CRAWL];

struct Visit {
    bool     used;
    uint8_t  id[RNSD_IDENT_HASH_LEN];
    uint32_t at;
    bool     member;                      /* its announce carried a community signature */
};
Visit s_visited[NG_MAX_VISITED];

/* ── the interfaces a visited node runs ──
 *
 * Out of its `/status` answer. This is how a neighbour's way OUT becomes
 * visible: a TCP interface to the wider world has a far end that never
 * announces, so no route and no crawled path row will ever name it, and the
 * only evidence it exists at all is the node's own list of what it is running.
 *
 * The name is carried VERBATIM and the class left empty. Upstream names an
 * interface `TCPInterface[wan0]` or `RNodeInterface[LoRa]`, and deciding which
 * medium that is would put a per-medium decoder in core — which is exactly what
 * the record format was shaped to avoid. Rendered as it arrived is the honest
 * answer, and the operator reads it perfectly well. */
#define NG_MAX_CRAWL_IF 64

struct CrawlIface {
    bool     used;
    uint8_t  from[RNSD_IDENT_HASH_LEN];
    char     name[48];
    char     detail[16];                  /* "up" / "down" */
    uint32_t at;
};
PSRAM_BSS CrawlIface s_crawlIf[NG_MAX_CRAWL_IF];

/** Record one interface a visited node reported. Replaces the row already held
 *  for the same (node, name) — one visit per node per crawl, so the newest
 *  answer is simply the current one. */
void ngCrawlIfNote(const uint8_t* from, const char* name, bool up) {
    if (!name || !*name) return;
    int slot = -1, oldest = -1;
    for (int i = 0; i < NG_MAX_CRAWL_IF; i++) {
        CrawlIface& c = s_crawlIf[i];
        if (!c.used) { if (slot < 0) slot = i; continue; }
        if (std::memcmp(c.from, from, RNSD_IDENT_HASH_LEN) == 0 &&
            std::strcmp(c.name, name) == 0) { slot = i; break; }
        if (oldest < 0 || c.at < s_crawlIf[oldest].at) oldest = i;
    }
    if (slot < 0) slot = oldest;
    if (slot < 0) return;
    CrawlIface& c = s_crawlIf[slot];
    c = CrawlIface{};
    c.used = true;
    std::memcpy(c.from, from, RNSD_IDENT_HASH_LEN);
    safeStrncpy(c.name, name, sizeof c.name);
    safeStrncpy(c.detail, up ? "up" : "down", sizeof c.detail);
    c.at = nowUnix();
}

/** Record one adjacency a visited node reported. Replaces any row already held
 *  for the same (from, to) — one visit per node per crawl, so the newest answer
 *  is simply the current one. */
void ngCrawlNote(const uint8_t* from, const uint8_t* to, const char* iface) {
    int free_slot = -1, oldest = -1;
    for (int i = 0; i < NG_MAX_CRAWL; i++) {
        CrawlEdge& c = s_crawl[i];
        if (!c.used) { if (free_slot < 0) free_slot = i; continue; }
        if (std::memcmp(c.from, from, RNSD_IDENT_HASH_LEN) == 0 &&
            std::memcmp(c.to, to, RNSD_DEST_HASH_LEN) == 0) { free_slot = i; break; }
        if (oldest < 0 || c.at < s_crawl[oldest].at) oldest = i;
    }
    if (free_slot < 0) free_slot = oldest;
    if (free_slot < 0) return;
    CrawlEdge& c = s_crawl[free_slot];
    c = CrawlEdge{};
    c.used = true;
    std::memcpy(c.from, from, RNSD_IDENT_HASH_LEN);
    std::memcpy(c.to,   to,   RNSD_DEST_HASH_LEN);
    safeStrncpy(c.iface, iface ? iface : "", sizeof c.iface);
    c.at = nowUnix();
}

/** Mark a node visited, for `netgraph.nodes.<i>.visited`. */
void ngVisitNote(const uint8_t* id, bool member) {
    int slot = -1, oldest = -1;
    for (int i = 0; i < NG_MAX_VISITED; i++) {
        if (!s_visited[i].used) { if (slot < 0) slot = i; continue; }
        if (std::memcmp(s_visited[i].id, id, RNSD_IDENT_HASH_LEN) == 0) { slot = i; break; }
        if (oldest < 0 || s_visited[i].at < s_visited[oldest].at) oldest = i;
    }
    if (slot < 0) slot = oldest;
    if (slot < 0) return;
    s_visited[slot].used = true;
    std::memcpy(s_visited[slot].id, id, RNSD_IDENT_HASH_LEN);
    s_visited[slot].at = nowUnix();
    s_visited[slot].member = member;
}

/** Fold the crawl's held answers into the resolved graph.
 *
 *  These land as `route1` because that is what they are — a node's own one-hop
 *  routes — but with `a` anchored at the node that answered and `src` naming
 *  it, which is the only thing that distinguishes them from our own table. */
void ngCrawlApply(Resolved* r) {
    uint32_t cut = 0;
    if (clockSane()) {
        uint32_t h = (uint32_t)cfgHeardH() * 3600u;
        uint32_t now = nowUnix();
        cut = now > h ? now - h : 0;
    }
    int opaque = 0;
    for (int i = 0; i < NG_MAX_CRAWL; i++) {
        CrawlEdge& c = s_crawl[i];
        if (!c.used) continue;
        if (cut && tsSane(c.at) && c.at < cut) { c.used = false; continue; }

        int a = ngVertFor(r, c.from);
        if (a < 0) continue;

        /* A /path answer is a list of DESTINATION hashes with no aspect and no
         * identity attached, so what a row means is only what OUR directory can
         * say about that address. Three outcomes, and two of them are silence:
         *
         *   node-level, known    → the device it belongs to. This is the edge
         *                          worth having: one neighbour's view of
         *                          another, which we cannot see ourselves.
         *   application, known   → a person's address hosted somewhere. Not a
         *                          device, and drawing one asserts a device
         *                          that does not exist.
         *   unknown              → we have never heard it announce. It is far
         *                          more likely to be an application address
         *                          than a node — there are more of them — and a
         *                          stub captioned with four bytes of hash tells
         *                          the reader nothing they can act on. Counted,
         *                          not drawn.
         *
         * Without this the crawl re-admits by the back door exactly what the
         * aspect rule keeps out of the local passes: a three-device bench came
         * back with nine circles and thirty-five lines, most of them one
         * device's applications and unnamed stubs — including this node's own
         * LXMF address, reported by a neighbour that routes to it. */
        /* Ourselves first. Every neighbour routes to us, and our own addresses
         * are in nobody's directory including our own — so without this the
         * one row that closes a line is the one row that gets thrown away. */
        int b;
        if (ngIsOwnDest(c.to)) {
            b = s_haveSelf ? ngVertexOfIdentity(r, s_self) : -1;
        } else {
            int di = ngDirIndexForDest(c.to);
            if (di < 0 || !s_dir[di].isNode) { opaque++; continue; }
            b = ngVertFor(r, s_dir[di].id);
        }
        if (b < 0 || b == a) continue;
        /* The medium, where the answering node named it in a vocabulary we
         * share. A node running this firmware says `lora/0`; a stock one says
         * `RNodeInterface[LoRa]` and gets no colour rather than a guessed one.
         * ngKnownClass asks the pill registry, so netgraph still holds no table
         * of media of its own. */
        char cls[16];
        ngKnownClass(c.iface, cls, sizeof cls);
        ngEdgeAdd(r, a, b, nullptr, cls, c.iface, NG_EV_ROUTE1, c.at, false, c.from);
    }
    if (opaque)
        verb("crawl: %d reported route%s named an address that is not a node "
             "we can place", opaque, opaque == 1 ? "" : "s");

    for (int i = 0; i < NG_MAX_VISITED; i++) {
        if (!s_visited[i].used) continue;
        int v = ngVertexOfIdentity(r, s_visited[i].id);
        if (v < 0) continue;
        r->verts[v].visited = s_visited[i].at;
        if (s_visited[i].member) r->verts[v].member = true;
    }

    /* What each visited node is running, onto that node's `if` rows. The only
     * evidence there is for an interface whose far end never announces — a TCP
     * uplink to the wider world, say. */
    const int ifcap = (int)(sizeof(r->ifs) / sizeof(r->ifs[0]));
    for (int i = 0; i < NG_MAX_CRAWL_IF && r->nifs < ifcap; i++) {
        CrawlIface& c = s_crawlIf[i];
        if (!c.used) continue;
        if (cut && tsSane(c.at) && c.at < cut) { c.used = false; continue; }
        int v = ngVertexOfIdentity(r, c.from);
        if (v < 0) continue;
        auto& e = r->ifs[r->nifs++];
        e.v = (int16_t)v;
        /* Its medium where the name is in a vocabulary we share, and nothing
         * where it is not — the same test the edges use. */
        ngKnownClass(c.name, e.cls, sizeof e.cls);
        safeStrncpy(e.name,   c.name,   sizeof e.name);
        safeStrncpy(e.detail, c.detail, sizeof e.detail);
    }
}

/* Membership and askability, out of the management announces we have heard.
 * A node that announces the service exists whether or not anything routes to
 * it yet, so this ALSO puts a vertex on the graph for one we have only heard
 * advertise itself — which is what the crawl then has something to visit. */
void ngMembersApply(Resolved* r) {
    for (int i = 0; i < NG_MAX_MEMBERS; i++) {
        if (!s_members[i].used) continue;
        /* ANNOTATE, never create. Hearing a node's management announce says it
         * exists, not how we reach it — and a circle with no line to anything
         * is a worse answer than leaving it out, because the drawing is about
         * connectivity. The crawl gathers its targets from this table directly,
         * so a member with no vertex is still visited; once it answers, its own
         * edges put it on the picture properly. */
        int v = ngVertexOfIdentity(r, s_members[i].id);
        if (v < 0) continue;
        if (s_members[i].member)    r->verts[v].member = true;
        if (s_members[i].transport) r->verts[v].transport = true;
        /* The device's own name for itself, which outranks anything inferred
         * from an announce on some other identity. */
        if (s_members[i].name[0])
            safeStrncpy(r->verts[v].name, s_members[i].name, sizeof r->verts[v].name);
    }
}

/* ═══════════════════════════ publication ═══════════════════════════ */

int s_pubNodes = 0, s_pubLinks = 0;
int s_pubIfaceCount[NG_MAX_VERTS];      /* `if` lines published per vertex, last time */

void ngPublish(Resolved* r) {
    char key[72], val[80];

    /* How many `if` lines each vertex will carry — needed before the deletes,
     * so only rows that are genuinely going away are removed. */
    int perVertex[NG_MAX_VERTS] = {};
    for (int i = 0; i < r->nifs; i++) {
        int v = r->ifs[i].v;
        if (v >= 0 && v < r->nverts) perVertex[v]++;
    }

    /* Rows the graph no longer has go FIRST and outside the bracket: a delete
     * does not ride the op list, and a reader must never see a count that still
     * spans a vertex that is gone. */
    for (int i = r->nverts; i < s_pubNodes; i++) {
        std::snprintf(key, sizeof key, "netgraph.nodes.%d", i); storageDeleteTree(key);
    }
    for (int j = r->nedges; j < s_pubLinks; j++) {
        std::snprintf(key, sizeof key, "netgraph.links.%d", j); storageDeleteTree(key);
    }
    for (int v = 0; v < NG_MAX_VERTS; v++) {
        int want = (v < r->nverts) ? perVertex[v] : 0;
        if (!want && s_pubIfaceCount[v]) {
            std::snprintf(key, sizeof key, "netgraph.ifs.%d", v); storageDeleteTree(key);
        } else {
            for (int k = want; k < s_pubIfaceCount[v]; k++) {
                std::snprintf(key, sizeof key, "netgraph.ifs.%d.%d", v, k);
                storageDeleteTree(key);
            }
        }
        s_pubIfaceCount[v] = want;
    }

    storageBegin();
    if (s_haveSelf) { char h[2*RNSD_IDENT_HASH_LEN+1]; hex(h, s_self, RNSD_IDENT_HASH_LEN);
                      storageSet("netgraph.self", h); }
    storageSet("netgraph.radius", cfgRadius());

    uint32_t now = nowUnix();
    for (int i = 0; i < r->nverts; i++) {
        const Vert& v = r->verts[i];
        char id[2*RNSD_IDENT_HASH_LEN+1] = "";
        if (v.have_id) hex(id, v.id, RNSD_IDENT_HASH_LEN);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.id", i);        storageSet(key, id);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.name", i);      storageSet(key, v.name);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.label", i);     storageSet(key, v.label);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.transport", i); storageSet(key, v.transport ? 1 : 0);
        /* Text, so it can be EMPTY: nothing joined this one up, and an integer
         * cannot say that — 0 already means "us". */
        std::snprintf(val, sizeof val, "%u", (unsigned)v.dist);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.dist", i);
        storageSet(key, v.dist == NG_DIST_UNKNOWN ? "" : val);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.member", i);    storageSet(key, v.member ? 1 : 0);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.visited", i);   storageSet(key, (int)v.visited);
    }
    storageSet("netgraph.nodes.slots", r->nverts);

    for (int j = 0; j < r->nedges; j++) {
        const Edge& e = r->edges[j];
        std::snprintf(key, sizeof key, "netgraph.links.%d.a", j);     storageSet(key, (int)e.a);
        std::snprintf(key, sizeof key, "netgraph.links.%d.b", j);     storageSet(key, (int)e.b);
        std::snprintf(val, sizeof val, "%02x%02x%02x%02x", e.bref[0], e.bref[1], e.bref[2], e.bref[3]);
        std::snprintf(key, sizeof key, "netgraph.links.%d.bref", j);
        storageSet(key, (e.b < 0 && e.have_bref) ? val : "");
        std::snprintf(key, sizeof key, "netgraph.links.%d.ev", j);    storageSet(key, kEvName[e.ev & 3]);
        std::snprintf(key, sizeof key, "netgraph.links.%d.cls", j);   storageSet(key, e.cls);
        std::snprintf(key, sizeof key, "netgraph.links.%d.iface", j); storageSet(key, e.iface);
        /* Empty where the evidence carries no date. A route has none — its
         * presence in the table is the whole of its currency — and saying 0
         * would claim we watched it happen this second. */
        std::snprintf(key, sizeof key, "netgraph.links.%d.age_s", j);
        if (clockSane() && tsSane(e.seen) && now >= e.seen) {
            std::snprintf(val, sizeof val, "%u", (unsigned)(now - e.seen));
            storageSet(key, val);
        } else storageSet(key, "");
        std::snprintf(key, sizeof key, "netgraph.links.%d.transport", j); storageSet(key, e.transport ? 1 : 0);
        char src[2*RNSD_IDENT_HASH_LEN+1] = "";
        if (e.have_src) hex(src, e.src, RNSD_IDENT_HASH_LEN);
        std::snprintf(key, sizeof key, "netgraph.links.%d.src", j);   storageSet(key, src);
    }
    storageSet("netgraph.links.count", r->nedges);

    /* Per-vertex interface lines, numbered within the vertex. */
    int written[NG_MAX_VERTS] = {};
    for (int i = 0; i < r->nifs; i++) {
        int v = r->ifs[i].v;
        if (v < 0 || v >= r->nverts) continue;
        int k = written[v]++;
        std::snprintf(key, sizeof key, "netgraph.ifs.%d.%d.cls", v, k);    storageSet(key, r->ifs[i].cls);
        std::snprintf(key, sizeof key, "netgraph.ifs.%d.%d.name", v, k);   storageSet(key, r->ifs[i].name);
        std::snprintf(key, sizeof key, "netgraph.ifs.%d.%d.detail", v, k); storageSet(key, r->ifs[i].detail);
    }
    for (int v = 0; v < r->nverts; v++)
        if (written[v]) {
            std::snprintf(key, sizeof key, "netgraph.ifs.%d.count", v);
            storageSet(key, written[v]);
        }
    storageEnd();

    s_pubNodes = r->nverts;
    s_pubLinks = r->nedges;
}

/** Re-resolve the whole store and republish. Cheap enough to do wholesale: the
 *  community is tens of records, and a partial update would need exactly the
 *  cross-record bookkeeping the one-writer rule exists to avoid. */
/* A node that files no record can still have SAID what it is called: rnsd keeps
 * the display name out of every announce it hears. A member's own record always
 * wins — that is the node speaking for itself — but for everything else this is
 * the difference between "Rop Columba" and eight bytes of hex. */
void ngNameFromAnnounces(Resolved* r) {
    struct NameCtx { Resolved* r; } c{ r };
    rnsdPeersForEach("", [](const rnsd_peer_t* p, void* v) {
        NameCtx* c = (NameCtx*)v;
        if (!p->name[0]) return;
        /* NEVER FROM A NODE-LEVEL ANNOUNCE. rnsd derives a peer's name by
         * SNIFFING app_data — msgpack array, else raw UTF-8 — because that is
         * how LXMF and NomadNet carry one and neither says which it used. A
         * transport announce carries no display name at all, and the management
         * one carries a binary frame whose signature bytes can occasionally
         * pass for a msgpack string; taking a name from either yields nonsense
         * on the odd announce.
         *
         * The authoritative name for such a node arrives through
         * ngMembersApply, out of a field it actually declared. This path is for
         * the other case: something whose only self-description is the display
         * name in an application announce. */
        if (ngNodeAspect(p->aspect)) return;
        const uint8_t* id = ngIdForDest(p->dest);
        if (!id) return;
        int vi = ngVertexOfIdentity(c->r, id);
        if (vi < 0) return;
        Vert& vt = c->r->verts[vi];
        if (vt.rec >= 0 || vt.name[0]) return;   /* its own record outranks this */
        safeStrncpy(vt.name, p->name, sizeof vt.name);
    }, &c);
}

/* Defined with the community identity, well below: whether a community is
 * configured at all is a question the resolver has to ask about ITSELF, and
 * the derivation is too far down the file to reach any other way. */
bool ngCommunityHash(uint8_t* out);

/** Re-resolve everything and republish.
 *
 * ORDER MATTERS in exactly one place: route1 goes in before `heard`, because
 * `heard` is defined as the peers routing does not cover and asks ngRoutedFrom
 * to say so. Everything else folds by `(a, b, cls)` and is order-independent. */
void ngResolve() {
    Resolved* r = &s_res;
    r->nverts = r->nedges = r->npfx = r->nifs = 0;
    /* Who owns which address, for every address this device has heard. Loaded
     * first because every pass below resolves through it. */
    s_ndir = 0;
    rnsdDirForEach(ngDirCollect, nullptr);
    /* And our own addresses, which appear in no directory at all — the half a
     * neighbour's report of us resolves through. */
    s_nOwnDest = 0;
    rnsdHostedDestsForEach(ngOwnDestCollect, nullptr);
    /* And which interfaces still exist, because a route does not stop being a
     * route table entry when its interface goes away. */
    s_nLiveIf = 0;
    rnsdIfaceWalk(ngLiveIfCollect, nullptr);

    /* Us, always vertex 0 and always present — the graph has a centre whether
     * or not anything else is on it, and a picture with nothing at all on it
     * cannot be told apart from a broken renderer. */
    int self = -1;
    if (s_haveSelf) {
        self = ngVertFor(r, s_self);
        if (self >= 0) {
            ngOwnName(r->verts[self].name, sizeof r->verts[self].name);
            r->verts[self].transport = storageGetInt("s.rnsd.transport_enabled", 0) != 0;
            /* We hold the community key, so we are in the community — the
             * membership announce is how we tell everyone ELSE, and waiting to
             * hear our own would be waiting for a message we never send to
             * ourselves. */
            r->verts[self].member = ngCommunityHash(nullptr);
        }
    }

    /* Records: their origins become vertices and their `dt` prefixes the join
     * table, before any `ln` cell is read against it. */
    for (int i = 0; i < NG_MAX_RECORDS; i++) {
        if (!s_recs[i].used) continue;
        int v = ngVertFor(r, s_recs[i].origin);   /* one door in */
        if (v < 0) continue;
        r->verts[v].rec = i;
        PfxCtx c{ r, v };
        ngForEachLine(s_recs[i].bytes, s_recs[i].len, collectPfxLine, &c);
    }

    /* Our own path table, then the peers it does not cover. */
    if (self >= 0) {
        ngRoutes(r, self);
        ngHeard(r, self);
    }

    /* Records last: a record never overrides a route, and the fold enforces
     * that by strength whatever order they arrive in.
     *
     * OUR OWN record is skipped. It is built from the very tables the two passes
     * above just read, so every cell in it restates something we already hold
     * first-hand — and restating it as a `record` edge can only duplicate. Worse,
     * a cell names a peer by 4-byte DESTINATION prefix while the local passes
     * name it by identity or by transport address, so the two would not even
     * fold together: the same neighbour would arrive twice, once as itself and
     * once as an unresolved stub. A record is evidence about a node that is not
     * us; about ourselves we have the source. */
    for (int v = 0; v < r->nverts; v++) {
        int slot = r->verts[v].rec;
        if (slot < 0 || !s_recs[slot].used || s_recs[slot].mine) continue;
        EdgeCtx c{ r, v, s_recs[slot].seq };
        ngForEachLine(s_recs[slot].bytes, s_recs[slot].len, collectEdgeLine, &c);
    }

    ngNameFromAnnounces(r);
    ngCrawlApply(r);
    ngMembersApply(r);
    ngDistances(r, self);

    int byEv[4] = {};
    int unresolved = 0;
    for (int i = 0; i < r->nedges; i++) {
        byEv[r->edges[i].ev & 3]++;
        if (r->edges[i].b < 0) unresolved++;
    }
    ngPublish(r);

    /* Which layer produced what. A graph that draws nothing says where it was
     * lost: no route1 and no heard means rnsd's tables are empty, edges but no
     * lines means the browser. */
    info("resolved: %d vertice%s, %d link%s — %d route1, %d route2, %d heard, "
         "%d record (%d unresolved)",
         r->nverts, r->nverts == 1 ? "" : "s",
         r->nedges, r->nedges == 1 ? "" : "s",
         byEv[NG_EV_ROUTE1], byEv[NG_EV_ROUTE2], byEv[NG_EV_HEARD],
         byEv[NG_EV_RECORD], unresolved);
    if (r->nedges >= NG_MAX_LINKS)
        warn("link table full at %d — the graph is truncated", NG_MAX_LINKS);
    if (r->nverts >= NG_MAX_VERTS)
        warn("vertex table full at %d — the graph is truncated", NG_MAX_VERTS);
    if (s_ndir >= NG_MAX_DIR)
        warn("directory walk hit %d entries — evidence was dropped before "
             "the resolver saw it", NG_MAX_DIR);
}

/* ═══════════════════════════ own record + announce ═══════════════════════════ */

int      s_destHandle   = -1;
int      s_annSub       = -1;
uint32_t s_lastRebuild  = 0;      /* ms */
/* The announced form, held until the floor lets it out. Rebuilding is free —
 * it only re-reads tables this node already has — but ANNOUNCING costs every
 * medium's airtime, and a node joining a busy neighbourhood would otherwise
 * re-flood its record once per neighbour. So the two are separated: the record
 * and the published rows follow the neighbourhood immediately, and the air
 * hears about it at most once per floor. Throttling the local publish is what
 * made a node's own graph run ten minutes behind its own peer table. */
uint32_t s_lastAnnounce   = 0;    /* ms */
size_t   s_pendingAnnounce = 0;   /* bytes held in s_announceBuf, 0 = nothing due */
PSRAM_BSS uint8_t s_announceBuf[NG_MAX_RECORD];
uint32_t s_sigLast      = 0;
bool     s_rebuildWanted = true;

uint32_t fnv(const uint8_t* d, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}

uint32_t ngNextSeq() {
    /* seq doubles as the record's build timestamp. Guarded monotonic and
     * persisted, so a reboot with a bad clock cannot re-issue an old seq and
     * have the community reject the node's own news about itself. */
    uint32_t now  = nowUnix();
    uint32_t last = (uint32_t)storageGetInt("s.netgraph.seq", 0);
    uint32_t seq  = now > last ? now : last + 1;
    storageSet("s.netgraph.seq", (int)seq);
    return seq;
}

void ngAnnounce(const uint8_t* rec, size_t n) {
    if (s_destHandle < 0) return;
    uint8_t frame[1 + NG_ANNOUNCE_MAX];
    if (n > NG_ANNOUNCE_MAX) return;
    frame[0] = RNSD_DEST_ANNOUNCE;
    std::memcpy(frame + 1, rec, n);
    (void)frame;
    /* MOTHBALLED — plans/netgraph.md, "Protocol". A record flooded per node per
     * announce beat does not scale on LoRa, and until there is a relay or a
     * central distribution point the crawl is how the rest of the graph gets
     * filled in. Restoring the flood is uncommenting this one call, which is
     * why it is a comment and not a deletion.
     *
     * rnsd holds the bytes; WHEN they go on the air is each interface's call.
     * netgraph owns no announce timer. */
    /* itsSend(s_destHandle, frame, n + 1, pdMS_TO_TICKS(200)); */
}

/** Air the record we are holding, once the floor allows. Separate from the
 *  rebuild so a node's own graph tracks its own neighbourhood immediately while
 *  the mesh still hears from it at most once per floor. */
void ngAnnounceDue() {
    if (!s_pendingAnnounce) return;
    uint32_t floor_ms = (uint32_t)cfgRebuildFloorS() * 1000u;
    uint32_t now = nowMs();
    if (s_lastAnnounce && (uint32_t)(now - s_lastAnnounce) < floor_ms) return;
    ngAnnounce(s_announceBuf, s_pendingAnnounce);
    s_lastAnnounce = now ? now : 1;
    s_pendingAnnounce = 0;
}

void ngRebuild() {
    if (!s_haveSelf) return;
    Build* b = &s_build;
    ngCompose(b);

    uint32_t seq = ngNextSeq();
    PSRAM_BSS static uint8_t full[NG_MAX_RECORD];
    uint8_t* abr = s_announceBuf;

    bool cutFull = false;
    size_t nf = ngEncode(b, full, sizeof full, seq, NG_MAX_CELLS, /*sig=*/false, &cutFull);
    if (!nf) { warn("rebuild: own record does not fit %d B", NG_MAX_RECORD); return; }
    recStore(full, nf, nullptr, 0, /*mine=*/true);

    /* The announced form is the abridged one. If it still will not fit the
     * airtime budget, shed cells until it does — a record too big to announce
     * is a record nobody hears. */
    int cells = cfgAnnounceCells();
    size_t na = 0;
    bool cutAbr = false;
    for (;;) {
        cutAbr = false;
        na = ngEncode(b, abr, NG_MAX_RECORD, seq, cells, /*sig=*/false, &cutAbr);
        if (na && na <= NG_ANNOUNCE_MAX) break;
        if (cells <= 1) { na = 0; break; }
        cells = cells > 4 ? cells / 2 : 1;
    }
    if (na) s_pendingAnnounce = na;      /* aired by ngAnnounceDue, on the floor */
    else    warn("rebuild: no abridged form fits %d B — not announcing", NG_ANNOUNCE_MAX);

    s_lastRebuild = nowMs();
    s_rebuildWanted = false;

    /* Say what was actually composed, not just how big it came out. A record
     * with no cells and a record with cells are the same size to within a few
     * bytes, and the difference between them is the whole graph — so the counts
     * that produced it are what a log needs to carry. */
    int units = 0, celled = 0;
    for (int i = 0; i < b->nifs; i++) {
        units += b->ifs[i].nunits;
        for (int k = 0; k < b->ifs[i].nunits; k++) if (b->ifs[i].units[k].have_prefix) celled++;
    }
    info("record rebuilt: seq=%u %zu B — %d iface%s, %d link%s (%d with a destination), "
         "%d uplink%s, %d dest%s; announced %zu B%s",
         (unsigned)seq, nf,
         b->nifs, b->nifs == 1 ? "" : "s",
         units, units == 1 ? "" : "s", celled,
         b->nups, b->nups == 1 ? "" : "s",
         b->ndt, b->ndt == 1 ? "" : "s",
         na, cutAbr ? " (abridged)" : "");
    if (b->nifs && !celled)
        warn("record has interfaces but no link cells — rnsd reports no announced "
             "peer on any of them, so no node can draw a line to us");
}

/* ── has anything the GRAPH is drawn from moved? ──
 *
 * A poll, because rnsd has no "the neighbourhood changed" hook and this is
 * cheaper than growing one per event source. What it must not do is re-resolve
 * on a beat: a node whose network has not moved should do nothing at all every
 * thirty seconds, and republishing a few hundred rows into a browser-synced
 * tier for no reason is the opposite of nothing.
 *
 * STRUCTURE ONLY. Which destinations are routed, over what, at how many hops;
 * which interfaces exist; which peers are on them. Deliberately NOT the
 * timestamps — a peer's last-heard moves every time it speaks, and hashing it
 * would make every scan look like a change and defeat the whole purpose. The
 * cost is that `age_s` on a published row only refreshes when something
 * structural also moves, which is a display detail rather than a fact about
 * the network.
 *
 * When the event hooks arrive this becomes their fallback rather than the
 * primary trigger. */
struct SigCtx { uint32_t h; };

void sigMix(SigCtx* c, const void* p, size_t n) {
    const uint8_t* d = (const uint8_t*)p;
    for (size_t i = 0; i < n; i++) { c->h ^= d[i]; c->h *= 16777619u; }
}

bool ngGraphInputsChanged() {
    SigCtx c{ 2166136261u };

    rnsdDirForEach([](const rnsd_dir_entry_t* e, void* v) {
        SigCtx* c = (SigCtx*)v;
        if (!e->have_route) return;
        sigMix(c, e->dest, RNSD_DEST_HASH_LEN);
        sigMix(c, e->via, RNSD_DEST_HASH_LEN);
        sigMix(c, e->iface, std::strlen(e->iface));
        sigMix(c, e->aspect, std::strlen(e->aspect));
        sigMix(c, &e->hops, 1);
    }, &c);

    rnsdIfaceWalk([](const char* name, uint8_t radius, void* v) {
        SigCtx* c = (SigCtx*)v;
        sigMix(c, name, std::strlen(name));
        sigMix(c, &radius, 1);
    }, &c);

    rnsdPeersForEach("", [](const rnsd_peer_t* p, void* v) {
        SigCtx* c = (SigCtx*)v;
        sigMix(c, p->dest, RNSD_DEST_HASH_LEN);
        sigMix(c, p->iface, std::strlen(p->iface));
        sigMix(c, p->aspect, std::strlen(p->aspect));
    }, &c);

    rnsdNodesForEach("", [](int, const rnsd_node_t* nd, void* v) {
        SigCtx* c = (SigCtx*)v;
        sigMix(c, nd->iface, std::strlen(nd->iface));
        sigMix(c, nd->label, std::strlen(nd->label));
        sigMix(c, &nd->transport, 1);
    }, &c);

    static uint32_t last = 0;
    static bool     seen = false;
    if (seen && c.h == last) return false;
    last = c.h;
    seen = true;
    return true;
}

/** Has the COMPOSITION changed — a link appearing or disappearing, a
 *  contributed field, the horizon expiring a link? Freshness alone must not
 *  count, so the signature is taken over an encoding with the buckets and the
 *  timestamp zeroed. */
bool ngCompositionChanged() {
    if (!s_haveSelf) return false;
    ngCompose(&s_build);
    PSRAM_BSS static uint8_t sigbuf[NG_MAX_RECORD];
    size_t n = ngEncode(&s_build, sigbuf, sizeof sigbuf, 0, NG_MAX_CELLS, /*sig=*/true, nullptr);
    if (!n) return false;
    uint32_t h = fnv(sigbuf, n);
    if (h == s_sigLast) return false;
    s_sigLast = h;
    return true;
}

/* ═══════════════════════════ announce ingest ═══════════════════════════ */

/* hops(1) | dest(16) | identity_hash(16) | pubkey(64) | ratchet(32) | app_data */
constexpr size_t NG_ANN_HDR = 1 + 16 + 16 + RNSD_PUBKEY_LEN + RNSD_RATCHET_LEN;

struct Fetch { bool used; uint8_t origin[16]; uint8_t dest[16]; uint32_t next_ms; };
Fetch s_fetch[4];

void fetchQueue(const uint8_t* origin, const uint8_t* dest) {
    for (auto& f : s_fetch)
        if (f.used && std::memcmp(f.origin, origin, 16) == 0) return;
    for (auto& f : s_fetch)
        if (!f.used) {
            f.used = true;
            std::memcpy(f.origin, origin, 16);
            std::memcpy(f.dest, dest, 16);
            f.next_ms = nowMs();
            return;
        }
}

void onAnnounce(int handle, size_t) {
    PSRAM_BSS static uint8_t buf[NG_ANN_HDR + NG_MAX_RECORD];
    for (;;) {
        size_t n = itsRecv(handle, buf, sizeof buf, 0);
        if (n == 0) return;
        if (n <= NG_ANN_HDR) continue;
        const uint8_t* dest = buf + 1;
        const uint8_t* ident = buf + 17;
        const uint8_t* rec = buf + NG_ANN_HDR;
        size_t rn = n - NG_ANN_HDR;
        if (!ngValidate(rec, rn)) continue;
        /* A first-hand record is covered by the announce's own signature, and
         * the announcing identity IS the origin — anything else is somebody
         * relaying another node's record over an announce, which is not a thing
         * this protocol does. */
        if (std::memcmp(ngOrigin(rec), ident, RNSD_IDENT_HASH_LEN) != 0) continue;
        if (ngIngest(rec, rn, dest, buf[0])) {
            /* The abridged form is all an announce can carry. Ask the origin
             * itself for the rest — the announce's dest hash is routable. */
            if (ngAbridged(rec)) fetchQueue(ngOrigin(rec), dest);
        }
    }
}

void onAnnounceDisc(int) { s_annSub = -1; }

/* ═══════════════════════════ the sync engine ═══════════════════════════ */

struct Sess {
    bool     used;
    bool     initiator;
    int      handle;
    /** rnsd's tag for this channel — ours for an outbound one, rnsd's
     *  "in.<8hex>" for an inbound one. It keys `rnsd.chan.<tag>.*`, which is
     *  how the send window below reads what has actually left. */
    char     tag[24];
    uint32_t sent_msgs;                       /* messages handed to rnsd on this channel */
    bool     sent_done, peer_done;
    bool     want_only;                       /* targeted fetch: one WANT, no digest */
    uint8_t  want_origin[RNSD_IDENT_HASH_LEN];
    /* Records queued to send, paced by the window. A backfill is the whole
     * store, and handing it over in one burst would overrun rnsd's channel
     * outbox — which DROPS past its bound rather than blocking. */
    int16_t  q[NG_MAX_RECORDS];
    uint8_t  qn, qi;
    bool     want_done;                       /* DONE, once the queue has drained */
    uint16_t dig_total, dig_n;
    struct { uint8_t o[RNSD_IDENT_HASH_LEN]; uint32_t seq; } dig[NG_MAX_RECORDS];
    bool     asm_active;
    uint8_t  asm_origin[RNSD_IDENT_HASH_LEN];
    uint32_t asm_seq;
    uint8_t  asm_parts, asm_next;
    uint16_t asm_len;
    uint8_t  asm_buf[NG_MAX_RECORD];
    uint32_t active_ms;     /* last message in or out — the idle timeout's clock */
    uint32_t close_at;      /* initiator: when the linger below is up. 0 = not closing */
    /** Records THIS exchange taught us. The beat's backoff is derived from it
     *  on close, so it must count what came in over this channel and nothing
     *  else — a global tally is also moved by announces and by other peers'
     *  inbound syncs, which say nothing about whether asking this partner was
     *  worth the airtime. */
    uint16_t ingested;
};

PSRAM_BSS Sess s_sess[NG_SESS_MAX];

/* Outbound state. One sync in flight at a time — an anti-entropy beat that
 * overlapped itself would spend the airtime it exists to save. */
enum { NG_OUT_IDLE = 0, NG_OUT_CONNECTING, NG_OUT_RUNNING };
int      s_outState = NG_OUT_IDLE;
char     s_outTag[24];
int      s_partnerRot = 0;
uint32_t s_nextSync   = 0;      /* ms */
/* ── how often to ask ──
 *
 * ADAPTIVE, because the cost and the value move together. An exchange that
 * changed something is evidence the community is in flux — a node rebooted, a
 * medium came up, somebody moved — and if one neighbour had news the next
 * probably does too, so halve the wait. An exchange that changed nothing is
 * evidence everyone already agrees, and the design says so outright: steady
 * state is digests that match. So double it, toward `sync_min` and stay there.
 * Halving rather than resetting, because one record arriving says the community
 * moved a little, not that this node knows nothing — a reset put a settled mesh
 * back at the bottom of the ramp for every single update anywhere in it.
 *
 * A fixed half-hourly beat gets the worst of both: a node that reboots knows
 * nothing for up to thirty minutes, while a settled mesh still pays for beats
 * that find nothing. A matching digest is ~20 B per community node, so asking
 * often while it is worth asking is nearly free. */
#define NG_SYNC_FAST_MS  30000u
uint32_t s_syncBackoff = NG_SYNC_FAST_MS;
volatile bool s_syncNow = false;
/* `netgraph sync <hash>` — the one way left to run a record exchange while the
 * flood is mothballed. The CLI parses the hash and the netgraph task opens the
 * channel, because opening one from the cli task would touch session state that
 * has exactly one writer. */
uint8_t       s_syncTarget[RNSD_IDENT_HASH_LEN];
volatile bool s_syncTargetSet = false;

void ngSend(int h, uint16_t mt, const uint8_t* pl, size_t n) {
    uint8_t f[2 + NG_CHAN_MDU];
    if (h < 0 || n > NG_CHAN_MDU) return;
    f[0] = (uint8_t)(mt >> 8);
    f[1] = (uint8_t)mt;
    if (n) std::memcpy(f + 2, pl, n);
    itsSend(h, f, n + 2, pdMS_TO_TICKS(500));
}

/* Every send on a session goes through here, so `sent_msgs` really is what we
 * have handed rnsd and the window below means something. */
void ngSendS(Sess& s, uint16_t mt, const uint8_t* pl, size_t n) {
    ngSend(s.handle, mt, pl, n);
    s.sent_msgs++;
}

/** How many messages are sitting in rnsd's channel outbox: what we handed it,
 *  less what its reliability engine has accepted. rnsd's outbox is bounded and
 *  DROPS past the bound, so this is the difference between a backfill arriving
 *  and a backfill mostly evaporating. */
#define NG_SEND_WINDOW 8
int ngInFlight(Sess& s) {
    if (!s.tag[0]) return 0;                  /* no tag to ask about — do not throttle */
    char k[64];
    std::snprintf(k, sizeof k, "rnsd.chan.%s.tx_msgs", s.tag);
    int32_t d = (int32_t)(s.sent_msgs - (uint32_t)storageGetInt(k, 0));
    return d > 0 ? (int)d : 0;
}

void ngSendDone(Sess& s) {
    if (s.sent_done) return;
    ngSendS(s, NG_MT_DONE, nullptr, 0);
    s.sent_done = true;
}

/** Every (origin, seq) we hold, chunked to the channel MDU. Full 16-byte
 *  origins: a false match here silently loses an update, and the cost is only
 *  ~20 B per community node on an exchange that runs twice an hour against one
 *  neighbour. A node holding nothing still sends one empty digest — that is how
 *  it asks for the world. */
void ngSendDigest(Sess& s) {
    uint8_t pl[4 + NG_DIGEST_PER_MSG * 20];
    int total = 0;
    for (auto& r : s_recs) if (r.used) total++;

    int sent = 0, i = 0;
    for (;;) {
        int inThis = 0;
        size_t o = 4;
        while (i < NG_MAX_RECORDS && inThis < NG_DIGEST_PER_MSG) {
            if (s_recs[i].used) {
                std::memcpy(pl + o, s_recs[i].origin, 16); o += 16;
                uint32_t q = s_recs[i].seq;
                pl[o++] = (uint8_t)q;         pl[o++] = (uint8_t)(q >> 8);
                pl[o++] = (uint8_t)(q >> 16); pl[o++] = (uint8_t)(q >> 24);
                inThis++;
            }
            i++;
        }
        pl[0] = (uint8_t)total; pl[1] = (uint8_t)(total >> 8);
        pl[2] = (uint8_t)sent;  pl[3] = (uint8_t)(sent >> 8);
        ngSendS(s, NG_MT_DIGEST, pl, o);
        sent += inThis;
        if (sent >= total || i >= NG_MAX_RECORDS) break;
    }
}

void ngSendRecord(Sess& s, int slot) {
    const Rec& r = s_recs[slot];
    uint8_t pl[22 + NG_PART_PAYLOAD];
    int parts = (int)((r.len + NG_PART_PAYLOAD - 1) / NG_PART_PAYLOAD);
    if (parts < 1) parts = 1;
    for (int p = 0; p < parts; p++) {
        size_t off = (size_t)p * NG_PART_PAYLOAD;
        size_t take = r.len - off;
        if (take > NG_PART_PAYLOAD) take = NG_PART_PAYLOAD;
        std::memcpy(pl, r.origin, 16);
        pl[16] = (uint8_t)r.seq;         pl[17] = (uint8_t)(r.seq >> 8);
        pl[18] = (uint8_t)(r.seq >> 16); pl[19] = (uint8_t)(r.seq >> 24);
        pl[20] = (uint8_t)parts;
        pl[21] = (uint8_t)p;
        std::memcpy(pl + 22, r.bytes + off, take);
        ngSendS(s, NG_MT_PART, pl, 22 + take);
    }
}

void ngQueueRecord(Sess& s, int slot) {
    if (s.qn >= NG_MAX_RECORDS) return;
    s.q[s.qn++] = (int16_t)slot;
}

/** Hand rnsd as much of the queue as its outbox can hold, then DONE when there
 *  is nothing left. Called from the task loop and after every received message,
 *  so a drained window refills within a tick. */
void ngSessPump(Sess& s) {
    while (s.qi < s.qn) {
        if (ngInFlight(s) >= NG_SEND_WINDOW) return;
        int slot = s.q[s.qi++];
        if (slot >= 0 && slot < NG_MAX_RECORDS && s_recs[slot].used) ngSendRecord(s, slot);
        s.active_ms = nowMs();
    }
    s.qn = s.qi = 0;
    if (s.want_done) { s.want_done = false; ngSendDone(s); }
    /* The initiator closes the channel once both sides are finished — but not
     * the instant the peer's DONE lands: a Channel message is retransmitted
     * until the peer proves it, and tearing the link down while our own last
     * records were still going out would kill them. Linger, then close. */
    if (s.initiator && s.peer_done && s.sent_done && !s.close_at)
        s.close_at = nowMs() + 3000;
}

void ngSendWant(Sess& s, const uint8_t (*origins)[16], int n) {
    uint8_t pl[1 + NG_WANT_PER_MSG * 16];
    int i = 0;
    while (i < n) {
        int inThis = n - i > NG_WANT_PER_MSG ? NG_WANT_PER_MSG : n - i;
        pl[0] = (uint8_t)inThis;
        for (int k = 0; k < inThis; k++) std::memcpy(pl + 1 + 16*k, origins[i + k], 16);
        ngSendS(s, NG_MT_WANT, pl, 1 + 16 * inThis);
        i += inThis;
    }
}

/** The peer's digest is complete: push what it lacks, ask for what we lack,
 *  then say we are finished. */
void ngServeDigest(Sess& s) {
    for (int i = 0; i < NG_MAX_RECORDS; i++) {
        if (!s_recs[i].used) continue;
        bool theirs = false;
        for (int k = 0; k < s.dig_n; k++) {
            if (std::memcmp(s.dig[k].o, s_recs[i].origin, 16) != 0) continue;
            theirs = true;
            if (s.dig[k].seq < s_recs[i].seq) theirs = false;   /* they hold older */
            break;
        }
        if (!theirs) ngQueueRecord(s, i);
    }

    static uint8_t want[NG_MAX_RECORDS][16];   /* off the stack: one task, one at a time */
    int nw = 0;
    for (int k = 0; k < s.dig_n && nw < NG_MAX_RECORDS; k++) {
        int i = recFind(s.dig[k].o);
        /* Also ask for an origin we hold at the SAME seq but only abridged —
         * the peer may hold the full record the announce could not carry. */
        if (i < 0 || s_recs[i].seq < s.dig[k].seq ||
            (s_recs[i].seq == s.dig[k].seq && s_recs[i].abridged))
            std::memcpy(want[nw++], s.dig[k].o, 16);
    }
    if (nw) ngSendWant(s, want, nw);
    /* DONE is a promise that nothing more is coming, so it waits behind the
     * queued records rather than racing them. */
    s.want_done = true;
    ngSessPump(s);
}

/** The interval to wait, less up to a quarter of it. Nodes that came up
 *  together and back off in step would otherwise dial each other at the same
 *  instant forever, each one's exchange resetting the other's clock to the same
 *  phase — the jitter is what lets a settled mesh spread out. */
uint32_t ngBeatDelay() {
    uint32_t j = s_syncBackoff / 4;
    return s_syncBackoff - (j ? esp_random() % j : 0);
}

/** Fold a finished exchange into the beat — ours OR a neighbour's.
 *
 *  What an exchange measures is whether this node and one other agreed, and
 *  which of them dialled does not change the answer. A mesh where everybody
 *  syncs everybody would otherwise pay for it twice: each node initiates on its
 *  own clock while being visited on everyone else's, and the visits — which
 *  already told it everything — do nothing to postpone the next dial.
 *
 *  Productive exchanges HALVE the interval rather than resetting it to the
 *  floor. One record arriving is not evidence that the whole community is in
 *  flux, and slamming back to 30 s meant a single update anywhere restarted the
 *  entire ramp — a settled mesh could never climb out of it. */
void ngBeatFrom(uint16_t ingested) {
    uint32_t ceiling = (uint32_t)cfgSyncMin() * 60000u;
    if (ceiling < NG_SYNC_FAST_MS) ceiling = NG_SYNC_FAST_MS;
    if (ingested) {
        s_syncBackoff /= 2;
        if (s_syncBackoff < NG_SYNC_FAST_MS) s_syncBackoff = NG_SYNC_FAST_MS;
    }
    else if (s_syncBackoff < ceiling) s_syncBackoff *= 2;
    if (s_syncBackoff > ceiling) s_syncBackoff = ceiling;
    s_nextSync = nowMs() + ngBeatDelay();
}

void ngSessClose(Sess& s) {
    if (!s.used) return;
    int h = s.handle;
    bool init = s.initiator;
    bool spoke = s.sent_done || s.ingested;
    uint16_t got = s.ingested;
    s.used = false;
    s.handle = -1;
    if (h >= 0) itsDisconnect(h);
    if (init) s_outState = NG_OUT_IDLE;
    /* A responder counts only once it actually answered: a link that died
     * during establishment says nothing about whether anyone agrees. */
    if (init || spoke) ngBeatFrom(got);
}

void ngSessMsg(Sess& s, uint16_t mt, const uint8_t* pl, size_t n) {
    switch (mt) {
        case NG_MT_DIGEST: {
            if (n < 4) break;
            uint16_t total = rd16(pl);
            uint16_t off   = rd16(pl + 2);
            int entries = (int)((n - 4) / 20);
            s.dig_total = total;
            if (off == 0) s.dig_n = 0;
            for (int i = 0; i < entries && s.dig_n < NG_MAX_RECORDS; i++) {
                std::memcpy(s.dig[s.dig_n].o, pl + 4 + 20*i, 16);
                s.dig[s.dig_n].seq = rd32(pl + 4 + 20*i + 16);
                s.dig_n++;
            }
            /* The cap is the same on both sides, so a peer can never announce
             * more entries than we can hold — but stop waiting for entries that
             * would not fit rather than stalling the exchange if it does. */
            if (s.dig_n >= total || s.dig_n >= NG_MAX_RECORDS) ngServeDigest(s);
            break;
        }
        case NG_MT_WANT: {
            if (n < 1) break;
            int cnt = pl[0];
            if (1 + (size_t)cnt * 16 > n) break;
            for (int i = 0; i < cnt; i++) {
                int slot = recFind(pl + 1 + 16*i);
                if (slot >= 0) ngQueueRecord(s, slot);
            }
            s.want_done = true;
            ngSessPump(s);
            break;
        }
        case NG_MT_PART: {
            if (n < 22) break;
            uint8_t parts = pl[20], part = pl[21];
            if (parts == 0 || part >= parts) break;
            if (part == 0) {
                s.asm_active = true;
                std::memcpy(s.asm_origin, pl, 16);
                s.asm_seq   = rd32(pl + 16);
                s.asm_parts = parts;
                s.asm_next  = 0;
                s.asm_len   = 0;
            }
            if (!s.asm_active || part != s.asm_next ||
                std::memcmp(s.asm_origin, pl, 16) != 0) { s.asm_active = false; break; }
            size_t take = n - 22;
            if (s.asm_len + take > sizeof s.asm_buf) { s.asm_active = false; break; }
            std::memcpy(s.asm_buf + s.asm_len, pl + 22, take);
            s.asm_len += (uint16_t)take;
            s.asm_next++;
            if (s.asm_next == s.asm_parts) {
                s.asm_active = false;
                if (ngIngest(s.asm_buf, s.asm_len, nullptr, 0)) {
                    s.ingested++;
                    verb("sync: took record %02x%02x… seq=%u",
                         s.asm_origin[0], s.asm_origin[1], (unsigned)s.asm_seq);
                }
            }
            break;
        }
        case NG_MT_DONE:
            /* Channel messages arrive in order, so the peer's WANT — if it sent
             * one — is already answered by the time this lands. Nothing further
             * from us either, once whatever we queued for it has gone out. */
            s.peer_done = true;
            s.want_done = true;
            ngSessPump(s);
            break;
        default:
            break;   /* an unknown msgtype is skipped, never fatal */
    }
}

void ngSessDrain(Sess& s) {
    PSRAM_BSS static uint8_t buf[2 + NG_CHAN_MDU + 64];
    for (;;) {
        /* Re-checked each round: handling DONE closes the session from inside
         * the loop, and the handle is gone the moment it does. */
        if (!s.used || s.handle < 0) return;
        size_t n = itsRecv(s.handle, buf, sizeof buf, 0);
        if (n < 2) return;
        s.active_ms = nowMs();
        ngSessMsg(s, (uint16_t)((buf[0] << 8) | buf[1]), buf + 2, n - 2);
    }
}

int sessAlloc() {
    for (int i = 0; i < NG_INBOUND_MAX; i++) if (!s_sess[i].used) return i;
    return -1;
}

int onInboxConnect(int handle, const void* data, size_t len) {
    int i = sessAlloc();
    if (i < 0) { warn("no free sync session — rejecting"); return -1; }
    Sess& s = s_sess[i];
    s = Sess{};
    s.used = true;
    s.handle = handle;
    s.active_ms = nowMs();
    /* rnsd names the channel it just accepted; the send window needs that name
     * to read how much of what we handed it has actually left. The responder is
     * the side that pushes a whole backfill, so this is the side that matters. */
    if (data && len >= sizeof(rnsd_link_incoming_t))
        safeStrncpy(s.tag, ((const rnsd_link_incoming_t*)data)->tag, sizeof s.tag);
    return i;
}

void onInboxRecv(int handle, size_t) {
    for (int i = 0; i < NG_INBOUND_MAX; i++)
        if (s_sess[i].used && s_sess[i].handle == handle) { ngSessDrain(s_sess[i]); return; }
}

void onInboxDisconnect(int ref) {
    if (ref < 0 || ref >= NG_INBOUND_MAX) return;
    if (!s_sess[ref].used) return;
    /* The usual end of an inbound exchange: the initiator closes its link once
     * both sides are done, so this — not the idle timeout — is where a
     * neighbour's visit gets folded into our own beat. */
    bool spoke = s_sess[ref].sent_done || s_sess[ref].ingested;
    uint16_t got = s_sess[ref].ingested;
    s_sess[ref].used = false;
    s_sess[ref].handle = -1;
    if (spoke) ngBeatFrom(got);
}

void onOutRecv(int, size_t)  { if (s_sess[NG_SESS_OUT].used) ngSessDrain(s_sess[NG_SESS_OUT]); }
void onOutDisc(int)          { Sess& s = s_sess[NG_SESS_OUT];
                               s.used = false; s.handle = -1;
                               s_outState = NG_OUT_IDLE; }

/* ── partner selection ──
 *
 * A partner is a neighbour: hops == 1, and known by the netgraph destination
 * its own announce arrived on. One whose destination sits on a medium other
 * than LoRa is preferred — a backfill is thousands of bytes, and a radio is the
 * one place where that is expensive. */
struct PartnerScan { const uint8_t* dest; bool lora; };

void partnerIfaceCb(const rnsd_peer_t* p, void* vctx) {
    PartnerScan* s = (PartnerScan*)vctx;
    if (std::memcmp(p->dest, s->dest, RNSD_DEST_HASH_LEN) != 0) return;
    char cls[16];
    ifaceClass(p->iface, cls, sizeof cls);
    if (std::strcmp(cls, "lora") == 0) s->lora = true;
}

bool ngPickPartner(uint8_t out[RNSD_DEST_HASH_LEN]) {
    int cand[NG_MAX_RECORDS], n = 0;
    for (int i = 0; i < NG_MAX_RECORDS; i++)
        if (s_recs[i].used && !s_recs[i].mine && s_recs[i].have_dest && s_recs[i].hops == 1)
            cand[n++] = i;
    if (!n) return false;

    int best = -1;
    for (int k = 0; k < n; k++) {
        int i = cand[(s_partnerRot + k) % n];
        PartnerScan sc{ s_recs[i].dest, false };
        rnsdPeersForEach("", partnerIfaceCb, &sc);
        if (!sc.lora) { best = i; break; }
        if (best < 0) best = i;
    }
    s_partnerRot = (s_partnerRot + 1) % n;
    std::memcpy(out, s_recs[best].dest, RNSD_DEST_HASH_LEN);
    return true;
}

bool ngOpenChannel(const uint8_t dest[RNSD_DEST_HASH_LEN], bool fetch, const uint8_t* origin) {
    if (s_outState != NG_OUT_IDLE) return false;
    static int seq = 0;
    std::snprintf(s_outTag, sizeof s_outTag, "%s%d", NG_TAGNAME, seq++ & 0xff);
    int h = rnsdChannelOpen(dest, NG_ASPECT, /*identity_key*/"", s_outTag,
                            /*path_timeout_ms*/0, /*link_timeout_ms*/30000,
                            /*ref*/0, onOutRecv, onOutDisc);
    if (h < 0) return false;
    Sess& s = s_sess[NG_SESS_OUT];
    s = Sess{};
    s.used = true;
    s.initiator = true;
    s.handle = h;
    s.active_ms = nowMs();
    safeStrncpy(s.tag, s_outTag, sizeof s.tag);
    s.want_only = fetch;
    if (fetch && origin) std::memcpy(s.want_origin, origin, RNSD_IDENT_HASH_LEN);
    s_outState  = NG_OUT_CONNECTING;
    return true;
}

/** Drive the outbound half: wait for the channel to go active, then open the
 *  exchange. Never blocks — a sync that stalls is dropped and retried on the
 *  next beat, because nothing may wait on one. */
void ngOutTick() {
    if (s_outState == NG_OUT_IDLE) return;
    Sess& s = s_sess[NG_SESS_OUT];
    if (s.close_at && (int32_t)(nowMs() - s.close_at) >= 0) { ngSessClose(s); return; }
    if ((uint32_t)(nowMs() - s.active_ms) > NG_SYNC_IDLE_MS) {
        info("sync: idle timeout");
        ngSessClose(s);
        return;
    }
    if (s_outState == NG_OUT_RUNNING) { ngSessPump(s); return; }
    if (s_outState != NG_OUT_CONNECTING) return;

    char key[64], st[24] = {};
    std::snprintf(key, sizeof key, "rnsd.chan.%s.state", s_outTag);
    storageGetStr(key, st, sizeof st, "");
    if (std::strcmp(st, "failed") == 0) { ngSessClose(s); return; }
    if (std::strcmp(st, "active") != 0) return;

    s_outState = NG_OUT_RUNNING;
    if (s.want_only) {
        uint8_t one[1][16];
        std::memcpy(one[0], s.want_origin, 16);
        ngSendWant(s, one, 1);
        ngSendDone(s);
    } else {
        ngSendDigest(s);
    }
}

/* Uncalled while the flood is mothballed — plans/netgraph.md, "The sync
 * engine". Partner selection needs a path to a peer's netgraph.discovery
 * destination and no announce supplies one; `netgraph sync <hash>` goes
 * through ngManualSync below instead. */
[[maybe_unused]] void ngSyncBeat() {
    if (s_outState != NG_OUT_IDLE) return;

    /* A targeted fetch first: it is one message against a known gap, and it is
     * what upgrades an abridged announce to the whole record. */
    uint32_t now = nowMs();
    for (auto& f : s_fetch) {
        if (!f.used || (int32_t)(now - f.next_ms) < 0) continue;
        int i = recFind(f.origin);
        if (i >= 0 && !s_recs[i].abridged) { f.used = false; continue; }
        f.next_ms = now + NG_FETCH_BACKOFF_MS;
        if (ngOpenChannel(f.dest, /*fetch=*/true, f.origin)) return;
    }

    uint8_t dest[RNSD_DEST_HASH_LEN];
    if (!ngPickPartner(dest)) return;
    ngOpenChannel(dest, /*fetch=*/false, nullptr);
}

/** `netgraph sync <hash>`: derive the peer's netgraph.discovery destination from
 *  an identity hash we were handed and open one channel to it.
 *
 *  Deriving the address always works; reaching it needs a path, and while the
 *  flood is mothballed nothing announces netgraph.discovery, so nothing on the
 *  mesh holds one. Failing cleanly and saying which half failed is the whole
 *  contract here — this verb exists to be usable the day a relay does. */
void ngManualSync() {
    if (!s_syncTargetSet) return;
    s_syncTargetSet = false;

    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hex(h, s_syncTarget, RNSD_IDENT_HASH_LEN);

    uint8_t dest[RNSD_DEST_HASH_LEN];
    if (!rnsdDestinationHashFromIdentityHash(s_syncTarget, "netgraph", "discovery", dest)) {
        warn("sync: could not derive a netgraph.discovery destination for %s", h);
        return;
    }
    if (!ngOpenChannel(dest, /*fetch=*/false, nullptr))
        warn("sync: no channel to %s — no path to its netgraph.discovery, "
             "or an exchange is already in flight", h);
    else
        info("sync: opening a channel to %s", h);
}

/* ═══════════════════════════ the community identity ═══════════════════════════
 *
 * ONE KEYPAIR ADMITS THE WHOLE COMMUNITY. Derived from a name and a passphrase,
 * so it is reproducible on every node that knows both, with nothing exchanged
 * and nothing per-peer to configure:
 *
 *     salt = "netgraph-community:" ‖ s.netgraph.community
 *     key  = PBKDF2-HMAC-SHA256(s.netgraph.passphrase, salt, iters, 64 B)
 *
 * Identity::load_private_key takes those 64 bytes as 32 X25519 followed by 32
 * Ed25519, so the derivation lands as 128 hex characters in
 * `secrets.netgraph.identity` — secrets tier, persisted, never synced to the
 * browser — and that key NAME is what rnsdLinkIdentify is handed.
 *
 * THE PASSPHRASE IS AN ORDINARY SETTING, not a secret. Every node in the
 * community holds it, so a tier that hides it from the operator who has to type
 * it into the next node buys nothing. The DERIVED key stays in the secrets
 * tier — it is a private key, and there is no reason for the browser to hold
 * one — but the passphrase itself is editable in the settings pane like any
 * other field.
 *
 * It is still the community's access credential rather than a network name:
 * anyone holding it can query every node that trusts it and can identify as the
 * community to third parties. The slowness of the derivation is what stands
 * between a weak passphrase and an offline attack, and the community identity
 * hash becomes public the moment we announce.
 *
 * The community key is what IDENTIFIES, never what addresses. Building the
 * management destination on it would give every community node the same
 * destination hash, and a management query is always about one specific node. */

#define NG_COMMUNITY_KEY  "secrets.netgraph.identity"
#define NG_COMMUNITY_PASS "s.netgraph.passphrase"

/* Something the community depends on moved: the name, the passphrase, or the
 * granted hashes. Set from whichever task saw the change; the netgraph task
 * re-derives, re-pushes the allow list and re-airs the membership announce. */
volatile bool s_communityDirty = false;

/* The stock management address, split the way rnsd splits an aspect: app name
 * up to the first dot, the rest after it. */
#define NG_RM_APP     "rnstransport"
#define NG_RM_ASPECT  "remote.management"
#define NG_RM_FULL    "rnstransport.remote.management"
#define NG_RM_TAG     "ngrm"

/* NOT MEASURED YET. The plan asks for the figure the slowest supported board
 * can afford once at boot, written here rather than a round number — that
 * measurement needs a board, so this is a placeholder chosen to be defensible
 * rather than accurate, and the first bring-up on the slowest target should
 * replace it with what was actually timed. Raising it later re-derives a
 * DIFFERENT key, so every node has to change together — the same "all nodes
 * flash together" rule the wire format lives by. */
#define NG_PBKDF2_ITERS 20000

/** Derive and persist the community identity, if a community and passphrase are
 *  configured and the stored key does not already match them. Returns true when
 *  a community identity is available at NG_COMMUNITY_KEY. */
bool ngCommunityEnsure() {
    char community[64];
    storageGetStr("s.netgraph.community", community, sizeof community, "");
    if (!community[0]) return false;

    char pass[128];
    storageGetStr(NG_COMMUNITY_PASS, pass, sizeof pass, "");
    if (!pass[0]) return false;

    /* Re-derive only when the inputs changed. The derivation is deliberately
     * expensive, so doing it on every boot for a community that has not moved
     * would be paying the cost of the defence twice over for nothing. */
    char salt[96];
    std::snprintf(salt, sizeof salt, "netgraph-community:%s", community);
    uint8_t want_tag[RNSD_HASH_LEN];
    {
        char material[256];
        std::snprintf(material, sizeof material, "%s|%s|%d", salt, pass, NG_PBKDF2_ITERS);
        rnsdSha256((const uint8_t*)material, std::strlen(material), want_tag);
    }
    char tag_hex[2 * RNSD_HASH_LEN + 1];
    hex(tag_hex, want_tag, RNSD_HASH_LEN);
    char have_tag[2 * RNSD_HASH_LEN + 1];
    storageGetStr("s.netgraph.community_tag", have_tag, sizeof have_tag, "");
    if (std::strcmp(tag_hex, have_tag) == 0 && rnsdIdentityExists(NG_COMMUNITY_KEY))
        return true;

    uint8_t key[64];
    /* IDF's mbedTLS sets MBEDTLS_DEPRECATED_REMOVED, which compiles out the
     * un-suffixed mbedtls_pkcs5_pbkdf2_hmac — the _ext variant is the one that
     * exists. */
    uint32_t t0 = nowMs();
    int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                           (const unsigned char*)pass, std::strlen(pass),
                                           (const unsigned char*)salt, std::strlen(salt),
                                           NG_PBKDF2_ITERS, sizeof key, key);
    uint32_t took = nowMs() - t0;
    if (rc != 0) { err("community: PBKDF2 failed (%d)", rc); return false; }

    char hexkey[2 * sizeof(key) + 1];
    hex(hexkey, key, sizeof key);
    storageSet(NG_COMMUNITY_KEY, hexkey);
    storageSet("s.netgraph.community_tag", tag_hex);
    std::memset(key, 0, sizeof key);
    std::memset(pass, 0, sizeof pass);

    uint8_t idh[RNSD_IDENT_HASH_LEN];
    if (rnsdIdentityHash(NG_COMMUNITY_KEY, idh)) {
        char h[2 * RNSD_IDENT_HASH_LEN + 1];
        hex(h, idh, RNSD_IDENT_HASH_LEN);
        info("community '%s' identity %s (PBKDF2 %d iters took %ums)",
             community, h, NG_PBKDF2_ITERS, (unsigned)took);
        /* THE ONE THING AN OPERATOR HAS TO CARRY ELSEWHERE. A stock Reticulum
         * node knows nothing about communities; what it understands is a hash
         * in `remote_management_allowed`. So the hash is printed with what to
         * do with it, in both places an operator might be looking. */
        info("Ask remote nodes that do not have NetGraph to enable network "
             "management and to allow access to this identity to make them "
             "answer queries by this community.");
    }
    return true;
}

/** The community identity hash, or false where no community is configured.
 *  `out` may be null for a bare "is there one?" — the failure line below asks
 *  exactly that and has nowhere to put the answer. */
bool ngCommunityHash(uint8_t* out) {
    char community[64];
    storageGetStr("s.netgraph.community", community, sizeof community, "");
    if (!community[0]) return false;
    uint8_t tmp[RNSD_IDENT_HASH_LEN];
    if (!rnsdIdentityHash(NG_COMMUNITY_KEY, out ? out : tmp)) return false;
    return true;
}

/** Publish the community identity, so the settings pane can show it and an
 *  operator can copy it into somebody else's `remote_management_allowed`.
 *  Empty where no community is configured — the pane hides the row rather than
 *  showing a hash of nothing. */
void ngPublishCommunity() {
    uint8_t idh[RNSD_IDENT_HASH_LEN];
    char h[2 * RNSD_IDENT_HASH_LEN + 1] = "";
    if (ngCommunityHash(idh)) hex(h, idh, RNSD_IDENT_HASH_LEN);
    storageSet("netgraph.community.id", h);
}

/* ── what the management announce carries, and who can read it ──
 *
 *   no community          no app_data at all
 *   a community           encrypt_to_community(
 *                             issued:u32 LE ‖ flags:u8 ‖ namelen:u8 ‖ name ‖ sig:64)
 *
 * flags bit0 = this node is an RNS transport node.
 *
 * ENCRYPTED OR NOTHING. A node's hostname and whether it forwards are facts
 * about somebody's device, and a management destination announces on every
 * interface every couple of hours forever — in clear text that is a standing
 * broadcast of the community's inventory to anyone within earshot. Encrypting
 * to the community identity means every member can read it, because every
 * member holds that private key, and nobody else can. A node with no community
 * has no key to encrypt with and no community to describe itself to, so it
 * announces the service and says nothing else. It is still perfectly askable:
 * the allow list, not the announce, is what grants anything.
 *
 * THE SIGNATURE STAYS, INSIDE. Encryption alone would WEAKEN membership rather
 * than prove it — rnsdEncryptFor is ephemeral ECDH to a public key, so anyone
 * holding the community PUBLIC key can mint a valid token, and we hand that key
 * out ourselves every time we identify to a node we crawl. The signature is
 * what requires the private key, and it covers the announcer's identity hash
 * along with the body, so one community's frame cannot be replayed as another's.
 *
 * THE NAME IS HERE BECAUSE THIS IS THE ONLY PLACE IT CAN BE. A device's name
 * belongs to the device, and the only address that IS the device is its
 * transport identity — which is exactly what this destination is built on. The
 * display name in an LXMF announce belongs to a person, sits on a different
 * identity, and nothing links the two on a medium that cannot attribute a
 * packet to a node. Without this, a graph of devices is a graph of hex — which
 * is what a community-less deployment now gets, and the price of the rule.
 *
 * The transport flag rides along for the same reason: it is a property of the
 * device, the `heard` path that used to carry it is suppressed for every
 * neighbour a route already covers, and whether a node forwards for others is
 * the one property that changes what the graph MEANS.
 *
 * Stock clients ignore app_data on this destination, so none of this costs
 * compatibility. */
#define NG_ANN_MIN       (4 + 1 + 1)
#define NG_ANN_TRANSPORT 0x01
#define NG_ANN_PLAIN_MAX (NG_ANN_MIN + RNSD_PEER_NAME_MAX + RNSD_SIG_LEN)
#define NG_ANN_MAX       (NG_ANN_PLAIN_MAX + RNSD_ENCRYPT_OVERHEAD)

size_t ngAnnounceCompose(uint8_t* out, size_t outsz) {
    if (!s_haveSelf || outsz < NG_ANN_MAX) return 0;

    /* No community, nothing to say. Not a degraded frame — an absent one. */
    uint8_t chash[RNSD_IDENT_HASH_LEN];
    if (!ngCommunityHash(chash)) return 0;
    uint8_t pub[RNSD_PUBKEY_LEN];
    if (!rnsdIdentityPubkey(NG_COMMUNITY_KEY, pub)) return 0;

    char name[RNSD_PEER_NAME_MAX];
    ngOwnName(name, sizeof name);
    size_t nlen = std::strlen(name);

    uint8_t plain[NG_ANN_PLAIN_MAX];
    uint32_t issued = nowUnix();
    size_t   n = 0;
    plain[n++] = (uint8_t)issued;
    plain[n++] = (uint8_t)(issued >> 8);
    plain[n++] = (uint8_t)(issued >> 16);
    plain[n++] = (uint8_t)(issued >> 24);
    plain[n++] = storageGetInt("s.rnsd.transport_enabled", 0) ? NG_ANN_TRANSPORT : 0;
    plain[n++] = (uint8_t)nlen;
    std::memcpy(plain + n, name, nlen);
    n += nlen;

    /* Signed over our identity followed by everything written so far, so the
     * name is inside the signature rather than merely beside it. */
    uint8_t material[RNSD_IDENT_HASH_LEN + NG_ANN_PLAIN_MAX];
    std::memcpy(material, s_self, RNSD_IDENT_HASH_LEN);
    std::memcpy(material + RNSD_IDENT_HASH_LEN, plain, n);
    if (!rnsdSign(NG_COMMUNITY_KEY, material, RNSD_IDENT_HASH_LEN + n, plain + n)) {
        warn("membership: signing failed — announcing nothing");
        return 0;
    }
    n += RNSD_SIG_LEN;

    /* No destination to name, so no ratchet: the community identity hosts
     * nothing. The token is readable by anyone who later obtains the community
     * key, which is inherent to a passphrase every member already shares. */
    size_t tok = 0;
    if (!rnsdEncryptFor(pub, nullptr, plain, n, out, &tok)) {
        warn("membership: encryption failed — announcing nothing");
        return 0;
    }
    std::memset(plain, 0, sizeof plain);
    return tok;
}

void ngMembershipPublish() {
    uint8_t app[NG_ANN_MAX];
    size_t  n = ngAnnounceCompose(app, sizeof app);
    rnsdRemoteManagementAnnounceData(n ? app : nullptr, n);
}

/** What a management announce told us about the node that sent it. */
struct AnnOpened {
    bool        member;               /* decrypted AND the signature checked */
    bool        transport;
    char        name[RNSD_PEER_NAME_MAX];
    /* Why it did not open, for the log. A static string, never allocated. */
    const char* why;
};

/** Open a management announce: decrypt with the community key, then verify the
 *  signature inside. Both must succeed — decryption alone says only that the
 *  sender knew our community's public key, which is not a secret we can keep.
 *
 *  False is the ordinary case, not an error: a stock node, or a node of some
 *  other community. It is still askable, and the caller records it as such. */
bool ngAnnounceOpen(const uint8_t* app, size_t n, const uint8_t* who, AnnOpened* out) {
    *out = AnnOpened{};
    if (!app || !who || !n) { out->why = "empty"; return false; }
    /* Oversize is its own answer, and a distinct one: it says the frame reached
     * us longer than anything we could have sent, which is a transport
     * question rather than a key question. */
    if (n > NG_ANN_MAX) { out->why = "oversize"; return false; }

    uint8_t chash[RNSD_IDENT_HASH_LEN];
    if (!ngCommunityHash(chash)) { out->why = "no community here"; return false; }

    uint8_t plain[NG_ANN_MAX];                   /* the API wants room for n */
    size_t  pn = sizeof plain;
    if (!rnsdDecryptSelf(NG_COMMUNITY_KEY, nullptr, app, n, plain, &pn)) {
        /* Either it is not ours, or it did not arrive whole. The two are
         * indistinguishable from here — an authenticated token fails the same
         * way for a wrong key and for a lost byte — which is why the length is
         * logged beside this. */
        out->why = "will not decrypt";
        return false;
    }
    if (pn < NG_ANN_MIN + RNSD_SIG_LEN) { out->why = "decrypted short"; return false; }

    size_t nlen = plain[5];
    size_t body = NG_ANN_MIN + nlen;
    if (body + RNSD_SIG_LEN != pn) { out->why = "bad shape"; return false; }

    uint8_t pub[RNSD_PUBKEY_LEN];
    if (!rnsdIdentityPubkey(NG_COMMUNITY_KEY, pub)) { out->why = "no community key"; return false; }
    uint8_t material[RNSD_IDENT_HASH_LEN + NG_ANN_MAX];
    std::memcpy(material, who, RNSD_IDENT_HASH_LEN);
    std::memcpy(material + RNSD_IDENT_HASH_LEN, plain, body);
    if (!rnsdVerify(pub, material, RNSD_IDENT_HASH_LEN + body, plain + body)) {
        out->why = "signature";
        return false;
    }

    out->member    = true;
    out->transport = (plain[4] & NG_ANN_TRANSPORT) != 0;
    char raw[RNSD_PEER_NAME_MAX];
    size_t k = nlen < sizeof raw - 1 ? nlen : sizeof raw - 1;
    std::memcpy(raw, plain + NG_ANN_MIN, k);
    raw[k] = '\0';
    sanitizeField(raw, out->name, sizeof out->name);
    return true;
}

/* ── who is a member, and who is askable ──
 *
 * Discovery costs nothing. Management destinations announce on the stock
 * two-hour beat, so every node offering the service advertises itself with its
 * key: subscribing to that aspect means each one arrives recallable and ready
 * for a visit, with no hash derivation and nothing configured.
 *
 * The announce table evicts by memory pressure and never by time, so an
 * unclaimed announce sits early on the eviction ladder — recalling a two-hourly
 * announce reliably means claiming it. */
int s_mgmtSub = -1;

void ngMemberNote(const uint8_t* id, const uint8_t* dest, bool member,
                  const char* name, bool transport,
                  const char* why, size_t app_n) {
    int slot = -1, oldest = -1;
    for (int i = 0; i < NG_MAX_MEMBERS; i++) {
        if (!s_members[i].used) { if (slot < 0) slot = i; continue; }
        if (std::memcmp(s_members[i].id, id, RNSD_IDENT_HASH_LEN) == 0) { slot = i; break; }
        if (oldest < 0 || s_members[i].heard < s_members[oldest].heard) oldest = i;
    }
    if (slot < 0) slot = oldest;
    if (slot < 0) return;
    Member& m = s_members[slot];
    /* All four read the PREVIOUS state, so they are taken before any of it is
     * overwritten below. */
    bool isNew     = !m.used || !m.member;
    bool renamed   = name && *name && std::strcmp(m.name, name) != 0;
    bool reflagged = m.used && m.transport != transport;
    bool wasOurs   = m.used && m.member;
    m.used = true;
    std::memcpy(m.id, id, RNSD_IDENT_HASH_LEN);
    std::memcpy(m.dest, dest, RNSD_DEST_HASH_LEN);
    m.member = member;
    m.transport = transport;
    /* An announce that carries no name does not erase the one we have: a node
     * that has not set a hostname yet is not a node that has been renamed to
     * nothing. */
    if (name && *name) safeStrncpy(m.name, name, sizeof m.name);
    m.heard = nowUnix();
    if (renamed) s_storeDirty = true;
    /* Claim it, or the next memory squeeze takes the announce and with it our
     * ability to reach the node without a fresh path request. */
    rnsdClaim(dest, RNSD_CLAIM_NETGRAPH, RNSD_CLAIM_EPHEMERAL,
              RNSD_CLAIM_LAYER_DIR, /*decay_s=*/6 * 3600);
    /* Say what the frame actually contained, not merely that one arrived. Every
     * field here has been wrong at least once, and each time the log said only
     * "member: <hash>" — which is consistent with the frame being read
     * perfectly and with it being read wrong, so it settled nothing. */
    /* A member that stops opening is the interesting event and the one the
     * old log could not show: it fired once on first sight and then went quiet,
     * so a node that opened at boot and never again looked identical to one
     * that opened every time. Log the transition in both directions, with the
     * app_data length — the length is what separates "not our community" from
     * "did not arrive whole", which an authenticated token cannot tell apart. */
    if (isNew || renamed || reflagged || wasOurs != member) {
        char h[2 * RNSD_IDENT_HASH_LEN + 1];
        hex(h, id, RNSD_IDENT_HASH_LEN);
        if (member)
            info("announce from %s: ours, %zu B, name=%s, transport=%d", h,
                 app_n, m.name[0] ? m.name : "(none)", transport ? 1 : 0);
        else
            info("announce from %s: not ours (%s), %zu B%s", h,
                 why ? why : "?", app_n,
                 m.name[0] ? " — keeping the name an earlier one gave" : "");
        s_storeDirty = true;
    }
}

/** Is this node one of ours, as its own management announce claimed? */
bool ngIsMember(const uint8_t* id) {
    for (int i = 0; i < NG_MAX_MEMBERS; i++)
        if (s_members[i].used && s_members[i].member &&
            std::memcmp(s_members[i].id, id, RNSD_IDENT_HASH_LEN) == 0) return true;
    return false;
}

void onMgmtAnnounce(int handle, size_t) {
    PSRAM_BSS static uint8_t buf[NG_ANN_HDR + 256];
    for (;;) {
        size_t n = itsRecv(handle, buf, sizeof buf, 0);
        if (n == 0) return;
        if (n < NG_ANN_HDR) continue;
        const uint8_t* dest  = buf + 1;
        const uint8_t* ident = buf + 17;
        const uint8_t* app   = buf + NG_ANN_HDR;
        size_t         an    = n - NG_ANN_HDR;
        if (s_haveSelf && std::memcmp(ident, s_self, RNSD_IDENT_HASH_LEN) == 0) continue;
        /* Everything the frame says is inside the encryption, so a node we
         * cannot open tells us only that it exists and offers the service —
         * which is enough to be worth crawling, and is exactly what a stock
         * node or another community's node is. Recorded either way; only the
         * name, the transport flag and membership need the key. */
        AnnOpened o;
        bool ours = ngAnnounceOpen(app, an, ident, &o);
        ngMemberNote(ident, dest, ours, ours ? o.name : "", ours && o.transport,
                     o.why, an);
    }
}

void onMgmtAnnounceDisc(int) { s_mgmtSub = -1; }

bool ngMgmtAnnounceSub() {
    if (s_mgmtSub >= 0) return true;
    rnsd_announces_connect_t req = {};
    safeStrncpy(req.aspect, NG_RM_FULL, sizeof req.aspect);
    s_mgmtSub = itsConnect("rnsd", RNSD_PORT_ANNOUNCES, &req, sizeof req,
                           pdMS_TO_TICKS(2000), /*ref*/0,
                           onMgmtAnnounce, onMgmtAnnounceDisc);
    if (s_mgmtSub < 0) { warn("management announce sub: connect failed"); return false; }
    return true;
}

/* ── the allow list ──
 *
 * What rnsd gates `/path` and `/status` on: the community identity hash, plus
 * whatever `s.netgraph.allow` grants individually. Each granted entry is one
 * 32-hex identity hash — the same form as stock `remote_management_allowed`,
 * so a line copies straight across in either direction.
 *
 * The list is a COLLECTION rather than a comma-separated string: the settings
 * pane binds rows to it, and every mutation arrives on a sentinel and is
 * validated here. Nothing else writes the array, so a malformed hash cannot get
 * in by any route. */
#define NG_MAX_ALLOW 16

int ngAllowCount() { return storageArrayCount("s.netgraph.allow."); }

std::string ngAllowField(int idx, const char* field) {
    char k[64];
    std::snprintf(k, sizeof k, "s.netgraph.allow.%d.%s", idx, field);
    return storageGetStr(k, "");
}

void ngPushAllowList() {
    static uint8_t allow[NG_MAX_ALLOW][RNSD_IDENT_HASH_LEN];
    int n = 0;

    if (ngCommunityHash(allow[n])) n++;

    int count = ngAllowCount();
    for (int i = 0; i < count && n < NG_MAX_ALLOW; i++) {
        std::string h = ngAllowField(i, "hash");
        if (unhex(h.c_str(), allow[n], RNSD_IDENT_HASH_LEN)) n++;
        else warn("allow: '%s' is not a %d-hex identity hash", h.c_str(),
                  (int)(2 * RNSD_IDENT_HASH_LEN));
    }
    rnsdRemoteManagementAllow(allow, n);
    if (!n) warn("serving remote management with an empty allow list — "
                 "no community configured and no hashes granted, so every "
                 "request will be refused");
}

/* ── the collection's sentinels ──
 *
 * The pane never touches the array; it writes `netgraph.allow.add` /
 * `.remove` and these are the only writers. A rejection is a sentence on
 * `netgraph.allow.error`, which the add form shows — which is why no UI parses
 * an identity hash. */

void ngAllowWrite(int idx, const std::string& id, const std::string& hash) {
    char k[64];
    std::snprintf(k, sizeof k, "s.netgraph.allow.%d.id",   idx); storageSet(k, id.c_str());
    std::snprintf(k, sizeof k, "s.netgraph.allow.%d.hash", idx); storageSet(k, hash.c_str());
}

std::string ngAllowNextId() {
    int best = 0, n = ngAllowCount();
    for (int i = 0; i < n; i++) {
        int v = std::atoi(ngAllowField(i, "id").c_str());
        if (v > best) best = v;
    }
    char buf[12];
    std::snprintf(buf, sizeof buf, "%d", best + 1);
    return buf;
}

void ngAllowAck() {
    static int ack = 0;
    storageSet("netgraph.allow.done", ++ack);
}

/** Normalized, or "" — trimmed, lower-cased, and only if it really is a
 *  32-character identity hash. */
std::string ngAllowNormalize(const std::string& raw) {
    std::string h;
    for (char c : raw) {
        if (std::isspace((unsigned char)c)) continue;
        h += (char)std::tolower((unsigned char)c);
    }
    uint8_t tmp[RNSD_IDENT_HASH_LEN];
    return unhex(h.c_str(), tmp, RNSD_IDENT_HASH_LEN) ? h : std::string();
}

void ngAllowAdd(const std::string& raw) {
    std::string h = ngAllowNormalize(raw);
    if (h.empty()) {
        char why[96];
        std::snprintf(why, sizeof why,
                      "Expected a %d-character identity hash.",
                      (int)(2 * RNSD_IDENT_HASH_LEN));
        storageSet("netgraph.allow.error", why);
        return;
    }
    int n = ngAllowCount();
    for (int i = 0; i < n; i++)
        if (ngAllowField(i, "hash") == h) {
            storageSet("netgraph.allow.error", "That identity is already allowed.");
            return;
        }
    if (n >= NG_MAX_ALLOW) {
        storageSet("netgraph.allow.error", "The allow list is full.");
        return;
    }
    storageBegin();
    ngAllowWrite(n, ngAllowNextId(), h);
    storageSet("netgraph.allow.error", "");
    storageEnd();
    ngAllowAck();
    s_communityDirty = true;
}

void ngAllowRemove(const std::string& id) {
    int n = ngAllowCount(), idx = -1;
    for (int i = 0; i < n; i++) if (ngAllowField(i, "id") == id) { idx = i; break; }
    if (idx < 0) { storageSet("netgraph.allow.error", "No such entry."); return; }
    storageBegin();
    for (int i = idx; i < n - 1; i++)
        ngAllowWrite(i, ngAllowField(i + 1, "id"), ngAllowField(i + 1, "hash"));
    char tail[64];
    std::snprintf(tail, sizeof tail, "s.netgraph.allow.%d", n - 1);
    storageUnset(tail);
    storageSet("netgraph.allow.error", "");
    storageEnd();
    ngAllowAck();
    s_communityDirty = true;
}

void ngAllowSentinel(const char* key, const char* val) {
    if (!val || !*val) return;
    if (std::strcmp(key, "netgraph.allow.add") == 0) {
        /* The add form submits its fields as one JSON object. */
        cJSON* o = cJSON_Parse(val);
        cJSON* h = o ? cJSON_GetObjectItem(o, "hash") : nullptr;
        ngAllowAdd(cJSON_IsString(h) ? h->valuestring : "");
        if (o) cJSON_Delete(o);
        storageSet("netgraph.allow.add", "");
    } else if (std::strcmp(key, "netgraph.allow.remove") == 0) {
        ngAllowRemove(val);
        storageSet("netgraph.allow.remove", "");
    }
}

/* ═══════════════════════════ asking: the client half ═══════════════════════════
 *
 *   us → any node running stock Reticulum
 *     ─ LINK ─────────────────────────────────►
 *     ─ IDENTIFY (community identity, or ours) ►   checked against their
 *     ─ REQUEST /path   ["table", nil, 1] ────►    remote_management_allowed
 *     ◄ RESPONSE [{hash, timestamp, via, hops, expires, interface}, …]
 *     ─ REQUEST /status [true] ───────────────►
 *     ◄ RESPONSE [stats-dict, link-count]
 *     ─ CLOSE ────────────────────────────────►   one visit, one Link
 *
 * ONE AT A TIME. A crawl is a sequence of visits, not a fan-out: the whole
 * design rests on it being cheap and polite, and a device that opened thirty
 * links at once would be neither. */

enum { NG_ASK_IDLE = 0, NG_ASK_PATH, NG_ASK_STATUS };

struct Ask {
    bool     used;
    uint8_t  target[RNSD_IDENT_HASH_LEN];
    char     tag[24];
    int      handle;
    int      req_id;
    uint8_t  stage;
    uint32_t deadline_ms;
    bool     crawling;      /* part of a pass; feeds the graph and the queue */
    bool     member;        /* its announce carried a community signature */
    int      rows;          /* what the /path answer yielded */
};
Ask s_ask;

void ngAskClose(bool ok) {
    if (!s_ask.used) return;
    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hex(h, s_ask.target, RNSD_IDENT_HASH_LEN);
    if (s_ask.handle >= 0) itsDisconnect(s_ask.handle);
    if (ok) info("ask %s: done, %d route%s", h, s_ask.rows, s_ask.rows == 1 ? "" : "s");
    s_ask = Ask{};
    s_ask.handle = -1;
}

/** Decode a `/path` table answer into crawl edges anchored at the node that
 *  answered. One hop only — see plans/netgraph.md: a node's one-hop answer is
 *  its adjacency list, and its two-hop answer is a reachability table, which is
 *  the quadratic term the crawl cannot afford. */
int ngAskTakePath(const uint8_t* buf, size_t n, const uint8_t* from, bool feed) {
    int rows = 0;
    try {
        MsgPack::ArrayReader a(buf, n);
        while (a.next()) {
            MsgPack::bin_t<uint8_t> dest;
            double hops = 0;
            std::string iface;
            MsgPack::MapReader m(a.value_ptr(), a.value_len());
            while (m.next()) {
                if      (m.key_is("hash"))      m.value_bin(dest);
                else if (m.key_is("hops"))      m.value_num(hops);
                else if (m.key_is("interface")) m.value_str(iface);
                else                            m.skip_value();
            }
            a.advance(m.finish());
            if (dest.size() != RNSD_DEST_HASH_LEN) continue;
            if ((int)hops != 1) continue;      /* only what it is adjacent to */
            rows++;
            if (!feed) continue;
            /* Drop what we can already see is not a device. A busy node's table
             * is mostly application addresses, and holding them costs the store
             * space a later node's real adjacencies will want. An address we
             * simply have not heard of is KEPT — an announce may arrive before
             * the next resolve and make it placeable. */
            int di = ngDirIndexForDest(dest.data());
            if (di >= 0 && !s_dir[di].isNode) continue;
            ngCrawlNote(from, dest.data(), iface.c_str());
        }
    } catch (const std::exception& e) {
        warn("ask: /path answer did not decode: %s", e.what());
        return rows;
    }
    return rows;
}

/** Decode a `/status` answer far enough to log what the node runs. The
 *  interface list is decoration the crawl may not finish receiving over LoRa,
 *  which is why it is asked second and nothing depends on it. */
void ngAskTakeStatus(const uint8_t* buf, size_t n, const uint8_t* from) {
    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hex(h, from, RNSD_IDENT_HASH_LEN);
    try {
        MsgPack::ArrayReader top(buf, n);
        if (!top.next()) return;
        MsgPack::MapReader stats(top.value_ptr(), top.value_len());
        int nifs = 0;
        while (stats.next()) {
            if (!stats.key_is("interfaces")) { stats.skip_value(); continue; }
            MsgPack::ArrayReader ifs(stats.value_ptr(), stats.value_len());
            while (ifs.next()) {
                std::string name;
                bool up = false;
                MsgPack::MapReader f(ifs.value_ptr(), ifs.value_len());
                while (f.next()) {
                    if      (f.key_is("name"))   f.value_str(name);
                    else if (f.key_is("status")) f.value_bool(up);
                    else                         f.skip_value();
                }
                ifs.advance(f.finish());
                nifs++;
                ngCrawlIfNote(from, name.c_str(), up);
                info("  %s iface: %s %s", h, name.c_str(), up ? "up" : "down");
            }
            stats.skip_value();
        }
        info("ask %s: %d interface%s", h, nifs, nifs == 1 ? "" : "s");
    } catch (const std::exception& e) {
        warn("ask: /status answer did not decode: %s", e.what());
    }
}

void ngCrawlAdvance(bool ok);      /* defined with the crawl below */

void onAskAux(TaskHandle_t, const void* data, size_t len) {
    if (len < sizeof(rnsd_link_resource_done_t)) return;
    rnsd_link_resource_done_t d;
    std::memcpy(&d, data, sizeof d);
    if (!s_ask.used || (int)d.opaque_id != s_ask.req_id) {
        if (d.buf) rnsdResourceRelease(d.buf);
        return;
    }

    if (d.opcode == RNSD_LINK_REQUEST_FAILED) {
        char h[2 * RNSD_IDENT_HASH_LEN + 1];
        hex(h, s_ask.target, RNSD_IDENT_HASH_LEN);
        /* Getting the identity wrong is the overwhelmingly likely cause, so the
         * failure line names the one that was used. */
        warn("ask %s: %s refused or timed out (identified as %s)", h,
             s_ask.stage == NG_ASK_PATH ? "/path" : "/status",
             ngCommunityHash(nullptr) ? "the community" : "this node");
        bool crawling = s_ask.crawling;
        ngAskClose(false);
        if (crawling) ngCrawlAdvance(false);
        return;
    }
    if (d.opcode != RNSD_LINK_REQUEST_RESPONSE) {
        if (d.buf) rnsdResourceRelease(d.buf);
        return;
    }

    const uint8_t* buf = (const uint8_t*)d.buf;
    if (s_ask.stage == NG_ASK_PATH) {
        if (buf && d.len) {
            s_ask.rows = ngAskTakePath(buf, d.len, s_ask.target, s_ask.crawling);
            /* Publish after /path, before /status is even asked: a crawl that
             * dies half way must still leave the picture better than it found
             * it. */
            if (s_ask.crawling) { ngVisitNote(s_ask.target, s_ask.member); s_storeDirty = true; }
        }
        rnsdResourceRelease(d.buf);

        /* Then the decoration, which may not arrive. */
        uint8_t arg[8];
        size_t  an = 0;
        {
            std::vector<uint8_t> b;
            MsgPack::detail::pack_array_header(b, 1);
            MsgPack::detail::pack_bool(b, true);          /* include link count */
            an = b.size() < sizeof arg ? b.size() : sizeof arg;
            std::memcpy(arg, b.data(), an);
        }
        s_ask.stage  = NG_ASK_STATUS;
        s_ask.req_id = rnsdLinkRequest(s_ask.tag, "/status", arg, an,
                                       NETGRAPH_REQ_PORT, /*data_packed=*/true);
        if (s_ask.req_id < 0) {
            bool crawling = s_ask.crawling;
            ngAskClose(true);
            if (crawling) ngCrawlAdvance(true);
        }
        return;
    }

    if (s_ask.stage == NG_ASK_STATUS) {
        if (buf && d.len) ngAskTakeStatus(buf, d.len, s_ask.target);
        rnsdResourceRelease(d.buf);
        bool crawling = s_ask.crawling;
        ngAskClose(true);
        if (crawling) ngCrawlAdvance(true);
        return;
    }
    if (d.buf) rnsdResourceRelease(d.buf);
}

void onAskDisc(int) { s_ask.handle = -1; }

/** The RESOURCE lifecycle on our own link.
 *
 *  A management answer normally arrives through the request/response path, on
 *  our own port, and never reaches here. But rnsd reports every Resource event
 *  on every consumer's link to one shared port, and a link WE opened is a link
 *  whose events are ours — a `/status` answer too large for a packet is
 *  advertised as a Resource, and a peer may push one at us unasked.
 *
 *  So this exists to be a destination. Without it rnsd logs "aux send to
 *  unregistered port" and frees the buffer, which is a lost answer reported as
 *  a plumbing fault. We take ownership and release: netgraph asks for nothing
 *  that arrives this way, and holding a buffer we have no reader for would be
 *  the worse of the two mistakes. */
void onResourceAux(TaskHandle_t, const void* data, size_t len) {
    if (len < sizeof(rnsd_link_resource_done_t)) return;
    rnsd_link_resource_done_t d;
    std::memcpy(&d, data, sizeof d);
    if (d.opcode == RNSD_LINK_RESOURCE_INBOUND_DONE)
        verb("resource: %uB on a management link, dropped — netgraph reads its "
             "answers through the request path", (unsigned)d.len);
    if (d.buf) rnsdResourceRelease(d.buf);
}

/** Open one visit. `crawling` marks it as part of a pass, so its answers feed
 *  the graph and the queue rather than only the log. */
bool ngAskStart(const uint8_t* target, bool crawling, bool member) {
    if (s_ask.used) return false;

    uint8_t dest[RNSD_DEST_HASH_LEN];
    if (!rnsdDestinationHashFromIdentityHash(target, NG_RM_APP, NG_RM_ASPECT, dest)) {
        warn("ask: cannot derive a management destination");
        return false;
    }

    static int seq = 0;
    s_ask = Ask{};
    s_ask.used = true;
    s_ask.crawling = crawling;
    s_ask.member = member;
    s_ask.stage = NG_ASK_PATH;
    std::memcpy(s_ask.target, target, RNSD_IDENT_HASH_LEN);
    std::snprintf(s_ask.tag, sizeof s_ask.tag, "%s%d", NG_RM_TAG, seq++ & 0xff);
    s_ask.deadline_ms = nowMs() + (uint32_t)cfgCrawlTimeoutS() * 1000u;

    s_ask.handle = rnsdLinkOpen(dest, NG_RM_FULL, /*identity_key=*/"", s_ask.tag,
                                /*path_timeout_ms=*/0,
                                /*link_timeout_ms=*/(uint32_t)cfgCrawlTimeoutS() * 1000u,
                                /*ref=*/0, [](int, size_t){}, onAskDisc);
    if (s_ask.handle < 0) { s_ask = Ask{}; s_ask.handle = -1; return false; }

    /* Identify BEFORE the request, while the link is still coming up: rnsd
     * holds both and runs them in that order at establishment, so the node has
     * the identity before it decides whether to answer. The community key where
     * there is one, our own node identity otherwise — and the failure line
     * above names whichever was used, because getting this wrong is the
     * overwhelmingly likely cause of a refusal. */
    uint8_t chash[RNSD_IDENT_HASH_LEN];
    const char* ident = ngCommunityHash(chash) ? NG_COMMUNITY_KEY : "";
    rnsdLinkIdentify(s_ask.tag, ident);

    /* ["table", nil, 1] — one hop, filtered by the node answering. */
    uint8_t arg[32];
    size_t  an;
    {
        std::vector<uint8_t> b;
        MsgPack::detail::pack_array_header(b, 3);
        MsgPack::detail::pack_str(b, "table", 5);
        MsgPack::detail::pack_nil(b);
        MsgPack::detail::pack_uint(b, 1);
        an = b.size() < sizeof arg ? b.size() : sizeof arg;
        std::memcpy(arg, b.data(), an);
    }
    s_ask.req_id = rnsdLinkRequest(s_ask.tag, "/path", arg, an,
                                   NETGRAPH_REQ_PORT, /*data_packed=*/true);
    if (s_ask.req_id < 0) { ngAskClose(false); return false; }

    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hex(h, target, RNSD_IDENT_HASH_LEN);
    info("ask %s: /path", h);
    return true;
}

void ngAskTick() {
    if (!s_ask.used) return;
    if ((int32_t)(nowMs() - s_ask.deadline_ms) < 0) return;
    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hex(h, s_ask.target, RNSD_IDENT_HASH_LEN);
    warn("ask %s: timed out", h);
    bool crawling = s_ask.crawling;
    ngAskClose(false);
    if (crawling) ngCrawlAdvance(false);
}

/* ═══════════════════════════ the crawl ═══════════════════════════
 *
 *   gather   nodes at distance ≤ s.netgraph.radius from LOCAL evidence only
 *   visit    each, once, in distance order
 *   extend   a visited node's route1 answer adds vertices; those inside the
 *            radius join the queue for this same pass
 *   stop     queue empty, or radius reached
 *
 * NEVER AUTOMATIC. `netgraph crawl` and a button in the browser panel, and
 * nothing else. No timer, no boot pass, no refresh-on-idle. This is pull
 * traffic over somebody else's airtime, and a device that quietly re-reads a
 * neighbour's tables on a schedule is what gets its hash removed from an allow
 * list. */

#define NG_CRAWL_QUEUE 48

struct CrawlQ {
    bool     running;
    uint8_t  id[NG_CRAWL_QUEUE][RNSD_IDENT_HASH_LEN];
    uint8_t  dist[NG_CRAWL_QUEUE];
    bool     member[NG_CRAWL_QUEUE];
    bool     done[NG_CRAWL_QUEUE];
    int      n;
    int      visited, refused;
    uint32_t started;
};
PSRAM_BSS CrawlQ s_cq;

int cqFind(const uint8_t* id) {
    for (int i = 0; i < s_cq.n; i++)
        if (std::memcmp(s_cq.id[i], id, RNSD_IDENT_HASH_LEN) == 0) return i;
    return -1;
}

/** Enqueue a node for this pass. EXACTLY ONCE per node per crawl: a node
 *  reachable two ways is still one visit, and the visited set is what says so. */
void cqPush(const uint8_t* id, uint8_t dist, bool member) {
    if (s_cq.n >= NG_CRAWL_QUEUE) return;
    if (dist > (uint8_t)cfgRadius()) return;
    if (s_haveSelf && std::memcmp(id, s_self, RNSD_IDENT_HASH_LEN) == 0) return;
    if (cqFind(id) >= 0) return;
    int i = s_cq.n++;
    std::memcpy(s_cq.id[i], id, RNSD_IDENT_HASH_LEN);
    s_cq.dist[i]   = dist;
    s_cq.member[i] = member;
    s_cq.done[i]   = false;
}

void ngCrawlPump();

void ngCrawlAdvance(bool ok) {
    if (!s_cq.running) return;
    if (ok) s_cq.visited++;
    else    s_cq.refused++;
    /* Failure is normal and quiet: no path, refused identify, timeout. Count
     * it, leave `visited` as it was, move to the next node. One refusal must
     * never stall a pass. */
    ngCrawlPump();
}

void ngCrawlPump() {
    if (!s_cq.running || s_ask.used) return;

    /* Distance order, so the picture fills outward and a pass cut short has
     * done the most useful part first. */
    int best = -1;
    for (int i = 0; i < s_cq.n; i++) {
        if (s_cq.done[i]) continue;
        if (best < 0 || s_cq.dist[i] < s_cq.dist[best]) best = i;
    }
    if (best < 0) {
        s_cq.running = false;
        storageSet("netgraph.crawl.state", "idle");
        info("crawl done: %d visited, %d unreachable, %us elapsed",
             s_cq.visited, s_cq.refused, (unsigned)(nowUnix() - s_cq.started));
        s_storeDirty = true;
        return;
    }
    s_cq.done[best] = true;
    if (!ngAskStart(s_cq.id[best], /*crawling=*/true, s_cq.member[best]))
        ngCrawlAdvance(false);
}

/** Gather from LOCAL evidence only — the resolved graph, which is route1,
 *  route2 and heard, plus whatever a previous crawl left. A node whose
 *  management announce carried a valid community signature is a member and
 *  goes in regardless. */
void ngCrawlStart(const uint8_t* only) {
    if (s_cq.running) { warn("crawl: already running"); return; }
    s_cq = CrawlQ{};
    s_cq.running = true;
    s_cq.started = nowUnix();

    if (only) {
        /* An operator naming a node is intent, not inference: visit it whatever
         * we have heard, because "try this one" is the whole point of saying so. */
        cqPush(only, 0, ngIsMember(only));
    } else {
        /* ONLY NODES WE HAVE HEARD ANNOUNCE THE MANAGEMENT SERVICE.
         *
         * The graph's vertices are not the right gather set, because a vertex
         * is an IDENTITY and a device hosts several — its transport identity,
         * its LXMF identity, one per application. Only the transport identity
         * has a management destination; asking any of the others is a link that
         * cannot be built, and it costs a full crawl_timeout_s each before the
         * pass moves on. A node that has not announced the service cannot
         * answer, and a node that has is announcing it on the stock beat, so
         * this is both the cheaper set and the better-evidenced one. */
        Resolved* r = &s_res;
        int radius = cfgRadius();
        for (int i = 0; i < NG_MAX_MEMBERS; i++) {
            if (!s_members[i].used) continue;
            int v = ngVertexOfIdentity(r, s_members[i].id);
            /* Distance from the graph where it has one. A management announce
             * we hold but nothing routes to is still worth one visit — it
             * reached us somehow — so it enters at the radius edge rather than
             * being dropped for having no distance at all. */
            uint8_t d = (v >= 0 && r->verts[v].dist != NG_DIST_UNKNOWN &&
                         r->verts[v].dist > 0)
                      ? r->verts[v].dist : (uint8_t)radius;
            cqPush(s_members[i].id, d, s_members[i].member);
        }
    }
    storageSet("netgraph.crawl.state", "running");
    info("crawl: %d node%s within %d hop%s", s_cq.n, s_cq.n == 1 ? "" : "s",
         cfgRadius(), cfgRadius() == 1 ? "" : "s");
    ngCrawlPump();
}

/* ═══════════════════════════ CLI ═══════════════════════════ */

/* The task's own handle and flags, declared here so the CLI — which runs on the
 * cli task — can wake it instead of leaving a `netgraph sync` sitting until the
 * next half-hourly deadline. */
TaskHandle_t  s_task        = nullptr;
volatile bool s_stop        = true;
volatile bool s_parked      = false;
volatile bool s_enableDirty = false;
/* An interface came or went, or a peer did. The composition scan is a poll
 * because rnsd has no general "the neighbourhood changed" hook — but it does
 * signal these two, and they are the ones an operator causes deliberately.
 * Switching a medium off should show on THIS node's own graph at once; that
 * everyone else takes a little longer is the announce floor doing its job. */
volatile bool s_scanNow = false;
/* A crawl is started by a person — the CLI verb or the browser button — and by
 * nothing else. The flag is set from whichever task asked; the pass itself runs
 * on the netgraph task, which is the one that owns the link. */
volatile bool s_crawlNow    = false;
volatile bool s_crawlOneSet = false;
uint8_t       s_crawlOne[RNSD_IDENT_HASH_LEN];

void ngWake() { if (s_task) xTaskNotifyGive(s_task); }

void dumpEmit(const char* line, void*) { cliPrintf("  %s\n", line); }

void cliNetgraph(const char* args) {
    if (cliWantsHelp(args)) {
        cliPrintf("netgraph                     store summary\n");
        cliPrintf("netgraph d[ump] [<prefix>]   records as pipe text\n");
        cliPrintf("netgraph l[inks]             the resolved graph — what is drawn\n");
        cliPrintf("netgraph m[embers]           who announced management, and what they said\n");
        cliPrintf("netgraph c[rawl] [<hash>]    visit the community, or one node\n");
        cliPrintf("netgraph s[ync] <hash>       run a record exchange by hand\n");
        cliPrintf("netgraph r[ebuild]           rebuild our own record\n");
        return;
    }
    char sub[16] = {}, arg[40] = {};
    std::sscanf(args, "%15s %39s", sub, arg);

    /* Both listings copy out under the lock and print outside it. Printing is
     * console I/O; holding the store lock across it would park the netgraph
     * task on every ingest for as long as an operator's terminal takes. */
    if (sub[0] == '\0') {
        struct Row { uint8_t origin[RNSD_IDENT_HASH_LEN]; uint32_t seq, age;
                     uint16_t len; uint8_t hops; bool mine, abridged, have_dest; int lines; };
        PSRAM_BSS static Row rows[NG_MAX_RECORDS];
        int n = 0;
        size_t bytes;
        {
            std::lock_guard<std::mutex> g(s_lock);
            uint32_t now = nowUnix();
            bytes = s_bytes;
            for (auto& r : s_recs) {
                if (!r.used) continue;
                Row& o = rows[n++];
                std::memcpy(o.origin, r.origin, RNSD_IDENT_HASH_LEN);
                o.seq = r.seq;
                o.age = now > r.received_at ? now - r.received_at : 0;
                o.len = r.len;
                o.hops = r.hops;
                o.mine = r.mine;
                o.abridged = r.abridged;
                o.have_dest = r.have_dest;
                o.lines = 0;
                ngForEachLine(r.bytes, r.len, ngLineCountCb, &o.lines);
            }
        }
        char h[2*RNSD_IDENT_HASH_LEN+1];
        if (s_haveSelf) { hex(h, s_self, RNSD_IDENT_HASH_LEN); cliPrintf("self  %s\n", h); }
        cliPrintf("store %zu B of %d KB, %d nodes / %d links published\n",
                  bytes, cfgStoreKb(), s_pubNodes, s_pubLinks);
        for (int i = 0; i < n; i++) {
            const Row& o = rows[i];
            hex(h, o.origin, RNSD_IDENT_HASH_LEN);
            cliPrintf("  %s seq=%u %s%3us ago %4u B %2d lines hops=%u%s%s\n",
                      h, (unsigned)o.seq, o.mine ? "(self) " : "       ",
                      (unsigned)o.age, (unsigned)o.len, o.lines, (unsigned)o.hops,
                      o.abridged ? " abridged" : "",
                      o.have_dest ? "" : " no-dest");
        }
        if (!n) cliPrintf("  (no records)\n");
        cliPrintf("sync  %s — the record flood is mothballed, so nothing dials "
                  "on its own; use `netgraph sync <hash>`\n",
                  s_outState == NG_OUT_IDLE ? "idle"
                    : s_outState == NG_OUT_CONNECTING ? "connecting" : "running");
        return;
    }

    if (cliVerbIs(sub, "dump", 1)) {
        PSRAM_BSS static uint8_t copy[NG_MAX_RECORD];
        char h[2*RNSD_IDENT_HASH_LEN+1];
        int shown = 0;
        for (int i = 0; i < NG_MAX_RECORDS; i++) {
            size_t len = 0;
            uint32_t seq = 0;
            bool abridged = false;
            {
                std::lock_guard<std::mutex> g(s_lock);
                if (!s_recs[i].used) continue;
                hex(h, s_recs[i].origin, RNSD_IDENT_HASH_LEN);
                if (arg[0] && std::strncmp(h, arg, std::strlen(arg)) != 0) continue;
                len = s_recs[i].len;
                seq = s_recs[i].seq;
                abridged = s_recs[i].abridged;
                std::memcpy(copy, s_recs[i].bytes, len);
            }
            cliPrintf("%s  seq=%u%s\n", h, (unsigned)seq, abridged ? "  abridged" : "");
            ngToText(copy, len, dumpEmit, nullptr);
            shown++;
        }
        if (!shown) cliPrintf("no record matches\n");
        return;
    }
    /* The resolved graph — what is actually DRAWN. `netgraph` above lists the
     * records that went in; between the two, a missing line says which side
     * lost it. Read back from the published rows rather than re-resolved, so
     * this is literally what the browser sees. */
    if (cliVerbIs(sub, "links", 1)) {
        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int nl = storageGetInt("netgraph.links.count", 0);
        char k[72], v[80];
        cliPrintf("%d vertice%s:\n", nv, nv == 1 ? "" : "s");
        for (int i = 0; i < nv; i++) {
            char id[40], name[RNSD_PEER_NAME_MAX], label[RNSD_NODE_LABEL_MAX], dist[8];
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);    storageGetStr(k, id, sizeof id, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.name", i);  storageGetStr(k, name, sizeof name, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.label", i); storageGetStr(k, label, sizeof label, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.dist", i);  storageGetStr(k, dist, sizeof dist, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.member", i);
            bool member = storageGetInt(k, 0) != 0;
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.visited", i);
            int visited = storageGetInt(k, 0);
            cliPrintf("  %2d %-3s %-16.16s %-16.16s%s%s\n", i,
                      dist[0] ? dist : "-", id[0] ? id : "-",
                      name[0] ? name : label,
                      member ? "  member" : "",
                      visited ? "  visited" : "");
        }
        cliPrintf("%d link%s:\n", nl, nl == 1 ? "" : "s");
        for (int j = 0; j < nl; j++) {
            char cls[16], iface[RNSD_PEER_IFACE_MAX], bref[16], ev[12], age[12], src[40];
            std::snprintf(k, sizeof k, "netgraph.links.%d.cls", j);   storageGetStr(k, cls, sizeof cls, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.iface", j); storageGetStr(k, iface, sizeof iface, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.bref", j);  storageGetStr(k, bref, sizeof bref, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.ev", j);    storageGetStr(k, ev, sizeof ev, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.age_s", j); storageGetStr(k, age, sizeof age, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.src", j);   storageGetStr(k, src, sizeof src, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.a", j);
            int a = storageGetInt(k, -1);
            std::snprintf(k, sizeof k, "netgraph.links.%d.b", j);
            int b = storageGetInt(k, -1);
            if (b < 0) std::snprintf(v, sizeof v, "?%s", bref);
            else       std::snprintf(v, sizeof v, "%d", b);
            cliPrintf("  %2d -> %-9s %-7s %-5s %-16.16s %s%s\n", a, v, ev, cls, iface,
                      age[0] ? age : "-",
                      src[0] ? "  (crawled)" : "");
        }
        return;
    }
    /* Who has announced the management service, and what their announce said.
     * The vertex rows show the RESULT; this shows the evidence it came from,
     * which is the difference between "the graph is wrong" and "the graph is
     * faithfully drawing something the announce got wrong". */
    if (cliVerbIs(sub, "members", 1)) {
        /* Rendered, measured, then printed — a column is as wide as what is in
         * it. A hostname has no bound this file knows, so a guessed width would
         * either truncate it or leave a gap. */
        struct Row { char id[2 * RNSD_IDENT_HASH_LEN + 1]; const char* ours;
                     const char* trns; const char* name; char age[24]; };
        PSRAM_BSS static Row rows[NG_MAX_MEMBERS];
        int n = 0;
        uint32_t now = nowUnix();
        size_t w_id = std::strlen("identity"), w_name = std::strlen("name");
        for (int i = 0; i < NG_MAX_MEMBERS; i++) {
            if (!s_members[i].used) continue;
            Row& r = rows[n++];
            hex(r.id, s_members[i].id, RNSD_IDENT_HASH_LEN);
            r.ours = s_members[i].member    ? "yes" : "no";
            r.trns = s_members[i].transport ? "yes" : "no";
            r.name = s_members[i].name[0] ? s_members[i].name : "-";
            if (clockSane() && tsSane(s_members[i].heard) && now > s_members[i].heard)
                std::snprintf(r.age, sizeof r.age, "%us ago",
                              (unsigned)(now - s_members[i].heard));
            else
                safeStrncpy(r.age, "just now", sizeof r.age);
            w_id   = w_id   > std::strlen(r.id)   ? w_id   : std::strlen(r.id);
            w_name = w_name > std::strlen(r.name) ? w_name : std::strlen(r.name);
        }
        if (!n) { cliPrintf("(no management announce heard yet)\n"); return; }

        cliPrintf("%-*s %-4s %-4s %-*s %s\n",
                  (int)w_id, "identity", "ours", "trns", (int)w_name, "name", "heard");
        for (int i = 0; i < n; i++)
            cliPrintf("%-*s %-4s %-4s %-*s %s\n",
                      (int)w_id, rows[i].id, rows[i].ours, rows[i].trns,
                      (int)w_name, rows[i].name, rows[i].age);
        cliPrintf("\n`ours` is a frame that decrypted and verified; the other "
                  "columns are only meaningful when it does.\n");
        return;
    }
    if (cliVerbIs(sub, "crawl", 1)) {
        if (arg[0]) {
            uint8_t id[RNSD_IDENT_HASH_LEN];
            if (!unhex(arg, id, RNSD_IDENT_HASH_LEN)) {
                cliPrintf("usage: netgraph crawl [<%d-hex identity hash>]\n",
                          (int)(2 * RNSD_IDENT_HASH_LEN));
                return;
            }
            std::memcpy(s_crawlOne, id, RNSD_IDENT_HASH_LEN);
            s_crawlOneSet = true;
        }
        s_crawlNow = true;
        ngWake();
        /* The answers land in the log and in the graph, not here: the CLI
         * session may be gone by the time a LoRa node answers, and a verb that
         * waited for one would be a verb that blocks. */
        cliPrintf("netgraph: crawl requested — watch the log, then `netgraph links`\n");
        return;
    }
    if (cliVerbIs(sub, "sync", 1)) {
        /* An argument, because the beat's own partner selection is mothballed
         * with the flood: nothing on the mesh holds a path to a peer's
         * netgraph.discovery destination, so there is nobody to pick. */
        uint8_t id[RNSD_IDENT_HASH_LEN];
        if (!unhex(arg, id, RNSD_IDENT_HASH_LEN)) {
            cliPrintf("usage: netgraph sync <%d-hex identity hash>\n",
                      (int)(2 * RNSD_IDENT_HASH_LEN));
            return;
        }
        std::memcpy(s_syncTarget, id, RNSD_IDENT_HASH_LEN);
        s_syncTargetSet = true;
        s_syncNow = true;
        ngWake();
        cliPrintf("netgraph: sync requested with %s\n", arg);
        return;
    }
    if (cliVerbIs(sub, "rebuild", 1)) { s_rebuildWanted = true; s_lastRebuild = 0; ngWake();
                                        cliPrintf("netgraph: rebuild requested\n"); return; }
    cliPrintf("usage: netgraph [dump [<prefix>]|links|members|crawl [<hash>]|sync <hash>|rebuild]\n");
}

/* ═══════════════════════════ task ═══════════════════════════ */

bool s_up = false;

/* Uncalled while the flood is mothballed — plans/netgraph.md, "Protocol".
 * Kept whole, with its callbacks, so restoring the flood is uncommenting the
 * two call sites rather than rewriting the ingest path. */
[[maybe_unused]] bool ngAnnounceSub() {
    if (s_annSub >= 0) return true;
    rnsd_announces_connect_t req = {};
    safeStrncpy(req.aspect, NG_ASPECT, sizeof req.aspect);
    s_annSub = itsConnect("rnsd", RNSD_PORT_ANNOUNCES, &req, sizeof req,
                          pdMS_TO_TICKS(2000), /*ref*/0, onAnnounce, onAnnounceDisc);
    if (s_annSub < 0) { warn("announce sub: connect failed"); return false; }
    return true;
}

/* Our own identity hash is the record's origin, so nothing can be built before
 * it is known. rnsd has it the moment it is up, but this is retried on the
 * composition scan rather than assumed, so a late identity costs one scan
 * rather than the whole component. */
bool ngSelf() {
    if (s_haveSelf) return true;
    uint8_t id[RNSD_IDENT_HASH_LEN];
    if (!rnsdIdentityHash("secrets.rnsd.identity", id)) return false;
    std::memcpy(s_self, id, RNSD_IDENT_HASH_LEN);
    s_haveSelf = true;
    return true;
}

void ngUp() {
    if (s_up) return;
    ngSelf();
    s_destHandle = rnsdDestOpen(NG_ASPECT, /*identity_key*/"", /*SINGLE*/0,
                                /*ref*/0, [](int, size_t){}, [](int){ s_destHandle = -1; });
    if (s_destHandle < 0) { warn("rnsdDestOpen(%s) failed (%d)", NG_ASPECT, s_destHandle); return; }
    if (!rnsdDestListenChannels(s_destHandle, NETGRAPH_SYNC_PORT))
        warn("rnsdDestListenChannels failed — sync will be receive-only");

    /* MOTHBALLED — plans/netgraph.md, "Protocol". This is the fan-out that
     * ingested a record out of a neighbour's announce; with nothing announcing
     * records there is nothing for it to hear. */
    /* ngAnnounceSub(); */

    /* Serve remote management, if we are meant to. The community key is derived
     * first, because the allow list is built from its hash — and a node serving
     * with neither a community nor a granted hash refuses everyone, which
     * ngPushAllowList says out loud rather than letting it look like a fault. */
    if (cfgServe()) {
        ngCommunityEnsure();
        ngPublishCommunity();
        if (rnsdRemoteManagementStart()) {
            ngPushAllowList();
            ngMembershipPublish();
        }
    }
    /* Whether or not we serve, we listen: this is how the crawl learns who is
     * askable, and it costs one subscription against announces already on the
     * air. */
    ngMgmtAnnounceSub();

    s_up = true;
    s_rebuildWanted = true;
    s_lastRebuild = 0;
    s_syncBackoff = NG_SYNC_FAST_MS;
    s_nextSync = nowMs();
    storageSet("netgraph.crawl.state", "idle");
    info("up: hosting %s (record flood mothballed)%s", NG_ASPECT,
         rnsdRemoteManagementServing() ? ", serving remote management" : "");
}

void ngDown() {
    if (s_ask.used) ngAskClose(false);
    s_cq.running = false;
    rnsdRemoteManagementStop();
    for (auto& s : s_sess) if (s.used) ngSessClose(s);
    if (s_annSub >= 0)     { itsDisconnect(s_annSub); s_annSub = -1; }
    if (s_mgmtSub >= 0)    { itsDisconnect(s_mgmtSub); s_mgmtSub = -1; }
    if (s_destHandle >= 0) { itsDisconnect(s_destHandle); s_destHandle = -1; }
    s_outState = NG_OUT_IDLE;
    s_up = false;
    /* Take the rows down with the component. A graph left standing after the
     * thing that resolves it has stopped is a picture of a moment, presented as
     * the present. */
    storageDeleteTree("netgraph");
    s_pubNodes = s_pubLinks = 0;
    for (auto& c : s_pubIfaceCount) c = 0;
}

void ngClearStore() {
    std::lock_guard<std::mutex> g(s_lock);
    for (int i = 0; i < NG_MAX_RECORDS; i++) recFree(i);
    s_bytes = 0;
    s_storeDirty = false;
    /* What other nodes told us goes with it. A crawl's answers are a snapshot
     * somebody handed us, and keeping them across a restart would present one
     * moment's picture as the present. */
    for (auto& c : s_crawl)   c.used = false;
    for (auto& c : s_crawlIf) c.used = false;
    for (auto& v : s_visited) v.used = false;
}

void netgraphTask(void*) {
    itsServerInit();
    itsClientInit(6);
    itsServerPortOpen(NETGRAPH_SYNC_PORT, ITS_PACKET, NG_INBOUND_MAX, 4096, 4096, 0, 4096);
    itsServerOnConnect(NETGRAPH_SYNC_PORT,    onInboxConnect);
    itsServerOnRecv(NETGRAPH_SYNC_PORT,       onInboxRecv);
    itsServerOnDisconnect(NETGRAPH_SYNC_PORT, onInboxDisconnect);
    /* Aux-only: rnsd hands back one remote-management answer per request. */
    itsServerPortOpen(NETGRAPH_REQ_PORT, /*packetBased=*/false,
                      /*maxHandles=*/1, /*toSize=*/0, /*fromSize=*/0);
    itsOnAux(NETGRAPH_REQ_PORT, onAskAux);
    /* And the shared one every link consumer must open — rnsd reports the
     * Resource lifecycle there for any link we open, whether or not we asked
     * for a Resource. */
    itsServerPortOpen(RNSD_LINK_RESOURCE_AUX_PORT, /*packetBased=*/false,
                      /*maxHandles=*/1, /*toSize=*/0, /*fromSize=*/0);
    itsOnAux(RNSD_LINK_RESOURCE_AUX_PORT, onResourceAux);
    s_ask.handle = -1;

    /* The enable switch is watched, not polled: the subscription runs on this
     * task, so a toggle both flags the reconcile and wakes the wait below. */
    storageSubscribeChanges("s.netgraph.enable",
                            ON_CHANGE { (void)key; (void)val; s_enableDirty = true; });
    /* Both run on this task, so setting the flag also wakes the wait below —
     * the scan happens on the same pass that learned about the change. */
    storageSubscribeChanges("rnsd.iface_event_seq",
                            ON_CHANGE { (void)key; (void)val; s_scanNow = true; });
    storageSubscribeChanges("rnsd.peers.count",
                            ON_CHANGE { (void)key; (void)val; s_scanNow = true; });
    /* The browser's crawl button. A rising value rather than a flag: two
     * crawls in a row must both be seen, and a key already at 1 produces no
     * change for this subscription to notice. */
    storageSubscribeChanges("netgraph.crawl.req",
                            ON_CHANGE { (void)key; (void)val; s_crawlNow = true; });
    /* The community's inputs. Changing either re-derives the key, which
     * changes the identity we present and the one we admit, so the allow list
     * and the membership signature both have to follow. */
    storageSubscribeChanges("s.netgraph.community",
                            ON_CHANGE { (void)key; (void)val; s_communityDirty = true; });
    storageSubscribeChanges("s.netgraph.passphrase",
                            ON_CHANGE { (void)key; (void)val; s_communityDirty = true; });
    /* THE ANNOUNCE IS COMPOSED ONCE AND REPLAYED FOREVER. rnsd holds the bytes
     * and airs them on the hosted beat, so a fact that changed after the last
     * compose never reaches anyone: enabling transport, or renaming the device,
     * left every other node still showing what was true when this one started.
     * Both are carried in the frame, so both have to re-air it. */
    storageSubscribeChanges("s.net.hostname",
                            ON_CHANGE { (void)key; (void)val; s_communityDirty = true; });
    storageSubscribeChanges("s.rnsd.transport_enabled",
                            ON_CHANGE { (void)key; (void)val; s_communityDirty = true; });
    /* The settings collection's mutations. The pane never writes the array
     * itself, so these are the only writers and the validation in
     * ngAllowAdd cannot be bypassed. */
    storageSubscribeChanges("netgraph.allow.add",    ngAllowSentinel);
    storageSubscribeChanges("netgraph.allow.remove", ngAllowSentinel);

  for (;;) {
    uint32_t nextScan = 0;
    while (!s_stop) {
        bool want = cfgEnable() != 0;
        if (want && !s_up)  ngUp();
        if (!want && s_up)  ngDown();

        /* Wait for the next thing that is actually due, never on a fixed beat.
         * Switched off there is no duty at all, so the wait is unbounded and
         * netgraph costs an idle node nothing: an inbound sync is an ITS
         * notify, an arriving announce is an ITS notify, the enable switch is a
         * storage subscription hosted here, and the CLI notifies. */
        uint32_t now = nowMs();
        uint32_t due = now + 3600000u;
        auto soonest = [&](uint32_t at) { if ((int32_t)(at - due) < 0) due = at; };
        if (s_up) {
            if (s_scanNow) soonest(now);
            soonest(nextScan);
            soonest(s_nextSync);
            if (s_rebuildWanted && s_haveSelf) soonest(now);
            if (s_pendingAnnounce)
                soonest(s_lastAnnounce + (uint32_t)cfgRebuildFloorS() * 1000u);
            /* An outbound channel reports establishment through storage rather
             * than a callback, so while one is in flight there is something to
             * look at rather than wait for. */
            if (s_outState != NG_OUT_IDLE) soonest(now + 500);
            /* A visit in flight: come back for its deadline, and for the next
             * node the moment it finishes. */
            if (s_ask.used) soonest(s_ask.deadline_ms);
            if (s_crawlNow || s_communityDirty) soonest(now);
            for (int i = 0; i < NG_INBOUND_MAX; i++) {
                if (!s_sess[i].used) continue;
                soonest(s_sess[i].active_ms + NG_SYNC_IDLE_MS);
                /* Records still queued behind the send window: come back for
                 * them as the peer's channel drains, not at the next beat. */
                if (s_sess[i].qi < s_sess[i].qn || s_sess[i].want_done) soonest(now + 300);
            }
        }
        int32_t delta = (int32_t)(due - now);
        itsPoll(!want  ? portMAX_DELAY
              : !s_up  ? pdMS_TO_TICKS(5000)     /* wanted, but the destination
                                                    would not open — retry */
              : delta <= 0 ? 0 : pdMS_TO_TICKS((uint32_t)delta));

        if (s_enableDirty) { s_enableDirty = false; continue; }
        if (!s_up) continue;

        now = nowMs();

        /* Composition scan. A burst of changes coalesces into one rebuild: the
         * floor is what stops a node joining a busy neighbourhood from
         * re-flooding its record once per neighbour. */
        if (s_scanNow || (int32_t)(now - nextScan) >= 0) {
            s_scanNow = false;
            nextScan = now + NG_SCAN_MS;
            /* MOTHBALLED with the subscription in ngUp — this was where a
             * dropped record announce fan-out got re-established. */
            /* ngAnnounceSub(); */
            /* The management one is live, and this is the one place with a
             * cadence of its own to re-establish it from. */
            ngMgmtAnnounceSub();
            if (ngSelf() && ngCompositionChanged()) s_rebuildWanted = true;
            /* Re-resolve when the GRAPH's inputs moved, which is not the same
             * question as whether our own record did: three of the four
             * evidence classes come from rnsd's tables rather than the record,
             * and an interface switched off changes what is drawn without
             * changing a byte of what we would announce about ourselves.
             *
             * Signature rather than a full resolve, because this is a poll. It
             * costs three table walks against a resolve-and-republish, and on a
             * settled node it does nothing at all. */
            if (ngGraphInputsChanged()) s_storeDirty = true;
        }
        /* Rebuild the moment the composition changes. The floor below bounds
         * what goes ON THE AIR, not what this node knows about itself. */
        if (s_rebuildWanted && s_haveSelf) ngRebuild();
        ngAnnounceDue();

        if (s_communityDirty) {
            s_communityDirty = false;
            /* The derivation and the published hash follow the settings
             * whether or not we serve — an operator who has typed a passphrase
             * expects to see the identity it produced, and turning `serve` on
             * afterwards should not be what finally computes it. */
            ngCommunityEnsure();
            ngPublishCommunity();
            if (cfgServe() && rnsdRemoteManagementServing()) {
                ngPushAllowList();
                ngMembershipPublish();
            }
        }
        if (s_crawlNow) {
            s_crawlNow = false;
            bool one = s_crawlOneSet;
            s_crawlOneSet = false;
            ngCrawlStart(one ? s_crawlOne : nullptr);
        }
        ngAskTick();

        if (s_syncNow) { s_syncNow = false; ngManualSync(); }
        if ((int32_t)(now - s_nextSync) >= 0) {
            ngExpire();
            /* Provisional; the exchange refines it on close from what it
             * actually learned. Left as-is when no partner could be picked, so
             * a node with nobody to ask keeps trying at the current rate. */
            s_nextSync = now + ngBeatDelay();
            /* MOTHBALLED — plans/netgraph.md, "The sync engine". The boot
             * backfill and the periodic anti-entropy dial both need a path to a
             * peer's netgraph.discovery destination, and no announce supplies
             * one. The beat itself stays: the expiry sweep above rides it, and
             * `netgraph sync <hash>` still opens a channel by hand. */
            /* ngSyncBeat(); */
        }
        ngOutTick();

        /* Inbound sessions: keep the send window fed, and drop one that stopped
         * talking — nothing waits on a sync, so a stalled one costs nothing to
         * abandon and retry on the next beat. */
        for (int i = 0; i < NG_INBOUND_MAX; i++) {
            if (!s_sess[i].used) continue;
            if ((uint32_t)(now - s_sess[i].active_ms) > NG_SYNC_IDLE_MS) {
                ngSessClose(s_sess[i]);
                continue;
            }
            ngSessPump(s_sess[i]);
        }

        if (s_storeDirty) { s_storeDirty = false; ngResolve(); }
    }

    /* rns stop: drop every rnsd connection so rnsd frees the slots, and let the
     * store go — a rebooted or restarted node backfills from one neighbour
     * faster than keeping it would be worth. Then PARK; the task lives across
     * stop/start so its ITS ports are reused rather than leaked. */
    ngDown();
    ngClearStore();
    s_parked = true;
    info("[%s] stopped", TAG);
    while (s_stop) itsPoll(portMAX_DELAY);
    s_parked = false;
  }
}

void netgraphStart(void) {
    s_stop = false;
    if (!s_task) s_task = spawnTask(netgraphTask, TAG, 8192, nullptr, 1, 0, STACK_PSRAM);
    else         xTaskNotifyGive(s_task);
}

void netgraphStop(void) {
    if (!s_task || s_stop) return;
    s_stop = true;
    xTaskNotifyGive(s_task);
    for (int i = 0; i < 300 && !s_parked; i++) delay(10);
    if (!s_parked) warn("[%s] stop timed out", TAG);
}

}  // namespace

/* ═══════════════════════════ public surface ═══════════════════════════ */

void netgraphContributeIface(const char* cls, netgraph_iface_detail_t cb)
{
    if (!cls || !cb) return;
    for (int i = 0; i < s_ncontrib; i++)
        if (std::strcmp(s_contrib[i].cls, cls) == 0) { s_contrib[i].cb = cb; return; }
    if (s_ncontrib >= (int)(sizeof(s_contrib)/sizeof(s_contrib[0]))) return;
    s_contrib[s_ncontrib].cls = cls;
    s_contrib[s_ncontrib].cb  = cb;
    s_ncontrib++;
}

void NetgraphService::onInit()
{
    /* `seq` is state, not configuration — it is never seeded here, because a
     * default would let a reboot re-issue a sequence number the community has
     * already seen and rejected. `allow` is a collection the sentinels below
     * own, so it is not seeded either: an empty array is its own absence. */
    storageDefaultTree("s.netgraph", R"({
      "enable": 1,
      "heard_h": 3,
      "radius": 2,
      "crawl_timeout_s": 20,
      "serve": 1,
      "community": "",
      "passphrase": "",
      "rebuild_floor_s": 600,
      "announce_cells": 8,
      "link_horizon_h": 6,
      "horizon_h": 24,
      "sync_min": 30,
      "store_kb": 24
    })");

    cliRegisterCmd("netgraph", cliNetgraph);

    /* `rnpath -R` / `rnstatus -R` ask through here. rnsd owns the tables and
     * the Link but not the policy — which identity to present, what to do with
     * the answer — so the switch calls up rather than rnsd learning about
     * communities. Registered at init rather than at start, so the switch
     * reports a real failure instead of "not available" while rns is down. */
    /* `rnpath -r` asks here for a DEVICE's name. rnsd names a destination from
     * the display name its announce advertised, which the addresses that are a
     * device never carry — so without this the path table could only ever print
     * an aspect for exactly the rows an operator most wants named. */
    rnsdSetNameResolver([](const uint8_t* ident, char* out, size_t outsz) -> bool {
        if (s_haveSelf && std::memcmp(ident, s_self, RNSD_IDENT_HASH_LEN) == 0) {
            ngOwnName(out, outsz);
            return out[0] != '\0';
        }
        for (int i = 0; i < NG_MAX_MEMBERS; i++)
            if (s_members[i].used && s_members[i].name[0] &&
                std::memcmp(s_members[i].id, ident, RNSD_IDENT_HASH_LEN) == 0) {
                safeStrncpy(out, s_members[i].name, outsz);
                return true;
            }
        return false;
    });

    rnsdSetRemoteAsker([](const uint8_t* ident) {
        std::memcpy(s_crawlOne, ident, RNSD_IDENT_HASH_LEN);
        s_crawlOneSet = true;
        s_crawlNow    = true;
        ngWake();
    });

    /* A CLIENT of rnsd, not an interface: it comes up after the interfaces and
     * goes down before them, so its destination and channels still have
     * something to ride on while they are torn down. */
    rnsServiceRegister(TAG, netgraphStart, netgraphStop, RNS_PHASE_CLIENT);
}
