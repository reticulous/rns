/**
 * netgraph — the community's whole graph, held by every node.
 *
 *   push (continuous, unsolicited, mesh-wide):
 *     every node:  ANNOUNCE netgraph.discovery  app_data = own record, abridged
 *
 *   sync (on demand, over one Reticulum Channel between two nodes):
 *     I → R   DIGEST        every (origin, seq) I hold
 *     R → I   RECORD_PART*  records I lack or hold older
 *     R → I   WANT          origins R lacks or holds older
 *     I → R   RECORD_PART*  those records
 *     both    DONE          then the initiator closes the channel
 *
 * A RECORD is one node's self-report about itself and nothing else: its name,
 * the destinations it announces, its interfaces, its links. No node ever writes
 * into another's, records replace wholesale rather than merge, and newer seq
 * wins — that is the entire conflict story. The graph is the union of everyone's
 * records plus a local-only overlay for neighbours that have never announced,
 * resolved here and published as `netgraph.*` rows. The browser NetGraph app is
 * then a renderer: it joins nothing, because the join already happened here.
 *
 * Records are UNSIGNED. A first-hand one arrives as announce app_data and is
 * covered by the announce's own signature; a relayed one travels over an
 * encrypted Link between community members and carries no signature of its own.
 * A member can fabricate, and a signature never prevented that. The consequence
 * is the rule: a record must never be handed to a party that does not trust the
 * whole community.
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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <mutex>

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
#define NG_MAX_VERTS        (NG_MAX_RECORDS + 16)
#define NG_MAX_LINKS        192
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

uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/** The interface CLASS behind a registered name: `lora/0` → `lora`,
 *  `tcp_in/1.2.3.4#0` → `tcp`. The same rule the status-line pill and the
 *  browser's ifaceClass() use, so one vocabulary names a medium everywhere. */
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

/* ═══════════════════════════ settings ═══════════════════════════ */

int cfgEnable()        { return storageGetInt("s.netgraph.enable", 1); }
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
        /* The hostname first: a vertex on this graph is a DEVICE, and the
         * hostname is what its operator called that device. An LXMF display
         * name is what a person calls themselves, is the same on every device
         * they run, and belongs to a destination rather than to a node — it is
         * a decent last resort for a node that has no hostname set and nothing
         * else to go by, and a poor label wherever there is one. */
        char raw[RNSD_PEER_NAME_MAX];
        storageGetStr("s.net.hostname", raw, sizeof raw, "");
        if (!raw[0]) storageGetStr("s.lxmf.id.0.display_name", raw, sizeof raw, "");
        char name[RNSD_PEER_NAME_MAX];
        sanitizeField(raw, name, sizeof name);
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

/* What a vertex IS, which is the one thing a renderer cannot work out for
 * itself and needs a different shape for. A member speaks for itself through a
 * record; a local-only vertex is a neighbour of ours that has never announced,
 * so only we can see it; an uplink is not in the community at all. */
enum { NG_KIND_MEMBER = 0, NG_KIND_LOCAL = 1, NG_KIND_UPLINK = 2, NG_KIND_ROUTED = 3 };
const char* const kKindName[] = { "member", "local", "uplink", "routed" };

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
    uint8_t  kind;
    char     name[RNSD_PEER_NAME_MAX];
    char     label[RNSD_NODE_LABEL_MAX];
    bool     transport;
    uint32_t ts;
};

struct Edge {
    int16_t  a, b;                      /* vertex indices; b = -1 unresolved */
    uint8_t  bref[4];
    char     cls[16];
    char     iface[RNSD_PEER_IFACE_MAX];
    /* Freshness is only known for a link some node MEASURED — an `ln` cell. An
     * uplink was never heard from (its far end does not announce, it is dialled)
     * and a local-only neighbour has never announced at all, so for those the
     * answer is that there is no answer. Published empty rather than 0, on the
     * same principle as rnsd's rssi/snr: the field is part of the shape and its
     * emptiness IS the answer, which a zero would not be. */
    uint8_t  fresh;
    bool     have_fresh;
    bool     transport;
    /* Nobody REPORTED this link; it was inferred from the routing table, which
     * is all a node that does not speak netgraph ever gives us. Drawn dotted:
     * a route is evidence of adjacency, not a statement of one. */
    bool     inferred;
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
    /* Uplinks, gathered in the first pass and turned into vertices in the last:
     * they append to `verts`, which the edge pass is iterating. */
    struct { int16_t v; char cls[16]; char iface[RNSD_PEER_IFACE_MAX];
             char label[RNSD_NODE_LABEL_MAX]; }
             ups[NG_MAX_RECORDS];
    int      nups;
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
    } else if (tag == NG_TAG_UP) {
        Resolved* r = c->r;
        if (r->nups >= (int)(sizeof(r->ups)/sizeof(r->ups[0]))) return true;
        char text[192];
        size_t k = n < sizeof(text) - 1 ? n : sizeof(text) - 1;
        std::memcpy(text, b, k); text[k] = '\0';
        /* cls|iface|label[|detail] — the detail is the class's and is not shown
         * on the far end, which is not ours to describe. */
        char* p1 = std::strchr(text, '|');       if (!p1) return true;
        *p1 = '\0';
        char* p2 = std::strchr(p1 + 1, '|');     if (!p2) return true;
        *p2 = '\0';
        char* p3 = std::strchr(p2 + 1, '|');     if (p3) *p3 = '\0';
        if (!*(p2 + 1)) return true;             /* no far end named — not a way anywhere */
        auto& e = r->ups[r->nups++];
        e.v = (int16_t)c->v;
        safeStrncpy(e.cls,   text,   sizeof e.cls);
        safeStrncpy(e.iface, p1 + 1, sizeof e.iface);
        safeStrncpy(e.label, p2 + 1, sizeof e.label);
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

/* ── inferred links: what routing knows and nobody reported ──
 *
 * A stock RNS node announces its destinations and never a record, so routing is
 * the only evidence it exists and the only evidence of where it hangs off. What
 * a route can honestly place:
 *
 *   hops == 1  a direct neighbour — the far end is us.
 *   hops == 2  reachable through a next hop we can name, so the destination
 *              really is ADJACENT to that node. This is the case that finds a
 *              link between two OTHER nodes when neither has told us about it.
 *   hops > 2   it is out there and we know roughly how far, but not who it
 *              hangs off. Drawing it to the next hop would assert an adjacency
 *              that is not in the data, so it is not drawn at all.
 *
 * The join is the IDENTITY behind a destination, which is the same value a
 * record is originated by — so a routed node either lands on the vertex that
 * speaks for itself, or gets one of its own that says it does not. */

#define NG_MAX_DIR 96

/* rnsd's directory, flattened: every address this device has ever heard, and
 * the node it belongs to. This is what makes one unified view possible — it
 * turns any destination, from any source, into the same node key. */
struct DirEnt {
    uint8_t dest[RNSD_DEST_HASH_LEN];
    uint8_t id[RNSD_IDENT_HASH_LEN];
    uint8_t via[RNSD_DEST_HASH_LEN];
    char    iface[RNSD_PEER_IFACE_MAX];
    uint8_t hops;
    bool    haveId, haveRoute;
};
PSRAM_BSS DirEnt s_dir[NG_MAX_DIR];
int s_ndir = 0;

void ngDirCollect(const rnsd_dir_entry_t* e, void*) {
    if (s_ndir >= NG_MAX_DIR || !e->have_identity) return;
    DirEnt& d = s_dir[s_ndir++];
    std::memcpy(d.dest, e->dest, RNSD_DEST_HASH_LEN);
    std::memcpy(d.id,   e->identity, RNSD_IDENT_HASH_LEN);
    std::memcpy(d.via,  e->via, RNSD_DEST_HASH_LEN);
    safeStrncpy(d.iface, e->iface, sizeof d.iface);
    d.hops = e->hops;
    d.haveId = true;
    d.haveRoute = e->have_route;
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

/** Who is at the far end of a point-to-point interface: whoever answers on it
 *  one hop away. This is what stops a Bluetooth peer being drawn as a MAC
 *  beside the very node it is. */
const uint8_t* ngIdOnIface(const char* iface) {
    if (!iface || !*iface) return nullptr;
    const uint8_t* found = nullptr;
    for (int i = 0; i < s_ndir; i++) {
        if (!s_dir[i].haveRoute || s_dir[i].hops != 1) continue;
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

/** Find or create the vertex for a node. A new one starts as `routed` — seen,
 *  not heard from — and is upgraded the moment its own record arrives. */
int ngVertFor(Resolved* r, const uint8_t* id) {
    int v = ngVertexOfIdentity(r, id);
    if (v >= 0) return v;
    if (r->nverts >= NG_MAX_VERTS) return -1;
    v = r->nverts++;
    Vert& vt = r->verts[v];
    vt = Vert{};
    vt.rec  = -1;
    vt.kind = NG_KIND_ROUTED;
    std::memcpy(vt.id, id, RNSD_IDENT_HASH_LEN);
    vt.have_id = true;
    hex(vt.label, id, 4);
    return v;
}

/** Any edge already joining these two, in either direction and any medium. A
 *  reported link always outranks an inferred one — routing must never draw a
 *  second line beside a link somebody actually stated. */
bool ngPairJoined(Resolved* r, int a, int b) {
    for (int i = 0; i < r->nedges; i++)
        if ((r->edges[i].a == a && r->edges[i].b == b) ||
            (r->edges[i].a == b && r->edges[i].b == a)) return true;
    return false;
}

int pfxLookup(Resolved* r, const uint8_t* p) {
    for (int i = 0; i < r->npfx; i++)
        if (std::memcmp(r->pfx[i].p, p, 4) == 0) return r->pfx[i].v;
    return -1;
}

struct EdgeCtx { Resolved* r; int v; };

/** Both directions of a link arrive — each endpoint reports it — and both are
 *  published: asymmetric hearing is information, and the renderer already draws
 *  parallel arcs. What is collapsed is a DUPLICATE within one record: a peer
 *  that announced two destinations we resolve to the same node is one link. */
bool edgeExists(Resolved* r, int a, int b, const uint8_t* bref, const char* iface) {
    for (int i = 0; i < r->nedges; i++) {
        const Edge& e = r->edges[i];
        if (e.a != a || std::strcmp(e.iface, iface) != 0) continue;
        if (b >= 0) { if (e.b == b) return true; }
        else if (e.b < 0 && std::memcmp(e.bref, bref, 4) == 0) return true;
    }
    return false;
}

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
    for (int i = 0; i < cells && r->nedges < NG_MAX_LINKS; i++) {
        const uint8_t* cell = q + 5 * i;
        int to = pfxLookup(r, cell);
        if (to < 0) {
            /* Not in anybody's `dt`, but rnsd may still know whose address it
             * is — and if it does, this is that node, not a nameless stub. */
            const uint8_t* id = ngIdForPrefix(cell);
            if (id) to = ngVertFor(r, id);
        }
        if (to == c->v) continue;                       /* a record naming itself */
        if (edgeExists(r, c->v, to, cell, iface)) continue;
        Edge& e = r->edges[r->nedges++];
        e = Edge{};
        e.a = (int16_t)c->v;
        e.b = (int16_t)to;
        std::memcpy(e.bref, cell, 4);
        safeStrncpy(e.cls, cls, sizeof e.cls);
        safeStrncpy(e.iface, iface, sizeof e.iface);
        e.fresh = (uint8_t)(cell[4] & 0x03);
        e.have_fresh = true;               /* somebody measured this one */
        e.transport = (cell[4] & 0x04) != 0;
    }
    return true;
}

/* ── the local overlay ──
 *
 * THE INVARIANT: anything rnsd says is reachable is on the graph. Not "should
 * be" — is. A status pill reading `B2` beside a picture with no Bluetooth line
 * is not a display quirk to be explained away; it is the graph contradicting
 * the node's own neighbour table, and the graph is the one that is wrong.
 *
 * So this does not ASSUME that a peer which has announced is covered by a cell
 * in our record. It checks. Everything our record actually reported is
 * collected first, and every reachable node whose destinations are not in that
 * set is added here under the transport address rnsd labelled it by — a MAC, a
 * host:port. A peer that goes missing between the neighbour table and the
 * record then appears as its address rather than as nothing, which is both the
 * honest drawing and very much easier to debug than a blank canvas.
 *
 * The old form of this trusted `rnsd_node_t.peers` as a proxy for "a cell
 * covers it" and silently dropped anything the proxy got wrong. */

#define NG_OVERLAY_NODES 32       /* rnsd's node table is smaller; this bounds the walk */

struct OverlayCtx {
    Resolved* r;
    int      self;
    uint8_t  cell[NG_MAX_IFACES * NG_MAX_CELLS][4];   /* prefixes OUR record reported */
    int      ncell;
    /* Interfaces our record already spoke for with an `up` line — their far end
     * is on the graph as a box, and adding it again here would draw it twice. */
    char     upIface[NG_MAX_UPLINKS][RNSD_PEER_IFACE_MAX];
    int      nup;
    bool     covered[NG_OVERLAY_NODES];
    /* Interfaces our record put at least one link cell on. */
    char     cellIface[NG_MAX_IFACES][RNSD_PEER_IFACE_MAX];
    int      ncellIface;
    /* Interfaces where a peer names its node by INDEX. On those, coverage is
     * per node; everywhere else the interface IS the node. */
    char     attrIface[NG_MAX_IFACES][RNSD_PEER_IFACE_MAX];
    int      nattrIface;
    /* Interfaces that have a declared node — there, the node is the vertex and
     * a loose peer is only one of its destinations. */
    char     nodeIface[NG_MAX_IFACES][RNSD_PEER_IFACE_MAX];
    int      nnodeIface;
};
PSRAM_BSS OverlayCtx s_overlay;

/* A small set of interface names; every list in OverlayCtx is one. */
bool ovHas(char (*set)[RNSD_PEER_IFACE_MAX], int n, const char* iface) {
    for (int i = 0; i < n; i++) if (std::strcmp(set[i], iface) == 0) return true;
    return false;
}
void ovPut(char (*set)[RNSD_PEER_IFACE_MAX], int* n, const char* iface) {
    if (*n >= NG_MAX_IFACES || ovHas(set, *n, iface)) return;
    safeStrncpy(set[(*n)++], iface, RNSD_PEER_IFACE_MAX);
}

bool ovReported(OverlayCtx* c, const uint8_t* p) {
    for (int i = 0; i < c->ncell; i++)
        if (std::memcmp(c->cell[i], p, 4) == 0) return true;
    return false;
}

/** Add a vertex for something only this node can see, and the edge to it. */
void ovAdd(OverlayCtx* c, const char* iface, const char* label, bool transport) {
    Resolved* r = c->r;
    if (r->nverts >= NG_MAX_VERTS || r->nedges >= NG_MAX_LINKS) return;
    int v = r->nverts++;
    Vert& vt = r->verts[v];
    vt = Vert{};
    vt.rec  = -1;
    vt.kind = NG_KIND_LOCAL;
    safeStrncpy(vt.label, label, sizeof vt.label);
    vt.transport = transport;
    Edge& e = r->edges[r->nedges++];
    e = Edge{};
    e.a = (int16_t)c->self;
    e.b = (int16_t)v;
    ifaceClass(iface, e.cls, sizeof e.cls);
    safeStrncpy(e.iface, iface, sizeof e.iface);
    e.have_fresh = false;      /* nothing here was dated by anybody */
    e.transport = transport;
}

/* Pass 1 — what our own record actually put on the air. */
bool ovCollectCells(uint8_t tag, const uint8_t* b, size_t n, void* vctx) {
    if (tag != NG_TAG_LN || n < 1) return true;
    OverlayCtx* c = (OverlayCtx*)vctx;
    size_t ilen = b[0];
    if (1 + ilen + 3 > n) return true;
    const uint8_t* q = b + 1 + ilen;
    uint8_t cells = q[2];
    q += 3;
    if ((size_t)(q - b) + (size_t)cells * 5 > n) return true;
    const int cap = (int)(sizeof(c->cell) / sizeof(c->cell[0]));
    for (int i = 0; i < cells && c->ncell < cap; i++)
        std::memcpy(c->cell[c->ncell++], q + 5 * i, 4);
    if (cells) {
        char iface[RNSD_PEER_IFACE_MAX];
        size_t k2 = ilen < sizeof(iface) - 1 ? ilen : sizeof(iface) - 1;
        std::memcpy(iface, b + 1, k2); iface[k2] = '\0';
        ovPut(c->cellIface, &c->ncellIface, iface);
    }
    return true;
}

bool ovSpokenFor(OverlayCtx* c, const char* iface) {
    for (int i = 0; i < c->nup; i++)
        if (std::strcmp(c->upIface[i], iface) == 0) return true;
    return false;
}

/* Pass 1b — the interfaces our record already drew as a box. */
bool ovCollectUps(uint8_t tag, const uint8_t* b, size_t n, void* vctx) {
    if (tag != NG_TAG_UP) return true;
    OverlayCtx* c = (OverlayCtx*)vctx;
    if (c->nup >= NG_MAX_UPLINKS) return true;
    char text[192];
    size_t k = n < sizeof(text) - 1 ? n : sizeof(text) - 1;
    std::memcpy(text, b, k); text[k] = '\0';
    char* p1 = std::strchr(text, '|');      if (!p1) return true;   /* past the class */
    char* p2 = std::strchr(p1 + 1, '|');    if (p2) *p2 = '\0';
    safeStrncpy(c->upIface[c->nup++], p1 + 1, RNSD_PEER_IFACE_MAX);
    return true;
}

/* Pass 2 — which rnsd nodes one of those cells speaks for.
 *
 * A peer names its node by INDEX only where the medium can attribute a packet
 * to one. A point-to-point medium cannot and does not need to — the interface
 * IS the node — so its peers arrive with node == -1 however well they have
 * announced. Covering only the indexed ones therefore leaves every Bluetooth
 * peer uncovered forever, and the overlay draws each of them as a MAC beside
 * the named vertex its own cell already resolved to. So an unattributed peer
 * covers its INTERFACE, which on such a medium is the same statement. */
void ovMarkCovered(const rnsd_peer_t* p, void* vctx) {
    OverlayCtx* c = (OverlayCtx*)vctx;
    if (p->node >= 0 && p->node < NG_OVERLAY_NODES) {
        ovPut(c->attrIface, &c->nattrIface, p->iface);
        if (ovReported(c, p->dest)) c->covered[p->node] = true;
    }
    /* An unattributed peer needs no per-peer coverage: on such an interface the
     * far end IS the interface, and ovNode covers it from cellIface. Matching
     * the exact destination here is what made w12 appear twice — a cell holds
     * whichever of a peer's aspects announced most recently, and that changes
     * between rebuilds, so the prefix in the record stops matching the peer row
     * it came from and the node looks uncovered. */
}

void ovNoteNodeIface(int, const rnsd_node_t* nd, void* vctx) {
    OverlayCtx* c = (OverlayCtx*)vctx;
    ovPut(c->nodeIface, &c->nnodeIface, nd->iface);
}

/* Pass 3 — an unattributed peer stands for a node of its own, so one we did not
 * report needs a vertex of its own too. Its address is its destination. */
void ovLoosePeer(const rnsd_peer_t* p, void* vctx) {
    OverlayCtx* c = (OverlayCtx*)vctx;
    if (p->node >= 0) return;
    if (ovSpokenFor(c, p->iface)) return;
    /* An interface with a declared node has that node as its vertex; a loose
     * peer there is one of its destinations, not a thing of its own. */
    if (ovHas(c->nodeIface, c->nnodeIface, p->iface)) return;
    if (ovReported(c, p->dest)) return;
    char label[2 * 4 + 1];
    hex(label, p->dest, 4);
    ovAdd(c, p->iface, label, false);
}

/* Pass 4 — every reachable node no cell and no `up` line of ours speaks for.
 *
 * NOT gated on the community radius. The radius says how far to go looking for
 * nodes to serve — where to STOP REACHING — and nothing whatever about what is
 * worth drawing. A radius-0 interface still has somebody at the other end of
 * the wire, rnsd declares a node for it precisely because that is a fact rather
 * than a policy, and a graph that hid it would be answering a question nobody
 * asked. */
void ovNode(int idx, const rnsd_node_t* nd, void* vctx) {
    OverlayCtx* c = (OverlayCtx*)vctx;
    if (idx >= 0 && idx < NG_OVERLAY_NODES && c->covered[idx]) return;
    if (ovSpokenFor(c, nd->iface)) return;     /* already drawn as a box */
    /* Before inventing a vertex for an address, ask who actually answers on
     * this interface. A MAC must mean "nobody has ever announced here" — not
     * "this node was reached by a route nobody joined up". */
    const uint8_t* id = ngIdOnIface(nd->iface);
    if (id) {
        int v = ngVertFor(c->r, id);
        if (v >= 0 && v != c->self) {
            if (ngPairJoined(c->r, c->self, v)) return;
            if (c->r->nedges >= NG_MAX_LINKS) return;
            Edge& e = c->r->edges[c->r->nedges++];
            e = Edge{};
            e.a = (int16_t)c->self;
            e.b = (int16_t)v;
            ifaceClass(nd->iface, e.cls, sizeof e.cls);
            safeStrncpy(e.iface, nd->iface, sizeof e.iface);
            e.transport = nd->transport;
        }
        return;
    }
    /* Where a peer carries no node index, the interface is the node: any cell
     * our record put on it reported THIS node, whichever destination it named. */
    if (!ovHas(c->attrIface, c->nattrIface, nd->iface) &&
        ovHas(c->cellIface, c->ncellIface, nd->iface)) return;
    ovAdd(c, nd->iface, nd->label, nd->transport);
}

void ngInferFromRouting(Resolved* r, int self) {
    (void)self;
    for (int i = 0; i < s_ndir; i++) {
        const DirEnt& e = s_dir[i];
        /* TWO HOPS ONLY. One hop is a direct neighbour — a real link on our own
         * interface, whose medium we know, and a link whose colour we know is by
         * definition not a guess; the peer table and the overlay already have
         * it. Beyond two we know the node exists but not who it hangs off, and
         * drawing it to the next hop would assert an adjacency that is not in
         * the data. So exactly one case is inferable, and it is the only one
         * drawn dotted. */
        if (!e.haveRoute || e.hops != 2) continue;

        /* Who it hangs off. `received_from` is the next hop's TRANSPORT id, not
         * one of its announced destinations, so looking it up as an address
         * almost never lands — which is why nothing was ever inferred. What
         * does land is the interface: a two-hop route goes through whoever is
         * one hop away on the same one, and on a point-to-point link that is
         * exactly one node. Where several answer there it names nobody, and
         * the route stays unplaceable. */
        const uint8_t* viaId = ngIdForDest(e.via);
        if (!viaId) viaId = ngIdOnIface(e.iface);
        if (!viaId) continue;
        int other = ngVertexOfIdentity(r, viaId);
        if (other < 0) continue;                    /* nothing to hang it off */

        int v = ngVertFor(r, e.id);
        if (v < 0 || v == other || ngPairJoined(r, other, v)) continue;
        if (r->nedges >= NG_MAX_LINKS) break;

        Edge& ed = r->edges[r->nedges++];
        ed = Edge{};
        ed.a = (int16_t)other;
        ed.b = (int16_t)v;
        ed.inferred = true;
        /* No class: this is somebody else's link and we have no idea what it
         * runs over. An inferred edge is exactly the edge whose colour we do
         * not know, which is why dotted and colourless are the same statement. */
    }
}

void ngOverlayLocal(Resolved* r, int self) {
    OverlayCtx* c = &s_overlay;
    c->r = r; c->self = self; c->ncell = 0; c->nup = 0;
    c->ncellIface = c->nattrIface = c->nnodeIface = 0;
    for (auto& b : c->covered) b = false;
    if (r->verts[self].rec >= 0) {
        const Rec& mine = s_recs[r->verts[self].rec];
        ngForEachLine(mine.bytes, mine.len, ovCollectCells, c);
        ngForEachLine(mine.bytes, mine.len, ovCollectUps, c);
    }
    rnsdNodesForEach("", ovNoteNodeIface, c);
    rnsdPeersForEach("", ovMarkCovered, c);
    rnsdPeersForEach("", ovLoosePeer, c);
    rnsdNodesForEach("", ovNode, c);
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

    uint32_t now = nowUnix();
    uint32_t halfHorizon = (uint32_t)cfgHorizonH() * 1800u;
    for (int i = 0; i < r->nverts; i++) {
        const Vert& v = r->verts[i];
        char id[2*RNSD_IDENT_HASH_LEN+1] = "";
        if (v.rec >= 0) hex(id, s_recs[v.rec].origin, RNSD_IDENT_HASH_LEN);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.id", i);        storageSet(key, id);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.name", i);      storageSet(key, v.name);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.label", i);     storageSet(key, v.label);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.kind", i);
        storageSet(key, kKindName[v.kind < (int)(sizeof(kKindName)/sizeof(kKindName[0]))
                                  ? v.kind : 0]);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.transport", i); storageSet(key, v.transport ? 1 : 0);
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.ts", i);        storageSet(key, (int)v.ts);
        bool stale = v.ts && clockSane() && now > v.ts && (now - v.ts) > halfHorizon;
        std::snprintf(key, sizeof key, "netgraph.nodes.%d.stale", i);     storageSet(key, stale ? 1 : 0);
    }
    storageSet("netgraph.nodes.slots", r->nverts);

    for (int j = 0; j < r->nedges; j++) {
        const Edge& e = r->edges[j];
        std::snprintf(key, sizeof key, "netgraph.links.%d.a", j);     storageSet(key, (int)e.a);
        std::snprintf(key, sizeof key, "netgraph.links.%d.b", j);     storageSet(key, (int)e.b);
        std::snprintf(val, sizeof val, "%02x%02x%02x%02x", e.bref[0], e.bref[1], e.bref[2], e.bref[3]);
        std::snprintf(key, sizeof key, "netgraph.links.%d.bref", j);  storageSet(key, e.b < 0 ? val : "");
        std::snprintf(key, sizeof key, "netgraph.links.%d.cls", j);   storageSet(key, e.cls);
        std::snprintf(key, sizeof key, "netgraph.links.%d.iface", j); storageSet(key, e.iface);
        /* Text, so it can be EMPTY: an int key cannot say "not measured". */
        std::snprintf(val, sizeof val, "%u", (unsigned)e.fresh);
        std::snprintf(key, sizeof key, "netgraph.links.%d.fresh", j);
        storageSet(key, e.have_fresh ? val : "");
        std::snprintf(key, sizeof key, "netgraph.links.%d.transport", j); storageSet(key, e.transport ? 1 : 0);
        std::snprintf(key, sizeof key, "netgraph.links.%d.inferred", j); storageSet(key, e.inferred ? 1 : 0);
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
        const uint8_t* id = ngIdForDest(p->dest);
        if (!id) return;
        int vi = ngVertexOfIdentity(c->r, id);
        if (vi < 0) return;
        Vert& vt = c->r->verts[vi];
        if (vt.rec >= 0 || vt.name[0]) return;   /* its own record outranks this */
        safeStrncpy(vt.name, p->name, sizeof vt.name);
    }, &c);
}

void ngResolve() {
    Resolved* r = &s_res;
    r->nverts = r->nedges = r->npfx = r->nifs = r->nups = 0;
    /* Who owns which address, for every address this device has heard. Loaded
     * first because every pass below resolves through it. */
    s_ndir = 0;
    rnsdDirForEach(ngDirCollect, nullptr);

    int self = -1;
    for (int i = 0; i < NG_MAX_RECORDS && r->nverts < NG_MAX_VERTS; i++) {
        if (!s_recs[i].used) continue;
        int v = ngVertFor(r, s_recs[i].origin);   /* one door in */
        if (v < 0) continue;
        Vert& vt = r->verts[v];
        vt.rec  = i;
        vt.kind = NG_KIND_MEMBER;                 /* it speaks for itself */
        vt.ts   = s_recs[i].seq;
        vt.label[0] = '\0';
        if (s_recs[i].mine) self = v;
        PfxCtx c{ r, v };
        ngForEachLine(s_recs[i].bytes, s_recs[i].len, collectPfxLine, &c);
    }
    for (int v = 0; v < r->nverts; v++) {
        EdgeCtx c{ r, v };
        ngForEachLine(s_recs[r->verts[v].rec].bytes, s_recs[r->verts[v].rec].len,
                      collectEdgeLine, &c);
    }
    /* Ways out of the community. Two nodes naming the SAME address get one
     * vertex: that is not a guess about the network, it is what both records
     * literally say — the same host and port. */
    for (int i = 0; i < r->nups; i++) {
        if (r->nverts >= NG_MAX_VERTS || r->nedges >= NG_MAX_LINKS) break;
        int to = -1;
        for (int k = 0; k < r->nverts; k++)
            if (r->verts[k].kind == NG_KIND_UPLINK &&
                std::strcmp(r->verts[k].label, r->ups[i].label) == 0) { to = k; break; }
        if (to < 0) {
            to = r->nverts++;
            Vert& vt = r->verts[to];
            vt = Vert{};
            vt.rec  = -1;
            vt.kind = NG_KIND_UPLINK;
            safeStrncpy(vt.label, r->ups[i].label, sizeof vt.label);
        }
        Edge& e = r->edges[r->nedges++];
        e = Edge{};
        e.a = r->ups[i].v;
        e.b = (int16_t)to;
        safeStrncpy(e.cls,   r->ups[i].cls,   sizeof e.cls);
        safeStrncpy(e.iface, r->ups[i].iface, sizeof e.iface);
    }

    ngNameFromAnnounces(r);
    if (self >= 0) {
        ngOverlayLocal(r, self);
        ngInferFromRouting(r, self);   /* last: reported links always win */
    }
    int unresolved = 0;
    for (int i = 0; i < r->nedges; i++) if (r->edges[i].b < 0) unresolved++;
    ngPublish(r);

    /* The other half of the story: what the union came to. Between this and the
     * rebuild line above, a graph that draws nothing says which layer lost it —
     * no cells means the builder, cells but no links means the resolver, links
     * but no lines means the browser. */
    int held = 0;
    for (auto& rec : s_recs) if (rec.used) held++;
    info("resolved: %d record%s -> %d vertice%s, %d link%s (%d unresolved)",
         held, held == 1 ? "" : "s",
         r->nverts, r->nverts == 1 ? "" : "s",
         r->nedges, r->nedges == 1 ? "" : "s", unresolved);
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
    /* rnsd holds the bytes; WHEN they go on the air is each interface's call.
     * netgraph owns no announce timer. */
    itsSend(s_destHandle, frame, n + 1, pdMS_TO_TICKS(200));
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
bool     s_syncNow    = false;

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

void ngSyncBeat() {
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

void ngWake() { if (s_task) xTaskNotifyGive(s_task); }

void dumpEmit(const char* line, void*) { cliPrintf("  %s\n", line); }

void cliNetgraph(const char* args) {
    if (cliWantsHelp(args)) {
        cliPrintf("netgraph                     store summary\n");
        cliPrintf("netgraph d[ump] [<prefix>]   records as pipe text\n");
        cliPrintf("netgraph l[inks]             the resolved graph — what is drawn\n");
        cliPrintf("netgraph s[ync]              run an exchange now\n");
        cliPrintf("netgraph r[ebuild]           rebuild and announce our own record\n");
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
        cliPrintf("sync  %s, next in %us (asking every %us — %s)\n",
                  s_outState == NG_OUT_IDLE ? "idle"
                    : s_outState == NG_OUT_CONNECTING ? "connecting" : "running",
                  (unsigned)((int32_t)(s_nextSync - nowMs()) > 0
                             ? (s_nextSync - nowMs()) / 1000 : 0),
                  (unsigned)(s_syncBackoff / 1000),
                  s_syncBackoff <= NG_SYNC_FAST_MS ? "still learning"
                                                   : "settled");
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
            char id[40], name[RNSD_PEER_NAME_MAX], label[RNSD_NODE_LABEL_MAX], kind[16];
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);    storageGetStr(k, id, sizeof id, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.name", i);  storageGetStr(k, name, sizeof name, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.label", i); storageGetStr(k, label, sizeof label, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);  storageGetStr(k, kind, sizeof kind, "");
            std::snprintf(k, sizeof k, "netgraph.nodes.%d.stale", i);
            cliPrintf("  %2d %-6s %-16.16s %s%s\n", i, kind,
                      id[0] ? id : "-", name[0] ? name : label,
                      storageGetInt(k, 0) ? "  (stale)" : "");
        }
        cliPrintf("%d link%s:\n", nl, nl == 1 ? "" : "s");
        for (int j = 0; j < nl; j++) {
            char cls[16], iface[RNSD_PEER_IFACE_MAX], bref[16], fresh[8];
            std::snprintf(k, sizeof k, "netgraph.links.%d.cls", j);   storageGetStr(k, cls, sizeof cls, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.iface", j); storageGetStr(k, iface, sizeof iface, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.bref", j);  storageGetStr(k, bref, sizeof bref, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.fresh", j); storageGetStr(k, fresh, sizeof fresh, "");
            std::snprintf(k, sizeof k, "netgraph.links.%d.a", j);
            int a = storageGetInt(k, -1);
            std::snprintf(k, sizeof k, "netgraph.links.%d.b", j);
            int b = storageGetInt(k, -1);
            if (b < 0) std::snprintf(v, sizeof v, "?%s", bref);
            else       std::snprintf(v, sizeof v, "%d", b);
            cliPrintf("  %2d -> %-4s %-6s %-20.20s %s\n", a, v, cls, iface,
                      fresh[0] ? fresh : "(not measured)");
        }
        return;
    }
    if (cliVerbIs(sub, "sync", 1))    { s_syncNow = true; ngWake();
                                        cliPrintf("netgraph: sync requested\n"); return; }
    if (cliVerbIs(sub, "rebuild", 1)) { s_rebuildWanted = true; s_lastRebuild = 0; ngWake();
                                        cliPrintf("netgraph: rebuild requested\n"); return; }
    cliPrintf("usage: netgraph [dump [<prefix>]|links|sync|rebuild]\n");
}

/* ═══════════════════════════ task ═══════════════════════════ */

bool s_up = false;

bool ngAnnounceSub() {
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

    ngAnnounceSub();

    s_up = true;
    s_rebuildWanted = true;
    s_lastRebuild = 0;
    s_syncBackoff = NG_SYNC_FAST_MS;
    s_nextSync = nowMs();
    info("up: hosting %s", NG_ASPECT);
}

void ngDown() {
    for (auto& s : s_sess) if (s.used) ngSessClose(s);
    if (s_annSub >= 0)     { itsDisconnect(s_annSub); s_annSub = -1; }
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
}

void netgraphTask(void*) {
    itsServerInit();
    itsClientInit(6);
    itsServerPortOpen(NETGRAPH_SYNC_PORT, ITS_PACKET, NG_INBOUND_MAX, 4096, 4096, 0, 4096);
    itsServerOnConnect(NETGRAPH_SYNC_PORT,    onInboxConnect);
    itsServerOnRecv(NETGRAPH_SYNC_PORT,       onInboxRecv);
    itsServerOnDisconnect(NETGRAPH_SYNC_PORT, onInboxDisconnect);

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
            ngAnnounceSub();          /* re-establish it here, or never: this is
                                         the one place with a cadence of its own */
            if (ngSelf() && ngCompositionChanged()) s_rebuildWanted = true;
        }
        /* Rebuild the moment the composition changes. The floor below bounds
         * what goes ON THE AIR, not what this node knows about itself. */
        if (s_rebuildWanted && s_haveSelf) ngRebuild();
        ngAnnounceDue();

        if (s_syncNow) { s_syncNow = false; s_nextSync = now; }
        if ((int32_t)(now - s_nextSync) >= 0) {
            ngExpire();
            /* Boot backfill first — one exchange against one neighbour brings
             * the whole world in far faster than waiting out announce beats. */
            /* Provisional; the exchange refines it on close from what it
             * actually learned. Left as-is when no partner could be picked, so
             * a node with nobody to ask keeps trying at the current rate. */
            s_nextSync = now + ngBeatDelay();
            ngSyncBeat();
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
    storageDefaultTree("s.netgraph", R"({
      "enable": 1,
      "rebuild_floor_s": 600,
      "announce_cells": 8,
      "link_horizon_h": 6,
      "horizon_h": 24,
      "sync_min": 30,
      "store_kb": 24
    })");

    cliRegisterCmd("netgraph", cliNetgraph);

    /* A CLIENT of rnsd, not an interface: it comes up after the interfaces and
     * goes down before them, so its destination and channels still have
     * something to ride on while they are torn down. */
    rnsServiceRegister(TAG, netgraphStart, netgraphStop, RNS_PHASE_CLIENT);
}
