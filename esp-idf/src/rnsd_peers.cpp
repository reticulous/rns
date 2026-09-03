/**
 * rnsd_peers — the direct-peer table, the `n[eighbors]` printer, and the
 * status-line pill publisher.
 *
 * Every interface has the same question to answer — who is one hop away — and
 * the same evidence to answer it with: an announce that arrived with hops == 1
 * was transmitted by the node that originated it. rnsd already sees every
 * announce and, since the fork's `received_announce` carries the receiving
 * interface, already knows where each arrived. So the neighbourhood is computed
 * once here for every medium rather than once per interface straddle, and a
 * medium added tomorrow gets `n` for free.
 *
 * A peer is a DESTINATION. Two destinations announced by one physical node look
 * exactly like two nodes on the air, and only a medium with a node-level
 * protocol of its own (LoRa's SUPE) can prove otherwise — it does so in its own
 * table, which is why `lora n` stays richer than this. Guessing at the join
 * here would draw edges that are not there.
 *
 * No µR types: this file talks byte arrays, exactly as a consumer would, so the
 * table has no opinion about the protocol engine underneath.
 */
#include "rnsd_peers.h"

#include "spangap.h"
#include "mem.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>

/* One table for the whole node, not one per interface: a peer is looked up by
 * (interface, destination) and the media between them hold a handful each. 32
 * slots is a LoRa neighbourhood plus every connection a small node carries;
 * past that the least recently heard goes, which is the one a listing would
 * have shown last anyway. */
#define RNSD_PEERS_MAX 32

/* Nodes are the things at the far end, and there are fewer of them than there
 * are destinations: a node announces several. A point-to-point medium spends
 * one per interface, a multi-peer one as many as it has peers. */
#define RNSD_NODES_MAX 16

/* Peers age out on the same clock as a path: a neighbour that has not announced
 * in a whole path lifetime is not a neighbour any more, and the interface it
 * sat on would have to re-learn it exactly as the directory does. A NODE does
 * not age out on this clock — its lifetime is the interface's statement that it
 * is reachable, which is a fact about the transport and not about announces. */
#define RNSD_PEER_TTL_DEFAULT_S 86400

namespace {

struct Peer {
    bool     used;
    rnsd_peer_t p;
};

struct Node {
    bool     used;
    rnsd_node_t n;
};

Peer*       s_peers   = nullptr;
Node        s_nodes[RNSD_NODES_MAX];
std::mutex  s_lock;
uint32_t    s_gen     = 0;     /* bumped by every change worth republishing */
uint32_t    s_pubGen  = 0;     /* generation the ephemerals were written at */
int         s_pubCount = 0;    /* peer indices currently published */
uint32_t    s_pubNodes = 0;    /* node slots currently published, one bit each */

/* Aspects this firmware speaks, so a peer row can say `lxmf.delivery` instead
 * of ten bytes of hash. A name hash is SHA-256(aspect)[:10] and one-way, so
 * this table is the only way back — an aspect that is not here can only ever be
 * shown as its hash, which is the honest answer rather than a missing one. */
const char* const kAspects[] = {
    "lxmf.delivery", "lxmf.propagation", "nomadnetwork.node",
    "rnstransport.probe", "rnsh", "rlpg.mailbox", "netgraph.discovery",
    /* Read constantly by the crawl: every node offering remote management
     * announces this on the stock two-hour beat, which is how a crawl finds
     * who is askable without deriving a single hash. */
    "rnstransport.remote.management",
};
constexpr int kAspectCount = (int)(sizeof(kAspects) / sizeof(kAspects[0]));
uint8_t s_aspectHash[kAspectCount][RNSD_NAME_HASH_LEN];
bool    s_aspectsReady = false;

void aspectsInit() {
    if (s_aspectsReady) return;
    for (int i = 0; i < kAspectCount; i++) {
        uint8_t sha[RNSD_HASH_LEN];
        rnsdSha256((const uint8_t*)kAspects[i], std::strlen(kAspects[i]), sha);
        std::memcpy(s_aspectHash[i], sha, RNSD_NAME_HASH_LEN);
    }
    s_aspectsReady = true;
}

bool ensureTable() {
    if (s_peers) return true;
    s_peers = (Peer*)gp_calloc(RNSD_PEERS_MAX, sizeof(Peer));
    if (!s_peers) warn("peers: table alloc failed (%d slots)", RNSD_PEERS_MAX);
    return s_peers != nullptr;
}

bool prefixMatch(const char* name, const char* prefix) {
    if (!prefix || !*prefix) return true;
    return std::strncmp(name, prefix, std::strlen(prefix)) == 0;
}

void hex(char* out, const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[d[i] >> 4]; out[2*i+1] = H[d[i] & 0xF]; }
    out[2*n] = '\0';
}

uint32_t nowUnix() { return (uint32_t)std::time(nullptr); }

}  // namespace

/* ─────────────── aspect + name decoding ─────────────── */

const char* rnsdAspectLabel(const uint8_t name_hash[RNSD_NAME_HASH_LEN]) {
    aspectsInit();
    for (int i = 0; i < kAspectCount; i++)
        if (std::memcmp(s_aspectHash[i], name_hash, RNSD_NAME_HASH_LEN) == 0)
            return kAspects[i];
    return nullptr;
}

/* A display name is TEXT. app_data is not: an application is free to put any
 * bytes there, and one of them — a netgraph record, led by 0xF5 precisely so it
 * cannot be mistaken for text — would otherwise be sniffed as a name and put
 * mojibake in every peer listing. So every candidate below is checked for valid
 * UTF-8 and refused outright when it is not, rather than trusted because it
 * happened to land where a name goes. */
static bool utf8Ok(const uint8_t* q, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b = q[i];
        size_t need;
        if      (b < 0x80)           need = 0;
        else if ((b & 0xE0) == 0xC0) need = 1;
        else if ((b & 0xF0) == 0xE0) need = 2;
        else if ((b & 0xF8) == 0xF0) need = 3;
        else return false;                          /* continuation byte, or 0xF5-0xFF */
        if (need && i + need >= len) return false;  /* sequence runs off the end */
        for (size_t k = 1; k <= need; k++)
            if ((q[i + k] & 0xC0) != 0x80) return false;
        i += need + 1;
    }
    return true;
}

/* LXMF wraps the display name in a msgpack array whose first element it is,
 * optionally behind the 32-byte ratchet; NomadNet and older clients send raw
 * UTF-8. Only the first element is ever wanted, so this is a deliberately small
 * subset of the parser lxmf/ carries — rnsd must not depend on a consumer. */
void rnsdAnnounceName(const uint8_t* p, size_t n, char* out, size_t outsz) {
    if (!out || !outsz) return;
    out[0] = '\0';
    if (!p || !n) return;

    auto plausible = [&](size_t off, size_t len) {
        if (off >= n || !len) return false;
        if (off + len > n) len = n - off;
        for (size_t k = 0; k < len; k++) {
            uint8_t b = p[off + k];
            if (b == 0x7F || (b < 0x20 && b != '\t' && b != '\n' && b != '\r')) return false;
        }
        return utf8Ok(p + off, len);
    };
    auto copy = [&](const uint8_t* q, size_t len) {
        if (len >= outsz) len = outsz - 1;
        /* Shrink to the longest valid-UTF-8 prefix: that trims the partial
         * sequence a buffer-length truncation may have left, and collapses a
         * candidate that was never text at all to the empty name. */
        while (len && !utf8Ok(q, len)) len--;
        std::memcpy(out, q, len);
        out[len] = '\0';
    };
    auto tryArray = [&](size_t i) {
        if (i >= n) return false;
        uint8_t b = p[i++];
        if (b >= 0x90 && b <= 0x9F) { if (!(b & 0x0F)) return false; }
        else if (b == 0xDC) { if (i + 2 > n) return false; i += 2; }
        else return false;
        if (i >= n) return false;
        uint8_t t = p[i++];
        size_t len;
        if (t == 0xC0) return true;                        /* nil name — valid, empty */
        else if (t >= 0xA0 && t <= 0xBF) len = t & 0x1F;   /* fixstr */
        else if (t == 0xD9 || t == 0xC4) { if (i >= n) return false; len = p[i++]; }
        else if (t == 0xDA || t == 0xC5) { if (i + 2 > n) return false; len = ((size_t)p[i] << 8) | p[i+1]; i += 2; }
        else return false;
        if (i + len > n) return false;
        copy(p + i, len);
        return true;
    };
    if (n >= 34 && tryArray(32)) return;
    if (tryArray(0)) return;
    if (n > 32 && plausible(32, n - 32)) { copy(p + 32, n - 32); return; }
    if (plausible(0, n)) copy(p, n);
}

/* ─────────────── the node table ─────────────── */

namespace {

const uint8_t kNoKey[RNSD_NODE_KEY_LEN] = {};

/* Caller holds s_lock. -1 when the interface cannot attribute a packet to a
 * peer (a shared radio) and so has no node to find. */
int nodeFind(const char* iface, const uint8_t* key) {
    if (!key) return -1;
    for (int i = 0; i < RNSD_NODES_MAX; i++) {
        Node* e = &s_nodes[i];
        if (!e->used || std::strcmp(e->n.iface, iface) != 0) continue;
        if (std::memcmp(e->n.key, key, RNSD_NODE_KEY_LEN) == 0) return i;
    }
    return -1;
}

}  // namespace

void rnsdNodeDeclare(const char* iface, const uint8_t key[RNSD_NODE_KEY_LEN],
                     const char* label, bool up)
{
    if (!iface || !*iface) return;
    const uint8_t* k = key ? key : kNoKey;
    std::lock_guard<std::mutex> g(s_lock);
    int idx = nodeFind(iface, k);
    if (!up) {
        if (idx < 0) return;                 /* withdrawing what was never declared */
        s_nodes[idx].used = false;
        /* Its destinations go with it. Nothing announces a departure, so the
         * interface saying the peer is gone is the only evidence there is. */
        for (int i = 0; s_peers && i < RNSD_PEERS_MAX; i++)
            if (s_peers[i].used && s_peers[i].p.node == idx) s_peers[i].used = false;
        s_gen++;
        return;
    }
    if (idx < 0) {
        for (int i = 0; i < RNSD_NODES_MAX; i++) {
            if (s_nodes[i].used) continue;
            idx = i;
            s_nodes[i] = Node{};
            s_nodes[i].used = true;
            safeStrncpy(s_nodes[i].n.iface, iface, sizeof(s_nodes[i].n.iface));
            std::memcpy(s_nodes[i].n.key, k, RNSD_NODE_KEY_LEN);
            break;
        }
        if (idx < 0) { warn("peers: node table full (%d)", RNSD_NODES_MAX); return; }
    }
    safeStrncpy(s_nodes[idx].n.label, label ? label : "", sizeof(s_nodes[idx].n.label));
    s_gen++;
}

int rnsdNodesForEach(const char* iface_prefix,
                     void (*cb)(int idx, const rnsd_node_t*, void*), void* ctx)
{
    /* Declaration order, which is the order the peers became reachable — and
     * stable, so a node keeps its number in the listing across a refresh. */
    uint8_t ord[RNSD_NODES_MAX];
    int n = 0;
    {
        std::lock_guard<std::mutex> g(s_lock);
        for (int i = 0; i < RNSD_NODES_MAX; i++)
            if (s_nodes[i].used && prefixMatch(s_nodes[i].n.iface, iface_prefix))
                ord[n++] = (uint8_t)i;
    }
    if (!cb) return n;
    int visited = 0;
    for (int i = 0; i < n; i++) {
        rnsd_node_t one;
        {
            std::lock_guard<std::mutex> g(s_lock);
            Node* e = &s_nodes[ord[i]];
            if (!e->used || !prefixMatch(e->n.iface, iface_prefix)) continue;
            one = e->n;
        }
        cb(ord[i], &one, ctx);
        visited++;
    }
    return visited;
}

int rnsdNodesCount(const char* iface_prefix)
{
    return rnsdNodesForEach(iface_prefix, nullptr, nullptr);
}

/* ─────────────── the peer table ─────────────── */

void rnsdPeersObserve(const char* iface, uint8_t community_radius, uint8_t hops,
                      const uint8_t* origin,
                      const uint8_t dest[RNSD_DEST_HASH_LEN],
                      const uint8_t name_hash[RNSD_NAME_HASH_LEN],
                      const uint8_t* app_data, size_t app_n,
                      bool have_signal, int16_t rssi, int16_t snr10)
{
    if (!iface || !*iface) return;

    /* A node that FORWARDS. hops is the raw RNS count, which Transport::inbound
     * has already stepped for this hop, so 1 is the node at the other end of the
     * wire and anything above it travelled through that node from somewhere
     * else. Only a transport node produces that, so the announce proves it
     * without anyone being asked. Not gated on the radius: whether the peer
     * forwards is a fact about the peer, and an uplink — the radius-0 case — is
     * very nearly always one. */
    if (hops > 1) {
        std::lock_guard<std::mutex> g(s_lock);
        int idx = nodeFind(iface, origin);
        if (idx >= 0 && !s_nodes[idx].n.transport) {
            s_nodes[idx].n.transport = true;
            s_gen++;
        }
        return;
    }

    /* Direct, and now the radius does apply: an uplink's far end is a route
     * rather than a neighbourhood, and its announce firehose is every node in
     * the wide network that is one hop from IT. The node itself stays — it is
     * still the thing at the other end of the wire, under its address. */
    if (community_radius == 0) return;
    if (!ensureTable()) return;

    std::lock_guard<std::mutex> g(s_lock);
    int node = nodeFind(iface, origin);
    Peer* slot = nullptr;
    Peer* oldest = nullptr;
    for (int i = 0; i < RNSD_PEERS_MAX; i++) {
        Peer* e = &s_peers[i];
        if (!e->used) { if (!slot) slot = e; continue; }
        if (std::memcmp(e->p.dest, dest, RNSD_DEST_HASH_LEN) == 0 &&
            std::strcmp(e->p.iface, iface) == 0) { slot = e; break; }
        if (!oldest || e->p.heard < oldest->p.heard) oldest = e;
    }
    if (!slot) slot = oldest;
    if (!slot) return;

    bool fresh = !slot->used ||
                 std::memcmp(slot->p.dest, dest, RNSD_DEST_HASH_LEN) != 0 ||
                 std::strcmp(slot->p.iface, iface) != 0;
    if (fresh) {
        std::memset(&slot->p, 0, sizeof(slot->p));
        std::memcpy(slot->p.dest, dest, RNSD_DEST_HASH_LEN);
        safeStrncpy(slot->p.iface, iface, sizeof(slot->p.iface));
        slot->used = true;
    }
    slot->p.node = (int16_t)node;
    std::memcpy(slot->p.name_hash, name_hash, RNSD_NAME_HASH_LEN);
    const char* asp = rnsdAspectLabel(name_hash);
    safeStrncpy(slot->p.aspect, asp ? asp : "", sizeof(slot->p.aspect));
    /* An announce with no app_data does not erase a name an earlier one gave:
     * the transport probe announces nameless from the same node whose
     * lxmf.delivery carries the name, and each is its own row. */
    char nm[RNSD_PEER_NAME_MAX];
    rnsdAnnounceName(app_data, app_n, nm, sizeof(nm));
    if (nm[0] || fresh) safeStrncpy(slot->p.name, nm, sizeof(slot->p.name));
    slot->p.hops        = hops;
    slot->p.heard       = nowUnix();
    slot->p.announces  += 1;
    if (have_signal) {
        slot->p.have_signal = true;
        slot->p.rssi  = rssi;
        slot->p.snr10 = snr10;
    }
    if (node >= 0) {
        s_nodes[node].n.heard = slot->p.heard;
        uint16_t c = 0;
        for (int i = 0; i < RNSD_PEERS_MAX; i++)
            if (s_peers[i].used && s_peers[i].p.node == node) c++;
        s_nodes[node].n.peers = c;
    }
    s_gen++;
}

void rnsdPeersIfaceGone(const char* iface)
{
    if (!iface || !*iface) return;
    std::lock_guard<std::mutex> g(s_lock);
    for (int i = 0; s_peers && i < RNSD_PEERS_MAX; i++) {
        Peer* e = &s_peers[i];
        if (e->used && std::strcmp(e->p.iface, iface) == 0) { e->used = false; s_gen++; }
    }
    for (int i = 0; i < RNSD_NODES_MAX; i++) {
        Node* e = &s_nodes[i];
        if (e->used && std::strcmp(e->n.iface, iface) == 0) { e->used = false; s_gen++; }
    }
}

int rnsdPeersForEach(const char* iface_prefix,
                     void (*cb)(const rnsd_peer_t*, void*), void* ctx)
{
    if (!s_peers) return 0;
    /* An ORDER first, then one record at a time. The callback is a printer or a
     * publisher — both can block on their own transport — so the lock must not
     * be held across it; and a whole-table snapshot would be near four kilobytes
     * of stack on a task that has a few, so only the ordering (a slot index and
     * its timestamp) is taken in one pass. */
    struct Ord { uint8_t slot; uint32_t heard; } ord[RNSD_PEERS_MAX];
    int n = 0;
    {
        std::lock_guard<std::mutex> g(s_lock);
        for (int i = 0; i < RNSD_PEERS_MAX; i++) {
            Peer* e = &s_peers[i];
            if (!e->used || !prefixMatch(e->p.iface, iface_prefix)) continue;
            ord[n++] = { (uint8_t)i, e->p.heard };
        }
    }
    /* Most recently heard first — insertion sort over at most RNSD_PEERS_MAX. */
    for (int i = 1; i < n; i++) {
        Ord t = ord[i];
        int j = i - 1;
        while (j >= 0 && ord[j].heard < t.heard) { ord[j+1] = ord[j]; j--; }
        ord[j+1] = t;
    }
    if (!cb) return n;
    int visited = 0;
    for (int i = 0; i < n; i++) {
        rnsd_peer_t one;
        {
            std::lock_guard<std::mutex> g(s_lock);
            Peer* e = &s_peers[ord[i].slot];
            /* A slot can have been evicted or reused between the two passes —
             * an announce lands on the rnsd task while a CLI client is
             * printing. Skip what no longer matches rather than show a peer
             * under the wrong heading. */
            if (!e->used || e->p.heard != ord[i].heard ||
                !prefixMatch(e->p.iface, iface_prefix)) continue;
            one = e->p;
        }
        cb(&one, ctx);
        visited++;
    }
    return visited;
}

int rnsdPeersCount(const char* iface_prefix)
{
    return rnsdPeersForEach(iface_prefix, nullptr, nullptr);
}

/* ─────────────── the `n[eighbors]` printer ─────────────── */

bool rnsdIsNeighborsVerb(const char* tok)
{
    if (!tok) return false;
    return cliVerbIs(tok, "neighbors", 1) || cliVerbIs(tok, "neighbours", 1);
}

bool rnsdPeersCli(const char* args, const char* iface_prefix, const char* title)
{
    if (!args) return false;
    while (*args == ' ') args++;
    char verb[16];
    size_t n = 0;
    while (args[n] && args[n] != ' ' && n + 1 < sizeof verb) { verb[n] = args[n]; n++; }
    verb[n] = '\0';
    if (!rnsdIsNeighborsVerb(verb)) return false;
    rnsdPeersPrint(iface_prefix, title, std::strstr(args + n, "-v") != nullptr);
    return true;
}

namespace {

void ago(char* b, size_t n, uint32_t now, uint32_t then) {
    uint32_t s = now > then ? now - then : 0;
    if      (s < 120)   std::snprintf(b, n, "%us", (unsigned)s);
    else if (s < 7200)  std::snprintf(b, n, "%um", (unsigned)(s / 60));
    else                std::snprintf(b, n, "%uh", (unsigned)(s / 3600));
}

/* `num` is the node's number, printed on its first row only and blank on every
 * continuation, so a node reads as one block. `want` selects which node's
 * destinations this pass prints; -1 takes the ones no node could be found for. */
struct PrintCtx { uint32_t now; bool verbose; const char* num; int want; int rows; };

void printPeer(const rnsd_peer_t* p, void* ud) {
    PrintCtx* c = (PrintCtx*)ud;
    if (p->node != c->want) return;
    char h[2 * RNSD_DEST_HASH_LEN + 1], nh[2 * RNSD_NAME_HASH_LEN + 1], t[16];
    hex(h, p->dest, RNSD_DEST_HASH_LEN);
    hex(nh, p->name_hash, RNSD_NAME_HASH_LEN);
    ago(t, sizeof t, c->now, p->heard);
    cliPrintf(RNSD_PEER_ROW_FMT "%s %s", c->rows ? "" : c->num, h,
              p->aspect[0] ? p->aspect : nh);
    if (p->name[0]) cliPrintf("  \"%s\"", p->name);
    cliPrintf("  %s ago\n", t);
    c->rows++;
    if (!c->verbose) return;
    cliPrintf(RNSD_PEER_ROW_PAD "%u announce%s",
              (unsigned)p->announces, p->announces == 1 ? "" : "s");
    if (p->have_signal)
        cliPrintf("  %d dBm  %.1f dB", (int)p->rssi, (double)p->snr10 / 10.0);
    cliPrintf("\n");
}

struct NodeCtx { const char* prefix; bool verbose; uint32_t now; int num; };

void printNode(int idx, const rnsd_node_t* nd, void* ud) {
    NodeCtx* c = (NodeCtx*)ud;
    char num[12];
    std::snprintf(num, sizeof num, "%d", ++c->num);
    PrintCtx pc = { c->now, c->verbose, num, idx, 0 };
    rnsdPeersForEach(c->prefix, printPeer, &pc);
    /* Reachable and silent is a state, not an absence: the interface said this
     * peer is there, so it gets a row under its transport address whatever else
     * is known. On an uplink that is the whole row by design — its destinations
     * are a route, not a neighbourhood — and saying so beats an empty "nothing
     * heard", which reads as a link that is not working. */
    if (!pc.rows)
        cliPrintf(RNSD_PEER_ROW_FMT "%s  %s\n", num,
                  nd->label[0] ? nd->label : nd->iface,
                  rnsdIfaceRadius(nd->iface) ? "(no announce yet)"
                                             : "(uplink — destinations not tracked)");
    if (nd->transport) cliPrintf(RNSD_PEER_ROW_PAD "( TRANSPORT )\n");
    if (c->verbose && nd->label[0])
        cliPrintf(RNSD_PEER_ROW_PAD "%s on %s\n", nd->label, nd->iface);
    cliPrintf("\n");
}

/* The unattributed tail: one destination, one number, no block. */
struct FlatCtx { uint32_t now; bool verbose; int num; };

void printFlat(const rnsd_peer_t* p, void* ud) {
    FlatCtx* f = (FlatCtx*)ud;
    if (p->node >= 0) return;
    char num[12];
    std::snprintf(num, sizeof num, "%d", ++f->num);
    PrintCtx one = { f->now, f->verbose, num, -1, 0 };
    printPeer(p, &one);
    cliPrintf("\n");
}

struct IfaceCtx { const char* prefix; int shown; int uplinks; };

}  // namespace

void rnsdPeersPrint(const char* iface_prefix, const char* title, bool verbose)
{
    const char* prefix = iface_prefix ? iface_prefix : "";
    /* The interface REGISTRATIONS are the straddle's plumbing — one per
     * Bluetooth peer, one per TCP connection — and a listing that named them
     * would be reporting that rather than the neighbourhood. So the medium is
     * named once, and the nodes under it are numbered straight through. */
    cliPrintf("%s neighbors:\n\n", title && *title ? title : prefix);

    NodeCtx nc = { prefix, verbose, nowUnix(), 0 };
    rnsdNodesForEach(prefix, printNode, &nc);

    /* Destinations no node could be attributed to: a shared broadcast medium,
     * where a packet carries no statement of who transmitted it. One row each,
     * numbered on from the nodes, because one destination is exactly what is
     * known — grouping them would be a guess. */
    FlatCtx fc = { nc.now, verbose, nc.num };
    rnsdPeersForEach(prefix, printFlat, &fc);

    if (fc.num == 0) cliPrintf("  (none heard yet)\n\n");

    /* Only where the list said nothing. A node row states its own case — an
     * uplink says so on its own line — so repeating it per interface here would
     * be the same fact twice. What is left to explain is an empty list, and
     * naming the registrations behind it is the explanation. */
    if (fc.num > 0) return;
    IfaceCtx ic = { prefix, 0, 0 };
    rnsdIfaceWalk([](const char* name, uint8_t radius, void* ud) {
        IfaceCtx* c = (IfaceCtx*)ud;
        if (!prefixMatch(name, c->prefix)) return;
        c->shown++;
        if (radius) return;
        if (!c->uplinks++)
            cliPrintf("  community radius 0 — an uplink, no neighbourhood tracked:");
        cliPrintf(" %s", name);
    }, &ic);
    if (ic.uplinks) cliPrintf("\n");
    if (ic.shown == 0) cliPrintf("  (no interface registered)\n");
}

/* ─────────────── ephemeral publication ───────────────
 *
 * One standardised shape for every medium, so a graph drawer reads peers the
 * same way whatever they arrived over. LoRa's own table knows more per peer
 * (node identity, link ids, power) and publishes that itself; what is common
 * lives here, and a reader that only understands this shape still sees the
 * whole neighbourhood.
 */

namespace {

void publishPeer(int i, const rnsd_peer_t* p) {
    char key[64], h[2 * RNSD_DEST_HASH_LEN + 1], nh[2 * RNSD_NAME_HASH_LEN + 1], v[16];
    hex(h, p->dest, RNSD_DEST_HASH_LEN);
    hex(nh, p->name_hash, RNSD_NAME_HASH_LEN);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.iface", i);     storageSet(key, p->iface);
    /* Which node announced it — the edge of the graph. `-1` on a shared medium
     * that cannot say who transmitted a packet, which is a real answer and not
     * a missing one. */
    std::snprintf(key, sizeof key, "rnsd.peers.%d.node", i);      storageSet(key, (int)p->node);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.dest", i);      storageSet(key, h);
    /* The aspect in words where rnsd knows the name behind the hash, the hash
     * itself where it does not — never empty, since a reader always has
     * something to key a row on. */
    std::snprintf(key, sizeof key, "rnsd.peers.%d.aspect", i);    storageSet(key, p->aspect[0] ? p->aspect : nh);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.name", i);      storageSet(key, p->name);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.hops", i);      storageSet(key, (int)p->hops);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.heard", i);     storageSet(key, (int)p->heard);
    std::snprintf(key, sizeof key, "rnsd.peers.%d.announces", i); storageSet(key, (int)p->announces);
    /* Always written, EMPTY where the medium measures no signal: the field is
     * part of the standard shape, and its emptiness is the answer ("this medium
     * has no such number"), which a zero would not be. Written as text for the
     * same reason — an int key cannot be empty. */
    if (p->have_signal) std::snprintf(v, sizeof v, "%d", (int)p->rssi); else v[0] = '\0';
    std::snprintf(key, sizeof key, "rnsd.peers.%d.rssi", i);      storageSet(key, v);
    if (p->have_signal) std::snprintf(v, sizeof v, "%.1f", (double)p->snr10 / 10.0); else v[0] = '\0';
    std::snprintf(key, sizeof key, "rnsd.peers.%d.snr", i);       storageSet(key, v);
}

/* Nodes are published under their TABLE index, not a compacted one, because a
 * peer names its node by that index — compaction would renumber the graph's
 * edges every time a Bluetooth peer came or went. A withdrawn node's subtree is
 * deleted; `rnsd.nodes.slots` is how far a reader iterates. */
void publishNode(int i, const rnsd_node_t* nd) {
    char key[64], k[2 * RNSD_NODE_KEY_LEN + 1];
    hex(k, nd->key, RNSD_NODE_KEY_LEN);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.iface", i);     storageSet(key, nd->iface);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.key", i);       storageSet(key, k);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.label", i);     storageSet(key, nd->label);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.transport", i); storageSet(key, nd->transport ? 1 : 0);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.heard", i);     storageSet(key, (int)nd->heard);
    std::snprintf(key, sizeof key, "rnsd.nodes.%d.peers", i);     storageSet(key, (int)nd->peers);
}

void publishIfacePeers(const char* name, uint8_t radius, void*) {
    char key[80];
    std::snprintf(key, sizeof key, "rnsd.ifaces.%s.peers", name);
    storageSet(key, radius ? rnsdPeersCount(name) : 0);
    std::snprintf(key, sizeof key, "rnsd.ifaces.%s.nodes", name);
    storageSet(key, radius ? rnsdNodesCount(name) : 0);
}

void publishPeers() {
    /* Table order, not recency: an index that reshuffled on every announce
     * would rewrite every row for one peer's timestamp. Here a peer keeps its
     * index until the membership changes, so an ordinary announce dirties two
     * keys. A reader that wants them newest-first sorts on `heard`, which it
     * has. */
    int used = 0;
    {
        std::lock_guard<std::mutex> g(s_lock);
        for (int i = 0; s_peers && i < RNSD_PEERS_MAX; i++) if (s_peers[i].used) used++;
    }
    /* Rows the table no longer has go FIRST, and outside the op bracket — a
     * delete does not ride the op list, and a reader must never see a count
     * that still spans a stale peer. */
    for (int i = used; i < s_pubCount; i++) {
        char key[48];
        std::snprintf(key, sizeof key, "rnsd.peers.%d", i);
        storageDeleteTree(key);
    }
    s_pubCount = used;

    /* A node that has gone: its slot is a graph vertex id, so the subtree is
     * dropped rather than renumbered. */
    for (int i = 0; i < RNSD_NODES_MAX; i++) {
        bool live;
        { std::lock_guard<std::mutex> g(s_lock); live = s_nodes[i].used; }
        if (live || !(s_pubNodes & (1u << i))) continue;
        char key[48];
        std::snprintf(key, sizeof key, "rnsd.nodes.%d", i);
        storageDeleteTree(key);
        s_pubNodes &= ~(1u << i);
    }

    /* One bracket for the rest: unbracketed this is a sync round-trip to the
     * storage actor per key, and a full table is a few hundred of them. */
    storageBegin();
    for (int i = 0; i < RNSD_NODES_MAX; i++) {
        rnsd_node_t nd;
        {
            std::lock_guard<std::mutex> g(s_lock);
            if (!s_nodes[i].used) continue;
            nd = s_nodes[i].n;
        }
        publishNode(i, &nd);
        s_pubNodes |= (1u << i);
    }
    storageSet("rnsd.nodes.slots", RNSD_NODES_MAX);

    rnsd_peer_t snap;
    int n = 0;
    for (int i = 0; s_peers && i < RNSD_PEERS_MAX && n < used; i++) {
        {
            std::lock_guard<std::mutex> g(s_lock);
            if (!s_peers[i].used) continue;
            snap = s_peers[i].p;
        }
        publishPeer(n++, &snap);
    }
    storageSet("rnsd.peers.count", n);
    rnsdIfaceWalk(publishIfacePeers, nullptr);
    storageEnd();
}

}  // namespace

void rnsdPeersTick(void)
{
    uint32_t ttl = (uint32_t)storageGetInt("s.rnsd.path.ttl", RNSD_PEER_TTL_DEFAULT_S);
    uint32_t now = nowUnix();
    {
        std::lock_guard<std::mutex> g(s_lock);
        bool dropped = false;
        for (int i = 0; s_peers && i < RNSD_PEERS_MAX; i++) {
            Peer* e = &s_peers[i];
            if (e->used && now > e->p.heard && now - e->p.heard > ttl) {
                e->used = false;
                dropped = true;
                s_gen++;
            }
        }
        /* A node's destination count follows its destinations. The NODE itself
         * does not age out with them: it is there because the interface says it
         * is reachable, and a silent peer is still a peer. */
        if (dropped) {
            for (int k = 0; k < RNSD_NODES_MAX; k++) {
                if (!s_nodes[k].used) continue;
                uint16_t c = 0;
                for (int i = 0; s_peers && i < RNSD_PEERS_MAX; i++)
                    if (s_peers[i].used && s_peers[i].p.node == k) c++;
                s_nodes[k].n.peers = c;
            }
        }
    }
    if (s_gen == s_pubGen) return;
    /* Same gate the other stat publishers use: on a headless, WiFi-down node
     * nothing reads these, and a neighbourhood churns on every announce. */
    if (!uiTelemetryWanted()) return;
    publishPeers();
    s_pubGen = s_gen;
}

/* ─────────────── status-line pills ─────────────── */

void rnsdPillSet(const char* id, char letter, int count, const char* color, int order)
{
    if (!id || !*id) return;
    char key[64], text[16];
    std::snprintf(text, sizeof text, "%c%d", letter, count);
    storageBegin();
    std::snprintf(key, sizeof key, "rns.pill.%s.text", id);  storageSet(key, text);
    std::snprintf(key, sizeof key, "rns.pill.%s.color", id); storageSet(key, color ? color : "888888");
    std::snprintf(key, sizeof key, "rns.pill.%s.order", id); storageSet(key, order);
    storageEnd();
}

void rnsdPillColor(const char* id, const char* color, int order, const char* title)
{
    if (!id || !*id) return;
    char key[64];
    storageBegin();
    std::snprintf(key, sizeof key, "rns.pill.%s.color", id); storageSet(key, color ? color : "888888");
    std::snprintf(key, sizeof key, "rns.pill.%s.order", id); storageSet(key, order);
    /* The class slug is the fallback everywhere that reads this, so a straddle
     * with nothing better to say publishes nothing rather than a duplicate. */
    std::snprintf(key, sizeof key, "rns.pill.%s.title", id); storageSet(key, title && *title ? title : "");
    storageEnd();
    /* No `text`: both renderers gate on it, so this publishes a palette entry
     * and not a pill. */
}

void rnsdPillClear(const char* id)
{
    if (!id || !*id) return;
    /* Emptied, not deleted: a delete fires no change callback, so the display's
     * renderer would never learn the pill had gone. The colour and the order
     * stay, which also keeps the row in place if the class comes back. */
    char key[64];
    std::snprintf(key, sizeof key, "rns.pill.%s.text", id);
    storageSet(key, "");
}
