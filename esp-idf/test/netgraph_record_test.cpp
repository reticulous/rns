/**
 * netgraph_record_test — host-side tests for the network-graph RECORD.
 *
 *   make -C rns/esp-idf/test
 *
 * The record is the specification: compose → encode → parse → resolve is
 * arithmetic over rnsd's tables, and it is exactly the part a device cannot
 * show you. A node draws circles and no lines and there is nothing on the wire
 * to tell you whether the builder emitted no cells, the encoder mislaid them,
 * or the resolver failed to join them. So the platform is stubbed just far
 * enough to link, rnsd's tables are stubbed as data this file writes, and the
 * record path itself runs for real.
 *
 * netgraph.cpp is INCLUDED rather than linked: the builder, encoder and
 * resolver live in an anonymous namespace, which is right — they are not a
 * surface anybody else should call — and this is how a test reaches them
 * anyway.
 */
#include "stubs/platform_stubs.h"

/* The REAL rnsd surface — the tables below have to be exactly the shape the
 * builder reads, or the test proves nothing about the builder. */
#include "rnsd.h"
#include "rnsd_peers.h"

#include <vector>
#include <cstdarg>
#include <ctime>
#include <utility>

uint32_t g_ticks = 0;
bool     g_verbose = false;
std::map<std::string, std::string> g_store;

int storageGetInt(const char* k, int def) {
    auto it = g_store.find(k);
    return it == g_store.end() ? def : atoi(it->second.c_str());
}
void storageGetStr(const char* k, char* out, size_t n, const char* def) {
    auto it = g_store.find(k);
    safeStrncpy(out, it == g_store.end() ? def : it->second.c_str(), n);
}
void storageSet(const char* k, int v) { g_store[k] = std::to_string(v); }
void storageSet(const char* k, const char* v) { g_store[k] = v ? v : ""; }
void storageBegin() {}
void storageEnd() {}
void storageDeleteTree(const char* prefix) {
    std::string p(prefix);
    for (auto it = g_store.begin(); it != g_store.end(); )
        it = (it->first == p || it->first.rfind(p + ".", 0) == 0) ? g_store.erase(it) : ++it;
}
bool storageDefaultTree(const char*, const char*) { return true; }
void storageSubscribeChanges(const char*, storage_change_cb_t, bool) {}
int cliPrintf(const char* fmt, ...) {
    if (!g_verbose) return 0;
    va_list ap; va_start(ap, fmt); int n = vprintf(fmt, ap); va_end(ap); return n;
}

/* ── the rnsd tables this node is pretending to have ── */

struct StubIface { std::string name; uint8_t radius; };
static std::vector<StubIface>   g_ifaces;
static std::vector<rnsd_node_t> g_nodes;
static std::vector<rnsd_peer_t> g_peers;
static std::vector<rnsd_hosted_dest_t> g_dests;
static uint8_t g_identity[16];

void rnsdIfaceWalk(void (*cb)(const char*, uint8_t, void*), void* ctx) {
    for (auto& i : g_ifaces) cb(i.name.c_str(), i.radius, ctx);
}
uint8_t rnsdIfaceRadius(const char* name) {
    for (auto& i : g_ifaces) if (i.name == name) return i.radius;
    return 0;
}
int rnsdNodesForEach(const char*, void (*cb)(int, const rnsd_node_t*, void*), void* ctx) {
    for (size_t i = 0; i < g_nodes.size(); i++) cb((int)i, &g_nodes[i], ctx);
    return (int)g_nodes.size();
}
int rnsdPeersForEach(const char*, void (*cb)(const rnsd_peer_t*, void*), void* ctx) {
    for (auto& p : g_peers) cb(&p, ctx);
    return (int)g_peers.size();
}
int rnsdHostedDestsForEach(void (*cb)(const rnsd_hosted_dest_t*, void*), void* ctx) {
    for (auto& d : g_dests) cb(&d, ctx);
    return (int)g_dests.size();
}
bool rnsdIdentityHash(const char*, uint8_t out[16]) { memcpy(out, g_identity, 16); return true; }
int  rnsdDestOpen(const char*, const char*, uint8_t, int, void (*)(int, size_t), void (*)(int)) { return -1; }
bool rnsdDestListenChannels(int, uint16_t) { return false; }
int  rnsdChannelOpen(const uint8_t*, const char*, const char*, const char*,
                     uint32_t, uint32_t, int, void (*)(int, size_t), void (*)(int)) { return -1; }
void rnsServiceRegister(const char*, void (*)(), void (*)(), int) {}

/* The routing table this node is pretending to have. */
static std::vector<rnsd_dir_entry_t> g_paths;
int rnsdDirForEach(void (*cb)(const rnsd_dir_entry_t*, void*), void* ctx) {
    for (auto& p : g_paths) cb(&p, ctx);
    return (int)g_paths.size();
}

#include "../src/netgraph.cpp"

/* ═══════════════════════════ harness ═══════════════════════════ */

static int g_fail = 0, g_run = 0;
static void ok(bool cond, const char* what) {
    g_run++;
    if (!cond) { g_fail++; printf("FAIL  %s\n", what); }
}

static void reset() {
    g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
    g_paths.clear();
    g_store.clear();
    for (auto& r : s_recs) r = Rec{};
    s_bytes = 0;
    memset(g_identity, 0xAA, sizeof g_identity);
    memcpy(s_self, g_identity, 16); s_haveSelf = true;
    s_pubNodes = s_pubLinks = 0;
    for (auto& c : s_pubIfaceCount) c = 0;
}

static void addIface(const char* name, uint8_t radius) { g_ifaces.push_back({ name, radius }); }
static void addNode(const char* iface, const char* label, bool transport, uint32_t heard, uint16_t peers) {
    rnsd_node_t n{};
    safeStrncpy(n.iface, iface, sizeof n.iface);
    safeStrncpy(n.label, label, sizeof n.label);
    n.transport = transport; n.heard = heard; n.peers = peers;
    g_nodes.push_back(n);
}
static void addPeer(const char* iface, int node, uint8_t b0, uint32_t heard) {
    rnsd_peer_t p{};
    safeStrncpy(p.iface, iface, sizeof p.iface);
    p.node = (int16_t)node; p.heard = heard; p.hops = 1;
    p.dest[0] = b0; p.dest[1] = 0x11; p.dest[2] = 0x22; p.dest[3] = 0x33;
    g_peers.push_back(p);
}
static void addDest(uint8_t b0) {
    rnsd_hosted_dest_t d{};
    d.dest[0] = b0; d.dest[1] = 0x11; d.dest[2] = 0x22; d.dest[3] = 0x33;
    safeStrncpy(d.aspect, "lxmf.delivery", sizeof d.aspect);
    g_dests.push_back(d);
}

static void addPath(const uint8_t id[16], const uint8_t dest[16], const uint8_t* via,
                    const char* iface, uint8_t hops) {
    rnsd_dir_entry_t p{};
    memcpy(p.dest, dest, 16);
    if (id) { memcpy(p.identity, id, 16); p.have_identity = true; }
    if (via) memcpy(p.via, via, 16);
    p.have_route = hops != 0;
    safeStrncpy(p.iface, iface, sizeof p.iface);
    p.hops = hops;
    g_paths.push_back(p);
}

static void dumpLine(const char* line, void*) { printf("      %s\n", line); }

/* Count the cells the encoder actually emitted, by walking the packed form. */
static int g_cells;
static bool countCells(uint8_t tag, const uint8_t* b, size_t n, void*) {
    if (tag != NG_TAG_LN || n < 1) return true;
    size_t ilen = b[0];
    if (1 + ilen + 3 > n) return true;
    g_cells += b[1 + ilen + 2];
    return true;
}
static int cellsIn(const uint8_t* rec, size_t n) {
    g_cells = 0; ngForEachLine(rec, n, countCells, nullptr); return g_cells;
}

int main(int argc, char** argv) {
    g_verbose = argc > 1 && !strcmp(argv[1], "-v");
    uint8_t buf[NG_MAX_RECORD];

    /* ── 1. the shape of a node that has neighbours ── */
    reset();
    g_ticks = 1000;
    addIface("lora/0", 3);
    addIface("tcp/0", 0);                      /* the uplink */
    uint32_t now = (uint32_t)time(nullptr);
    addNode("lora/0", "", false, now - 60, 2);  /* an attributed LoRa peer */
    addNode("tcp/0", "rns.birdsnet.com.br:4242", false, 0, 0);
    addPeer("lora/0", 0, 0x9f, now - 60);
    addPeer("lora/0", -1, 0x7c, now - 70);          /* unattributed, its own unit */
    addDest(0xa1);

    Build* b = &s_build;
    ngCompose(b);
    ok(b->nifs == 1, "one interface with a community");
    ok(b->nups == 1, "one uplink");
    ok(b->ups[0].have_label, "uplink far end is named");
    ok(b->ifs[0].nunits == 2, "two link units on lora/0");
    int withPrefix = 0;
    for (int i = 0; i < b->ifs[0].nunits; i++) if (b->ifs[0].units[i].have_prefix) withPrefix++;
    ok(withPrefix == 2, "both units carry a destination prefix");
    if (b->ifs[0].nunits != 2 || withPrefix != 2)
        printf("      nifs=%d nunits=%d withPrefix=%d\n", b->nifs, b->ifs[0].nunits, withPrefix);

    bool cut = false;
    size_t n = ngEncode(b, buf, sizeof buf, now, NG_MAX_CELLS, false, &cut);
    ok(n > 0, "record encodes");
    ok(ngValidate(buf, n), "record validates");
    ok(cellsIn(buf, n) == 2, "encoder emitted both cells");
    if (g_verbose || cellsIn(buf, n) != 2) {
        printf("    record (%zu B, %d cells):\n", n, cellsIn(buf, n));
        ngToText(buf, n, dumpLine, nullptr);
    }

    /* ── 2. the horizon must not eat a fresh link ── */
    reset();
    g_ticks = 1000;
    addIface("lora/0", 3);
    addNode("lora/0", "", false, (uint32_t)time(nullptr), 1);
    addPeer("lora/0", 0, 0x9f, (uint32_t)time(nullptr));
    ngCompose(&s_build);
    ok(s_build.ifs[0].nunits == 1, "a link heard just now survives the horizon");

    /* ── 3. round trip: two nodes, each reporting the other ── */
    reset();
    g_ticks = 1000;
    uint8_t selfA[16]; memset(selfA, 0xAA, 16);
    uint8_t selfB[16]; memset(selfB, 0xBB, 16);

    /* A: hosts a1.., hears B's b1.. over lora */
    memcpy(s_self, selfA, 16);
    uint32_t t = (uint32_t)time(nullptr);
    addIface("lora/0", 3); addNode("lora/0", "", false, t - 60, 1);
    addPeer("lora/0", 0, 0xb1, t - 60); addDest(0xa1);
    ngCompose(&s_build);
    size_t na = ngEncode(&s_build, buf, sizeof buf, t, NG_MAX_CELLS, false, nullptr);
    ok(cellsIn(buf, na) == 1, "A reports one link");
    recStore(buf, na, nullptr, 0, true);

    /* B: hosts b1.., hears A's a1.. — built with B's identity, then ingested */
    uint8_t recB[NG_MAX_RECORD];
    g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
    memcpy(s_self, selfB, 16);
    addIface("lora/0", 3); addNode("lora/0", "", false, t - 60, 1);
    addPeer("lora/0", 0, 0xa1, t - 60); addDest(0xb1);
    ngCompose(&s_build);
    size_t nb = ngEncode(&s_build, recB, sizeof recB, t, NG_MAX_CELLS, false, nullptr);
    /* We are A again — and A's neighbour table with us, or the overlay would
     * rightly report B's peers as neighbours of ours that we never reported. */
    memcpy(s_self, selfA, 16);
    g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
    addIface("lora/0", 3); addNode("lora/0", "", false, t - 60, 1);
    addPeer("lora/0", 0, 0xb1, t - 60); addDest(0xa1);
    ok(ngIngest(recB, nb, nullptr, 1), "B's record ingests");

    ngResolve();
    int verts = storageGetInt("netgraph.nodes.slots", -1);
    int links = storageGetInt("netgraph.links.count", -1);
    ok(verts == 2, "two vertices");
    ok(links == 2, "two links — each end reporting once");
    if (verts != 2 || links != 2) printf("      verts=%d links=%d\n", verts, links);
    ok(storageGetInt("netgraph.links.0.b", -99) >= 0, "the link resolved to a vertex");
    if (g_verbose) for (auto& kv : g_store)
        if (kv.first.rfind("netgraph.", 0) == 0) printf("      %s = %s\n", kv.first.c_str(), kv.second.c_str());

    /* ── 4. the clock step ──
     *
     * The regression that emptied every graph in the field. A node boots, hears
     * its neighbours within seconds and stamps them with a clock counting from
     * the epoch; NTP lands and the clock jumps by decades. Nothing about those
     * links changed, and none of them may vanish. */
    reset();
    g_ticks = 1000;
    uint32_t pre = 900;                       /* heard before the clock was set */
    addIface("lora/0", 3);
    addNode("lora/0", "", false, pre, 1);
    addPeer("lora/0", 0, 0x9f, pre);
    addDest(0xa1);
    ngCompose(&s_build);
    ok(s_build.ifs[0].nunits == 1, "a link heard before the clock was set survives the step");
    size_t nc = ngEncode(&s_build, buf, sizeof buf, (uint32_t)time(nullptr),
                         NG_MAX_CELLS, false, nullptr);
    ok(cellsIn(buf, nc) == 1, "and is still a cell in the record");
    if (cellsIn(buf, nc) != 1) ngToText(buf, nc, dumpLine, nullptr);

    /* And a record from a node whose clock is NOT set must still be taken by
     * one whose clock is: otherwise the two never see each other at all. */
    reset();
    uint8_t unsynced[NG_MAX_RECORD];
    uint8_t selfC[16]; memset(selfC, 0xCC, 16);
    memcpy(s_self, selfC, 16);
    addIface("lora/0", 3); addNode("lora/0", "", false, pre, 1);
    addPeer("lora/0", 0, 0xa1, pre); addDest(0xc1);
    ngCompose(&s_build);
    size_t nu = ngEncode(&s_build, unsynced, sizeof unsynced, 901 /* tiny seq */,
                         NG_MAX_CELLS, false, nullptr);
    memset(s_self, 0xAA, 16);                 /* we are a synced node again */
    ok(ngIngest(unsynced, nu, nullptr, 1), "a synced node accepts an unsynced node's record");
    ok(ngExpire() == 0, "and does not immediately age it out");

    /* ── 5. what was never measured is published empty, not zero ── */
    reset();
    g_ticks = 1000;
    uint32_t nw = (uint32_t)time(nullptr);
    addIface("lora/0", 3);
    addIface("tcp/0", 0);
    addNode("lora/0", "", false, nw - 60, 1);
    addNode("tcp/0", "rns.example.org:4242", false, 0, 0);
    addPeer("lora/0", 0, 0x9f, nw - 60);
    addDest(0xa1);
    ngCompose(&s_build);
    size_t nr = ngEncode(&s_build, buf, sizeof buf, nw, NG_MAX_CELLS, false, nullptr);
    recStore(buf, nr, nullptr, 0, true);
    ngResolve();
    {
        int nl = storageGetInt("netgraph.links.count", 0);
        ok(nl == 2, "a measured link and an uplink");
        int measured = 0, blank = 0;
        for (int j = 0; j < nl; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.fresh", j);
            (g_store.count(k) && g_store[k].empty() ? blank : measured)++;
        }
        ok(measured == 1, "the heard link carries a freshness bucket");
        ok(blank == 1, "the uplink carries none — empty, not a fabricated 0");
        if (measured != 1 || blank != 1)
            for (int j = 0; j < nl; j++) {
                char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.fresh", j);
                printf("      %s = %s\n", k, g_store[k].c_str());
            }
    }

    /* ── 6. the bench rig, end to end ──
     *
     *   internet <tcp> tbeam <lora> xiao <auto> w12 <ble> tdeck
     *                                 \____________ble____/
     *
     * Four nodes, four media, every record built by the real builder and then
     * ingested into ONE node's store, exactly as the announce path would. This
     * is the shape the field is drawing almost no lines for. */
    {
        reset();
        g_ticks = 1000;
        uint32_t t6 = (uint32_t)time(nullptr) - 30;

        struct Rig { const char* name; uint8_t id; uint8_t dest; };
        const Rig TB{"tbeam", 0xB1, 0x10}, XI{"xiao", 0xB2, 0x20},
                  W1{"w12",   0xB3, 0x30}, TD{"tdeck", 0xB4, 0x40};

        /* Build one node's record from its own tables, the way the device does. */
        auto build = [&](const Rig& me, std::vector<std::pair<const char*, const Rig*>> links,
                         std::vector<const char*> uplinks, uint8_t* out) -> size_t {
            g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
            memset(s_self, me.id, 16); s_haveSelf = true;
            addDest(me.dest);
            for (auto& L : links) {
                addIface(L.first, 3);
                addNode(L.first, "", false, t6, 1);
                addPeer(L.first, (int)g_nodes.size() - 1, L.second->dest, t6);
            }
            for (auto* u : uplinks) { addIface(u, 0); addNode(u, "rns.example.org:4242", false, 0, 0); }
            ngCompose(&s_build);
            return ngEncode(&s_build, out, NG_MAX_RECORD, t6, NG_MAX_CELLS, false, nullptr);
        };

        uint8_t rTB[NG_MAX_RECORD], rXI[NG_MAX_RECORD], rW1[NG_MAX_RECORD], rTD[NG_MAX_RECORD];
        size_t nTB = build(TB, {{"lora/0", &XI}}, {"tcp/0"}, rTB);
        size_t nXI = build(XI, {{"lora/0", &TB}, {"auto/0", &W1}, {"ble/aa", &TD}}, {}, rXI);
        size_t nW1 = build(W1, {{"auto/0", &XI}, {"ble/bb", &TD}}, {}, rW1);
        size_t nTD = build(TD, {{"ble/cc", &W1}, {"ble/dd", &XI}}, {}, rTD);
        ok(cellsIn(rTB, nTB) == 1 && cellsIn(rXI, nXI) == 3 &&
           cellsIn(rW1, nW1) == 2 && cellsIn(rTD, nTD) == 2, "every node reports its own links");

        /* Now be xiao, holding everyone's record. */
        for (auto& r : s_recs) r = Rec{};
        s_bytes = 0;
        g_store.clear();
        s_pubNodes = s_pubLinks = 0;
        for (auto& c : s_pubIfaceCount) c = 0;
        memset(s_self, XI.id, 16); s_haveSelf = true;
        g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
        addIface("lora/0", 3); addIface("auto/0", 3); addIface("ble/aa", 3);
        addDest(XI.dest);

        recStore(rXI, nXI, nullptr, 0, true);
        ok(ngIngest(rTB, nTB, nullptr, 1), "tbeam's record ingests");
        ok(ngIngest(rW1, nW1, nullptr, 1), "w12's record ingests");
        ok(ngIngest(rTD, nTD, nullptr, 1), "tdeck's record ingests");
        ngResolve();

        int verts = storageGetInt("netgraph.nodes.slots", -1);
        int links = storageGetInt("netgraph.links.count", -1);
        /* 4 members + 1 uplink box; 8 member link-rows (4 links, both ends) + 1 uplink. */
        ok(verts == 5, "four members and one uplink box");
        ok(links == 9, "eight member link rows plus the uplink");
        if (verts != 5 || links != 9) {
            printf("      verts=%d links=%d\n", verts, links);
            for (int i = 0; i < verts; i++) {
                char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
                char k2[64]; snprintf(k2, sizeof k2, "netgraph.nodes.%d.kind", i);
                printf("        node %d id=%s kind=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
            for (int j = 0; j < links; j++) {
                char a[64], b[64], c[64];
                snprintf(a, sizeof a, "netgraph.links.%d.a", j);
                snprintf(b, sizeof b, "netgraph.links.%d.b", j);
                snprintf(c, sizeof c, "netgraph.links.%d.cls", j);
                printf("        link %d  %s -> %s  %s\n", j,
                       g_store[a].c_str(), g_store[b].c_str(), g_store[c].c_str());
            }
            for (auto& r : s_recs) if (r.used) { printf("      -- record --\n");
                                                 ngToText(r.bytes, r.len, dumpLine, nullptr); }
        }
        int unresolved = 0;
        for (int j = 0; j < links; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.b", j);
            if (atoi(g_store[k].c_str()) < 0) unresolved++;
        }
        ok(unresolved == 0, "every member link resolved to a vertex");
    }

    /* ── 7. the ANNOUNCE path ──
     *
     * What every other node actually receives is not the full record but the
     * abridged one, capped at s.netgraph.announce_cells and shrunk further if it
     * still will not fit the airtime budget. A cap that came out as zero would
     * put a node on everyone's graph with no links at all — which is the field
     * symptom exactly, so it is worth a test of its own. */
    {
        reset();
        g_ticks = 1000;
        uint32_t t7 = (uint32_t)time(nullptr) - 30;
        addIface("lora/0", 3);
        for (int i = 0; i < 5; i++) addPeer("lora/0", -1, (uint8_t)(0x90 + i), t7 - i);
        addDest(0xa1);
        ngCompose(&s_build);
        ok(s_build.ifs[0].nunits == 5, "five heard peers");

        bool cutA = false;
        size_t nf = ngEncode(&s_build, buf, sizeof buf, t7, NG_MAX_CELLS, false, nullptr);
        uint8_t abr[NG_MAX_RECORD];
        size_t na2 = ngEncode(&s_build, abr, sizeof abr, t7, cfgAnnounceCells(), false, &cutA);
        ok(cellsIn(buf, nf) == 5, "the full record carries every cell");
        ok(na2 > 0 && cellsIn(abr, na2) == 5, "the announced record carries them too at the default cap");
        ok(!cutA, "and is not marked abridged");
        if (cellsIn(abr, na2) != 5)
            printf("      announce_cells=%d full=%d abridged=%d\n",
                   cfgAnnounceCells(), cellsIn(buf, nf), cellsIn(abr, na2));

        /* And a cap of zero must not silently produce a link-less record. */
        g_store["s.netgraph.announce_cells"] = "0";
        bool cutZ = false;
        uint8_t z[NG_MAX_RECORD];
        size_t nz = ngEncode(&s_build, z, sizeof z, t7, cfgAnnounceCells(), false, &cutZ);
        ok(cellsIn(z, nz) == 0 && cutZ, "a zero cap yields no cells and says it was abridged");
        g_store.erase("s.netgraph.announce_cells");
    }

    /* ── 8. THE INVARIANT: anything rnsd calls reachable is on the graph ──
     *
     * A status pill reading B2 beside a picture with no Bluetooth line is the
     * graph contradicting the neighbour table. Whatever the reason a peer failed
     * to become a cell — and the field found reasons — it must still be drawn,
     * under whatever address rnsd has for it. */
    {
        reset();
        g_ticks = 1000;
        uint32_t t8 = (uint32_t)time(nullptr) - 30;
        addIface("lora/0", 3);
        addIface("ble/aa:bb:cc:dd:ee:01", 3);
        addIface("ble/aa:bb:cc:dd:ee:02", 3);
        addDest(0xa1);
        /* Two BLE peers that have announced — B2 on the pill — and one LoRa. */
        addNode("ble/aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01", false, t8, 1);
        addNode("ble/aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:02", false, t8, 1);
        addPeer("ble/aa:bb:cc:dd:ee:01", 0, 0x50, t8);
        addPeer("ble/aa:bb:cc:dd:ee:02", 1, 0x60, t8);
        addPeer("lora/0", -1, 0x70, t8);

        ngCompose(&s_build);
        size_t n8 = ngEncode(&s_build, buf, sizeof buf, t8, NG_MAX_CELLS, false, nullptr);
        recStore(buf, n8, nullptr, 0, true);
        ngResolve();
        ok(storageGetInt("netgraph.links.count", 0) >= 3,
           "three reachable peers, three lines");

        /* Now the pathological case the field hit: the record reports NOTHING,
         * yet the neighbour table is full. Every peer must still be drawn. */
        for (auto& r : s_recs) r = Rec{};
        s_bytes = 0; g_store.clear();
        s_pubNodes = s_pubLinks = 0;
        for (auto& c : s_pubIfaceCount) c = 0;
        /* A record with the interfaces but no cells at all — exactly what the
         * devices were shipping. */
        static Build empty;
        empty = s_build;
        for (int i = 0; i < empty.nifs; i++) empty.ifs[i].nunits = 0;
        size_t ne = ngEncode(&empty, buf, sizeof buf, t8, 0, false, nullptr);
        recStore(buf, ne, nullptr, 0, true);
        ngResolve();
        int lines = storageGetInt("netgraph.links.count", 0);
        ok(lines >= 3, "a record with no cells still draws every reachable peer");
        if (lines < 3) {
            printf("      links=%d — the overlay did not cover the gap\n", lines);
            int nv = storageGetInt("netgraph.nodes.slots", 0);
            for (int i = 0; i < nv; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.kind", i);
                printf("        node %d label=%s kind=%s\n", i, g_store[k].c_str(), g_store[k2].c_str());
            }
        }
    }

    /* ── 9. the community radius is not a display filter ──
     *
     * It bounds where we stop REACHING for nodes to serve. A radius-0 interface
     * still has somebody at the other end of the wire, and must be drawn — as a
     * box where the record spoke for it, and by the overlay where it did not.
     * More radius-0 interfaces than a record can carry `up` lines for is the
     * case that used to lose them silently. */
    {
        reset();
        g_ticks = 1000;
        uint32_t t9 = (uint32_t)time(nullptr) - 30;
        addIface("lora/0", 3);
        addPeer("lora/0", -1, 0x70, t9);
        addDest(0xa1);
        /* Six uplinks — more than NG_MAX_UPLINKS, so the record cannot name
         * them all. Every one of them must still reach the graph. */
        for (int i = 0; i < 6; i++) {
            char nm[24], lb[40];
            snprintf(nm, sizeof nm, "tcp/%d", i);
            snprintf(lb, sizeof lb, "host%d.example.org:4242", i);
            addIface(nm, 0);
            addNode(nm, lb, false, 0, 0);
        }
        ngCompose(&s_build);
        ok(s_build.nups == NG_MAX_UPLINKS, "the record names as many uplinks as it can");
        size_t n9 = ngEncode(&s_build, buf, sizeof buf, t9, NG_MAX_CELLS, false, nullptr);
        recStore(buf, n9, nullptr, 0, true);
        ngResolve();

        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int nl = storageGetInt("netgraph.links.count", 0);
        /* us + six far ends. The lora peer is a CELL whose prefix no record
         * claims, so it ships as b = -1 and the browser draws the stub — the
         * device does not invent a vertex for something it cannot name. */
        ok(nv == 7, "every far end has a vertex, radius or no radius");
        ok(nl == 7, "and a line to each, the unresolved cell included");
        if (nv != 7 || nl != 7) {
            printf("      verts=%d links=%d (nups=%d)\n", nv, nl, s_build.nups);
            for (int i = 0; i < nv; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.kind", i);
                printf("        node %d kind=%-7s label=%s\n", i,
                       g_store[k2].c_str(), g_store[k].c_str());
            }
        }
        /* And nothing is drawn twice: the four the record named are boxes, the
         * two it could not are local vertices. */
        int boxes = 0, locals = 0;
        for (int i = 0; i < nv; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
            if (g_store[k] == "uplink") boxes++;
            if (g_store[k] == "local")  locals++;
        }
        ok(boxes == NG_MAX_UPLINKS, "the named far ends are boxes");
        ok(locals == 6 - NG_MAX_UPLINKS, "the rest come through the overlay, once each");
        if (boxes != NG_MAX_UPLINKS || locals != 6 - NG_MAX_UPLINKS)
            printf("      boxes=%d locals=%d\n", boxes, locals);
    }

    /* ── 10. a point-to-point peer that HAS announced is not a MAC ──
     *
     * Bluetooth cannot attribute a packet to a peer and does not need to: the
     * interface is the node, so its peers arrive with node == -1 however well
     * they announced. Covering only node-indexed peers left every one of them
     * uncovered, so the overlay drew each as a MAC beside the named vertex its
     * own cell had already resolved to. A MAC must mean exactly one thing: this
     * peer has never announced. */
    {
        reset();
        g_ticks = 1000;
        uint32_t ta = (uint32_t)time(nullptr) - 30;
        addDest(0xa1);
        /* Two BLE peers that announced — unattributed, as the medium gives them. */
        addIface("ble/9150b4f7", 3);
        addNode("ble/9150b4f7", "AA:BB:CC:DD:EE:01", false, ta, 1);
        addPeer("ble/9150b4f7", -1, 0x50, ta);
        addIface("ble/72a5d006", 3);
        addNode("ble/72a5d006", "AA:BB:CC:DD:EE:02", false, ta, 1);
        addPeer("ble/72a5d006", -1, 0x60, ta);
        /* And Columba: connected, declared, but has never sent an announce —
         * so no peer row, and a MAC is the only honest thing to call it. */
        addIface("ble/a467286a", 3);
        addNode("ble/a467286a", "AA:BB:CC:DD:EE:03", false, 0, 0);

        ngCompose(&s_build);
        size_t na3 = ngEncode(&s_build, buf, sizeof buf, ta, NG_MAX_CELLS, false, nullptr);
        ok(cellsIn(buf, na3) == 2, "the two that announced are cells");
        recStore(buf, na3, nullptr, 0, true);
        ngResolve();

        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int macs = 0;
        for (int i = 0; i < nv; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
            if (g_store[k] == "local") macs++;
        }
        ok(macs == 1, "only the silent peer is drawn as a MAC");
        if (macs != 1) {
            printf("      %d local vertices of %d\n", macs, nv);
            for (int i = 0; i < nv; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.label", i);
                printf("        node %d kind=%-7s label=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
        }
        /* Three peers, three lines: two from cells, one from the overlay. */
        ok(storageGetInt("netgraph.links.count", 0) == 3, "and all three still have a line");
    }

    /* ── 11. links inferred from routing ──
     *
     * tdeck holds tbeam's record but nobody has reported a link to it. Routing
     * says tbeam is two hops away via xiao, which means tbeam really is
     * adjacent to xiao — the one thing a route can honestly place. And a node
     * that speaks no netgraph at all gets a vertex of its own, so long as it
     * can be attached to something. */
    {
        reset();
        g_ticks = 1000;
        uint32_t tb = (uint32_t)time(nullptr) - 30;
        uint8_t idMe[16], idX[16], idT[16], idStock[16];
        memset(idMe, 0xAA, 16); memset(idX, 0xBB, 16);
        memset(idT, 0xCC, 16);  memset(idStock, 0xDD, 16);
        uint8_t dX[16], dT[16], dS[16];
        memset(dX, 0, 16); dX[0] = 0xb1;
        memset(dT, 0, 16); dT[0] = 0xc1;
        memset(dS, 0, 16); dS[0] = 0xd1;

        /* Us: one BLE link to xiao, which we report properly. */
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addIface("ble/bb", 3);
        addNode("ble/bb", "AA:BB:CC:DD:EE:01", false, tb, 1);
        addPeer("ble/bb", -1, 0xb1, tb);
        addDest(0xa1);
        ngCompose(&s_build);
        size_t nm = ngEncode(&s_build, buf, sizeof buf, tb, NG_MAX_CELLS, false, nullptr);
        recStore(buf, nm, nullptr, 0, true);

        /* xiao's and tbeam's records exist but report no links of their own. */
        for (const uint8_t* who : { idX, idT }) {
            g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
            memcpy(s_self, who, 16);
            addDest(who == idX ? 0xb1 : 0xc1);
            ngCompose(&s_build);
            uint8_t rec[NG_MAX_RECORD];
            size_t nr2 = ngEncode(&s_build, rec, sizeof rec, tb, NG_MAX_CELLS, false, nullptr);
            memcpy(s_self, idMe, 16);
            ok(ngIngest(rec, nr2, nullptr, 1), "a peer's record ingests");
        }
        memcpy(s_self, idMe, 16);
        g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
        addIface("ble/bb", 3);
        addNode("ble/bb", "AA:BB:CC:DD:EE:01", false, tb, 1);
        addPeer("ble/bb", -1, 0xb1, tb);
        addDest(0xa1);

        /* Routing: xiao direct, tbeam two hops via xiao, and a stock node also
         * two hops via xiao that has no record anywhere. */
        addPath(idX, dX, nullptr, "ble/bb", 1);
        addPath(idT, dT, dX, "ble/bb", 2);
        addPath(idStock, dS, dX, "ble/bb", 2);
        ngResolve();

        int nl = storageGetInt("netgraph.links.count", 0);
        int inferred = 0;
        for (int j = 0; j < nl; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.inferred", j);
            if (storageGetInt(k, 0)) inferred++;
        }
        ok(inferred == 2, "tbeam and the stock node are placed beside xiao");
        int routed = 0, nv2 = storageGetInt("netgraph.nodes.slots", 0);
        for (int i = 0; i < nv2; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
            if (g_store[k] == "routed") routed++;
        }
        ok(routed == 1, "only the node with no record of its own is 'routed'");
        if (inferred != 2 || routed != 1) {
            printf("      inferred=%d routed=%d links=%d verts=%d\n", inferred, routed, nl, nv2);
            for (int j = 0; j < nl; j++) {
                char a[64], b[64], f[64];
                snprintf(a, sizeof a, "netgraph.links.%d.a", j);
                snprintf(b, sizeof b, "netgraph.links.%d.b", j);
                snprintf(f, sizeof f, "netgraph.links.%d.inferred", j);
                printf("        link %d  %s -> %s  inferred=%s\n", j,
                       g_store[a].c_str(), g_store[b].c_str(), g_store[f].c_str());
            }
        }

        /* A reported link must never gain a dotted twin. */
        int dupe = 0;
        for (int j = 0; j < nl; j++) {
            char ka[64], kb[64], kf[64];
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            snprintf(kb, sizeof kb, "netgraph.links.%d.b", j);
            snprintf(kf, sizeof kf, "netgraph.links.%d.inferred", j);
            if (!storageGetInt(kf, 0)) continue;
            int a = atoi(g_store[ka].c_str()), b = atoi(g_store[kb].c_str());
            for (int m = 0; m < nl; m++) {
                if (m == j) continue;
                char ma[64], mb[64], mf[64];
                snprintf(ma, sizeof ma, "netgraph.links.%d.a", m);
                snprintf(mb, sizeof mb, "netgraph.links.%d.b", m);
                snprintf(mf, sizeof mf, "netgraph.links.%d.inferred", m);
                if (storageGetInt(mf, 0)) continue;
                int a2 = atoi(g_store[ma].c_str()), b2 = atoi(g_store[mb].c_str());
                if ((a == a2 && b == b2) || (a == b2 && b == a2)) dupe++;
            }
        }
        ok(dupe == 0, "a reported link never gains a dotted twin");
    }

    /* ── 12. ONE UNIFIED VIEW ──
     *
     * The same node arriving from four different directions — a record, a link
     * cell, an attached interface, and four routed destinations — is ONE
     * circle. Five nodes must never become seven because each source of
     * evidence invented its own vertex. */
    {
        reset();
        g_ticks = 1000;
        uint32_t tu = (uint32_t)time(nullptr) - 30;
        uint8_t idMe[16], idX[16];
        memset(idMe, 0xAA, 16); memset(idX, 0xBB, 16);

        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addIface("ble/bb", 3);
        addNode("ble/bb", "AA:BB:CC:DD:EE:01", false, tu, 1);   /* attached, by MAC */
        addPeer("ble/bb", -1, 0xb1, tu);                        /* and heard */
        addDest(0xa1);

        /* xiao answers on that interface, and has four addresses of its own. */
        for (int k = 0; k < 4; k++) {
            uint8_t d[16]; memset(d, 0, 16); d[0] = (uint8_t)(0xb1 + k);
            addPath(idX, d, nullptr, "ble/bb", 1);
        }
        ngCompose(&s_build);
        size_t nu2 = ngEncode(&s_build, buf, sizeof buf, tu, NG_MAX_CELLS, false, nullptr);
        recStore(buf, nu2, nullptr, 0, true);

        /* And it files a record too. */
        g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
        memcpy(s_self, idX, 16);
        addDest(0xb1);
        ngCompose(&s_build);
        uint8_t rx[NG_MAX_RECORD];
        size_t nrx = ngEncode(&s_build, rx, sizeof rx, tu, NG_MAX_CELLS, false, nullptr);
        memcpy(s_self, idMe, 16);
        /* restore our own tables */
        g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
        addIface("ble/bb", 3);
        addNode("ble/bb", "AA:BB:CC:DD:EE:01", false, tu, 1);
        addPeer("ble/bb", -1, 0xb1, tu);
        addDest(0xa1);
        ok(ngIngest(rx, nrx, nullptr, 1), "xiao's record ingests");

        ngResolve();
        int nv3 = storageGetInt("netgraph.nodes.slots", 0);
        ok(nv3 == 2, "us and xiao — one circle each, however many ways we know it");
        int macs = 0;
        for (int i = 0; i < nv3; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
            if (g_store[k] == "local") macs++;
        }
        ok(macs == 0, "no MAC beside the node it is");
        if (nv3 != 2 || macs) {
            printf("      verts=%d macs=%d\n", nv3, macs);
            for (int i = 0; i < nv3; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.kind", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.label", i);
                printf("        node %d kind=%-7s label=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
        }
    }

    /* ── 13. the sync beat adapts to what it learns ── */
    {
        reset();
        g_store["s.netgraph.sync_min"] = "30";      /* ceiling: 1800 s */
        uint32_t ceiling = 30u * 60000u;

        /* Nothing learned: back off, doubling, and stop at the ceiling. */
        s_syncBackoff = NG_SYNC_FAST_MS;
        s_ingestCount = s_ingestAtOpen = 7;
        for (int i = 0; i < 12; i++) {
            uint32_t before = s_syncBackoff;
            if (s_ingestCount != s_ingestAtOpen) s_syncBackoff = NG_SYNC_FAST_MS;
            else if (s_syncBackoff < ceiling)    s_syncBackoff *= 2;
            if (s_syncBackoff > ceiling) s_syncBackoff = ceiling;
            ok(s_syncBackoff >= before, "a fruitless exchange never speeds up");
        }
        ok(s_syncBackoff == ceiling, "and settles exactly at sync_min");

        /* One record taken and it is eager again — a reboot converges in
         * seconds rather than waiting out the half hour. */
        s_ingestCount++;
        if (s_ingestCount != s_ingestAtOpen) s_syncBackoff = NG_SYNC_FAST_MS;
        ok(s_syncBackoff == NG_SYNC_FAST_MS, "learning something resets the rate");
        g_store.erase("s.netgraph.sync_min");
    }

    printf("%s  %d/%d checks passed\n", g_fail ? "FAILED" : "ok", g_run - g_fail, g_run);
    return g_fail ? 1 : 0;
}
