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
std::string storageGetStr(const char* k, const char* def) {
    auto it = g_store.find(k);
    return it == g_store.end() ? std::string(def) : it->second;
}
void storageSet(const char* k, int v) { g_store[k] = std::to_string(v); }
void storageSet(const char* k, const char* v) { g_store[k] = v ? v : ""; }
/* The real one is unified with storageDeleteTree: one DELETE op that removes
 * the whole subtree under the key. A stub that erased only the exact key would
 * leave an array element's fields behind and make a compacting remove look
 * broken when it is not. */
void storageUnset(const char* k) {
    std::string p(k);
    for (auto it = g_store.begin(); it != g_store.end(); )
        it = (it->first == p || it->first.rfind(p + ".", 0) == 0) ? g_store.erase(it) : ++it;
}
/* Contiguous elements under an array prefix, stopping at the first gap — the
 * same contiguity the collection's add/remove maintain. */
int storageArrayCount(const char* prefix) {
    std::string p(prefix);
    int n = 0;
    for (;;) {
        std::string want = p + std::to_string(n) + ".";
        bool any = false;
        for (auto& kv : g_store)
            if (kv.first.rfind(want, 0) == 0) { any = true; break; }
        if (!any) return n;
        n++;
    }
}
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

/* ── remote management: present, inert ──
 *
 * Enough of the surface for netgraph.cpp to link. The crawl and the server are
 * exercised against a real rnsd on the bench, not here: this build has no
 * Reticulum under it, so a stub that pretended to answer would be testing the
 * stub. What it DOES verify is that the resolver folds crawl results correctly,
 * which is why ngCrawlNote below is the real function. */
bool rnsdRemoteManagementStart(void) { return false; }
void rnsdRemoteManagementStop(void) {}
void rnsdRemoteManagementAllow(const uint8_t (*)[16], int) {}
bool rnsdRemoteManagementServing(void) { return false; }
void rnsdRemoteManagementAnnounceData(const uint8_t*, size_t) {}
void rnsdSetRemoteAsker(void (*)(const uint8_t*)) {}
void rnsdSetNameResolver(bool (*)(const uint8_t*, char*, size_t)) {}
bool rnsdIdentityExists(const char*) { return false; }
bool rnsdIdentityPubkey(const char*, uint8_t*) { return false; }
bool rnsdEncryptFor(const uint8_t*, const uint8_t*, const uint8_t*, size_t,
                    uint8_t*, size_t*) { return false; }
bool rnsdDecryptSelf(const char*, const uint8_t*, const uint8_t*, size_t,
                     uint8_t*, size_t*) { return false; }
bool rnsdSign(const char*, const uint8_t*, size_t, uint8_t*) { return false; }
bool rnsdVerify(const uint8_t*, const uint8_t*, size_t, const uint8_t*) { return false; }
bool rnsdDestinationHashFromIdentityHash(const uint8_t*, const char*, const char*, uint8_t*)
    { return false; }
bool rnsdLinkIdentify(const char*, const char*) { return false; }
int  rnsdLinkOpen(const uint8_t*, const char*, const char*, const char*,
                  uint32_t, uint32_t, int, void (*)(int, size_t), void (*)(int)) { return -1; }
int  rnsdLinkRequest(const char*, const char*, const void*, size_t, uint16_t, bool) { return -1; }
void rnsdResourceRelease(void*) {}

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
/* A NODE-level aspect by default. A device announces several — its transport
 * ones, and one per application — and only the transport ones say "there is a
 * device here". A fixture that left the aspect empty would be testing a peer
 * the resolver is right to ignore. `aspect` is what a test overrides to build
 * the application case. */
#define NODE_ASPECT "rnstransport.probe"
#define APP_ASPECT  "lxmf.delivery"

static void addPeer(const char* iface, int node, uint8_t b0, uint32_t heard,
                    const char* aspect = NODE_ASPECT) {
    rnsd_peer_t p{};
    safeStrncpy(p.iface, iface, sizeof p.iface);
    safeStrncpy(p.aspect, aspect, sizeof p.aspect);
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
                    const char* iface, uint8_t hops,
                    const char* aspect = NODE_ASPECT) {
    rnsd_dir_entry_t p{};
    memcpy(p.dest, dest, 16);
    if (id) { memcpy(p.identity, id, 16); p.have_identity = true; }
    if (via) memcpy(p.via, via, 16);
    p.have_route = hops != 0;
    safeStrncpy(p.iface, iface, sizeof p.iface);
    safeStrncpy(p.aspect, aspect, sizeof p.aspect);
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

    /* ── 5. what carries no date is published empty, not zero ──
     *
     * A peer row carries a last-heard; an interface that has somebody attached
     * who has never announced carries nothing. `age_s` must say so by being
     * EMPTY: 0 already means "this second", and inventing it would claim we
     * watched something happen that we did not. */
    reset();
    g_ticks = 1000;
    uint32_t nw = (uint32_t)time(nullptr);
    addIface("lora/0", 3);
    addIface("tcp/0", 0);
    addNode("lora/0", "", false, nw - 60, 1);
    addNode("tcp/0", "rns.example.org:4242", false, 0, 0);
    addPeer("lora/0", 0, 0x9f, nw - 60);
    addDest(0xa1);
    ngResolve();
    {
        int nl = storageGetInt("netgraph.links.count", 0);
        ok(nl == 2, "the heard peer and the attached far end");
        int dated = 0, blank = 0;
        for (int j = 0; j < nl; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.age_s", j);
            (g_store.count(k) && g_store[k].empty() ? blank : dated)++;
        }
        ok(dated == 1, "the peer we heard carries an age");
        ok(blank == 1, "the one nobody dated carries none — empty, not a fabricated 0");
        for (int j = 0; j < nl && (dated != 1 || blank != 1); j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.age_s", j);
            printf("      %s = '%s'\n", k, g_store[k].c_str());
        }
        /* Both are `heard`: nothing is routed here, and that is the class. */
        int heard = 0;
        for (int j = 0; j < nl; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.ev", j);
            if (g_store[k] == "heard") heard++;
        }
        ok(heard == 2, "with no route to either, both are `heard`");
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

        /* Now be xiao, holding everyone's record AND its own neighbour tables —
         * which is the whole point: xiao's own three links come from routing and
         * interfaces, first-hand, and the other three nodes' links come from
         * their records. The two halves have to join into one drawing. */
        for (auto& r : s_recs) r = Rec{};
        s_bytes = 0;
        g_store.clear();
        s_pubNodes = s_pubLinks = 0;
        for (auto& c : s_pubIfaceCount) c = 0;
        memset(s_self, XI.id, 16); s_haveSelf = true;
        g_ifaces.clear(); g_nodes.clear(); g_peers.clear(); g_dests.clear();
        g_paths.clear();
        addDest(XI.dest);
        struct Near { const char* iface; const Rig* who; };
        const Near near[] = { {"lora/0", &TB}, {"auto/0", &W1}, {"ble/aa", &TD} };
        for (auto& L : near) {
            addIface(L.iface, 3);
            addNode(L.iface, "", false, t6, 1);
            addPeer(L.iface, (int)g_nodes.size() - 1, L.who->dest, t6);
            /* An announce is what creates a peer row, and it also files the
             * directory row that says whose address it was. Both, or the join
             * under test is not the one the device performs. */
            uint8_t id[16], d[16];
            memset(id, L.who->id, 16);
            memset(d, 0, 16); d[0] = L.who->dest; d[1] = 0x11; d[2] = 0x22; d[3] = 0x33;
            addPath(id, d, nullptr, L.iface, 1);
        }

        recStore(rXI, nXI, nullptr, 0, true);
        ok(ngIngest(rTB, nTB, nullptr, 1), "tbeam's record ingests");
        ok(ngIngest(rW1, nW1, nullptr, 1), "w12's record ingests");
        ok(ngIngest(rTD, nTD, nullptr, 1), "tdeck's record ingests");
        ngResolve();

        int verts = storageGetInt("netgraph.nodes.slots", -1);
        int links = storageGetInt("netgraph.links.count", -1);
        /* Four nodes, one circle each — xiao arrives from its own tables and the
         * other three from records, and neither may invent a second circle for a
         * node the other already has. */
        ok(verts == 4, "four nodes, one circle each");
        /* xiao's own three (route1, first-hand) plus what the other three
         * reported about themselves: tbeam 1, w12 2, tdeck 2. */
        ok(links == 8, "three of our own and five reported");
        if (verts != 4 || links != 8) {
            printf("      verts=%d links=%d\n", verts, links);
            for (int i = 0; i < verts; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.dist", i);
                printf("        node %d id=%s dist=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
            for (int j = 0; j < links; j++) {
                char a[64], b[64], c[64], e[64];
                snprintf(a, sizeof a, "netgraph.links.%d.a", j);
                snprintf(b, sizeof b, "netgraph.links.%d.b", j);
                snprintf(c, sizeof c, "netgraph.links.%d.cls", j);
                snprintf(e, sizeof e, "netgraph.links.%d.ev", j);
                printf("        link %d  %s -> %s  %s %s\n", j,
                       g_store[a].c_str(), g_store[b].c_str(),
                       g_store[c].c_str(), g_store[e].c_str());
            }
            for (auto& r : s_recs) if (r.used) { printf("      -- record --\n");
                                                 ngToText(r.bytes, r.len, dumpLine, nullptr); }
        }
        int unresolved = 0;
        for (int j = 0; j < links; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.b", j);
            if (atoi(g_store[k].c_str()) < 0) unresolved++;
        }
        ok(unresolved == 0, "every link resolved to a vertex");

        /* Our own three are route1, not record: we have them first-hand, and
         * our own record must never restate them as a second class. */
        int route1 = 0, record = 0;
        for (int j = 0; j < links; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.ev", j);
            if (g_store[k] == "route1") route1++;
            if (g_store[k] == "record") record++;
        }
        ok(route1 == 3, "our own links are routes, first-hand");
        ok(record == 5, "the rest are the other nodes' own reports");

        /* Distance falls out of the edges: everyone is one hop from xiao except
         * tbeam, which xiao routes to directly, so all three neighbours are 1. */
        for (int i = 0; i < verts; i++) {
            char k[64], kd[64];
            snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
            snprintf(kd, sizeof kd, "netgraph.nodes.%d.dist", i);
            bool isUs = g_store[k].rfind("b2b2", 0) == 0;
            ok(g_store[kd] == (isUs ? "0" : "1"),
               isUs ? "we are at distance 0" : "a neighbour is at distance 1");
        }
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
            printf("      links=%d — a reachable peer went undrawn\n", lines);
            int nv = storageGetInt("netgraph.nodes.slots", 0);
            for (int i = 0; i < nv; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.id", i);
                printf("        node %d label=%s id=%-8.8s\n", i, g_store[k].c_str(), g_store[k2].c_str());
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
        ngResolve();

        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int nl = storageGetInt("netgraph.links.count", 0);
        /* us + six far ends + the lora peer. Every one of them is drawn: the
         * record could only name four of the six, and the drawing does not come
         * from the record — it comes from the tables rnsd already keeps. */
        ok(nv == 8, "every far end has a vertex, radius or no radius");
        ok(nl == 7, "and a line to each");
        if (nv != 8 || nl != 7) {
            printf("      verts=%d links=%d (nups=%d)\n", nv, nl, s_build.nups);
            for (int i = 0; i < nv; i++) {
                char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
                printf("        node %d label=%s\n", i, g_store[k].c_str());
            }
        }
        /* And nothing is drawn twice — six far ends, six distinct labels. */
        std::map<std::string, int> seen;
        for (int i = 0; i < nv; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
            if (!g_store[k].empty()) seen[g_store[k]]++;
        }
        int dupes = 0;
        for (auto& kv : seen) if (kv.second > 1) dupes++;
        ok(dupes == 0, "and none of them twice");
        if (dupes) for (auto& kv : seen) if (kv.second > 1)
            printf("      %s appears %d times\n", kv.first.c_str(), kv.second);
    }

    /* ── 10. a point-to-point peer that HAS announced is not a MAC ──
     *
     * Bluetooth cannot attribute a packet to a peer and does not need to: the
     * interface is the node, so its peers arrive with node == -1 however well
     * they announced. Every table that reaches such an interface — the node row
     * and each peer row on it — has to land on ONE circle, keyed by whoever
     * answers there. A MAC must mean exactly one thing: this peer has never
     * announced. */
    {
        reset();
        g_ticks = 1000;
        uint32_t ta = (uint32_t)time(nullptr) - 30;
        addDest(0xa1);
        uint8_t id1[16], id2[16], d1[16], d2[16];
        memset(id1, 0xE1, 16); memset(id2, 0xE2, 16);
        memset(d1, 0, 16); d1[0] = 0x50; d1[1] = 0x11; d1[2] = 0x22; d1[3] = 0x33;
        memset(d2, 0, 16); d2[0] = 0x60; d2[1] = 0x11; d2[2] = 0x22; d2[3] = 0x33;

        /* Two BLE peers that announced — unattributed, as the medium gives them,
         * and each with the directory row its announce filed. */
        addIface("ble/9150b4f7", 3);
        addNode("ble/9150b4f7", "AA:BB:CC:DD:EE:01", false, ta, 1);
        addPeer("ble/9150b4f7", -1, 0x50, ta);
        addPath(id1, d1, nullptr, "ble/9150b4f7", 1);
        addIface("ble/72a5d006", 3);
        addNode("ble/72a5d006", "AA:BB:CC:DD:EE:02", false, ta, 1);
        addPeer("ble/72a5d006", -1, 0x60, ta);
        addPath(id2, d2, nullptr, "ble/72a5d006", 1);
        /* And Columba: connected, declared, but has never sent an announce —
         * so no peer row, no directory row, and a MAC is the only honest thing
         * to call it. */
        addIface("ble/a467286a", 3);
        addNode("ble/a467286a", "AA:BB:CC:DD:EE:03", false, 0, 0);

        ngCompose(&s_build);
        size_t na3 = ngEncode(&s_build, buf, sizeof buf, ta, NG_MAX_CELLS, false, nullptr);
        ok(cellsIn(buf, na3) == 2, "the two that announced are cells");
        ngResolve();

        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int macs = 0, ided = 0;
        for (int i = 0; i < nv; i++) {
            char k[64], kl[64];
            snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
            snprintf(kl, sizeof kl, "netgraph.nodes.%d.label", i);
            if (g_store[kl].rfind("AA:BB:", 0) == 0) macs++;
            else if (!g_store[k].empty()) ided++;
        }
        ok(macs == 1, "only the silent peer is drawn as a MAC");
        ok(ided == 3, "us and the two that announced are known by identity");
        if (macs != 1 || ided != 3) {
            printf("      %d MACs, %d identified, of %d\n", macs, ided, nv);
            for (int i = 0; i < nv; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.label", i);
                printf("        node %d id=%-8.8s label=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
        }
        /* Three far ends, three lines — and the two that announced are ROUTED,
         * because a directory row with a one-hop route is exactly that. */
        ok(storageGetInt("netgraph.links.count", 0) == 3, "and all three still have a line");
        int r1 = 0, hd = 0;
        for (int j = 0; j < 3; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.ev", j);
            if (g_store[k] == "route1") r1++;
            if (g_store[k] == "heard")  hd++;
        }
        ok(r1 == 2, "the two we route to are route1");
        ok(hd == 1, "the one we merely hold is heard");
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
        /* `via` is the forwarding node's IDENTITY hash — upstream fills it from
         * Transport.identity.hash, not from any destination that node hosts.
         * This fixture passed xiao's destination for years because the resolver
         * looked it up as one; both were wrong together, so nothing failed. */
        addPath(idT, dT, idX, "ble/bb", 2);
        addPath(idStock, dS, idX, "ble/bb", 2);
        ngResolve();

        int nl = storageGetInt("netgraph.links.count", 0);
        int route2 = 0, route1 = 0;
        int viaXiao = 0, xiaoVert = ngVertexOfIdentity(&s_res, idX);
        for (int j = 0; j < nl; j++) {
            char k[64], ka[64];
            snprintf(k, sizeof k, "netgraph.links.%d.ev", j);
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            if (g_store[k] == "route1") route1++;
            if (g_store[k] == "route2") {
                route2++;
                if (atoi(g_store[ka].c_str()) == xiaoVert) viaXiao++;
            }
        }
        ok(route2 == 2, "tbeam and the stock node are two hops out");
        ok(viaXiao == 2, "and both hang off xiao, not off us");
        ok(route1 == 1, "xiao itself is one hop, from our own table");

        /* A route2 carries no class: our iface names what WE transmit on, not
         * what the via-node used, and colouring it would assert a medium. */
        int coloured = 0;
        for (int j = 0; j < nl; j++) {
            char k[64], kc[64];
            snprintf(k, sizeof k, "netgraph.links.%d.ev", j);
            snprintf(kc, sizeof kc, "netgraph.links.%d.cls", j);
            if (g_store[k] == "route2" && !g_store[kc].empty()) coloured++;
        }
        ok(coloured == 0, "a two-hop route claims no medium");

        int nv2 = storageGetInt("netgraph.nodes.slots", 0);
        ok(nv2 == 4, "us, xiao, tbeam and the stock node");
        if (route2 != 2 || viaXiao != 2 || nv2 != 4) {
            printf("      route1=%d route2=%d viaXiao=%d links=%d verts=%d xiao=%d\n",
                   route1, route2, viaXiao, nl, nv2, xiaoVert);
            for (int j = 0; j < nl; j++) {
                char a[64], b[64], f[64];
                snprintf(a, sizeof a, "netgraph.links.%d.a", j);
                snprintf(b, sizeof b, "netgraph.links.%d.b", j);
                snprintf(f, sizeof f, "netgraph.links.%d.ev", j);
                printf("        link %d  %s -> %s  %s\n", j,
                       g_store[a].c_str(), g_store[b].c_str(), g_store[f].c_str());
            }
        }

        /* THE FOLD: xiao is both routed and heard, and that is ONE line. A
         * dashed `heard` drawn over the solid `route1` for every neighbour we
         * route through is what the precedence rule exists to prevent. */
        int pairs = 0;
        for (int j = 0; j < nl; j++) {
            char ka[64], kb[64], kc[64];
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            snprintf(kb, sizeof kb, "netgraph.links.%d.b", j);
            snprintf(kc, sizeof kc, "netgraph.links.%d.cls", j);
            for (int m = j + 1; m < nl; m++) {
                char ma[64], mb[64], mc[64];
                snprintf(ma, sizeof ma, "netgraph.links.%d.a", m);
                snprintf(mb, sizeof mb, "netgraph.links.%d.b", m);
                snprintf(mc, sizeof mc, "netgraph.links.%d.cls", m);
                if (g_store[ka] == g_store[ma] && g_store[kb] == g_store[mb] &&
                    g_store[kc] == g_store[mc]) pairs++;
            }
        }
        ok(pairs == 0, "one row per (a, b, class) — routed-and-heard is one line");
        int dist = -1;
        for (int i = 0; i < nv2; i++) {
            char k[64], kd[64];
            snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
            snprintf(kd, sizeof kd, "netgraph.nodes.%d.dist", i);
            if (g_store[k].rfind("cccc", 0) == 0) dist = atoi(g_store[kd].c_str());
        }
        ok(dist == 2, "tbeam solves to two hops from the edges alone");

        /* `via` IS AN IDENTITY, and nothing else will do. A destination hash
         * there must match nothing — and with no interface to fall back on,
         * that means the route is not placed at all rather than hung off a
         * circle invented for a node that does not exist.
         *
         * The two-hop route is put on an interface with no one-hop node route
         * of its own, so the point-to-point fallback cannot fire and answer the
         * question by other means. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("ble/bb", 3);
        addIface("ble/zz", 3);
        addPath(idX, dX, nullptr, "ble/bb", 1);
        addPath(idT, dT, dX, "ble/zz", 2);      /* a DESTINATION as via: wrong */
        ngResolve();
        int nl2 = storageGetInt("netgraph.links.count", 0);
        int r2 = 0;
        for (int j = 0; j < nl2; j++) {
            char ke[64]; snprintf(ke, sizeof ke, "netgraph.links.%d.ev", j);
            if (g_store[ke] == "route2") r2++;
        }
        ok(r2 == 0, "a destination hash in `via` is not read as an identity");
        ok(storageGetInt("netgraph.nodes.slots", 0) == 2,
           "and no circle is invented for the node it does not name");

        /* The via that IS an identity, on the same shape, does place. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("ble/bb", 3);
        addIface("ble/zz", 3);
        addPath(idX, dX, nullptr, "ble/bb", 1);
        addPath(idT, dT, idX, "ble/zz", 2);
        ngResolve();
        int placed = 0, viaX = ngVertexOfIdentity(&s_res, idX);
        nl2 = storageGetInt("netgraph.links.count", 0);
        for (int j = 0; j < nl2; j++) {
            char ke[64], ka[64];
            snprintf(ke, sizeof ke, "netgraph.links.%d.ev", j);
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            if (g_store[ke] == "route2" && atoi(g_store[ka].c_str()) == viaX) placed++;
        }
        ok(placed == 1, "and an identity in `via` hangs the route off that node");
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
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.label", i);
            if (g_store[k].rfind("AA:BB:", 0) == 0) macs++;
        }
        ok(macs == 0, "no MAC beside the node it is");
        if (nv3 != 2 || macs) {
            printf("      verts=%d macs=%d\n", nv3, macs);
            for (int i = 0; i < nv3; i++) {
                char k[64], k2[64];
                snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
                snprintf(k2, sizeof k2, "netgraph.nodes.%d.label", i);
                printf("        node %d id=%-8.8s label=%s\n", i,
                       g_store[k].c_str(), g_store[k2].c_str());
            }
        }
    }

    /* ── 12b. heard_h removes a line; it never dims one ──
     *
     * There is no aged style anywhere in the drawing. Evidence expires and the
     * edge LEAVES, which is why the browser can treat everything it is handed as
     * current without asking how old it is. */
    {
        reset();
        g_ticks = 1000;
        uint32_t tz = (uint32_t)time(nullptr);
        g_store["s.netgraph.heard_h"] = "3";
        addDest(0xa1);
        addIface("lora/0", 3);
        addPeer("lora/0", -1, 0x51, tz - 60);            /* a minute ago */
        addPeer("lora/0", -1, 0x52, tz - 2 * 3600);      /* two hours ago */
        addPeer("lora/0", -1, 0x53, tz - 5 * 3600);      /* five — past the horizon */
        ngResolve();
        ok(storageGetInt("netgraph.links.count", 0) == 2,
           "a peer unheard past heard_h is not drawn at all");

        /* Widen the horizon and it comes back — nothing was destroyed, the
         * question was simply asked differently. */
        g_store["s.netgraph.heard_h"] = "6";
        ngResolve();
        ok(storageGetInt("netgraph.links.count", 0) == 3,
           "and returns when the horizon widens");
        g_store.erase("s.netgraph.heard_h");
    }

    /* ── 13. the sync beat adapts to what it learns ──
     *
     * Calling the real ngBeatFrom, not a copy of its arithmetic: the previous
     * form of this test reimplemented the rule inline and went on passing after
     * the rule moved, which is the one thing a test must not do. */
    {
        reset();
        g_store["s.netgraph.sync_min"] = "30";      /* ceiling: 1800 s */
        uint32_t ceiling = 30u * 60000u;

        /* Nothing learned: back off, doubling, and stop at the ceiling. */
        s_syncBackoff = NG_SYNC_FAST_MS;
        for (int i = 0; i < 12; i++) {
            uint32_t before = s_syncBackoff;
            ngBeatFrom(0);
            ok(s_syncBackoff >= before, "a fruitless exchange never speeds up");
        }
        ok(s_syncBackoff == ceiling, "and settles exactly at sync_min");

        /* Something learned HALVES the wait rather than resetting it: one record
         * arriving says the community moved a little, not that this node knows
         * nothing, and a reset put a settled mesh back at the bottom of the ramp
         * for every single update anywhere in it. */
        ngBeatFrom(1);
        ok(s_syncBackoff == ceiling / 2, "learning something halves the wait");
        for (int i = 0; i < 12; i++) ngBeatFrom(1);
        ok(s_syncBackoff == NG_SYNC_FAST_MS, "and it floors at the fast rate, never below");
        g_store.erase("s.netgraph.sync_min");
    }

    /* ── 14. what the crawl brings back ──
     *
     * A path-table row from another node is a third party's report about
     * itself: it anchors at that node, carries `src` so it can be told from our
     * own table, and expires on heard_h like every other class. */
    {
        reset();
        g_ticks = 1000;
        uint32_t tc = (uint32_t)time(nullptr);
        uint8_t idMe[16], idX[16], idFar[16];
        memset(idMe, 0xAA, 16); memset(idX, 0xBB, 16); memset(idFar, 0xEE, 16);
        uint8_t dX[16], dFar[16];
        memset(dX, 0, 16);   dX[0] = 0xb1;
        memset(dFar, 0, 16); dFar[0] = 0xe1;

        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        addPath(idX, dX, nullptr, "lora/0", 1);        /* xiao, one hop from us */

        /* We visited xiao; it reported one adjacency of its own, to a node we
         * hold an announce for but have no route to. */
        addPath(idFar, dFar, nullptr, "", 0);          /* known address, no route */
        ngCrawlNote(idX, dFar, "lora/1");
        ngVisitNote(idX, /*member=*/true);
        ngResolve();

        int nv = storageGetInt("netgraph.nodes.slots", 0);
        int nl = storageGetInt("netgraph.links.count", 0);
        ok(nv == 3, "us, xiao, and the node xiao named");
        ok(nl == 2, "our route to xiao, and xiao's own report");

        /* The crawled row anchors at XIAO and says so. */
        int crawled = 0, anchoredAtX = 0;
        int xv = ngVertexOfIdentity(&s_res, idX);
        for (int j = 0; j < nl; j++) {
            char ks[64], ka[64];
            snprintf(ks, sizeof ks, "netgraph.links.%d.src", j);
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            if (g_store[ks].empty()) continue;
            crawled++;
            if (atoi(g_store[ka].c_str()) == xv) anchoredAtX++;
            ok(g_store[ks].rfind("bbbb", 0) == 0, "and names who answered");
        }
        ok(crawled == 1, "exactly one row came from a crawl");
        ok(anchoredAtX == 1, "and it hangs off the node that reported it");

        /* Our own route to xiao carries no src — it is ours, not a report. */
        int ours = 0;
        for (int j = 0; j < nl; j++) {
            char ks[64]; snprintf(ks, sizeof ks, "netgraph.links.%d.src", j);
            if (g_store[ks].empty()) ours++;
        }
        ok(ours == 1, "our own evidence carries no src");

        /* And the visit is on the node. */
        int visited = 0, members = 0;
        for (int i = 0; i < nv; i++) {
            char kv[64], km[64];
            snprintf(kv, sizeof kv, "netgraph.nodes.%d.visited", i);
            snprintf(km, sizeof km, "netgraph.nodes.%d.member", i);
            if (storageGetInt(kv, 0)) visited++;
            if (storageGetInt(km, 0)) members++;
        }
        ok(visited == 1, "the visited node says when");
        ok(members == 1, "and that its announce proved membership");

        /* Past heard_h it goes, like everything else — there is no aged style
         * to fall back on. */
        s_crawl[0].at = tc - 10 * 3600;
        g_store["s.netgraph.heard_h"] = "3";
        ngResolve();
        int after = storageGetInt("netgraph.links.count", 0);
        ok(after == 1, "a stale crawl result leaves the graph, it does not dim");
        g_store.erase("s.netgraph.heard_h");
        for (auto& c : s_crawl)   c.used = false;
        for (auto& v : s_visited) v.used = false;
    }

    /* ── 14b. the crawl may not re-admit what the aspect rule keeps out ──
     *
     * A /path answer is destination hashes with no aspect, so a crawled row
     * means only what OUR directory can say about the address. The first cut of
     * this resolved every row by identity, which let a neighbour's report of
     * its own LXMF peers put those addresses back on the graph as nodes — the
     * same three-devices-nine-circles fault, through a different door. */
    {
        reset();
        g_ticks = 1000;
        uint8_t idMe[16], idX[16], idNode[16], idApp[16];
        memset(idMe, 0xAA, 16); memset(idX, 0xBB, 16);
        memset(idNode, 0xB1, 16); memset(idApp, 0xC1, 16);
        uint8_t dX[16], dNode[16], dApp[16], dUnknown[16];
        memset(dX, 0, 16);       dX[0] = 0xb1;
        memset(dNode, 0, 16);    dNode[0] = 0x10;
        memset(dApp, 0, 16);     dApp[0] = 0x20;
        memset(dUnknown, 0, 16); dUnknown[0] = 0x30;

        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        addPath(idX, dX, nullptr, "lora/0", 1, "rnstransport.remote.management");
        /* Two addresses we hold announces for — one a device, one a person —
         * and one we have never heard at all. */
        addPath(idNode, dNode, nullptr, "", 0, "rnstransport.probe");
        addPath(idApp,  dApp,  nullptr, "", 0, "lxmf.delivery");

        /* xiao reports all three as its own one-hop neighbours. */
        ngCrawlNote(idX, dNode,    "auto");
        ngCrawlNote(idX, dApp,     "auto");
        ngCrawlNote(idX, dUnknown, "auto");
        ngVisitNote(idX, true);
        ngResolve();

        ok(storageGetInt("netgraph.nodes.slots", 0) == 3,
           "us, xiao, and the one device xiao named");
        ok(storageGetInt("netgraph.links.count", 0) == 2,
           "our route to xiao, and xiao's route to that device");

        int stubs = 0;
        int nl = storageGetInt("netgraph.links.count", 0);
        for (int j = 0; j < nl; j++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.%d.b", j);
            if (atoi(g_store[k].c_str()) < 0) stubs++;
        }
        ok(stubs == 0, "an address we cannot place is counted, not drawn as a stub");
        if (stubs || storageGetInt("netgraph.nodes.slots", 0) != 3) {
            int nv = storageGetInt("netgraph.nodes.slots", 0);
            for (int i = 0; i < nv; i++) {
                char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
                printf("        node %d id=%-8.8s\n", i, g_store[k].c_str());
            }
        }
        for (auto& c : s_crawl)   c.used = false;
        for (auto& v : s_visited) v.used = false;
    }

    /* ── 14c. a crawled node's route back to US closes the line ──
     *
     * Our own addresses appear in no directory — a node does not ingest its own
     * announces — so a neighbour's report of the route it has to us resolved to
     * nothing and was discarded as unplaceable. That row is the reciprocal half
     * of every edge we have, and without it every line on the drawing stays
     * open at the far end forever. */
    {
        reset();
        g_ticks = 1000;
        uint8_t idMe[16], idX[16];
        memset(idMe, 0xAA, 16); memset(idX, 0xBB, 16);
        uint8_t dX[16];
        memset(dX, 0, 16); dX[0] = 0xb1;

        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addIface("lora/0", 3);
        addPath(idX, dX, nullptr, "lora/0", 1, "rnstransport.remote.management");
        /* One of ours, node-level — the address a neighbour would route to. */
        addDest(0xa1);
        g_dests.back().dest[0] = 0xa1;
        safeStrncpy(g_dests.back().aspect, "rnstransport.remote.management",
                    sizeof g_dests.back().aspect);

        uint8_t dMe[16];
        memset(dMe, 0, 16);
        memcpy(dMe, g_dests.back().dest, 16);

        ngCrawlNote(idX, dMe, "lora/0");     /* xiao says it routes to us */
        ngVisitNote(idX, true);
        ngResolve();

        ok(storageGetInt("netgraph.nodes.slots", 0) == 2, "still just us and xiao");
        ok(storageGetInt("netgraph.links.count", 0) == 2,
           "our route out, and xiao's route back");

        int back = 0;
        int nl = storageGetInt("netgraph.links.count", 0);
        for (int j = 0; j < nl; j++) {
            char ka[64], kb[64], ks[64];
            snprintf(ka, sizeof ka, "netgraph.links.%d.a", j);
            snprintf(kb, sizeof kb, "netgraph.links.%d.b", j);
            snprintf(ks, sizeof ks, "netgraph.links.%d.src", j);
            if (atoi(g_store[ka].c_str()) == 1 && atoi(g_store[kb].c_str()) == 0 &&
                !g_store[ks].empty()) back++;
        }
        ok(back == 1, "the return row points at us, not at a discarded stub");
        for (auto& c : s_crawl)   c.used = false;
        for (auto& v : s_visited) v.used = false;
    }

    /* ── 15. the allow list validates, and only here ──
     *
     * The settings pane writes a sentinel and never the array, so this is the
     * only writer. A hash that is not a hash must be refused with a sentence
     * the form can show, not stored and puzzled over later. */
    {
        reset();
        const char* good = "00112233445566778899aabbccddeeff";

        ngAllowAdd(good);
        ok(ngAllowCount() == 1, "a well-formed identity hash is accepted");
        ok(g_store["s.netgraph.allow.0.hash"] == good, "and stored verbatim");
        ok(g_store["netgraph.allow.error"].empty(), "with no complaint");

        ngAllowAdd(good);
        ok(ngAllowCount() == 1, "the same hash twice is still one entry");
        ok(!g_store["netgraph.allow.error"].empty(), "and says why");

        ngAllowAdd("not a hash");
        ok(ngAllowCount() == 1, "a malformed hash never reaches the list");
        ngAllowAdd("00112233445566778899aabbccddee");        /* two chars short */
        ok(ngAllowCount() == 1, "and neither does a short one");

        /* Case and surrounding whitespace are an operator pasting, not an
         * error — normalized rather than refused. */
        ngAllowAdd("  AABBCCDDEEFF00112233445566778899  ");
        ok(ngAllowCount() == 2, "a pasted upper-case hash is accepted");
        ok(g_store["s.netgraph.allow.1.hash"] == "aabbccddeeff00112233445566778899",
           "and normalized to lower case, trimmed");

        /* Removal compacts, so the array a collection walks stays contiguous. */
        std::string id0 = g_store["s.netgraph.allow.0.id"];
        ngAllowRemove(id0);
        ok(ngAllowCount() == 1, "removing an entry leaves one");
        ok(g_store["s.netgraph.allow.0.hash"] == "aabbccddeeff00112233445566778899",
           "and compacts the survivor down to index 0");

        ngAllowRemove("nosuch");
        ok(!g_store["netgraph.allow.error"].empty(), "removing nothing says so");

        /* And the sentinel path itself: the form submits JSON. */
        g_store["netgraph.allow.error"] = "";
        ngAllowSentinel("netgraph.allow.add", "{\"hash\":\"ffeeddccbbaa99887766554433221100\"}");
        ok(ngAllowCount() == 2, "the add form's JSON reaches the list");
        ok(g_store["netgraph.allow.add"].empty(), "and the sentinel is cleared");
    }

    /* ── 16. a device is not its identities ──
     *
     * THE REGRESSION THIS EXISTS FOR: a three-node bench drew nine circles.
     * A device hosts several identities — its transport one, LXMF's, one per
     * application — and the directory's "identity behind a destination" is the
     * owner of an ADDRESS, not the device. Keying vertices on it draws each of
     * a device's identities as a separate node, wearing whatever display name
     * its user chose, and the crawl then spends a full timeout on each one
     * discovering that an LXMF address has no management destination.
     *
     * Only a node-level aspect makes a vertex. */
    {
        reset();
        g_ticks = 1000;
        uint8_t idMe[16], idNode[16], idApp1[16], idApp2[16];
        memset(idMe, 0xAA, 16); memset(idNode, 0xB1, 16);
        memset(idApp1, 0xC1, 16); memset(idApp2, 0xC2, 16);
        uint8_t dNode[16], dApp1[16], dApp2[16];
        memset(dNode, 0, 16); dNode[0] = 0x10;
        memset(dApp1, 0, 16); dApp1[0] = 0x20;
        memset(dApp2, 0, 16); dApp2[0] = 0x30;

        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);

        /* ONE device, one hop away, announcing three destinations: its
         * transport identity and two applications, each on an identity of its
         * own — which is what a real device looks like. */
        addPath(idNode, dNode, nullptr, "lora/0", 1, "rnstransport.remote.management");
        addPath(idApp1, dApp1, nullptr, "lora/0", 1, "lxmf.delivery");
        addPath(idApp2, dApp2, nullptr, "lora/0", 1, "nomadnetwork.node");
        ngResolve();

        ok(storageGetInt("netgraph.nodes.slots", 0) == 2,
           "us and one device — not one circle per identity");
        ok(storageGetInt("netgraph.links.count", 0) == 1,
           "and one line to it, not three");
        ok(g_store["netgraph.nodes.1.id"].rfind("b1b1", 0) == 0,
           "the circle is the transport identity, the one we can address");

        /* A peer HEARD on an application aspect is the same mistake in the
         * other pass. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        uint32_t tn = (uint32_t)time(nullptr);
        addPeer("lora/0", -1, 0x41, tn, "lxmf.delivery");
        ngResolve();
        ok(storageGetInt("netgraph.nodes.slots", 0) == 1,
           "an lxmf address heard on the radio is a person, not a device");
        ok(storageGetInt("netgraph.links.count", 0) == 0, "and gets no line");

        /* An unknown aspect is not evidence of a node either — a name hash we
         * cannot resolve says nothing about what is behind it. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        addPeer("lora/0", -1, 0x42, tn, "");
        ngResolve();
        ok(storageGetInt("netgraph.nodes.slots", 0) == 1,
           "and neither is an aspect we cannot name");

        /* ── the same device routed AND heard is one circle ──
         *
         * The regression: the aspect rule guarded only the shared-medium
         * branch. An interface with a declared node took its vertex from
         * whichever peer row came first, so where that was an application
         * address the device arrived twice — once as the transport identity we
         * route to, solid, and once beside it under its user's display name,
         * dashed. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("auto/0", 3);
        addNode("auto/0", "peer-addr", true, tn, 2);   /* a DECLARED node */

        uint8_t dT[16], dL[16];
        memset(dT, 0, 16); dT[0] = 0x51;
        memset(dL, 0, 16); dL[0] = 0x52;
        /* One device, routed on its transport address; its LXMF address is
         * heard on the same interface and listed FIRST, which is what used to
         * decide the interface's vertex. */
        addPeer("auto/0", 0, 0x52, tn, "lxmf.delivery");
        addPeer("auto/0", 0, 0x51, tn, "rnstransport.remote.management");
        addPath(idNode, dT, nullptr, "auto/0", 1, "rnstransport.remote.management");
        addPath(idApp1, dL, nullptr, "auto/0", 1, "lxmf.delivery");
        ngResolve();

        ok(storageGetInt("netgraph.nodes.slots", 0) == 2,
           "a device routed and heard at once is still one circle");
        ok(storageGetInt("netgraph.links.count", 0) == 1,
           "with one line, not a solid and a dashed one beside it");
        {
            char k[64]; snprintf(k, sizeof k, "netgraph.links.0.ev");
            ok(g_store[k] == "route1", "and routing wins the fold, not hearing");
            snprintf(k, sizeof k, "netgraph.nodes.1.id");
            ok(g_store[k].rfind("b1b1", 0) == 0,
               "the circle is the transport identity, not the application one");
        }

        /* ── two nodes on one radio must not conjure a third ──
         *
         * ngIdOnIface answers "nobody" when several nodes reply on one
         * interface, because then the interface does not name a single node.
         * That is the right answer to that question and the wrong reason to
         * invent a vertex: several answering means several are already drawn.
         * hcNode took the "nobody" and fell through to rnsd's node label,
         * putting a nameless circle beside the ones it duplicated — which on
         * the bench appeared as a second "tbeam" with an empty id. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        addNode("lora/0", "tbeam", false, tn, 2);   /* rnsd's label for the radio */

        uint8_t idA[16], idB[16], dA[16], dB[16];
        memset(idA, 0xD1, 16); memset(idB, 0xD2, 16);
        memset(dA, 0, 16); dA[0] = 0x61;
        memset(dB, 0, 16); dB[0] = 0x62;
        addPath(idA, dA, nullptr, "lora/0", 1, "rnstransport.remote.management");
        addPath(idB, dB, nullptr, "lora/0", 1, "rnstransport.remote.management");
        ngResolve();

        ok(storageGetInt("netgraph.nodes.slots", 0) == 3,
           "two nodes on one radio are two circles, not three");
        int nameless = 0;
        int nv2 = storageGetInt("netgraph.nodes.slots", 0);
        for (int i = 0; i < nv2; i++) {
            char k[64]; snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
            if (g_store[k].empty()) nameless++;
        }
        ok(nameless == 0, "and none of them is a bare transport label");

        /* ── a node that has announced ANYTHING is not a silent attachment ──
         *
         * On a radio, iface-lora declares a node and labels it with the display
         * names its destinations announced — so a device whose application
         * announce we heard, but whose management announce we have not, arrived
         * as a circle wearing a person's name, with no identity, drawn `heard`.
         * It reads as a real node and is a duplicate waiting for the
         * node-level announce to land. hcNode is for the silent case only. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("lora/0", 3);
        addNode("lora/0", "tdeck", false, tn, 1);       /* labelled with a NAME */
        addPeer("lora/0", -1, 0x71, tn, APP_ASPECT);    /* its lxmf announce */
        ngResolve();
        ok(storageGetInt("netgraph.nodes.slots", 0) == 1,
           "a device we have only heard announce an application is not a node yet");
        ok(storageGetInt("netgraph.links.count", 0) == 0, "and gets no line");

        /* Genuinely silent — attached, nothing announced — still draws, which
         * is the case hcNode is for. */
        reset();
        g_ticks = 1000;
        memcpy(s_self, idMe, 16); s_haveSelf = true;
        addDest(0xa1);
        addIface("ble/aa", 3);
        addNode("ble/aa", "AA:BB:CC:DD:EE:0F", false, 0, 0);
        ngResolve();
        ok(storageGetInt("netgraph.nodes.slots", 0) == 2,
           "something attached that has never announced is still drawn");
        ok(storageGetInt("netgraph.links.count", 0) == 1, "with a line to it");
        if (nameless) for (int i = 0; i < nv2; i++) {
            char k[64], kl[64];
            snprintf(k, sizeof k, "netgraph.nodes.%d.id", i);
            snprintf(kl, sizeof kl, "netgraph.nodes.%d.label", i);
            printf("        node %d id=%-8.8s label=%s\n", i,
                   g_store[k].c_str(), g_store[kl].c_str());
        }
    }

    printf("%s  %d/%d checks passed\n", g_fail ? "FAILED" : "ok", g_run - g_fail, g_run);
    return g_fail ? 1 : 0;
}
