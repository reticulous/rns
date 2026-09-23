/**
 * rnsd_gateway — how far this node is from a way out of its community.
 *
 *   gateway G  → air   ANNOUNCE rnstransport.remote.management  (distance 0)
 *   node    B  → air   ANNOUNCE rnstransport.remote.management  (distance 1)
 *   node    A          hears B at hops 1 → A's distance is 2
 *
 * A node's distance is 0 when it has an uplink (a radius-0 point-to-point
 * interface whose far end rnsd has named) or when `s.rnsd.gateway.self` says
 * so; otherwise it is one more than the smallest distance a direct neighbour
 * declared in a management announce still inside the horizon, capped at
 * RNSD_GW_NONE, which means "no gateway reachable". The number rides inside the
 * community-encrypted management announce (netgraph composes it), so only
 * members read it and only a member's declaration is ever noted here.
 *
 * What the number is for: a relay repeats a path request back onto the radio
 * it heard it on only when it is closer to a gateway than the node that asked
 * (Transport::path_request). That is what lets a question from deep inside a
 * radio-only area walk downhill to the nearest gateway without flooding.
 *
 * Two things besides declarations make a neighbour a gateway: an operator
 * saying so (`s.rnsd.gateway.peer.<identity hex>` = 1, or 0 to refuse its
 * declarations), and a stock Reticulum interface-discovery announce for a wired
 * interface type heard directly from it. Neither needs the neighbour to run
 * this firmware.
 *
 * No µR types: byte arrays in, byte arrays out. The table is written from the
 * netgraph task (declarations) and the rnsd task (everything else) and read by
 * Transport on the rnsd task, so one mutex covers it.
 */
#include "rnsd_peers.h"

#include "spangap.h"
#include "compat.h"

#include <cstdio>
#include <cstring>
#include <mutex>

/* A LoRa neighbourhood is at most a few dozen stations, and only community
 * members' management announces and wired-interface discovery announces land
 * here — not every destination a neighbour hosts. */
#define RNSD_GW_NBRS_MAX 48

/* A declaration is kept for three of LoRa's default half-hour announce beats,
 * so two lost announces in a row do not make a gateway disappear. */
#define RNSD_GW_HORIZON_DEFAULT_S 5400

/* The shortest gap between two management announces re-aired because a
 * neighbour has evidently not heard ours. */
#define RNSD_GW_REAIR_MIN_S 60

namespace {

struct Nbr {
    bool     used;
    uint8_t  id[RNSD_IDENT_HASH_LEN];
    uint8_t  declared;       /* 0..RNSD_GW_NONE from a management announce, or
                              * RNSD_GW_UNKNOWN when only discovery or a direct
                              * announce put the row here */
    bool     discovery_gw;   /* a stock discovery announce for a wired interface */
    uint32_t heard_s;        /* uptime seconds of the last direct evidence */
};

Nbr        s_nbrs[RNSD_GW_NBRS_MAX];
std::mutex s_lock;
bool       s_uplink   = false;
uint8_t    s_own      = RNSD_GW_NONE;
bool       s_announce_owed = false;   /* the distance moved since it was last aired */
uint32_t   s_last_reair_s  = 0;       /* uptime of the last re-air for a neighbour */
bool       s_published = false;

uint32_t uptimeS() { return (uint32_t)(millis() / 1000u); }

uint32_t horizonS() {
    int v = storageGetInt("s.rnsd.gateway.horizon_s", RNSD_GW_HORIZON_DEFAULT_S);
    return v > 0 ? (uint32_t)v : RNSD_GW_HORIZON_DEFAULT_S;
}

void hexId(char out[2 * RNSD_IDENT_HASH_LEN + 1], const uint8_t* id) {
    for (int i = 0; i < RNSD_IDENT_HASH_LEN; i++) std::sprintf(out + 2 * i, "%02x", id[i]);
    out[2 * RNSD_IDENT_HASH_LEN] = '\0';
}

/* The operator's word on one neighbour: 1 = a gateway, 0 = never count it,
 * -1 = no override. */
int overrideOf(const uint8_t* id) {
    char h[2 * RNSD_IDENT_HASH_LEN + 1];
    hexId(h, id);
    char key[64];
    std::snprintf(key, sizeof key, "s.rnsd.gateway.peer.%s", h);
    return storageGetInt(key, -1);
}

/* What one neighbour counts as, after the operator's word. RNSD_GW_UNKNOWN
 * means it contributes nothing. Caller holds the lock. */
uint8_t effectiveOf(const Nbr& n) {
    int ov = overrideOf(n.id);
    if (ov == 1) return 0;
    if (ov == 0) return RNSD_GW_UNKNOWN;
    if (n.discovery_gw) return 0;
    return n.declared;
}

Nbr* findOrAlloc(const uint8_t* id) {
    Nbr* free_slot = nullptr;
    Nbr* oldest = nullptr;
    for (auto& n : s_nbrs) {
        if (!n.used) { if (!free_slot) free_slot = &n; continue; }
        if (std::memcmp(n.id, id, RNSD_IDENT_HASH_LEN) == 0) return &n;
        if (!oldest || (int32_t)(n.heard_s - oldest->heard_s) < 0) oldest = &n;
    }
    Nbr* s = free_slot ? free_slot : oldest;
    if (!s) return nullptr;
    *s = Nbr{};
    s->used = true;
    std::memcpy(s->id, id, RNSD_IDENT_HASH_LEN);
    s->declared = RNSD_GW_UNKNOWN;
    return s;
}

/* Recompute the own distance and publish it when it moved. */
void recompute(const char* why) {
    uint8_t own;
    uint8_t via_id[RNSD_IDENT_HASH_LEN] = {};
    bool    have_via = false;
    {
        std::lock_guard<std::mutex> g(s_lock);
        uint32_t now = uptimeS(), hz = horizonS();
        bool self = storageGetInt("s.rnsd.gateway.self", 0) != 0;
        uint8_t best = RNSD_GW_NONE;
        for (auto& n : s_nbrs) {
            if (!n.used) continue;
            if ((uint32_t)(now - n.heard_s) > hz) { n.used = false; continue; }
            uint8_t e = effectiveOf(n);
            if (e >= RNSD_GW_NONE) continue;
            if ((uint8_t)(e + 1) < best) {
                best = (uint8_t)(e + 1);
                std::memcpy(via_id, n.id, RNSD_IDENT_HASH_LEN);
                have_via = true;
            }
        }
        own = (s_uplink || self) ? 0 : best;
        if (own == 0) have_via = false;
        if (own == s_own && s_published) return;
        if (s_published) s_announce_owed = true;
        s_own = own;
        s_published = true;
        char via[2 * RNSD_IDENT_HASH_LEN + 1] = "-";
        if (have_via) hexId(via, via_id);
        if (own == RNSD_GW_NONE)
            info("gateway distance: none (%s)", why);
        else if (own == 0)
            info("gateway distance: 0, this node is a gateway (%s)", why);
        else
            info("gateway distance: %u via %s (%s)", (unsigned)own, via, why);
    }
    char v[8];
    if (own >= RNSD_GW_NONE) std::snprintf(v, sizeof v, "none");
    else                     std::snprintf(v, sizeof v, "%u", (unsigned)own);
    storageBegin();
    storageSet("rnsd.gateway.distance", v);
    storageSet("rnsd.gateway.uplink", s_uplink ? 1 : 0);
    storageEnd();
}

}  // namespace

uint8_t rnsdGatewayDistance(void)
{
    std::lock_guard<std::mutex> g(s_lock);
    return s_own;
}

uint8_t rnsdGatewayDistanceOf(const uint8_t ident[RNSD_IDENT_HASH_LEN])
{
    if (!ident) return RNSD_GW_UNKNOWN;
    std::lock_guard<std::mutex> g(s_lock);
    uint32_t now = uptimeS(), hz = horizonS();
    for (auto& n : s_nbrs) {
        if (!n.used || std::memcmp(n.id, ident, RNSD_IDENT_HASH_LEN) != 0) continue;
        if ((uint32_t)(now - n.heard_s) > hz) return RNSD_GW_UNKNOWN;
        return effectiveOf(n);
    }
    /* Not a neighbour we have heard, but the operator may still have named it. */
    return overrideOf(ident) == 1 ? 0 : RNSD_GW_UNKNOWN;
}

void rnsdGatewayNote(const uint8_t ident[RNSD_IDENT_HASH_LEN], uint8_t distance)
{
    if (!ident) return;
    if (distance > RNSD_GW_NONE) distance = RNSD_GW_NONE;
    bool changed = false, reair = false;
    {
        std::lock_guard<std::mutex> g(s_lock);
        Nbr* n = findOrAlloc(ident);
        if (!n) return;
        changed = n->declared != distance;
        n->declared = distance;
        n->heard_s  = uptimeS();
        /* A neighbour further out than one hop past us has not heard what we
         * declared — its distance would follow from ours if it had. Say it
         * again, once a minute at most: on a shared radio an announce is lost
         * to a node we cannot hear transmitting, and the next beat is half an
         * hour away. */
        uint32_t now = uptimeS();
        if (s_own < RNSD_GW_NONE && distance > s_own + 1 &&
            (s_last_reair_s == 0 || now - s_last_reair_s >= RNSD_GW_REAIR_MIN_S)) {
            s_last_reair_s = now ? now : 1;
            reair = true;
        }
    }
    if (changed) recompute("a neighbour declared a new distance");
    if (reair) rnsdManagementReair();
}

void rnsdGatewayDiscoveryNote(const uint8_t transport_id[RNSD_IDENT_HASH_LEN])
{
    if (!transport_id) return;
    bool changed = false;
    {
        std::lock_guard<std::mutex> g(s_lock);
        Nbr* n = findOrAlloc(transport_id);
        if (!n) return;
        changed = !n->discovery_gw;
        n->discovery_gw = true;
        n->heard_s = uptimeS();
    }
    if (changed) recompute("a neighbour announced a wired interface");
}

void rnsdGatewayHeard(const uint8_t ident[RNSD_IDENT_HASH_LEN])
{
    if (!ident) return;
    int ov = overrideOf(ident);
    bool changed = false;
    {
        std::lock_guard<std::mutex> g(s_lock);
        for (auto& n : s_nbrs) {
            if (n.used && std::memcmp(n.id, ident, RNSD_IDENT_HASH_LEN) == 0) {
                /* A declaration lives exactly as long as the announce that
                 * carried it; only a row the operator's word keeps is
                 * refreshed by any announce at all. */
                if (n.declared == RNSD_GW_UNKNOWN && !n.discovery_gw) n.heard_s = uptimeS();
                return;
            }
        }
        /* A neighbour with nothing to declare is only worth a row when the
         * operator has named it one way or the other. */
        if (ov < 0) return;
        Nbr* n = findOrAlloc(ident);
        if (!n) return;
        n->heard_s = uptimeS();
        changed = true;
    }
    if (changed) recompute("an operator-named neighbour was heard");
}

void rnsdGatewaySetUplink(bool up)
{
    {
        std::lock_guard<std::mutex> g(s_lock);
        if (up == s_uplink && s_published) return;
        s_uplink = up;
    }
    recompute(up ? "an uplink came up" : "no uplink");
}

void rnsdGatewayTick(void)
{
    recompute("expiry sweep");
}

bool rnsdGatewayAnnounceOwed(void)
{
    std::lock_guard<std::mutex> g(s_lock);
    bool owed = s_announce_owed;
    s_announce_owed = false;
    return owed;
}

void rnsdGatewayPrint(void)
{
    struct Row { uint8_t id[RNSD_IDENT_HASH_LEN]; uint8_t eff; uint8_t declared;
                 bool disc; int ov; uint32_t age; };
    Row rows[RNSD_GW_NBRS_MAX];
    int n = 0;
    uint8_t own;
    bool uplink;
    {
        std::lock_guard<std::mutex> g(s_lock);
        own = s_own;
        uplink = s_uplink;
        uint32_t now = uptimeS();
        for (auto& e : s_nbrs) {
            if (!e.used) continue;
            Row& r = rows[n++];
            std::memcpy(r.id, e.id, RNSD_IDENT_HASH_LEN);
            r.eff = effectiveOf(e);
            r.declared = e.declared;
            r.disc = e.discovery_gw;
            r.ov = overrideOf(e.id);
            r.age = now - e.heard_s;
        }
    }
    if (own >= RNSD_GW_NONE) cliPrintf("Gateway distance: none\n");
    else if (own == 0)      cliPrintf("Gateway distance: 0 (%s)\n",
                                       uplink ? "this node has an uplink" : "s.rnsd.gateway.self");
    else                     cliPrintf("Gateway distance: %u\n", (unsigned)own);
    if (!n) { cliPrintf("(no neighbour has declared a distance)\n"); return; }
    cliPrintf("%-32s %-8s %-8s %s\n", "neighbour identity", "declared", "counts", "heard");
    for (int i = 0; i < n; i++) {
        char h[2 * RNSD_IDENT_HASH_LEN + 1];
        hexId(h, rows[i].id);
        char d[12], c[16];
        if (rows[i].declared == RNSD_GW_UNKNOWN) std::snprintf(d, sizeof d, "-");
        else if (rows[i].declared >= RNSD_GW_NONE) std::snprintf(d, sizeof d, "none");
        else std::snprintf(d, sizeof d, "%u", (unsigned)rows[i].declared);
        if (rows[i].eff == RNSD_GW_UNKNOWN || rows[i].eff >= RNSD_GW_NONE) std::snprintf(c, sizeof c, "-");
        else std::snprintf(c, sizeof c, "%u%s", (unsigned)rows[i].eff,
                           rows[i].ov == 1 ? " (set)" : rows[i].disc ? " (disc)" : "");
        if (rows[i].ov == 0) std::snprintf(c, sizeof c, "refused");
        cliPrintf("%-32s %-8s %-8s %us ago\n", h, d, c, (unsigned)rows[i].age);
    }
}
