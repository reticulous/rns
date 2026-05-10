/**
 * rnsd — RNS protocol task.
 *
 * Phase 1 scope: identity load/generate, RNSD_PORT_REGISTER server, an
 * iface table, basic stats, CLI. Path table integration with mR's
 * Transport machinery comes when transports start delivering real
 * packets (full Phase 1 milestone).
 *
 * See docs/component-plan.md §11.
 */
#include "rnsd.h"
#include "diptych.h"
#include "ports.h"

/* mR's Log.h declares free functions `info`, `warn`, `error`, `debug`, ...
 * inside namespace RNS. diptych's log.h defines `info`/`warn`/`err`/etc. as
 * preprocessor macros (ESP_LOGI shims). The macros corrupt the function
 * declarations on parse. Save + suppress around the mR include, then
 * restore.
 *
 * Also: mR's Log.h does `#define msg (msg)` (a wart from its Arduino-side
 * format-string mangling). Undefine after include so it doesn't poison
 * later parameter names. */
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

#include "Identity.h"
#include "Bytes.h"
#include "Interface.h"
#include "Transport.h"
#include "Reticulum.h"
#include "Persistence/DestinationEntry.h"
#include "Utilities/OS.h"

#undef msg
#pragma pop_macro("info")
#pragma pop_macro("warn")
#pragma pop_macro("err")
#pragma pop_macro("dbg")
#pragma pop_macro("verb")

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstring>
#include <string>
#include <set>
#include <memory>
#include <vector>
#include <unordered_map>

#include "cJSON.h"

static const char* TAG = "rnsd";

#define RNSD_VERSION 1

/* Up to N concurrent registered transport ifaces. Each TCP peer is its
 * own iface, so this caps total transports (lora + udp + N tcp). */
#define RNSD_MAX_IFACES 16

/* mR Interface impl wrapping the ITS handle to a transport task. mR's
 * Transport calls `send_outgoing(Bytes)` when it wants to push a packet
 * out our way; we relay over the ITS handle. Inbound packets arrive via
 * the ITS server-port recv callback; we wrap the bytes into Interface
 * and call `iface.handle_incoming(...)`, which routes through
 * InterfaceImpl::handle_incoming → Transport::inbound. */
class TaskInterface : public RNS::InterfaceImpl {
public:
    TaskInterface(const rnsd_register_t& info, int handle) : _handle(handle) {
        _name = info.name;
        _online = true;
        _IN  = info.in  != 0;
        _OUT = info.out != 0;
        _FWD = info.fwd != 0;
        _RPT = info.rpt != 0;
        _HW_MTU = info.mtu;
        _FIXED_MTU = true;
        _AUTOCONFIGURE_MTU = false;
        _bitrate = info.bitrate;
        _mode = static_cast<RNS::Type::Interface::modes>(info.mode);
    }
protected:
    void send_outgoing(const RNS::Bytes& data) override {
        if (_handle < 0) return;
        size_t s = itsSend(_handle, data.data(), data.size(), pdMS_TO_TICKS(100));
        if (s == 0) warn("iface %s: ITS send dropped (%zu B)", _name.c_str(), data.size());
        _txb += data.size();
    }
private:
    int _handle;
};

struct iface_t {
    bool used;
    int  handle;            /* ITS server handle for this connection */
    rnsd_register_t info;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    /* mR Interface wrapper — holds shared_ptr<TaskInterface>. Empty
     * (Type::NONE) when slot is unused. */
    RNS::Interface mr_iface{RNS::Type::NONE};
};

static iface_t s_ifaces[RNSD_MAX_IFACES];

static TaskHandle_t s_task = nullptr;
static std::unique_ptr<RNS::Identity> s_identity;
static std::unique_ptr<RNS::Reticulum> s_reticulum;

/* Stats — diff-published to ephemeral storage at 1 Hz. */
static struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t announces_in;
    uint64_t announces_out;
} s_stats;

static TickType_t s_lastPublishTick = 0;

/* ─────────────── Identity ─────────────── */

static const char* mode_name(uint8_t mode)
{
    switch (mode) {
        case RNS_IFACE_MODE_FULL:         return "full";
        case RNS_IFACE_MODE_GATEWAY:      return "gateway";
        case RNS_IFACE_MODE_ACCESS_POINT: return "access_point";
        case RNS_IFACE_MODE_ROAMING:      return "roaming";
        case RNS_IFACE_MODE_BOUNDARY:     return "boundary";
    }
    return "?";
}

/** Load identity from secrets.rnsd.identity (128 hex chars). If absent or
 *  malformed, generate fresh keys and persist. */
static void loadOrCreateIdentity(void)
{
    char hex[160] = {};
    storageGetStr("secrets.rnsd.identity", hex, sizeof(hex), "");

    if (strlen(hex) == 128) {
        RNS::Bytes prv;
        prv.assignHex((const uint8_t*)hex, 128);
        if (prv.size() == 64) {
            auto id = std::make_unique<RNS::Identity>(false);
            if (id->load_private_key(prv)) {
                s_identity = std::move(id);
                info("loaded identity %s", s_identity->hexhash().c_str());
                return;
            }
        }
        warn("stored identity malformed — regenerating");
    }

    s_identity = std::make_unique<RNS::Identity>(true);
    info("generated identity %s", s_identity->hexhash().c_str());

    std::string hexPrv = s_identity->get_private_key().toHex();
    storageSet("secrets.rnsd.identity", hexPrv.c_str());
}

/* ─────────────── iface table ─────────────── */

static iface_t* ifaceFindByHandle(int handle)
{
    for (auto& i : s_ifaces) if (i.used && i.handle == handle) return &i;
    return nullptr;
}

static iface_t* ifaceAlloc(void)
{
    for (auto& i : s_ifaces) if (!i.used) return &i;
    return nullptr;
}

static void publishIfaceUp(const iface_t& i)
{
    char key[80];
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.up", i.info.name);          storageSet(key, 1);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.mtu", i.info.name);         storageSet(key, (int)i.info.mtu);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.bitrate", i.info.name);     storageSet(key, (int)i.info.bitrate);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.mode", i.info.name);        storageSet(key, mode_name(i.info.mode));
}

static void publishIfaceDown(const iface_t& i)
{
    char key[80];
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.up", i.info.name); storageSet(key, 0);
}

/* ─────────────── ITS callbacks ─────────────── */

static int onRegisterConnect(int handle, const void* data, size_t len)
{
    if (len < sizeof(rnsd_register_t)) {
        err("register: payload too small (%zu)", len);
        return -1;
    }
    iface_t* slot = ifaceAlloc();
    if (!slot) {
        err("register: iface table full (%d)", RNSD_MAX_IFACES);
        return -1;
    }
    slot->used = true;
    slot->handle = handle;
    memcpy(&slot->info, data, sizeof(rnsd_register_t));
    slot->info.name[sizeof(slot->info.name) - 1] = '\0';
    slot->rx_packets = slot->tx_packets = slot->rx_bytes = slot->tx_bytes = 0;
    info("register: iface=%s mtu=%u bitrate=%u mode=%s in=%u out=%u fwd=%u rpt=%u",
         slot->info.name, (unsigned)slot->info.mtu, (unsigned)slot->info.bitrate,
         mode_name(slot->info.mode), slot->info.in, slot->info.out, slot->info.fwd, slot->info.rpt);

    /* Wrap in mR Interface and register with Transport so announces /
     * paths route through us. Transport stores its own copy of Interface
     * (sharing the shared_ptr<TaskInterface>); we keep one too. */
    std::shared_ptr<RNS::InterfaceImpl> impl =
        std::make_shared<TaskInterface>(slot->info, handle);
    slot->mr_iface = RNS::Interface(impl);
    try {
        RNS::Transport::register_interface(slot->mr_iface);
    } catch (const std::exception& e) {
        err("Transport::register_interface threw: %s", e.what());
    }

    publishIfaceUp(*slot);
    return (int)(slot - s_ifaces);
}

static void onRegisterDisconnect(int ref)
{
    if (ref < 0 || ref >= RNSD_MAX_IFACES) return;
    iface_t& i = s_ifaces[ref];
    if (!i.used) return;
    info("deregister: iface=%s rx=%llu/%llu tx=%llu/%llu",
         i.info.name, (unsigned long long)i.rx_packets, (unsigned long long)i.rx_bytes,
         (unsigned long long)i.tx_packets, (unsigned long long)i.tx_bytes);
    if (i.mr_iface) {
        try { RNS::Transport::deregister_interface(i.mr_iface); }
        catch (const std::exception& e) { warn("deregister_interface threw: %s", e.what()); }
        i.mr_iface = RNS::Interface(RNS::Type::NONE);
    }
    publishIfaceDown(i);
    i.used = false;
    i.handle = -1;
}

static void onRegisterRecv(int handle, size_t /*bytesAvail*/)
{
    iface_t* i = ifaceFindByHandle(handle);
    if (!i) return;
    /* Drain one packet per dispatch; itsPoll re-dispatches on the next tick if more.
     * Plain static — only the rnsd task dispatches this callback, so no
     * concurrency. Avoid `thread_local` (lazy libgcc TLS init has been seen
     * to corrupt FreeRTOS scheduler state at boot). */
    static uint8_t pktbuf[600];   /* > RNS MTU 500 */
    size_t n = itsRecv(handle, pktbuf, sizeof(pktbuf), 0);
    if (n == 0) return;
    i->rx_packets++;
    i->rx_bytes += n;
    s_stats.packets_in++;
    s_stats.bytes_in += n;

    /* Hand to mR Transport via the Interface — InterfaceImpl::handle_incoming
     * routes through to Transport::inbound(data, iface), which decodes the
     * packet, updates the path table on announces, and forwards as needed. */
    if (i->mr_iface) {
        RNS::Bytes data(pktbuf, n);
        i->mr_iface.handle_incoming(data);
    }
}

/* ─────────────── announce tracker ─────────────── */

/* Every announce we hear — regardless of transport_enabled — is streamed
 * directly into `rnsd.nodes[idx].*` as it arrives. Storage's patch layer
 * coalesces unchanged fields, so subsequent announces from the same
 * destination only broadcast the fields that actually change.
 *
 * Storage holds the values, but a `dest_hex → idx` cache in RAM keeps the
 * announce hot path O(1) per existing destination — avoiding a linear
 * `storageGetStr` scan for every announce. The cache is rebuilt from
 * scratch on boot (storage for `rnsd.*` is ephemeral, so they start in
 * sync). LRU eviction still scans `last_seen` from storage, but that
 * only fires on capacity overflow. */

#define RNSD_MAX_NODES   64
#define RNSD_HOPS_UNKNOWN 128         /* matches µR PATHFINDER_M */

static int rnsdFindLruIdx(int count) {
    int oldest_i = 0;
    int oldest_t = INT32_MAX;
    for (int i = 0; i < count; i++) {
        char key[40];
        snprintf(key, sizeof(key), "rnsd.nodes.%d.last_seen", i);
        int t = storageGetInt(key, 0);
        if (t < oldest_t) { oldest_t = t; oldest_i = i; }
    }
    return oldest_i;
}

static std::string rnsdAppDataString(const RNS::Bytes& app_data) {
    std::string out;
    for (size_t i = 0; i < app_data.size(); i++) {
        uint8_t b = app_data.data()[i];
        if (b >= 0x20 && b < 0x7f) out.push_back((char)b);
        else if (b == 0) break;
        else return "";
    }
    return out;
}

class AnnounceTracker : public RNS::AnnounceHandler {
public:
    AnnounceTracker() : RNS::AnnounceHandler(nullptr) {}

    void received_announce(const RNS::Bytes& destination_hash,
                           const RNS::Identity& announced_identity,
                           const RNS::Bytes& app_data) override {
        int now = (int)RNS::Utilities::OS::time();
        std::string dh = destination_hash.toHex();
        std::string app_data_hex = app_data.toHex();
        std::string app_data_str = rnsdAppDataString(app_data);
        int hops = (int)RNS::Transport::hops_to(destination_hash);   /* PATHFINDER_M if unknown */

        char key[40];
        auto it = _dest_to_idx.find(dh);
        int idx = (it != _dest_to_idx.end()) ? it->second : -1;

        if (idx >= 0) {
            /* Existing — bump counters + refresh mutable fields. */
            snprintf(key, sizeof(key), "rnsd.nodes.%d.count", idx);
            int prev = storageGetInt(key, 0);
            storageBegin();
            storageSet(key, prev + 1);
            snprintf(key, sizeof(key), "rnsd.nodes.%d.last_seen", idx);
            storageSet(key, now);
            snprintf(key, sizeof(key), "rnsd.nodes.%d.app_data", idx);
            storageSet(key, app_data_hex.c_str());
            snprintf(key, sizeof(key), "rnsd.nodes.%d.name", idx);
            if (!app_data_str.empty()) storageSet(key, app_data_str.c_str());
            else                       storageUnset(key);
            snprintf(key, sizeof(key), "rnsd.nodes.%d.hops", idx);
            storageSet(key, hops);
            storageEnd();
            return;
        }

        /* New destination — evict LRU first if at capacity. Eviction is its
         * own commit so the shift lands before we append. */
        int count = storageArrayCount("rnsd.nodes");
        if (count >= RNSD_MAX_NODES) {
            int lru = rnsdFindLruIdx(count);
            snprintf(key, sizeof(key), "rnsd.nodes.%d", lru);
            storageUnset(key);
            /* Storage shifts subsequent indices down — keep our cache aligned. */
            for (auto e = _dest_to_idx.begin(); e != _dest_to_idx.end(); ) {
                if (e->second == lru)      e = _dest_to_idx.erase(e);
                else { if (e->second > lru) e->second--; ++e; }
            }
            count--;
        }
        idx = count;
        _dest_to_idx[dh] = idx;

        storageBegin();
        snprintf(key, sizeof(key), "rnsd.nodes.%d.dest", idx);
        storageSet(key, dh.c_str());
        snprintf(key, sizeof(key), "rnsd.nodes.%d.identity", idx);
        storageSet(key, announced_identity.hexhash().c_str());
        snprintf(key, sizeof(key), "rnsd.nodes.%d.pubkey", idx);
        storageSet(key, announced_identity.get_public_key().toHex().c_str());
        snprintf(key, sizeof(key), "rnsd.nodes.%d.app_data", idx);
        storageSet(key, app_data_hex.c_str());
        if (!app_data_str.empty()) {
            snprintf(key, sizeof(key), "rnsd.nodes.%d.name", idx);
            storageSet(key, app_data_str.c_str());
        }
        snprintf(key, sizeof(key), "rnsd.nodes.%d.first_seen", idx);
        storageSet(key, now);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.last_seen", idx);
        storageSet(key, now);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.count", idx);
        storageSet(key, 1);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.hops", idx);
        storageSet(key, hops);
        storageEnd();
    }

private:
    /* Cache of dest_hex → array index. Avoids a linear storage scan per
     * announce. Kept in sync with `rnsd.nodes` writes; storage is the
     * authority for everything else. */
    std::unordered_map<std::string, int> _dest_to_idx;
};

static std::shared_ptr<AnnounceTracker> s_tracker;

/* ─────────────── path table snapshot ─────────────── */

/** Strip "Interface[name]" → "name". mR's default Interface::toString() wraps
 *  the name; the browser map wants the bare name (e.g. "tcp/0", "lora"). */
static std::string ifaceShortName(const std::string& mrToString)
{
    auto open  = mrToString.find('[');
    auto close = mrToString.rfind(']');
    if (open != std::string::npos && close != std::string::npos && close > open)
        return mrToString.substr(open + 1, close - open - 1);
    return mrToString;
}

static void publishPathTable(void)
{
    cJSON* arr = cJSON_CreateArray();
    try {
        auto& paths = RNS::Transport::get_new_path_table();
        for (auto kv : paths) {
            RNS::Persistence::DestinationEntry& entry = kv.value;
            cJSON* obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "dest", kv.key.toHex().c_str());
            cJSON_AddStringToObject(obj, "next_hop_addr", entry._received_from.toHex().c_str());
            cJSON_AddStringToObject(obj, "next_hop", entry._receiving_interface
                ? ifaceShortName(entry._receiving_interface.toString()).c_str() : "");
            cJSON_AddNumberToObject(obj, "hops", (double)entry._hops);
            cJSON_AddNumberToObject(obj, "last_announce", (double)entry._timestamp);
            cJSON_AddItemToArray(arr, obj);
        }
    } catch (const std::exception& e) {
        warn("publishPathTable threw: %s", e.what());
    }
    storageSetTree("rnsd.paths", arr);   /* takes ownership */
}

/* ─────────────── stats publishing ─────────────── */

static void publishStats(void)
{
    storageSet("rnsd.stats.packets_in",  (int)(s_stats.packets_in  & 0x7fffffff));
    storageSet("rnsd.stats.packets_out", (int)(s_stats.packets_out & 0x7fffffff));
    storageSet("rnsd.stats.bytes_in",    (int)(s_stats.bytes_in    & 0x7fffffff));
    storageSet("rnsd.stats.bytes_out",   (int)(s_stats.bytes_out   & 0x7fffffff));
    storageSet("rnsd.stats.announces_in",  (int)(s_stats.announces_in  & 0x7fffffff));
    storageSet("rnsd.stats.announces_out", (int)(s_stats.announces_out & 0x7fffffff));

    int activeIfaces = 0;
    for (auto& i : s_ifaces) if (i.used) activeIfaces++;
    storageSet("rnsd.stats.ifaces_up", activeIfaces);
}

/* ─────────────── CLI ─────────────── */

static void cliRnsd(const char* args)
{
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("  %-*s RNS status / control\n",
                  CLI_HELP_COL, "rnsd [identity|persist|reload]");
        return;
    }
    if (!args || !*args) {
        if (!s_identity) { cliPrintf("identity: not loaded\n"); return; }
        cliPrintf("identity: %s\n", s_identity->hexhash().c_str());
        cliPrintf("packets in/out: %llu/%llu  bytes in/out: %llu/%llu\n",
                  (unsigned long long)s_stats.packets_in,
                  (unsigned long long)s_stats.packets_out,
                  (unsigned long long)s_stats.bytes_in,
                  (unsigned long long)s_stats.bytes_out);
        cliPrintf("registered ifaces:\n");
        for (auto& i : s_ifaces) {
            if (!i.used) continue;
            cliPrintf("  %-20s mtu=%u bitrate=%u mode=%s rx=%llu/%llu tx=%llu/%llu\n",
                      i.info.name, (unsigned)i.info.mtu, (unsigned)i.info.bitrate,
                      mode_name(i.info.mode),
                      (unsigned long long)i.rx_packets, (unsigned long long)i.rx_bytes,
                      (unsigned long long)i.tx_packets, (unsigned long long)i.tx_bytes);
        }
        return;
    }
    if (strcmp(args, "identity") == 0) {
        if (!s_identity) { cliPrintf("identity: not loaded\n"); return; }
        cliPrintf("hash:    %s\n", s_identity->hexhash().c_str());
        cliPrintf("pubkey:  %s\n", s_identity->get_public_key().toHex().c_str());
        return;
    }
    if (strncmp(args, "persist", 7) == 0) {
        bool ifTransport = strstr(args, "if-transport") != nullptr;
        bool transportEnabled = storageGetInt("s.rnsd.transport_enabled", 0) != 0;
        if (ifTransport && !transportEnabled) return;        /* silent no-op */
        /* TODO: write paths/hashlist/tunnels when Transport is wired. */
        return;
    }
    if (strcmp(args, "reload") == 0) {
        loadOrCreateIdentity();
        return;
    }
    cliPrintf("usage: rnsd [identity|persist [if-transport]|reload]\n");
}

/** `rnsd nodes` — every destination we've heard an announce from. */
static void cliRnsdNodes(const char* args)
{
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("  %-*s discovered destinations (announces)\n",
                  CLI_HELP_COL, "rnsd nodes");
        return;
    }
    int count = storageArrayCount("rnsd.nodes");
    if (count == 0) { cliPrintf("(no nodes)\n"); return; }
    uint32_t now = (uint32_t)RNS::Utilities::OS::time();
    cliPrintf("  %-18s %-18s %-6s %-3s %-3s %s\n",
              "destination", "identity", "age", "n", "hop", "name");
    for (int i = 0; i < count; i++) {
        char key[40], dbuf[80], ibuf[80], nbuf[80];
        snprintf(key, sizeof(key), "rnsd.nodes.%d.dest", i);
        storageGetStr(key, dbuf, sizeof(dbuf), "");
        snprintf(key, sizeof(key), "rnsd.nodes.%d.identity", i);
        storageGetStr(key, ibuf, sizeof(ibuf), "");
        snprintf(key, sizeof(key), "rnsd.nodes.%d.last_seen", i);
        int ls = storageGetInt(key, 0);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.count", i);
        int n = storageGetInt(key, 0);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.hops", i);
        int hops = storageGetInt(key, RNSD_HOPS_UNKNOWN);
        snprintf(key, sizeof(key), "rnsd.nodes.%d.name", i);
        storageGetStr(key, nbuf, sizeof(nbuf), "");
        char hopStr[6];
        if (hops == RNSD_HOPS_UNKNOWN) snprintf(hopStr, sizeof(hopStr), "?");
        else                            snprintf(hopStr, sizeof(hopStr), "%d", hops);
        std::string ds(dbuf), is(ibuf);
        cliPrintf("  %-18s %-18s %5lus %3d %-3s %s\n",
                  ds.substr(0, 16).c_str(),
                  is.substr(0, 16).c_str(),
                  (unsigned long)(now - (uint32_t)ls),
                  n, hopStr, nbuf);
    }
}

/** `rnsd paths` — routing table (only filled when transport_enabled). */
static void cliRnsdPaths(const char* args)
{
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("  %-*s routing paths (transport mode)\n",
                  CLI_HELP_COL, "rnsd paths");
        return;
    }
    auto& pt = RNS::Transport::get_new_path_table();
    if (pt.size() == 0) { cliPrintf("(no paths)\n"); return; }
    double now = RNS::Utilities::OS::time();
    cliPrintf("  %-18s %-18s %-16s %-5s %-8s\n",
              "destination", "next hop", "iface", "hops", "age");
    for (auto kv : pt) {
        std::string iname = kv.value._receiving_interface
            ? kv.value._receiving_interface.name() : "?";
        std::string dh = kv.key.toHex();
        std::string nh = kv.value._received_from.toHex();
        cliPrintf("  %-18s %-18s %-16s %-5u %lus\n",
                  dh.substr(0, 16).c_str(),
                  nh.substr(0, 16).c_str(),
                  iname.c_str(),
                  (unsigned)kv.value._hops,
                  (unsigned long)(now - kv.value._timestamp));
    }
}

/* ─────────────── Task ─────────────── */

static TickType_t nextDeadline(void)
{
    /* Publish stats at 1 Hz. */
    TickType_t now = xTaskGetTickCount();
    TickType_t due = s_lastPublishTick + pdMS_TO_TICKS(1000);
    if (due <= now) return 0;
    return due - now;
}

static void rnsdTaskMain(void*)
{
    info("[%s] task up", TAG);

    if (!itsServerInit()) { err("itsServerInit failed"); vTaskDelete(nullptr); return; }
    if (!itsServerPortOpen(RNSD_PORT_REGISTER, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_IFACES,
                           /*toSize=*/2048, /*fromSize=*/2048)) {
        err("RNSD_PORT_REGISTER open failed");
        vTaskDelete(nullptr);
        return;
    }
    itsServerOnConnect(RNSD_PORT_REGISTER, onRegisterConnect);
    itsServerOnDisconnect(RNSD_PORT_REGISTER, onRegisterDisconnect);
    itsServerOnRecv(RNSD_PORT_REGISTER, onRegisterRecv);

    loadOrCreateIdentity();
    storageSet("rnsd.up", 1);
    if (s_identity) storageSet("rnsd.identity_hash", s_identity->hexhash().c_str());

    /* Bring up mR. Reticulum::transport_enabled() is a static global
     * consulted by Transport for forwarding decisions. We mirror our
     * persistent flag into it before start(). */
    try {
        s_reticulum = std::make_unique<RNS::Reticulum>();
        RNS::Reticulum::transport_enabled(
            storageGetInt("s.rnsd.transport_enabled", 0) != 0);
        s_reticulum->start();
        info("Reticulum/Transport up (transport_enabled=%d)",
             (int)RNS::Reticulum::transport_enabled());

        /* Register the announce tracker — fires for every announce regardless
         * of transport_enabled, so a leaf node still builds a node list. */
        s_tracker = std::make_shared<AnnounceTracker>();
        RNS::Transport::register_announce_handler(s_tracker);
    } catch (const std::exception& e) {
        err("Reticulum::start threw: %s", e.what());
    }

    s_lastPublishTick = xTaskGetTickCount();

    for (;;) {
        itsPoll(nextDeadline());

        TickType_t now = xTaskGetTickCount();
        if (now - s_lastPublishTick >= pdMS_TO_TICKS(1000)) {
            /* mR housekeeping: announce queue, link/resource state, hashlist
             * culling, path expiry. Caps tasks's idle CPU at 1 Hz instead
             * of the per-tick loop mR was originally designed for. */
            try { RNS::Transport::jobs(); }
            catch (const std::exception& e) { warn("Transport::jobs threw: %s", e.what()); }

            publishStats();
            publishPathTable();
            s_lastPublishTick = now;
        }
    }
}

void rnsdInit(void)
{
    /* One-time storage defaults gated on version. */
    if (storageGetInt("s.rnsd.version", 0) < RNSD_VERSION) {
        storageDefault("s.rnsd.enable", 1);
        storageDefault("s.rnsd.transport_enabled", 0);
        storageDefault("s.rnsd.name", "");
        storageDefault("s.rnsd.announce.interval", 1800);   /* 30 min */
        storageDefault("s.rnsd.path.max", 256);
        storageDefault("s.rnsd.path.ttl", 86400);
        storageSet("s.rnsd.version", RNSD_VERSION);
    }

    cliRegisterCmd("rnsd", cliRnsd);
    cliRegisterCmd("rnsd nodes", cliRnsdNodes);
    cliRegisterCmd("rnsd paths", cliRnsdPaths);

    /* Cron line per §11.3 — no-op when transport disabled, hourly otherwise. */
    cronDefault("0 * * * * N", "rnsd persist if-transport");

    /* PSRAM stack, core 0 alongside tcpip_thread, prio 2. */
    s_task = spawnTask(rnsdTaskMain, TAG, 12288, nullptr, 2, 0, STACK_PSRAM);
}
