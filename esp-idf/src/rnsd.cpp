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
#include <memory>
#include <vector>
#include <map>
#include <algorithm>
#include <new>

#include "esp_heap_caps.h"

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
    void send_outgoing(const RNS::Bytes& data) override;
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

/* Allocated from PSRAM in rnsdInit() to keep ~1.7 KiB out of DRAM. Hot
 * path (rx counter bump) pays ~50 ns vs ~1 ns DRAM per access — fine at
 * our packet rates. RNS::Interface has a non-trivial ctor, so we use
 * placement-new on each slot. */
static iface_t* s_ifaces = nullptr;

static TaskHandle_t s_task = nullptr;
static std::unique_ptr<RNS::Identity> s_identity;
static std::unique_ptr<RNS::Reticulum> s_reticulum;

/* Stats — diff-published to ephemeral storage at 1 Hz. */
static struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
} s_stats;

static TickType_t s_lastPublishTick = 0;

/* ─────────────── RNSD_PORT_PACKET state ───────────────
 *
 * Per-connection state for the raw-packet API. Apps connect with a
 * rnsd_packet_connect_t describing their destination + sender identity.
 * Each ITS packet over the connection = payload bytes; rnsd wraps in a
 * mR Packet and sends. PacketReceipt callback → small status struct sent
 * back to the originating connection.
 *
 * Receipt callbacks are C function pointers with no user-data slot; we
 * carry the connection identity through `outstanding_hash` and look up
 * by that hash when the callback fires. One outstanding send per slot. */

#define RNSD_MAX_PACKET_CONNS  4

/* Result status byte sent back to the app for each probe. */
#define PACKET_RESULT_DELIVERY        0   /* delivery confirmed, rtt_ms/hops populated */
#define PACKET_RESULT_TIMEOUT         1   /* mR receipt timeout, no proof */
#define PACKET_RESULT_NO_PATH         2   /* no path; request_path issued */
#define PACKET_RESULT_NO_IDENTITY     3   /* path known but identity not cached; request_path issued */
#define PACKET_RESULT_DEST_ERROR      4   /* Destination ctor threw */
#define PACKET_RESULT_NO_SENDER_ID    5   /* couldn't load sender identity from storage key */
#define PACKET_RESULT_SEND_FAILED     6   /* pkt.send() returned no receipt */

struct packet_conn_t {
    bool                  used;
    int                   handle;

    /* connect params, stashed verbatim — no mR work in onPacketConnect. */
    rnsd_packet_connect_t req;

    /* lazily built on first recv. */
    bool                  resources_ready;
    RNS::Identity         sender_identity{RNS::Type::NONE};
    RNS::Destination      dest{RNS::Type::NONE};

    /* in-flight tracking — receipt callbacks dispatch by hash. */
    RNS::Bytes            outstanding_hash;
    double                outstanding_sent_at;
    uint8_t               outstanding_hops_at_send;
};

static packet_conn_t* s_packet_conns = nullptr;

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
    for (int j = 0; j < RNSD_MAX_IFACES; j++)
        if (s_ifaces[j].used && s_ifaces[j].handle == handle) return &s_ifaces[j];
    return nullptr;
}

static iface_t* ifaceAlloc(void)
{
    for (int j = 0; j < RNSD_MAX_IFACES; j++)
        if (!s_ifaces[j].used) return &s_ifaces[j];
    return nullptr;
}

void TaskInterface::send_outgoing(const RNS::Bytes& data)
{
    if (_handle < 0) return;
    size_t s = itsSend(_handle, data.data(), data.size(), pdMS_TO_TICKS(100));
    if (s == 0) {
        warn("iface %s: ITS send dropped (%zu B)", _name.c_str(), data.size());
        return;
    }
    _txb += data.size();
    if (iface_t* i = ifaceFindByHandle(_handle)) {
        i->tx_packets++;
        i->tx_bytes += data.size();
    }
    s_stats.packets_out++;
    s_stats.bytes_out += data.size();
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

/* ─────────────── RNSD_PORT_PACKET handlers ─────────────── */

static packet_conn_t* packetConnFindByHandle(int handle)
{
    for (int j = 0; j < RNSD_MAX_PACKET_CONNS; j++)
        if (s_packet_conns[j].used && s_packet_conns[j].handle == handle) return &s_packet_conns[j];
    return nullptr;
}

static packet_conn_t* packetConnFindByHash(const RNS::Bytes& hash)
{
    for (int j = 0; j < RNSD_MAX_PACKET_CONNS; j++)
        if (s_packet_conns[j].used && s_packet_conns[j].outstanding_hash == hash)
            return &s_packet_conns[j];
    return nullptr;
}

static packet_conn_t* packetConnAlloc(void)
{
    for (int j = 0; j < RNSD_MAX_PACKET_CONNS; j++)
        if (!s_packet_conns[j].used) return &s_packet_conns[j];
    return nullptr;
}

/* Pack a 6-byte result into a buffer and itsSend it to the connection.
 *   [0]    status  0=delivery, 1=timeout
 *   [1..4] rtt_ms  big-endian u32 (0 on timeout)
 *   [5]    hops    hop count at send time */
static void packetConnSendResult(packet_conn_t& c, uint8_t status, uint32_t rtt_ms, uint8_t hops)
{
    uint8_t out[6];
    out[0] = status;
    out[1] = (uint8_t)((rtt_ms >> 24) & 0xFF);
    out[2] = (uint8_t)((rtt_ms >> 16) & 0xFF);
    out[3] = (uint8_t)((rtt_ms >>  8) & 0xFF);
    out[4] = (uint8_t)( rtt_ms        & 0xFF);
    out[5] = hops;
    if (itsSend(c.handle, out, sizeof(out), pdMS_TO_TICKS(100)) == 0)
        warn("packet conn: result send dropped");
    c.outstanding_hash = RNS::Bytes();
}

static void onPacketSendDelivery(const RNS::PacketReceipt& r)
{
    packet_conn_t* c = packetConnFindByHash(r.truncated_hash());
    if (!c) return;
    double rtt_s = r.concluded_at() - c->outstanding_sent_at;
    if (rtt_s < 0) rtt_s = 0;
    uint32_t rtt_ms = (uint32_t)(rtt_s * 1000.0);
    packetConnSendResult(*c, PACKET_RESULT_DELIVERY, rtt_ms, c->outstanding_hops_at_send);
}

static void onPacketSendTimeout(const RNS::PacketReceipt& r)
{
    packet_conn_t* c = packetConnFindByHash(r.truncated_hash());
    if (!c) return;
    packetConnSendResult(*c, PACKET_RESULT_TIMEOUT, 0, c->outstanding_hops_at_send);
}

static int onPacketConnect(int handle, const void* data, size_t len)
{
    if (len != sizeof(rnsd_packet_connect_t)) {
        err("packet connect: bad payload len %zu (want %zu)", len, sizeof(rnsd_packet_connect_t));
        return -1;
    }

    packet_conn_t* slot = packetConnAlloc();
    if (!slot) { err("packet connect: no slots"); return -1; }

    slot->used            = true;
    slot->handle          = handle;
    slot->req             = *(const rnsd_packet_connect_t*)data;
    slot->resources_ready = false;
    slot->sender_identity = RNS::Identity(RNS::Type::NONE);
    slot->dest            = RNS::Destination(RNS::Type::NONE);
    slot->outstanding_hash = RNS::Bytes();

    /* Resource resolution (identity load, has_path, recall, Destination
     * ctor) is deferred to onPacketRecv. Failures there are reported as
     * 6-byte result codes back to the app instead of rejecting the connect. */
    info("packet conn %d open: dest=%s aspect=%s",
         (int)(slot - s_packet_conns),
         RNS::Bytes((const uint8_t*)slot->req.dest_hash, 16).toHex().c_str(),
         slot->req.aspect);
    return (int)(slot - s_packet_conns);
}

/* Build sender_identity + dest in the slot, requesting paths and reporting
 * errors via result codes as needed. Returns true iff resources are now
 * ready; false means a result has been sent and the caller should bail. */
static bool packetConnEnsureResources(packet_conn_t& c)
{
    if (c.resources_ready) return true;

    /* Sender identity. */
    const char* key = c.req.identity_key[0] ? c.req.identity_key : "secrets.rnsd.identity";
    char hex[160] = {};
    storageGetStr(key, hex, sizeof(hex), "");
    if (strlen(hex) != 128) {
        err("packet recv: no sender identity at %s", key);
        packetConnSendResult(c, PACKET_RESULT_NO_SENDER_ID, 0, 0);
        return false;
    }
    RNS::Bytes prv;
    prv.assignHex((const uint8_t*)hex, 128);
    if (prv.size() != 64) {
        err("packet recv: bad sender identity hex at %s", key);
        packetConnSendResult(c, PACKET_RESULT_NO_SENDER_ID, 0, 0);
        return false;
    }
    RNS::Identity sender(false);
    if (!sender.load_private_key(prv)) {
        err("packet recv: sender identity load failed for %s", key);
        packetConnSendResult(c, PACKET_RESULT_NO_SENDER_ID, 0, 0);
        return false;
    }

    RNS::Bytes dh((const uint8_t*)c.req.dest_hash, 16);

    /* Path. */
    if (!RNS::Transport::has_path(dh)) {
        warn("packet recv: no path to %s — issuing path request", dh.toHex().c_str());
        try { RNS::Transport::request_path(dh); }
        catch (const std::exception& e) { warn("request_path threw: %s", e.what()); }
        packetConnSendResult(c, PACKET_RESULT_NO_PATH, 0, 0);
        return false;
    }

    /* Target identity. */
    RNS::Identity target = RNS::Identity::recall(dh);
    if (!target) {
        warn("packet recv: identity for %s not in cache — issuing path request",
             dh.toHex().c_str());
        try { RNS::Transport::request_path(dh); }
        catch (const std::exception& e) { warn("request_path threw: %s", e.what()); }
        packetConnSendResult(c, PACKET_RESULT_NO_IDENTITY, 0, 0);
        return false;
    }

    /* Destination. Split aspect at first dot. */
    std::string aspect = c.req.aspect;
    std::string app_name = aspect, aspects;
    auto dot = aspect.find('.');
    if (dot != std::string::npos) {
        app_name = aspect.substr(0, dot);
        aspects  = aspect.substr(dot + 1);
    }
    RNS::Type::Destination::types dtype = RNS::Type::Destination::SINGLE;
    if      (c.req.dest_type == 1) dtype = RNS::Type::Destination::PLAIN;
    else if (c.req.dest_type == 2) dtype = RNS::Type::Destination::GROUP;
    try {
        c.dest = RNS::Destination(target, RNS::Type::Destination::OUT, dtype,
                                  app_name.c_str(), aspects.c_str());
    } catch (const std::exception& e) {
        err("packet recv: Destination ctor threw: %s", e.what());
        packetConnSendResult(c, PACKET_RESULT_DEST_ERROR, 0, 0);
        return false;
    }

    c.sender_identity  = sender;
    c.resources_ready  = true;
    return true;
}

static void onPacketDisconnect(int ref)
{
    if (ref < 0 || ref >= RNSD_MAX_PACKET_CONNS) return;
    packet_conn_t& c = s_packet_conns[ref];
    if (!c.used) return;
    info("packet conn %d close", ref);
    c.used = false;
    c.handle = -1;
    c.resources_ready = false;
    c.sender_identity = RNS::Identity(RNS::Type::NONE);
    c.dest = RNS::Destination(RNS::Type::NONE);
    c.outstanding_hash = RNS::Bytes();
}

static void onPacketRecv(int handle, size_t /*bytesAvail*/)
{
    packet_conn_t* c = packetConnFindByHandle(handle);
    if (!c) return;
    static uint8_t payload[600];
    size_t n = itsRecv(handle, payload, sizeof(payload), 0);
    if (n == 0) return;

    /* Build sender identity + target Destination if not already done. On
     * failure, packetConnEnsureResources sends a status byte and returns
     * false — we bail without touching mR. */
    if (!packetConnEnsureResources(*c)) return;

    try {
        RNS::Bytes data(payload, n);
        RNS::Packet pkt(c->dest, data);
        RNS::PacketReceipt receipt = pkt.send();
        if (!receipt) {
            warn("packet recv: send returned no receipt");
            packetConnSendResult(*c, PACKET_RESULT_SEND_FAILED, 0, 0);
            return;
        }
        c->outstanding_hash         = receipt.truncated_hash();
        c->outstanding_sent_at      = RNS::Utilities::OS::time();
        c->outstanding_hops_at_send = (uint8_t)RNS::Transport::hops_to(c->dest.hash());
        receipt.set_timeout(15);
        receipt.set_delivery_callback(onPacketSendDelivery);
        receipt.set_timeout_callback(onPacketSendTimeout);
    } catch (const std::exception& e) {
        err("packet recv: send threw: %s", e.what());
        packetConnSendResult(*c, PACKET_RESULT_SEND_FAILED, 0, 0);
    }
}

/* ─────────────── announce dbg logger ─────────────── */

/* Each byte → printable ASCII if 0x20..0x7E, else '.'. Lets us spot
 * LXMF/Nomad display names without losing the structure of binary blobs. */
static std::string appDataPrintable(const RNS::Bytes& app_data) {
    std::string out;
    out.reserve(app_data.size());
    for (size_t i = 0; i < app_data.size(); i++) {
        uint8_t b = app_data.data()[i];
        out += (b >= 0x20 && b <= 0x7E) ? (char)b : '.';
    }
    return out;
}

/* True iff `n` bytes at `p` contain no control codes — i.e. plausibly a
 * UTF-8 / ASCII display name. Allows >=0x80 bytes (UTF-8 multibyte). */
static bool isPlausibleText(const uint8_t* p, size_t n) {
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = p[i];
        if (b == 0x7F) return false;
        if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') return false;
    }
    return true;
}

/* Tiny msgpack pretty-printer — bounded recursion, bounded output size.
 * Returns true iff one valid msgpack value was decoded starting at *i.
 * Handles fixint, fixstr/str8/16/32, fixarray/array16/32, fixmap/map16/32,
 * nil, bool, int8/16/32/64, uint8/16/32/64, bin8/16/32, float32/64. Bails
 * on ext / fixext (not used by LXMF/Nomad announce data). */
static bool mpDecode(const uint8_t* d, size_t n, size_t& i,
                     std::string& out, int depth)
{
    if (depth > 8)        { out += "..."; return false; }
    if (i >= n)           return false;
    if (out.size() > 800) return false;   /* hard size cap — no ellipsis */

    auto needN = [&](size_t k) { return i + k <= n; };
    auto putStr = [&](size_t L) {
        if (!needN(L)) return false;
        out += '"';
        for (size_t k = 0; k < L; k++) {
            char c = (char)d[i+k];
            out += (c >= 0x20 && c <= 0x7E) ? c : '.';
        }
        out += '"';
        i += L;
        return true;
    };
    auto putBin = [&](size_t L) {
        if (!needN(L)) return false;
        out += "b\"";
        for (size_t k = 0; k < L; k++) {
            char c[4]; snprintf(c, sizeof(c), "%02x", d[i+k]);
            out += c;
        }
        out += '"';
        i += L;
        return true;
    };
    auto readBe = [&](int bytes, uint64_t& v) {
        if (!needN((size_t)bytes)) return false;
        v = 0; for (int j = 0; j < bytes; j++) v = (v << 8) | d[i+j];
        i += bytes; return true;
    };

    uint8_t b = d[i++];
    if (b <= 0x7F)               { out += std::to_string(b); return true; }
    if (b >= 0xE0)               { out += std::to_string((int)(int8_t)b); return true; }
    if (b >= 0xA0 && b <= 0xBF)  return putStr(b & 0x1F);
    if (b >= 0x90 && b <= 0x9F) {
        size_t cnt = b & 0x0F;
        out += '[';
        for (size_t k = 0; k < cnt; k++) {
            if (k) out += ", ";
            if (!mpDecode(d, n, i, out, depth+1)) return false;
        }
        out += ']'; return true;
    }
    if (b >= 0x80 && b <= 0x8F) {
        size_t cnt = b & 0x0F;
        out += '{';
        for (size_t k = 0; k < cnt; k++) {
            if (k) out += ", ";
            if (!mpDecode(d, n, i, out, depth+1)) return false;
            out += ": ";
            if (!mpDecode(d, n, i, out, depth+1)) return false;
        }
        out += '}'; return true;
    }
    uint64_t v;
    switch (b) {
        case 0xC0: out += "nil";   return true;
        case 0xC2: out += "false"; return true;
        case 0xC3: out += "true";  return true;
        case 0xC4: if (!readBe(1, v)) return false; return putBin((size_t)v);
        case 0xC5: if (!readBe(2, v)) return false; return putBin((size_t)v);
        case 0xC6: if (!readBe(4, v)) return false; return putBin((size_t)v);
        case 0xCC: if (!readBe(1, v)) return false; out += std::to_string(v); return true;
        case 0xCD: if (!readBe(2, v)) return false; out += std::to_string(v); return true;
        case 0xCE: if (!readBe(4, v)) return false; out += std::to_string(v); return true;
        case 0xCF: if (!readBe(8, v)) return false; out += std::to_string(v); return true;
        case 0xD0: if (!readBe(1, v)) return false; out += std::to_string((int)(int8_t)v); return true;
        case 0xD1: if (!readBe(2, v)) return false; out += std::to_string((int)(int16_t)v); return true;
        case 0xD2: if (!readBe(4, v)) return false; out += std::to_string((int)(int32_t)v); return true;
        case 0xD3: if (!readBe(8, v)) return false; out += std::to_string((long long)(int64_t)v); return true;
        case 0xD9: if (!readBe(1, v)) return false; return putStr((size_t)v);
        case 0xDA: if (!readBe(2, v)) return false; return putStr((size_t)v);
        case 0xDB: if (!readBe(4, v)) return false; return putStr((size_t)v);
        case 0xDC: if (!readBe(2, v)) return false; { size_t cnt=(size_t)v; out+='['; for (size_t k=0;k<cnt;k++){if(k)out+=", ";if(!mpDecode(d,n,i,out,depth+1))return false;} out+=']';return true;}
        case 0xDD: if (!readBe(4, v)) return false; { size_t cnt=(size_t)v; out+='['; for (size_t k=0;k<cnt;k++){if(k)out+=", ";if(!mpDecode(d,n,i,out,depth+1))return false;} out+=']';return true;}
        case 0xDE: if (!readBe(2, v)) return false; { size_t cnt=(size_t)v; out+='{'; for (size_t k=0;k<cnt;k++){if(k)out+=", ";if(!mpDecode(d,n,i,out,depth+1))return false;out+=": ";if(!mpDecode(d,n,i,out,depth+1))return false;} out+='}';return true;}
        case 0xDF: if (!readBe(4, v)) return false; { size_t cnt=(size_t)v; out+='{'; for (size_t k=0;k<cnt;k++){if(k)out+=", ";if(!mpDecode(d,n,i,out,depth+1))return false;out+=": ";if(!mpDecode(d,n,i,out,depth+1))return false;} out+='}';return true;}
        case 0xCA: { if (!readBe(4, v)) return false; float f; uint32_t bits=(uint32_t)v; memcpy(&f,&bits,4); char buf[24]; snprintf(buf,sizeof(buf),"%g",(double)f); out+=buf; return true; }
        case 0xCB: { if (!readBe(8, v)) return false; double f; memcpy(&f,&v,8); char buf[32]; snprintf(buf,sizeof(buf),"%g",f); out+=buf; return true; }

        /* fixext1/2/4/8/16: 1 type byte + N data bytes. */
        case 0xD4: case 0xD5: case 0xD6: case 0xD7: case 0xD8: {
            size_t L = (size_t)1 << (b - 0xD4);
            if (!needN(1 + L)) return false;
            uint8_t etype = d[i]; i++;
            char hdr[24]; snprintf(hdr, sizeof(hdr), "ext(%d,%zuB)=", (int)(int8_t)etype, L);
            out += hdr;
            return putBin(L);
        }
        /* ext8/16/32: len + type + data. */
        case 0xC7: case 0xC8: case 0xC9: {
            int lb = (b == 0xC7) ? 1 : (b == 0xC8 ? 2 : 4);
            if (!readBe(lb, v)) return false;
            size_t L = (size_t)v;
            if (!needN(1 + L)) return false;
            uint8_t etype = d[i]; i++;
            char hdr[24]; snprintf(hdr, sizeof(hdr), "ext(%d,%zuB)=", (int)(int8_t)etype, L);
            out += hdr;
            return putBin(L);
        }
        default:   return false;   /* reserved / unused — bail */
    }
}

/* Returns a msgpack pretty-string iff bytes [start, end) parse fully as one
 * msgpack value. */
static std::string appDataMsgPackRange(const RNS::Bytes& app_data,
                                        size_t start, size_t end) {
    if (end > app_data.size() || end <= start) return "";
    std::string out;
    size_t i = start;
    if (!mpDecode(app_data.data(), end, i, out, 0)) return "";
    if (i != end) return "";
    return out;
}

static std::string appDataMsgPackAt(const RNS::Bytes& app_data, size_t start) {
    return appDataMsgPackRange(app_data, start, app_data.size());
}

static std::string appDataMsgPack(const RNS::Bytes& app_data) {
    return appDataMsgPackAt(app_data, 0);
}

/* Logs every announce mR sees at dbg-level. No persistence — that's the
 * application layer's job (LXMF, etc.) and would scale badly on busy
 * networks. See feedback notes on TCP-relay announce volume. */
class AnnounceDebugLogger : public RNS::AnnounceHandler {
public:
    AnnounceDebugLogger() : RNS::AnnounceHandler(nullptr) {}
    void received_announce(const RNS::Bytes& destination_hash,
                           const RNS::Identity& announced_identity,
                           const RNS::Bytes& app_data) override {
        int hops = (int)RNS::Transport::hops_to(destination_hash);
        std::string dest = destination_hash.toHex();
        std::string id   = announced_identity.hexhash();

        std::string mp = appDataMsgPack(app_data);
        if (!mp.empty()) {
            dbg("announce dest=%s id=%s hops=%d app_data(%zuB) mp=%s",
                dest.c_str(), id.c_str(), hops, app_data.size(), mp.c_str());
        } else if (app_data.size() >= 32 &&
                   !(mp = appDataMsgPackAt(app_data, 32)).empty()) {
            /* Ratchet (32 B X25519 pubkey) + msgpack payload. */
            RNS::Bytes ratchet(app_data.data(), 32);
            std::string ratchetHex = ratchet.toHex();
            dbg("announce dest=%s id=%s hops=%d app_data(%zuB) ratchet=%s mp=%s",
                dest.c_str(), id.c_str(), hops, app_data.size(),
                ratchetHex.c_str(), mp.c_str());
        } else if (app_data.size() >= 32 &&
                   isPlausibleText(app_data.data() + 32, app_data.size() - 32)) {
            /* Ratchet + raw UTF-8/ASCII display name (no msgpack wrap). */
            RNS::Bytes ratchet(app_data.data(), 32);
            std::string ratchetHex = ratchet.toHex();
            std::string name((const char*)app_data.data() + 32,
                             app_data.size() - 32);
            dbg("announce dest=%s id=%s hops=%d app_data(%zuB) ratchet=%s name=\"%s\"",
                dest.c_str(), id.c_str(), hops, app_data.size(),
                ratchetHex.c_str(), name.c_str());
        } else if (app_data.size() >= 33 &&
                   !(mp = appDataMsgPackRange(app_data, 1, app_data.size() - 32)).empty()) {
            /* version-byte + msgpack metadata + trailing 32-byte ratchet
             * (Reticulum interface advertisements with location etc.). */
            uint8_t prefix = app_data.data()[0];
            RNS::Bytes ratchet(app_data.data() + app_data.size() - 32, 32);
            dbg("announce dest=%s id=%s hops=%d app_data(%zuB) v=%02x mp=%s ratchet=%s",
                dest.c_str(), id.c_str(), hops, app_data.size(),
                prefix, mp.c_str(), ratchet.toHex().c_str());
        } else {
            dbg("announce dest=%s id=%s hops=%d app_data(%zuB)=\"%s\"",
                dest.c_str(), id.c_str(), hops, app_data.size(),
                appDataPrintable(app_data).c_str());
        }
        if (app_data.size() > 0)
            verb("announce hex %s", app_data.toHex().c_str());
    }
};

static std::shared_ptr<AnnounceDebugLogger> s_announce_logger;

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

/* Cap the number of paths we publish per tick. Each entry runs ~150 B in
 * the cJSON patch, and the storage layer caps patches at 60 KB. Also: each
 * TypedStore iterator step copies a DestinationEntry, which includes a
 * std::set<RNS::Bytes> _random_blobs whose destructor walks an RB-tree in
 * PSRAM — capping bounds that work so IDLE0 doesn't starve. */
#define RNSD_PATHS_PUBLISH_MAX 64
#define RNSD_PATHS_YIELD_EVERY 8

static void publishPathTable(void)
{
    cJSON* arr = cJSON_CreateArray();
    int n = 0;
    try {
        auto& paths = RNS::Transport::get_new_path_table();
        for (auto kv : paths) {
            if (n >= RNSD_PATHS_PUBLISH_MAX) break;
            RNS::Persistence::DestinationEntry& entry = kv.value;
            cJSON* obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "dest", kv.key.toHex().c_str());
            cJSON_AddStringToObject(obj, "next_hop_addr", entry._received_from.toHex().c_str());
            cJSON_AddStringToObject(obj, "next_hop", entry._receiving_interface
                ? ifaceShortName(entry._receiving_interface.toString()).c_str() : "");
            cJSON_AddNumberToObject(obj, "hops", (double)entry._hops);
            cJSON_AddNumberToObject(obj, "last_announce", (double)entry._timestamp);
            cJSON_AddItemToArray(arr, obj);
            if ((++n % RNSD_PATHS_YIELD_EVERY) == 0) vTaskDelay(1);
        }
    } catch (const std::exception& e) {
        warn("publishPathTable threw: %s", e.what());
    }
    storageSetTree("rnsd.paths", arr);   /* takes ownership */
}

/* ─────────────── stats publishing ─────────────── */

static void publishStats(void)
{
    storageBegin();
    storageSet("rnsd.stats.packets_in",  (int)(s_stats.packets_in  & 0x7fffffff));
    storageSet("rnsd.stats.packets_out", (int)(s_stats.packets_out & 0x7fffffff));
    storageSet("rnsd.stats.bytes_in",    (int)(s_stats.bytes_in    & 0x7fffffff));
    storageSet("rnsd.stats.bytes_out",   (int)(s_stats.bytes_out   & 0x7fffffff));
    int activeIfaces = 0;
    for (int j = 0; j < RNSD_MAX_IFACES; j++) {
        auto& i = s_ifaces[j];
        if (!i.used) continue;
        activeIfaces++;
        char key[80];
        snprintf(key, sizeof(key), "rnsd.ifaces.%s.rx_packets", i.info.name);
        storageSet(key, (int)(i.rx_packets & 0x7fffffff));
        snprintf(key, sizeof(key), "rnsd.ifaces.%s.tx_packets", i.info.name);
        storageSet(key, (int)(i.tx_packets & 0x7fffffff));
        snprintf(key, sizeof(key), "rnsd.ifaces.%s.rx_bytes", i.info.name);
        storageSet(key, (int)(i.rx_bytes & 0x7fffffff));
        snprintf(key, sizeof(key), "rnsd.ifaces.%s.tx_bytes", i.info.name);
        storageSet(key, (int)(i.tx_bytes & 0x7fffffff));
    }
    storageSet("rnsd.stats.ifaces_up", activeIfaces);
    storageEnd();
}

/* ─────────────── CLI ─────────────── */

static void cliRnsd(const char* args)
{
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("  %-*s identity & control (see rnstatus for status)\n",
                  CLI_HELP_COL, "rnsd [identity|persist|reload]");
        return;
    }
    if (!args || !*args) {
        cliPrintf("usage: rnsd [identity|persist [if-transport]|reload]\n");
        cliPrintf("       rnstatus  — interfaces & traffic\n");
        cliPrintf("       rnpath    — routing paths\n");
        cliPrintf("       rnprobe   — RTT probe\n");
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

/* ─────────────── rnpath ─────────────── */

struct PathRow {
    std::string dest;
    std::string next_hop;
    std::string iface;
    int          hops;
    double       timestamp;
};

#define RNPATH_DEFAULT_LIMIT 32
#define RNPATH_YIELD_EVERY   16

/** Consume one whitespace-delimited token starting at *i in `a`; advance *i. */
static std::string rnpathNextToken(const std::string& a, size_t* i)
{
    while (*i < a.size() && (a[*i] == ' ' || a[*i] == '\t')) (*i)++;
    size_t s = *i;
    while (*i < a.size() && a[*i] != ' ' && a[*i] != '\t') (*i)++;
    return a.substr(s, *i - s);
}

static void cliRnpath(const char* args)
{
    std::string filter_dest;
    std::string filter_iface;
    int  max_hops    = -1;
    int  limit       = RNPATH_DEFAULT_LIMIT;
    bool show_all    = false;
    bool summary     = false;
    bool drop        = false;
    bool json        = false;
    bool show_help   = false;

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            std::string t = rnpathNextToken(a, &i);
            if (t.empty()) break;
            if      (t == "help")                       show_help = true;
            else if (t == "-a" || t == "--all")         show_all = true;
            else if (t == "-s" || t == "--summary")     summary  = true;
            else if (t == "-d" || t == "--drop")        drop     = true;
            else if (t == "-j" || t == "--json")        json     = true;
            else if (t == "-i" || t == "--iface")       filter_iface = rnpathNextToken(a, &i);
            else if (t == "-m" || t == "--max-hops")    max_hops = atoi(rnpathNextToken(a, &i).c_str());
            else if (t == "-n" || t == "--limit")       limit    = atoi(rnpathNextToken(a, &i).c_str());
            else if (!t.empty() && t[0] != '-')         filter_dest = t;
            else {
                cliPrintf("unknown option: %s\n", t.c_str());
                cliPrintf("usage: rnpath [destination] [-i iface] [-m hops] [-n N] [-a] [-s] [-d] [-j]\n");
                return;
            }
        }
    }

    if (show_help) {
        cliPrintf("  %-*s routing paths\n", CLI_HELP_COL, "rnpath [destination]");
        cliPrintf("    -i iface     filter by interface\n");
        cliPrintf("    -m hops      filter by max hops\n");
        cliPrintf("    -n N         row limit (default %d)\n", RNPATH_DEFAULT_LIMIT);
        cliPrintf("    -a --all     no row limit\n");
        cliPrintf("    -s --summary counts only, no rows\n");
        cliPrintf("    -d --drop    drop path to destination\n");
        cliPrintf("    -j --json    JSON output\n");
        return;
    }

    if (drop) {
        if (filter_dest.empty()) { cliPrintf("rnpath -d: destination required\n"); return; }
        RNS::Bytes h;
        h.assignHex((const uint8_t*)filter_dest.c_str(), filter_dest.size());
        bool ok = false;
        try { ok = RNS::Transport::expire_path(h); }
        catch (const std::exception& e) { cliPrintf("expire_path threw: %s\n", e.what()); return; }
        cliPrintf("%s\n", ok ? "dropped" : "no such path");
        return;
    }

    /* Single pass: collect matching rows + accumulate histograms. The path
     * table can be ~thousands of entries on a busy testnet; iteration copies
     * each DestinationEntry, so we only walk once. */
    std::vector<PathRow> rows;
    std::map<std::string, int> by_iface;
    std::map<int, int>         by_hops;
    int total = 0;
    int yield_n = 0;
    try {
        auto& pt = RNS::Transport::get_new_path_table();
        for (auto kv : pt) {
            total++;
            const auto& entry = kv.value;
            std::string iname = entry._receiving_interface
                ? ifaceShortName(entry._receiving_interface.toString()) : "?";
            int hops = (int)entry._hops;
            by_iface[iname]++;
            by_hops[hops]++;

            std::string dh = kv.key.toHex();
            if (!filter_dest.empty()  && dh.rfind(filter_dest, 0) != 0) goto next;
            if (!filter_iface.empty() && iname != filter_iface)         goto next;
            if (max_hops >= 0         && hops  > max_hops)              goto next;
            rows.push_back({dh, entry._received_from.toHex(), iname, hops, entry._timestamp});
        next:
            if ((++yield_n % RNPATH_YIELD_EVERY) == 0) vTaskDelay(1);
        }
    } catch (const std::exception& e) {
        cliPrintf("path table iteration threw: %s\n", e.what());
        return;
    }

    if (json) {
        cJSON* root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "total",    total);
        cJSON_AddNumberToObject(root, "matching", (int)rows.size());
        cJSON* arr = cJSON_CreateArray();
        int max_emit = show_all ? (int)rows.size() : std::min((int)rows.size(), limit);
        for (int n = 0; n < max_emit; n++) {
            cJSON* o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "dest",     rows[n].dest.c_str());
            cJSON_AddStringToObject(o, "next_hop", rows[n].next_hop.c_str());
            cJSON_AddStringToObject(o, "iface",    rows[n].iface.c_str());
            cJSON_AddNumberToObject(o, "hops",     rows[n].hops);
            cJSON_AddNumberToObject(o, "timestamp", rows[n].timestamp);
            cJSON_AddItemToArray(arr, o);
        }
        cJSON_AddItemToObject(root, "paths", arr);
        char* text = cJSON_PrintUnformatted(root);
        if (text) { cliPrintf("%s\n", text); cJSON_free(text); }
        cJSON_Delete(root);
        return;
    }

    cliPrintf("%d paths total", total);
    if ((int)rows.size() != total) cliPrintf(" (%d matching)", (int)rows.size());
    cliPrintf("\n");

    cliPrintf("  by iface:");
    for (auto& kv : by_iface) cliPrintf("  %s %d", kv.first.c_str(), kv.second);
    cliPrintf("\n  by hops: ");
    for (auto& kv : by_hops)  cliPrintf("  %d:%d", kv.first, kv.second);
    cliPrintf("\n");

    if (summary || rows.empty()) return;

    int to_show = show_all ? (int)rows.size() : std::min((int)rows.size(), limit);
    if (to_show < (int)rows.size())
        cliPrintf("\n  (showing %d of %d, use -a or -n N for more)\n", to_show, (int)rows.size());
    cliPrintf("\n  %-32s %-32s %-16s %-5s %-8s\n",
              "destination", "next hop", "iface", "hops", "age");

    double now = RNS::Utilities::OS::time();
    for (int n = 0; n < to_show; n++) {
        cliPrintf("  %-32s %-32s %-16s %-5d %lus\n",
                  rows[n].dest.c_str(),
                  rows[n].next_hop.c_str(),
                  rows[n].iface.c_str(),
                  rows[n].hops,
                  (unsigned long)(now - rows[n].timestamp));
    }
}

/* ─────────────── rnstatus ─────────────── */

static std::string formatBytes(uint64_t b)
{
    char buf[24];
    if      (b < 1024ULL)              snprintf(buf, sizeof(buf), "%llu B",   (unsigned long long)b);
    else if (b < 1024ULL*1024)         snprintf(buf, sizeof(buf), "%.1f KiB", (double)b / 1024.0);
    else if (b < 1024ULL*1024*1024)    snprintf(buf, sizeof(buf), "%.1f MiB", (double)b / (1024.0*1024.0));
    else                               snprintf(buf, sizeof(buf), "%.2f GiB", (double)b / (1024.0*1024.0*1024.0));
    return buf;
}

static std::string formatBitrate(uint32_t bps)
{
    char buf[24];
    if      (bps < 1000)               snprintf(buf, sizeof(buf), "%u bps",    (unsigned)bps);
    else if (bps < 1000000)            snprintf(buf, sizeof(buf), "%.1f kbps", (double)bps / 1000.0);
    else                               snprintf(buf, sizeof(buf), "%.1f Mbps", (double)bps / 1000000.0);
    return buf;
}

static int countActiveIfaces(void)
{
    int n = 0;
    for (int j = 0; j < RNSD_MAX_IFACES; j++) if (s_ifaces[j].used) n++;
    return n;
}

static bool ifaceMatchesFilter(const iface_t& i, const std::string& filter)
{
    if (filter.empty()) return true;
    return strstr(i.info.name, filter.c_str()) != nullptr;
}

static void rnstatusHeader(void)
{
    bool tx_en = storageGetInt("s.rnsd.transport_enabled", 0) != 0;
    if (s_identity) cliPrintf("Reticulum transport instance %s\n", s_identity->hexhash().c_str());
    else            cliPrintf("Reticulum (no identity)\n");
    cliPrintf("  Transport    %s\n", tx_en ? "enabled" : "disabled");
    cliPrintf("  Interfaces   %d up\n", countActiveIfaces());
}

static void rnstatusPrintIface(const iface_t& i)
{
    cliPrintf("\n%s\n", i.info.name);
    cliPrintf("  Status       up\n");
    cliPrintf("  Mode         %s\n", mode_name(i.info.mode));
    cliPrintf("  MTU          %u\n", (unsigned)i.info.mtu);
    cliPrintf("  Bitrate      %s\n", formatBitrate(i.info.bitrate).c_str());
    cliPrintf("  Traffic      %s in / %s out  (%llu pkt in / %llu out)\n",
              formatBytes(i.rx_bytes).c_str(),
              formatBytes(i.tx_bytes).c_str(),
              (unsigned long long)i.rx_packets,
              (unsigned long long)i.tx_packets);
}

static void rnstatusPrintTotals(void)
{
    cliPrintf("\nTotals\n");
    cliPrintf("  Packets      %llu in / %llu out\n",
              (unsigned long long)s_stats.packets_in,
              (unsigned long long)s_stats.packets_out);
    cliPrintf("  Bytes        %s in / %s out\n",
              formatBytes(s_stats.bytes_in).c_str(),
              formatBytes(s_stats.bytes_out).c_str());
}

static void rnstatusJson(const std::string& filter)
{
    cJSON* root = cJSON_CreateObject();
    if (s_identity) cJSON_AddStringToObject(root, "identity", s_identity->hexhash().c_str());
    cJSON_AddBoolToObject(root, "transport_enabled",
                          storageGetInt("s.rnsd.transport_enabled", 0) != 0);

    cJSON* arr = cJSON_CreateArray();
    for (int j = 0; j < RNSD_MAX_IFACES; j++) {
        auto& i = s_ifaces[j];
        if (!i.used) continue;
        if (!ifaceMatchesFilter(i, filter)) continue;
        cJSON* o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", i.info.name);
        cJSON_AddStringToObject(o, "mode", mode_name(i.info.mode));
        cJSON_AddNumberToObject(o, "mtu", i.info.mtu);
        cJSON_AddNumberToObject(o, "bitrate", i.info.bitrate);
        cJSON_AddNumberToObject(o, "rx_packets", (double)i.rx_packets);
        cJSON_AddNumberToObject(o, "tx_packets", (double)i.tx_packets);
        cJSON_AddNumberToObject(o, "rx_bytes",   (double)i.rx_bytes);
        cJSON_AddNumberToObject(o, "tx_bytes",   (double)i.tx_bytes);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "ifaces", arr);

    cJSON* st = cJSON_CreateObject();
    cJSON_AddNumberToObject(st, "packets_in",    (double)s_stats.packets_in);
    cJSON_AddNumberToObject(st, "packets_out",   (double)s_stats.packets_out);
    cJSON_AddNumberToObject(st, "bytes_in",      (double)s_stats.bytes_in);
    cJSON_AddNumberToObject(st, "bytes_out",     (double)s_stats.bytes_out);
    cJSON_AddItemToObject(root, "stats", st);

    char* text = cJSON_PrintUnformatted(root);
    if (text) { cliPrintf("%s\n", text); cJSON_free(text); }
    cJSON_Delete(root);
}

static void cliRnstatus(const char* args)
{
    std::string filter;
    bool show_totals = false;
    bool json        = false;
    bool show_help   = false;

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            while (i < a.size() && (a[i] == ' ' || a[i] == '\t')) i++;
            if (i >= a.size()) break;
            size_t s = i;
            while (i < a.size() && a[i] != ' ' && a[i] != '\t') i++;
            std::string t = a.substr(s, i - s);
            if      (t == "help")                  show_help = true;
            else if (t == "-t" || t == "--totals") show_totals = true;
            else if (t == "-j" || t == "--json")   json = true;
            else if (!t.empty() && t[0] != '-')    filter = t;
            else {
                cliPrintf("unknown option: %s\n", t.c_str());
                cliPrintf("usage: rnstatus [filter] [-t] [-j]\n");
                return;
            }
        }
    }

    if (show_help) {
        cliPrintf("  %-*s interfaces & traffic\n",
                  CLI_HELP_COL, "rnstatus [filter]");
        cliPrintf("    -t  --totals  global traffic totals\n");
        cliPrintf("    -j  --json    JSON output\n");
        return;
    }

    if (json) { rnstatusJson(filter); return; }

    rnstatusHeader();

    if (show_totals) { rnstatusPrintTotals(); return; }

    for (int j = 0; j < RNSD_MAX_IFACES; j++) {
        auto& i = s_ifaces[j];
        if (!i.used) continue;
        if (!ifaceMatchesFilter(i, filter)) continue;
        rnstatusPrintIface(i);
    }
}

/* ─────────────── rnprobe ─────────────── */

#define RNPROBE_DEFAULT_SIZE     32
#define RNPROBE_DEFAULT_TIMEOUT  15

/* rnprobe is a client of RNSD_PORT_PACKET. CLI task opens an ITS connection
 * with the target dest + aspect in the connect payload, sends the probe
 * payload bytes, blocks on itsRecv waiting for a 6-byte result, prints,
 * disconnects. All mR Packet work runs on rnsd's task — cross-task ITS
 * boundaries clean. */
static void cliRnprobe(const char* args)
{
    std::string aspect, hash_hex;
    int  size      = RNPROBE_DEFAULT_SIZE;
    int  probes    = 1;
    int  timeout   = RNPROBE_DEFAULT_TIMEOUT;
    int  wait      = 1;
    bool show_help = false;
    int  positional = 0;

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            std::string t = rnpathNextToken(a, &i);
            if (t.empty()) break;
            if      (t == "help")                    show_help = true;
            else if (t == "-s" || t == "--size")     size    = atoi(rnpathNextToken(a, &i).c_str());
            else if (t == "-n" || t == "--probes")   probes  = atoi(rnpathNextToken(a, &i).c_str());
            else if (t == "-t" || t == "--timeout")  timeout = atoi(rnpathNextToken(a, &i).c_str());
            else if (t == "-w" || t == "--wait")     wait    = atoi(rnpathNextToken(a, &i).c_str());
            else if (!t.empty() && t[0] != '-') {
                if      (positional == 0) aspect   = t;
                else if (positional == 1) hash_hex = t;
                positional++;
            } else {
                cliPrintf("unknown option: %s\n", t.c_str());
                cliPrintf("usage: rnprobe [aspect] <destination_hash> [-s N] [-n N] [-t S] [-w S]\n");
                return;
            }
        }
    }
    (void)wait;

    /* Single-positional shortcut: a 32-char all-hex string is the hash;
     * default aspect to the conventional transport management endpoint. */
    auto isHexHash = [](const std::string& s) {
        if (s.size() != (size_t)RNS::Type::Reticulum::DESTINATION_LENGTH * 2) return false;
        for (char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    };
    if (hash_hex.empty() && isHexHash(aspect)) {
        hash_hex = aspect;
        aspect   = "rnstransport.remote.management";
    }

    if (show_help || aspect.empty() || hash_hex.empty()) {
        cliPrintf("  %-*s probe destination, measure RTT\n",
                  CLI_HELP_COL, "rnprobe [aspect] <hash>");
        cliPrintf("    aspect    default: rnstransport.remote.management\n");
        cliPrintf("    -s SIZE   payload bytes (default %d)\n", RNPROBE_DEFAULT_SIZE);
        cliPrintf("    -n N      probe count (only 1 supported for now)\n");
        cliPrintf("    -t SECS   timeout (default %d)\n", RNPROBE_DEFAULT_TIMEOUT);
        cliPrintf("    -w SECS   interval between probes\n");
        return;
    }
    if (probes > 1)
        cliPrintf("rnprobe: -n > 1 not yet implemented; sending one probe\n");

    /* Validate hash early so we can give a clean error before opening ITS. */
    RNS::Bytes dh;
    dh.assignHex((const uint8_t*)hash_hex.c_str(), hash_hex.size());
    if (dh.size() != RNS::Type::Reticulum::DESTINATION_LENGTH) {
        cliPrintf("rnprobe: bad hash length (need %u bytes)\n",
                  (unsigned)RNS::Type::Reticulum::DESTINATION_LENGTH);
        return;
    }

    /* has_path + request_path happen inside rnsd's onPacketConnect — those
     * touch mR state and need to run on rnsd's task to avoid the cross-task
     * itsSend failure (request_path's outbound would otherwise silently
     * drop). If rejected, the ITS_LOGE / err() lines tell the story. */

    /* Build connect payload. identity_key empty → rnsd uses its own. */
    rnsd_packet_connect_t req = {};
    memcpy(req.dest_hash, dh.data(), 16);
    safeStrncpy(req.aspect, aspect.c_str(), sizeof(req.aspect));
    req.dest_type = 0;   /* SINGLE */

    int handle = itsConnect("rnsd", RNSD_PORT_PACKET,
                            &req, sizeof(req), pdMS_TO_TICKS(2000));
    if (handle < 0) {
        cliPrintf("rnprobe: connect to rnsd failed\n");
        return;
    }

    if (size < 0)   size = 0;
    if (size > 400) size = 400;
    std::vector<uint8_t> payload(size, 0);

    if (itsSend(handle, payload.data(), payload.size(), pdMS_TO_TICKS(1000)) == 0) {
        cliPrintf("rnprobe: send failed\n");
        itsDisconnect(handle);
        return;
    }

    std::string short_hash = hash_hex.substr(0, 16);
    cliPrintf("probing %s (%d B, %ds timeout)...\n",
              short_hash.c_str(), size, timeout);

    /* Block waiting for the 6-byte result. App-side timeout = mR timeout
     * + small slack so we can pick up "timeout" status rather than aborting
     * the wait ourselves. */
    uint8_t result[6];
    size_t got = itsRecv(handle, result, sizeof(result),
                         pdMS_TO_TICKS((timeout + 2) * 1000));
    itsDisconnect(handle);

    if (got == 0) {
        cliPrintf("rnprobe: no response from rnsd (CLI timeout)\n");
        return;
    }
    if (got < 6) {
        cliPrintf("rnprobe: short response (%zu B)\n", got);
        return;
    }
    uint8_t  status  = result[0];
    uint32_t rtt_ms  = ((uint32_t)result[1] << 24) | ((uint32_t)result[2] << 16)
                     | ((uint32_t)result[3] <<  8) |  (uint32_t)result[4];
    uint8_t  hops    = result[5];

    switch (status) {
        case PACKET_RESULT_DELIVERY:
            cliPrintf("reply from %s: rtt=%u ms hops=%u\n",
                      short_hash.c_str(), (unsigned)rtt_ms, (unsigned)hops);
            break;
        case PACKET_RESULT_TIMEOUT:
            cliPrintf("timeout to %s\n", short_hash.c_str());
            break;
        case PACKET_RESULT_NO_PATH:
            cliPrintf("no path to %s — path request issued, try again shortly\n",
                      hash_hex.c_str());
            break;
        case PACKET_RESULT_NO_IDENTITY:
            cliPrintf("identity for %s not cached — path request issued, try again shortly\n",
                      hash_hex.c_str());
            break;
        case PACKET_RESULT_DEST_ERROR:
            cliPrintf("rnprobe: destination construct failed (aspect=%s)\n", aspect.c_str());
            break;
        case PACKET_RESULT_NO_SENDER_ID:
            cliPrintf("rnprobe: no sender identity at storage key\n");
            break;
        case PACKET_RESULT_SEND_FAILED:
            cliPrintf("rnprobe: send failed (no interfaces accepted the packet)\n");
            break;
        default:
            cliPrintf("rnprobe: unknown status %u\n", (unsigned)status);
            break;
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

    if (!itsServerPortOpen(RNSD_PORT_PACKET, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_PACKET_CONNS,
                           /*toSize=*/2048, /*fromSize=*/512)) {
        err("RNSD_PORT_PACKET open failed");
        vTaskDelete(nullptr);
        return;
    }
    itsServerOnConnect(RNSD_PORT_PACKET,    onPacketConnect);
    itsServerOnDisconnect(RNSD_PORT_PACKET, onPacketDisconnect);
    itsServerOnRecv(RNSD_PORT_PACKET,       onPacketRecv);

    loadOrCreateIdentity();
    storageSet("rnsd.up", 1);
    if (s_identity) storageSet("rnsd.identity_hash", s_identity->hexhash().c_str());

    /* Bump mR's identity cache from 100 → 1000 entries (~200 KiB PSRAM).
     * 100 is too small for busy testnet traffic — entries get evicted before
     * we have a chance to probe them, even though the path table still has
     * the route. Identity::recall then fails and rnprobe can't proceed. */
    RNS::Identity::known_destinations_maxsize(1000);

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

        s_announce_logger = std::make_shared<AnnounceDebugLogger>();
        RNS::Transport::register_announce_handler(s_announce_logger);
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
    /* PSRAM-place the iface and packet-connection tables. RNS::Interface /
     * RNS::Destination / RNS::Identity have non-trivial ctors — placement-
     * new each slot. */
    s_ifaces = (iface_t*)heap_caps_malloc(RNSD_MAX_IFACES * sizeof(iface_t), MALLOC_CAP_SPIRAM);
    if (!s_ifaces) { err("s_ifaces PSRAM alloc failed"); return; }
    for (int j = 0; j < RNSD_MAX_IFACES; j++) new (&s_ifaces[j]) iface_t{};

    s_packet_conns = (packet_conn_t*)heap_caps_malloc(
        RNSD_MAX_PACKET_CONNS * sizeof(packet_conn_t), MALLOC_CAP_SPIRAM);
    if (!s_packet_conns) { err("s_packet_conns PSRAM alloc failed"); return; }
    for (int j = 0; j < RNSD_MAX_PACKET_CONNS; j++) new (&s_packet_conns[j]) packet_conn_t{};

    /* One-time storage defaults gated on version. */
    if (storageGetInt("s.rnsd.version", 0) < RNSD_VERSION) {
        storageDefault("s.rnsd.enable", 1);
        storageDefault("s.rnsd.transport_enabled", 0);
        storageDefault("s.rnsd.name", "");
        storageDefault("s.rnsd.announce.interval", 1800);   /* 30 min */
        /* `s.rnsd.path.max` / `s.rnsd.path.ttl` removed: mR's path table is
         * unbounded (BasicHeapStore), pruned only by PATHFINDER_E (24 h).
         * Re-add when we implement post-process pruning or interface-mode
         * intake control. */
        storageSet("s.rnsd.version", RNSD_VERSION);
    }

    cliRegisterCmd("rnsd",     cliRnsd);
    cliRegisterCmd("rnstatus", cliRnstatus);
    cliRegisterCmd("rnpath",   cliRnpath);
    cliRegisterCmd("rnprobe",  cliRnprobe);

    /* Cron line per §11.3 — no-op when transport disabled, hourly otherwise. */
    cronDefault("0 * * * * N", "rnsd persist if-transport");

    /* PSRAM stack, core 0 alongside tcpip_thread, prio 2. */
    s_task = spawnTask(rnsdTaskMain, TAG, 12288, nullptr, 2, 0, STACK_PSRAM);
}
