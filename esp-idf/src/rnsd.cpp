/**
 * rnsd — RNS protocol task.
 *
 * Phase 1 scope: identity load/generate, RNSD_PORT_TRANSPORT server,
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
#include "Destination.h"
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

static std::string formatAnnounceAppData(const RNS::Bytes& app_data);

/* Cached `s.rnsd.debug.only_local` — when true, the dbg() lines that
 * describe announces (everyone's traffic) are demoted to verb() so
 * they only show at log level verbose. dbg-level then surfaces just
 * the traffic that affects this node directly. Live-mirrored from
 * storage via subscription, so writes take effect immediately. */
static bool s_dbg_only_local = false;

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
    TaskInterface(const rnsd_transport_t& info, int handle) : _handle(handle) {
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
    rnsd_transport_t info;
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

/* ─────────────── RNSD_PORT_DEST state ───────────────
 *
 * Per-connection state for the bidirectional destination API. Apps
 * open via rnsdDestOpen() (rnsd.h), which sends an rnsd_dest_connect_t
 * — defined privately here since no consumer constructs one. rnsd:
 *   - loads the identity, registers a SINGLE-IN Destination on that
 *     aspect (mR's Destination ctor auto-registers with Transport),
 *   - sets a packet callback that fans inbound plaintexts to the
 *     matching handle as 0x04 IN_PACKET frames,
 *   - parses 0x01 OUT_PACKET frames; if a path is known sends
 *     immediately and emits 0x02 OUT_RESULT status=sent; if no path,
 *     emits 0x05 OUT_STATUS REQUESTING_PATH, requests the path, and
 *     parks the send for the periodic walker to retry.
 *
 * One pending send slot per conn keeps the state machine bounded for
 * Phase 4a. The lxmf task throttles its own OUT_PACKET cadence via the
 * stage-driven lifecycle. */

/* Connect payload for RNSD_PORT_DEST — rnsd-private. Consumers go
 * through rnsdDestOpen(), which fills this from typed args. Fixed size
 * (≤ ITS_MAX_MSG_DATA) so it fits in the itsConnect aux slot. */
typedef struct {
    char    aspect[32];          /* "lxmf.delivery", "rnprobe", … */
    char    identity_key[40];    /* storage path of 128-hex private key; empty → default */
    uint8_t dest_type;           /* 0=SINGLE, 1=PLAIN, 2=GROUP */
} rnsd_dest_connect_t;
static_assert(sizeof(rnsd_dest_connect_t) <= ITS_MAX_MSG_DATA,
              "rnsd_dest_connect_t must fit ITS_MAX_MSG_DATA");

#define RNSD_MAX_MAILBOX_CONNS    4

/* Length-checked inbound buffer for the IN destination dispatcher. RNS
 * MTU is 500 — 600 covers framing slack. */
#define RNSD_MAILBOX_INBOUND_MAX  600

struct mailbox_pending_t {
    bool                 used;
    uint16_t             send_id;
    std::vector<uint8_t> bytes;          /* full LXM wire (incl. 16B target hash prefix) */
    double               first_seen_at;  /* mR time stamp */
    double               last_request_path_at;
    int                  attempts;       /* RETRY frames emitted so far */
};

struct mailbox_conn_t {
    bool                       used;
    int                        handle;
    rnsd_dest_connect_t     req;

    /* Listener identity + IN destination — built in onMailboxConnect.
     * Empty (Type::NONE) on failure; that conn drops all OUT/IN traffic
     * silently with err() logged. */
    RNS::Identity              listener_identity{RNS::Type::NONE};
    RNS::Destination           listener_dest{RNS::Type::NONE};
    RNS::Bytes                 listener_hash;          /* for inbound dispatch lookup */

    mailbox_pending_t          pending;                /* one in-flight at a time */
};

static mailbox_conn_t* s_mailbox_conns = nullptr;

/* Retry / path-request cadence. RNS PATH_REQUEST_WAIT is 7s; we pace our
 * own RETRY emissions a little behind that to avoid stepping on it. */
#define RNSD_MAILBOX_PATH_RETRY_INTERVAL_S   8.0

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

/* Monotonic counter bumped on every iface up-transition. Consumers
 * (e.g. lxmf) subscribe to this single key to learn "an iface just
 * came online" without having to subscribe broadly under
 * `rnsd.ifaces.` (which would also fire on every 1 Hz stats update).
 * Wraps after 4 billion events; subscribers compare by inequality
 * (or just react), never by absolute value. */
static int s_iface_event_seq = 0;

/* ─────────────── remote-management announce ───────────────
 *
 * Conventional Reticulum probe endpoint on aspect
 * `rnstransport.remote.management`, hosted on this node's transport
 * identity. Construct + register with Transport when
 * `s.rnsd.remote_management != 0`; deregister when flipped off. Same
 * 10 s debounce-after-iface-up + periodic schedule as lxmf's
 * announces.
 *
 * State lives here (above publishIfaceUp) so the iface-up debounce
 * arm fits inline; the helpers (Up/Down/sendAnnounce) are defined
 * lower alongside the rest of the protocol plumbing.
 *
 * No packet callback yet — inbound probes silently land at the
 * destination and get dropped. Probe-reply is a separate change. */
static RNS::Destination s_management_dest{RNS::Type::NONE};
/* Probe responder. When `s.rnsd.respond_to_probes != 0` we host an
 * IN/SINGLE destination at aspect `rnstransport.probe` with
 * accepts_links(false) + PROVE_ALL — same shape as upstream rnsd. mR
 * auto-proves every DATA packet that reaches the destination, so
 * `rnprobe` from a peer round-trips at the protocol level (no
 * application code involved). */
static RNS::Destination s_probe_dest{RNS::Type::NONE};
static TickType_t       s_rnsd_announce_due_tick  = 0;
static TickType_t       s_rnsd_last_announce_tick = 0;
#define RNSD_ANNOUNCE_DEBOUNCE_MS 10000

static void publishIfaceUp(const iface_t& i)
{
    char key[80];
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.up", i.info.name);          storageSet(key, 1);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.mtu", i.info.name);         storageSet(key, (int)i.info.mtu);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.bitrate", i.info.name);     storageSet(key, (int)i.info.bitrate);
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.mode", i.info.name);        storageSet(key, mode_name(i.info.mode));
    storageSet("rnsd.iface_event_seq", ++s_iface_event_seq);
    /* If we're hosting any rnsd-side destination (management and/or
     * probe), (re)arm the announce debounce. Same 10 s rate-limit
     * shape as lxmf's. */
    if (s_management_dest || s_probe_dest) {
        s_rnsd_announce_due_tick = xTaskGetTickCount() +
            pdMS_TO_TICKS(RNSD_ANNOUNCE_DEBOUNCE_MS);
    }
}

static void publishIfaceDown(const iface_t& i)
{
    char key[80];
    snprintf(key, sizeof(key), "rnsd.ifaces.%s.up", i.info.name); storageSet(key, 0);
}

/* ─────────────── ITS callbacks ─────────────── */

static int onTransportConnect(int handle, const void* data, size_t len)
{
    if (len < sizeof(rnsd_transport_t)) {
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
    memcpy(&slot->info, data, sizeof(rnsd_transport_t));
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

static void onTransportDisconnect(int ref)
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

static void onTransportRecv(int handle, size_t /*bytesAvail*/)
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

/* ─────────────── RNSD_PORT_DEST handlers ─────────────── */

static mailbox_conn_t* mailboxFindByHandle(int handle)
{
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++)
        if (s_mailbox_conns[j].used && s_mailbox_conns[j].handle == handle) return &s_mailbox_conns[j];
    return nullptr;
}

static mailbox_conn_t* mailboxFindByDestHash(const RNS::Bytes& h)
{
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++) {
        mailbox_conn_t& c = s_mailbox_conns[j];
        if (c.used && c.listener_hash == h) return &c;
    }
    return nullptr;
}

static mailbox_conn_t* mailboxAlloc(void)
{
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++)
        if (!s_mailbox_conns[j].used) return &s_mailbox_conns[j];
    return nullptr;
}

/* Frame helpers. Headers are small; we stack-allocate. */

static void mailboxSendOutResult(mailbox_conn_t& c, uint16_t send_id,
                                 uint8_t status, uint32_t rtt_ms, uint8_t hops)
{
    uint8_t f[9];
    f[0] = RNSD_DEST_OUT_RESULT;
    f[1] = (uint8_t)(send_id >> 8);
    f[2] = (uint8_t)(send_id & 0xFF);
    f[3] = status;
    f[4] = (uint8_t)((rtt_ms >> 24) & 0xFF);
    f[5] = (uint8_t)((rtt_ms >> 16) & 0xFF);
    f[6] = (uint8_t)((rtt_ms >>  8) & 0xFF);
    f[7] = (uint8_t)( rtt_ms        & 0xFF);
    f[8] = hops;
    if (itsSend(c.handle, f, sizeof(f), pdMS_TO_TICKS(100)) == 0)
        warn("mailbox: OUT_RESULT send dropped (send_id=%u)", (unsigned)send_id);
}

static void mailboxSendOutStatusBare(mailbox_conn_t& c, uint16_t send_id, uint8_t type)
{
    uint8_t f[4];
    f[0] = RNSD_DEST_OUT_STATUS;
    f[1] = (uint8_t)(send_id >> 8);
    f[2] = (uint8_t)(send_id & 0xFF);
    f[3] = type;
    if (itsSend(c.handle, f, sizeof(f), pdMS_TO_TICKS(100)) == 0)
        warn("mailbox: OUT_STATUS send dropped (send_id=%u type=0x%02x)",
             (unsigned)send_id, (unsigned)type);
}

static void mailboxSendOutStatusRetry(mailbox_conn_t& c, uint16_t send_id,
                                      uint8_t attempt, uint8_t reason)
{
    uint8_t f[6];
    f[0] = RNSD_DEST_OUT_STATUS;
    f[1] = (uint8_t)(send_id >> 8);
    f[2] = (uint8_t)(send_id & 0xFF);
    f[3] = RNSD_DEST_AUX_RETRY;
    f[4] = attempt;
    f[5] = reason;
    if (itsSend(c.handle, f, sizeof(f), pdMS_TO_TICKS(100)) == 0)
        warn("mailbox: OUT_STATUS RETRY send dropped");
}

static void mailboxClearPending(mailbox_conn_t& c)
{
    c.pending.used = false;
    c.pending.bytes.clear();
}

/* Try to send `bytes` (LXM wire) on c's connection. The first 16 bytes are
 * the target dest_hash. Returns:
 *   1  — sent: OUT_STATUS EGRESS_QUEUED + OUT_RESULT status=sent emitted
 *   0  — pending: REQUESTING_PATH emitted, send is parked
 *  -1  — terminal failure (recall/Destination/send threw): OUT_RESULT
 *        status=evicted emitted */
static int mailboxTrySend(mailbox_conn_t& c, uint16_t send_id,
                          const uint8_t* bytes, size_t n)
{
    if (n < 16) {
        err("mailbox: OUT_PACKET too short (%zu)", n);
        mailboxSendOutResult(c, send_id, RNSD_DEST_STATUS_EVICTED, 0, 0);
        return -1;
    }

    RNS::Bytes dh(bytes, 16);

    if (!RNS::Transport::has_path(dh)) {
        info("mailbox: send_id=%u requesting path for %s (no entry)",
             (unsigned)send_id, dh.toHex().c_str());
        try { RNS::Transport::request_path(dh); }
        catch (const std::exception& e) { warn("mailbox: request_path threw: %s", e.what()); }
        mailboxSendOutStatusBare(c, send_id, RNSD_DEST_AUX_REQUESTING_PATH);
        return 0;
    }

    RNS::Identity target = RNS::Identity::recall(dh);
    if (!target) {
        info("mailbox: send_id=%u requesting path for %s (have path, no identity)",
             (unsigned)send_id, dh.toHex().c_str());
        try { RNS::Transport::request_path(dh); }
        catch (const std::exception& e) { warn("mailbox: request_path threw: %s", e.what()); }
        mailboxSendOutStatusBare(c, send_id, RNSD_DEST_AUX_REQUESTING_PATH);
        return 0;
    }

    /* Construct OUT destination on the same aspect as the listener. mR's
     * Destination ctor splits the aspect string at the first dot into
     * `app_name` + remaining aspects. */
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
        RNS::Destination out_dest(target, RNS::Type::Destination::OUT, dtype,
                                  app_name.c_str(), aspects.c_str());
        /* Opportunistic LXMF wire on the network strips the leading 16-byte
         * destination hash; the recipient prepends `packet.destination.hash`
         * back before parsing the LXM wire. See LXMF reference
         * LXMessage.__packed_packet() / LXMRouter.delivery_packet(). The
         * incoming `bytes` here is the full wire `dest || src || sig ||
         * packed` (n >= 16 already gated above); send `bytes + 16` as the
         * RNS Packet payload. */
        RNS::Bytes payload(bytes + 16, n - 16);
        RNS::Packet pkt(out_dest, payload);
        uint8_t hops = (uint8_t)RNS::Transport::hops_to(dh);
        RNS::PacketReceipt receipt = pkt.send();
        if (!receipt) {
            warn("mailbox: pkt.send() returned no receipt");
            mailboxSendOutResult(c, send_id, RNSD_DEST_STATUS_EVICTED, 0, 0);
            return -1;
        }
        mailboxSendOutStatusBare(c, send_id, RNSD_DEST_AUX_EGRESS_QUEUED);
        /* Opportunistic: there is no native ack, so we promote "sent" the
         * moment Transport accepted the packet. See lxmf.md §15. */
        mailboxSendOutResult(c, send_id, RNSD_DEST_STATUS_SENT, 0, hops);
        info("mailbox: send_id=%u sent to %s (hops=%u, %zuB payload)",
             (unsigned)send_id, dh.toHex().c_str(), (unsigned)hops, n);
        return 1;
    } catch (const std::exception& e) {
        err("mailbox: send threw: %s", e.what());
        mailboxSendOutResult(c, send_id, RNSD_DEST_STATUS_EVICTED, 0, 0);
        return -1;
    }
}

/* mR's packet callback for incoming LXM-style packets on any listener
 * destination. We don't get a user-data slot, so the dispatcher walks
 * the conn table comparing destination hashes. */
static void onMailboxInbound(const RNS::Bytes& plaintext, const RNS::Packet& packet)
{
    mailbox_conn_t* c = mailboxFindByDestHash(packet.destination().hash());
    if (!c) {
        info("mailbox inbound: no conn for dest %s (%zuB plaintext)",
             packet.destination().hash().toHex().c_str(), plaintext.size());
        return;
    }
    /* Opportunistic LXMF wire on the network omits the leading 16-byte
     * destination hash; reconstruct the full LXM wire by prepending our
     * own destination hash (the IN destination that received this packet)
     * before handing off to the consumer. Symmetric with the strip done
     * in mailboxTrySend. See LXMF LXMRouter.delivery_packet(). */
    if (plaintext.size() + 1 + 16 > RNSD_MAILBOX_INBOUND_MAX) {
        warn("mailbox inbound: oversize plaintext %zu B (dropping)", plaintext.size());
        return;
    }
    info("mailbox inbound: %zuB for dest %s → handle=%d",
         plaintext.size(), packet.destination().hash().toHex().c_str(), c->handle);
    uint8_t f[RNSD_MAILBOX_INBOUND_MAX];
    f[0] = RNSD_DEST_IN_PACKET;
    memcpy(f + 1,      packet.destination().hash().data(), 16);
    memcpy(f + 1 + 16, plaintext.data(), plaintext.size());
    if (itsSend(c->handle, f, 1 + 16 + plaintext.size(), pdMS_TO_TICKS(100)) == 0)
        warn("mailbox inbound: ITS send dropped (%zu B)", plaintext.size());
}

static int onMailboxConnect(int handle, const void* data, size_t len)
{
    if (len != sizeof(rnsd_dest_connect_t)) {
        err("mailbox connect: bad payload len %zu (want %zu)",
            len, sizeof(rnsd_dest_connect_t));
        return -1;
    }
    mailbox_conn_t* slot = mailboxAlloc();
    if (!slot) { err("mailbox connect: no slots"); return -1; }

    slot->used   = true;
    slot->handle = handle;
    memcpy(&slot->req, data, sizeof(rnsd_dest_connect_t));
    slot->req.aspect[sizeof(slot->req.aspect) - 1] = '\0';
    slot->req.identity_key[sizeof(slot->req.identity_key) - 1] = '\0';
    slot->listener_identity = RNS::Identity(RNS::Type::NONE);
    slot->listener_dest     = RNS::Destination(RNS::Type::NONE);
    slot->listener_hash     = RNS::Bytes();
    slot->pending           = mailbox_pending_t{};

    /* Load listener identity. */
    const char* key = slot->req.identity_key[0] ? slot->req.identity_key : "secrets.rnsd.identity";
    char hex[160] = {};
    storageGetStr(key, hex, sizeof(hex), "");
    if (strlen(hex) != 128) {
        err("mailbox connect: no identity at %s — accepting outbound-only mode", key);
        info("mailbox conn %d open: aspect=%s outbound-only",
             (int)(slot - s_mailbox_conns), slot->req.aspect);
        return (int)(slot - s_mailbox_conns);
    }
    RNS::Bytes prv;
    prv.assignHex((const uint8_t*)hex, 128);
    if (prv.size() != 64) {
        err("mailbox connect: bad identity hex at %s", key);
        return (int)(slot - s_mailbox_conns);
    }
    RNS::Identity id(false);
    if (!id.load_private_key(prv)) {
        err("mailbox connect: identity load failed for %s", key);
        return (int)(slot - s_mailbox_conns);
    }

    /* Split aspect into app_name + remaining. */
    std::string aspect = slot->req.aspect;
    std::string app_name = aspect, aspects;
    auto dot = aspect.find('.');
    if (dot != std::string::npos) {
        app_name = aspect.substr(0, dot);
        aspects  = aspect.substr(dot + 1);
    }
    RNS::Type::Destination::types dtype = RNS::Type::Destination::SINGLE;
    if      (slot->req.dest_type == 1) dtype = RNS::Type::Destination::PLAIN;
    else if (slot->req.dest_type == 2) dtype = RNS::Type::Destination::GROUP;

    try {
        RNS::Destination d(id, RNS::Type::Destination::IN, dtype,
                           app_name.c_str(), aspects.c_str());
        /* Phase A of docs/plans/link.md §4.3: mR defaults
         * Destination::_accept_link_requests to true. Until Phase D's
         * RNSD_DEST_LINK_LISTEN aux flips it back on per-consumer, every
         * IN destination must explicitly refuse Link requests — otherwise
         * inbound LRs spawn Link objects with no callbacks attached. */
        d.accepts_links(false);
        d.set_packet_callback(onMailboxInbound);
        slot->listener_identity = id;
        slot->listener_dest     = d;
        slot->listener_hash     = d.hash();
        info("mailbox conn %d open: aspect=%s identity=%s dest=%s",
             (int)(slot - s_mailbox_conns), slot->req.aspect,
             id.hexhash().c_str(), d.hash().toHex().c_str());
    } catch (const std::exception& e) {
        err("mailbox connect: Destination ctor threw: %s", e.what());
    }

    return (int)(slot - s_mailbox_conns);
}

static void onMailboxDisconnect(int ref)
{
    if (ref < 0 || ref >= RNSD_MAX_MAILBOX_CONNS) return;
    mailbox_conn_t& c = s_mailbox_conns[ref];
    if (!c.used) return;
    info("mailbox conn %d close (dest=%s)", ref,
         c.listener_hash ? c.listener_hash.toHex().c_str() : "-");
    if (c.listener_dest) {
        try { RNS::Transport::deregister_destination(c.listener_dest); }
        catch (const std::exception& e) { warn("deregister_destination threw: %s", e.what()); }
    }
    c.used   = false;
    c.handle = -1;
    c.listener_identity = RNS::Identity(RNS::Type::NONE);
    c.listener_dest     = RNS::Destination(RNS::Type::NONE);
    c.listener_hash     = RNS::Bytes();
    c.pending = mailbox_pending_t{};
}

static void onMailboxRecv(int handle, size_t /*bytesAvail*/)
{
    mailbox_conn_t* c = mailboxFindByHandle(handle);
    if (!c) return;
    static uint8_t buf[1 + RNSD_MAILBOX_INBOUND_MAX];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (n == 0) return;

    uint8_t op = buf[0];
    switch (op) {
        case RNSD_DEST_OUT_PACKET: {
            if (n < 3 + 16) {
                err("mailbox: OUT_PACKET too short (%zu)", n);
                return;
            }
            uint16_t send_id = ((uint16_t)buf[1] << 8) | (uint16_t)buf[2];
            const uint8_t* lxm = buf + 3;
            size_t lxm_n = n - 3;
            int r = mailboxTrySend(*c, send_id, lxm, lxm_n);
            if (r == 0) {
                /* Park for the periodic walker. One slot per conn — if
                 * something else is parked, the lxmf task is supposed to
                 * pace itself; we still take this one (lifo) to keep the
                 * latest in flight. */
                if (c->pending.used)
                    warn("mailbox: dropping previous pending send_id=%u for new send_id=%u",
                         (unsigned)c->pending.send_id, (unsigned)send_id);
                c->pending.used    = true;
                c->pending.send_id = send_id;
                c->pending.bytes.assign(lxm, lxm + lxm_n);
                c->pending.first_seen_at        = RNS::Utilities::OS::time();
                c->pending.last_request_path_at = c->pending.first_seen_at;
                c->pending.attempts             = 0;
            }
            break;
        }
        case RNSD_DEST_OUT_CANCEL: {
            if (n < 3) { err("mailbox: OUT_CANCEL too short (%zu)", n); return; }
            uint16_t send_id = ((uint16_t)buf[1] << 8) | (uint16_t)buf[2];
            if (c->pending.used && c->pending.send_id == send_id) {
                mailboxClearPending(*c);
                mailboxSendOutResult(*c, send_id, RNSD_DEST_STATUS_CANCELLED, 0, 0);
            } else {
                /* Not parked — already terminal. Send a synthetic
                 * cancelled so the client's state machine resolves. */
                mailboxSendOutResult(*c, send_id, RNSD_DEST_STATUS_CANCELLED, 0, 0);
            }
            break;
        }
        case RNSD_DEST_ANNOUNCE: {
            if (!c->listener_dest) {
                warn("mailbox: ANNOUNCE on outbound-only conn (no listener)");
                break;
            }
            RNS::Bytes app_data;
            if (n > 1) app_data.assign(buf + 1, n - 1);
            try {
                c->listener_dest.announce(app_data, /*path_response=*/false);
                info("announced %s aspect=%s app_data %s",
                     c->listener_hash.toHex().c_str(),
                     c->req.aspect,
                     formatAnnounceAppData(app_data).c_str());
            } catch (const std::exception& e) {
                err("mailbox: announce threw: %s", e.what());
            }
            break;
        }
        default:
            warn("mailbox: unknown opcode 0x%02x", (unsigned)op);
            break;
    }
}

/* Periodic walker: retry pending sends as paths land. Called from the
 * rnsd main loop at 1 Hz. */
static void mailboxTickPending(void)
{
    double now = RNS::Utilities::OS::time();
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++) {
        mailbox_conn_t& c = s_mailbox_conns[j];
        if (!c.used || !c.pending.used) continue;

        RNS::Bytes dh(c.pending.bytes.data(), 16);

        if (RNS::Transport::has_path(dh) && RNS::Identity::recall(dh)) {
            uint16_t send_id = c.pending.send_id;
            std::vector<uint8_t> bytes = c.pending.bytes;
            mailboxClearPending(c);
            mailboxTrySend(c, send_id, bytes.data(), bytes.size());
            continue;
        }

        if (now - c.pending.last_request_path_at >= RNSD_MAILBOX_PATH_RETRY_INTERVAL_S) {
            info("mailbox: send_id=%u retrying path request for %s (attempt %u)",
                 (unsigned)c.pending.send_id, dh.toHex().c_str(),
                 (unsigned)(c.pending.attempts + 1));
            try { RNS::Transport::request_path(dh); }
            catch (const std::exception& e) { warn("mailbox: request_path threw: %s", e.what()); }
            c.pending.attempts++;
            mailboxSendOutStatusRetry(c, c.pending.send_id,
                                      (uint8_t)std::min(c.pending.attempts, 255),
                                      /*reason=path_timeout*/ 0x01);
            c.pending.last_request_path_at = now;
        }
    }
}

/* ─────────────── announce dbg logger ─────────────── */

/* Strip C0 controls (0x00–0x1F) and DEL (0x7F); pass everything else
 * through, including UTF-8 multibyte sequences. Single-byte C0 bytes
 * are never UTF-8 continuation bytes so this preserves valid UTF-8
 * intact while keeping ESC out of xterm.js's parser. */
static std::string appDataPrintable(const RNS::Bytes& app_data) {
    std::string out;
    out.reserve(app_data.size());
    for (size_t i = 0; i < app_data.size(); i++) {
        uint8_t b = app_data.data()[i];
        out += (b < 0x20 || b == 0x7F) ? '.' : (char)b;
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
            uint8_t b = d[i+k];
            out += (b < 0x20 || b == 0x7F) ? '.' : (char)b;
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

/* Render an announce app_data blob into a human-readable suffix for a
 * single log line. Recognises (in order):
 *   - empty                                      → "(0B)"
 *   - pure msgpack                               → "(NB) mp=…"
 *   - 32B ratchet || msgpack                     → "(NB) ratchet=… mp=…"
 *   - 32B ratchet || UTF-8 text                  → "(NB) ratchet=… name=\"…\""
 *   - version byte || msgpack || trailing ratchet→ "(NB) v=XX mp=… ratchet=…"
 *   - otherwise                                  → "(NB)=\"<printable>\""
 *
 * Used by both incoming announces (AnnounceDebugLogger) and outgoing
 * announces (mailbox ANNOUNCE / management dest) so they format the
 * same way. Returns a self-contained suffix; callers prepend whatever
 * destination/identity/hops context they have. */
static std::string formatAnnounceAppData(const RNS::Bytes& app_data)
{
    char buf[64];
    if (app_data.size() == 0) return "(0B)";

    std::string out;
    out.reserve(64 + app_data.size() * 2);
    snprintf(buf, sizeof(buf), "(%zuB) ", app_data.size());
    out += buf;

    std::string mp = appDataMsgPack(app_data);
    if (!mp.empty()) {
        out += "mp=" + mp;
        return out;
    }
    if (app_data.size() >= 32 &&
        !(mp = appDataMsgPackAt(app_data, 32)).empty()) {
        RNS::Bytes ratchet(app_data.data(), 32);
        out += "ratchet=" + ratchet.toHex() + " mp=" + mp;
        return out;
    }
    if (app_data.size() >= 32 &&
        isPlausibleText(app_data.data() + 32, app_data.size() - 32)) {
        RNS::Bytes ratchet(app_data.data(), 32);
        std::string name((const char*)app_data.data() + 32,
                         app_data.size() - 32);
        out += "ratchet=" + ratchet.toHex() + " name=\"" + name + "\"";
        return out;
    }
    if (app_data.size() >= 33 &&
        !(mp = appDataMsgPackRange(app_data, 1, app_data.size() - 32)).empty()) {
        uint8_t prefix = app_data.data()[0];
        RNS::Bytes ratchet(app_data.data() + app_data.size() - 32, 32);
        snprintf(buf, sizeof(buf), "v=%02x ", prefix);
        out += buf;
        out += "mp=" + mp + " ratchet=" + ratchet.toHex();
        return out;
    }
    out += "=\"" + appDataPrintable(app_data) + "\"";
    return out;
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
        /* All output here is dbg() — or verb() when `s.rnsd.debug.only_local`
         * is set, which demotes announce noise so it only shows at the
         * verbose level. Gate against the level we'd actually fire at so
         * the msgpack walker / shape detectors in formatAnnounceAppData
         * (a few hundred µs per announce — measurable on a busy testnet)
         * aren't paid when the output would be suppressed anyway. */
        esp_log_level_t lvl = esp_log_level_get(TAG);
        esp_log_level_t needed = s_dbg_only_local ? ESP_LOG_VERBOSE : ESP_LOG_DEBUG;
        if (lvl < needed) return;

        int hops = (int)RNS::Transport::hops_to(destination_hash);
        std::string body = formatAnnounceAppData(app_data);
        if (s_dbg_only_local)
            verb("announce dest=%s id=%s hops=%d app_data %s",
                 destination_hash.toHex().c_str(),
                 announced_identity.hexhash().c_str(), hops, body.c_str());
        else
            dbg ("announce dest=%s id=%s hops=%d app_data %s",
                 destination_hash.toHex().c_str(),
                 announced_identity.hexhash().c_str(), hops, body.c_str());
        if (app_data.size() > 0)
            verb("announce hex %s", app_data.toHex().c_str());
    }
};

static std::shared_ptr<AnnounceDebugLogger> s_announce_logger;

/* ─────────────── announce fan-out (RNSD_PORT_ANNOUNCES) ───────────────
 *
 * One internal AnnounceHandler with empty aspect filter catches every
 * announce mR sees on rnsd's task. For each connected subscriber, we
 * apply that subscriber's aspect filter and forward the event over its
 * ITS handle as one packet:
 *
 *     hops(1) | dest_hash(16) | identity_hash(16) | app_data(N)
 *
 * Drop-on-full (itsSend timeout=0) — slow consumers lose announces,
 * never block the rnsd task. Same fan-out shape as diptych-core's
 * log :1 consumers (log.cpp logSlots[]). */

#define RNSD_MAX_ANNOUNCE_SUBS 4

struct announce_sub_t {
    bool used;
    int  handle;
    char aspect[32];           /* "" = every announce */
};
static announce_sub_t s_announce_subs[RNSD_MAX_ANNOUNCE_SUBS];

static announce_sub_t* announceSubAlloc(void) {
    for (auto& s : s_announce_subs) if (!s.used) return &s;
    return nullptr;
}

class AnnounceFanout : public RNS::AnnounceHandler {
public:
    AnnounceFanout() : RNS::AnnounceHandler(nullptr) {}
    void received_announce(const RNS::Bytes& dest_hash,
                           const RNS::Identity& announced_identity,
                           const RNS::Bytes& app_data) override
    {
        /* Build the frame once. 16 B dest_hash + 16 B identity hash +
         * 1 B hops + app_data. RNS announce app_data is bounded by mR's
         * configuration; our outbound ITS buffer is 4096, well above
         * any normal announce. */
        size_t app_n = app_data.size();
        if (app_n > 1024) {
            warn("announce fanout: oversize app_data %zu B — dropping", app_n);
            return;
        }
        uint8_t frame[1 + 16 + 16 + 1024];
        frame[0] = (uint8_t)RNS::Transport::hops_to(dest_hash);
        std::memcpy(frame + 1,      dest_hash.data(),                16);
        std::memcpy(frame + 1 + 16, announced_identity.hash().data(), 16);
        if (app_n > 0)
            std::memcpy(frame + 1 + 16 + 16, app_data.data(), app_n);
        size_t frame_n = 1 + 16 + 16 + app_n;

        for (auto& sub : s_announce_subs) {
            if (!sub.used || sub.handle < 0) continue;

            /* Server-side aspect filter — empty = pass all. Otherwise
             * match the same way mR matches AnnounceHandler subclasses
             * (Transport.cpp:2278). */
            if (sub.aspect[0]) {
                try {
                    RNS::Bytes expected = RNS::Destination::hash_from_name_and_identity(
                        sub.aspect, announced_identity);
                    if (expected != dest_hash) continue;
                } catch (const std::exception& e) {
                    warn("announce fanout: aspect hash threw: %s", e.what());
                    continue;
                }
            }

            /* Drop on full — never block the rnsd task. */
            if (itsSend(sub.handle, frame, frame_n, 0) == 0)
                verb("announce fanout: drop to handle=%d aspect=%s",
                     sub.handle, sub.aspect);
        }
    }
};

static std::shared_ptr<AnnounceFanout> s_announce_fanout;

static void rnsdManagementDestUp(void)
{
    if (s_management_dest) return;   /* already up */
    if (!s_identity)       return;
    try {
        s_management_dest = RNS::Destination(*s_identity,
            RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE,
            "rnstransport", "remote.management");
        /* Phase A of docs/plans/link.md §4.3: refuse Link requests until
         * Phase G ports register_request_handler and we know how to
         * service them. */
        s_management_dest.accepts_links(false);
        info("management dest up: %s",
             s_management_dest.hash().toHex().c_str());
        /* Arm the debounce so the announce goes out after the usual
         * iface-settling window — covers the boot case where ifaces
         * came up before we ran this. */
        s_rnsd_announce_due_tick = xTaskGetTickCount() +
            pdMS_TO_TICKS(RNSD_ANNOUNCE_DEBOUNCE_MS);
    } catch (const std::exception& e) {
        err("management dest construct threw: %s", e.what());
    }
}

static void rnsdManagementDestDown(void)
{
    if (!s_management_dest) return;
    try { RNS::Transport::deregister_destination(s_management_dest); }
    catch (const std::exception& e) { warn("deregister_destination threw: %s", e.what()); }
    s_management_dest = RNS::Destination(RNS::Type::NONE);
    /* Don't zero the shared announce ticks here — probe may still be
     * up and needing them. The scheduling loop guards on dest presence. */
    info("management dest down");
}

static void sendManagementAnnounce(void)
{
    if (!s_management_dest) return;
    try {
        RNS::Bytes empty;
        s_management_dest.announce(empty, /*path_response=*/false);
        TickType_t t = xTaskGetTickCount();
        s_rnsd_last_announce_tick = (t == 0) ? 1 : t;  /* 0 = never */
        info("announced %s aspect=rnstransport.remote.management app_data %s",
             s_management_dest.hash().toHex().c_str(),
             formatAnnounceAppData(empty).c_str());
    } catch (const std::exception& e) {
        err("management announce threw: %s", e.what());
    }
}

/* Subscriber callback: s.rnsd.remote_management flipped. Runs on the
 * rnsd task (subscriptions dispatch on the registering task). */
static void onRemoteManagementChange(const char* /*key*/, const char* val)
{
    bool enabled = val && std::atoi(val) != 0;
    if (enabled) rnsdManagementDestUp();
    else         rnsdManagementDestDown();
}

static void rnsdProbeDestUp(void)
{
    if (s_probe_dest) return;
    if (!s_identity)  return;
    try {
        s_probe_dest = RNS::Destination(*s_identity,
            RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE,
            "rnstransport", "probe");
        /* Opportunistic SINGLE only — no Link establishment. mR auto-
         * proves every incoming DATA packet so `rnprobe` round-trips
         * without needing any callback or app-level handler. */
        s_probe_dest.accepts_links(false);
        s_probe_dest.set_proof_strategy(RNS::Type::Destination::PROVE_ALL);
        info("probe dest up: %s (auto-proves incoming packets)",
             s_probe_dest.hash().toHex().c_str());
        s_rnsd_announce_due_tick = xTaskGetTickCount() +
            pdMS_TO_TICKS(RNSD_ANNOUNCE_DEBOUNCE_MS);
    } catch (const std::exception& e) {
        err("probe dest construct threw: %s", e.what());
    }
}

static void rnsdProbeDestDown(void)
{
    if (!s_probe_dest) return;
    try { RNS::Transport::deregister_destination(s_probe_dest); }
    catch (const std::exception& e) { warn("deregister_destination threw: %s", e.what()); }
    s_probe_dest = RNS::Destination(RNS::Type::NONE);
    info("probe dest down");
}

static void sendProbeAnnounce(void)
{
    if (!s_probe_dest) return;
    try {
        RNS::Bytes empty;
        s_probe_dest.announce(empty, /*path_response=*/false);
        TickType_t t = xTaskGetTickCount();
        s_rnsd_last_announce_tick = (t == 0) ? 1 : t;
        info("announced %s aspect=rnstransport.probe app_data %s",
             s_probe_dest.hash().toHex().c_str(),
             formatAnnounceAppData(empty).c_str());
    } catch (const std::exception& e) {
        err("probe announce threw: %s", e.what());
    }
}

static void onRespondToProbesChange(const char* /*key*/, const char* val)
{
    bool enabled = val && std::atoi(val) != 0;
    if (enabled) rnsdProbeDestUp();
    else         rnsdProbeDestDown();
}

static int onAnnouncesConnect(int handle, const void* data, size_t len)
{
    if (len != sizeof(rnsd_announces_connect_t)) {
        err("announces connect: bad payload len %zu (want %zu)",
            len, sizeof(rnsd_announces_connect_t));
        return -1;
    }
    announce_sub_t* slot = announceSubAlloc();
    if (!slot) { err("announces connect: no slots"); return -1; }
    auto* req = (const rnsd_announces_connect_t*)data;
    slot->used   = true;
    slot->handle = handle;
    std::memcpy(slot->aspect, req->aspect, sizeof(slot->aspect));
    slot->aspect[sizeof(slot->aspect) - 1] = '\0';
    info("announces sub %d open: aspect=%s",
         (int)(slot - s_announce_subs),
         slot->aspect[0] ? slot->aspect : "(all)");
    return (int)(slot - s_announce_subs);
}

static void onAnnouncesDisconnect(int ref)
{
    if (ref < 0 || ref >= RNSD_MAX_ANNOUNCE_SUBS) return;
    announce_sub_t& s = s_announce_subs[ref];
    if (!s.used) return;
    info("announces sub %d close (aspect=%s)", ref,
         s.aspect[0] ? s.aspect : "(all)");
    s.used = false;
    s.handle = -1;
    s.aspect[0] = '\0';
}

/* Subscribers don't send anything; if they do, drain and ignore. Port
 * is unidirectional today (toSize=0 at port open), so this should never
 * fire — kept as a defensive sink. */
static void onAnnouncesRecv(int handle, size_t /*bytesAvail*/)
{
    static uint8_t scratch[64];
    (void)itsRecv(handle, scratch, sizeof(scratch), 0);
}

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

/* rnprobe is a client of RNSD_PORT_DEST. CLI task opens an ITS mailbox
 * connection with `identity_key=""` (rnsd uses its own identity) and the
 * target aspect, writes one OUT_PACKET (send_id=1, dest_hash || payload),
 * reads frames until a terminal OUT_RESULT lands, prints, disconnects. */
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
     * default aspect to the conventional probe endpoint (rnstransport.probe,
     * which any node with `respond_to_probes = yes` hosts with PROVE_ALL). */
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
        aspect   = "rnstransport.probe";
    }

    if (show_help || aspect.empty() || hash_hex.empty()) {
        cliPrintf("  %-*s probe destination, measure RTT\n",
                  CLI_HELP_COL, "rnprobe [aspect] <hash>");
        cliPrintf("    aspect    default: rnstransport.probe\n");
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

    /* identity_key=nullptr → rnsd uses its default identity. */
    int handle = rnsdDestOpen(aspect.c_str(), nullptr, /*SINGLE*/ 0,
                              /*ref*/ 0, nullptr, nullptr);
    if (handle < 0) {
        cliPrintf("rnprobe: connect to rnsd failed\n");
        return;
    }

    if (size < 0)   size = 0;
    if (size > 400) size = 400;

    /* OUT_PACKET frame: opcode | send_id(2) | dest_hash(16) | payload */
    const uint16_t send_id = 1;
    std::vector<uint8_t> frame(3 + 16 + (size_t)size, 0);
    frame[0] = RNSD_DEST_OUT_PACKET;
    frame[1] = (uint8_t)(send_id >> 8);
    frame[2] = (uint8_t)(send_id & 0xFF);
    memcpy(frame.data() + 3, dh.data(), 16);
    /* Probe payload after dest_hash is zeros (size bytes). */

    if (itsSend(handle, frame.data(), frame.size(), pdMS_TO_TICKS(1000)) == 0) {
        cliPrintf("rnprobe: send failed\n");
        itsDisconnect(handle);
        return;
    }

    std::string short_hash = hash_hex.substr(0, 16);
    cliPrintf("probing %s (%d B, %ds timeout)...\n",
              short_hash.c_str(), size, timeout);

    /* Drain frames until a terminal OUT_RESULT lands or the user-visible
     * deadline expires. Aux OUT_STATUS frames are narrated inline. */
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS((timeout + 2) * 1000);
    bool done = false;
    while (!done) {
        TickType_t now = xTaskGetTickCount();
        TickType_t left = (deadline > now) ? (deadline - now) : 0;
        uint8_t buf[64];
        size_t got = itsRecv(handle, buf, sizeof(buf), left);
        if (got == 0) {
            cliPrintf("rnprobe: deadline reached, cancelling\n");
            /* OUT_CANCEL: opcode | send_id(2) */
            uint8_t c[3] = { RNSD_DEST_OUT_CANCEL,
                             (uint8_t)(send_id >> 8), (uint8_t)(send_id & 0xFF) };
            itsSend(handle, c, sizeof(c), pdMS_TO_TICKS(200));
            /* Wait a beat for the cancelled OUT_RESULT, then bail. */
            itsRecv(handle, buf, sizeof(buf), pdMS_TO_TICKS(500));
            break;
        }
        switch (buf[0]) {
            case RNSD_DEST_OUT_RESULT: {
                if (got < 9) { cliPrintf("rnprobe: short OUT_RESULT (%zu B)\n", got); done = true; break; }
                uint8_t  status = buf[3];
                uint32_t rtt_ms = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
                                | ((uint32_t)buf[6] <<  8) |  (uint32_t)buf[7];
                uint8_t  hops   = buf[8];
                switch (status) {
                    case RNSD_DEST_STATUS_SENT:
                        cliPrintf("sent to %s: hops=%u\n", short_hash.c_str(), (unsigned)hops);
                        break;
                    case RNSD_DEST_STATUS_DELIVERED:
                        cliPrintf("delivered to %s: rtt=%u ms hops=%u\n",
                                  short_hash.c_str(), (unsigned)rtt_ms, (unsigned)hops);
                        break;
                    case RNSD_DEST_STATUS_CANCELLED:
                        cliPrintf("cancelled probe to %s\n", short_hash.c_str());
                        break;
                    case RNSD_DEST_STATUS_EVICTED:
                        cliPrintf("evicted: rnsd dropped the probe (resource limit)\n");
                        break;
                    default:
                        cliPrintf("rnprobe: unknown OUT_RESULT status %u\n", (unsigned)status);
                        break;
                }
                done = true;
                break;
            }
            case RNSD_DEST_OUT_STATUS: {
                if (got < 4) { cliPrintf("rnprobe: short OUT_STATUS (%zu B)\n", got); break; }
                uint8_t type = buf[3];
                switch (type) {
                    case RNSD_DEST_AUX_REQUESTING_PATH:
                        cliPrintf("  requesting path...\n");
                        break;
                    case RNSD_DEST_AUX_EGRESS_QUEUED:
                        cliPrintf("  egress queued\n");
                        break;
                    case RNSD_DEST_AUX_RETRY:
                        if (got >= 6)
                            cliPrintf("  retry (attempt %u, reason 0x%02x)\n",
                                      (unsigned)buf[4], (unsigned)buf[5]);
                        else
                            cliPrintf("  retry\n");
                        break;
                    default:
                        cliPrintf("  status 0x%02x\n", (unsigned)type);
                        break;
                }
                break;
            }
            case RNSD_DEST_IN_PACKET:
                /* Probes shouldn't be getting LXMF deliveries — ignore. */
                break;
            default:
                cliPrintf("rnprobe: unknown frame 0x%02x\n", (unsigned)buf[0]);
                break;
        }
    }

    itsDisconnect(handle);
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

/* ─────────────── public API (rnsd.h) ───────────────
 *
 * Byte-array wrappers around the mR primitives consumers (lxmf etc.)
 * need. All pure-crypto helpers execute on the caller's task —
 * underlying mbedTLS calls (used by mR) are thread-safe and the
 * Identity objects are local to each call. The recall API takes
 * mR's `_known_destinations_mux` (added in Identity.h). The async
 * path request crosses to rnsd's task via a storage sentinel
 * (`rnsd.cmd.request_path`). */

/* Load the identity at `identity_key` (128-hex private bytes in
 * storage) into a local `RNS::Identity`. Returns false on missing /
 * malformed. Used by rnsdSign / rnsdDestinationHash / rnsdIdentityHash. */
static bool loadIdentityFromStorage(const char* identity_key, RNS::Identity& out)
{
    if (!identity_key || !*identity_key) return false;
    char hex[160] = {};
    storageGetStr(identity_key, hex, sizeof(hex), "");
    if (std::strlen(hex) != 128) return false;
    RNS::Bytes prv;
    prv.assignHex((const uint8_t*)hex, 128);
    if (prv.size() != 64) return false;
    RNS::Identity id(false);
    if (!id.load_private_key(prv)) return false;
    out = id;
    return true;
}

void rnsdSha256(const uint8_t* data, size_t n, uint8_t out[RNSD_HASH_LEN])
{
    RNS::Bytes h = RNS::Identity::full_hash(RNS::Bytes(data, n));
    if (h.size() >= RNSD_HASH_LEN) std::memcpy(out, h.data(), RNSD_HASH_LEN);
    else { std::memset(out, 0, RNSD_HASH_LEN); std::memcpy(out, h.data(), h.size()); }
}

bool rnsdDestinationHash(const char* identity_key,
                         const char* app_name, const char* aspect,
                         uint8_t out[RNSD_DEST_HASH_LEN])
{
    RNS::Identity id(RNS::Type::NONE);
    if (!loadIdentityFromStorage(identity_key, id)) return false;
    try {
        RNS::Bytes dh = RNS::Destination::hash(id, app_name, aspect);
        if (dh.size() != RNSD_DEST_HASH_LEN) return false;
        std::memcpy(out, dh.data(), RNSD_DEST_HASH_LEN);
        return true;
    } catch (const std::exception& e) {
        warn("rnsdDestinationHash: %s", e.what());
        return false;
    }
}

bool rnsdSign(const char* identity_key,
              const uint8_t* data, size_t n,
              uint8_t out_sig[RNSD_SIG_LEN])
{
    RNS::Identity id(RNS::Type::NONE);
    if (!loadIdentityFromStorage(identity_key, id)) return false;
    try {
        RNS::Bytes sig = id.sign(RNS::Bytes(data, n));
        if (sig.size() != RNSD_SIG_LEN) return false;
        std::memcpy(out_sig, sig.data(), RNSD_SIG_LEN);
        return true;
    } catch (const std::exception& e) {
        warn("rnsdSign: %s", e.what());
        return false;
    }
}

bool rnsdVerify(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                const uint8_t* data, size_t n,
                const uint8_t sig[RNSD_SIG_LEN])
{
    try {
        RNS::Identity id(false);
        id.load_public_key(RNS::Bytes(pubkey, RNSD_PUBKEY_LEN));
        return id.validate(RNS::Bytes(sig, RNSD_SIG_LEN),
                           RNS::Bytes(data, n));
    } catch (const std::exception& e) {
        warn("rnsdVerify: %s", e.what());
        return false;
    }
}

bool rnsdIdentityGenerate(const char* identity_key)
{
    if (rnsdIdentityExists(identity_key)) return true;
    try {
        RNS::Identity id(true);
        RNS::Bytes prv = id.get_private_key();
        if (prv.size() != RNSD_PRIVKEY_LEN) return false;
        storageSet(identity_key, prv.toHex().c_str());
        return true;
    } catch (const std::exception& e) {
        err("rnsdIdentityGenerate: %s", e.what());
        return false;
    }
}

bool rnsdIdentityExists(const char* identity_key)
{
    if (!identity_key || !*identity_key) return false;
    char hex[160] = {};
    storageGetStr(identity_key, hex, sizeof(hex), "");
    return std::strlen(hex) == 128;
}

bool rnsdIdentityHash(const char* identity_key,
                      uint8_t out[RNSD_IDENT_HASH_LEN])
{
    RNS::Identity id(RNS::Type::NONE);
    if (!loadIdentityFromStorage(identity_key, id)) return false;
    RNS::Bytes h = id.hash();
    if (h.size() != RNSD_IDENT_HASH_LEN) return false;
    std::memcpy(out, h.data(), RNSD_IDENT_HASH_LEN);
    return true;
}

void rnsdIdentityErase(const char* identity_key)
{
    if (!identity_key || !*identity_key) return;
    storageUnset(identity_key);
}

bool rnsdRecallPubkey(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                      uint8_t out_pubkey[RNSD_PUBKEY_LEN])
{
    try {
        /* Identity::recall takes _known_destinations_mux internally
         * (see Identity.cpp), so this is safe from any task. */
        RNS::Identity id = RNS::Identity::recall(
            RNS::Bytes(dest_hash, RNSD_DEST_HASH_LEN));
        if (!id) return false;
        RNS::Bytes pk = id.get_public_key();
        if (pk.size() != RNSD_PUBKEY_LEN) return false;
        std::memcpy(out_pubkey, pk.data(), RNSD_PUBKEY_LEN);
        return true;
    } catch (const std::exception& e) {
        warn("rnsdRecallPubkey: %s", e.what());
        return false;
    }
}

void rnsdRequestPath(const uint8_t dest_hash[RNSD_DEST_HASH_LEN])
{
    /* Write a self-clearing sentinel; rnsd's task picks it up via
     * subscription and calls Transport::request_path on its own
     * task (where mR state is safe to touch). */
    char hex[RNSD_DEST_HASH_LEN * 2 + 1];
    for (size_t i = 0; i < RNSD_DEST_HASH_LEN; ++i)
        std::snprintf(hex + 2*i, 3, "%02x", dest_hash[i]);
    storageSet("rnsd.cmd.request_path", hex);
}

/* ──────────────── destination / link client API ──────────────── */

int rnsdDestOpen(const char* aspect,
                 const char* identity_key,
                 uint8_t     dest_type,
                 int         ref,
                 void (*on_recv)(int, size_t),
                 void (*on_disconnect)(int))
{
    if (!aspect || !*aspect) {
        warn("rnsdDestOpen: aspect required");
        return -1;
    }
    rnsd_dest_connect_t req = {};
    safeStrncpy(req.aspect, aspect, sizeof(req.aspect));
    if (identity_key && *identity_key)
        safeStrncpy(req.identity_key, identity_key, sizeof(req.identity_key));
    req.dest_type = dest_type;
    return itsConnect("rnsd", RNSD_PORT_DEST,
                      &req, sizeof(req), pdMS_TO_TICKS(2000),
                      ref, on_recv, on_disconnect);
}

int rnsdLinkOpen(const uint8_t /*dest_hash*/[RNSD_DEST_HASH_LEN],
                 const char* /*aspect*/,
                 const char* /*identity_key*/,
                 uint32_t    /*timeout_ms*/,
                 int         /*ref*/,
                 void (*/*on_recv*/)(int, size_t),
                 void (*/*on_disconnect*/)(int))
{
    /* mR's Link layer is stubbed in our fork — Link::validate_request
     * et al. are no-ops. Defined here so callers compile cleanly today
     * and can switch on availability later. See rnsd.h. */
    err("rnsdLinkOpen: Link layer not yet implemented in this build");
    return -1;
}

bool rnsdDestListenLinks(int      /*dest_handle*/,
                         uint16_t /*target_port*/)
{
    err("rnsdDestListenLinks: Link layer not yet implemented in this build");
    return false;
}

/* Subscription handler for rnsdRequestPath. Runs on rnsd's task. */
static void onCmdRequestPath(const char* key, const char* val)
{
    if (!val || !*val) return;   /* self-unset re-fire */
    if (std::strlen(val) != RNSD_DEST_HASH_LEN * 2) {
        warn("cmd.request_path: bad hex length");
        storageUnset(key);
        return;
    }
    try {
        RNS::Bytes dh;
        dh.assignHex((const uint8_t*)val, std::strlen(val));
        if (dh.size() == RNSD_DEST_HASH_LEN) {
            RNS::Transport::request_path(dh);
            info("cmd.request_path: %s", val);
        }
    } catch (const std::exception& e) {
        warn("cmd.request_path threw: %s", e.what());
    }
    storageUnset(key);
}

static void rnsdTaskMain(void*)
{
    info("[%s] task up", TAG);

    if (!itsServerInit()) { err("itsServerInit failed"); vTaskDelete(nullptr); return; }
    /* 4 KB per direction per handle — bursty announce traffic on a busy
     * testnet can fill 2 KB before rnsd drains during the 1 Hz publish
     * block. 4 KB gives ~4× more headroom; PSRAM-allocated, ~64 KB total
     * across RNSD_MAX_IFACES=16 × 2 directions. */
    if (!itsServerPortOpen(RNSD_PORT_TRANSPORT, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_IFACES,
                           /*toSize=*/4096, /*fromSize=*/4096)) {
        err("RNSD_PORT_TRANSPORT open failed");
        vTaskDelete(nullptr);
        return;
    }
    itsServerOnConnect(RNSD_PORT_TRANSPORT, onTransportConnect);
    itsServerOnDisconnect(RNSD_PORT_TRANSPORT, onTransportDisconnect);
    itsServerOnRecv(RNSD_PORT_TRANSPORT, onTransportRecv);

    if (!itsServerPortOpen(RNSD_PORT_DEST, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_MAILBOX_CONNS,
                           /*toSize=*/4096, /*fromSize=*/2048)) {
        err("RNSD_PORT_DEST open failed");
        vTaskDelete(nullptr);
        return;
    }
    itsServerOnConnect(RNSD_PORT_DEST,    onMailboxConnect);
    itsServerOnDisconnect(RNSD_PORT_DEST, onMailboxDisconnect);
    itsServerOnRecv(RNSD_PORT_DEST,       onMailboxRecv);

    /* Announce fan-out — unidirectional rnsd → subscribers (toSize=0).
     * 4 KB per-connection outbound buffer comfortably holds a few queued
     * announces (typical app_data is < 200 B). */
    if (!itsServerPortOpen(RNSD_PORT_ANNOUNCES, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_ANNOUNCE_SUBS,
                           /*toSize=*/0, /*fromSize=*/4096)) {
        err("RNSD_PORT_ANNOUNCES open failed");
        vTaskDelete(nullptr);
        return;
    }
    itsServerOnConnect(RNSD_PORT_ANNOUNCES,    onAnnouncesConnect);
    itsServerOnDisconnect(RNSD_PORT_ANNOUNCES, onAnnouncesDisconnect);
    itsServerOnRecv(RNSD_PORT_ANNOUNCES,       onAnnouncesRecv);

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

        /* Fan-out handler — every announce mR sees gets dispatched to
         * connected RNSD_PORT_ANNOUNCES subscribers. Empty aspect filter
         * so we catch every announce; per-subscriber aspect filtering
         * lives in AnnounceFanout::received_announce. */
        s_announce_fanout = std::make_shared<AnnounceFanout>();
        RNS::Transport::register_announce_handler(s_announce_fanout);

        /* Bring up the management destination if enabled, and subscribe
         * for runtime flips of the gate. The subscriber callback runs
         * on the rnsd task (storage subs dispatch on the registering
         * task), which is where mR state must be touched. */
        if (storageGetInt("s.rnsd.remote_management", 1))
            rnsdManagementDestUp();
        storageSubscribeChanges("s.rnsd.remote_management",
                                onRemoteManagementChange);

        /* Probe responder. Same lifecycle pattern as the management
         * dest, gated by s.rnsd.respond_to_probes (default 0 — opt-in). */
        if (storageGetInt("s.rnsd.respond_to_probes", 0))
            rnsdProbeDestUp();
        storageSubscribeChanges("s.rnsd.respond_to_probes",
                                onRespondToProbesChange);

        /* Async-path-request endpoint for the rnsd.h API. Callers
         * write `rnsd.cmd.request_path = <32-hex>`; we process it on
         * this task (mR's Transport::request_path silently drops when
         * called from any other task — see memory note). */
        storageSubscribeChanges("rnsd.cmd.request_path", onCmdRequestPath);

        /* Live-mirror s.rnsd.debug.only_local into the cached bool so
         * toggling at runtime takes effect on the next announce. Also
         * push the same flag into mR's Transport so its high-volume
         * announce/path-request DEBUGFs demote to VERBOSE. */
        RNS::Transport::demote_dbg(s_dbg_only_local);
        storageSubscribeChanges("s.rnsd.debug.only_local",
            [](const char* /*key*/, const char* val) {
                s_dbg_only_local = val && val[0] && std::atoi(val) != 0;
                RNS::Transport::demote_dbg(s_dbg_only_local);
            });
    } catch (const std::exception& e) {
        err("Reticulum::start threw: %s", e.what());
    }

    s_lastPublishTick = xTaskGetTickCount();
    int tickPhase = 0;

    for (;;) {
        itsPoll(nextDeadline());

        TickType_t now = xTaskGetTickCount();
        if (now - s_lastPublishTick >= pdMS_TO_TICKS(1000)) {
            /* The 1 Hz block is unyieldy except for publishPathTable's
             * internal yield-every-8. Running Transport::jobs() *and*
             * publishPathTable() in the same tick can park the rnsd task
             * past tcp's 100 ms itsSend timeout on busy networks —
             * RNSD_PORT_TRANSPORT recv drops follow. Stagger across two
             * ticks so each tick only carries one slow workload. */
            if (tickPhase == 0) {
                try { RNS::Transport::jobs(); }
                catch (const std::exception& e) { warn("Transport::jobs threw: %s", e.what()); }
                mailboxTickPending();

                /* Rnsd-hosted announces — debounce fire + periodic check.
                 * Each sendX() is a no-op when its destination is down,
                 * so flipping mgmt/probe at runtime works cleanly. Cheap
                 * either way (tick compare + maybe an mR announce). */
                if (s_rnsd_announce_due_tick != 0 &&
                    (int32_t)(now - s_rnsd_announce_due_tick) >= 0) {
                    s_rnsd_announce_due_tick = 0;
                    sendManagementAnnounce();
                    sendProbeAnnounce();
                }
                if ((s_management_dest || s_probe_dest) &&
                    s_rnsd_last_announce_tick != 0) {
                    int announce_s = storageGetInt("s.rnsd.announce.interval", 1800);
                    /* Signed comparison: the sendX() helpers re-read
                     * xTaskGetTickCount() after their mR announce()
                     * (which takes a few ms), so s_rnsd_last_announce_tick
                     * can be *just past* the outer `now`. Unsigned
                     * `now - last` then underflows to ~UINT32_MAX and
                     * spuriously passes the threshold — causing a
                     * second announce right after the debounce fire. */
                    if (announce_s > 0 &&
                        (int32_t)(now - s_rnsd_last_announce_tick) >=
                            (int32_t)pdMS_TO_TICKS(announce_s * 1000)) {
                        sendManagementAnnounce();
                        sendProbeAnnounce();
                    }
                }
            } else {
                publishPathTable();
            }
            publishStats();   /* cheap, every tick */
            tickPhase ^= 1;
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

    s_mailbox_conns = (mailbox_conn_t*)heap_caps_malloc(
        RNSD_MAX_MAILBOX_CONNS * sizeof(mailbox_conn_t), MALLOC_CAP_SPIRAM);
    if (!s_mailbox_conns) { err("s_mailbox_conns PSRAM alloc failed"); return; }
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++) new (&s_mailbox_conns[j]) mailbox_conn_t{};

    for (auto& s : s_announce_subs) { s.used = false; s.handle = -1; s.aspect[0] = '\0'; }

    /* One-time storage defaults gated on version. */
    if (storageGetInt("s.rnsd.version", 0) < RNSD_VERSION) {
        storageDefault("s.rnsd.enable", 1);
        storageDefault("s.rnsd.transport_enabled", 0);
        storageDefault("s.rnsd.name", "");
        storageDefault("s.rnsd.announce.interval", 1800);   /* 30 min */
        storageDefault("s.rnsd.remote_management", 1);      /* host rnstransport.remote.management */
        storageDefault("s.rnsd.respond_to_probes", 0);      /* host rnstransport.probe (PROVE_ALL) */
        storageDefault("s.rnsd.debug.only_local", 0);       /* demote announce-traffic dbg to verb */
        /* `s.rnsd.path.max` / `s.rnsd.path.ttl` removed: mR's path table is
         * unbounded (BasicHeapStore), pruned only by PATHFINDER_E (24 h).
         * Re-add when we implement post-process pruning or interface-mode
         * intake control. */
        storageSet("s.rnsd.version", RNSD_VERSION);
    }

    s_dbg_only_local = storageGetInt("s.rnsd.debug.only_local", 0) != 0;

    cliRegisterCmd("rnsd",     cliRnsd);
    cliRegisterCmd("rnstatus", cliRnstatus);
    cliRegisterCmd("rnpath",   cliRnpath);
    cliRegisterCmd("rnprobe",  cliRnprobe);

    /* Cron line per §11.3 — no-op when transport disabled, hourly otherwise. */
    cronDefault("0 * * * * N", "rnsd persist if-transport");

    /* PSRAM stack, core 0 alongside tcpip_thread, prio 2. */
    s_task = spawnTask(rnsdTaskMain, TAG, 12288, nullptr, 2, 0, STACK_PSRAM);
}
