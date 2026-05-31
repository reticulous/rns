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
#include "spangap.h"
#include "ports.h"

/* mR's Log.h declares free functions `info`, `warn`, `error`, `debug`, ...
 * inside namespace RNS. spangap's log.h defines `info`/`warn`/`err`/etc. as
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
#include "Link.h"
#include "Resource.h"
#include "Persistence/DestinationEntry.h"
#include "Utilities/OS.h"
#include "Utilities/Memory.h"

#undef msg
#pragma pop_macro("info")
#pragma pop_macro("warn")
#pragma pop_macro("err")
#pragma pop_macro("dbg")
#pragma pop_macro("verb")

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstring>
#include <cstdlib>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <algorithm>
#include <new>

#include "esp_heap_caps.h"
#ifdef CONFIG_HEAP_TASK_TRACKING
#include "esp_heap_task_info.h"
#endif

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
 * own iface, so this caps total transports (lora + auto + espnow + N tcp). */
#define RNSD_MAX_IFACES 16

/* mR Interface impl wrapping the ITS handle to a transport task. mR's
 * Transport calls `send_outgoing(Bytes)` when it wants to push a packet
 * out our way; we relay over the ITS handle. Inbound packets arrive via
 * the ITS server-port recv callback; we wrap the bytes into Interface
 * and call `iface.handle_incoming(...)`, which routes through
 * InterfaceImpl::handle_incoming → Transport::inbound. */
/* Map an rnsd-facing rns_iface_mode (ports.h) to mR's Type::Interface::modes.
 * The two enums deliberately do NOT share a bit layout — ports.h must not
 * include mR headers — so a raw static_cast is wrong (e.g. rnsd GATEWAY
 * 0x02 is not any mR mode, and would silently disable DISCOVER_PATHS_FOR
 * and misfire the roaming anti-loop check). */
static RNS::Type::Interface::modes mapIfaceMode(uint8_t m) {
    switch (m) {
        case RNS_IFACE_MODE_FULL:         return RNS::Type::Interface::MODE_FULL;
        case RNS_IFACE_MODE_GATEWAY:      return RNS::Type::Interface::MODE_GATEWAY;
        case RNS_IFACE_MODE_ACCESS_POINT: return RNS::Type::Interface::MODE_ACCESS_POINT;
        case RNS_IFACE_MODE_ROAMING:      return RNS::Type::Interface::MODE_ROAMING;
        case RNS_IFACE_MODE_BOUNDARY:     return RNS::Type::Interface::MODE_BOUNDARY;
        default:                          return RNS::Type::Interface::MODE_FULL;
    }
}

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
        _mode = mapIfaceMode(info.mode);
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

/* RNSD_PORT_LINK connect payload — rnsd-private (mirrors
 * rnsd_dest_connect_t; consumers go through rnsdLinkOpen() in rnsd.h,
 * which fills it from typed args). Phase C — docs/plans/link.md §6.1. */
typedef struct {
    uint8_t  dest_hash[RNSD_DEST_HASH_LEN];  /* target destination hash */
    char     aspect[32];                     /* "lxmf.delivery" */
    char     identity_key[40];               /* our id privkey path; "" → default */
    char     tag[24];                        /* caller tag, keys rnsd.links.<tag>.* */
    uint32_t path_timeout_ms;                /* 0 → s.rnsd.link.path_timeout_s */
} rnsd_link_connect_t;
static_assert(sizeof(rnsd_link_connect_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_connect_t must fit ITS_MAX_MSG_DATA");

#define RNSD_MAX_MAILBOX_CONNS    4
/* Generous — costs only a slot struct + (lazily, PSRAM) ITS buffers each.
 * When the table is full a new open evicts the longest-idle link rather than
 * failing (linkAlloc), so this is a soft concurrency ceiling, never a hard
 * refusal. */
#define RNSD_MAX_LINK_CONNS       32

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

    /* Phase D — RNSD_DEST_LINK_LISTEN. Zero = not listening for Links.
     * link_listener_task is itsRemoteTask(handle) cached at register
     * time so inbound Links back-connect without a name lookup. */
    TaskHandle_t               link_listener_task = nullptr;
    uint16_t                   link_inbox_port    = 0;

    mailbox_pending_t          pending;                /* one in-flight at a time */
};

static mailbox_conn_t* s_mailbox_conns = nullptr;

/* Path-request retry cadence: exponential backoff, not a fixed interval.
 * A parked send fires its first request immediately; mailboxRetryDelay()
 * gives the gap before each *subsequent* request, indexed by how many
 * retries have already gone out (pending.attempts). Steady state caps at
 * 30 min so a long-unreachable peer keeps a slow heartbeat without
 * flooding the mesh. After RNSD_MAILBOX_PATH_GIVEUP_S with no path the
 * send is failed (OUT_RESULT status=FAILED) and unparked. */
static double mailboxRetryDelay(int attempts) {
    static const double S[] = { 5, 30, 60, 120, 240, 480, 960 };
    if (attempts < 0) attempts = 0;
    if (attempts >= (int)(sizeof(S) / sizeof(S[0]))) return 1800.0;
    return S[attempts];
}
#define RNSD_MAILBOX_PATH_GIVEUP_S   (6.0 * 3600.0)

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

/* Debug: when `rnsd.debug.log_msg_content` (ephemeral, toggle live via
 * CLI/storage) is set, dump a stable FNV-1a/32 hash + printable preview
 * of a message payload. The on-send and after-decryption payloads are
 * the same byte span (sender strips the 16-byte dest, receiver gets it
 * back as the RNS plaintext), so the fnv= values match for one message
 * — lets us pair a send with its decrypted echo and tell it apart from
 * unrelated traffic. rnsd stays content-agnostic: just bytes. */
static void rnsdDbgMsgContent(const char* dir, const uint8_t* p, size_t n)
{
    if (storageGetInt("rnsd.debug.log_msg_content", 0) == 0) return;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    std::string prev;
    size_t lim = n < 96 ? n : 96;
    prev.reserve(lim);
    for (size_t i = 0; i < lim; i++) {
        uint8_t b = p[i];
        prev += (b >= 0x20 && b < 0x7F) ? (char)b : '.';
    }
    info("debug.msg %s len=%zu fnv=%08x \"%s\"%s",
         dir, n, (unsigned)h, prev.c_str(), n > lim ? "..." : "");
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
        RNS::Interface oif = RNS::Transport::next_hop_interface(dh);
        info("mailbox: send_id=%u sent to %s via %s (hops=%u, %zuB payload)",
             (unsigned)send_id, dh.toHex().c_str(),
             oif ? oif.toString().c_str() : "<none>",
             (unsigned)hops, n);
        rnsdDbgMsgContent("send", bytes + 16, n - 16);
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
/* Phase D: inbound-Link established callback, set on every listening IN
 * destination. Defined in the Phase C block (needs s_link_conns etc.). */
static void onIncomingLinkEstablished(RNS::Link& link);

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
    rnsdDbgMsgContent("recv", plaintext.data(), plaintext.size());
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
        /* Observability: surface hosted destinations to storage so the
         * browser / CLI can see what we host (and so tests can resolve
         * a dest hash without log access). */
        {
            int idx = (int)(slot - s_mailbox_conns);
            char k[64];
            snprintf(k, sizeof(k), "rnsd.mailbox.%d.aspect", idx);
            storageSet(k, slot->req.aspect);
            snprintf(k, sizeof(k), "rnsd.mailbox.%d.dest", idx);
            storageSet(k, d.hash().toHex().c_str());
        }
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
    {
        char p[48];
        snprintf(p, sizeof(p), "rnsd.mailbox.%d", ref);
        storageDeleteTree(p);
    }
    c.used   = false;
    c.handle = -1;
    c.link_listener_task = nullptr;
    c.link_inbox_port    = 0;
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
        case RNSD_DEST_LINK_LISTEN: {
            if (!c->listener_dest) {
                warn("mailbox: LINK_LISTEN on outbound-only conn");
                break;
            }
            if (n < 3) { err("mailbox: LINK_LISTEN too short (%zu)", n); break; }
            uint16_t port = ((uint16_t)buf[1] << 8) | (uint16_t)buf[2];
            if (port == 0) { warn("mailbox: LINK_LISTEN port 0"); break; }
            c->link_listener_task = itsRemoteTask(handle);
            c->link_inbox_port    = port;
            try {
                c->listener_dest.set_link_established_callback(
                    onIncomingLinkEstablished);
                c->listener_dest.accepts_links(true);
            } catch (const std::exception& e) {
                err("mailbox: LINK_LISTEN wiring threw: %s", e.what());
                break;
            }
            info("mailbox conn %d: listening for inbound Links → port %u",
                 (int)(c - s_mailbox_conns), (unsigned)port);
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

        if (now - c.pending.first_seen_at >= RNSD_MAILBOX_PATH_GIVEUP_S) {
            uint16_t send_id = c.pending.send_id;
            info("mailbox: send_id=%u giving up path search for %s after %.0fs",
                 (unsigned)send_id, dh.toHex().c_str(),
                 now - c.pending.first_seen_at);
            mailboxClearPending(c);
            mailboxSendOutResult(c, send_id, RNSD_DEST_STATUS_FAILED, 0, 0);
            continue;
        }

        if (now - c.pending.last_request_path_at >= mailboxRetryDelay(c.pending.attempts)) {
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
 * never block the rnsd task. Same fan-out shape as spangap-core's
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

/* Defined in the Phase C block below, where s_link_conns lives. */
static int rnsdLinkConnsUsed();

/* One `rnsd memory` breakdown row, aligned, with bytes + % of task PSRAM.
 * count<0 → no count/cap column (ITS / misc / TOTAL rows). For tables,
 * `bytes` is count*perEntry where perEntry is a rough total cost per entry —
 * the std::map/std::set tree node PLUS the Bytes payload blocks it owns
 * (Bytes = shared_ptr<vector>), Xtensa 32-bit, incl. ~12 B heap headers.
 * Estimates: payload size varies, so treat table totals as relative (which
 * table dominates), not exact — the task PSRAM line is authoritative. `approx`
 * prints the "~" estimate marker (tables, misc); ITS/TOTAL are exact. Returns
 * bytes so the caller can sum. */
static unsigned long long memBar(const char* name, int count, unsigned cap,
                                 unsigned long long bytes, unsigned long long total,
                                 bool approx)
{
    unsigned pm = total ? (unsigned)(bytes * 1000ULL / total) : 0;
    char mid[32];
    if (count < 0)   mid[0] = '\0';
    else if (cap)    snprintf(mid, sizeof(mid), "%d / %u", count, cap);
    else             snprintf(mid, sizeof(mid), "%d", count);
    cliPrintf("%-14s %-11s %c%7llu B  %2u.%u%%\n",
              name, mid, approx ? '~' : ' ', bytes, pm / 10, pm % 10);
    return bytes;
}

/* `rnsd memory` — breaks down where rnsd's heap goes, as far as the
 * instrumentation allows: (1) the task's attributed heap from ESP-IDF's
 * per-task tracking, (2) µR's container-allocator live total (the std::map
 * nodes behind the tables), (3) per-table entry counts vs caps, (4) rnsd's
 * own fixed-slot arrays, and (5) system free for context. */
static void cliRnsdMemory(void)
{
    unsigned psramTot = 0, dramTot = 0, pblk = 0, dblk = 0;
#ifdef CONFIG_HEAP_TASK_TRACKING
    {
        constexpr size_t MAX_HT = 40;
        static heap_task_totals_t htotals[MAX_HT];
        memset(htotals, 0, sizeof(htotals));
        size_t ntot = 0;
        heap_task_info_params_t p = {};
        p.caps[0] = MALLOC_CAP_INTERNAL; p.mask[0] = MALLOC_CAP_INTERNAL;
        p.caps[1] = MALLOC_CAP_SPIRAM;   p.mask[1] = MALLOC_CAP_SPIRAM;
        p.totals = htotals; p.num_totals = &ntot; p.max_totals = MAX_HT;
        heap_caps_get_per_task_info(&p);
        for (size_t i = 0; i < ntot; i++) {
            if (htotals[i].task == s_task) {
                dramTot  = (unsigned)htotals[i].size[0]; dblk = (unsigned)htotals[i].count[0];
                psramTot = (unsigned)htotals[i].size[1]; pblk = (unsigned)htotals[i].count[1];
                break;
            }
        }
    }
#endif
    cliPrintf("task heap (attributed to rnsd):\n");
    cliPrintf("DRAM   %8u B  %5u blocks\n", dramTot, dblk);
    cliPrintf("PSRAM  %8u B  %5u blocks\n", psramTot, pblk);

    /* ---- PSRAM breakdown: one row per consumer, % of the task total, summing
     * to ~100%. ITS buffers are exact (with s.rnsd.its_no_pool on); table
     * rows are count*est(node+payload); `misc` is the remainder — engine object
     * graph (Reticulum/Transport/Identity/Interface/Destination), the identity
     * keypair, and transient in-flight Bytes. */
    its_mem_t its = itsTaskMem(s_task);
    bool itsExact = storageGetInt("s.rnsd.its_no_pool", 0) != 0;
    cliPrintf("PSRAM breakdown (%% of %u B task total):  [ITS %s]\n",
              psramTot, itsExact ? "exact (no_pool)" : "approx — set s.rnsd.its_no_pool=1");
    memBar("ITS stream buf", -1, 0, its.streamBytes, psramTot, false);
    memBar("ITS inbox",      -1, 0, its.inboxBytes,  psramTot, false);

    /* Per-entry byte costs, calibrated for the real allocation shape: tree
     * node + each Bytes field as a separate shared_ptr<vector> (control block +
     * vector + data buffer), rounded to heap alignment, plus per-block heap/
     * task-tracking overhead. Still estimates (payload length varies), but
     * tuned so the rows account for most of the table footprint and `misc`
     * drains to ~the engine object graph + transient in-flight Bytes. */
    unsigned id_n = (unsigned)RNS::Identity::known_destinations_size();
    unsigned pa_n = (unsigned)RNS::Transport::path_table_size();
    unsigned an_n = (unsigned)RNS::Transport::announce_table_size();
    unsigned he_n = (unsigned)RNS::Transport::held_announces_size();
    unsigned hl_n = (unsigned)RNS::Transport::hashlist_size();
    unsigned pr_n = (unsigned)RNS::Transport::pr_tags_count();
    unsigned rv_n = (unsigned)RNS::Transport::reverse_table_size();
    unsigned lk_n = (unsigned)RNS::Transport::link_table_size();
    unsigned tu_n = (unsigned)RNS::Transport::tunnels_count();
    unsigned pq_n = (unsigned)RNS::Transport::path_requests_count();
    unsigned de_n = (unsigned)RNS::Transport::destinations_count();
    unsigned if_n = (unsigned)RNS::Transport::interfaces_count();

    unsigned long long tot = 0;
    tot += memBar("identity cache", (int)id_n, (unsigned)RNS::Identity::known_destinations_maxsize(),
                  (unsigned long long)id_n * 520, psramTot, true);
    tot += memBar("path table",     (int)pa_n, (unsigned)RNS::Transport::path_table_maxsize(),
                  (unsigned long long)pa_n * 340, psramTot, true);
    tot += memBar("announce table", (int)an_n, (unsigned)RNS::Transport::announce_table_maxsize(),
                  (unsigned long long)an_n * 520, psramTot, true);
    tot += memBar("held announces", (int)he_n, 0, (unsigned long long)he_n * 520, psramTot, true);
    tot += memBar("hashlist",       (int)hl_n, (unsigned)RNS::Transport::hashlist_maxsize(),
                  (unsigned long long)hl_n * 120, psramTot, true);
    tot += memBar("pr tags",        (int)pr_n, (unsigned)RNS::Transport::max_pr_tags(),
                  (unsigned long long)pr_n * 120, psramTot, true);
    tot += memBar("reverse table",  (int)rv_n, 0, (unsigned long long)rv_n * 110, psramTot, true);
    tot += memBar("link table",     (int)lk_n, 0, (unsigned long long)lk_n * 280, psramTot, true);
    tot += memBar("tunnels",        (int)tu_n, 0, (unsigned long long)tu_n * 220, psramTot, true);
    tot += memBar("path requests",  (int)pq_n, 0, (unsigned long long)pq_n * 120, psramTot, true);
    tot += memBar("destinations",   (int)de_n, 0, (unsigned long long)de_n * 300, psramTot, true);
    tot += memBar("interfaces",     (int)if_n, 0, (unsigned long long)if_n * 220, psramTot, true);

    unsigned long long base = (unsigned long long)its.streamBytes + its.inboxBytes + tot;
    unsigned long long misc = psramTot > base ? psramTot - base : 0;
    memBar("misc",  -1, 0, misc,     psramTot, true);
    memBar("TOTAL", -1, 0, psramTot, psramTot, false);
    cliPrintf("(links: pending %u active %u)\n",
              (unsigned)RNS::Transport::pending_links_count(),
              (unsigned)RNS::Transport::active_links_count());

    {
        int ifc = 0, mbc = 0, lkc = rnsdLinkConnsUsed();
        for (int j = 0; j < RNSD_MAX_IFACES; j++)        if (s_ifaces[j].used)        ifc++;
        for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++) if (s_mailbox_conns[j].used) mbc++;
        cliPrintf("rnsd slots (used / max):  ifaces %d/%d  mailbox %d/%d  link %d/%d\n",
                  ifc, RNSD_MAX_IFACES, mbc, RNSD_MAX_MAILBOX_CONNS, lkc, RNSD_MAX_LINK_CONNS);
    }

    cliPrintf("stats: pkts in %u out %u, dests added %u\n",
              (unsigned)RNS::Transport::packets_received(),
              (unsigned)RNS::Transport::packets_sent(),
              (unsigned)RNS::Transport::destinations_added());
    cliPrintf("system free:  PSRAM %u B  DRAM %u B\n",
              (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
              (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
}

static void cliRnsd(const char* args)
{
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("%-*s identity & control (rnstatus for traffic)\n", CLI_HELP_COL, "rnsd [...]");
        return;
    }
    if (args && cliWantsHelp(args)) {
        cliPrintf("rnsd                             identity + link summary\n");
        cliPrintf("rnsd identity                    identity hash + public key\n");
        cliPrintf("rnsd persist [if-transport]      persist transport state\n");
        cliPrintf("rnsd reload                      reload / create identity\n");
        cliPrintf("rnsd memory                      heap usage breakdown\n");
        cliPrintf("rnsd link <dest_hash> [aspect]   outbound Link probe (Phase B)\n");
        cliPrintf("rnsd link teardown               drop the active probe link\n");
        cliPrintf("rnsd links                       pending/active Link table sizes\n");
        cliPrintf("rnsd clink <dest_hash> [aspect]  Phase C consumer-API link\n");
        cliPrintf("rnsd clink send <text> | close\n");
        cliPrintf("rnsd creq <dest_hash> <path>     request/response smoke (nomad)\n");
        cliPrintf("(see also: rnstatus, rnpath, rnprobe)\n");
        return;
    }
    if (!args || !*args) {
        if (s_identity) cliPrintf("identity: %s\n", s_identity->hexhash().c_str());
        else            cliPrintf("identity: not loaded\n");
        cliPrintf("transport: %s\n", storageGetInt("s.rnsd.transport_enabled", 0) ? "enabled" : "disabled");
        cliPrintf("pending_links: %zu\n", RNS::Transport::pending_links_count());
        cliPrintf("active_links:  %zu\n", RNS::Transport::active_links_count());
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
    if (strcmp(args, "memory") == 0 || strcmp(args, "mem") == 0) {
        cliRnsdMemory();
        return;
    }
    if (strncmp(args, "link", 4) == 0 && (args[4] == 0 || args[4] == ' ')) {
        const char* rest = args + 4;
        while (*rest == ' ') rest++;
        if (!*rest) {
            cliPrintf("usage: rnsd link <dest_hash> [aspect]\n");
            cliPrintf("rnsd link teardown\n");
            cliPrintf("default aspect: rnstransport.probe\n");
            return;
        }
        /* Hand off to the rnsd task via storage subscriber. CLI prints
         * the queue ack; subsequent state transitions land in the log. */
        storageSet("rnsd.cmd.link.open", rest);
        cliPrintf("rnsd link: queued (%s) — watch log for state transitions\n", rest);
        return;
    }
    if (strcmp(args, "links") == 0) {
        cliPrintf("pending_links: %zu\n", RNS::Transport::pending_links_count());
        cliPrintf("active_links:  %zu\n", RNS::Transport::active_links_count());
        return;
    }
    if (strncmp(args, "clink", 5) == 0 && (args[5] == 0 || args[5] == ' ')) {
        const char* rest = args + 5;
        while (*rest == ' ') rest++;
        if (!*rest) {
            cliPrintf("usage: rnsd clink <dest_hash> [aspect]   — Phase C outbound link\n");
            cliPrintf("rnsd clink send <text>\n");
            cliPrintf("rnsd clink close\n");
            cliPrintf("rnsd clink listen <aspect>        — Phase D: host dest, accept inbound Links\n");
            cliPrintf("rnsd clink listen off\n");
            cliPrintf("default aspect: lxmf.delivery; watch rnsd.links.* / log\n");
            return;
        }
        storageSet("rnsd.cmd.clink", rest);
        cliPrintf("rnsd clink: queued (%s) — watch rnsd.links.clink.* and log\n", rest);
        return;
    }
    if (strncmp(args, "creq", 4) == 0 && (args[4] == 0 || args[4] == ' ')) {
        const char* rest = args + 4;
        while (*rest == ' ') rest++;
        if (!*rest) {
            cliPrintf("usage: rnsd creq <dest_hash> <path> [aspect]  — Phase 0 request smoke\n");
            cliPrintf("opens a Link + link.request(path), logs the response bytes\n");
            cliPrintf("default aspect: nomadnetwork.node\n");
            cliPrintf("e.g. rnsd creq <hash> /page/index.mu\n");
            return;
        }
        storageSet("rnsd.cmd.creq", rest);
        cliPrintf("rnsd creq: queued (%s) — watch log for response\n", rest);
        return;
    }
    cliPrintf("unknown subcommand. try `rnsd -h`\n");
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

    /* `help` listing → one line; `-h`/`--help` → detail. */
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("%-*s routing paths\n", CLI_HELP_COL, "rnpath [destination]");
        return;
    }

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            std::string t = rnpathNextToken(a, &i);
            if (t.empty()) break;
            if      (t == "-h" || t == "--help")        show_help = true;
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
        cliPrintf("%-*s routing paths\n", CLI_HELP_COL, "rnpath [destination]");
        cliPrintf("-i iface     filter by interface\n");
        cliPrintf("-m hops      filter by max hops\n");
        cliPrintf("-n N         row limit (default %d)\n", RNPATH_DEFAULT_LIMIT);
        cliPrintf("-a --all     no row limit\n");
        cliPrintf("-s --summary counts only, no rows\n");
        cliPrintf("-d --drop    drop path to destination\n");
        cliPrintf("-j --json    JSON output\n");
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

    cliPrintf("by iface:");
    for (auto& kv : by_iface) cliPrintf("  %s %d", kv.first.c_str(), kv.second);
    cliPrintf("\nby hops: ");
    for (auto& kv : by_hops)  cliPrintf("  %d:%d", kv.first, kv.second);
    cliPrintf("\n");

    if (summary || rows.empty()) return;

    int to_show = show_all ? (int)rows.size() : std::min((int)rows.size(), limit);
    if (to_show < (int)rows.size())
        cliPrintf("\n(showing %d of %d, use -a or -n N for more)\n", to_show, (int)rows.size());
    cliPrintf("\n%-32s %-32s %-16s %-5s %-8s\n",
              "destination", "next hop", "iface", "hops", "age");

    double now = RNS::Utilities::OS::time();
    for (int n = 0; n < to_show; n++) {
        cliPrintf("%-32s %-32s %-16s %-5d %lus\n",
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
    cliPrintf("Transport    %s\n", tx_en ? "enabled" : "disabled");
    cliPrintf("Interfaces   %d up\n", countActiveIfaces());
}

static void rnstatusPrintIface(const iface_t& i)
{
    cliPrintf("\n%s\n", i.info.name);
    cliPrintf("Status       up\n");
    cliPrintf("Mode         %s\n", mode_name(i.info.mode));
    cliPrintf("MTU          %u\n", (unsigned)i.info.mtu);
    cliPrintf("Bitrate      %s\n", formatBitrate(i.info.bitrate).c_str());
    cliPrintf("Traffic      %s in / %s out  (%llu pkt in / %llu out)\n",
              formatBytes(i.rx_bytes).c_str(),
              formatBytes(i.tx_bytes).c_str(),
              (unsigned long long)i.rx_packets,
              (unsigned long long)i.tx_packets);
}

static void rnstatusPrintTotals(void)
{
    cliPrintf("\nTotals\n");
    cliPrintf("Packets      %llu in / %llu out\n",
              (unsigned long long)s_stats.packets_in,
              (unsigned long long)s_stats.packets_out);
    cliPrintf("Bytes        %s in / %s out\n",
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

    /* `help` listing → one line. `-h`/`--help` → detail (handled below). */
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("%-*s interfaces & traffic\n", CLI_HELP_COL, "rnstatus [filter] [-t] [-j]");
        return;
    }

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            while (i < a.size() && (a[i] == ' ' || a[i] == '\t')) i++;
            if (i >= a.size()) break;
            size_t s = i;
            while (i < a.size() && a[i] != ' ' && a[i] != '\t') i++;
            std::string t = a.substr(s, i - s);
            if      (t == "-h" || t == "--help")   show_help = true;
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
        cliPrintf("%-*s interfaces & traffic\n", CLI_HELP_COL, "rnstatus [filter]");
        cliPrintf("%-*s global traffic totals\n", CLI_HELP_COL, "  -t  --totals");
        cliPrintf("%-*s JSON output\n", CLI_HELP_COL, "  -j  --json");
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

    /* `help` listing → one line; `-h`/`--help` (or missing args) → detail. */
    if (args && strcmp(args, "help") == 0) {
        cliPrintf("%-*s probe destination, measure RTT\n", CLI_HELP_COL, "rnprobe [aspect] <hash>");
        return;
    }

    if (args && *args) {
        std::string a = args;
        size_t i = 0;
        while (i < a.size()) {
            std::string t = rnpathNextToken(a, &i);
            if (t.empty()) break;
            if      (t == "-h" || t == "--help")     show_help = true;
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
        cliPrintf("%-*s probe destination, measure RTT\n", CLI_HELP_COL, "rnprobe [aspect] <hash>");
        cliPrintf("aspect    default: rnstransport.probe\n");
        cliPrintf("-s SIZE   payload bytes (default %d)\n", RNPROBE_DEFAULT_SIZE);
        cliPrintf("-n N      probe count (only 1 supported for now)\n");
        cliPrintf("-t SECS   timeout (default %d)\n", RNPROBE_DEFAULT_TIMEOUT);
        cliPrintf("-w SECS   interval between probes\n");
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
                        cliPrintf("requesting path...\n");
                        break;
                    case RNSD_DEST_AUX_EGRESS_QUEUED:
                        cliPrintf("egress queued\n");
                        break;
                    case RNSD_DEST_AUX_RETRY:
                        if (got >= 6)
                            cliPrintf("retry (attempt %u, reason 0x%02x)\n",
                                      (unsigned)buf[4], (unsigned)buf[5]);
                        else
                            cliPrintf("retry\n");
                        break;
                    default:
                        cliPrintf("status 0x%02x\n", (unsigned)type);
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

int rnsdLinkOpen(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                 const char*   aspect,
                 const char*   identity_key,
                 const char*   tag,
                 uint32_t      path_timeout_ms,
                 int           ref,
                 void (*on_recv)(int, size_t),
                 void (*on_disconnect)(int))
{
    if (!aspect || !*aspect) { warn("rnsdLinkOpen: aspect required"); return -1; }
    if (!tag || !*tag)       { warn("rnsdLinkOpen: tag required");    return -1; }
    rnsd_link_connect_t req = {};
    memcpy(req.dest_hash, dest_hash, RNSD_DEST_HASH_LEN);
    safeStrncpy(req.aspect, aspect, sizeof(req.aspect));
    safeStrncpy(req.tag, tag, sizeof(req.tag));
    if (identity_key && *identity_key)
        safeStrncpy(req.identity_key, identity_key, sizeof(req.identity_key));
    req.path_timeout_ms = path_timeout_ms;
    return itsConnect("rnsd", RNSD_PORT_LINK,
                      &req, sizeof(req), pdMS_TO_TICKS(2000),
                      ref, on_recv, on_disconnect);
}

bool rnsdLinkTeardown(const char* tag)
{
    if (!tag || !*tag) { warn("rnsdLinkTeardown: tag required"); return false; }
    uint8_t buf[1 + 24];
    buf[0] = RNSD_LINK_AUX_TEARDOWN;
    size_t tl = strnlen(tag, 23);
    memcpy(buf + 1, tag, tl);
    return itsSendAux("rnsd", RNSD_PORT_LINK, buf, 1 + tl,
                      pdMS_TO_TICKS(500));
}

bool rnsdLinkSendResource(const char* tag, void* buf, size_t len,
                          uint32_t opaque_id)
{
    if (!tag || !*tag || !buf || len == 0) {
        warn("rnsdLinkSendResource: bad args");
        if (buf) free(buf);
        return false;
    }
    rnsd_link_send_resource_t p = {};
    p.op = RNSD_LINK_AUX_SEND_RESOURCE;
    safeStrncpy(p.tag, tag, sizeof(p.tag));
    p.buf       = buf;          /* ownership transfers to rnsd */
    p.len       = (uint32_t)len;
    p.opaque_id = opaque_id;
    bool ok = itsSendAux("rnsd", RNSD_PORT_LINK, &p, sizeof(p),
                         pdMS_TO_TICKS(1000));
    if (!ok) {
        warn("rnsdLinkSendResource: aux send failed, freeing buf");
        free(buf);
    }
    return ok;
}

int rnsdLinkRequest(const char* tag, const char* path,
                    const void* data, size_t data_len,
                    uint16_t resp_port, bool data_packed)
{
    if (!tag || !*tag || !path) { warn("rnsdLinkRequest: bad args"); return -1; }
    if (!data) data_len = 0;
    size_t path_len = strlen(path);
    if (path_len > 0xffff || data_len > 0xffff) {
        warn("rnsdLinkRequest: path/data too long");
        return -1;
    }
    size_t total = sizeof(rnsd_link_request_t) + path_len + data_len;
    if (total > ITS_MAX_MSG_DATA) {
        warn("rnsdLinkRequest: inline payload too large (%zu > %d)",
             total, (int)ITS_MAX_MSG_DATA);
        return -1;
    }

    /* Monotonic correlation id. Single-byte-wraps are fine: it only has to
     * be unique among a consumer's in-flight requests (one per link in v1). */
    static uint16_t s_req_seq = 0;
    uint16_t req_id = ++s_req_seq;
    if (req_id == 0) req_id = ++s_req_seq;   /* never hand out 0 */

    uint8_t buf[ITS_MAX_MSG_DATA];
    rnsd_link_request_t hdr = {};
    hdr.op        = RNSD_LINK_AUX_REQUEST;
    safeStrncpy(hdr.tag, tag, sizeof(hdr.tag));
    hdr.req_id    = req_id;
    hdr.resp_port = resp_port;
    hdr.path_len  = (uint16_t)path_len;
    hdr.data_len  = (uint16_t)data_len;
    hdr.data_packed = data_packed ? 1 : 0;
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), path, path_len);
    if (data_len) memcpy(buf + sizeof(hdr) + path_len, data, data_len);

    if (!itsSendAux("rnsd", RNSD_PORT_LINK, buf, total, pdMS_TO_TICKS(1000))) {
        warn("rnsdLinkRequest: aux send failed");
        return -1;
    }
    return (int)req_id;
}

void rnsdResourceRelease(void* buf)
{
    if (buf) free(buf);
}

bool rnsdDestListenLinks(int dest_handle, uint16_t target_port)
{
    if (dest_handle < 0 || target_port == 0) {
        warn("rnsdDestListenLinks: bad args");
        return false;
    }
    /* In-band frame on the existing RNSD_PORT_DEST handle (§7.1) — rnsd
     * already knows the owning task via itsRemoteTask(handle), so the
     * frame only carries the inbox port. The act of sending it on a
     * handle you own proves you own the destination. */
    uint8_t f[3] = {
        RNSD_DEST_LINK_LISTEN,
        (uint8_t)(target_port >> 8),
        (uint8_t)(target_port & 0xFF),
    };
    return itsSend(dest_handle, f, sizeof(f), pdMS_TO_TICKS(500)) == sizeof(f);
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

/* ─────────────── one-shot Link probe (Phase B §5.1.6) ───────────────
 *
 * `rnsd link <hash> [aspect]` triggers an outbound Link establishment to
 * the named destination, with state transitions logged via info(). This
 * is the device-side counterpart to scripts/link-probe (which exercises
 * the inbound path). It deliberately skips the eventual rnsdLinkOpen()
 * consumer API (Phase C) — Phase B is just about getting establishment
 * to work end-to-end, so we hold one Link in a static slot and report.
 *
 * `rnsd link teardown` drops the active probe link (if any). Without
 * that, a stuck-in-PENDING link stays until mR's stale-time cull. */

static RNS::Link s_probe_link{RNS::Type::NONE};

static void onProbeLinkEstablished(RNS::Link& link)
{
    /* link.link_id() and friends are valid only once ACTIVE, hence the
     * full dump on this callback. RTT comes from the LRPROOF round-trip. */
    info("rnsd link: ESTABLISHED link_id=%s mtu=%u rtt=%.3fs",
         link.link_id().toHex().c_str(),
         (unsigned)link.get_mtu(),
         link.rtt());

    /* Phase B §5.1.6: send one test packet on establish so we exercise the
     * encrypted send path and (for an echo-style peer) get a reply on the
     * packet callback. RNS::Packet(link, payload).send() per upstream's
     * Link API — Link::send is not a member, that's the Packet ctor that
     * branches on its destination's type (Link vs SINGLE). */
    try {
        static const RNS::Bytes probe_payload =
            RNS::Bytes((const uint8_t*)"reticulous probe", 16);
        RNS::Packet pkt(link, probe_payload);
        pkt.send();
        info("rnsd link: sent test packet (16B)");
    } catch (const std::exception& e) {
        warn("rnsd link: test send threw: %s", e.what());
    }
}

static void onProbeLinkClosed(RNS::Link& link)
{
    info("rnsd link: CLOSED reason=%u",
         (unsigned)link.teardown_reason());
    /* Single-slot design — clear unconditionally so the next `rnsd link
     * <hash>` doesn't trip the "previous probe link still exists" branch.
     * Comparing &link == &s_probe_link wouldn't work: mR copies Link
     * wrappers into its tables (shared_ptr backed), so the callback runs
     * with a different wrapper address even when the underlying state is
     * ours. */
    s_probe_link = RNS::Link{RNS::Type::NONE};
}

static void onProbeLinkPacket(const RNS::Bytes& plaintext,
                              const RNS::Packet& /*packet*/)
{
    size_t n = plaintext.size();
    size_t show = n < 32 ? n : 32;
    info("rnsd link: PKT %zuB head=%s%s",
         n,
         RNS::Bytes(plaintext.data(), show).toHex().c_str(),
         n > show ? "…" : "");
}

/* Subscription handler for `rnsd link <hash> [aspect]`. Runs on rnsd's
 * task — mR's Link constructor takes Transport state and the callbacks
 * fire on the rnsd task too, so we must build the Link here, not on CLI. */
static void onCmdLinkOpen(const char* key, const char* val)
{
    if (!val || !*val) { storageUnset(key); return; }

    std::string cmd = val;
    storageUnset(key);  /* consume — single-shot */

    /* Special verb: teardown the active probe link. */
    if (cmd == "teardown") {
        if (!s_probe_link) {
            info("rnsd link: no active probe link to tear down");
            return;
        }
        try {
            s_probe_link.teardown();
            info("rnsd link: teardown requested");
        } catch (const std::exception& e) {
            warn("rnsd link: teardown threw: %s", e.what());
        }
        s_probe_link = RNS::Link{RNS::Type::NONE};
        return;
    }

    /* Parse: "<32-hex> [<aspect>]" */
    std::string hash_hex, aspect = "rnstransport.probe";
    size_t sp = cmd.find(' ');
    if (sp == std::string::npos) {
        hash_hex = cmd;
    } else {
        hash_hex = cmd.substr(0, sp);
        aspect   = cmd.substr(sp + 1);
        while (!aspect.empty() && aspect[0] == ' ') aspect.erase(0, 1);
    }

    if (hash_hex.size() != RNSD_DEST_HASH_LEN * 2) {
        warn("rnsd link: bad hash length (got %zu, need %u)",
             hash_hex.size(), (unsigned)(RNSD_DEST_HASH_LEN * 2));
        return;
    }

    RNS::Bytes dh;
    try { dh.assignHex((const uint8_t*)hash_hex.c_str(), hash_hex.size()); }
    catch (...) { warn("rnsd link: bad hash hex"); return; }
    if (dh.size() != RNSD_DEST_HASH_LEN) {
        warn("rnsd link: bad hash bytes");
        return;
    }

    /* Aspect format mirrors what mailbox does (rnsd.cpp ~line 538): split
     * at first dot → app_name + aspects. "rnstransport.probe" → app
     * "rnstransport" aspect "probe"; "lxmf.delivery" → "lxmf"/"delivery". */
    std::string app_name = aspect, aspects;
    auto dot = aspect.find('.');
    if (dot != std::string::npos) {
        app_name = aspect.substr(0, dot);
        aspects  = aspect.substr(dot + 1);
    }

    /* Recall identity; if absent, request a path and tell the user to retry
     * once the announce lands. Asynchronous path waits don't belong in a
     * storage subscriber — keep this side simple. */
    RNS::Identity target = RNS::Identity::recall(dh);
    if (!target) {
        info("rnsd link: no identity cached for %s, requesting path — retry once announced",
             hash_hex.c_str());
        try { RNS::Transport::request_path(dh); }
        catch (const std::exception& e) {
            warn("rnsd link: request_path threw: %s", e.what());
        }
        return;
    }

    if (s_probe_link) {
        warn("rnsd link: previous probe link still exists, replacing");
        try { s_probe_link.teardown(); } catch (...) {}
        s_probe_link = RNS::Link{RNS::Type::NONE};
    }

    try {
        RNS::Destination out_dest(target,
                                  RNS::Type::Destination::OUT,
                                  RNS::Type::Destination::SINGLE,
                                  app_name.c_str(), aspects.c_str());
        info("rnsd link: opening Link → %s aspect=%s",
             hash_hex.c_str(), aspect.c_str());
        s_probe_link = RNS::Link(out_dest);
        s_probe_link.set_link_established_callback(onProbeLinkEstablished);
        s_probe_link.set_link_closed_callback(onProbeLinkClosed);
        s_probe_link.set_packet_callback(onProbeLinkPacket);
    } catch (const std::exception& e) {
        warn("rnsd link threw: %s", e.what());
        s_probe_link = RNS::Link{RNS::Type::NONE};
    }
}

/* ─────────────── Phase C: RNSD_PORT_LINK outbound consumer API ───────────────
 *
 * docs/plans/link.md §6. Consumers (lxmf in Phase E, CLI tools) call
 * rnsdLinkOpen() → itsConnect(RNSD_PORT_LINK) with an rnsd-private
 * rnsd_link_connect_t. The connect accepts immediately; the Link
 * establishes asynchronously on the rnsd task. Per-link progress is
 * published to the ephemeral rnsd.links.<tag>.* tree (browser-synced
 * for free via storage's empty-prefix subscriber). Slot↔Link is
 * resolved by shared-LinkData pointer identity, not wrapper address —
 * mR passes Link wrapper *copies* into callbacks; copies share the
 * shared_ptr<LinkData> and the public operator< compares _object.get().
 * See memory project_link_slot_mapping; refines §6.2 / decision #8.
 *
 * §10a.1 in-session consumer reconnect (re-attach a live Link to a
 * returning consumer) is intentionally deferred: lxmf (Phase E) is the
 * first reconnecting consumer and the plan treats 10a as cross-cutting
 * C/D/E. Consumer disconnect here parks the Link for orphan_ttl then
 * tears it down — it never silently dies with the handle. */

enum link_state_t : uint8_t {
    LST_FREE = 0, LST_AWAITING_PATH, LST_ESTABLISHING,
    LST_ACTIVE, LST_CLOSING, LST_CLOSED, LST_FAILED
};

static const char* lstName(link_state_t s)
{
    switch (s) {
        case LST_AWAITING_PATH: return "awaiting_path";
        case LST_ESTABLISHING:  return "establishing";
        case LST_ACTIVE:        return "active";
        case LST_CLOSING:       return "closing";
        case LST_CLOSED:        return "closed";
        case LST_FAILED:        return "failed";
        default:                return "free";
    }
}

struct link_conn_t {
    bool                 used;
    int                  handle;        /* -1 once consumer disconnected */
    int                  ref;           /* opaque, echoed to ITS callbacks */
    char                 tag[24];
    RNS::Bytes           dest_hash;
    std::string          aspect;
    std::string          identity_key;
    link_state_t         state;
    RNS::Link            link{RNS::Type::NONE};
    double               opened_at;     /* OS::time() */
    double               last_activity; /* OS::time() of last open/establish/traffic — LRU eviction key */
    double               path_deadline; /* OS::time() a path must answer by */
    double               estab_deadline;/* OS::time() ACTIVE must arrive by */
    double               orphan_at;     /* OS::time() consumer left; 0 = attached */
    double               dead_at;       /* OS::time() entered CLOSED/FAILED; 0 = n/a */
    bool                 pend_used;     /* one-packet pre-active outbox */
    std::vector<uint8_t> pend_bytes;

    /* Phase F resource transfer (link.md §9). One in-flight resource
     * per link in v1 (the §9.5 soak is sequential). consumer_task is
     * where the rnsd_link_resource_done_t aux is delivered. */
    TaskHandle_t         consumer_task; /* lxmf task for the §9.1 aux */
    RNS::Bytes           res_hash;      /* in-flight resource_hash; empty = idle */
    bool                 res_outbound;  /* true = we are sending it */
    uint32_t             res_opaque;    /* outbound: caller correlation id */

    /* Pre-active outbound-Resource deferral: rnsdLinkSendResource may
     * arrive before the async link reaches ACTIVE (lxmf opens the link
     * then immediately sends). Hold the buffer and start the Resource
     * from onLinkEstablishedCb — mirrors the one-packet pend_* outbox. */
    bool                 pend_res_used;
    void*                pend_res_buf;
    uint32_t             pend_res_len;
    uint32_t             pend_res_opaque;

    /* Request/response (nomad page fetch, nomad.md §1). One in-flight
     * request per link (v1). req_mrid is µR's RequestReceipt request_id —
     * the response/failed callbacks have no userdata, so the slot is
     * resolved by matching it (linkFindByReqMrid), the same trick the
     * Resource path uses with res_hash. req_cid/req_port/req_task are the
     * consumer's correlation id + where to deliver the response aux. */
    RNS::Bytes           req_mrid;       /* empty = idle */
    uint16_t             req_cid;
    uint16_t             req_port;
    TaskHandle_t         req_task;
    double               req_deadline;   /* OS::time() response must arrive by; 0 = n/a */

    /* Pre-active request deferral — held request issued on establish
     * (mirrors pend_res_*). One pending request. */
    bool                 pend_req_used;
    std::string          pend_req_path;
    std::vector<uint8_t> pend_req_data;
    uint16_t             pend_req_cid;
    uint16_t             pend_req_port;
    TaskHandle_t         pend_req_task;
    bool                 pend_req_packed;
};

static link_conn_t* s_link_conns = nullptr;

/* Count active link-consumer slots — for the `rnsd memory` breakdown,
 * which is defined earlier than s_link_conns. */
static int rnsdLinkConnsUsed() {
    int n = 0;
    if (s_link_conns)
        for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)
            if (s_link_conns[j].used) n++;
    return n;
}

/* Two Link wrappers reference the same underlying LinkData iff neither
 * orders before the other under mR's public operator< (which compares
 * _object.get()). Works in every state — link_id is empty on a failed
 * establishment, the shared_ptr identity is not. */
static inline bool sameLink(const RNS::Link& a, const RNS::Link& b)
{
    return a && b && !(a < b) && !(b < a);
}

static link_conn_t* linkFindByHandle(int handle)
{
    if (handle < 0) return nullptr;
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)
        if (s_link_conns[j].used && s_link_conns[j].handle == handle)
            return &s_link_conns[j];
    return nullptr;
}

static link_conn_t* linkFindByLink(const RNS::Link& l)
{
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++) {
        link_conn_t& c = s_link_conns[j];
        if (c.used && c.link && sameLink(c.link, l)) return &c;
    }
    return nullptr;
}

static link_conn_t* linkFindByTag(const char* tag)
{
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)
        if (s_link_conns[j].used && strcmp(s_link_conns[j].tag, tag) == 0)
            return &s_link_conns[j];
    return nullptr;
}

static void linkFreeSlot(link_conn_t& c);   /* defined below */

static inline void linkTouch(link_conn_t& c)
{
    c.last_activity = RNS::Utilities::OS::time();
}

static link_conn_t* linkAlloc(void)
{
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)
        if (!s_link_conns[j].used) return &s_link_conns[j];
    /* Table full — evict the longest-idle link rather than refuse a new one.
     * linkFreeSlot tears the victim down cleanly: cascades a disconnect to
     * its consumer and fails any outstanding request, so the consumer learns
     * its link went away instead of hanging. */
    int    victim = -1;
    double oldest = 0;
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++) {
        if (!s_link_conns[j].used) continue;
        if (victim < 0 || s_link_conns[j].last_activity < oldest) {
            oldest = s_link_conns[j].last_activity;
            victim = j;
        }
    }
    if (victim < 0) return nullptr;
    link_conn_t& v = s_link_conns[victim];
    info("link[%s]: evicting longest-idle (link slot table full)", v.tag);
    try { if (v.link) v.link.teardown(); } catch (...) {}
    v.link = RNS::Link{RNS::Type::NONE};
    linkFreeSlot(v);
    return &s_link_conns[victim];
}

/* rnsd.links.<tag>.<field> — segments are well under the 95-char cap. */
static void linkKey(const link_conn_t& c, const char* field,
                    char* out, size_t n)
{
    snprintf(out, n, "rnsd.links.%s.%s", c.tag, field);
}

static void linkSetStr(const link_conn_t& c, const char* field, const char* v)
{
    char k[96];
    linkKey(c, field, k, sizeof(k));
    storageSet(k, v);
}

static void linkSetInt(const link_conn_t& c, const char* field, int v)
{
    char k[96];
    linkKey(c, field, k, sizeof(k));
    storageSet(k, v);
}

static void linkPublishState(link_conn_t& c)
{
    linkSetStr(c, "state", lstName(c.state));
}

static void linkSetError(link_conn_t& c, const char* err_msg)
{
    linkSetStr(c, "last_error", err_msg);
}

/* Resolve our local identity for the OUT destination. Mirrors the
 * mailbox path: identity_key or the rnsd default. */
static bool linkLoadIdentity(const std::string& identity_key, RNS::Identity& out)
{
    const char* key = !identity_key.empty()
                     ? identity_key.c_str() : "secrets.rnsd.identity";
    char hex[160] = {};
    storageGetStr(key, hex, sizeof(hex), "");
    if (strlen(hex) != 128) {
        warn("link: no identity at %s", key);
        return false;
    }
    RNS::Bytes prv;
    prv.assignHex((const uint8_t*)hex, 128);
    if (prv.size() != 64) { warn("link: bad identity hex at %s", key); return false; }
    RNS::Identity id(false);
    if (!id.load_private_key(prv)) {
        warn("link: identity load failed for %s", key);
        return false;
    }
    out = id;
    return true;
}

/* Defined below; needed here by linkStartOutboundResource. */
static void onResConcluded(const RNS::Resource& r);
static void resSendAux(link_conn_t& c, uint8_t opcode,
                       void* buf, uint32_t len, uint8_t flags);

/* Defined below (request/response block); needed here by
 * onLinkEstablishedCb to flush a request deferred before ACTIVE. */
static void linkStartRequest(link_conn_t& c, const std::string& path,
                             const std::vector<uint8_t>& data,
                             uint16_t cid, uint16_t port, TaskHandle_t task,
                             bool data_packed);

/* Construct + advertise an outbound Resource on an ACTIVE link from a
 * caller-owned buffer. The engine encrypts/chunks (copies) at
 * construction, registers on the link's outgoing set and advertises,
 * so the buffer is freed immediately after. Used by onLinkAux (link
 * already active) and onLinkEstablishedCb (deferred pre-active send). */
static void linkStartOutboundResource(link_conn_t& c, void* buf,
                                      uint32_t reqlen, uint32_t opaque)
{
    if (c.res_hash.size()) {
        warn("link[%s]: resource already in flight, dropping send", c.tag);
        if (buf) free(buf);
        return;
    }
    try {
        RNS::Resource res(RNS::Bytes((const uint8_t*)buf, reqlen),
                          c.link, /*advertise=*/true,
                          /*auto_compress=*/false,
                          /*concluded=*/onResConcluded,
                          /*progress=*/nullptr);
        if (buf) free(buf);
        c.res_hash     = res.hash();
        c.res_outbound = true;
        c.res_opaque   = opaque;
        char k[96];
        linkKey(c, "resource.state", k, sizeof(k)); storageSet(k, "sending");
        linkKey(c, "resource.size",  k, sizeof(k)); storageSet(k, (int)reqlen);
        info("link[%s]: sending %uB resource (opaque=%u)",
             c.tag, (unsigned)reqlen, (unsigned)opaque);
    } catch (const std::exception& e) {
        warn("link[%s]: resource send threw: %s", c.tag, e.what());
        if (buf) free(buf);
        resSendAux(c, RNSD_LINK_RESOURCE_FAILED, nullptr, 0, 0);
    }
}

static void onLinkEstablishedCb(RNS::Link& link)
{
    link_conn_t* c = linkFindByLink(link);
    if (!c) { warn("link: established cb, no slot"); return; }

    c->state         = LST_ACTIVE;
    c->orphan_at     = 0;
    c->estab_deadline = 0;
    linkTouch(*c);
    std::string lid  = link.link_id().toHex();
    info("link[%s]: ACTIVE link_id=%s mtu=%u rtt=%.3fs",
         c->tag, lid.c_str(), (unsigned)link.get_mtu(), link.rtt());

    linkSetStr(*c, "link_id", lid.c_str());
    linkSetInt(*c, "mtu", (int)link.get_mtu());
    linkSetInt(*c, "rtt_ms", (int)(link.rtt() * 1000.0));
    linkSetInt(*c, "activated_s", (int)RNS::Utilities::OS::time());
    linkPublishState(*c);
    /* Reverse index for inbound/link_id-only lookups (Phase D uses it). */
    {
        char k[96];
        snprintf(k, sizeof(k), "rnsd.links.byid.%s", lid.c_str());
        storageSet(k, c->tag);
    }

    /* Flush the one-packet pre-active outbox. */
    if (c->pend_used) {
        try {
            RNS::Packet pkt(c->link,
                            RNS::Bytes(c->pend_bytes.data(), c->pend_bytes.size()));
            pkt.send();
            linkSetInt(*c, "tx_packets", 1);
            linkSetInt(*c, "last_outbound_s", (int)RNS::Utilities::OS::time());
            info("link[%s]: flushed queued %zuB on establish",
                 c->tag, c->pend_bytes.size());
        } catch (const std::exception& e) {
            warn("link[%s]: flush send threw: %s", c->tag, e.what());
            linkSetError(*c, "flush_failed");
        }
        c->pend_used = false;
        c->pend_bytes.clear();
    }

    /* Flush a deferred outbound Resource (rnsdLinkSendResource that
     * arrived before the link was ACTIVE). */
    if (c->pend_res_used) {
        c->pend_res_used = false;
        linkStartOutboundResource(*c, c->pend_res_buf,
                                  c->pend_res_len, c->pend_res_opaque);
        c->pend_res_buf = nullptr;
        c->pend_res_len = 0;
        c->pend_res_opaque = 0;
    }

    /* Flush a deferred request (rnsdLinkRequest before ACTIVE). */
    if (c->pend_req_used) {
        c->pend_req_used = false;
        linkStartRequest(*c, c->pend_req_path, c->pend_req_data,
                         c->pend_req_cid, c->pend_req_port, c->pend_req_task,
                         c->pend_req_packed);
        c->pend_req_path.clear();
        c->pend_req_data.clear();
        c->pend_req_task = nullptr;
        c->pend_req_packed = false;
    }
}

static void onLinkClosedCb(RNS::Link& link)
{
    link_conn_t* c = linkFindByLink(link);
    if (!c) return;   /* already culled */
    unsigned reason = (unsigned)link.teardown_reason();
    info("link[%s]: CLOSED reason=%u", c->tag, reason);
    c->state   = LST_CLOSED;
    c->dead_at = RNS::Utilities::OS::time();
    if (reason == (unsigned)RNS::Type::Link::TIMEOUT)
        linkSetError(*c, "timeout");
    else if (reason == (unsigned)RNS::Type::Link::DESTINATION_CLOSED)
        linkSetError(*c, "remote_closed");
    linkPublishState(*c);
    /* Release the mR wrapper now; slot + storage tree are reclaimed
     * after a short grace window by linkTick so subscribers observe
     * the "closed" transition first. */
    c->link = RNS::Link{RNS::Type::NONE};
}

static void onLinkPacketCb(const RNS::Bytes& plaintext, const RNS::Packet& packet)
{
    /* No Link arg on this callback; Transport stamped packet.link()
     * with the matched active Link just before link.receive(). */
    link_conn_t* c = linkFindByLink(packet.link());
    if (!c) { warn("link: inbound pkt, no slot"); return; }
    linkTouch(*c);
    if (c->handle < 0) return;   /* consumer detached; drop (orphan window) */
    /* Packet-mode handle: one Link plaintext = one ITS packet, no type
     * byte. Drop on back-pressure (timeout 0) rather than stall rnsd. */
    size_t w = itsSend(c->handle, plaintext.data(), plaintext.size(), 0);
    if (w == 0) {
        linkSetError(*c, "rx_overflow");
        return;
    }
    char k[96];
    linkKey(*c, "rx_packets", k, sizeof(k));
    storageSet(k, storageGetInt(k, 0) + 1);
    linkSetInt(*c, "last_inbound_s", (int)RNS::Utilities::OS::time());
}

/* ─────────────── Phase F: Resource transfer (link.md §9) ───────────────
 *
 * The Link's resource callbacks are plain C function pointers with no
 * userdata; we resolve the owning slot the same way the packet path
 * does — onResAdvertised gets adv.link (stamped by Link.cpp), and
 * onResConcluded matches r.hash() against the slot's in-flight
 * res_hash recorded at advertisement (inbound) or send (outbound). */

static link_conn_t* linkFindByResHash(const RNS::Bytes& h)
{
    if (h.size() == 0) return nullptr;
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++) {
        link_conn_t& c = s_link_conns[j];
        if (c.used && c.res_hash.size() && c.res_hash == h) return &c;
    }
    return nullptr;
}

/* One small ITS aux frame to the consumer's resource-aux port (§9.1). */
static void resSendAux(link_conn_t& c, uint8_t opcode,
                       void* buf, uint32_t len, uint8_t flags)
{
    if (!c.consumer_task) {
        warn("link[%s]: resource aux but no consumer task", c.tag);
        if (buf) free(buf);
        return;
    }
    rnsd_link_resource_done_t d = {};
    d.opcode = opcode;
    if (c.link && c.link.link_id().size() >= 16)
        memcpy(d.link_id, c.link.link_id().data(), 16);
    if (c.res_hash.size() >= 32) memcpy(d.resource_hash, c.res_hash.data(), 32);
    if (c.dest_hash.size() >= 16)
        memcpy(d.local_dest_hash, c.dest_hash.data(), 16);
    d.buf       = buf;
    d.len       = len;
    d.opaque_id = c.res_opaque;
    d.flags     = flags;
    if (!itsSendAuxByTaskHandle(c.consumer_task, LXMF_LINK_RESOURCE_AUX_PORT,
                                &d, sizeof(d), pdMS_TO_TICKS(2000))) {
        warn("link[%s]: resource aux send failed (op=%u)", c.tag, opcode);
        if (buf) free(buf);   /* consumer never took ownership */
    }
}

/* ACCEPT_APP gate. Returns true to accept the advertised resource. */
static bool onResAdvertised(const RNS::ResourceAdvertisement& adv)
{
    if (!adv.link) { warn("resource adv: no link"); return false; }
    link_conn_t* c = linkFindByLink(*adv.link);
    if (!c) { warn("resource adv: no slot"); return false; }

    if (c->res_hash.size()) {
        warn("link[%s]: resource already in flight, rejecting", c->tag);
        return false;
    }
    int total_inflight = 0;
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)
        if (s_link_conns[j].used && s_link_conns[j].res_hash.size())
            total_inflight++;
    if (total_inflight >= storageGetInt("s.rnsd.link.max_inbound_resources_total", 4)) {
        warn("link[%s]: inbound resource cap reached, rejecting", c->tag);
        return false;
    }
    uint32_t maxsz = (uint32_t)storageGetInt("s.lxmf.max_resource_size", 262144);
    if (adv.d > maxsz) {
        warn("link[%s]: resource %uB > max %uB, rejecting",
             c->tag, (unsigned)adv.d, (unsigned)maxsz);
        return false;
    }

    c->res_hash     = adv.h;
    c->res_outbound = false;
    c->res_opaque   = 0;
    char k[96];
    linkKey(*c, "resource.state", k, sizeof(k)); storageSet(k, "receiving");
    linkKey(*c, "resource.size",  k, sizeof(k)); storageSet(k, (int)adv.d);
    linkKey(*c, "resource.parts", k, sizeof(k)); storageSet(k, (int)adv.n);
    info("link[%s]: accepting resource %uB (%u parts)",
         c->tag, (unsigned)adv.d, (unsigned)adv.n);
    return true;
}

static void onResConcluded(const RNS::Resource& r)
{
    link_conn_t* c = linkFindByResHash(r.hash());
    if (!c) { warn("resource concluded: no slot for hash"); return; }

    bool ok = (r.status() == RNS::Type::Resource::COMPLETE);
    char k[96];
    if (ok && !c->res_outbound) {
        const RNS::Bytes& d = r.data();
        size_t len = d.size();
        void* buf = (len > 0) ? malloc(len) : nullptr;
        if (len > 0 && !buf) {
            warn("link[%s]: resource malloc %zuB failed", c->tag, len);
            resSendAux(*c, RNSD_LINK_RESOURCE_FAILED, nullptr, 0, 0);
        } else {
            if (len > 0) memcpy(buf, d.data(), len);
            linkKey(*c, "resource.state", k, sizeof(k));
            storageSet(k, "received");
            info("link[%s]: inbound resource complete %zuB → consumer",
                 c->tag, len);
            resSendAux(*c, RNSD_LINK_RESOURCE_INBOUND_DONE,
                       buf, (uint32_t)len, 0);
        }
    } else if (ok && c->res_outbound) {
        linkKey(*c, "resource.state", k, sizeof(k)); storageSet(k, "sent");
        info("link[%s]: outbound resource delivered (proof ok)", c->tag);
        resSendAux(*c, RNSD_LINK_RESOURCE_OUTBOUND_DONE, nullptr, 0, 0);
    } else {
        /* Encode the engine status so spangap-cli reveals the precise
         * outcome without device logs: 7=FAILED 8=CORRUPT 3=still
         * TRANSFERRING-when-concluded (timeout/cancel mid-flight). */
        char st[24];
        snprintf(st, sizeof(st), "failed:%s:%d",
                 c->res_outbound ? "out" : "in", (int)r.status());
        linkKey(*c, "resource.state", k, sizeof(k)); storageSet(k, st);
        warn("link[%s]: resource %s failed (status=%d)",
             c->tag, c->res_outbound ? "outbound" : "inbound",
             (int)r.status());
        resSendAux(*c, RNSD_LINK_RESOURCE_FAILED, nullptr, 0, 0);
    }
    c->res_hash     = RNS::Bytes();
    c->res_outbound = false;
    c->res_opaque   = 0;
}

/* Wire the resource strategy + callbacks onto a freshly-built Link.
 * ACCEPT_APP routes every advertisement through onResAdvertised's gate. */
static void linkWireResource(RNS::Link& link)
{
    try {
        link.set_resource_strategy(RNS::Type::Link::ACCEPT_APP);
        link.set_resource_callback(onResAdvertised);
        link.set_resource_concluded_callback(onResConcluded);
    } catch (const std::exception& e) {
        warn("link: resource wire threw: %s", e.what());
    }
}

/* ─────────────── nomad: request / response (nomad.md §1) ───────────────
 *
 * Bridges µR's Link::request(path, data) to the byte-array consumer
 * world. The consumer (nomad task; the `creq` smoke task here) calls
 * rnsdLinkRequest(tag, path, …) → RNSD_LINK_AUX_REQUEST aux → onLinkAux →
 * linkStartRequest, which issues the request with our static response /
 * failed thunks. µR's callbacks carry no userdata, so the owning slot is
 * resolved in the thunk by matching the RequestReceipt's request_id
 * against the slot's req_mrid (the same shared-identity trick the packet
 * and Resource paths use). Responses ride back to the consumer as a heap
 * buffer over one aux frame (rnsd_link_resource_done_t), exactly like an
 * inbound Resource — a page response can be large. */

static link_conn_t* linkFindByReqMrid(const RNS::Bytes& mrid)
{
    if (mrid.size() == 0) return nullptr;
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++) {
        link_conn_t& c = s_link_conns[j];
        if (c.used && c.req_mrid.size() && c.req_mrid == mrid) return &c;
    }
    return nullptr;
}

/* Deliver a request response/failure to the consumer's aux port. Mirrors
 * resSendAux but uses the per-request task+port captured at issue time
 * (the requester, which may differ from the link opener). */
static void reqSendAux(link_conn_t& c, uint8_t opcode, void* buf, uint32_t len)
{
    if (!c.req_task || c.req_port == 0) {
        warn("link[%s]: request aux but no consumer port", c.tag);
        if (buf) free(buf);
        return;
    }
    rnsd_link_resource_done_t d = {};
    d.opcode = opcode;
    if (c.link && c.link.link_id().size() >= 16)
        memcpy(d.link_id, c.link.link_id().data(), 16);
    if (c.req_mrid.size() >= 16) memcpy(d.resource_hash, c.req_mrid.data(), 16);
    if (c.dest_hash.size() >= 16) memcpy(d.local_dest_hash, c.dest_hash.data(), 16);
    d.buf       = buf;
    d.len       = len;
    d.opaque_id = c.req_cid;
    if (!itsSendAuxByTaskHandle(c.req_task, c.req_port, &d, sizeof(d),
                                pdMS_TO_TICKS(2000))) {
        warn("link[%s]: request aux send failed (op=%u)", c.tag, opcode);
        if (buf) free(buf);   /* consumer never took ownership */
    }
}

/* Fail a request before a slot is bound to it (unknown link, request
 * already in flight, request() threw) — we still owe the requester a
 * REQUEST_FAILED so it doesn't hang. */
static void reqFailDirect(TaskHandle_t task, uint16_t port, uint16_t cid)
{
    if (!task || port == 0) return;
    rnsd_link_resource_done_t d = {};
    d.opcode    = RNSD_LINK_REQUEST_FAILED;
    d.opaque_id = cid;
    itsSendAuxByTaskHandle(task, port, &d, sizeof(d), pdMS_TO_TICKS(500));
}

static void onReqResponseCb(const RNS::RequestReceipt& rr)
{
    link_conn_t* c = linkFindByReqMrid(rr.get_request_id());
    if (!c) { warn("link: request response, no slot"); return; }
    linkTouch(*c);
    RNS::Bytes resp = rr.get_response();
    size_t len = resp.size();
    void* buf = (len > 0) ? malloc(len) : nullptr;
    if (len > 0 && !buf) {
        warn("link[%s]: response malloc %zuB failed", c->tag, len);
        reqSendAux(*c, RNSD_LINK_REQUEST_FAILED, nullptr, 0);
    } else {
        if (len > 0) memcpy(buf, resp.data(), len);
        char k[96];
        linkKey(*c, "request.state", k, sizeof(k)); storageSet(k, "done");
        info("link[%s]: request response %zuB → consumer (cid=%u)",
             c->tag, len, (unsigned)c->req_cid);
        reqSendAux(*c, RNSD_LINK_REQUEST_RESPONSE, buf, (uint32_t)len);
    }
    c->req_mrid     = RNS::Bytes();
    c->req_deadline = 0;
}

static void onReqFailedCb(const RNS::RequestReceipt& rr)
{
    link_conn_t* c = linkFindByReqMrid(rr.get_request_id());
    if (!c) return;
    char k[96];
    linkKey(*c, "request.state", k, sizeof(k)); storageSet(k, "failed");
    warn("link[%s]: request failed (cid=%u)", c->tag, (unsigned)c->req_cid);
    reqSendAux(*c, RNSD_LINK_REQUEST_FAILED, nullptr, 0);
    c->req_mrid     = RNS::Bytes();
    c->req_deadline = 0;
}

/* Issue link.request on an ACTIVE link. Forward-declared above. */
static void linkStartRequest(link_conn_t& c, const std::string& path,
                             const std::vector<uint8_t>& data,
                             uint16_t cid, uint16_t port, TaskHandle_t task,
                             bool data_packed)
{
    if (c.req_mrid.size()) {
        warn("link[%s]: request already in flight, dropping (cid=%u)",
             c.tag, (unsigned)cid);
        reqFailDirect(task, port, cid);
        return;
    }
    try {
        RNS::Bytes path_b((const uint8_t*)path.data(), path.size());
        /* Empty data → a plain GET. NOTE: the MsgPack shim packs an empty
         * Bytes as an empty bin (0xc4 0x00), not msgpack nil. Real
         * NomadNet static-page handlers ignore the request-data element,
         * so a GET interops; if a desktop node is found to require nil for
         * the data-less case, pack nil in Link::request — a documented
         * Phase-0 HW follow-up (nomad.md §"What µR already gives us").
         * When data_packed, `data` is a complete msgpack object (form map)
         * spliced verbatim as the request's 3rd element. */
        RNS::Bytes data_b = data.empty()
                          ? RNS::Bytes()
                          : RNS::Bytes(data.data(), data.size());
        double timeout = (double)storageGetInt("s.rnsd.link.request_timeout_s", 15);
        if (timeout < 1.0) timeout = 15.0;
        RNS::RequestReceipt rr = c.link.request(path_b, data_b,
                                                onReqResponseCb, onReqFailedCb,
                                                nullptr, timeout, data_packed);
        if (!rr) {
            warn("link[%s]: request returned none", c.tag);
            reqFailDirect(task, port, cid);
            return;
        }
        c.req_mrid     = rr.get_request_id();
        c.req_cid      = cid;
        c.req_port     = port;
        c.req_task     = task;
        c.req_deadline = RNS::Utilities::OS::time() + timeout + 5.0;
        linkTouch(c);
        char k[96];
        linkKey(c, "request.path", k, sizeof(k));  storageSet(k, path.c_str());
        linkKey(c, "request.state", k, sizeof(k)); storageSet(k, "sent");
        info("link[%s]: request '%s' sent (cid=%u, req_id=%s)",
             c.tag, path.c_str(), (unsigned)cid, c.req_mrid.toHex().c_str());
    } catch (const std::exception& e) {
        warn("link[%s]: request threw: %s", c.tag, e.what());
        reqFailDirect(task, port, cid);
    }
}

/* Construct the OUT destination + RNS::Link and wire callbacks. The
 * target identity must already be recallable. Runs on the rnsd task. */
static bool linkKickoff(link_conn_t& c)
{
    RNS::Identity target = RNS::Identity::recall(c.dest_hash);
    if (!target) return false;

    RNS::Identity local{RNS::Type::NONE};
    if (!linkLoadIdentity(c.identity_key, local)) {
        c.state = LST_FAILED;
        linkSetError(c, "no_identity");
        linkPublishState(c);
        return true;   /* terminal — caller stops retrying */
    }

    std::string app_name = c.aspect, aspects;
    auto dot = c.aspect.find('.');
    if (dot != std::string::npos) {
        app_name = c.aspect.substr(0, dot);
        aspects  = c.aspect.substr(dot + 1);
    }
    try {
        RNS::Destination out_dest(target, RNS::Type::Destination::OUT,
                                  RNS::Type::Destination::SINGLE,
                                  app_name.c_str(), aspects.c_str());
        c.link = RNS::Link(out_dest);
        c.link.set_link_established_callback(onLinkEstablishedCb);
        c.link.set_link_closed_callback(onLinkClosedCb);
        c.link.set_packet_callback(onLinkPacketCb);
        linkWireResource(c.link);                 /* Phase F */
        c.state = LST_ESTABLISHING;
        c.estab_deadline = RNS::Utilities::OS::time() + 60.0;
        linkPublishState(c);
        info("link[%s]: kickoff → %s aspect=%s", c.tag,
             c.dest_hash.toHex().c_str(), c.aspect.c_str());
    } catch (const std::exception& e) {
        warn("link[%s]: kickoff threw: %s", c.tag, e.what());
        c.state = LST_FAILED;
        linkSetError(c, "ctor_threw");
        linkPublishState(c);
    }
    return true;
}

static void linkFreeSlot(link_conn_t& c)
{
    /* A request still outstanding when the link is reclaimed (establish
     * failure, no-path, remote close, orphan-ttl teardown) will never get
     * a response — tell the consumer so it doesn't hang. Done before the
     * field resets below so req_task/port are still valid. After a normal
     * DONE the callbacks already cleared req_mrid, so this no-ops. */
    if (c.req_mrid.size())
        reqSendAux(c, RNSD_LINK_REQUEST_FAILED, nullptr, 0);
    if (c.pend_req_used)
        reqFailDirect(c.pend_req_task, c.pend_req_port, c.pend_req_cid);

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "rnsd.links.%s", c.tag);
    storageDeleteTree(prefix);
    if (c.handle >= 0) itsDisconnect(c.handle);
    c.used = false;
    c.handle = -1;
    c.last_activity = 0;
    c.link = RNS::Link{RNS::Type::NONE};
    c.dest_hash = RNS::Bytes();
    c.aspect.clear();
    c.identity_key.clear();
    c.pend_used = false;
    c.pend_bytes.clear();
    if (c.pend_res_used && c.pend_res_buf) free(c.pend_res_buf);
    c.pend_res_used = false;
    c.pend_res_buf = nullptr;
    c.pend_res_len = 0;
    c.pend_res_opaque = 0;
    c.consumer_task = nullptr;
    c.res_hash = RNS::Bytes();
    c.res_outbound = false;
    c.res_opaque = 0;
    c.req_mrid = RNS::Bytes();
    c.req_cid = 0;
    c.req_port = 0;
    c.req_task = nullptr;
    c.req_deadline = 0;
    c.pend_req_used = false;
    c.pend_req_path.clear();
    c.pend_req_data.clear();
    c.pend_req_cid = 0;
    c.pend_req_port = 0;
    c.pend_req_task = nullptr;
    c.pend_req_packed = false;
    c.state = LST_FREE;
}

/* 1 Hz from the rnsd loop (tickPhase 0), beside mailboxTickPending. */
static void linkTick(void)
{
    if (!s_link_conns) return;
    double now = RNS::Utilities::OS::time();
    int orphan_ttl = storageGetInt("s.rnsd.link.orphan_ttl_s", 600);

    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++) {
        link_conn_t& c = s_link_conns[j];
        if (!c.used) continue;

        /* Request timeout backstop. µR does not drive RequestReceipt
         * timeouts (the upstream response-timeout thread isn't ported),
         * so fail the consumer here if no response arrived in time. */
        if (c.req_mrid.size() && c.req_deadline != 0 && now >= c.req_deadline) {
            warn("link[%s]: request timed out (cid=%u)", c.tag, (unsigned)c.req_cid);
            char k[96];
            linkKey(c, "request.state", k, sizeof(k)); storageSet(k, "timeout");
            reqSendAux(c, RNSD_LINK_REQUEST_FAILED, nullptr, 0);
            c.req_mrid     = RNS::Bytes();
            c.req_deadline = 0;
        }

        switch (c.state) {
        case LST_AWAITING_PATH:
            if (RNS::Identity::recall(c.dest_hash)) {
                linkKickoff(c);
            } else if (now >= c.path_deadline) {
                warn("link[%s]: no path within budget", c.tag);
                c.state = LST_FAILED;
                linkSetError(c, "no_path");
                linkPublishState(c);
                c.dead_at = now;
            }
            break;

        case LST_ESTABLISHING:
            if (c.estab_deadline != 0 && now >= c.estab_deadline) {
                warn("link[%s]: establishment timed out", c.tag);
                try { if (c.link) c.link.teardown(); } catch (...) {}
                c.link = RNS::Link{RNS::Type::NONE};
                c.state = LST_FAILED;
                linkSetError(c, "establish_timeout");
                linkPublishState(c);
                c.dead_at = now;
            }
            break;

        case LST_ACTIVE:
            /* Consumer gone past the orphan budget → tear the Link down
             * (§10a.1: consumer-handle close ≠ Link teardown; the
             * orphan TTL is the backstop, not an immediate close). */
            if (c.orphan_at != 0 && now - c.orphan_at >= orphan_ttl) {
                info("link[%s]: orphan ttl elapsed, tearing down", c.tag);
                try { if (c.link) c.link.teardown(); } catch (...) {}
                c.state = LST_CLOSING;
                linkPublishState(c);
            }
            break;

        case LST_CLOSED:
        case LST_FAILED:
            /* Grace so subscribers see the terminal state, then reclaim. */
            if (c.dead_at == 0) c.dead_at = now;
            if (now - c.dead_at >= 3.0) linkFreeSlot(c);
            break;

        default:
            break;
        }
    }
}

static int onLinkConnect(int handle, const void* data, size_t len)
{
    if (len != sizeof(rnsd_link_connect_t)) {
        err("link connect: bad payload len %zu (want %zu)",
            len, sizeof(rnsd_link_connect_t));
        return -1;
    }
    rnsd_link_connect_t req;
    memcpy(&req, data, sizeof(req));
    req.aspect[sizeof(req.aspect) - 1]             = '\0';
    req.identity_key[sizeof(req.identity_key) - 1] = '\0';
    req.tag[sizeof(req.tag) - 1]                   = '\0';

    if (req.tag[0] == '\0') { err("link connect: empty tag"); return -1; }
    if (linkFindByTag(req.tag)) {
        err("link connect: duplicate tag '%s'", req.tag);
        return -1;
    }
    link_conn_t* c = linkAlloc();
    if (!c) { err("link connect: no slots"); return -1; }

    c->used   = true;
    c->handle = handle;
    c->ref    = (int)(c - s_link_conns);
    safeStrncpy(c->tag, req.tag, sizeof(c->tag));
    c->dest_hash    = RNS::Bytes(req.dest_hash, RNSD_DEST_HASH_LEN);
    c->aspect       = req.aspect;
    c->identity_key = req.identity_key;
    c->opened_at    = RNS::Utilities::OS::time();
    c->last_activity = c->opened_at;
    c->orphan_at    = 0;
    c->dead_at      = 0;
    c->estab_deadline = 0;
    c->pend_used    = false;
    c->pend_bytes.clear();
    c->pend_res_used = false;
    c->pend_res_buf = nullptr;
    c->pend_res_len = 0;
    c->pend_res_opaque = 0;
    c->consumer_task = itsRemoteTask(handle);   /* Phase F resource aux target */
    c->res_hash      = RNS::Bytes();
    c->res_outbound  = false;
    c->res_opaque    = 0;
    c->req_mrid      = RNS::Bytes();
    c->req_cid       = 0;
    c->req_port      = 0;
    c->req_task      = nullptr;
    c->req_deadline  = 0;
    c->pend_req_used = false;
    c->pend_req_path.clear();
    c->pend_req_data.clear();
    c->pend_req_cid  = 0;
    c->pend_req_port = 0;
    c->pend_req_task = nullptr;
    c->pend_req_packed = false;

    int path_to_s = storageGetInt("s.rnsd.link.path_timeout_s", 30);
    if (req.path_timeout_ms != 0) path_to_s = (int)(req.path_timeout_ms / 1000);
    c->path_deadline = c->opened_at + (path_to_s > 0 ? path_to_s : 30);

    /* Initial state tree. storageSet (not Default) so the browser /
     * consumer subscribers fire on every field. */
    linkSetStr(*c, "direction", "out");
    linkSetStr(*c, "aspect", c->aspect.c_str());
    linkSetStr(*c, "remote_hash", c->dest_hash.toHex().c_str());
    linkSetInt(*c, "opened_s", (int)c->opened_at);
    linkSetStr(*c, "last_error", "");

    if (RNS::Identity::recall(c->dest_hash)) {
        c->state = LST_ESTABLISHING;
        linkPublishState(*c);
        linkKickoff(*c);
    } else {
        c->state = LST_AWAITING_PATH;
        linkPublishState(*c);
        info("link[%s]: no identity for %s, requesting path",
             c->tag, c->dest_hash.toHex().c_str());
        try { RNS::Transport::request_path(c->dest_hash); }
        catch (const std::exception& e) {
            warn("link[%s]: request_path threw: %s", c->tag, e.what());
        }
    }
    return c->ref;
}

static void onLinkRecv(int handle, size_t /*bytesAvail*/)
{
    link_conn_t* c = linkFindByHandle(handle);
    if (!c) return;
    static uint8_t buf[2048];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (n == 0) return;

    if (c->state == LST_ACTIVE && c->link) {
        if (n > RNS::Type::Link::MDU) {
            warn("link[%s]: oversize send %zuB", c->tag, n);
            linkSetError(*c, "oversize");
            return;
        }
        try {
            RNS::Packet pkt(c->link, RNS::Bytes(buf, n));
            pkt.send();
            linkTouch(*c);
            char k[96];
            linkKey(*c, "tx_packets", k, sizeof(k));
            storageSet(k, storageGetInt(k, 0) + 1);
            linkSetInt(*c, "last_outbound_s", (int)RNS::Utilities::OS::time());
        } catch (const std::exception& e) {
            warn("link[%s]: send threw: %s", c->tag, e.what());
            linkSetError(*c, "send_threw");
        }
        return;
    }

    /* Pre-active: one-packet outbox, drop-newer. */
    if (c->pend_used) {
        warn("link[%s]: send queue full, dropping newer %zuB", c->tag, n);
        linkSetError(*c, "send_queue_full");
        return;
    }
    c->pend_used = true;
    c->pend_bytes.assign(buf, buf + n);
}

static void onLinkDisconnect(int ref)
{
    if (ref < 0 || ref >= RNSD_MAX_LINK_CONNS) return;
    link_conn_t& c = s_link_conns[ref];
    if (!c.used) return;
    /* §10a.1: consumer handle close does NOT tear the Link down. Park
     * it; linkTick tears down after s.rnsd.link.orphan_ttl_s if the
     * consumer never comes back. Terminal slots just get reclaimed. */
    c.handle = -1;
    if (c.state == LST_ACTIVE || c.state == LST_ESTABLISHING ||
        c.state == LST_AWAITING_PATH) {
        c.orphan_at = RNS::Utilities::OS::time();
        info("link[%s]: consumer detached, parking (orphan ttl)", c.tag);
    }
}

/* Explicit consumer-initiated teardown (rnsdLinkTeardown → aux on
 * RNSD_PORT_LINK). Runs on the rnsd task (itsOnAux dispatches on the
 * registering task), where mR Link state must be touched. Distinct
 * from onLinkDisconnect's park-for-reconnect: this fully closes the
 * Link and frees the slot + tag immediately. */
static void onLinkAux(TaskHandle_t sender, const void* data, size_t len)
{
    if (len < 1) return;
    uint8_t op = ((const uint8_t*)data)[0];

    if (op == RNSD_LINK_AUX_TEARDOWN) {
        char tag[24] = {};
        size_t tl = len - 1; if (tl > sizeof(tag) - 1) tl = sizeof(tag) - 1;
        memcpy(tag, (const uint8_t*)data + 1, tl);
        link_conn_t* c = linkFindByTag(tag);
        if (!c) { info("link[%s]: teardown — no such link", tag); return; }
        info("link[%s]: explicit teardown", c->tag);
        try { if (c->link) c->link.teardown(); } catch (...) {}
        c->link  = RNS::Link{RNS::Type::NONE};
        c->state = LST_CLOSED;
        linkPublishState(*c);          /* subscribers observe the close … */
        linkFreeSlot(*c);              /* … then slot + storage tree freed */
        return;
    }

    if (op == RNSD_LINK_AUX_SEND_RESOURCE) {
        if (len < sizeof(rnsd_link_send_resource_t)) {
            warn("link: short SEND_RESOURCE aux %zu", len);
            return;
        }
        rnsd_link_send_resource_t req;
        memcpy(&req, data, sizeof(req));
        req.tag[sizeof(req.tag) - 1] = '\0';
        void* buf = req.buf;            /* rnsd owns this now */
        link_conn_t* c = linkFindByTag(req.tag);
        if (!c) {
            warn("link[%s]: SEND_RESOURCE for unknown link", req.tag);
            if (buf) free(buf);
            return;
        }
        if (c->pend_res_used || c->res_hash.size()) {
            warn("link[%s]: resource already pending/in-flight, dropping",
                 c->tag);
            if (buf) free(buf);
            return;
        }
        if (!c->link || c->state != LST_ACTIVE) {
            /* lxmf opens the link then immediately sends; the async
             * handshake (~200 ms) isn't done yet. Defer to
             * onLinkEstablishedCb (mirrors the one-packet outbox). */
            c->pend_res_used   = true;
            c->pend_res_buf    = buf;
            c->pend_res_len    = req.len;
            c->pend_res_opaque = req.opaque_id;
            info("link[%s]: SEND_RESOURCE deferred (link %s) %uB",
                 c->tag, lstName(c->state), (unsigned)req.len);
            return;
        }
        linkStartOutboundResource(*c, buf, req.len, req.opaque_id);
        return;
    }

    if (op == RNSD_LINK_AUX_REQUEST) {
        if (len < sizeof(rnsd_link_request_t)) {
            warn("link: short REQUEST aux %zu", len);
            return;
        }
        rnsd_link_request_t hdr;
        memcpy(&hdr, data, sizeof(hdr));
        hdr.tag[sizeof(hdr.tag) - 1] = '\0';
        if (len < sizeof(hdr) + (size_t)hdr.path_len + (size_t)hdr.data_len) {
            warn("link[%s]: REQUEST aux truncated (have %zu, need %zu)", hdr.tag,
                 len, sizeof(hdr) + (size_t)hdr.path_len + (size_t)hdr.data_len);
            reqFailDirect(sender, hdr.resp_port, hdr.req_id);
            return;
        }
        const uint8_t* p = (const uint8_t*)data + sizeof(hdr);
        std::string          path((const char*)p, hdr.path_len);
        std::vector<uint8_t> rdata(p + hdr.path_len,
                                   p + hdr.path_len + hdr.data_len);
        link_conn_t* c = linkFindByTag(hdr.tag);
        if (!c) {
            warn("link[%s]: REQUEST for unknown link", hdr.tag);
            reqFailDirect(sender, hdr.resp_port, hdr.req_id);
            return;
        }
        if (c->state != LST_ACTIVE || !c->link) {
            /* Defer until ACTIVE (one pending request, mirrors pend_res). */
            if (c->pend_req_used || c->req_mrid.size()) {
                warn("link[%s]: request already pending/in-flight, dropping",
                     c->tag);
                reqFailDirect(sender, hdr.resp_port, hdr.req_id);
                return;
            }
            c->pend_req_used = true;
            c->pend_req_path = path;
            c->pend_req_data = rdata;
            c->pend_req_cid  = hdr.req_id;
            c->pend_req_port = hdr.resp_port;
            c->pend_req_task = sender;
            c->pend_req_packed = (hdr.data_packed != 0);
            info("link[%s]: REQUEST deferred (link %s) path='%s'",
                 c->tag, lstName(c->state), path.c_str());
            return;
        }
        linkStartRequest(*c, path, rdata, hdr.req_id, hdr.resp_port, sender,
                         hdr.data_packed != 0);
        return;
    }
}

/* ─────────────── Phase D: inbound Link → consumer forwarding ───────────────
 *
 * docs/plans/link.md §7. A consumer that has an RNSD_PORT_DEST handle
 * sends RNSD_DEST_LINK_LISTEN with an inbox port; rnsd flips
 * accepts_links(true) on that IN destination and sets *this* as its
 * Destination-level established callback. mR fires it (Link.cpp:539,
 * `_owner.callbacks()._link_established`) once an inbound Link reaches
 * ACTIVE. We slot it into the shared s_link_conns table (direction
 * "in"), reuse the Phase-C packet/closed thunks (sameLink resolves the
 * slot), and itsConnectByTaskHandle back to the registered consumer
 * with an rnsd_link_incoming_t describing the remote. Consumer→link
 * sends and consumer detach reuse onLinkRecv / onLinkDisconnect. */
static void onIncomingLinkEstablished(RNS::Link& link)
{
    RNS::Bytes local = link.destination().hash();   /* our IN dest (set
                                                       by validate_request) */
    mailbox_conn_t* mc = mailboxFindByDestHash(local);
    if (!mc || !mc->link_listener_task || mc->link_inbox_port == 0) {
        warn("inlink: LR on %s with no listener — tearing down",
             local.toHex().c_str());
        try { link.teardown(); } catch (...) {}
        return;
    }
    link_conn_t* c = linkAlloc();
    if (!c) {
        warn("inlink: no slots — tearing down");
        try { link.teardown(); } catch (...) {}
        return;
    }
    std::string lid = link.link_id().toHex();
    std::string tag = "in." + lid.substr(0, 8);

    c->used   = true;
    c->handle = -1;
    c->ref    = (int)(c - s_link_conns);
    safeStrncpy(c->tag, tag.c_str(), sizeof(c->tag));
    c->dest_hash    = local;
    c->aspect       = mc->req.aspect;
    c->identity_key.clear();
    c->state        = LST_ACTIVE;
    c->link         = link;          /* copy shares shared_ptr<LinkData> */
    c->opened_at    = RNS::Utilities::OS::time();
    c->last_activity = c->opened_at;
    c->orphan_at    = 0;
    c->dead_at      = 0;
    c->estab_deadline = 0;
    c->pend_used    = false;
    c->pend_bytes.clear();
    c->pend_res_used = false;
    c->pend_res_buf = nullptr;
    c->pend_res_len = 0;
    c->pend_res_opaque = 0;

    link.set_packet_callback(onLinkPacketCb);
    link.set_link_closed_callback(onLinkClosedCb);
    linkWireResource(link);                       /* Phase F */
    c->consumer_task = mc->link_listener_task;     /* resource aux target */
    c->res_hash      = RNS::Bytes();
    c->res_outbound  = false;
    c->res_opaque    = 0;

    RNS::Bytes rid;
    {
        const RNS::Identity& ri = link.get_remote_identity();
        if (ri) rid = ri.hash();
    }

    linkSetStr(*c, "direction", "in");
    linkSetStr(*c, "aspect", c->aspect.c_str());
    linkSetStr(*c, "local_hash", local.toHex().c_str());
    if (rid) linkSetStr(*c, "remote_identity", rid.toHex().c_str());
    linkSetStr(*c, "link_id", lid.c_str());
    linkSetInt(*c, "mtu", (int)link.get_mtu());
    linkSetInt(*c, "opened_s", (int)c->opened_at);
    linkSetInt(*c, "activated_s", (int)c->opened_at);
    linkSetStr(*c, "last_error", "");
    linkPublishState(*c);
    {
        char k[96];
        snprintf(k, sizeof(k), "rnsd.links.byid.%s", lid.c_str());
        storageSet(k, c->tag);
    }

    rnsd_link_incoming_t pl = {};
    safeStrncpy(pl.tag, c->tag, sizeof(pl.tag));
    if (link.link_id().size() >= 16)
        memcpy(pl.link_id, link.link_id().data(), 16);
    if (rid.size() >= 16) memcpy(pl.remote_identity_hash, rid.data(), 16);
    if (local.size() >= 16) memcpy(pl.local_dest_hash, local.data(), 16);
    pl.mtu = link.get_mtu();

    int h = itsConnectByTaskHandle(mc->link_listener_task,
                                   mc->link_inbox_port,
                                   &pl, sizeof(pl), pdMS_TO_TICKS(2000),
                                   c->ref, onLinkRecv, onLinkDisconnect);
    if (h < 0) {
        warn("inlink[%s]: consumer unreachable (%d), tearing down",
             c->tag, h);
        linkSetError(*c, "consumer_unreachable");
        try { link.teardown(); } catch (...) {}
        c->link  = RNS::Link{RNS::Type::NONE};
        c->state = LST_FAILED;
        c->dead_at = RNS::Utilities::OS::time();
        return;   /* linkTick reclaims after grace */
    }
    c->handle = h;
    info("inlink[%s]: ACTIVE link_id=%s mtu=%u → consumer port %u",
         c->tag, lid.c_str(), (unsigned)link.get_mtu(),
         (unsigned)mc->link_inbox_port);
}

/* ─────────────── Phase C smoke: `clink` test consumer task ───────────────
 *
 * docs/plans/link.md §6.3 — "a trivial test consumer task on the device
 * can open a Link, send, receive, disconnect". This is a *real*
 * RNSD_PORT_LINK consumer (its own ITS-client task), distinct from the
 * Phase B `rnsd link` probe (which builds RNS::Link directly on the
 * rnsd task). Driven by `rnsd clink …` → `rnsd.cmd.clink` storage key.
 *
 *   rnsd clink <hash> [aspect]   open via rnsdLinkOpen() + queue a probe
 *                                packet (exercises the pre-active outbox)
 *   rnsd clink send <text>       send one Link packet
 *   rnsd clink close             itsDisconnect (Link parks per §10a.1)
 *
 * Inbound Link packets are logged. With an echo-style peer the probe
 * round-trips, proving establish + outbox flush + inbound forwarding. */

static const char* CLINK_TAG = "clink";
static int s_clink_handle      = -1;   /* outbound RNSD_PORT_LINK handle */
static int s_clink_dest_handle = -1;   /* hosted RNSD_PORT_DEST handle (listen) */
#define CLINK_INBOX_PORT 120           /* consumer-side inbound-Link port */
#define CREQ_RESP_PORT   121           /* consumer-side request-response aux port */

static void onClinkRecv(int handle, size_t /*bytesAvail*/)
{
    static uint8_t buf[1024];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (n == 0) return;
    size_t show = n < 48 ? n : 48;
    info("clink: RX %zuB head=%s%s", n,
         RNS::Bytes(buf, show).toHex().c_str(), n > show ? "…" : "");
}

static void onClinkDisc(int /*handle*/)
{
    info("clink: ITS handle closed");
    s_clink_handle = -1;
}

/* ---- Phase D test: host a destination + receive inbound Links ---- */

static void onClinkDestRecv(int handle, size_t /*n*/)
{
    /* Drain whatever rnsd sends on the hosted-dest handle (IN_PACKET,
     * OUT_RESULT, …). The test only cares about inbound Links, which
     * arrive on CLINK_INBOX_PORT, not here. */
    static uint8_t b[700];
    itsRecv(handle, b, sizeof(b), 0);
}
static void onClinkDestDisc(int /*handle*/)
{
    info("clink: hosted dest closed");
    s_clink_dest_handle = -1;
}

static int onClinkInboxConnect(int /*handle*/, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_incoming_t)) {
        warn("clink inbox: short payload %zu", len);
        return -1;
    }
    rnsd_link_incoming_t pl;
    memcpy(&pl, data, sizeof(pl));
    pl.tag[sizeof(pl.tag) - 1] = '\0';
    info("clink inbox: INBOUND LINK tag=%s link_id=%s mtu=%u "
         "remote_id=%s local=%s",
         pl.tag,
         RNS::Bytes(pl.link_id, 16).toHex().c_str(),
         (unsigned)pl.mtu,
         RNS::Bytes(pl.remote_identity_hash, 16).toHex().c_str(),
         RNS::Bytes(pl.local_dest_hash, 16).toHex().c_str());
    return 0;   /* accept */
}
static void onClinkInboxRecv(int handle, size_t /*n*/)
{
    static uint8_t b[1024];
    size_t n = itsRecv(handle, b, sizeof(b), 0);
    if (n == 0) return;
    size_t show = n < 48 ? n : 48;
    info("clink inbox: RX %zuB head=%s%s", n,
         RNS::Bytes(b, show).toHex().c_str(), n > show ? "…" : "");
    /* Echo it straight back over the same inbound Link. */
    itsSend(handle, b, n, 0);
}
static void onClinkInboxDisc(int /*handle*/)
{
    info("clink inbox: link forward closed");
}

/* ---- Phase 0 smoke: request/response (nomad page fetch, nomad.md) ---- */

/* Request response/failure handoff from rnsd (rnsd_link_resource_done_t
 * on CREQ_RESP_PORT). Logs the response bytes hex + ASCII so a page GET
 * is human-readable at the serial console. */
static void onCreqResponse(TaskHandle_t /*sender*/, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_resource_done_t)) {
        warn("creq: short response aux %zu", len);
        return;
    }
    rnsd_link_resource_done_t d;
    memcpy(&d, data, sizeof(d));

    if (d.opcode == RNSD_LINK_REQUEST_FAILED) {
        warn("creq: request FAILED (cid=%u)", (unsigned)d.opaque_id);
        return;
    }
    if (d.opcode != RNSD_LINK_REQUEST_RESPONSE) return;

    if (d.buf && d.len) {
        /* One-line preview: hex head + a sanitized text fragment (CR/LF/
         * controls folded to '.') + ellipsis. No full-page dump in the log. */
        const uint8_t* b = (const uint8_t*)d.buf;
        size_t hx = d.len < 12 ? d.len : 12;
        std::string frag;
        size_t fn = d.len < 56 ? d.len : 56;
        for (size_t i = 0; i < fn; ++i)
            frag += (b[i] < 0x20 || b[i] == 0x7f) ? '.' : (char)b[i];
        info("creq: RESPONSE %uB (cid=%u) hex=%s%s text=\"%s%s\"",
             (unsigned)d.len, (unsigned)d.opaque_id,
             RNS::Bytes(b, hx).toHex().c_str(), d.len > hx ? "…" : "",
             frag.c_str(), d.len > fn ? "…" : "");
    } else {
        info("creq: RESPONSE %uB (cid=%u)", (unsigned)d.len, (unsigned)d.opaque_id);
    }
    rnsdResourceRelease(d.buf);   /* we own it on REQUEST_RESPONSE */
}

/* `rnsd creq <hash> <path> [aspect]` → rnsd.cmd.creq. Opens an outbound
 * Link (reusing the clink slot/tag) and issues one request; rnsd holds it
 * until the Link is ACTIVE, then fires it. The response lands in
 * onCreqResponse above. */
static void onCmdCreq(const char* key, const char* val)
{
    if (!val || !*val) return;            /* self-unset re-fire */
    std::string cmd = val;
    storageUnset(key);                    /* single-shot */

    /* "<hash> <path> [aspect]" */
    size_t sp1 = cmd.find(' ');
    if (sp1 == std::string::npos) {
        warn("creq: usage <dest_hash> <path> [aspect]");
        return;
    }
    std::string hash_hex = cmd.substr(0, sp1);
    std::string tail     = cmd.substr(sp1 + 1);
    while (!tail.empty() && tail[0] == ' ') tail.erase(0, 1);
    std::string path = tail, aspect = "nomadnetwork.node";
    size_t sp2 = tail.find(' ');
    if (sp2 != std::string::npos) {
        path   = tail.substr(0, sp2);
        aspect = tail.substr(sp2 + 1);
        while (!aspect.empty() && aspect[0] == ' ') aspect.erase(0, 1);
    }
    if (path.empty()) path = "/page/index.mu";
    if (hash_hex.size() != RNSD_DEST_HASH_LEN * 2) {
        warn("creq: bad hash length %zu", hash_hex.size());
        return;
    }
    RNS::Bytes dh;
    try { dh.assignHex((const uint8_t*)hash_hex.c_str(), hash_hex.size()); }
    catch (...) { warn("creq: bad hash hex"); return; }
    if (dh.size() != RNSD_DEST_HASH_LEN) { warn("creq: bad hash bytes"); return; }

    if (s_clink_handle >= 0) { itsDisconnect(s_clink_handle); s_clink_handle = -1; }
    rnsdLinkTeardown(CLINK_TAG);   /* clear any parked/lingering prior link */
    int h = rnsdLinkOpen(dh.data(), aspect.c_str(), "", CLINK_TAG,
                         /*path_timeout_ms=*/0, /*ref=*/0,
                         onClinkRecv, onClinkDisc);
    if (h < 0) { warn("creq: rnsdLinkOpen failed (%d)", h); return; }
    s_clink_handle = h;
    int rid = rnsdLinkRequest(CLINK_TAG, path.c_str(), nullptr, 0, CREQ_RESP_PORT);
    info("creq: opened → %s aspect=%s path=%s (req_id=%d)",
         hash_hex.c_str(), aspect.c_str(), path.c_str(), rid);
}

static void onCmdClink(const char* key, const char* val)
{
    if (!val || !*val) return;            /* self-unset re-fire */
    std::string cmd = val;
    storageUnset(key);                    /* single-shot */

    if (cmd == "close") {
        /* Full teardown (frees the "clink" tag for immediate reuse) —
         * not bare itsDisconnect, which would only park per §10a.1. */
        rnsdLinkTeardown(CLINK_TAG);
        if (s_clink_handle >= 0) { itsDisconnect(s_clink_handle); s_clink_handle = -1; }
        info("clink: teardown requested");
        return;
    }
    if (cmd.rfind("send ", 0) == 0) {
        std::string txt = cmd.substr(5);
        if (s_clink_handle < 0) { warn("clink: no link open"); return; }
        itsSend(s_clink_handle, txt.data(), txt.size(), 0);
        info("clink: sent %zuB", txt.size());
        return;
    }
    if (cmd.rfind("listen", 0) == 0) {
        std::string arg = cmd.size() > 6 ? cmd.substr(7) : "";
        while (!arg.empty() && arg[0] == ' ') arg.erase(0, 1);
        if (arg == "off" || arg.empty()) {
            if (s_clink_dest_handle >= 0) {
                itsDisconnect(s_clink_dest_handle);
                s_clink_dest_handle = -1;
            }
            info("clink: listen off");
            return;
        }
        /* Host an IN destination on the rnsd default identity, register
         * for inbound Links to CLINK_INBOX_PORT, then announce so a
         * host-side peer can resolve + open a Link to it (Phase D). */
        int dh = rnsdDestOpen(arg.c_str(), "", /*SINGLE*/0, /*ref=*/1,
                              onClinkDestRecv, onClinkDestDisc);
        if (dh < 0) { warn("clink: rnsdDestOpen failed (%d)", dh); return; }
        s_clink_dest_handle = dh;
        if (!rnsdDestListenLinks(dh, CLINK_INBOX_PORT))
            warn("clink: rnsdDestListenLinks failed");
        uint8_t ann = RNSD_DEST_ANNOUNCE;            /* empty app_data */
        itsSend(dh, &ann, 1, pdMS_TO_TICKS(500));
        info("clink: listening on aspect=%s (announced; inbox port %u)",
             arg.c_str(), (unsigned)CLINK_INBOX_PORT);
        return;
    }

    /* "<32-hex> [aspect]" */
    std::string hash_hex = cmd, aspect = "lxmf.delivery";
    size_t sp = cmd.find(' ');
    if (sp != std::string::npos) {
        hash_hex = cmd.substr(0, sp);
        aspect   = cmd.substr(sp + 1);
        while (!aspect.empty() && aspect[0] == ' ') aspect.erase(0, 1);
    }
    if (hash_hex.size() != RNSD_DEST_HASH_LEN * 2) {
        warn("clink: bad hash length %zu", hash_hex.size());
        return;
    }
    RNS::Bytes dh;
    try { dh.assignHex((const uint8_t*)hash_hex.c_str(), hash_hex.size()); }
    catch (...) { warn("clink: bad hash hex"); return; }
    if (dh.size() != RNSD_DEST_HASH_LEN) { warn("clink: bad hash bytes"); return; }

    if (s_clink_handle >= 0) { itsDisconnect(s_clink_handle); s_clink_handle = -1; }
    rnsdLinkTeardown(CLINK_TAG);   /* clear any parked/lingering prior link */
    int h = rnsdLinkOpen(dh.data(), aspect.c_str(), "", CLINK_TAG,
                         /*path_timeout_ms=*/0, /*ref=*/0,
                         onClinkRecv, onClinkDisc);
    if (h < 0) { warn("clink: rnsdLinkOpen failed (%d)", h); return; }
    s_clink_handle = h;
    /* Queue a probe immediately — rnsd's one-packet pre-active outbox
     * buffers it and flushes on establishment (§6.2). */
    static const char probe[] = "reticulous clink probe";
    itsSend(h, probe, sizeof(probe) - 1, 0);
    info("clink: opened → %s aspect=%s (probe queued)",
         hash_hex.c_str(), aspect.c_str());
}

static void clinkTaskMain(void*)
{
    info("[%s] task up", CLINK_TAG);
    /* Both server (inbound-Link inbox port) and client (rnsdLinkOpen /
     * rnsdDestOpen connect to rnsd). itsServerInit sets up the shared
     * inbox; itsClientInit then reuses it. */
    if (!itsServerInit()) { err("clink itsServerInit failed"); }
    itsServerPortOpen(CLINK_INBOX_PORT, /*packetBased=*/true,
                      /*maxHandles=*/4, /*toSize=*/4096, /*fromSize=*/4096);
    itsServerOnConnect(CLINK_INBOX_PORT,    onClinkInboxConnect);
    itsServerOnDisconnect(CLINK_INBOX_PORT, onClinkInboxDisc);
    itsServerOnRecv(CLINK_INBOX_PORT,       onClinkInboxRecv);
    itsOnAux(CREQ_RESP_PORT,                onCreqResponse);   /* Phase 0 smoke */
    itsClientInit(4);
    storageSubscribeChanges("rnsd.cmd.clink", onCmdClink);
    storageSubscribeChanges("rnsd.cmd.creq",  onCmdCreq);
    TickType_t lastAnnounce = 0;
    for (;;) {
        while (itsPoll(0)) {}
        itsPoll(pdMS_TO_TICKS(1000));
        /* While hosting a Phase-D test dest, re-announce every 20 s so a
         * host-side peer's path to it stays fresh across test runs. */
        if (s_clink_dest_handle >= 0) {
            TickType_t now = xTaskGetTickCount();
            if (now - lastAnnounce >= pdMS_TO_TICKS(20000)) {
                uint8_t ann = RNSD_DEST_ANNOUNCE;
                itsSend(s_clink_dest_handle, &ann, 1, 0);
                lastAnnounce = now;
            }
        }
    }
}

static void rnsdTaskMain(void*)
{
    info("[%s] task up", TAG);

    /* PSRAM-place the iface and packet-connection tables in task context, so
     * heap tracking attributes them to rnsd rather than the main task. RNS::
     * Interface / Destination / Identity have non-trivial ctors — placement-
     * new each slot. */
    s_ifaces = (iface_t*)heap_caps_malloc(RNSD_MAX_IFACES * sizeof(iface_t), MALLOC_CAP_SPIRAM);
    s_mailbox_conns = (mailbox_conn_t*)heap_caps_malloc(
        RNSD_MAX_MAILBOX_CONNS * sizeof(mailbox_conn_t), MALLOC_CAP_SPIRAM);
    s_link_conns = (link_conn_t*)heap_caps_malloc(
        RNSD_MAX_LINK_CONNS * sizeof(link_conn_t), MALLOC_CAP_SPIRAM);
    if (!s_ifaces || !s_mailbox_conns || !s_link_conns) {
        err("rnsd table PSRAM alloc failed"); killSelf();
    }
    for (int j = 0; j < RNSD_MAX_IFACES; j++)        new (&s_ifaces[j])        iface_t{};
    for (int j = 0; j < RNSD_MAX_MAILBOX_CONNS; j++) new (&s_mailbox_conns[j]) mailbox_conn_t{};
    for (int j = 0; j < RNSD_MAX_LINK_CONNS; j++)    new (&s_link_conns[j])    link_conn_t{};

    /* s.rnsd.its_no_pool (default off): when on, rnsd's ITS connections bypass
     * the shared buffer pool — buffers are created on connect and freed on
     * disconnect. Returns transient buffers to the heap and makes `rnsd memory`'s
     * ITS figure exact under per-task heap tracking (no cross-task borrowing).
     * Read once here — takes effect on the next boot after toggling. */
    bool itsNoPool = storageGetInt("s.rnsd.its_no_pool", 0) != 0;
    if (!itsServerInit(0, 0, itsNoPool)) { err("itsServerInit failed"); killSelf(); return; }
    /* rnsd is also an ITS *client*: Phase D back-connects inbound Links
     * to the registered consumer via itsConnectByTaskHandle. Without
     * this the connect fails and onIncomingLinkEstablished tears the
     * Link down (peer sees DESTINATION_CLOSED). Shares the itsServerInit
     * inbox. RNSD_MAX_LINK_CONNS inbound forwards + headroom. */
    itsClientInit(RNSD_MAX_LINK_CONNS + 4);
    /* 4 KB per direction per handle — bursty announce traffic on a busy
     * testnet can fill 2 KB before rnsd drains during the 1 Hz publish
     * block. 4 KB gives ~4× more headroom; PSRAM-allocated, ~64 KB total
     * across RNSD_MAX_IFACES=16 × 2 directions. */
    if (!itsServerPortOpen(RNSD_PORT_TRANSPORT, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_IFACES,
                           /*toSize=*/4096, /*fromSize=*/4096)) {
        err("RNSD_PORT_TRANSPORT open failed");
        killSelf();
        return;
    }
    itsServerOnConnect(RNSD_PORT_TRANSPORT, onTransportConnect);
    itsServerOnDisconnect(RNSD_PORT_TRANSPORT, onTransportDisconnect);
    itsServerOnRecv(RNSD_PORT_TRANSPORT, onTransportRecv);

    if (!itsServerPortOpen(RNSD_PORT_DEST, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_MAILBOX_CONNS,
                           /*toSize=*/4096, /*fromSize=*/2048)) {
        err("RNSD_PORT_DEST open failed");
        killSelf();
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
        killSelf();
        return;
    }
    itsServerOnConnect(RNSD_PORT_ANNOUNCES,    onAnnouncesConnect);
    itsServerOnDisconnect(RNSD_PORT_ANNOUNCES, onAnnouncesDisconnect);
    itsServerOnRecv(RNSD_PORT_ANNOUNCES,       onAnnouncesRecv);

    /* RNSD_PORT_LINK — outbound Link consumer API (Phase C, §6.2).
     * Packet-mode: one Link plaintext per itsSend/itsRecv, no framing.
     * 4 KB/dir ≈ 9 in-flight Link packets — matches Resource cadence. */
    if (!itsServerPortOpen(RNSD_PORT_LINK, /*packetBased=*/true,
                           /*maxHandles=*/RNSD_MAX_LINK_CONNS,
                           /*toSize=*/4096, /*fromSize=*/4096)) {
        err("RNSD_PORT_LINK open failed");
        killSelf();
        return;
    }
    itsServerOnConnect(RNSD_PORT_LINK,    onLinkConnect);
    itsServerOnDisconnect(RNSD_PORT_LINK, onLinkDisconnect);
    itsServerOnRecv(RNSD_PORT_LINK,       onLinkRecv);
    itsOnAux(RNSD_PORT_LINK,              onLinkAux);   /* explicit teardown */

    loadOrCreateIdentity();
    storageSet("rnsd.up", 1);
    if (s_identity) storageSet("rnsd.identity_hash", s_identity->hexhash().c_str());

    /* Runtime-tunable mR caps/TTLs/cadence. Each fires once now (applying the
     * current stored value, or the fallback default if unset) and re-applies
     * on later `set`. Fallbacks are the working defaults; operators override
     * via `set s.rnsd.*`. No storageDefault — silent defaults wouldn't fire a
     * subscription, and the fallback in each read already covers "unset".
     *
     * Identity cache: 100 is too small for busy testnet traffic — entries get
     * evicted before we can probe them even though the path table still has the
     * route, so Identity::recall fails and rnprobe can't proceed. Default 1000. */
    NOW_AND_ON_CHANGE("s.rnsd.identity.cache_max", {
        RNS::Identity::known_destinations_maxsize(storageGetInt(key, 1000));
    });
    /* Path table: engages BasicHeapStore set_max_recs (uncapped until now —
     * only the 24h TTL pruned it). */
    NOW_AND_ON_CHANGE("s.rnsd.path.max", {
        RNS::Transport::path_table_maxsize(storageGetInt(key, 100));
    });
    NOW_AND_ON_CHANGE("s.rnsd.announce.table_max", {
        RNS::Transport::announce_table_maxsize(storageGetInt(key, 100));
    });
    NOW_AND_ON_CHANGE("s.rnsd.hashlist_max", {
        RNS::Transport::hashlist_maxsize(storageGetInt(key, 100));
    });
    NOW_AND_ON_CHANGE("s.rnsd.path.request_tags_max", {
        RNS::Transport::max_pr_tags(storageGetInt(key, 32));
    });
    /* Path-entry TTLs, seconds. */
    NOW_AND_ON_CHANGE("s.rnsd.path.ttl", {
        RNS::Transport::destination_timeout(storageGetInt(key, 86400));
    });
    NOW_AND_ON_CHANGE("s.rnsd.path.ttl_ap", {
        RNS::Transport::ap_path_time(storageGetInt(key, 21600));
    });
    NOW_AND_ON_CHANGE("s.rnsd.path.ttl_roaming", {
        RNS::Transport::roaming_path_time(storageGetInt(key, 3600));
    });
    /* jobs() cadence + table-cull cadence. */
    NOW_AND_ON_CHANGE("s.rnsd.jobs_interval_ms", {
        RNS::Transport::job_interval(storageGetInt(key, 250) / 1000.0f);
    });
    NOW_AND_ON_CHANGE("s.rnsd.cull_interval_s", {
        RNS::Transport::tables_cull_interval((float)storageGetInt(key, 60));
    });

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

        /* Phase B §5.1.6: `rnsd link <hash> [aspect]` one-shot probe.
         * CLI writes to this key; we build the Link here on the rnsd task. */
        storageSubscribeChanges("rnsd.cmd.link.open", onCmdLinkOpen);

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
                linkTick();

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

#if CONFIG_SPANGAP_LCD
#include "lcd.h"
/* Settings → Reticulum → General. Mirrors the web RnsdPanel. */
static void rnsdSettingsPane(void* arg) {
    lv_obj_t* p = static_cast<lv_obj_t*>(arg);
    lcdSettingSection(p, "Reticulum");
    lcdSettingValue  (p, "Identity", "rnsd.identity_hash");
    lcdSettingSwitch (p, "Enable", "s.rnsd.enable");
    lcdSettingSwitch (p, "Transport node", "s.rnsd.transport_enabled");
    lcdSettingText   (p, "Node name", "s.rnsd.name");
    lcdSettingSlider (p, "Announce (s)", "s.rnsd.announce.interval", 0, 21600);
    lcdSettingSection(p, "Path Table");
    lcdSettingSlider (p, "Capacity", "s.rnsd.path.max", 64, 512);
    lcdSettingSlider (p, "TTL (s)", "s.rnsd.path.ttl", 3600, 604800);
}
#endif

void rnsdInit(void)
{
    /* The iface / packet-connection tables are allocated in rnsdTaskMain (task
     * context) so heap tracking attributes them to rnsd, not the main task. */
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
        storageDefault("s.rnsd.link.path_timeout_s", 30);   /* §6.2 — LR retry budget */
        storageDefault("s.rnsd.link.orphan_ttl_s", 600);    /* §6.2 — keep orphaned Link 10 min */
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

#if CONFIG_SPANGAP_LCD
    lcdRegisterSettings("Reticulum/General", "General", rnsdSettingsPane);
#endif

    /* PSRAM stack, core 0 alongside tcpip_thread, prio 2. */
    s_task = spawnTask(rnsdTaskMain, TAG, 12288, nullptr, 2, 0, STACK_PSRAM);

    /* Phase C smoke consumer — its own ITS-client task, idle until
     * `rnsd clink …`. Core 1, prio 1, modest PSRAM stack. */
    spawnTask(clinkTaskMain, CLINK_TAG, 6144, nullptr, 1, 1, STACK_PSRAM);
}
