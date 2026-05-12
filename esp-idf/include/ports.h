/**
 * ports.h — ITS port constants for reticulous tasks.
 *
 * See docs/component-plan.md §9 and docs/plans/lxmf.md §5 for the full
 * ITS port surface.
 */
#pragma once

#include <cstdint>
#include "its.h"

/* ---- rnsd task ports ---- */

/** Transport registration. Connect payload is `rnsd_transport_t` describing
 *  the interface (name, MTU, bitrate, mode, capabilities). The connect
 *  handle then carries inbound RNS packets to rnsd and outbound RNS
 *  packets from rnsd (packet-mode ITS — one packet per send/recv).
 *  Disconnect = deregister. */
constexpr uint16_t RNSD_PORT_TRANSPORT = 1;

/** Browser network-map DC. Announce / path / link / iface events. */
constexpr uint16_t RNSD_PORT_MAP = 2;

/** Browser/CLI control DC: list dests, force announce, rotate identity,
 *  import/export. */
constexpr uint16_t RNSD_PORT_CTL = 3;

/** Bidirectional destination API for protocol consumers (rnprobe, lxmf, …).
 *  Open with `rnsdDestOpen()` from rnsd.h — connect payload is an
 *  rnsd-private struct, callers never construct it directly. After
 *  open, the handle carries type-tagged frames in both directions
 *  per the RNSD_DEST_* opcodes below.
 *
 *  See [docs/plans/lxmf.md §5](../docs/plans/lxmf.md#5-its-port). */
constexpr uint16_t RNSD_PORT_DEST = 4;

/** Datagram send. Aux for small (≤ITS aux cap), stream for larger
 *  payloads. */
constexpr uint16_t RNSD_PORT_DGRAM = 5;

/** Announce fan-out. Consumers connect with `rnsd_announces_connect_t`
 *  naming an optional aspect filter (empty = every announce). rnsd
 *  registers a single internal `AnnounceHandler` with empty filter at
 *  boot; each `received_announce` callback fans the event out to every
 *  matching connected subscriber as one packet-mode ITS message of
 *  shape:
 *
 *      hops(1) | dest_hash(16) | identity_hash(16) |
 *      app_data_len(2 BE) | app_data(N)
 *
 *  Per-slot drop-on-full (timeout=0) — slow consumers lose announces,
 *  not announces stall the rnsd task. Same fan-out shape as
 *  diptych-core's log `:1` consumers (see core `log.cpp`). */
constexpr uint16_t RNSD_PORT_ANNOUNCES = 6;

/** Generic Reticulum Link → ITS connection. Connect payload identifies the
 *  remote destination; rnsd establishes a Link and bridges in/out packets
 *  to/from the ITS connection. Deferred — needs mR Link support, which
 *  isn't there yet. */
constexpr uint16_t RNSD_PORT_LINK = 10;

/** RNS interface modes — mirrors Type::Interface::modes in microreticulum. */
enum rns_iface_mode : uint8_t {
    RNS_IFACE_MODE_FULL          = 0x01,
    RNS_IFACE_MODE_GATEWAY       = 0x02,
    RNS_IFACE_MODE_ACCESS_POINT  = 0x04,
    RNS_IFACE_MODE_ROAMING       = 0x08,
    RNS_IFACE_MODE_BOUNDARY      = 0x10,
};

/** Connect payload for RNSD_PORT_TRANSPORT. Sent by transport tasks when
 *  registering with rnsd. Fixed-size struct to keep the connect path
 *  cheap (fits in ITS_MAX_MSG_DATA = 96). */
typedef struct {
    char     name[24];      /* "tcp/0", "udp", "lora", "tcp_in/<addr:port>" */
    uint16_t mtu;           /* bytes — RNS protocol MTU is 500 */
    uint32_t bitrate;       /* bits/sec on the wire */
    uint8_t  mode;          /* rns_iface_mode */
    uint8_t  in;            /* 1 if iface accepts inbound packets */
    uint8_t  out;           /* 1 if iface sends outbound packets */
    uint8_t  fwd;           /* 1 if iface forwards (transport node) */
    uint8_t  rpt;           /* 1 if iface repeats announces */
    uint8_t  reserved[3];
} rnsd_transport_t;

/* ---- RNSD_PORT_DEST frame opcodes ---- */

enum : uint8_t {
    RNSD_DEST_OUT_PACKET = 0x01,   /* app → rnsd: send_id(2) | bytes */
    RNSD_DEST_OUT_RESULT = 0x02,   /* rnsd → app: send_id(2) | status(1) | rtt_ms(4) | hops(1) */
    RNSD_DEST_OUT_CANCEL = 0x03,   /* app → rnsd: send_id(2) */
    RNSD_DEST_IN_PACKET  = 0x04,   /* rnsd → app: bytes (decrypted plaintext) */
    RNSD_DEST_OUT_STATUS = 0x05,   /* rnsd → app: send_id(2) | type(1) | tail */
    RNSD_DEST_ANNOUNCE   = 0x06,   /* app → rnsd: app_data bytes (may be empty) */
};

/** OUT_RESULT.status. */
enum : uint8_t {
    RNSD_DEST_STATUS_SENT      = 0,   /* opportunistic egress acknowledged */
    RNSD_DEST_STATUS_DELIVERED = 1,   /* DIRECT link-proof received */
    RNSD_DEST_STATUS_CANCELLED = 2,   /* client wrote OUT_CANCEL */
    RNSD_DEST_STATUS_EVICTED   = 3,   /* rnsd buffer/memory limit */
};

/** OUT_STATUS.type — aux progress narration. See lxmf.md §5.2. */
enum : uint8_t {
    RNSD_DEST_AUX_REQUESTING_PATH   = 0x01,
    RNSD_DEST_AUX_PATH_KNOWN        = 0x02,   /* + iface(24) hops(1) next_hop(16) */
    RNSD_DEST_AUX_EGRESS_QUEUED     = 0x03,
    RNSD_DEST_AUX_LINK_ESTABLISHING = 0x04,
    RNSD_DEST_AUX_RESOURCE_PROGRESS = 0x05,   /* + pct(1) */
    RNSD_DEST_AUX_RETRY             = 0x06,   /* + attempt(1) reason(1) */
    RNSD_DEST_AUX_PATH_LOST         = 0x07,
};

/** Connect payload for RNSD_PORT_ANNOUNCES. Optional aspect filter — if
 *  non-empty, rnsd only delivers announces whose destination hash
 *  matches `Destination::hash_from_name_and_identity(aspect, identity)`,
 *  same predicate mR uses for AnnounceHandler subclasses. Empty filter
 *  delivers every announce mR sees. */
typedef struct {
    char    aspect[32];        /* dotted name, e.g. "lxmf.delivery"; "" = all */
} rnsd_announces_connect_t;
static_assert(sizeof(rnsd_announces_connect_t) <= ITS_MAX_MSG_DATA,
              "rnsd_announces_connect_t must fit ITS_MAX_MSG_DATA");

/* ---- lxmf task ports ---- */

/* lxmf has no client-facing ports. Storage is the API — every frontend
 * is a view over `s.lxmf.*` / `lxmf.*` / `secrets.lxmf.*` keys, and the
 * lxmf task subscribes to its own subtree to drive state changes. See
 * docs/plans/lxmf.md §3 for the rationale. */
