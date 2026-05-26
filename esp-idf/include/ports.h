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

/** Generic Reticulum Link → ITS connection (Phase C — link.md §6).
 *  Connect payload (rnsd-private rnsd_link_connect_t, built by
 *  rnsdLinkOpen()) identifies the remote destination; rnsd establishes
 *  the Link asynchronously and bridges plaintext packets to/from the
 *  packet-mode ITS handle (no framing bytes on the data path).
 *
 *  Consumer-initiated **explicit teardown** is an out-of-band aux frame
 *  on this same port (the data path stays type-byte-free): the payload
 *  is the link's `tag` string. itsDisconnect alone only *parks* the
 *  Link for `s.rnsd.link.orphan_ttl_s` (§10a.1 in-session reconnect);
 *  the aux is how a consumer says "really close it now, free the tag".
 *  Sent via rnsdLinkTeardown(tag) from rnsd.h. */
constexpr uint16_t RNSD_PORT_LINK = 10;

enum : uint8_t {
    RNSD_LINK_AUX_TEARDOWN     = 0x01,  /* payload: tag string (≤23 chars) */
    RNSD_LINK_AUX_SEND_RESOURCE = 0x02, /* payload: rnsd_link_send_resource_t —
                                         * Phase F outbound big send (link.md
                                         * §9.2). rnsd takes ownership of buf
                                         * and frees it once the engine has
                                         * copied it into encrypted parts. */
    RNSD_LINK_AUX_REQUEST      = 0x03,  /* payload: rnsd_link_request_t header
                                         * followed inline by path[path_len]
                                         * then data[data_len] — the nomad
                                         * page-fetch / request-response
                                         * primitive (nomad.md §1). Sent via
                                         * rnsdLinkRequest(). */
};

/** Request/response issue (RNSD_PORT_LINK aux, nomad.md §1). Sent by
 *  rnsdLinkRequest(): bridges a consumer byte-array request to µR's
 *  Link::request(path, data, …) on the Link already opened as `tag`. The
 *  path and request data are appended *inline* after this fixed header in
 *  the same aux frame: path occupies the next `path_len` bytes, the request
 *  data the following `data_len` bytes (`data_len == 0` → plain GET). The
 *  whole frame must fit ITS_MAX_MSG_DATA, so this rides packets only;
 *  request-as-Resource (large form uploads) is a later phase. */
typedef struct {
    uint8_t  op;            /* RNSD_LINK_AUX_REQUEST */
    char     tag[24];       /* outbound link tag (rnsdLinkOpen) */
    uint16_t req_id;        /* consumer correlation id, echoed in the response
                             * aux's opaque_id field */
    uint16_t resp_port;     /* consumer aux port the response/failed handoff
                             * is delivered to (on the requesting task) */
    uint16_t path_len;      /* path bytes following this header */
    uint16_t data_len;      /* request-data bytes following the path; 0 = GET */
    uint8_t  data_packed;   /* 1 = data is a complete msgpack object spliced
                             * verbatim as the request's 3rd element (NomadNet
                             * form {field_*,var_*} map); 0 = plain GET/bin */
    /* path[path_len], then data[data_len] follow inline. */
} rnsd_link_request_t;
static_assert(sizeof(rnsd_link_request_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_request_t must fit ITS_MAX_MSG_DATA");

/** Outbound Resource send request (RNSD_PORT_LINK aux, Phase F).
 *  Sent by rnsdLinkSendResource(). `buf` is a heap pointer in the shared
 *  address space; rnsd reads it on its own task, constructs the Resource
 *  (the engine copies the bytes), then free()s it. Caller must not touch
 *  buf after the call returns. */
typedef struct {
    uint8_t  op;            /* RNSD_LINK_AUX_SEND_RESOURCE */
    char     tag[24];       /* outbound link tag (rnsdLinkOpen) */
    void*    buf;           /* heap ptr, rnsd-owned after the aux */
    uint32_t len;
    uint32_t opaque_id;     /* echoed back in OUTBOUND_DONE (lxmf mid) */
} rnsd_link_send_resource_t;
static_assert(sizeof(rnsd_link_send_resource_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_send_resource_t must fit ITS_MAX_MSG_DATA");

/** Resource-aux opcodes (consumer's resource/response aux port). The
 *  REQUEST_* opcodes reuse the same handoff struct + delivery path as the
 *  RESOURCE_* ones (nomad.md §1): a request response can be a whole page,
 *  so it comes back as a heap buffer the consumer owns, tagged by the
 *  consumer's req_id (carried in opaque_id). */
enum : uint8_t {
    RNSD_LINK_RESOURCE_INBOUND_DONE  = 0x01,  /* buf valid, consumer owns it */
    RNSD_LINK_RESOURCE_OUTBOUND_DONE = 0x02,  /* buf null; opaque_id settles */
    RNSD_LINK_RESOURCE_FAILED        = 0x03,  /* buf null; transfer aborted */
    RNSD_LINK_REQUEST_RESPONSE       = 0x04,  /* buf = response bytes (may be
                                               * null/0 for an empty response),
                                               * consumer owns; opaque_id = req_id */
    RNSD_LINK_REQUEST_FAILED         = 0x05,  /* buf null; opaque_id = req_id */
};

/** Resource handoff frame. rnsd opens a one-shot ITS connection to the
 *  consumer's LXMF_LINK_RESOURCE_AUX_PORT carrying this as the connect
 *  payload (mirrors the rnsd_link_incoming_t pattern). On INBOUND_DONE
 *  the consumer takes ownership of `buf` and must rnsdResourceRelease()
 *  it. ≤ ITS_MAX_MSG_DATA. */
typedef struct {
    uint8_t  opcode;                   /* RNSD_LINK_RESOURCE_* */
    uint8_t  link_id[16];
    uint8_t  resource_hash[32];
    uint8_t  local_dest_hash[16];      /* which hosted dest (consumer→identity) */
    void*    buf;                      /* PSRAM ptr; consumer owns on INBOUND_DONE */
    uint32_t len;
    uint32_t opaque_id;                /* OUTBOUND_DONE correlation */
    uint8_t  flags;                    /* bit0 compressed, bit1 has_metadata */
    uint8_t  reserved[5];
} rnsd_link_resource_done_t;
static_assert(sizeof(rnsd_link_resource_done_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_resource_done_t must fit ITS_MAX_MSG_DATA");

/** RNS interface modes. These are the rnsd-facing wire values; they do
 *  NOT share the bit layout of mR's Type::Interface::modes — rnsd maps
 *  between the two (mapIfaceMode in rnsd.cpp). Keep this enum stable;
 *  never raw-cast it to an mR mode. */
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
    char     name[24];      /* "tcp/0", "auto", "lora", "tcp_in/<addr:port>" */
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
    RNSD_DEST_LINK_LISTEN = 0x07,  /* app → rnsd: link_inbox_port(2 BE) — Phase D */
};

/** Connect payload rnsd sends to the consumer's registered
 *  link_inbox_port on every accepted *inbound* Link (Phase D, §7.2).
 *  ≤ ITS_MAX_MSG_DATA. The consumer learns the rnsd-generated tag here
 *  so it can cross-reference rnsd.links.<tag>.* state. */
typedef struct {
    char     tag[24];                  /* rnsd-generated "in.<8hex>" */
    uint8_t  link_id[16];
    uint8_t  remote_identity_hash[16]; /* zeroed if peer not identified yet */
    uint8_t  local_dest_hash[16];      /* which hosted dest it landed on */
    uint16_t mtu;
    uint8_t  reserved[6];
} rnsd_link_incoming_t;
static_assert(sizeof(rnsd_link_incoming_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_incoming_t must fit ITS_MAX_MSG_DATA");

/** OUT_RESULT.status. */
enum : uint8_t {
    RNSD_DEST_STATUS_SENT      = 0,   /* opportunistic egress acknowledged */
    RNSD_DEST_STATUS_DELIVERED = 1,   /* DIRECT link-proof received */
    RNSD_DEST_STATUS_CANCELLED = 2,   /* client wrote OUT_CANCEL */
    RNSD_DEST_STATUS_EVICTED   = 3,   /* rnsd buffer/memory limit */
    RNSD_DEST_STATUS_FAILED    = 4,   /* gave up — no route found before deadline */
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
 * docs/plans/lxmf.md §3 for the rationale.
 *
 * The two ports below are *internal* (rnsd → lxmf only), not client-
 * facing: rnsd back-connects accepted inbound Links here after lxmf
 * registers via rnsdDestListenLinks() on its lxmf.delivery handle.
 * Phase E uses LINK_INBOX; LINK_RESOURCE_AUX is reserved for Phase F. */
constexpr uint16_t LXMF_LINK_INBOX_PORT        = 100;  /* inbound Link forwards */
constexpr uint16_t LXMF_LINK_RESOURCE_AUX_PORT = 101;  /* Resource handoff (Phase F) */
