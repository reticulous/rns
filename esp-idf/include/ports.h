/**
 * ports.h — ITS port constants for reticulous tasks.
 */
#pragma once

#include <cstdint>
#include "its.h"

/* ---- rnsd task ports ---- */

/** Interface registration. Connect payload is `rnsd_iface_t` describing
 *  the interface (name, MTU, bitrate, mode, capabilities). The connect
 *  handle then carries inbound RNS packets to rnsd and outbound RNS
 *  packets from rnsd (packet-mode ITS — one packet per send/recv).
 *  Disconnect = deregister. */
constexpr uint16_t RNSD_PORT_IFACE = 1;

/** Browser network-map DC. Announce / path / link / iface events. */
constexpr uint16_t RNSD_PORT_MAP = 2;

/** Browser/CLI control DC: list dests, force announce, rotate identity,
 *  import/export. */
constexpr uint16_t RNSD_PORT_CTL = 3;

/** Bidirectional destination API for protocol consumers (rnprobe, lxmf, …).
 *  Open with `rnsdDestOpen()` from rnsd.h — connect payload is an
 *  rnsd-private struct, callers never construct it directly. After
 *  open, the handle carries type-tagged frames in both directions
 *  per the RNSD_DEST_* opcodes below. */
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
 *      hops(1) | dest_hash(16) | identity_hash(16) | pubkey(64) |
 *      ratchet(32) | app_data(N)
 *
 *  app_data runs to the end of the message — there is no length field,
 *  because a packet-mode handle already carries the boundary. The public
 *  key rides along so a subscriber can act on an announce without calling
 *  back into rnsd; the ratchet is the announce's own field (all-zero when
 *  the destination advertises none) and is never part of app_data.
 *
 *  Per-slot drop-on-full (timeout=0) — slow consumers lose announces,
 *  not announces stall the rnsd task. Same fan-out shape as
 *  spangap-core's log `:1` consumers (see core `log.cpp`). */
constexpr uint16_t RNSD_PORT_ANNOUNCES = 6;

/** Generic Reticulum Link → ITS connection.
 *  Connect payload (rnsd-private rnsd_link_connect_t, built by
 *  rnsdLinkOpen()) identifies the remote destination; rnsd establishes
 *  the Link asynchronously and bridges plaintext packets to/from the
 *  packet-mode ITS handle (no framing bytes on the data path).
 *
 *  The Link's lifetime tracks the consumer's ITS handle 1:1: closing the
 *  handle (itsDisconnect) tears the Link down and frees the slot + tag.
 *  There is no separate teardown frame and no parking. */
constexpr uint16_t RNSD_PORT_LINK = 10;

/** Generic Reticulum Channel → ITS connection (RNSD_PORT_CHANNEL).
 *  Same shape as RNSD_PORT_LINK, but the bytes on the packet-mode ITS handle
 *  are *reliable, in-order Channel messages* (each one delivered exactly once,
 *  retried until the peer proves it) rather than best-effort Link packets. rnsd
 *  opens the underlying Link, obtains its Channel (Link::get_channel()), and
 *  bridges Channel messages to/from the handle. The Link itself is never
 *  exposed — the consumer only ever sees the channel. Connect payload is the
 *  rnsd-private rnsd_channel_connect_t (built by rnsdChannelOpen()).
 *  Closing the handle tears the Channel + Link down. */
constexpr uint16_t RNSD_PORT_CHANNEL = 11;
/* The connect payload (rnsd_channel_connect_t) is rnsd-private — defined in
 * rnsd.cpp alongside rnsd_link_connect_t; consumers go through rnsdChannelOpen().
 * Inbound channels reuse rnsd_link_incoming_t as the per-channel connect
 * payload. */

/** Directory claims + out-of-band key seeding (aux-only, no connection).
 *
 *  Every write to the directory store must happen on the rnsd task — the store
 *  is single-writer by construction, which is what lets every other task read
 *  it lock-free. Claims originate on an app task (lxmf/nomad/rlpg observe a
 *  storage write and react on their own task), so they are marshalled here as
 *  one `rnsd_dir_aux_t` and applied by rnsd's aux handler.
 *
 *  Fire-and-forget: a claim is advisory — an ordering preference for eviction,
 *  never a lifetime guarantee — so there is no reply to wait for. */
constexpr uint16_t RNSD_PORT_DIR = 12;

enum : uint8_t {
    RNSD_DIR_OP_CLAIM       = 0x00,  /* assert/refresh a claim */
    RNSD_DIR_OP_CLAIM_TOUCH = 0x01,  /* restamp an existing claim */
    RNSD_DIR_OP_CLAIM_DROP  = 0x02,  /* release this consumer's claim */
    RNSD_DIR_OP_SEED_PUBKEY = 0x03,  /* key learned off-network */
};

typedef struct {
    uint8_t  op;             /* RNSD_DIR_OP_* */
    uint8_t  consumer;       /* RNSD_CLAIM_* (rnsd.h) */
    uint8_t  klass;          /* RNSD_CLAIM_PERSIST | _EPHEMERAL */
    uint8_t  layers;         /* RNSD_CLAIM_LAYER_* */
    uint32_t decay_s;        /* ordering scale since last touch; 0 = default */
    uint8_t  dest[16];
    uint8_t  pubkey[64];     /* SEED_PUBKEY only */
} rnsd_dir_aux_t;
static_assert(sizeof(rnsd_dir_aux_t) <= ITS_MAX_MSG_DATA,
              "rnsd_dir_aux_t must fit ITS_MAX_MSG_DATA");

enum : uint8_t {
    /* 0x01 was RNSD_LINK_AUX_TEARDOWN — removed; itsDisconnect tears down. */
    RNSD_LINK_AUX_SEND_RESOURCE = 0x02, /* payload: rnsd_link_send_resource_t —
                                         * outbound big send (Resource). rnsd
                                         * takes ownership of buf and frees it
                                         * once the engine has copied it into
                                         * encrypted parts. */
    RNSD_LINK_AUX_REQUEST      = 0x03,  /* payload: rnsd_link_request_t header
                                         * followed inline by path[path_len]
                                         * then data[data_len] — the nomad
                                         * page-fetch / request-response
                                         * primitive. Sent via
                                         * rnsdLinkRequest(). */
    RNSD_LINK_AUX_IDENTIFY     = 0x04,  /* payload: rnsd_link_identify_t —
                                         * identify to the remote peer on an
                                         * ACTIVE outbound Link, signing with
                                         * the identity the link was opened
                                         * with (rnsdLinkOpen identity_key).
                                         * Sent via rnsdLinkIdentify(). */
};

/** Link-identify request (RNSD_PORT_LINK aux). Sent by rnsdLinkIdentify().
 *  Initiator-only (µR Link::identify is a no-op on inbound links); the
 *  peer sees rnsd.links.<tag>.remote_identity / .remote_dest flip on its
 *  side once the LINKIDENTIFY validates. */
typedef struct {
    uint8_t  op;            /* RNSD_LINK_AUX_IDENTIFY */
    char     tag[24];       /* outbound link tag (rnsdLinkOpen) */
    char     identity_key[40]; /* storage path of the 128-hex private key to
                                * sign with; "" = the identity the link was
                                * opened with. µR signs a LINKIDENTIFY with
                                * whatever identity it is handed, so WHO a
                                * link says it is need not be whose link it
                                * is: nomad browses on rnsd's identity and
                                * identifies as an LXMF one. */
} rnsd_link_identify_t;
static_assert(sizeof(rnsd_link_identify_t) <= ITS_MAX_MSG_DATA,
              "rnsd_link_identify_t must fit ITS_MAX_MSG_DATA");

/** Request/response issue (RNSD_PORT_LINK aux). Sent by
 *  rnsdLinkRequest(): bridges a consumer byte-array request to µR's
 *  Link::request(path, data, …) on the Link already opened as `tag`. The
 *  path and request data are appended *inline* after this fixed header in
 *  the same aux frame: path occupies the next `path_len` bytes, the request
 *  data the following `data_len` bytes (`data_len == 0` → plain GET). The
 *  whole frame must fit ITS_MAX_MSG_DATA, so this rides packets only;
 *  request-as-Resource (large form uploads) is not yet implemented. */
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

/** Outbound Resource send request (RNSD_PORT_LINK aux).
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
 *  RESOURCE_* ones: a request response can be a whole page,
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
    int16_t  rssi;                     /* INBOUND_DONE: link radio RSSI dBm (last part);
                                          INT16_MIN = no radio metric */
    int16_t  snr;                      /* INBOUND_DONE: link radio SNR dB*10 */
    char     iface[24];                /* INBOUND_DONE: receiving interface raw name; '' = unknown */
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

/* Default announce bandwidth cap (percent) applied when an interface registers
 * with announce_cap == 0. Mirrors RNS Reticulum.ANNOUNCE_CAP. */
#define RNS_IFACE_ANNOUNCE_CAP_DEFAULT 2

/** Connect payload for RNSD_PORT_IFACE. Sent by interface tasks when
 *  registering with rnsd. Fixed-size struct to keep the connect path cheap
 *  (fits in ITS_MAX_MSG_DATA).
 *
 *  IFAC (Interface Access Codes): an interface that wants to be on an
 *  access-coded RNS network fills `ifac_netname` (network_name) and/or
 *  `ifac_netkey` (passphrase); rnsd derives the IFAC identity and applies it
 *  (Transport::derive_ifac). Both empty => an open (non-IFAC) interface.
 *  `ifac_netkey` is a secret — interfaces read it from `secrets.*` storage. */
typedef struct {
    char     name[24];      /* "tcp/0", "auto", "lora/0", "tcp_in/<addr:port>" */
    uint16_t mtu;           /* bytes — RNS protocol MTU is 500 */
    uint32_t bitrate;       /* bits/sec on the wire */
    uint8_t  mode;          /* rns_iface_mode */
    uint8_t  in;            /* 1 if iface accepts inbound packets */
    uint8_t  out;           /* 1 if iface sends outbound packets */
    uint8_t  fwd;           /* 1 if iface forwards (transport node) */
    uint8_t  rpt;           /* 1 if iface repeats announces */
    uint8_t  ifac_size;     /* IFAC access-code length in bytes; 0 => default (1) */
    uint8_t  announce_cap;  /* max % of interface bandwidth spent propagating
                               announces; 0 => rnsd applies the RNS default (2) */
    uint8_t  point_to_point; /* 1 => no hidden-node problem (single peer, e.g.
                               TCP, or a switched LAN): forwarded announces and
                               path requests aren't echoed back out the
                               interface they arrived on. 0 (default) => shared
                               radio medium; keep re-broadcasting for hidden
                               nodes (LoRa, ESP-NOW). */
    uint8_t  community_radius; /* This interface's COMMUNITY: nodes within this
                               many hops heard on it are the ones this node
                               works for. Within the radius, an announce is
                               STORED (the original bytes kept, so path
                               requests for the member can be answered from
                               custody — the ability half of being a gateway),
                               ranked to persist in the directory, given the
                               custody path lifetime, and RE-BROADCAST to the
                               rest of the community; and path requests
                               arriving on an interface with a community
                               (radius > 0) are searched on the requestor's
                               behalf, out every other interface. 0 (the
                               struct default) => no community: a pure
                               endpoint/uplink — everything heard is forwarded
                               and resolved on demand, nothing unrequested is
                               stored, no relay work is done onto it, and no
                               errands are run for it. Nodes beyond the radius
                               are still HEARD (they show up on the mesh) and
                               REACHABLE (on-demand resolution, the direct
                               peer's own announces, claims and active routes
                               are all kept regardless) — they are just not
                               this node's responsibility. Answering a path
                               request for a destination already in custody is
                               never gated: custody, once taken, is served to
                               anyone who asks. */
    uint8_t  rx_signal;     /* 1 => each inbound data frame is prefixed with a
                               4-byte signal header int16 rssi_dBm | int16 snr_dB*10
                               (both BE, INT16_MIN = absent). Set by radio ifaces
                               (LoRa) that measure per-packet RSSI/SNR. */
    uint8_t  tx_power_known; /* 1 => tx_power_dbm below is meaningful. Zero-init
                               means "this interface has no notion of transmit
                               power", which is the right reading for anything
                               that isn't a radio and for a straddle predating
                               the field. */
    int8_t   tx_power_dbm;  /* Antenna transmit power in dBm, as configured. Read
                               only when tx_power_known. rnsd hands it to mR so
                               the rx-report proof can state the power that
                               produced the signal the peer measures — the other
                               half of a path loss. A radio that adapts its power
                               per peer reports its configured ceiling here; the
                               figure is a readout for the operator, not a term
                               in any control loop. Re-registration is what
                               refreshes it, which is what a config change
                               already does. */
    uint8_t  rx_origin;     /* 1 => this interface carries SEVERAL peers under one
                               registration and names them itself: each inbound
                               data frame is prefixed with a 16-byte ORIGIN KEY
                               saying which of them sent it, and each peer is
                               declared with RNSD_IFACE_AUX_PEER. It therefore
                               also overrides `point_to_point` as far as the
                               neighbourhood is concerned — AutoInterface sets
                               both, the one for the no-echo rule (a switched
                               LAN has no hidden node) and the other because it
                               has many peers. An ALL-ZERO key means "the sender
                               is unknown" — a shared radio can name the
                               transmitter of an announce it parsed and not of a
                               packet it merely overheard, and the field is
                               present either way so the strip stays a fixed
                               offset. For a medium that carries
                               several peers under ONE registration —
                               AutoInterface, where every peer is a unicast UDP
                               address — it is the only thing that can say who a
                               packet came from, and so the only way rnsd can
                               group a node's announces. A point-to-point
                               interface sets neither this nor a key: the
                               interface IS the node. The key is opaque to rnsd
                               and needs only to be stable and unique within the
                               interface (auto uses the peer's in6_addr
                               verbatim); the human-readable form is declared
                               separately with RNSD_IFACE_AUX_PEER. */
    char     peer_label[48];/* Who is at the far end, in an operator's terms —
                               a Bluetooth MAC, host:port. For a POINT-TO-POINT
                               interface only, where the interface is one node.
                               It is what the neighbourhood listing shows until
                               an announce gives the node a name, so a peer that
                               has attached and said nothing is still a row
                               rather than a silence. "" = nothing to show. */
    char     ifac_netname[32]; /* IFAC network_name; "" => no IFAC */
    char     ifac_netkey[64];  /* IFAC passphrase; "" => no IFAC */
} rnsd_iface_t;
static_assert(sizeof(rnsd_iface_t) <= ITS_MAX_MSG_DATA,
              "rnsd_iface_t must fit ITS_MAX_MSG_DATA");

/* ---- RNSD_PORT_IFACE aux opcodes ---- */

enum : uint8_t {
    RNSD_IFACE_AUX_ANNOUNCE = 0x01,  /* payload: rnsd_iface_announce_t */
    RNSD_IFACE_AUX_PEER     = 0x02,  /* payload: rnsd_iface_peer_t */
};

/** "Say who we are on these interfaces, now" (RNSD_PORT_IFACE aux). Sent by
 *  rnsdIfaceAnnounceNow(); rnsd replays every hosted destination's stored
 *  announce onto each matching interface, pinned to it, through the same
 *  debounced path a fresh registration uses.
 *
 *  Addressed by NAME PREFIX rather than by handle, because the caller is an
 *  interface straddle and its unit of thought is the medium, not the
 *  registration: BLE registers one interface per peer and TCP one per
 *  connection, so "announce on Bluetooth" is `ble` and "announce on TCP" is
 *  `tcp` (which also catches `tcp_in/…`). An exact name — `lora/0`, `auto` —
 *  is simply the prefix that matches one. Empty matches every interface, which
 *  is what the coalesced application announce uses.
 *
 *  Fire-and-forget, safe from any task: there is no reply, and a request for a
 *  prefix nothing matches is a no-op rather than an error. */
typedef struct {
    uint8_t  op;            /* RNSD_IFACE_AUX_ANNOUNCE */
    char     prefix[24];    /* registered-name prefix; "" = every interface */
} rnsd_iface_announce_t;
static_assert(sizeof(rnsd_iface_announce_t) <= ITS_MAX_MSG_DATA,
              "rnsd_iface_announce_t must fit ITS_MAX_MSG_DATA");

/** "A peer appeared / went away under this interface" (RNSD_PORT_IFACE aux),
 *  for a medium that carries SEVERAL peers under one registration. Sent on the
 *  interface's own handle, so rnsd knows which interface it is about.
 *
 *  This is the other half of `rx_origin`: the key attributes an inbound packet,
 *  and this gives the key a human-readable label and a lifetime. A peer
 *  declared here is a row in the neighbourhood listing from the moment it is
 *  reachable — labelled by its transport address until an announce names it —
 *  and stops being one when it is withdrawn, which is the only thing that can
 *  say a peer has left, since nothing announces a departure.
 *
 *  A point-to-point interface sends none of these: the interface is the node,
 *  and `rnsd_iface_t.peer_label` says who is at the far end.
 *
 *  Fire-and-forget, safe from any task; a withdrawal of a key never declared is
 *  a no-op. */
typedef struct {
    uint8_t  op;            /* RNSD_IFACE_AUX_PEER */
    uint8_t  up;            /* 1 = present, 0 = gone */
    /* The EXACT registered name, not a prefix: this names one interface's peer,
     * and aux is addressed to a port rather than to a handle, so the message
     * has to say which registration it belongs to. */
    char     iface[24];
    uint8_t  key[16];       /* the same origin key inbound frames are prefixed with */
    char     label[48];     /* the peer in an operator's terms — an address */
} rnsd_iface_peer_t;
static_assert(sizeof(rnsd_iface_peer_t) <= ITS_MAX_MSG_DATA,
              "rnsd_iface_peer_t must fit ITS_MAX_MSG_DATA");

/* ---- RNSD_PORT_DEST frame opcodes ---- */

enum : uint8_t {
    RNSD_DEST_OUT_PACKET = 0x01,   /* app → rnsd: send_id(2) | bytes */
    RNSD_DEST_OUT_RESULT = 0x02,   /* rnsd → app: send_id(2) | status(1) | rtt_ms(4) | hops(1) */
    RNSD_DEST_OUT_CANCEL = 0x03,   /* app → rnsd: send_id(2) */
    RNSD_DEST_IN_PACKET  = 0x04,   /* rnsd → app: bytes (decrypted plaintext) */
    RNSD_DEST_OUT_STATUS = 0x05,   /* rnsd → app: send_id(2) | type(1) | tail */
    RNSD_DEST_ANNOUNCE   = 0x06,   /* app → rnsd: app_data bytes (may be empty) */
    RNSD_DEST_LINK_LISTEN = 0x07,  /* app → rnsd: link_inbox_port(2 BE) */
    RNSD_DEST_CHANNEL_LISTEN = 0x08, /* app → rnsd: chan_inbox_port(2 BE) — like
                                      * LINK_LISTEN but forwards a reliable
                                      * Channel (inside the accepted inbound Link)
                                      * to the consumer instead of raw link
                                      * packets. Used by the rnsh server. */
};

/** Connect payload rnsd sends to the consumer's registered
 *  link_inbox_port on every accepted *inbound* Link.
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

/** OUT_RESULT.status.
 *
 *  Opportunistic sends emit OUT_RESULT *twice*: SENT immediately on
 *  egress (transfer accepted by Transport), then a second result when
 *  the delivery proof lands (DELIVERED) or the receipt times out
 *  (PROOF_TIMEOUT). PROOF_TIMEOUT is not a failure — the packet may
 *  well have arrived; the peer may simply not prove (their
 *  prove_incoming dial is off) or the proof was lost. */
enum : uint8_t {
    RNSD_DEST_STATUS_SENT          = 0,  /* opportunistic egress acknowledged */
    RNSD_DEST_STATUS_DELIVERED     = 1,  /* cryptographic delivery proof received */
    RNSD_DEST_STATUS_CANCELLED     = 2,  /* client wrote OUT_CANCEL */
    RNSD_DEST_STATUS_EVICTED       = 3,  /* rnsd buffer/memory limit */
    RNSD_DEST_STATUS_FAILED        = 4,  /* gave up — no route found before deadline */
    RNSD_DEST_STATUS_PROOF_TIMEOUT = 5,  /* no delivery proof before the receipt
                                          * deadline (follows an earlier SENT) */
    RNSD_DEST_STATUS_TOO_LARGE     = 6,  /* payload exceeds the single-packet
                                          * encrypted MDU — caller must use a
                                          * Link/Resource, not opportunistic */
};

/** OUT_STATUS.type — aux progress narration. */
enum : uint8_t {
    RNSD_DEST_AUX_REQUESTING_PATH   = 0x01,
    RNSD_DEST_AUX_PATH_KNOWN        = 0x02,   /* + iface(24) hops(1) next_hop(16) */
    RNSD_DEST_AUX_EGRESS_QUEUED     = 0x03,
    RNSD_DEST_AUX_LINK_ESTABLISHING = 0x04,
    RNSD_DEST_AUX_RESOURCE_PROGRESS = 0x05,   /* + pct(1) */
    RNSD_DEST_AUX_RETRY             = 0x06,   /* + attempt(1) reason(1) */
    RNSD_DEST_AUX_PATH_LOST         = 0x07,
    RNSD_DEST_AUX_QUEUE_FULL        = 0x08,   /* rnsd's per-conn pending
                                               * path-search table is full; the
                                               * send was NOT accepted. The app
                                               * holds the message and resends
                                               * once a slot frees (backpressure,
                                               * never a drop). */
};

/** RNSD_DEST_AUX_RETRY reason byte. */
enum : uint8_t {
    RNSD_DEST_RETRY_REASON_PATH_TIMEOUT = 0x01,  /* path request unanswered,
                                                  * asked the network again */
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
 * lxmf task subscribes to its own subtree to drive state changes.
 *
 * The two ports below are *internal* (rnsd → lxmf only), not client-
 * facing: rnsd back-connects accepted inbound Links here after lxmf
 * registers via rnsdDestListenLinks() on its lxmf.delivery handle.
 * LINK_INBOX carries inbound Link forwards; LINK_RESOURCE_AUX carries
 * Resource handoffs. */
constexpr uint16_t LXMF_LINK_INBOX_PORT        = 100;  /* inbound Link forwards */
constexpr uint16_t LXMF_LINK_RESOURCE_AUX_PORT = 101;  /* Resource handoff */

/* ---- netgraph task ports ---- */

/** Inbound netgraph sync Channels. netgraph hosts the node's
 *  `netgraph.discovery` destination and calls rnsdDestListenChannels() on it,
 *  so rnsd back-connects each accepted Channel here with an
 *  `rnsd_link_incoming_t`. The handle then carries the DIGEST / WANT /
 *  RECORD_PART / DONE messages of the record exchange (netgraph.h). */
constexpr uint16_t NETGRAPH_SYNC_PORT = 140;
