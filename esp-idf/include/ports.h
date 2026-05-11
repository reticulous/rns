/**
 * ports.h — ITS port constants for reticulous tasks.
 *
 * See docs/component-plan.md §9 for the full ITS port surface.
 */
#pragma once

#include <cstdint>

/* ---- rnsd task ports ---- */

/** Transport registration. Connect payload is `rnsd_register_t` describing
 *  the interface (name, MTU, bitrate, mode, capabilities). The connect
 *  handle then carries inbound RNS packets to rnsd and outbound RNS
 *  packets from rnsd (packet-mode ITS — one packet per send/recv).
 *  Disconnect = deregister. */
constexpr uint16_t RNSD_PORT_REGISTER = 1;

/** Browser network-map DC. Announce / path / link / iface events. */
constexpr uint16_t RNSD_PORT_MAP = 2;

/** Browser/CLI control DC: list dests, force announce, rotate identity,
 *  import/export. */
constexpr uint16_t RNSD_PORT_CTL = 3;

/** Raw-packet API for protocol consumers (rnprobe today, lxmf later).
 *  Connect payload (rnsd_packet_connect_t) specifies the target dest hash,
 *  aspect, dest type, and storage key for the sender identity. Thereafter
 *  each ITS packet app→rnsd is the *payload* to wrap in an RNS Packet (rnsd
 *  constructs / encrypts / sends via Transport — apps never touch mR
 *  internals). Each ITS packet rnsd→app is a 6-byte result for the most
 *  recent send: status (0=delivery, 1=timeout) + rtt_ms (big-endian u32)
 *  + hops_at_send (u8). */
constexpr uint16_t RNSD_PORT_PACKET = 4;

/** Datagram send. Aux for small (≤ITS aux cap), stream for larger
 *  payloads. */
constexpr uint16_t RNSD_PORT_DGRAM = 5;

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

/** Connect payload for RNSD_PORT_REGISTER. Sent by transport tasks when
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
} rnsd_register_t;

/** Connect payload for RNSD_PORT_PACKET. Identifies the target destination,
 *  aspect, dest type, and the storage key holding the sender identity's
 *  private key. Fixed 96 B (== ITS_MAX_MSG_DATA), so it always fits in the
 *  itsConnect aux slot exactly once. */
typedef struct {
    uint8_t dest_hash[16];       /* RNS::Type::Reticulum::DESTINATION_LENGTH */
    char    aspect[32];          /* dotted name, e.g. "lxmf.delivery"; NUL-terminated */
    char    identity_key[40];    /* storage key (e.g. "secrets.rnsd.identity"); NUL-terminated; empty → default */
    uint8_t dest_type;           /* 0=SINGLE, 1=PLAIN, 2=GROUP */
    uint8_t reserved[7];         /* pad to 96 */
} rnsd_packet_connect_t;
static_assert(sizeof(rnsd_packet_connect_t) == 96, "rnsd_packet_connect_t must fit ITS_MAX_MSG_DATA");

/* ---- lxmf task ports ---- */

/** Browser chat DC: {send: …} / {recv: …} JSON per message. */
constexpr uint16_t LXMF_PORT_CHAT = 1;

/** Task-to-task LXMF API for other modules. */
constexpr uint16_t LXMF_PORT_API = 2;
