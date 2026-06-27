# rns — Reticulum on the device

**rns** brings the [Reticulum](https://reticulum.network) network stack to the
device. Its core is **`rnsd`**, a single FreeRTOS task that owns the entire RNS
protocol state — identity, destinations, the path table, the Transport state
machine, Links, and Resources — and exposes it to the rest of the device. Other
straddles ([iface-tcp](../iface-tcp), [iface-auto](../iface-auto),
[iface-lora](../iface-lora), [iface-espnow](../iface-espnow)) plug their
interfaces in over ITS; `rnsd` itself has **zero** networking or radio
dependencies.

Reticulum is Mark Qvist's cryptography-based networking stack for resilient,
self-configuring networks over anything that can carry packets — LoRa, packet
radio, plain TCP/IP, a serial wire. There is no central authority and no
assigned addresses: every node is a self-generated cryptographic identity, links
are end-to-end encrypted by default, and the network keeps routing over cheap,
intermittently-connected links where conventional stacks fall over.

## Origins

The protocol engine is a modified fork of
[`attermann/microReticulum`](https://github.com/attermann/microReticulum) (µR),
the C++ port of Reticulum, kept under
[`esp-idf/components/microreticulum/`](esp-idf/components/microreticulum/). µR
provides `RNS::Reticulum`, `Transport`, `Interface`, `Link`, `Identity`,
`Destination`, `Packet`, and `Resource` — pathfinding, routing, link
establishment, and crypto.

On top of and inside that we added **`rnsd`** (the task that runs µR and bridges
it to the device over ITS, the in-process inter-task IPC), swapped µR's
Arduino-era dependencies for device-native ones (mbedTLS + ed25519-donna/x25519,
a hand-rolled MsgPack shim, cJSON, the central `gp_alloc` allocator, PSRAM
placement of large tables), and made a handful of correctness fixes to µR
itself. The full inventory of µR changes lives in [INTERNALS.md](INTERNALS.md);
this file is the user/operator guide.

## What this straddle owns

```
rns/
├── esp-idf/
│   ├── include/
│   │   ├── rnsd.h        public C API (rnsdLinkOpen, rnsdRecallPubkey, …)
│   │   └── ports.h       ITS port constants + frame opcodes shared with consumers
│   ├── src/rnsd.cpp      the rnsd task: identity, Transport, iface table, links
│   └── components/
│       ├── microreticulum/    our modified fork of attermann/microReticulum
│       └── bzip2/             vendored bzip2 1.0.8
└── browser/
    └── src/
        ├── modules/rnsd.ts          self-registering pinia module + RPC
        ├── panels/RnsdPanel.vue     Reticulum Settings panel
        ├── panels/NodesWindow.vue   live announce / path-table viewer
        └── panels/MapWindow.vue     status floating windows
```

## What it does

`rnsd` has no radio or network dependencies of its own. It receives RNS-format
packets from *interface* straddles over ITS, runs Transport, and sends packets
back out the same way. Everything else — messaging, page serving, discovery — is
a consumer that talks to `rnsd` over ITS or through its byte-array C API in
[`include/rnsd.h`](esp-idf/include/rnsd.h).

```
  iface-tcp  ─┐
  iface-lora ─┤  RNS packets        ┌─ lxmf   (messaging)
  iface-espnow┼───────  rnsd  ──────┼─ nomad  (page fetch)
  iface-auto ─┘   (Transport)       └─ your app
```

Downstream tasks operate on raw byte arrays and storage keys; they **never**
include `RNS::Identity` or any other µR type. That isolation is what lets
[lxmf](../lxmf) and [nomad](../nomad) build and test without dragging µR into
their dependency graphs, and means the engine underneath could be swapped
without touching consumers.

### How interfaces talk to it

An interface straddle gets Reticulum packets to and from the outside world
(TCP, LoRa, ESP-NOW…). To plug into Transport it opens an ITS connection to
**`RNSD_PORT_IFACE`** with an `rnsd_iface_t` connect payload describing
the interface: name (`"tcp/0"`, `"lora/0"`), MTU, bitrate, mode
(full/gateway/access-point/roaming/boundary), in/out/forward/repeat flags, and
optionally IFAC credentials for an access-coded network. After that the handle
*is* the packet pipe — every `itsSend` is one outbound RNS packet leaving on
that interface, every `itsRecv` is one inbound packet arriving. Disconnecting
deregisters the interface.

### How lxmf and nomad talk to it

Consumers never construct destinations or links; they call the wrappers in
`rnsd.h`:

- **lxmf** hosts its delivery destination with `rnsdDestOpen("lxmf.delivery", …)`,
  subscribes to discovery on `RNSD_PORT_ANNOUNCES` (filtered to `lxmf.delivery`),
  opens direct links with `rnsdLinkOpen()` for delivery, registers for inbound
  links with `rnsdDestListenLinks()`, and ships large messages as Resources via
  `rnsdLinkSendResource()`. It also uses the byte-array crypto helpers
  (`rnsdRecallPubkey`, `rnsdDestinationHash`, `rnsdSign`).
- **nomad** opens an outbound link with `rnsdLinkOpen()` and fetches pages with
  `rnsdLinkRequest("/page/index.mu", …)` — Reticulum request/response over a link.

A minimal consumer:

```c
// Host an inbound destination and learn its address.
int h = rnsdDestOpen("myapp.inbox", "secrets.myapp.id", /*SINGLE*/0,
                     /*ref*/0, on_recv, on_disc);

// Reach a remote: recall its key (ask the network if we haven't heard it),
// then open a link by its 16-byte destination hash.
uint8_t pub[RNSD_PUBKEY_LEN];
if (!rnsdRecallPubkey(dest_hash, pub)) rnsdRequestPath(dest_hash);   // retry later
int lh = rnsdLinkOpen(dest_hash, "myapp.inbox", "secrets.myapp.id",
                      "myapp.0", /*path_to*/0, /*link_to*/0, 0, on_recv, on_disc);
// lh returns immediately; watch rnsd.links.myapp.0.state for "active".
itsSend(lh, payload, n, timeout);     // one Link packet
```

The link's lifetime tracks your ITS handle 1:1 — close the handle and the link
tears down. A consumer that wants a warm link across idle gaps simply keeps the
handle open (this is how lxmf pools per-peer links).

`rnsd` is started for you: the build's generated init brings up the identity,
µR `Reticulum` + `Transport`, the interface table, and the announce fan-out.
If the `rns` straddle is in your build, `rnsd` is running — interfaces register
themselves at runtime, so it has zero compile-time knowledge of which exist.

## ITS port map

| Port | Name | Purpose |
|---|---|---|
| 1 | `RNSD_PORT_IFACE` | Interface registration + the inbound/outbound packet pipe. |
| 2 | `RNSD_PORT_MAP` | Browser network-map feed (announce/path/link/iface events). |
| 3 | `RNSD_PORT_CTL` | Browser/CLI control (list dests, force announce, rotate identity). |
| 4 | `RNSD_PORT_DEST` | Hosted-destination API (`rnsdDestOpen`); type-tagged frames both ways. |
| 5 | `RNSD_PORT_DGRAM` | Datagram send. |
| 6 | `RNSD_PORT_ANNOUNCES` | Announce fan-out to subscribers, with an optional aspect filter. |
| 10 | `RNSD_PORT_LINK` | Outbound links (`rnsdLinkOpen`) + request/Resource aux. |

(`lxmf` reserves internal ports 100/101 for rnsd→lxmf inbound-link and Resource
hand-offs; these are not client-facing.) Opcode tables for the framed ports
(`RNSD_DEST_*`, link aux, resource aux) are in
[`include/ports.h`](esp-idf/include/ports.h).

## Storage variables

`rnsd` has no socket API for configuration — storage is the control surface.
Settings live under `s.rnsd.*` (writable by user/browser); runtime state and
telemetry are published under `rnsd.*` and `rns.ready` for anything to observe.

### Settings (read)

| Key | Default | Meaning |
|---|---|---|
| `s.rnsd.transport_enabled` | `0` | Act as a Reticulum transport node (forward for others). |
| `s.rnsd.announce.interval` | `1800` | Seconds between periodic destination announces. |
| `s.rnsd.remote_management` | `1` | Host the `rnstransport.remote.management` destination. |
| `s.rnsd.respond_to_probes` | `0` | Host `rnstransport.probe` and answer probes (PROVE_ALL). |
| `s.rnsd.prove_incoming` | `1` | Emit delivery proofs for inbound packets we receive. |
| `s.rnsd.proof_timeout_s` | `60` | Deadline for an outbound delivery-proof receipt. |
| `s.rnsd.link.path_timeout_s` | `30` | Path-request / link-request retry budget. |
| `s.rnsd.link.request_timeout_s` | `15` | Request/response (page fetch) timeout. |
| `s.rnsd.link.max_inbound_resources_total` | `4` | Concurrent inbound Resource cap across all links. |
| `s.rnsd.its_no_pool` | `0` | Disable the ITS server inbox pool (debug). |
| `s.rnsd.debug.only_local` | `0` | Demote announce-traffic debug logs to verbose. |
| `s.lxmf.max_resource_size` | `262144` | Size gate for accepting an inbound Resource. |
| `s.net.up_wait_s` | `20` | Boot barrier: how long to wait for the network at startup. |

### Runtime state & telemetry (written)

| Key | Meaning |
|---|---|
| `rns.ready` | Boot barrier — set once the clock, network, and a settle delay have passed; consumers wait on this before using rnsd. |
| `rnsd.up` | Task is alive. |
| `rnsd.identity_hash` | Hex hash of rnsd's default identity. |
| `rnsd.iface_event_seq` | Monotonic counter bumped on interface up/down. |
| `rnsd.stats.{packets_in,packets_out,bytes_in,bytes_out,ifaces_up}` | Traffic counters. |
| `rnsd.links.<tag>.{state,direction,aspect,remote_hash,opened_s,last_error,…}` | Per-link state tree, keyed by the caller's `tag` — observable before the link_id exists. |
| `rnsd.links.byid.<link_id>` | Reverse index: link_id → tag. |
| `rnsd.dest.<idx>.{aspect,dest}` | Hosted-destination (our-dest) observability. |
| `rnsd.ifaces.<name>.{up,mode,mtu,bitrate,rx_bytes,rx_packets,tx_bytes,tx_packets}` | Per-interface state and counters. |
| `rnsd.paths` | Path-table snapshot (up to 64 entries: `{dest, next_hop_addr, next_hop, hops, last_announce}`) — the browser Nodes window reads this. |

### Command sentinels (read, self-clearing)

Single-shot debug triggers — write a value and rnsd consumes it on its own task:
`rnsd.cmd.clink`, `rnsd.cmd.creq`, `rnsd.cmd.link.open`, `rnsd.cmd.request_path`,
`rnsd.debug.log_msg_content`.

### Secrets

`secrets.rnsd.identity` — the 128-hex private key of rnsd's default identity
(used by `rnprobe` and any consumer that passes `""` for `identity_key`).

## CLI

```
rnsd                              identity + link summary, slot usage
rnsd identity                     identity hash + public key
rnsd persist [if-transport]       persist transport / path state
rnsd reload                       reload or create the identity
rnsd memory                       heap usage breakdown
rnsd link <dest_hash> [aspect]    one-shot outbound Link probe
rnsd link teardown                drop the probe link
rnsd links                        pending/active Link table sizes
rnsd clink <dest_hash> [aspect]   open a consumer-API link (debug)
rnsd clink send <text> | close
rnsd clink listen <aspect> | off  host a destination, accept inbound links
rnsd creq <dest_hash> <path>      request/response smoke test (page fetch)

rnstatus [filter] [-t] [-j]       interfaces & traffic — node header + per-iface block
rnpath [dest] [-n N|-a] [-s] [-j] routing path table (dest prefix-matches the hash)
rnpath -d <dest>                   DROP a path (destructive; requires the hash)
```

`rnprobe [aspect] <dest_hash> [-s size] [-n count] [-t timeout_s] [-w wait_s]`
is the Reticulum reachability probe (the `rnstatus`/`rnping` analogue): it dials
`rnstransport.probe` on the target by default and reports round-trip status.

Run any of these on-device through `spangap cli "<command>"`.

## Browser

The shared RNS UI lives in this straddle: the Reticulum Settings panel, the
Nodes window, the Announces window, and the RNS Pinia state. Interface-specific
UI lives in each interface straddle's own `browser/`.

## Dependencies

- [spangap-core](../spangap-core) — base runtime (ITS, storage, log, CLI, fs, cron).
- No networking or radio dependency at compile time.

## What it does NOT own

- WiFi / TCP / UDP / LoRa / ESP-NOW — those are interface straddles.
- LXMF messaging — [lxmf](../lxmf). NomadNet pages — [nomad](../nomad).
- Identity policy — `rnsd` does not auto-create an app identity at boot; that's
  the app's call.

## Read next

- [INTERNALS.md](INTERNALS.md) — every µR fork patch and rnsd addition, the task
  model, link/resource lifecycle, and maintainer pitfalls.
- [esp-idf/components/microreticulum/README.md](esp-idf/components/microreticulum/README.md)
  — the pinned upstream commit (and why) + licensing.

## Status

Hardware-verified against upstream Reticulum / LXMF. `rnsd` is real, not
scaffolding; the µR fork is ported and patched against the pinned commit.
