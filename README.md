# rns — Reticulum on the device

**rns** brings the [Reticulum](https://reticulum.network) network stack to the
device. Its core is **`rnsd`**, a single FreeRTOS task that owns the entire RNS
protocol state — identity, destinations, the directory, the Transport state
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

Each `RNSD_PORT_IFACE` connection is a bounded ITS packet link: an interface's
`itsSend` into rnsd (and rnsd's back out) blocks only up to 100 ms, then drops
the packet and logs `ITS send dropped`. Two things cause the inbox to back up
past that window under load, and each has a knob:

- **The rnsd task is single-threaded** and runs `Transport::jobs()` — an
  unyieldy sweep whose cost grows with the path table — on a ~2 s cadence.
  While it sweeps, nothing drains the inbox, so a burst of inbound packets
  (e.g. a resource transfer) overflows the window. rnsd load-sheds this: when
  at least `CONFIG_SPANGAP_RNSD_JOBS_DEFER_PKTS` packets (default 8) arrived
  since the last sweep, it defers the sweep for up to
  `CONFIG_SPANGAP_RNSD_JOBS_DEFER_MAX` consecutive sweep-ticks (default 3) so
  the inbox keeps draining; the cap keeps keepalives/retries/timeouts firing
  within a few seconds. Set `_MAX` to 0 to always sweep.
- **The far interface is slower than rnsd produces** — LoRa airtime in
  particular. That backpressure is physical; the deferral above does not help
  it. Raise the `RNSD_PORT_IFACE` `fromCap`/`toCap` to absorb larger bursts,
  or rate-limit the source.

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

### Reliable channels

A **Link** is a best-effort packet pipe: an `itsSend` on a link handle is one
Link packet, delivered at most once. When a consumer needs **reliable, in-order
messages** instead, it opens a **Channel** — a sequenced, retried,
deduplicated message stream that rides *inside* a Link (Reticulum's `Channel`,
ported to the device). The Link is owned internally; the consumer only ever
touches the channel, exactly as it would a link:

- `rnsdChannelOpen(dest_hash, aspect, …)` — outbound. Same immediate-accept
  lifecycle and `rnsd.chan.<tag>.state` as a link, but each `itsSend` is one
  message rnsd retransmits until the peer proves it, and each `itsRecv` is one
  message delivered exactly once, in send order.
- `rnsdDestListenChannels(dest_handle, port)` — inbound. Like
  `rnsdDestListenLinks`, but forwards a Channel per accepted inbound Link.

A message must fit the channel MDU (Link MDU − 6). [rnsh](../rnsh) is built on
this. See [INTERNALS.md §5.6](INTERNALS.md).

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
| 11 | `RNSD_PORT_CHANNEL` | Outbound reliable channels (`rnsdChannelOpen`); inbound via `rnsdDestListenChannels`. |
| 12 | `RNSD_PORT_DIR` | Directory claims + out-of-band key seeding (aux only; `rnsdClaim` / `rnsdSeedPubkey`). |

(`lxmf` reserves internal ports 100/101 for rnsd→lxmf inbound-link and Resource
hand-offs; these are not client-facing.) Opcode tables for the framed ports
(`RNSD_DEST_*`, link aux, resource aux) are in
[`include/ports.h`](esp-idf/include/ports.h).

## Transit policy — who we work for

Every interface answers one question: **are the nodes reachable through it our
responsibility?** By default it is answered by inference — access-point
interfaces are kept out of announce relaying and out of path discovery, which
is stock behaviour and what this build has always done. Set
`…policy_manual = 1` on an interface and you answer it yourself with
`…route_for`; until you do, `route_for` is not read at all.

`route_for = 1` means we relay announces towards that interface's nodes, we
search on their behalf, and their paths get `s.rnsd.path.ttl_custody`.
`route_for = 0` means their traffic is not our business — we still talk to them
as an endpoint, we just don't work for them.

Two things it deliberately does **not** govern. **Answering** a path request
for a destination we already know is never gated: that is custody, not transit,
and refusing it is what would stop a gateway being a gateway — a request
arriving from an interface we don't route for, asking after a node we *do*
route for, is still answered. And **split horizon** (`point_to_point`) is a
fact about the medium rather than a policy, so it always applies.

Searching is the asymmetric one. Relaying is decided on the destination side —
if it can reach a segment we serve, carry it. Searching is decided on the
**requestor** side: we look things up for the nodes we are custodian of, so a
request from an interface we don't route for is not our errand however well we
could run it. Otherwise the wider network's discovery load lands on our radio,
which is exactly what asking to be a gateway must not mean.

Custody also decides what survives memory pressure. A destination reached via
an interface we route for carries `RDIR_CLAIM_ANSWER_FOR`, which ranks it with
the persistent claims — above everything the node merely overheard. Without it
a gateway's own segment competes for the same directory slots as a large
network's announce churn and loses continuously, because the churn is what
keeps arriving. The claim is re-evaluated on every announce rather than
latched, so a destination that moves to an interface we don't route for stops
being our obligation.

A LoRa gateway with an internet uplink is therefore two settings — route for
the radio, don't route for the uplink:

```
s.lora.0.policy_manual = 1     s.lora.0.route_for = 1
s.tcp.peers.0.policy_manual = 1  s.tcp.peers.0.route_for = 0
```

## The directory

Everything `rnsd` knows about *other* destinations lives in one arena of packed
fixed-size records, sized from a byte budget at boot and persisted as an image
of the live records (`<state>/rnsd/dir.img`). There is no separate identity
cache: the public key, the aspect hash, and the route to a destination are
fields of the same record, so they are acquired together, evicted together, and
cannot disagree.

The image holds what the node currently knows, not the arena it knows it in:
records go out in eviction order (most valuable first) and the file is bounded
by `s.rnsd.dir.img_max_kb`, so a 256 KB-`/state` board writes a few KB rather
than its whole arena. The guard depth is never written — its ages are on the
uptime clock, which restarts at boot.

Three depths, each dropped before the one under it when memory runs short:

| depth | means | per record |
|---|---|---|
| guard | "I have seen this announce" | 28 B |
| + directory | "I know who this is" | 188 B |
| + blob | "I can answer a path request for this" | 508 B |

The ordering is the point: losing the ability to serve a path request for a
destination degrades a network service, while losing the ability to say who it
is degrades information — so the former goes first.

**What gets kept is a per-interface decision.** Every announce updates the guard
(replay and recency suppression, which is what stops a repeat announce
re-entering the retransmission queue at ~1.5 s of LoRa airtime). Whether
anything deeper is *retained* depends on where it arrived: an expensive or edge
interface keeps what it hears, because we are the custodian of the mesh behind
it and re-acquiring a neighbour costs airtime; a cheap or vast one keeps only
what was resolved on demand, claimed, or is in active use. Each interface
straddle exposes this as its own `retain_announces` setting — on by default for
LoRa, ESP-NOW and the LAN interface, off for TCP peers.

**Claims** are how an application says a destination matters to it, so that the
records `rnsd` drops under pressure are the ones nobody asked for. lxmf claims
your contacts, nomad claims your bookmarked nodes. A claim is a preference, not
a lifetime: retention is the maximum over all claims on a record, and `rnsd` may
still break any of them. The invariant that keeps that safe is that an unbounded
claim population may not carry a long duration — contacts are bounded by the
address book, mesh neighbours by the mesh, and network-at-large announces carry
no claim at all. See `rnsdClaim` in [`rnsd.h`](esp-idf/include/rnsd.h).

`rnsd.dir.<hex32>.{pubkey,name_hash,hops,last_heard,claims,route}` reads a
single record on demand (a storage provider, not a mirrored subtree);
`rnsd memory` shows pool occupancy and `rnpath` lists the records carrying a
route.

## Storage variables

`rnsd` has no socket API for configuration — storage is the control surface.
Settings live under `s.rnsd.*` (writable by user/browser); runtime state and
telemetry are published under `rnsd.*` and `rns.ready` for anything to observe.

### Settings (read)

| Key | Default | Meaning |
|---|---|---|
| `s.rnsd.enable` | `1` | Master switch — is this node on the mesh at all. **Read once at boot**: when `0`, rnsd brings up no Transport/ports and never sets `rns.ready`, so interfaces and clients never start. **Changing it requires a reboot.** |
| `s.rnsd.transport_enabled` | `0` | Act as a Reticulum transport node (forward for others). Live (no reboot). |
| `s.rnsd.announce.interval` | `1800` | Seconds between periodic destination announces. |
| `s.rnsd.announce.table_max` | `100` | Slots in the announce retransmission queue. Read once at Transport start: the queue is one fixed ring, so raising it later clamps rather than growing. |
| `s.rnsd.hashlist_max` | `100` | Packet-hashlist (dedup) capacity cap (`Transport::hashlist_maxsize`). |
| `s.rnsd.path.max` | `100` | Soft cap on resident directory records with a route. The directory's own slot count is the hard bound; this holds the resident set below it. |
| `s.rnsd.path.request_tags_max` | `32` | Pending path-request tag cap (`Transport::max_pr_tags`). |
| `s.rnsd.path.ttl` | `86400` | Path-entry age-out, seconds (`Transport::destination_timeout`). |
| `s.rnsd.path.ttl_ap` | `21600` | Access-point path lifetime, seconds (`Transport::ap_path_time`). |
| `s.rnsd.path.ttl_roaming` | `3600` | Roaming path lifetime, seconds (`Transport::roaming_path_time`). |
| `s.rnsd.path.escalate_s` | `3` | Cheapest-first discovery: seconds a path request we originate waits on the fast interfaces before it is also asked of the slow ones. Nearly every answer arrives over the cheap link, so the radio is usually never asked at all; the cost of being wrong is that a radio-only destination resolves this many seconds later. A node with no fast interface skips the grace entirely. |
| `s.rnsd.path.cheap_bps` | `50000` | Bits/sec at or above which an interface counts as cheap for the above. Bitrate rather than interface type, so a metered or slow uplink is treated like a radio without naming either. An interface that declares no bitrate counts as cheap — an unknown cost must not delay discovery. |
| `s.rnsd.path.ttl_custody` | `86400` | Lifetime for destinations reached via an interface whose policy says we route for it. Mode gets this backwards for a gateway — it hands the *shortest* lifetime (`ttl_ap`) to the access-point radio, whose destinations cost the most to re-acquire and are the ones we answer for. |
| `s.rnsd.dir.budget_kb` | `0` | Directory arena size in KiB. `0` derives it from free PSRAM at boot, clamped to 40–96 KiB. Boot-time value: pools do not resize live. |
| `s.rnsd.dir.blob_slot` | `320` | Bytes per retained-announce slot. An announce whose raw form exceeds it is not retained, and a path request for that destination falls through to normal discovery. Changing it discards the stored image (it is a structural property). |
| `s.rnsd.dir.persist_s` | `900` | Seconds between directory image writes, when anything changed. The contents are a cache, so a crash costs at most one interval; the interval is minutes rather than the 60 s storage class because the directory changes on every retained announce. `0` = never persist (every destination is re-learned by path request after a reboot). |
| `s.rnsd.dir.img_max_kb` | `0` | Ceiling on the image file. `0` = an eighth of the `/state` partition, which is what a small-flash board needs: the image is rewritten through a temp file, so the partition must hold two copies. Above the ceiling the most valuable records are kept and the rest are re-learned by path request. |
| `s.rnsd.jobs_interval_ms` | `250` | Transport `jobs()` cadence, milliseconds (`Transport::job_interval`). Only consulted by `Transport::loop()`, which rnsd does not drive — inert on the rnsd path; the real cadence is `s.rnsd.tick_min_ms`/`tick_max_ms` below. |
| `s.rnsd.cull_interval_s` | `60` | Table-cull cadence, seconds (`Transport::tables_cull_interval`). |
| `s.rnsd.tick_min_ms` | `1000` | Busy floor for the main-loop housekeeping tick, milliseconds — the wake period while packets flow or links are up. Keep at `1000` to preserve the burst load-shed tuning; drop toward `250` only for faster housekeeping under load. |
| `s.rnsd.tick_max_ms` | `60000` | Idle ceiling the tick backs off to (×2 per idle tick) on a silent LoRa-only node. Any inbound packet or open/pending link snaps the cadence back to `tick_min_ms`. |
| `s.rnsd.log.trace` | `0` | Add microReticulum's per-call step narration to `log rnsd verbose`. Off, verbose gives one line per event; on, it narrates the steps inside each one — a dozen lines per packet, which on a busy TCP link is the load rather than a description of it. Flips live. |
| `s.rnsd.respond_to_probes` | `1` | Host `rnstransport.probe` and answer probes (PROVE_ALL). |
| `s.rnsd.prove_incoming` | `1` | Emit delivery proofs for inbound packets we receive. |
| `s.rnsd.proof_timeout_s` | `60` | Deadline for an outbound delivery-proof receipt. |
| `s.rnsd.link.path_timeout_s` | `30` | Path-request / link-request retry budget. |
| `s.rnsd.link.request_timeout_s` | `15` | Request/response (page fetch) timeout. |
| `s.rnsd.link.max_inbound_resources_total` | `4` | Concurrent inbound Resource cap across all links. |
| `s.rnsd.its_no_pool` | `0` | Disable the ITS server inbox pool (debug). |
| `s.lxmf.max_resource_size` | `262144` | Size gate for accepting an inbound Resource. |
| `s.net.up_wait_s` | `20` | Boot barrier: how long to wait for the network at startup. |

### Runtime state & telemetry (written)

| Key | Meaning |
|---|---|
| `rns.ready` | Boot barrier — set once the clock, network, and a settle delay have passed; consumers wait on this before using rnsd. |
| `rnsd.up` | Task is alive and the mesh is running. |
| `rnsd.enabled` | `1` running, `0` when `s.rnsd.enable=0` held the node off (distinguishes "disabled by config" from "not up yet"). |
| `rnsd.identity_hash` | Hex hash of rnsd's default identity. |
| `rnsd.iface_event_seq` | Monotonic counter bumped on interface up/down. |
| `rnsd.stats.{packets_in,packets_out,bytes_in,bytes_out,ifaces_up}` | Traffic counters. |
| `rnsd.stats.dir.{entries,blobs,guards}` | Directory pool occupancy. |
| `rnsd.stats.dir.{guard_drops,evictions,recall_miss,seq_retries}` | Announces suppressed as replays, records evicted, public keys asked for and not held, and reader/writer races on a record. |
| `rnsd.dir.{slots,bytes}` | Directory pool capacity and arena size, published once at boot. |
| `rnsd.gw.{rssi,snr,timestamp}` | Gateway/infrastructure signal — the received quality (rssi dBm, snr dB) of the transport node that last relayed a packet to us: the last packet addressed to one of our destinations/links that arrived on a signal-capable interface with more than one hop. `timestamp` is device unix-seconds of that sample (UIs fade the indicator out over ~30 min from it). Kept as the last qualifying sample; not cleared on a direct packet. |
| `rnsd.links.<tag>.{state,direction,aspect,remote_hash,opened_s,last_error,…}` | Per-link state tree, keyed by the caller's `tag` — observable before the link_id exists. |
| `rnsd.links.byid.<link_id>` | Reverse index: link_id → tag. |
| `rnsd.chan.<tag>.{state,direction,aspect,remote_hash,link_id,mtu,rtt_ms,tx_msgs,rx_msgs,last_error,…}` | Per-channel state tree (`rnsdChannelOpen`), same shape as the link tree. |
| `rnsd.chan.byid.<link_id>` | Reverse index: channel's hidden link_id → tag. |
| `rnsd.dest.<idx>.{aspect,dest}` | Hosted-destination (our-dest) observability. |
| `rnsd.ifaces.<name>.{up,mode,mtu,bitrate,rx_bytes,rx_packets,tx_bytes,tx_packets}` | Per-interface state and counters. |

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
rnsd persist [if-transport]       persist transport state
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
