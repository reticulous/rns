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
│   ├── src/
│   │   ├── rnsd.cpp            the rnsd task: identity, Transport, iface table, links
│   │   └── rnsd_peers.cpp      the neighbourhood: nodes, their peers, the shared `n` printer
│   ├── conditional/spangap-lcd/
│   │   └── …/rnsd_pills_lcd.cpp   the status-bar pills, where there is a display
│   └── components/
│       ├── microreticulum/    our modified fork of attermann/microReticulum
│       └── bzip2/             vendored bzip2 1.0.8
├── browser/
│   └── src/
│       ├── modules/rnsd.ts            self-registering pinia module + RPC
│       ├── lib/netGraph.ts            the neighbourhood as vertices + edges
│       ├── lib/forceLayout.ts         where the vertices go (the one seam)
│       ├── panels/RnsdPanel.vue       Reticulum Settings panel
│       ├── panels/NetGraphWindow.vue  the NetGraph dock app
│       ├── panels/IfacePills.vue      per-medium status-line pills
│       ├── panels/NodesWindow.vue     live announce / path-table viewer
│       └── panels/MapWindow.vue       status floating windows
└── esp-idf/assets/lcd-icons/          launcher SVGs (LCD tiles + web dock)
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
| 1 | `RNSD_PORT_IFACE` | Interface registration + the inbound/outbound packet pipe; aux `RNSD_IFACE_AUX_ANNOUNCE` (`rnsdIfaceAnnounceNow`). |
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

## The announce beat — who schedules saying who we are

    app  → rnsd   RNSD_DEST_ANNOUNCE <app_data>      "this is my announce now"
    rnsd            … coalesce 60 s, then every interface
    iface→ rnsd   RNSD_IFACE_AUX_ANNOUNCE "lora/0"   "say it on mine"
    rnsd → iface  <announce packet>                  pinned to that interface

An application's job is to keep its **stored announce** current; rnsd holds the
bytes. **When** those bytes go on the air is each interface's call, because only
the interface knows what airtime costs on its medium — so `lxmf`, `rnsh` and
`rlpg` carry no announce timer and no interval setting, and every interface pane
carries one plus an **Announce now** button.

rnsd never schedules an announce on its own. It airs one when:

- **an interface registers** — every hosted destination's stored announce is
  replayed onto it, pinned to that interface, ~1.5 s after registration. This is
  what tells a Bluetooth peer or a TCP connection who we are within seconds of
  its arriving, and why those media need nothing else per-peer;
- **an interface asks** — `rnsdIfaceAnnounceNow(prefix)`, addressed by
  registered-name prefix so one call covers however many registrations a
  straddle holds (`ble` reaches every peer, `tcp` every connection in and out,
  `lora/0` one radio). `rnsdAnnounceBeat()` is the interval on top of it;
- **an application sets a new announce** — coalesced for a minute and then aired
  on every interface, so a boot that brings up four applications spends one
  sweep rather than four.

AutoInterface is the one medium with peers underneath a single registration, so
it asks for a replay itself when a LAN peer appears. That replay reaches every
peer rather than just the new one: outbound there is already a unicast fan-out,
and a few hundred bytes each on a switched link is not worth the plumbing to
address it.

## The community radius — whom we work for

Every interface carries one number, its **Community Radius**
(`rnsd_iface_t.community_radius`): nodes within that many hops heard on the
interface are this node's community — the ones it works for. A community
member's announce is **stored** (the original signed bytes, so path requests
for it can be answered from custody), ranked to **persist** in the directory
(`RDIR_CLAIM_ANSWER_FOR`, above everything merely overheard), given the
**custody path lifetime**, and **re-broadcast** to the rest of the community on
shared media. Path requests arriving on an interface with a community
(radius > 0) are **searched** on the requestor's behalf, out every other
interface. Radius 0 is a pure endpoint/uplink: everything heard there is
forwarded and resolved on demand, nothing unrequested is stored, no relay work
is spent onto it, and no errands are run for it.

Three verbs keep the triage honest: everyone on the mesh is **heard** (they
appear in On The Mesh whatever the radius) and **reachable** (on-demand
resolution, the direct peer's own announces, claims and active routes are kept
regardless); only the community is **served**. Membership is re-evaluated on
every announce rather than latched, so a destination that drifts beyond the
radius stops being an obligation.

Two things the radius deliberately does **not** govern. **Answering** a path
request for a destination already in custody is never gated: custody, once
taken, is served to anyone who asks — that is what makes a gateway a gateway.
And the **point-to-point** no-echo rule (`point_to_point`) is a fact about the
medium rather than a policy, so it always applies.

Searching is the asymmetric one. Relaying is decided on the egress side — a
forwarded announce is re-broadcast only within the listeners' radius, so the
uplink's firehose is never sprayed across a radio. Searching is decided on the
**requestor** side: a request arriving on a radius-0 interface is not our
errand however well we could run it — otherwise the wider network's discovery
load lands on this node, which is exactly what being an uplink's customer must
not mean.

A LoRa gateway with an internet uplink is therefore the defaults: radius 3 on
the radio (serve the mesh), radius 0 on the TCP peer (an uplink, on-demand
only). The hop bound is also the leak defense: another gateway relaying the
wide network onto the radio delivers those announces *deep* (they carried
their whole wide-network distance across it), so they fall outside the radius
and are never taken into custody, while native mesh members arrive shallow and
are.

## The neighbourhood — who is one hop away

    iface → rnsd    register (point_to_point, peer_label "AA:BB:…")   ─┐ a NODE
    iface → rnsd    RNSD_IFACE_AUX_PEER up, key, label                ─┘ is declared
    peer  → air     announce (hops 0)
    iface → rnsd    [origin key] ‖ packet
    rnsd            hops == 1, radius > 0 → a peer of that node
    cli   → rnsd    `tcp n` / `auto n` / `ble_if n` / `espnow n`
    rnsd → cli      one numbered block per node, its destinations under it

Every interface has the same question to answer — who is one hop away — and the
same evidence to answer it with, so `rnsd` answers it once for all of them. An
announce that arrives with `hops == 1` was transmitted by the node that
originated it, and `rnsd` sees every announce together with the interface it
arrived on, so the neighbourhood is built in one place and a medium added
tomorrow gets the verb for free. Every interface straddle's main command takes
`n` / `neighbors` (`-v` for announce counts and signal), and prints the same
format from the same code.

Kept only for an interface with a **community** (`community_radius > 0`): a
radius-0 interface is an uplink, whose far end is a route rather than a
neighbourhood, and whose announce firehose is the whole wide network. `n` says
so for such an interface instead of showing an empty list.

### Nodes and destinations

A **peer** is a destination; a **node** is the thing at the far end. They are
only the same on a medium that cannot tell them apart. Where the interface can
say *which* peer a packet came from, rnsd groups that peer's destinations under
one node and the listing shows one numbered block per node:

```
Bluetooth neighbors:

   1    c68e4bd797f6da5afd27f1f82f6b21ae rnstransport.probe  26m ago
        3520cc8cf908e6ac53d940ffc8fe4feb lxmf.delivery  "w12"  26m ago
        ( TRANSPORT )
```

Two things let an interface say that, and it declares which through
[`rnsd_iface_t`](esp-idf/include/ports.h):

- **`point_to_point`** — there is only one peer, so the interface *is* the node.
  Bluetooth registers one interface per peer and TCP one per connection, so this
  is the ordinary case, and the registration's `peer_label` (a MAC, a
  `host:port`) is who is at the far end.
- **`rx_origin`** — several peers under one registration, so each inbound frame
  is prefixed with a 16-byte **origin key** naming which of them sent it, and
  each peer is declared with `RNSD_IFACE_AUX_PEER`. An all-zero key is "the
  sender is unknown", which a medium has to be able to say per packet.
  [iface-auto](../iface-auto) is the simple case: every peer is a unicast UDP
  address, and that address is both the key and the label.
  [iface-lora](../iface-lora) is the interesting one — a shared radio cannot
  name the sender of a packet it merely overheard, but it CAN name the sender of
  an **announce**, because it verified the signature and joined the destination
  to a row in its own peer table. Announces are the only frames this
  neighbourhood is built from, so that is exactly the coverage needed, and the
  key is that row: every join the radio's table makes — an announce identity, a
  linkage frame, a SUPE association — ends in one row, so the shared listing
  groups exactly as `lora n` does.

A node exists from the moment it is **reachable**, not from its first announce —
so a peer that has attached and said nothing is a row under its transport
address rather than a silence, and a peer that goes away stops being a row,
which is the only thing that can ever say so (nothing announces a departure).
That holds on a **radius-0 uplink** too: whether this node serves a peer's mesh
is policy, but that somebody is at the other end of the wire is a fact, and an
uplink an operator dialled is exactly the peer they most want named back at
them. The radius gates only the peer's *destinations*, and the row says so.

**`( TRANSPORT )`** needs nothing extra. An announce arriving through a node
with `hops > 1` travelled through it from somewhere else, and only a node that
forwards for others produces that — so the announce proves it without anyone
being asked.

Where a medium declares no attribution at all, none of this is possible: two
identities announced into the air are indistinguishable from two nodes, and
merging on a guess would put the wrong lines on a graph. Those destinations are
listed one per row, numbered after the nodes — which is what
[iface-espnow](../iface-espnow) gets, having no node-level protocol to cluster
with. `lora n` remains the richer view of the same neighbourhood: it adds the
link ids, the identity prefixes, the negotiated SUPE budget and the derived
transmit power, none of which fits a shape every medium has to fill.

Names come from the announce's own `app_data` — the LXMF msgpack display name,
or the plain UTF-8 NomadNet and older clients send. `rnsdAnnounceName` and
`rnsdAspectLabel` (both in [`rnsd.h`](esp-idf/include/rnsd.h)) are that decoding,
shared rather than re-implemented per interface. `RNSD_PEER_ROW_FMT` /
`RNSD_PEER_ROW_PAD` are the row indent, shared for the same reason: every
medium's neighbourhood lines up in the same columns, this printer's and
iface-lora's alike.

## NetGraph — the neighbourhood as a picture

A dock app in this straddle's browser half: this node in the middle, one circle
per node around it, **one line per link**. It is drawn entirely from the
published tables above, so it needs no per-medium knowledge and a medium added
tomorrow appears the moment rnsd files its peers.

Two things it does that a plain node-link drawing does not, and the reason for
each:

- **Lines take the medium's colour** — the same `rns.pill.<class>.color` its
  status-line pill uses, read live. One vocabulary for "which medium" on every
  surface, and no palette in the app.
- **Parallel links are parallel arcs.** A peer reachable over both LoRa and
  Bluetooth is a peer that stays reachable, and that is the interesting fact on
  a mesh; one line between the circles would hide exactly it. The bundle between
  a pair is collected first and the curvatures spread symmetrically about where
  the straight line would have been, so one link is straight and two bow either
  side.

**One circle is one physical node, not one interface.** rnsd files a node per
(interface, peer) — correctly, since those are two different links — and the app
joins them on **evidence**: a destination hash is a cryptographic identity, so
two rnsd nodes that have announced the same destination are the same device.
Nothing else merges them, and a node that has announced nothing joins nothing,
because it has proved nothing about itself.

A dashed line is a link whose last announce is over an hour old — "was here and
has gone quiet" being a different thing from "not here". A second ring around a
circle is a transport node, which is the one property that changes what the
graph *means*: an edge through it reaches further than itself.

**Captions look for a clear spot.** Straight under the circle is where a caption
belongs, but on a graph that is the busiest space on the canvas — every line to
the node converges there. So each label is tried in a ring of eight spots
(below, above, the sides, the diagonals) against the sampled edge curves, the
other circles, the canvas edge and the captions already placed, and takes the
first that is clear. One with nowhere clear to go keeps the conventional spot
and is drawn on a black knockout instead: a dense graph genuinely has no clear
spot, and moving a caption far enough to find one makes it read as belonging to
a different circle.

`browser/src/lib/netGraph.ts` is the model, `panels/NetGraphWindow.vue` the
drawing, and `lib/forceLayout.ts` is the one seam — a spring embedder small
enough to carry inline for a graph this size, replaceable by a layout library
without touching anything else.

## Status-line pills

One pill per interface **class** in the top status line, on the display and in
the browser alike: a letter for the medium and how many peers are on it. `L3` is
three peers on LoRa — the same three `lora n` lists; `T0` is TCP configured and
not connected. A pill appears the moment its class is switched on, at 0 as
readily as at 3, and goes when it is switched off.

The count is each straddle's OWN notion of a peer, because what counts as one is
a property of the medium: a LoRa radio counts the nodes it hears, TCP counts
connections inbound and out. `rnsd` holds no table of media and no palette — it
composes the text, and owns only the keys both renderers read:

| Key | Meaning |
|---|---|
| `rns.pill.<id>.text` | The finished pill, e.g. `L3`. **Empty = no pill** (emptied rather than deleted, because a delete fires no change callback and the display's renderer would never learn it had gone). |
| `rns.pill.<id>.color` | `rrggbb` for the class. |
| `rns.pill.<id>.order` | Left-to-right placement — each straddle passes its own settings `order:`, so the pills read in the same sequence the Interfaces pane lists them. |

An interface straddle calls `rnsdPillSet(id, letter, count, color, order)` /
`rnsdPillClear(id)` and contributes nothing else; the browser component and the
on-device status-bar indicator both live here.

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

**What gets kept follows the community radius.** Every announce updates the
guard (replay and recency suppression, which is what stops a repeat announce
re-entering the retransmission queue at ~1.5 s of LoRa airtime). Whether
anything deeper is *retained* depends on where it arrived and how far away its
origin is: within the ingress interface's community radius it is kept —
custody of the mesh this node serves — and beyond it only what was resolved on
demand, originated by the direct peer, claimed, or is in active use. Each
interface straddle exposes the radius as its own `community_radius` setting —
default 3 for LoRa, ESP-NOW, the LAN interface and Bluetooth, 0 for TCP.

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
| `s.rnsd.announce.table_max` | `100` | Slots in the announce retransmission queue. Read once at Transport start: the queue is one fixed ring, so raising it later clamps rather than growing. |
| `s.rnsd.hashlist_max` | `100` | Packet-hashlist (dedup) capacity cap (`Transport::hashlist_maxsize`). |
| `s.rnsd.path.max` | `100` | Soft cap on resident directory records with a route. The directory's own slot count is the hard bound; this holds the resident set below it. |
| `s.rnsd.path.request_tags_max` | `32` | Pending path-request tag cap (`Transport::max_pr_tags`). |
| `s.rnsd.path.ttl` | `86400` | Path-entry age-out, seconds (`Transport::destination_timeout`). |
| `s.rnsd.path.ttl_ap` | `21600` | Access-point path lifetime, seconds (`Transport::ap_path_time`). |
| `s.rnsd.path.ttl_roaming` | `3600` | Roaming path lifetime, seconds (`Transport::roaming_path_time`). |
| `s.rnsd.path.escalate_s` | `3` | Cheapest-first discovery: seconds a path request we originate waits on the fast interfaces before it is also asked of the slow ones. Nearly every answer arrives over the cheap link, so the radio is usually never asked at all; the cost of being wrong is that a radio-only destination resolves this many seconds later. A node with no fast interface skips the grace entirely. |
| `s.rnsd.path.cheap_bps` | `50000` | Bits/sec at or above which an interface counts as cheap for the above. Bitrate rather than interface type, so a metered or slow uplink is treated like a radio without naming either. An interface that declares no bitrate counts as cheap — an unknown cost must not delay discovery. |
| `s.rnsd.path.ttl_custody` | `86400` | Lifetime for community members — destinations within their interface's community radius. Mode gets this backwards for a gateway — it hands the *shortest* lifetime (`ttl_ap`) to the access-point radio, whose destinations cost the most to re-acquire and are the ones we answer for. |
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
| `s.rnsd.ratchets` | `1` | Advertise a rotating ratchet key on every hosted destination's announces, so senders encrypt to it instead of our long-term identity key and past traffic stays unreadable if that key later leaks. Costs 32 bytes per announce. Live — a change reaches destinations already up. Off is interoperable in both directions: senders fall back to the identity key, and we still encrypt to a peer's ratchet when they advertise one. |
| `s.rnsd.proof_timeout_s` | `60` | Deadline for an outbound delivery-proof receipt, stamped onto the µR receipt too so Transport keeps it validatable for exactly as long as rnsd waits. |
| `s.rnsd.link.path_timeout_s` | `30` | Path-request / link-request retry budget. |
| `s.rnsd.link.request_timeout_s` | `15` | Request/response (page fetch) timeout. |
| `s.rnsd.link.max_inbound_resources_total` | `4` | Concurrent inbound Resource cap across all links. |
| `s.rnsd.its_no_pool` | `0` | Disable the ITS server inbox pool (debug). |
| `s.lxmf.max_resource_size` | `262144` | Size gate for accepting an inbound Resource. |
| `s.net.up_wait_s` | `20` | Boot barrier: how long to wait for the network at startup. |
| `s.rns.boot_min_s` | `10` | Mesh-safety boot window, floor: seconds from boot before the ecosystem may come up and first transmit. Always served — a boot-looping node must not be able to spam the shared medium with re-announces, and nothing cancels this part. |
| `s.rns.boot_max_s` | `300` | Same window, ceiling: how much longer an *unattended* node holds. Cancelled by `sys.human_detected` — the first keystroke on a console, USB host on the console, screen wake, or click in the web UI drops the rest of the hold, since someone at the controls is not a bootloop. |

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
| `rnsd.ifaces.<name>.{peers,nodes}` | Direct peers and the nodes they group into, on that interface; both `0` where its community radius is. |
| `rnsd.peers.count` | Direct peers across every interface with a community — the length of the list below. |
| `rnsd.peers.<i>.{iface,node,dest,aspect,name,hops,heard,announces,rssi,snr}` | One direct peer — a destination one hop away (below). |
| `rnsd.nodes.slots` | How far a reader iterates the node table. |
| `rnsd.nodes.<i>.{iface,key,label,transport,heard,peers}` | One node — the thing at the far end (below). |
| `rns.pill.<id>.{text,color,order}` | One interface class's status-line pill; `text` empty = no pill. Written by the interface straddles through `rnsdPillSet`. |

Together these are the graph: **nodes** are the vertices and **peers** the
destinations hanging off them, in the same shape whatever medium they arrived
over.

A peer's `iface` is the registered interface name (`lora/0`, `tcp_in/…`), `node`
the index of the node that announced it — or `-1` on a shared medium that cannot
say who transmitted a packet, which is a real answer and not a missing one.
`dest` is the 32-hex destination hash, `aspect` the aspect in words where rnsd
knows the name behind the hash and the 20-hex name hash where it does not, `name`
the display name the announce carried (empty when it carried none), `heard`
device unix-seconds of the last announce, and `rssi`/`snr` the reception where
the medium measures one — written **empty** where it does not, because that
absence is the answer and a zero would not be. Peer indices are table order, not
recency: a peer keeps its index until the membership changes, and a reader
wanting newest-first sorts on `heard`.

A node's `label` is its transport address (a Bluetooth MAC, `host:port`, a
link-local address) — what identifies it before any announce does, and on a
graph regardless; `key` is the origin key its packets carry, all-zero where the
interface itself is the node; `transport` says it forwards for others. Nodes are
published under their **table** index and a withdrawn one's subtree is deleted
rather than the rest renumbered, because a peer names its node by that index and
compaction would move the graph's edges every time a Bluetooth peer came or
went.

A medium that knows more publishes it under its own prefix
([iface-lora](../iface-lora) does); this is the floor, not the ceiling.

### Command sentinels (read, self-clearing)

Single-shot debug triggers — write a value and rnsd consumes it on its own task:
`rnsd.cmd.clink`, `rnsd.cmd.creq`, `rnsd.cmd.link.open`, `rnsd.cmd.request_path`,
`rnsd.debug.log_msg_content`.

### Secrets

`secrets.rnsd.identity` — the 128-hex private key of rnsd's default identity
(used by `rnprobe` and any consumer that passes `""` for `identity_key`).

`secrets.rnsd.ratchets.<dest_hex>` — one per hosted destination: its retained
ratchet private keys, newest first, as hex. Written on every rotation and read
back before the destination goes up, because a ratchet that does not survive a
reboot black-holes every message already in flight to it. Deleting one costs
whatever was encrypted to those ratchets and nothing else — the destination
generates a fresh set on its next announce.

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
NetGraph dock app, the interface-class pills, the Nodes window, the Announces
window, and the RNS Pinia state. Interface-specific
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
