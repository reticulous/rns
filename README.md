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
│   │   ├── netgraph.h    the network graph: boot hook + iface detail contribution
│   │   └── ports.h       ITS port constants + frame opcodes shared with consumers
│   ├── src/
│   │   ├── rnsd.cpp            the rnsd task: identity, Transport, iface table, links
│   │   ├── rnsd_peers.cpp      the neighbourhood: nodes, their peers, the shared `n` printer
│   │   └── netgraph.cpp        the graph: routing + interfaces, the crawl, remote mgmt
│   ├── conditional/spangap-lcd/
│   │   └── …/rnsd_pills_lcd.cpp   the status-bar pills, where there is a display
│   └── components/
│       ├── microreticulum/    our modified fork of attermann/microReticulum
│       └── bzip2/             vendored bzip2 1.0.8
├── browser/
│   └── src/
│       ├── modules/rnsd.ts            self-registering pinia module + RPC
│       ├── lib/netGraph.ts            netgraph.* rows as vertices + edges
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

(Port 100 is lxmf's inbound-link hand-off, not client-facing. Port 101,
`RNSD_LINK_RESOURCE_AUX_PORT`, is where rnsd reports the Resource lifecycle for
**every** link consumer, by task handle — a consumer that opens a link and does
not open that port gets "aux send to unregistered port 101" and rnsd frees the
frame's buffer.) Opcode tables for the framed ports
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

## Remote management — the stock service, both ways

```
serving (any RNS installation → us):
  us → all    ANNOUNCE rnstransport.remote.management   on the stock beat
  them → us   LINK → IDENTIFY → REQUEST /path | /status
  us → them   RESPONSE  upstream's own shapes, from Transport's tables

asking (`rnstatus -R <hash>` / `rnpath -R <hash>`, and the netgraph crawl):
  us → node   LINK → IDENTIFY → /path ["table", nil, hops] → /status [true]
```

The address is the stock one — `rnstransport.remote.management` on this node's
transport identity — so `rnstatus -R <our identity hash>` from an unmodified
`pip install rns` works with nothing on the other side but that hash in a config
file. `/path` answers upstream's list of `{hash, timestamp, via, hops, expires,
interface}` and `/status` its `[stats-dict, link-count]`.

**The handlers live in rnsd** (`rnsdRemoteManagementStart` / `…Allow` /
`…AnnounceData` in [`rnsd.h`](esp-idf/include/rnsd.h)). µR's response generator
returns its answer synchronously, inside `Link::handle_request` on the rnsd
task, and the answers *are* Transport's own path table and interface statistics
— so there is nothing to marshal anywhere else. A consumer supplies the policy
(whether to serve, and who may ask); rnsd supplies the answers. netgraph is that
consumer.

**An unidentified link is refused, and so is an identity that is not on the
allow list** — upstream's `ALLOW_LIST`, with the same meaning. An empty list
leaves the service reachable and refusing everyone, which is the correct state
for a node serving with no community configured and nothing granted.

Asking is the `-R` half: `rnsdSetRemoteAsker` registers whoever does the asking,
so the CLI verbs parse the hash, hand it over and print an acknowledgement — the
answer goes to the log, because a LoRa node may take a minute to reply and the
session that asked is long gone by then. `rnsdDestinationHashFromIdentityHash`
is what turns an operator-supplied identity hash into that address, needing
neither the public key nor an announce.

## netgraph — routing truth locally, remote management for the rest

```
crawl (on demand, one Link per node, never automatic):
  us → node   LINK → IDENTIFY → /path ["table", nil, 1] → /status [true] → CLOSE

sync (on demand, over one Reticulum Channel between two nodes):
  I → R   DIGEST        every (origin, seq) I hold
  R → I   RECORD_PART*  records I lack or hold older
  R → I   WANT          origins R lacks or holds older
  I → R   RECORD_PART*  those records
  both    DONE          then the initiator closes the channel
```

The neighbourhood tables above say who *this* node can hear. **netgraph** turns
that plus the path table into a drawing, and fills in the rest by asking other
nodes directly — over Reticulum's own remote-management service, so it reaches
stock installations whose software we do not write, and serves them the same
facility in return. The result is resolved into node and link tables under
`netgraph.*` that the browser app, the display and any on-device logic read.

**The graph has two sources and no others.** What this node knows for free — its
path table and its interface state, which cost no protocol and no traffic and
change the drawing the moment they change. And what other nodes know when asked,
one Link per node, once per crawl, started by a human.

It is a client of rnsd like any other ([`esp-idf/src/netgraph.cpp`](esp-idf/src/netgraph.cpp)).
The crawl is `rnsdLinkIdentify` + `rnsdLinkRequest`; the server half is
`rnsdDestListenRequests`; the sync path is `rnsdChannelOpen` and
`rnsdDestListenChannels`.

### The four classes of evidence

Every edge is one of four, and **line style states the class and nothing else**.
There is no style for "old": evidence expires and the line leaves.

| `ev` | where it comes from | the edge runs | drawn |
|---|---|---|---|
| `route1` | our path table, `hops == 1` | us → that node | solid, in the interface class's colour |
| `route2` | our path table, `hops == 2` | the `via` node → that node | thin, white, no colour |
| `heard` | the peer and node walks | us → that peer | dashed, class colour |
| `record` | a node's own self-report, over a sync Channel | origin → the cell's peer | solid, class colour |

`route2` gets no colour because our `iface` names the interface *we* transmit
on, not the one the via-node used — we do not know that hop's medium and must
not draw as though we did. Beyond two hops nothing is drawn at all: the
intermediate chain is not in our table, and hanging a node off the next hop
would assert an adjacency the data does not contain.

`heard` is defined as the peers routing does *not* cover — the nodes we could be
one hop from and are not, because a faster parallel link carries the route or
nothing has routed through them yet. It is the one class no third party will
ever report.

Precedence for the same adjacency, strongest first: `route1`, `route2`,
`record`, `heard`. One published row per `(a, b, cls)`, carrying the strongest
class held for it — a pair we both route to and hear is one line, not two.

**Records are never announced.** The builder, the store, the resolver and the
Channel server all work, but a record flooded per node per announce beat does
not scale on LoRa, so the push path and the sync beat that depends on it are
commented out at their call sites. `netgraph sync <hash>` still runs an exchange
by hand. See `plans/netgraph.md`.

### The rules that make it simple

- **One writer per record.** A record is one node's self-report *about itself*.
  No node ever writes into another's. "Newer seq wins" is the entire conflict
  story. A record is one evidence class among four, not the drawing's
  foundation.
- **Records are atomic wholes.** Ingest replaces everything held for an origin
  in one step — no partial update, ever. That is what makes unsigned
  re-serialization by a relay safe and lets a record's internal references stay
  record-scoped.
- **Records are unsigned.** They travel over encrypted Links between community
  members and carry no signature of their own. A member can fabricate, and a
  signature never prevented that — so a record must never be handed to a party
  that does not trust the whole community.
- **Configuration goes in a record; measurements do not.** Frequency, spreading
  factor, interface names, whether a link exists: yes. RSSI, SNR, negotiated
  budgets, counters: no. The test for a field is whether a change to it deserves
  waking the whole mesh.
- **A merely-heard peer is not a link.** A peer enters the link list only once
  an announce has been decoded from it — the same evidence that creates an rnsd
  peer row. The odd packet caught when the wind was right stays local.

### The community, and the crawl

**One keypair admits the whole community.** It is derived from a name and a
passphrase — `PBKDF2-HMAC-SHA256(s.netgraph.passphrase, "netgraph-community:" ‖
s.netgraph.community)`, 64 bytes read as X25519 ‖ Ed25519 — so every node that
knows both derives the same identity, with nothing exchanged and nothing
per-peer to configure. The derived key lands in `secrets.netgraph.identity` and
is what `rnsdLinkIdentify` is handed when we crawl; the community hash is what
this node's own allow list is seeded with. The passphrase is an ordinary
setting, not a secret: every node in the community holds it, and hiding it from
the operator who has to type it into the next node buys nothing. It is the
community's *access credential* rather than a network name — anyone holding it
can query every node that trusts it.

The community key **identifies, never addresses**. Building the management
destination on it would give every node the same address, and a management query
is always about one specific node.

**The management announce carries membership, encrypted or not at all.** With a
community configured, this node's `rnstransport.remote.management` announce
carries `issued ‖ flags ‖ name ‖ signature` encrypted to the community identity:
every member can read it because every member holds that private key, and nobody
else can. The signature is what proves membership — encryption alone would not,
since anyone holding the community *public* key can mint a token. Without a
community there is no app_data at all; the node is still perfectly askable,
because the allow list and not the announce is what grants anything. Stock
clients ignore app_data on this destination either way.

**The device's name lives here because this is the only place it can.** A
device's name belongs to the device, and the only address that *is* the device is
its transport identity — which is what this destination is built on. An LXMF
display name belongs to a person, on a different identity. A community-less
deployment therefore draws a graph of hex, and that is the price of the rule.

**A crawl happens when a person asks and at no other time.** `netgraph crawl`,
or the button in the browser panel: no timer, no boot pass, no refresh-on-idle.
It gathers the nodes whose management announce we hold, visits each once in
distance order out to `s.netgraph.radius`, and extends the queue with what each
one's own `route1` answers reveal. A refusal or a timeout is normal and quiet —
it counts, and the pass moves on. This is pull traffic over somebody else's
airtime, and a device that quietly re-reads a neighbour's tables on a schedule is
what gets its hash removed from an allow list.

### The record

The pipe-text form below **is** the specification; the packed wire form is a
mechanical tokenization of it — same lines, same fields, same order.

```
n|Kitchen T-Deck|t
dt|3|a1b2c3d4 9f3e2a11 77ab01cd
if|lora|lora/0|868.5|7|125|5|s
ln|lora/0|37|9f3e2a11.0.t 8ab2c3d4.1 7c1d99f0.2 …
if|tcp|tcp_in/10.0.0.4#0
ln|tcp_in/10.0.0.4#0|1|55aa66bb.0.t
```

- `n` — what this node calls itself (may be empty) and its flags; `t` means it
  is an RNS transport node. The name is the device's hostname, falling back to
  the LXMF display name where no hostname is set — a vertex here is a device,
  and the hostname is the name its operator gave that device. `|`, newline and
  control characters become spaces when the record is built, which is the whole
  escaping story: a consumer may split on `|` unconditionally.
- `dt` — this node's own announced destination hashes, as 4-byte prefixes. This
  is the **join evidence**: another record's `ln` cell naming one of these is a
  link to this node.
- `if` — one per interface: the class word behind the status-line pill, the
  registered instance name, then class-owned configuration fields, opaque to
  everyone but that class's straddle and rendered verbatim.
- `ln` — the links on one interface, referenced by interface **name**, never by
  position. Second field is the TRUE link count; then at most K cells (all of
  them in the full record, the freshest K in an announce). A cell is
  `prefix.freshbucket[.t]` — the peer's 4-byte destination prefix, a freshness
  bucket relative to the record's own timestamp (0 ≤ 5 min, 1 ≤ 1 h, 2 ≤ 6 h,
  3 older), `t` for a transport node. Only peers that have announced get a cell;
  one known solely by its transport address is counted and not listed, because
  no other node could join it to anything anyway.
- `up` — a way OUT of the community: `up|<class>|<iface>|<address>`, one per
  radius-0 point-to-point interface whose far end rnsd has named. **The
  community radius is not a display filter** — it says how far to go looking for
  nodes to *serve*, where to stop reaching, and nothing about what is worth
  drawing. It is used here only to decide what the far end IS: rnsd keeps no
  peer rows for a radius-0 interface, so there can never be destination-level
  evidence about what is over there and it can only ever be an address. That
  earns it a box rather than a member circle — but it is drawn either way, and
  anything this misses (more uplinks than a record can carry, say) reaches the
  graph through the local overlay instead. It gets a line
  of its own rather than an `ln` cell, because an `ln` cell means "a community
  peer, joinable by its destination prefix" and an uplink is the opposite of
  that — no prefix, no record, ever. Keeping the two apart is what stops a
  resolver trying to join the outside world to a member. rnsd already takes this
  position: it declares a node for such an interface regardless of the radius,
  because *whether we serve a peer's mesh is a policy; that there is somebody at
  the other end of the wire is a fact*.
- Detail lines (`lora|if|lora/0|…`) — class-owned extra lines, scoped by
  reference to an `if`. None are defined today; the rule exists so a straddle
  can add one without touching core code, and so a node that does not know the
  class still carries the line intact.
- Exactly two separator levels below the field, ever: space for list cells, `.`
  for subfields within a cell. Nothing nests further.

Forward tolerance is structural rather than negotiated: an unknown first field
is skipped and carried verbatim, and unknown trailing fields on a known line are
ignored. There are no capability bits and no schema version — all community
nodes flash together.

The packed form is `magic 0xF5 | origin:16 | seq:u32 LE | flags:u8`, then
repeated `len:u16 LE | tag:u8 | body` where `len` counts the tag and body
together, so one number skips a line whether or not its tag is understood.
Everything count-dominant is binary; the one-off descriptive fields (`if`
parameters, detail lines) stay UTF-8 text even packed, so expanding a record
back to text needs no per-medium decoder anywhere. `0xF5` is an invalid UTF-8
lead byte on purpose: nothing that sniffs announce `app_data` for a display name
can mistake a record for one.

`seq` doubles as the record's build timestamp — device unix seconds, guarded
monotonic and persisted, so a reboot with a bad clock cannot re-issue an old seq
and have the community reject the node's own news about itself.

### What each node publishes

Under `netgraph.*` (ephemeral, so browser-synced automatically), written inside
one `storageBegin`/`storageEnd` bracket so a reader sees one coalesced patch:

```
netgraph.self                own identity hash, hex
netgraph.radius              community radius in force
netgraph.nodes.slots         walk bound
netgraph.nodes.<i>.id        identity hash hex ("" = known only by address)
netgraph.nodes.<i>.name      display name (may be "")
netgraph.nodes.<i>.label     transport-address label where there is no name
netgraph.nodes.<i>.transport 0/1
netgraph.nodes.<i>.dist      hops from us; 0 = us, EMPTY = nothing joined it up
netgraph.nodes.<i>.member    1 = its management announce carried a community signature
netgraph.nodes.<i>.visited   unix seconds of the last crawl visit, 0 = never
netgraph.links.count
netgraph.links.<j>.a         node slot of the reporting side
netgraph.links.<j>.b         node slot of the peer, -1 unresolved
netgraph.links.<j>.bref      peer prefix hex, when b = -1
netgraph.links.<j>.ev        route1 | route2 | heard | record
netgraph.links.<j>.cls       interface class word ("lora"); "" for route2
netgraph.links.<j>.iface     reporting side's interface name
netgraph.links.<j>.age_s     seconds since refreshed, EMPTY where undated
netgraph.links.<j>.transport 0/1 (peer side, as reported)
netgraph.links.<j>.src       crawled node's hash; "" for our own evidence
netgraph.ifs.<i>.count       interface lines node <i> reports
netgraph.ifs.<i>.<k>.cls/.name/.detail
netgraph.crawl.state         idle | running
netgraph.crawl.req           written by a client to start a crawl
```

`src` is there because `a` cannot answer "whose statement is this". `a` is the
reporting side, and for `route2` the reporting side is the via-node even when we
derived the row from our own path table — so a local `route2` and one the crawl
pulled out of that same neighbour would otherwise publish identically. They are
different claims: one is our table, the other is a third party's answer, asked
once and stale from the moment it landed.

`dist` and `age_s` are text so they can be EMPTY. An integer cannot say "no
answer" for either — `0` already means "us" and "this second".

Both directions of an adjacency are published — they are two separate
statements, not one fact written twice, and until the far end has reported the
reverse we know how one end reaches the other and not how it gets back. A
*renderer* merges them into one line where both rows exist and **stops short of
the far circle** where only one does; the rows keep them apart, which is what
lets it. An edge whose far end names a destination nothing claims is kept as a
**pending edge** (`b` = -1) rather than dropped, so a node's degree stays honest
while whatever would name the other end is still missing.

### An interface contributes its own fields

[`netgraph.h`](esp-idf/include/netgraph.h) exposes `netgraphContributeIface(cls,
cb)`. At rebuild the builder calls the class's callback to fill the class-owned
tail of its `if` line — pipe-separated text, configuration only. iface-lora
registers one and supplies frequency, spreading factor, bandwidth, coding rate
and whether SUPE is on. A straddle never sees a record: it contributes fields
and the builder composes, which is the `rnsdPillSet` relationship one layer up.

## NetGraph — the community as a picture

A dock app in this straddle's browser half: one circle per node, **one line per
adjacency** — including adjacencies between two other nodes, over a mesh this
browser is not on. It draws `netgraph.*` and nothing else; every join behind the
picture happened on the device, which is the only place that holds the path
table, the interface state and whatever the crawl brought back.

**Nothing is pinned, and this device is the red circle.** A community graph has
no natural centre. Pinning the viewing node to the middle drags the rest into
whatever shape that leaves — a node at the end of a chain lands inside a
triangle of its own neighbours, which is a picture of the pin rather than of the
network. Where you are is said by colour instead, which costs the layout
nothing.

Two more things it does that a plain node-link drawing does not, and the reason
for each:

- **Lines take the medium's colour** — the same `rns.pill.<class>.color` its
  status-line pill uses, read live, and the legend names it with the
  `rns.pill.<class>.title` that straddle publishes beside it. One vocabulary for
  "which medium" on every surface, and no palette and no table of media in the
  app. This is why an interface straddle publishes its colour from boot rather
  than from the moment its medium is switched on: a LoRa link between two other
  nodes is still a LoRa link on a node whose own radio is off, and drawing it in
  the fallback grey would say something false about the network.
- **Parallel links are parallel arcs.** A peer reachable over both LoRa and
  Bluetooth is a peer that stays reachable, and that is the interesting fact on
  a mesh; one line between the circles would hide exactly it. The bundle between
  a pair is collected first and the curvatures spread symmetrically about where
  the straight line would have been, so one link is straight and two bow either
  side.

**Line style is the evidence class and nothing else.** Solid in the medium's
colour is a route one hop out; thin and white is a route two hops out, hanging
off the neighbour it sits behind; dashed is a peer an interface hears that
routing does not use. Nothing is styled by age — evidence that expired was
removed by the device rather than dimmed by the app, so what is drawn is current
by construction. The legend names each style in words, because they are not
self-explaining, and so does the hover text: "1 hop, radio0", "2 hops — medium
unknown", "heard on radio0, not routed".

**An unreciprocated edge stops short.** A link between two nodes arrives as two
rows, one from each end. Where both are present they merge into one line that
touches both circles. Where only one is, the line is drawn from the reporting
end and stopped a vertex-radius short of the far one, with no arrowhead: the gap
says "this is how `a` gets there; how `b` gets back is not known". That is the
visible half of the invariant — we never draw a return path nobody told us
about.

A second ring around a circle is a transport node, which is the one property
that changes what the graph *means*: an edge through it reaches further than
itself. A small hollow circle with no caption is a **stub**: the far end of an
edge nothing has named yet, drawn so the degree of the node reporting it stays
honest. A stub cannot report, so an edge to one never stops short — that would
read as a fault rather than as the definition it is.

**The crawl button, and nothing else, starts a crawl.** It is pull traffic over
somebody else's airtime; there is no timer behind it, no boot pass and no
refresh-on-idle. The caption names the radius it will go to.

**Captions look for a clear spot.** Straight under the circle is where a caption
belongs, but on a graph that is the busiest space on the canvas — every line to
the node converges there. So each label is tried in a ring of eight spots
(below, above, the sides, the diagonals) against the sampled edge curves, the
other circles, the canvas edge and the captions already placed, and takes the
first that is clear. The spots are measured from the outermost thing drawn at
the vertex, so a transport node's caption clears its second ring rather than
brushing it. One with nowhere clear to go keeps the conventional spot
and is drawn on a black knockout instead: a dense graph genuinely has no clear
spot, and moving a caption far enough to find one makes it read as belonging to
a different circle.

**Crossings are minimised, not left to chance.** A spring embedder has no term
for them and cannot grow one — whether two edges cross is a property of the
whole drawing, not a force between two vertices — so three connected nodes plus
one outlier would put the outlier on whichever side its starting angle chose,
and half the time its single edge cut straight through the triangle. So the
springs settle the shape and then an untangling pass relocates one vertex at a
time to whichever position around its neighbours crosses fewest edges, retrying
from a different starting arrangement while a fault survives. It is a local
search, so it does not guarantee a flat drawing of every graph that has one, but
it clears the shapes a neighbourhood actually makes.

**Wide angles where there is a choice.** Below the two faults, the search
prefers the arrangement whose narrowest fan of edges at any vertex is widest —
which is what stops a triangle being drawn as a sliver that reads as one line
rather than three. An angular-resolution *force* was tried for this and removed:
gentle, it barely moved the worst angle; strong enough to matter, it fought the
springs into new crossings and drove the worst angle to zero. The search reaches
~55° where the force reached ~9°, and costs no crossings to do it, because it
can refuse a move that breaks something a force can only shove at.

**Even lengths where nothing else decides.** A 200 px line beside a 40 px one
reads as a statement about distance, and nothing in a record is a distance — so
evenness is the honest default, and a chain of nodes comes out as a chain of
equal links. Two mechanisms: a relaxation pass pulls every edge toward the
drawing's mean length, half the correction at each end, moving only along the
edge so the shape the springs settled on is not rotated; and evenness is the
last of the four ranking criteria, below every fault and below the angles, so
the untangler prefers the arrangement whose lines most nearly agree. The pass
runs before the untangler and again after it — relocating a vertex is exactly
what leaves one edge long and one short — with the second run reverted if it
would cost a crossing or put an edge through a circle.

**The frame follows the window.** The layout runs in fixed graph units, but the
viewBox is the drawing's own bounds grown to the panel's shape, so the picture
fills the window and keeps filling it through a resize without the simulation
re-running and the vertices jumping under the hand doing the resizing. It stops
shrinking below a floor: a two-vertex community has bounds a few tens of units
across, and a frame that tight would blow its captions up into headlines.

**An edge never passes through a circle.** That is ranked above crossings and is
the one thing the layout will spend crossings to avoid. Two edges crossing is a
drawing that could be clearer; an edge running through a node it does not end at
is a drawing that is *wrong* — it reads as a connection that is not in the data,
and no amount of looking tells the reader otherwise. It is also exactly what a
crossings-only search reaches for, since flattening a triangle onto a line is a
cheap way to stop its edges crossing anything. The clearance comes from the
drawer, which is the half that knows how big a circle is.

`browser/src/lib/netGraph.ts` reads the rows, `panels/NetGraphWindow.vue` is the
drawing, and `lib/forceLayout.ts` is the one seam — small enough to carry inline
for a graph this size, replaceable by a layout library without touching anything
else.

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
| `rns.pill.<id>.title` | The medium in an operator's words — `LoRa`, `AutoInterface (LAN)` — for the surfaces that name a medium instead of abbreviating it to a letter, such as the NetGraph legend. Empty where the class slug already reads as the operator's word, and every reader falls back to that slug. |

An interface straddle calls `rnsdPillSet(id, letter, count, color, order)` /
`rnsdPillClear(id)` and contributes nothing else; the browser component and the
on-device status-bar indicator both live here.

**A pill is about this node; a colour is about the medium.** Both renderers gate
on `text`, so `rnsdPillColor(id, color, order, title)` publishes the colour, the
placement and the name with no pill — every straddle calls it once from `onInit`, whether or
not its medium is ever switched on here. The network graph is the reason: it
draws the whole community's links, including media this node does not run, and a
class whose colour had never been published would fall back to grey and read as
some other medium.

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

**A route is only true while the way to it exists.** "To reach X, send via Y over
Z" stops being true the moment Z goes away or Y stops answering, and neither
event touches the path table — the entry would sit there for its full TTL while
every packet aimed down it goes nowhere. So an interface going down drops the
routes learned over it, and a peer detaching on a connection-oriented medium
(`auto`, `ble`) drops the routes *to* the destinations it hosted and *through*
it: a detach is a certain, immediate fact arriving on time, and it is strictly
better evidence than any horizon. LoRa gets nothing from this — it is
connectionless, there is no detach to hear, and time is the only evidence there.
A boot is the same argument over a longer gap, which is `s.rnsd.dir.persist_routes`
above. Keys are kept throughout: a destination's key is true wherever it is, and
only the way there has gone.

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
| `s.rnsd.dir.persist_routes` | `0` | Trust the routes in a restored directory image. Off by default: a key is a fact about a destination and is true whenever we next need it, while a route is a statement about the network at one moment, and nothing in a restored image can vouch for the next hop still being there or the interface still being up. Dropping them costs one path request per destination actually used and keeps every key, which is the expensive half. A transport node serving path requests for others is the one case with an appetite for the old behaviour. |
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
| `s.netgraph.enable` | `1` | Run the distributed network graph. Live — a change starts or stops the component and takes the `netgraph.*` rows down with it. |
| `s.netgraph.community` | *(empty)* | The community's name. With `s.netgraph.passphrase` it derives the community keypair; empty means no community — the node serves and draws, and announces no membership. |
| `s.netgraph.passphrase` | *(empty)* | The community's passphrase. An ordinary setting rather than a secret: every node in the community holds it, and the *derived* key is what lives in the secrets tier. Changing either re-derives, re-pushes the allow list and re-airs the membership announce. |
| `s.netgraph.serve` | `1` | Answer `/path` and `/status` on the stock management address. Only the community and the identities below may ask; an unidentified request is refused. |
| `s.netgraph.allow.<i>.{id,hash}` | — | Identity hashes allowed to query this node besides the community, as a collection the settings pane binds rows to. Same form as stock `remote_management_allowed`, so a line copies straight across either way. Written only through the `netgraph.allow.add`/`.remove` sentinels, which is why no UI parses a hash. |
| `s.netgraph.radius` | `2` | How many hops out a crawl goes. |
| `s.netgraph.crawl_timeout_s` | `20` | How long one visit may take before the crawl gives up on that node and moves to the next. |
| `s.netgraph.heard_h` | `3` | Evidence unheard for this long leaves the drawing. Lines are removed rather than dimmed: everything on the picture is current. |
| `s.netgraph.rebuild_floor_s` | `600` | Minimum seconds between rebuilds of this node's own record. The floor is what stops a node joining a busy neighbourhood from re-flooding its record once per neighbour: a burst of changes coalesces into one rebuild. |
| `s.netgraph.announce_cells` | `8` | Record path (records are never announced — the settings from here down configure a subsystem that is built and mothballed). Maximum link cells per `ln` line in the ANNOUNCED form. Fewer are used automatically if the record still will not fit the airtime budget; the full record always carries all of them. |
| `s.netgraph.link_horizon_h` | `6` | A link not heard for this long leaves the record. A neighbour currently attached but never heard from is not stale — its lifetime is the interface's statement that it is reachable. |
| `s.netgraph.horizon_h` | `24` | Records older than this are dropped, never stored, and never offered in a digest. Half of it is the point at which a node is published as `stale`. |
| `s.netgraph.sync_min` | `30` | Anti-entropy ceiling in minutes: one Channel exchange against one rotating neighbour. The interval is adaptive between 30 s and this — an exchange that taught this node nothing doubles it, one that brought a record halves it — and it counts exchanges a NEIGHBOUR initiated too, since being visited answers the same question as visiting. Each wait is shortened by up to a quarter at random, so nodes that back off together do not end up dialling in lockstep. |
| `s.netgraph.store_kb` | `24` | Byte cap on the record store. Over it, the stalest-received record goes first; our own is never evicted. RAM only — a rebooted node backfills faster than flash-wear accounting would be worth. |

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
| `rns.pill.<id>.{text,color,order,title}` | One interface class's status-line pill, plus the colour and operator-facing name of the medium itself; `text` empty = no pill. Written by the interface straddles through `rnsdPillSet` / `rnsdPillColor`. |
| `netgraph.{self,radius,nodes.*,links.*,ifs.*}` | The network graph, resolved from the four classes of evidence (see the netgraph section above). Taken down wholesale when the component stops. |
| `netgraph.crawl.state` | `idle` or `running`. The browser's crawl button reads this rather than tracking a local flag, so a crawl started from the CLI or another browser disables it everywhere. |
| `netgraph.community.id` | The derived community identity hash, published only once a key exists — the row an operator who has just typed a passphrase is watching for. It is also what a node outside the community is asked to allow. |
| `netgraph.allow.{done,error}` | Acknowledgement counter and the rejection sentence the add form shows. |
| `s.netgraph.seq` | State, not a setting: the last sequence number this node issued for its own record. Persisted so a reboot with a bad clock cannot re-issue an old one. |

Together these are this node's own neighbourhood: **nodes** are the things one
hop away and **peers** the destinations hanging off them, in the same shape
whatever medium they arrived over. netgraph composes its record from exactly
these two tables, which is why a medium added tomorrow reaches the community's
graph without writing a line of code for it.

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

netgraph's are the same convention: `netgraph.crawl.req` (a rising value, not a
flag — two crawls in a row must both be seen) and `netgraph.allow.add` /
`netgraph.allow.remove`, the only writers of the allow collection.

### Secrets

`secrets.rnsd.identity` — the 128-hex private key of rnsd's default identity
(used by `rnprobe` and any consumer that passes `""` for `identity_key`).

`secrets.netgraph.identity` — the 128-hex private key derived from the community
name and passphrase. Derived rather than generated, so it is reproducible on
every node that knows both; deleting it costs nothing but the derivation.

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

netgraph                          record store: origins, seqs, ages, bytes, sync state
netgraph d[ump] [<prefix>]        records expanded to pipe text
netgraph l[inks]                  the resolved graph — what is drawn
netgraph m[embers]                who announced management, and what they said
netgraph c[rawl] [<hash>]         visit the community, or one node
netgraph s[ync] <hash>            run a record exchange by hand
netgraph r[ebuild]                rebuild our own record

rnstatus [filter] [-t] [-j]       interfaces & traffic — node header + per-iface block
rnstatus -R <identity hash>       ask that node instead (answer goes to the log)
rnpath [dest] [-n N|-a] [-s] [-j] routing path table (dest prefix-matches the hash)
rnpath -r                         name and aspect instead of the hash, where known
rnpath -R <identity hash>         ask that node instead (answer goes to the log)
rnpath -d <dest>                   DROP a path (destructive; requires the hash)
```

`-R` takes a transport identity hash exactly as upstream's `rnstatus`/`rnpath`
do, so the muscle memory transfers; the verb queues the visit and returns, and
the answer lands in the log rather than in the session that asked. `-r` puts a
destination in words — the display name and aspect the neighbourhood table
learned from its announce, and, where a resolver is registered
(`rnsdSetNameResolver`, which netgraph fills), the *device's* own name, which no
announce on a node's own addresses carries.

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
