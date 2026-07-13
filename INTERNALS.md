# rns — internals

Maintainer reference for `rnsd` and our microReticulum (µR) fork. The
[README](README.md) is the operator guide; this document is for changing the
code without breaking it. It is the authoritative source — there is no separate
plan document.

## 1. Everything we changed or added

### 1.1 Modifications to microReticulum

The engine is a modified fork of
[`attermann/microReticulum`](https://github.com/attermann/microReticulum),
pinned (see [components/microreticulum/README.md](esp-idf/components/microreticulum/README.md)).
Our deltas, by category:

**Functionality we brought up**

- **`Link` implemented.** Before us, the fork shipped `Link` as a stub
  (`Link_stub.cpp`) — no establishment, no link packets, no request/response.
  The real `Link` (LR/LRPROOF handshake + key derivation, link packets,
  request/response, Resource-over-link) is now in the build: unblocked by the
  MsgPack shim (`Link` needs the `Packer`/`Unpacker`/`bin_t` surface) and
  carrying ~28 of our own fixes on top. `Link_stub.cpp` is gone. The entire
  rnsd link lifecycle (§5) and nomad's page fetch rest on this — it's the single
  largest thing we added to µR.
- **`Channel` implemented.** The fork shipped `Channel` as an empty pimpl and
  `Link::get_channel()` commented out. `Channel.{h,cpp}` now hold a real port of
  upstream `RNS/Channel.py` — reliable, sequenced, windowed messaging that rides
  *inside* a `Link` (§5.6). `Link::get_channel()` is live and `Link::receive`
  routes `CONTEXT.CHANNEL` (0x0E) packets into it (`prove → decrypt →
  _receive`). This is what the [rnsh](../rnsh) shell rides on.
- **IFAC enforcement in `Transport.cpp`.** The fork had no Interface Access
  Code support; `ifac_salt`/`derive_ifac` (HKDF from netname+netkey, size
  clamped 1–64), outbound masking/signing, and inbound verify-by-recompute
  (unmask, recompute the signature over the reconstructed raw packet, drop on
  mismatch — an open interface likewise drops any packet with the IFAC flag
  set) are ours, byte-compatible with upstream Reticulum. **Pitfall:** the
  verify-by-recompute scheme depends on Ed25519 signing being deterministic
  (RFC 8032). Substituting a randomized signer silently drops 100% of inbound
  IFAC traffic.

**Dependency / platform swaps**

- **Crypto rewritten** against mbedTLS plus foreign primitives vendored under
  `src/donna/`: ed25519-donna (sign/verify/key-derivation, with SHA-512 via
  mbedTLS and RNG via `esp_fill_random`) and x25519 (ECDH, the same MIT
  implementation [wg](../wg) uses). The donna route is a performance
  requirement, not a convenience: mbedTLS's Curve25519 scalar multiplication
  takes ~100 ms on the ESP32-S3, versus under 10 ms for the software donna
  implementation — and X25519 ECDH runs per opportunistic packet outside an
  established Link. `Hashes`, `HKDF`, `Fernet`, `Token`,
  `X25519`, `Ed25519` are rewritten; `AES`/`HMAC`/`Random`/`PKCS7` are
  header-only; `CBC` was dropped.
- **MsgPack shim** — `src/MsgPack.h` is a hand-rolled msgpack encoder/decoder
  (the narrow `Packer`/`Unpacker`/`bin_t<uint8_t>` surface `Link` needs),
  replacing the Arduino `hideakitai/MsgPack` dependency — the prerequisite that
  unblocked the real `Link` (above).
- **cJSON** instead of ArduinoJson; the `convertToJson`/`convertFromJson`
  adapters were removed or block-commented.
- **No-op file I/O** — `OS::read_file`/`write_file`/etc. return empty/false; we
  own persistence end-to-end (§7). The path store uses µR's `BasicHeapStore`
  fallback (the pinned commit's `#if` guard makes this work without
  `RNS_USE_FS`/`RNS_PERSIST_PATHS`, which we deliberately do not define).
- **Logging rerouted** — `src/Log.cpp` maps every µR log call onto spangap's
  `info()`/`warn()`/`err()`/`dbg()`/`verb()`; `Serial.print*`/`printf` removed,
  `getTimeString()` stubbed (spangap prepends its own timestamp).
- **`malloc` → `gp_alloc`** — µR allocations go through the central allocator
  policy so placement (internal vs PSRAM) is governed in one place.
- **Event-driven** — no top-level `Reticulum::loop()`; rnsd drives µR from its
  own ITS wait loop.

**Correctness patches against upstream behaviour**

- `Transport.cpp` — **RAII guard for `_jobs_locked`.** Upstream leaks the lock
  on early returns from `Transport::inbound` (malformed packet, cache request,
  link-MTU clamp), permanently disabling `Transport::jobs()` for the session. A
  function-local guard releases it on every path.
- `Transport.cpp` — a requested `PATH_RESPONSE` **bypasses the `random_blob`
  replay guard** in announce ingest. Relays answer from a cached announce, so a
  re-requested path always carries an already-seen blob; upstream escapes via
  `path_is_unresponsive` (not ported), so we key on an outstanding
  `_path_requests` entry instead. Without this, path discovery works exactly
  once and then goes silent.
- `Identity.cpp`/`.h` — **`static std::recursive_mutex`** around every accessor
  of the `_known_destinations` map (`remember`/`recall`/`recall_app_data`/
  `validate_announce`/`cull_known_destinations`/save+load). Transport writes it
  during announce ingest on the rnsd task; consumers read it cross-task via
  `rnsdRecallPubkey`. Uncontended in the common case.
- `Packet.cpp` — malformed-packet error path **dumps the first ≤8 bytes hex** so
  HEADER_1-vs-HEADER_2 mis-parse, HDLC desync, or a noise byte are
  distinguishable in the log.
- `Packet.cpp` — **link-packet proof validation enabled.**
  `PacketReceipt::validate_link_proof` was stubbed (`if (false)`); `Link::validate`
  exists and verifies against the peer's link signing key, so the call is wired
  up. Without it a packet sent over a Link could never conclude its receipt
  (`DELIVERED`), which the per-link proof counters depend on.
- `Transport.cpp`/`Persistence/DestinationEntry.{h,cpp}` — **use-aware path
  eviction.** The path-table cap (`s.rnsd.path.max`, default 100) was enforced
  by `BasicHeapStore`'s `max_recs`, which evicts the lexicographically
  *smallest key* — on a busy mesh, destinations with low hashes were evicted
  within seconds of every announce, including peers in active use, so every
  link open re-sent a path request. `DestinationEntry` now carries a
  `_last_used` double (stamped on outbound use in `Transport::outbound`, at
  most once per `PATH_LAST_USED_GRANULARITY` = 60 s) and the cap is enforced
  by a rewritten `cull_path_table()` at the announce-insert site, evicting
  ascending by `(_last_used, _timestamp)` — never-used paths first, then
  least-recently-used; use older than `PATH_LAST_USED_STALE` (48 h) counts as
  never used, so a route last talked to months ago competes on announce age
  instead of outranking fresh announces. `_timestamp` stays the announce time. The stamp is
  patched into the encoded record at a fixed offset (`OFFSET_LAST_USED`)
  rather than decode/re-encode, which would bump the cached announce packet's
  hop count each round trip; the re-put also slides the store-level TTL so an
  in-use path doesn't age out at `s.rnsd.path.ttl` while traffic flows.
  Announce refreshes carry the previous `_last_used` over. Along the way:
  the periodic path cull in `Transport::jobs()` was commented out (it iterated
  the legacy `_path_table`, never populated in the microStore build — pure
  no-op), and `expire_path()` — which zeroed a timestamp on a decoded copy,
  another silent no-op — now removes the entry directly.
- `Destination.cpp` — **empty aspect adds no separator.** `expand_name` appended
  `"." + aspects` unconditionally, so an app-name-only destination (e.g. rnsh's
  `"rnsh"`, passed as app_name `rnsh` + empty aspects) expanded to `"rnsh."` —
  a different `name_hash`, hence a different address than upstream RNS computes
  for the same destination. Now the dot is only added for a non-empty aspect.
  All multi-segment destinations (`lxmf.delivery`, `nomadnetwork.node`) are
  unaffected; the fix only changes app-name-only destinations, which were
  previously mis-hashed and matched nothing.
- `Resource.cpp`/`ResourceData.h`/`Link.cpp`/`Transport.cpp`/`Type.h` —
  **Resource retransmission watchdogs.** The port originally had no equivalent
  of upstream's per-resource `__watchdog_job` thread: one lost RESOURCE_REQ,
  part or proof packet stalled a transfer forever (rnsd's wall-clock backstop
  then failed the whole message). Ported poll-driven: `Transport::jobs()` calls
  `Link::resource_watchdogs()` for every active link on the links-check cadence
  (~1 s, matching upstream's `WATCHDOG_MAX_SLEEP`), deferred past the
  `_jobs_running` clear like link teardown because retries transmit through
  `Transport::outbound`. `Resource::watchdog(now)` re-checks each state's
  deadline (upstream's arithmetic verbatim): advertisement retries
  (`MAX_ADV_RETRIES`), receiver part re-requests with window shrink, sender
  part-request timeout, and `AWAITING_PROOF` (upstream retries via the network
  packet cache, which this port lacks — a retry just extends the wait).
  Alongside it, the receiver's adaptive window now matches upstream:
  `_request_window` only fires when the outstanding window has drained (asking
  while parts are in flight made the sender resend them), the window grows
  toward `window_max`, and measured request→data rates escalate to
  `WINDOW_MAX_FAST` or cap at `WINDOW_MAX_VERY_SLOW` (the newer upstream
  very-slow-link constants are ported too, and `MAX_RETRIES` is upstream's
  current 16). `Resource::cancel()` on an outbound resource now sends
  `RESOURCE_ICL` so the receiver drops its inbound state instead of waiting
  out its own timeout.
- **Tunable identity-cache size** — `RNS::Identity::known_destinations_maxsize` is
  driven by `s.rnsd.identity.cache_max` (default `1000`, ~200 KiB PSRAM). The
  generous default prevents cache eviction before probes conclude on a busy network.
- **Log-demotion hook** — `RNS::Transport::demote_dbg(bool)` (wired from
  `s.rnsd.debug.only_local`) routes the high-volume DEBUGFs in `Transport::inbound`/
  `packet_filter`/`path_request` and `Identity::clean_known_destinations` through
  `DBGF_DEMOTE`/`DBG_DEMOTE` macros that drop them to verbose when set — otherwise
  announce traffic floods the log. A few DEBUGFs were also promoted to INFOF, plus
  a diagnostic for "DATA arrived for a dest with no local destination."

**Constraint we design around (not a patch)**

- µR concludes receipts on proof (`DELIVERED`, firing the delivery callback)
  but **never fires receipt-timeout callbacks** — `check_timeout()` flips status
  but the upstream callback-thread spawn is unported. rnsd drives all receipt
  *and* request timeouts itself by polling status from its 1 Hz tick, plus a
  wall-clock backstop.
- **`Buffer` is still stubbed.** `Channel` is now real (above, §5.6), but the
  `Buffer` / `RawChannelReader`/`Writer` byte-stream layer over it (StreamData
  chunking, bz2 compression) is not ported — rnsh frames its own bytes directly
  on Channel messages instead. Anything needing the upstream `Buffer` API must
  implement it first.

### 1.2 The rnsd layer (all new on top of µR)

`rnsd` is entirely ours — µR has no concept of it. It adds:

- **ITS bridging** — the whole port surface (§3) exposing µR to other straddles
  as byte arrays and framed ITS messages; no consumer sees an `RNS::` type.
- **Byte-array C API** (`rnsd.h`) — SHA-256, identity generate/sign/verify,
  destination-hash derivation, key recall, async path request.
- **Interface registration + packet bridge** (`RNSD_PORT_IFACE`).
- **IFAC** (Interface Access Codes) — per-interface PSK + per-packet HMAC
  access control, derived in rnsd from an interface's `ifac_netname`/`ifac_netkey`.
- **Boot barrier** (§6).
- **Hosted destinations (our-dests)** with concurrent path searches and
  `QUEUE_FULL` backpressure (§4).
- **Announce fan-out** with optional per-subscriber aspect filtering.
- **Outbound + inbound Link lifecycle** (§5), including the pre-active outboxes
  and the establishment-timeout budget.
- **Channel bridge** (§5.6) — outbound (`rnsdChannelOpen`) and inbound
  (`rnsdDestListenChannels`) reliable-messaging over a hidden Link, exposed as a
  packet-mode ITS handle where each message is delivered once, in order.
- **Resource transfer** (shared-memory hand-off) and **request/response** (page
  fetch) bridges.
- **Outbound delivery-proof tracking** (§5.4).
- **CLI + debug surfaces** (`rnsd`, `clink`, `rnprobe`).

## 2. The `rnsd` task

One FreeRTOS task, **core 0, prio 2, 12 KB PSRAM stack**. It owns µR's
`Reticulum` + `Transport`, the interface table, the hosted-destination (our-dest)
ports, the announce fan-out, the link slots, the management destination
(`rnstransport.remote.management`), and the optional probe responder
(`rnstransport.probe`, gated on `s.rnsd.respond_to_probes`).

**Threading rule that governs everything:** µR's Transport/Link/Identity state
is single-task-owned. Anything that mutates it — `Transport::request_path`,
building an `RNS::Link`, registering a destination — **must run on the rnsd
task**, or the work silently no-ops (an outbound path-request packet is just
dropped). Cross-task entry points therefore split in two: pure-crypto helpers
(`sha256`/`sign`/`verify`/`dest_hash`) run inline on the caller; `recall*` take
the recursive mutex; everything else is deferred to the rnsd task via an ITS
message or a storage command sentinel (`rnsd.cmd.*`), which rnsd drains on its
own task.

**Single wait point.** `itsPoll(deadline)` is the only blocking call — it wakes
on an ITS message, a task notification (radio ISR, lwIP recv), or a computed
deadline. Idle CPU is zero; there are no `while (itsPoll(0)) {}` drains. The
1 Hz `linkTick` services receipt/request timeouts, link state transitions, and
the terminal-grace slot reclaim.

## 3. ITS surface

Port numbers and the high-level purpose are in the [README](README.md#its-port-map);
the framing details:

- **`RNSD_PORT_IFACE` (1)** — connect with `rnsd_iface_t` (name, MTU,
  bitrate, mode, in/out/fwd/rpt, IFAC fields). The connect *is* the
  registration; the handle is then a packet-mode pipe (one RNS packet per
  send/recv). Disconnect deregisters. `rns_iface_mode` is a rnsd-facing enum and
  does **not** share µR's `Type::Interface::modes` bit layout — `mapIfaceMode`
  translates; never raw-cast between them.
- **`RNSD_PORT_DEST` (4)** — opened by `rnsdDestOpen`. Type-tagged frames both
  ways (`RNSD_DEST_*` opcodes in `ports.h`): `OUT_PACKET`/`IN_PACKET` for data,
  `OUT_RESULT` for send outcome, `OUT_STATUS` for aux progress narration,
  `ANNOUNCE` to emit an announce, `LINK_LISTEN` to register for inbound links.
- **`RNSD_PORT_ANNOUNCES` (6)** — connect with `rnsd_announces_connect_t`
  (optional dotted aspect filter). rnsd registers one internal `AnnounceHandler`
  with an empty filter at boot and fans each announce out to matching
  subscribers as one packet-mode message:
  `hops(1) | dest_hash(16) | identity_hash(16) | app_data_len(2 BE) | app_data(N)`.
  Per-slot drop-on-full (`itsSend(..,0)`) — a slow subscriber loses announces, it
  never stalls rnsd.
- **`RNSD_PORT_LINK` (10)** — connect (`rnsd_link_connect_t`, built by
  `rnsdLinkOpen`) opens an outbound link; the handle is the packet-mode data
  path. Out-of-band aux frames carry `SEND_RESOURCE` (0x02), `REQUEST` (0x03)
  and `IDENTIFY` (0x04, `rnsdLinkIdentify` — sign a `LINKIDENTIFY` to the peer
  with the identity the link was opened with; initiator-side, ACTIVE links
  only, no deferral). Opcode `0x01` was a teardown frame, now removed — see §5.
  On the *hosting* side, a validated inbound `LINKIDENTIFY` publishes
  `rnsd.links.<tag>.remote_identity` (identity hash) and `.remote_dest` (the
  peer's destination hash derived on the link's own aspect) — consumers poll
  these to treat an identified inbound link as a reply backchannel (lxmf does).

Consumer connect payloads are rnsd-private structs; callers use the `rnsd.h`
wrappers and never build them by hand. Every framed struct `static_assert`s
`<= ITS_MAX_MSG_DATA`.

## 4. Hosted destinations (our-dests)

`rnsdDestOpen(aspect, identity_key, dest_type, …)` registers an IN destination
on the named identity (`""` → `secrets.rnsd.identity`) and returns a
bidirectional handle. The aspect string is split at the **first dot** into µR's
`app_name` + `aspects` ctor args (`"lxmf.delivery"` → `lxmf` / `delivery`).
Opportunistic packets to/from that destination flow as `OUT_PACKET`/`IN_PACKET`
frames. These are the destinations *we* host — the code calls them **our-dests**
(`s_our_dests`, `our_dest_t`), distinct from `link_conns` (connections to
*others*) — and they're surfaced at `rnsd.dest.<idx>.{aspect,dest}`. The traffic
is Reticulum **opportunistic packets** (single packet, no Link). ("Mailbox" was
an earlier in-house name; it isn't Reticulum vocabulary and collided with ITS's
own "mailbox" message-queue term, so it's gone.)

**Concurrent path searches with backpressure.** Each in-flight `OUT_PACKET` that
lacks a path occupies one slot in a per-connection pending table. While the path
resolves, rnsd narrates progress with `OUT_STATUS` aux frames
(`REQUESTING_PATH` → `PATH_KNOWN` → `EGRESS_QUEUED`, with `RETRY` on
path-timeout). When the table is full, the send is **not accepted**: rnsd emits
`OUT_STATUS:QUEUE_FULL` and the consumer holds the message and resends once a
slot frees. This is backpressure, never a silent drop.

**Wire-format asymmetry (a correctness trap).** For a SINGLE destination the
LXMF-style wire omits the leading 16-byte destination hash, but `OUT_PACKET`/
`IN_PACKET` carry the *full* wire. So on the **opportunistic** path rnsd strips
the leading 16 bytes before the Reticulum `Packet` payload on send, and prepends
`destination.hash` on receive — consumers always see self-contained frames. The
**DIRECT / Link path does NOT strip or prepend.** Don't "unify" the two: the
opportunistic strip/prepend is required there and wrong on the Link path.

## 5. Link lifecycle

### 5.1 Outbound (`rnsdLinkOpen`)

The connect **accepts immediately** — the handle returns before the Reticulum
handshake (path request → LR → LRPROOF → key derivation) completes. The slot
moves `awaiting_path` → `establishing` → `active`/`failed`, mirrored to
`rnsd.links.<tag>.state` so the caller and browser can watch it before the
link_id exists. The link is built on the rnsd task in `linkKickoff`, which:

- recalls the remote identity (requesting a path first if unknown);
- builds the OUT `Destination` from `(identity, app_name, aspects)` and
  **asserts the result hash equals the caller's `dest_hash`** — a mismatch means
  the aspect doesn't belong to that hash (e.g. dialing a non-rnsh hash with the
  `"rnsh"` aspect), and fails terminally with `last_error = aspect_mismatch`
  rather than addressing the wrong destination;
- sets the establishment timeout: a caller-supplied `link_timeout_ms` is used
  verbatim (and pushed into µR's own watchdog); otherwise rnsd computes the
  Python-reference outbound budget — the next hop's first-hop timeout plus 6 s
  per hop.

**Pre-active outboxes.** A `itsSend` before the link is `active` is buffered in a
one-packet outbox and flushed on establishment (or dropped with
`last_error = send_queue_full` if a second arrives first). The same hold applies
to one pending Resource and one pending request, so a consumer can
`rnsdLinkOpen()` then immediately `rnsdLinkRequest()`/`rnsdLinkSendResource()`.

### 5.2 Lifetime: ITS handle == Link, no parking

The Link's lifetime tracks the consumer's ITS handle **1:1**. Closing the handle
(`itsDisconnect`, or the handle dying with its owning task) tears the µR Link
down and frees the slot + tag immediately — there is no teardown frame, no
orphan/parking window. `onLinkDisconnect` nulls the slot handle first so
`linkFreeSlot` won't re-disconnect, tears the Link down, and frees the slot; a
same-tag reopen issued FIFO-after sees the slot gone and a clean reclaim path
handles the brief terminal-grace overlap.

A consumer that wants a Link to survive idle gaps **keeps its handle open** and
reuses it. That is where any warm-hold / pooling policy lives — in the consumer,
not rnsd. lxmf does this with a per-(identity, peer) link pool reaped on
`s.lxmf.link.idle_s` (default 600 s); nomad keeps a per-session link for
same-node page reuse. (Earlier the daemon parked detached links for an
`orphan_ttl`; that was removed because nothing used it — consumers already hold
their own handles — and because inbound bytes on a parked link were silently
dropped. Don't reintroduce it.)

### 5.3 Inbound (`rnsdDestListenLinks`)

A consumer that has a hosted destination (`rnsdDestOpen`) calls
`rnsdDestListenLinks(dest_handle, target_port)` (an in-band `LINK_LISTEN` frame).
rnsd flips `accepts_links(true)` on that destination; when a remote completes the
LR/LRPROOF handshake, rnsd opens a fresh ITS connection to (owning task,
`target_port`) with a `rnsd_link_incoming_t` payload — the rnsd-generated tag
(`in.<8hex>`), link_id, the remote identity hash (zeroed until the peer
identifies), and the local destination hash. There is no target-task argument:
rnsd already knows the owning task from the dest handle, so a consumer can only
receive links for destinations it owns.

### 5.4 Outbound delivery-proof tracking

Always on. (`s.rnsd.prove_incoming`, default 1, only governs whether *we* prove
inbound packets — PROVE_ALL vs PROVE_NONE — not outbound tracking.)

**Opportunistic (`RNSD_PORT_DEST`):** `OUT_RESULT` is emitted *twice*. `SENT`
(0) goes out immediately on egress; rnsd keeps the µR `PacketReceipt` in a
bounded 8-entry table (oldest evicted with a synthetic timeout) correlated to
`send_id`, and emits a second result:

- `DELIVERED` (1) — the cryptographic proof validated (rtt populated), fired via
  the receipt's delivery callback (resolved by packet hash — µR callbacks carry
  no userdata).
- `PROOF_TIMEOUT` (5) — no proof before the deadline (µR's receipt timeout,
  observed by polling, or the `s.rnsd.proof_timeout_s` backstop, default 60).
  **Not a failure** — the packet may have arrived; the peer may simply not prove
  or the proof was lost.

**Link packets (`RNSD_PORT_LINK`):** the receipt lives in the link slot
(consumers serialize sends per link, so one suffices); `linkTick` publishes
`rnsd.links.<tag>.tx_proven` and `.proof_timeouts` counters. Consumers baseline
both at send time and watch for increments. Resource transfers don't use packet
receipts — the Resource ACK (`RNSD_LINK_RESOURCE_OUTBOUND_DONE`) is already
proof-grade.

## 5.5 Resource transfer & request/response

Messages larger than one Link packet (~440 B encrypted) ride a Reticulum
**Resource**, whose data path is a shared-memory hand-off, **not** the KB-capped
ITS data path:

- **Inbound** — rnsd accepts the advertised Resource (gated by
  `s.lxmf.max_resource_size`, default 262144, and `s.rnsd.link.max_inbound_resources_total`,
  default 4, across all links), reassembles it into a PSRAM buffer, and opens a
  one-shot ITS connection to the consumer's resource-aux port with
  `RNSD_LINK_RESOURCE_INBOUND_DONE`. The consumer then **owns `buf`** and must
  `rnsdResourceRelease()` it.
- **Outbound** — `rnsdLinkSendResource(tag, buf, len, opaque_id)` hands rnsd a
  heap buffer; rnsd takes ownership, wraps it in a Resource on the named link,
  and frees it after the engine copies it. Settlement is
  `RNSD_LINK_RESOURCE_OUTBOUND_DONE` (opaque_id echoed).

**Request/response** (`rnsdLinkRequest`) is Reticulum's `link.request(path, data)`
bridged to bytes — the NomadNet page-fetch path (`/page/<rel>.mu`, `/file/<rel>`)
and `rnstatus -R`/`rnpath -R`. The response comes back through the same
resource-aux handoff (`RNSD_LINK_REQUEST_RESPONSE`, the whole page as a
consumer-owned buffer) or `RNSD_LINK_REQUEST_FAILED`. One in-flight request per
link; path+data are sent inline in the aux so must fit `ITS_MAX_MSG_DATA`
(ample for a GET; large form uploads as a request-Resource are not yet
implemented).

## 5.6 Channel (reliable messaging inside a Link)

A **Channel** rides inside a `Link` and turns it from a best-effort packet pipe
into a stream of **reliable, in-order, deduplicated messages**. `Link` and
`Resource` already exist; Channel fills the gap between them — continuous and
bidirectional like a Link, but with automatic retries and sequencing like a
Resource, and size-constrained to one packet per message. It is the substrate
[rnsh](../rnsh) runs on.

**The µR primitive** (`components/microreticulum/src/Channel.{h,cpp}`) is a
device-native port of upstream `RNS/Channel.py`, kept **wire-identical**:

- Each message is one `RNS::Packet(link, raw, context = CHANNEL /*0x0E*/)` whose
  plaintext is a 6-byte big-endian envelope — `>HHH` = (msgtype, sequence,
  length) — followed by the payload. `Channel::mdu()` is the Link MDU minus 6.
- One internal msgtype (`0x0100`) carries opaque consumer bytes; callers frame
  their own protocol inside the payload (rnsh does — §rnsh INTERNALS).
- **Reliability rides the Link packet's delivery proof.** A sent envelope stays
  in the TX ring until its `PacketReceipt` reads `DELIVERED`; an un-proven one is
  retransmitted (`Packet::resend`) up to 5 times, after which the Link is torn
  down. On receive, `Link::receive` proves the CHANNEL packet, decrypts it, and
  hands the plaintext to `Channel::_receive`, which window/dup-checks the
  sequence, emplaces into the RX ring, and delivers the contiguous run in order.
- **Port adaptations from the Python original:** µR's `PacketReceipt` callbacks
  are plain C function pointers with no userdata, so delivery/timeout are driven
  by **polling** each envelope's receipt status from `Channel::poll()` (the same
  idiom the link-receipt tracking in §5.4 uses) — no global receipt registry.
  The delivered-message sink is a single `void*`-carrying callback (the rnsd
  bridge sets it to its channel slot). The window is a small fixed size for now;
  the adaptive RTT-based window growth from `Channel.py` is intentionally not
  ported yet.
- **Cycle break:** `LinkData` owns the `Channel`, and the `Channel` holds a
  `Link` handle back — a `shared_ptr` cycle. `Link::link_closed()` shuts the
  channel down and clears `LinkData::_channel` so the graph frees.

**The rnsd bridge** (`RNSD_PORT_CHANNEL`, port 11) mirrors the Link bridge (§5)
onto a separate `chan_conn_t` slot table (`s_chan_conns`, PSRAM), reusing the
`link_state_t`/`lstName`/`sameLink`/`linkLoadIdentity` helpers. Each slot owns a
**hidden** `RNS::Link` plus its `RNS::Channel`; the consumer only ever sees the
channel.

- **Outbound (`rnsdChannelOpen`)** — same immediate-accept, `awaiting_path →
  establishing → active/failed` shape as an outbound Link, published to
  `rnsd.chan.<tag>.state`. Establishment is **gated on `has_path() &&
  recall()`**, not `recall()` alone: on a churning mesh a cached identity can
  outlive its path-table entry, and a Link request with no next hop is silently
  dropped (→ `establish_timeout`); `channelTick` keeps re-requesting the path
  while awaiting. On `active` the slot calls `link.get_channel()`, registers the
  receive callback, and flushes a bounded pre-active **outbox** (up to 16
  messages — larger than the Link outbox because Channel is itself the
  reliability layer).
- **Inbound (`rnsdDestListenChannels`)** — the channel counterpart of
  `rnsdDestListenLinks` (§5.3): an in-band `CHANNEL_LISTEN` frame sets the
  destination's established callback to `onIncomingChannelEstablished`, which on
  each accepted Link connects the consumer inbox **first** (so no delivered
  message lands with a dead handle) and only then wires `get_channel()` + the
  receive callback. Reuses the `rnsd_link_incoming_t` payload.
- **Data path** — `onChannelRecv` sends consumer bytes as one Channel message
  (buffering to the outbox when the window is full or the link is pre-active);
  `onChannelMsgCb` forwards each delivered message to the consumer handle.
  `channelPollAll()` drives `Channel::poll()` on every rnsd loop wake (proof
  arrivals wake the loop), so delivery detection and window-freeing are prompt;
  `channelTick()` runs the 1 Hz state machine (path/establishment timeouts,
  3 s terminal-grace reclaim).
- **State tree** — `rnsd.chan.<tag>.{state,direction,aspect,remote_hash,
  link_id,mtu,rtt_ms,opened_s,activated_s,tx_msgs,rx_msgs,last_error}` plus the
  reverse index `rnsd.chan.byid.<link_id>`. Closing the ITS handle tears the
  Channel + hidden Link down and deletes the subtree — same 1:1 handle==channel
  lifetime as Links (§5.2).

## 6. Boot barrier

Consumers wait on `rns.ready` before using rnsd. rnsd holds it unset until the
clock is valid, the network is up (`s.net.up_wait_s`, default 20), and a short
settle delay has passed. **ITS ports are not opened until the clock is valid** —
opening them earlier crashes (timestamps feed receipt/announce logic). This
ordering is load-bearing; don't move port creation ahead of the clock check.

**`s.rnsd.enable` is the master switch, read once at boot.** When `0`, `rnsdTaskMain`
brings up nothing — no Transport, no ITS ports — and **never sets `rns.ready`**,
so every interface and client waits on the barrier, times out (`waitForFlag`,
~120 s), and bails: the node stays dark. The task then idles (so the CLI still
reports state) and publishes `rnsd.enabled = 0`. **There is no live toggle —
changing `s.rnsd.enable` requires a reboot.** This is deliberate: it keeps
`rns.ready` a pure one-shot barrier (never goes false) rather than a runtime
signal everything would have to re-check. (Contrast `s.rnsd.transport_enabled`,
which *is* live — it's read at runtime for forwarding.)

## 7. Persistence

Storage is the source of truth for the durable layer; the `rnsd.*` runtime tree
is an ephemeral 1 Hz mirror of live state. µR's own `OS::read_file/write_file`
are no-ops — rnsd is meant to persist transport/path state on demand via
`rnsd persist if-transport` (cron-driven). **`rnsd persist` is currently a
no-op stub** (`rnsd.cpp` `// TODO: write paths/hashlist/tunnels when Transport is
wired`): `if-transport` skips on non-transport endpoints, and even in transport
mode it writes nothing yet — so path/transport state does **not** survive reboot
today. The default identity is `secrets.rnsd.identity`; rnsd does **not**
auto-create an application identity at boot — that is the app's call.

## 8. Maintainer pitfalls

- **Run Transport-touching code on the rnsd task.** `request_path`, link
  construction, destination registration off-task silently no-op (the outbound
  packet is dropped). Defer via ITS or a `rnsd.cmd.*` sentinel.
- **Large tables go in PSRAM, FreeRTOS sync objects do not.** Internal
  DRAM/DMA is scarce on the T-Deck, so ITS metadata, identity cache, and recv
  buffers live in PSRAM. But queues/stream-buffers/mutexes placed in PSRAM trip
  the `S32C1I` spinlock assert — keep every FreeRTOS sync object in internal RAM.
- **A `LoadProhibited` in cJSON / `navigatePath` / `storageGetInt` during flash
  reads is MSPI timing, not heap corruption.** It's marginal 80 MHz octal-PSRAM
  timing; don't go poison-hunting it.
- **Don't enable `SPIRAM_TRY_ALLOCATE_WIFI_LWIP` on display boards** — it starves
  WiFi static RX.
- **A destination's address is a one-way hash of `(identity, app_name, aspects)`.**
  You can't recover the aspect from the hash, and µR builds OUT destinations from
  the name. So `rnsdLinkOpen` needs both the hash (to recall the identity and
  request a path) and the aspect (to construct the destination); `linkKickoff`
  asserts they agree. An app-name-only destination must expand without a trailing
  dot (§1.1).
- **Link MDU is ~440 B encrypted.** Anything larger must go as a Resource, not a
  packet send.
- **The 1 Hz tick is staggered, deliberately.** `Transport::jobs()` + our-dest
  retry run on one tick; `publishPathTable()` runs on the *alternate* tick
  (`tickPhase ^= 1`). Both in one tick parks rnsd past tcp's 100 ms `itsSend`
  timeout (symptom: `[tcp] rnsd ITS send dropped`). The cost is that
  `Transport::jobs()` effectively runs at ~2 s cadence. Don't collapse them.
- **Path table: bounded by caps; the snapshot publisher is disabled.** µR's path
  table would grow unbounded (age-pruned only), so it's capped at `s.rnsd.path.max`
  entries (`Transport::path_table_maxsize`, default 100) with age-out at
  `s.rnsd.path.ttl` seconds (`Transport::destination_timeout`, default 86400) —
  wired via `NOW_AND_ON_CHANGE`. Separately, `publishPathTable()` (which mirrored
  the table to `rnsd.paths` for the browser Nodes window) is currently `#if 0`'d:
  O(N)-snapshotting every tick tripped the task watchdog *inside* it under churn —
  the `DestinationEntry` dtor walks a PSRAM RB-tree of `_random_blobs`, starving
  IDLE0 — even with its 64-row cap and a `vTaskDelay(1)` every 8 entries. So
  **`rnsd.paths` is not published today**; re-enabling needs that bounded/yielded
  walk and ideally storage→SD. Don't re-enable it blind.
- **Resolve link callbacks by shared `LinkData`, not pointer.** µR hands callbacks
  `Link` wrapper *copies* (different address, same `shared_ptr<LinkData>`), so
  `&slot->link == &link` never matches. Use `sameLink(a,b)` (built on µR's public
  `operator<`). The packet callback gets no `Link&` — it reads `packet.link()`,
  stamped by Transport just before `link.receive()`.
- **Announce-due comparisons must be signed.** `sendXAnnounce()` rewrites
  `s_rnsd_last_announce_tick` *after* the µR call (a few ms), so it can land just
  past the loop's captured `now`; an unsigned `TickType_t` subtraction underflows
  to ~`UINT32_MAX` and re-fires immediately. The code casts to `int32_t` before
  the `>= 0` test — keep it.
- **`thread_local` is unsafe codebase-wide; use plain `static`.** libgcc's lazy
  TLS init has corrupted FreeRTOS scheduler state at boot. (Statics in ITS recv
  callbacks are fine — a port dispatches only on its registering task.) Also:
  **PSRAM-stack tasks must not `printf`** — use `info()`/`warn()`/etc.
- **Including both µR headers and spangap log macros needs the macro dance.**
  µR declares `info/warn/error/debug/msg` in `namespace RNS` (with `#define msg`);
  spangap's log *macros* corrupt them. `rnsd.cpp` `#pragma push_macro` + `#undef`s
  each name around the µR includes, then `pop_macro`s. Replicate it in any file
  that mixes the two.
- **We host `rnstransport.remote.management` but don't service its requests yet.**
  It's announced and accepts links, but has no request handler (pending a
  `register_request_handler` port), so `rnstatus -R` / `rnpath -R` *against this
  node* don't work — µR's `Link::handle_request` returns one opaque `bin`, while
  upstream expects an inline `[stats-dict, link_count]`.

## 9. Browser UI

The shared RNS UI lives in this straddle: `modules/rnsd.ts` (Pinia store +
`rnsd:1` DataChannel exposing the path table, identity, and announces),
`panels/RnsdPanel.vue` (Settings → Reticulum), `panels/NodesWindow.vue` (live
nodes), `panels/MapWindow.vue` (map of GPS-announcing peers). Interface-specific
UI is **not** here — each interface straddle contributes its own settings panel.

## 10. Bundled components

```
esp-idf/components/
├── microreticulum/  the µR fork — README covers the pinned commit, crypto, layout
└── bzip2/           bzip2 1.0.8 — µR's Resource compression path
```

The consuming buildable straddle picks these up via the
`staging/components/*/components/` glob in its top-level `CMakeLists.txt`.
`CMakeLists.txt` in the microreticulum component is the source of truth for which
µR files are in the build.

### 10.1 Ecosystem licensing constraints

Not everything in the Reticulum ecosystem is portable here:

- **LXST** (the Reticulum voice/telephony stack) is CC BY-NC-ND 4.0 —
  non-commercial *and* no derivatives, a hard blocker for porting any of it.
- **leviculum** (Rust port) is AGPL-3.0-or-later; a C++ transcription of it
  would still be a derivative work carrying the same obligations.
- **ratdeck** (T-Deck firmware on the same µR fork) is AGPL-3.0 — read it for
  ideas, never copy code. Its sibling `ratspeak/microReticulum` library is
  Apache-2.0 and is fine as an algorithm reference (see the component's
  NOTICE.md).

## 11. Announce app_data formatting (diagnostics)

Announce `app_data` has no single layout — different clients pack it differently
— so `formatAnnounceAppData()` renders a one-line log suffix by trying known
shapes **in order**, used identically for inbound announces and our own outbound
ones so they read the same:

1. empty → `(0B)`
2. pure msgpack → `(NB) mp=…`
3. 32-byte ratchet `||` msgpack → `ratchet=… mp=…`
4. 32-byte ratchet `||` UTF-8 text → `ratchet=… name="…"`
5. version byte `||` msgpack `||` trailing 32-byte ratchet → `v=XX mp=… ratchet=…`
6. none of the above → printable-bytes fallback `="…"`

The `mp=` rendering uses `mpDecode()`, a self-contained bounded msgpack
pretty-printer (recursion depth ≤ 8, output truncated at 800 chars, covers
fixint / fixstr+str8/16/32 / fixarray+array16/32 / fixmap+map16/32 / nil). It is
**diagnostic only** — purely for legible logs; nothing parses announce semantics
from it (LXMF's own `parseLxmfAnnounce` does the real decoding). This is the only
written record of the app_data dialects, hence its place here.

## 12. Testing

Because µR's wire is kept byte-identical to upstream RNS, the fastest way to
exercise Links, Channels, and rnsh end-to-end is against a **host-side reference
node running stock `rns` from PyPI** — no second device required.

**In-tree peer scripts.** `hw-tdeck/tests/peers/echo_peer.py` (+
`peer-config.template`) is the canonical peer shape: bring up `RNS.Reticulum`,
host a `Destination(identity, IN, SINGLE, app_name, *aspects)`, call
`set_proof_strategy(PROVE_ALL)` and `set_link_established_callback(...)`, then
announce on a tight cadence at startup (every 1 s for a ~10 s warm-up, backing
off to 30 s) so a freshly attached client sees an announce within ~1 s. It also
prints a `READY <dest_hash_hex>` sentinel on stdout so a fixture can synchronise
instead of racing on a sleep. That variant listens on a `TCPServerInterface` for
the LAN/loopback pytest path; `nomad_peer.py` is a NomadNet-node counterpart.

**Testnet rendezvous (no second device).** The T-Deck joins the *public*
Reticulum testnet — `show s.tcp.peers` lists outbound `TCPClientInterface` dials
to `rns.radical.computer:4242`, `rns.birdsnet.com.br:4242`,
`193.26.158.230:4965`, etc. The container has internet, so a host RNS node that
dials the **same** testnet TCP node shares the mesh with the device; both end up
≤ 2 hops apart and that node's cache already holds the device's announce, so
path requests resolve fast. `hw-tdeck/scripts/lxmf-stamp-test` is the worked
example (an LXMF node dialing the testnet directly to interop against a device
already on it — no bridge). Recipe for a bare RNS node:

- `python3 -m venv <dir> && <dir>/bin/pip install rns` (RNS 1.3.5; PyPI is
  reachable from the container).
- Write a config whose `[interfaces]` has a `TCPClientInterface` with
  `target_host = rns.radical.computer` / `target_port = 4242` — the same node
  the device dials.
- Drive it with the `echo_peer.py` pattern above (host the destination, prove
  all, announce, set the link-established callback).

**Channel interop.** To speak the device's Channel wire from stock RNS, register
a `MessageBase` subclass with `MSGTYPE = 0x0100` and raw `pack`/`unpack` — µR's
`Channel::MSGTYPE_RAW` (§5.6) is byte-identical to upstream, one 6-byte
`>HHH` (msgtype, sequence, length) envelope per message.

**Gotchas.**

- **Direct device ↔ container TCP does NOT work.** The container is on the
  docker bridge (172.17.0.2) and the device is on WiFi; there is no route
  between them. You *must* rendezvous through a shared public testnet node — the
  device's own outbound dials give you a common relay for free.
- **`recall()` succeeding ≠ `has_path()` true.** On the busy testnet the bounded
  100-entry path table (§8) churns, so a cached identity can outlive its path
  entry. Gate any outbound link/channel establishment on `has_path() && recall()`
  and re-`request_path()` while waiting — otherwise the link request has no next
  hop and is silently dropped, surfacing only as an `establish_timeout`. This is
  exactly why the device side gates §5.6 the same way.
- **`spangap cli "<cmd>"` is transient-flaky.** Occasional SSH banner timeout /
  "closed by remote host"; retry 2–3×. It also forwards piped stdin into a nested
  interactive command as long as stdin stays open, which is a feature — e.g.
  `( sleep 9; printf 'x\r'; sleep 10 ) | spangap cli "rnsh <dest>"` drives an
  interactive `rnsh` session over the loopback CLI.
