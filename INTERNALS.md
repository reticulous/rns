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
- **Link round-trip re-measurement.** Upstream takes one RTT sample at
  establishment and every retry timer above the link is a multiple of it.
  `Link::rtt_sample()` folds each delivered link proof's own round trip into a
  smoothed estimate instead (§5.3a), so a link that established while the medium
  was busy is not paced by that one reading forever.
- **`AnnounceHandler::received_announce` carries the receiving interface.** The
  handler is where a node learns of every destination on the network, and
  upstream tells it *how far away* the origin is (`hops`) without telling it
  *which way*. The pair is what a handler actually needs: whose neighbour the
  origin is, which interface's community it falls in, and — through the
  interface's own `r_stat_rssi`/`r_stat_snr`, which still hold this packet's
  sample on this call stack — how well it was heard. It is `Type::NONE` for an
  announce with no interface behind it. This is what lets one handler in rnsd
  build the direct-peer table for every medium at once (§1.3) instead of each
  interface straddle reconstructing it from its own wire.
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
- `Directory.{h,cpp}` (new) + `Identity.cpp`/`.h` — **one arena replaces the
  identity cache and the path table.** `Identity` has no `_known_destinations`
  map: `recall()` reads the directory pool, `recall_app_data()` slices the
  retained raw announce, and `remember()` is gone — validation no longer stores
  anything, because what to keep and at which depth is the retention decision in
  `Transport::inbound`. Single writer (the rnsd task), lock-free readers via a
  per-record sequence counter (§1.1.2).
- `Packet.cpp` — malformed-packet error path **dumps the first ≤8 bytes hex** so
  HEADER_1-vs-HEADER_2 mis-parse, HDLC desync, or a noise byte are
  distinguishable in the log.
- `Packet.cpp`/`Link.cpp`/`Transport.cpp` — **an unprovable proof is dropped, not
  fatal.** `Identity::validate` opens with `assert(_object)`, so calling it on an
  unset identity aborts the device. Three paths reached it from the air: the
  *explicit* branch of `PacketReceipt::validate_proof` (the implicit branch
  beside it had always guarded), `Link::validate_proof`, and `Transport`'s
  link-proof relay, where `Identity::recall()` answers "not known" with an unset
  identity that `get_public_key()` would have asserted on before `validate()`
  even ran. All three now check first and treat it as a proof that cannot be
  verified, which is what the surrounding code already claimed to do. A
  destination holding no identity is a remote party's doing, never a local
  invariant, so this is reachable by anyone in radio earshot: it presented as a
  reboot part-way through a 2 kB LXMF resource, which is simply a long enough
  run of proofs to find one.
- `Packet.cpp` — **link-packet proof validation enabled.**
  `PacketReceipt::validate_link_proof` was stubbed (`if (false)`); `Link::validate`
  exists and verifies against the peer's link signing key, so the call is wired
  up. Without it a packet sent over a Link could never conclude its receipt
  (`DELIVERED`), which the per-link proof counters depend on.
- `Packet.{h,cpp}`/`Identity.{h,cpp}` — **rx-signal report riding the delivery
  proof** (the "extended proof"; see [rnsd §5.7](../../INTERNALS.md)). `Packet::
  prove_report` / `Identity::prove(report_signal=true)` append the prover's own
  rx signal and antenna tx power (`int16 rssi dBm | int16 snr×10 | int8 txpwr
  dBm`, BE) after the proof data, outside the signature (which covers only the
  packet hash). `validate_proof` accepts the trailing 5 bytes on both proof forms
  — `IMPL_LENGTH + 5` (implicit, the default per `should_use_implicit_proof`) and
  `EXPL_LENGTH + 5` — and `validate_proof_packet` decodes them into
  `PacketReceipt::remote_rssi/remote_snr/remote_txp`, stamps `local_txp` from the
  interface the proof arrived on, and also captures the proof packet's own
  rssi/snr/hops for the receipt callback. `Transport.cpp`'s proof-hash size check
  likewise admits `EXPL_LENGTH + 5`. `Interface` carries `tx_power_dbm`
  (`INT8_MIN` = not a radio) for the driver to fill in.
  **Pitfall:** the trailer is inert to validation (signature covers only the
  hash), but a *vanilla* receiver length-rejects the longer proof — so rnsd only
  emits it under the per-peer negotiation in rnsd §5.7, never blindly.
- `Link.cpp`/`Transport.cpp` — **links follow the peer across interfaces.**
  `Link::receive` treated a link packet arriving on an interface other than
  `_attached_interface` as hostile ("Someone might be trying to manipulate your
  communication!") and refused to process it — but peers flip interfaces
  mid-link legitimately: a TCP reconnect yields a new iface impl (same name,
  different ptr), and a multi-path peer's traffic can start arriving via a
  different hop. Link payloads authenticate under the link token, so the packet
  is now processed regardless; the pin is *moved* only when the packet proves
  knowledge of the link key via a successful trial token decrypt (keepalives,
  resource parts and proofs are not token-encrypted — they are handled but never
  move the pin, so a replayed link_id cannot steer our traffic). On the outbound
  side, `Transport::outbound` now pins link traffic to the link's attached
  interface (upstream checks `destination.attached_interface`; this port keeps
  the pin on the Link), compared **by name** so a reconnect's new impl keeps
  carrying the link; a not-yet-pinned link broadcasts as before.
- `Log.{h,cpp}` — **step narration is a switch, not a level.** µR's `LOG_VERBOSE`,
  `LOG_MEM` and `LOG_TRACE` all map to `ESP_LOGV`, so `log rnsd verbose` could
  not ask for events without also asking for the dozen-lines-per-packet
  narration inside them — which on a busy TCP link *is* the load rather than a
  description of it. `TRACE`/`TRACEF` now test `RNS::trace_enabled()` (a plain
  bool, read before any formatting, so a suppressed `TRACEF` costs no
  `vsnprintf`), driven live from `s.rnsd.log.trace` and off by default. Nothing
  is lost and no level moves: verbose alone is one line per event, the switch
  adds the steps.
- **Bytes from strangers never reach the console unfiltered** (`logSafe()` in
  `rnsd.cpp`). Announce app_data, msgpack strings, announced names and remote
  request-response previews all pass through it: printable ASCII survives,
  everything else becomes `.`. The bar is *printable ASCII*, not *not a control
  code*, for a reason — a single 0x0E (Shift Out) in one announce switches the
  terminal to the DEC line-drawing charset, and from there every line the device
  emits, including other tasks' and the timestamps, renders as box glyphs until
  something sends 0x0F. One byte of someone else's app_data corrupts the entire
  log stream. High bytes go in the same sweep: validating UTF-8 cheaply is not
  worth it and a lone high byte renders as garbage regardless.
- `Transport.cpp` — **table culls are bounded and summarised** (`CULL_PER_PASS`).
  A busy peer leaves hundreds of pending path requests that expire together;
  the per-entry log line turned each expiry into a burst of blocking writes on
  the rnsd task, long enough that nothing drained the ITS inbox and interfaces
  logged `ITS send dropped` underneath it. A yield would not have helped —
  rnsd is the task that must drain its own inbox, so the sweep has to be
  *shorter*, not merely interruptible. One line per sweep, a cap on removals
  per pass (an entry a pass late is still expired), and `OS::time()` hoisted
  out of the walks — it was a call per entry, compared against a value that
  cannot change mid-walk.
- `Transport.cpp` — **`Bytes::toString()` is not a hash formatter.** The
  waiting-path-request expiry printed `destination_hash.toString()`, i.e. raw
  binary as text — mojibake in the log where a hash belonged. Hashes are
  `toHex()`; `toString()` is for `Interface`/`Identity`.
- `Transport.cpp` — **one announce, one line.** The relay decision is a clause
  on the announce's own `Destination %s is now %d hops away…` line, not a line
  of its own. Adding a line per decision to a path already emitting several is
  how the firehose got built in the first place.
- `Transport.cpp` — **an announce nothing could carry is refused at ingress.**
  `announce_relay_possible()` asks, before the announce table is touched,
  whether *any* OUT interface could re-broadcast this announce: an announce
  from beyond an interface's community radius is never re-broadcast onto it
  (radius 0 relays nothing), and a point-to-point interface
  never echoes back out what arrived on it. A node where neither survives — a
  radius-bounded radio plus the TCP link the announce came in on — used to store
  every announce it heard and retry it to the retry limit, walking the whole
  outbound path per attempt and refusing on every interface, refilled from the
  ingress faster than it drained. It is a **necessary** condition only: rate
  caps, queue depth and the roaming/boundary next-hop rules depend on emission
  -time state and stay in `outbound()`, which remains authoritative. The
  decision is one `VERBOSEF` line per announce, replacing the ten-per-attempt
  the retry walk emitted.
- `Transport.cpp` — **the announce walk is bounded per pass**
  (`ANNOUNCE_EMITS_PER_PASS`, round-robin from a cursor). Nothing in the
  emission path yields, so a full ring coming due together ran ~100 pack +
  decide + transmit cycles back-to-back on the rnsd task — IDLE0 starved into
  the task watchdog, with `[tcp] rnsd ITS send dropped` underneath it. The pass
  repeats at least once a second against a re-arm interval of seconds, so the
  ceiling costs no drain rate.
- `Transport.cpp`/`Packet.cpp` — **"handed to transport" is not "transmitted".**
  `outbound()` reports a deliberately-unrelayed forwarded announce as handled
  so `Packet::send` does not cry "No interfaces could process" over a routing
  decision — but it now says so in its own line, and `Packet::send` no longer
  logs `successfully sent packet!!!` over it. Conflating the two is how a node
  that relayed nothing for hours still read as working.
- `Transport.cpp` — **routing lives in the directory pool.** `Transport::outbound`
  copies a fixed-size `rdir_route_t` out and resolves one interface: it allocates
  nothing and constructs no `Packet` on the per-packet path. `has_path`,
  `hops_to`, `next_hop`, `next_hop_interface` and `remove_path` all read the same
  record; `remove_path` clears the *routing* fields and keeps the identity, since
  that is what makes the next path response cheap. There is no periodic path
  sweep: expiry and vanished-interface detection are lazy, in
  `peek_live_route()`, which clears a dead record's routing fields and reports a
  miss on first use so the caller path-requests instead of black-holing.
- `Transport.cpp` — **announce ingest splits forwarding from storage.** Upstream
  computes one `should_add` over retained state and uses it to gate the
  retransmission queue, the immediate rebroadcasts *and* the table insert. Here
  `fresh` is the forwarding input, computed by the guard pool over every announce
  we ever validated rather than over whatever we happened to keep; `retain` is
  the storage decision, true when the announce was resolved on demand (an
  outstanding path request), originated within the ingress interface's
  community radius, was originated by the direct peer, is claimed, or is in
  active use. A longer path never
  displaces a shorter one while the shorter one is still valid, and an announce
  we have already seen and already hold is not re-stored — on a mesh where
  several neighbours rebroadcast the same announce, that is most of the traffic.
- `Interface.{h}` — **`community_radius`**, set at registration the way `mode`
  is. This is what keeps the ingest split portable while the *policy* — how far
  each interface's community reaches — stays outside µR, in each interface
  straddle's own `community_radius` setting.

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
- `Resource.cpp`/`Compression.h` — **bz2 decode tables sized from the caller's
  output bound, not from the stream header.** Stock bzip2 sizes the
  decompressor's working set from the `blockSize100k` digit in the four-byte
  stream header, before it has looked at a byte of the compressed data behind
  it. Python's `bz2.compress` defaults to level 9, so every stock peer's
  compressed Resource — a 2 KB NomadNet page included — asks for ~2.25 MB,
  1.8 MB of that a single contiguous block, even with `small=1`. That fails on
  a 2 MB-PSRAM board whatever else is resident, and fails on an 8 MB one as
  soon as PSRAM is fragmented enough to have no 200 KB run left; either way the
  Resource is simply undecompressable.
  The vendored bzip2 therefore carries a local entry point,
  `BZ2_bzDecompressInitBounded(strm, verbosity, small, maxOut)`, which derives
  the decoder's block ceiling `nblockLimit` from `maxOut` — the largest output
  the caller will accept — and clamps it to the header digit, never above.
  `ll16`/`ll4`/`tt` are allocated to that ceiling, and every `nblock`/`tPos`/
  `origPtr` bound in `decompress.c` and the `BZ_GET_*` macros tests against it,
  so a shrunken table can never be indexed past its end. A 1.5 KB page decodes
  in ~4 KB of tables instead of 250 KB, and the cost stops depending on the
  peer's choice of level.
  `maxOut` is an *output* bound, and a block's Burrows-Wheeler data is the RLE1
  encoding of what it decodes to, which expands by at most 5/4 (a run of
  exactly four identical bytes becomes those four plus a count byte) — so
  `nblockLimit` is `5/4·maxOut`, computed inside the library where callers
  cannot get it wrong, and left unbounded above 720000 where that ceiling
  exceeds bzip2's largest block anyway. The bound is a *ceiling*: a block that
  genuinely needs more is refused as `BZ_DATA_ERROR`, not silently truncated,
  so an under-estimate fails loudly. Decompression drives `BZ2_bzDecompress`
  over the stream API rather than `BZ2_bzBuffToBuffDecompress`, which has no
  bounded variant. This is the receive-side counterpart of the
  `blockSize100k=1` we already compress with — both sides bound their own
  working set, and neither depends on the peer's choice of level.
  Alongside it, a failed inbound Resource says which stage failed: the assembled
  byte count against the advertised transfer size (parts arrived short or long),
  decryption failure over that count, and the bz2 return code with bytes
  produced against the cap. Previously every one of these surfaced as the same
  single "corrupt" line.
- **Announce/path-request logs are verbose** — the high-volume DEBUGFs in
  `Transport::inbound`/`packet_filter`/`path_request` and
  route through `DBGF_DEMOTE`/`DBG_DEMOTE`
  macros that emit at verbose unconditionally — busy TCP peers deliver hundreds
  of announces and route requests, and it's all other people's traffic. Same for
  rnsd's own per-announce logger and the per-packet iface tx/rx wire log. The one
  exception stays at INFOF: answering a path request for a destination local to
  this system. (Formerly switchable via `s.rnsd.debug.only_local`; the knob is
  gone.) A few DEBUGFs were also promoted to INFOF, plus a diagnostic for "DATA
  arrived for a dest with no local destination."

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

#### 1.1.1 Announce & path-request propagation

The upstream port left the whole announce-bandwidth-management path stubbed;
it is now implemented, plus fork-specific behaviour for point-to-point links.

- **`announce_cap` now works.** Upstream RNS caps announce bandwidth per
  interface (`Reticulum.ANNOUNCE_CAP`, default 2%): an announce whose airtime
  would exceed the cap is deferred into a per-interface `announce_queue` and
  emitted later. The port had `_announce_cap` hard-wired to `0` (so the throttle
  never engaged) and `Interface::process_announce_queue()` stubbed. Both are
  now live: `_announce_cap` is set at interface registration (percentage carried
  in `rnsd_iface_t.announce_cap`, `0` ⇒ the 2% default; `RNS_IFACE_ANNOUNCE_CAP_DEFAULT`
  in `ports.h`), configurable per interface. **The throttle math was also
  broken by integer truncation** — `tx_time = (bytes*8)/bitrate` in `uint16_t`
  is `0` for any sub-1-second frame, so `wait_time` was always `0`. All three
  cap sites (`outbound()`, recursive `request_path()`, `process_announce_queue()`)
  now compute in `double` seconds, matching upstream's float `announce_allowed_at`.
- **The retransmission queue is one fixed ring** (`Transport::AnnounceRec`),
  allocated once at `start()` from `s.rnsd.announce.table_max`. Each record
  carries the announce payload inline and names its receiving and attached
  interfaces by hash prefix rather than holding handles, so an entry costs a
  flat `sizeof(AnnounceRec)` with no allocation and nothing to run out of
  mid-burst — a queued `Packet` held nine separate `Bytes`, each its own heap
  block, and the cull that ran when the table filled built a sort index, which
  is an allocation at exactly the wrong moment. `cull_announce_table()` is now a
  select-min pass with no allocation at all.

  It keeps its own storage rather than referencing the directory's blob pool,
  deliberately: an entry lands here when we are *forwarding* for someone else,
  which on a gateway is precisely the traffic the retention policy declines to
  keep — so most references would dangle. Blob slots are also evicted under
  pressure at any moment, which a cache tolerates and a work queue does not.

  The held-announce edge case (a path request arriving for a destination whose
  announce is queued but not yet rebroadcast) is a flag on the record, not a
  second table: the announce is marked `ANNOUNCE_F_HELD`, the path response
  takes a slot of its own, and the held record is re-armed once that response
  has gone out.
- **Queue drain.** µR has no `threading.Timer`; `Transport::jobs()` polls each
  interface and calls `process_announce_queue()` once `announce_allowed_at` has
  elapsed, emitting one held announce (lowest hop count first). Queued announces
  count as *handled* in `outbound()` (a `deferred` flag), so `Packet::send` no
  longer logs a spurious "No interfaces could process" for a capped announce.
- **Point-to-point echo suppression.** A new interface property `point_to_point`
  (`rnsd_iface_t.point_to_point`, mirrored to `Interface::_point_to_point`)
  marks links with no hidden-node problem — a single peer (TCP) or a switched
  LAN (auto). On those, `outbound()` does *not* re-broadcast a forwarded
  announce back out the interface it arrived on, and `request_path()` does not
  ask a peer for a path it just provided. This is a fork addition — stock RNS
  does neither (it relies on `announce_cap` + receiver dedup). Radio interfaces
  (LoRa, ESP-NOW) leave `point_to_point` false so re-broadcasts still reach
  nodes hidden from the origin. The announce check keys off the rebroadcast
  packet's `receiving_interface()` (carried from the stored announce packet at
  retransmit time), **not** a `next_hop_interface()` path-table lookup — the
  latter misses after path culls or interface reconnects.
- **Instance-local destinations announce everywhere.** Upstream blocks *every*
  unattached announce on a `MODE_ACCESS_POINT` interface — the node's own
  included — so a radio-edge node whose only interface is an AP is
  undiscoverable *and* unreachable: its announce enters no cache, so no path
  request for it can ever be answered. Here the announce egress gate is the
  community radius (`Transport::outbound` blocks a forwarded announce whose
  hops exceed the egress interface's radius), and destinations in
  `_destinations` are exempt from it — this node's own announces are a
  trickle and must reach every interface. The radius keeps the airtime
  purpose: the transport network's announce flood never lands on an edge
  link, because it arrives deeper than any radius.
- **Path-request handling is community-aware.** Whether a request is searched
  at all is the requestor-side gate (`path_search_possible`: an interface with
  no community gets no errands run); a search that is taken on goes out every
  other interface, honouring the point-to-point echo suppression.
  The
  forwarded-request dedup table (`_discovery_pr_tags`) evicts **FIFO**
  (`_discovery_pr_tags_order`) instead of by `std::set` content order, and its
  cap (`RNS_PR_TAGS_MAX`) is 256 — the old content-ordered eviction dropped
  tags still circulating and let path requests loop between parallel uplinks.
- **`transport_enabled` is live.** rnsd mirrors `s.rnsd.transport_enabled` into
  the µR static via `NOW_AND_ON_CHANGE`, so toggling it takes effect without a
  reboot (Transport reads the flag per forwarding decision). On the *disable*
  transition `jobs()` clears `_announce_table` and drops all interface announce
  queues (`drop_announce_queues()`, previously stubbed), so pending rebroadcasts
  stop immediately instead of trickling the backlog out for minutes.

#### 1.1.2 The directory (`Directory.{h,cpp}`)

Everything this node knows about *other* destinations is one arena of packed
fixed-size records: the public key, the aspect name hash and the route are
fields of the same record, so they are acquired together, evicted together, and
cannot disagree. It depends on nothing outside µR's own types and a three-hook
platform struct (`arena_alloc`, `image_load`, `local_minutes`) — no filesystem,
no configuration store, no allocator policy. The embedder (rnsd) supplies the
hooks, the byte budget, and the file the image lands in (§7).

**Three pools, joined only by the destination hash.** No pool stores an index
into another: a stored link is a second expression of a relationship the key
already carries, and therefore a consistency obligation across a lock-free
reader and a raw persisted image.

| pool | means | slot |
|---|---|---|
| guard | "I have seen this announce" | 28 B |
| directory | "I know who this is" — keys, name hash, routing, claims | 160 B |
| blob | "I can answer a path request for this" — the raw signed announce | 320 B (`s.rnsd.dir.blob_slot`) |

Slot counts come from a byte budget (`s.rnsd.dir.budget_kb`, or a share of free
PSRAM at boot) split 8 : 4 : 1 guard : directory : blob — 664 : 332 : 83 at the
96 KiB ceiling. Nothing allocates after `rdirInit`, so no arrival path can fail
for memory: a full pool evicts, and an ingest that cannot get its deeper layer
silently keeps the weaker one. Lookup is a linear scan of the pool, which is
what having no index to keep coherent with a raw image costs, and at these slot
counts is a few hundred `memcmp`s of a 16-byte key.

**Concurrency: one writer, many readers.** Only the rnsd task writes; only the
directory pool is read cross-task, and only it carries a per-record sequence
counter — odd while the payload is in flux, even when coherent, closed with a
release store so no payload write sinks past it. A reader copies the record
out, re-reads the counter, and retries (`RDIR_SEQ_TRIES` = 8, then reports a
miss into `rnsd.stats.dir.seq_retries`). Slot reuse deliberately does **not**
reset the counter: a counter restarting at zero could match a value a reader
captured before the reuse, and that reader would accept a torn record. The
reader's *scan* is racy by construction — a slot can be reused mid-walk — so
the candidate is confirmed (used flag, key match) inside the seqlocked copy,
not before it. No pointer into the arena escapes.

**The guard is the forwarding memory, and it is not the directory.** Every
announce we validate updates it, whether or not we keep anything else: a
4-byte-truncated destination hash, a four-deep ring of 4-byte random-blob
fingerprints, the announce's own emission time, and a local age in wrapping
minutes. A blob already in the ring, or an emission older than the one held, is
a replay and does not reach the retransmission queue — which is what stops a
repeat announce costing ~1.5 s of LoRa airtime. Two things fall out of the
truncated key: a destination collision is possible, so a *run* of
older-emission suppressions (`RDIR_G_RUN_LIMIT`) resets the entry rather than
silencing the losing destination forever, at a cost of one duplicate forward;
and a requested `PATH_RESPONSE` must bypass the fingerprint check, because a
relay answers from its own cached announce and its blob is necessarily one we
have already heard — treat that as a replay and path discovery works exactly
once and then goes silent.

**Ingest splits forwarding from storage.** In `Transport::inbound`, `fresh` is
the forwarding input (the guard, over every announce ever validated) and
`retain` is the storage decision, true when a strictly-better-or-equal route
arrives *and* one of: the announce was resolved on demand (an outstanding path
request — the arm that keeps a radius-0 interface usable at all, or a node
with only a cheap link would discard the path response it just asked for), its
origin is within the ingress interface's community radius, it was originated
by the direct peer (hops 1 on the wire), the destination is claimed, or
its route is in active use. A longer path never displaces a shorter valid one;
an announce already seen and already held is not re-stored, which on a mesh
where several neighbours rebroadcast the same announce is most of the traffic.
The *policy* — how far each interface's community reaches — stays outside µR,
in each interface straddle's `community_radius` setting, carried in at
registration.

**Claims and eviction.** The claim vocabulary lives outside the store and is
compiled into the record at assert time (a per-consumer bit field for presence,
persistence and blob interest, plus `claim_touch`/`claim_decay`), so eviction
reads only in-record data. Records are removed lowest category first, oldest
first within a category:

| category | ordered by |
|---|---|
| guard-only | local age |
| unclaimed, no live route | `last_heard` |
| ephemeral claim past decay | `claim_touch` |
| ephemeral claim, live | `claim_touch` |
| interface-retained (`EDGE`), unclaimed | `last_heard` |
| persist claims, and custody | `claim_touch`, or `last_heard` for custody |
| route used recently | `last_used` |

`RDIR_CLAIM_ANSWER_FOR` is custody, not a consumer claim: it is set when the
destination is a community member — within its interface's community radius —
and it ranks with the persistent claims — without it a gateway's own
segment competes for slots with a large network's announce churn and loses
continuously, because the churn is what keeps arriving. It is re-evaluated on
every announce rather than latched, so a destination that drifts beyond the
radius stops being our obligation. Eviction is a select-min pass,
not a sort index: the store allocates nothing after init, and building one is
an allocation at exactly the wrong moment.

**Routing reads and writes the same record.** `Transport::outbound` copies a
fixed-size `rdir_route_t` out and resolves one interface — no allocation, no
`Packet` construction on the per-packet path. There is no periodic path sweep:
expiry and vanished-interface detection are lazy, in `peek_live_route()`, which
clears a dead record's routing fields and reports a miss on first use so the
caller path-requests instead of black-holing. `rdirTouchUsed` stamps outbound
use and slides the expiry out, because use is the evidence that a route is
good; `rdirClearRoute` drops the routing fields and keeps the identity, which
is what makes the next path response cheap.

**Reader surface.** `rnsdRecallPubkey` / `rnsdRecallAppData` (the latter slices
the retained blob, so it answers only while one is held), `rnsdClaim` /
`rnsdClaimTouch` / `rnsdClaimDrop` / `rnsdSeedPubkey` (marshalled to the rnsd
task over `RNSD_PORT_DIR`, §3), and `rnsd.dir.<hex32>.{pubkey,name_hash,hops,`
`last_heard,claims,route}` as a storage *provider* — a read answered from the
store per key, not a mirrored subtree, so nothing is published against the
chance that someone asks. Occupancy and the counters that explain it are in
`rnsd.stats.dir.*`; the persisted image is §7.

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

### 1.3 The neighbourhood (`rnsd_peers.cpp`)

Nodes and their direct peers, for every medium at once. It hangs off the same
announce handler as the fan-out: an announce with `hops == 1` was transmitted by
the node that originated it, and the fork's `received_announce` now says which
interface it arrived on (§1.1), so the whole neighbourhood is computable in one
place.

**Only for an interface with a community** (`community_radius > 0`). A radius-0
interface is an uplink: its far end is a route rather than a neighbourhood, and
its announce firehose is every node in the wide network that is one hop from
*it*. That is also what bounds the tables — 16 nodes and 32 peers, PSRAM,
least-recently-heard evicted — since the media that have communities have
neighbourhoods the size of a room, a LAN or a radio's range.

**A peer is a DESTINATION; a node is the thing at the far end.** Grouping them
takes attribution, which an interface declares one of two ways:

- `rnsd_iface_t.point_to_point` — one peer, so the interface *is* the node, filed
  under an all-zero origin key with `peer_label` as its address. rnsd declares it
  at registration.
- `rnsd_iface_t.rx_origin` — several peers under one registration, so every
  inbound frame is prefixed with a 16-byte origin key and each peer is declared
  with `RNSD_IFACE_AUX_PEER` (which carries the *exact* interface name, because
  aux is addressed to a port rather than to a handle). An all-zero key is "the
  sender is unknown": the field is present on every frame so the strip stays a
  fixed offset, and a medium that can name some senders and not others says so
  per packet. It overrides `point_to_point` for this purpose: iface-auto sets
  both, the one for the no-echo rule and the other because it has many peers.
  iface-lora sets it too — a shared radio cannot name the sender of a packet it
  overheard, but it names the sender of an **announce** from its own peer table,
  and announces are the only frames this table is built from.

The key is stripped in `onTransportRecv` and stashed in `s_rxOrigin` for the
length of one `handle_incoming` — not threaded through mR, because
`Transport::inbound` and every handler it calls run synchronously in that call
stack, so "the packet being processed" is a well-defined thing there and nowhere
else. It is cleared immediately after, since `Transport::inbound` is also reached
by a cache replay that has no arriving frame behind it.

**Without attribution there is no grouping, deliberately.** Two destinations
announced into the air by one node are indistinguishable from two nodes, so a
medium that declares no origin gets one row per destination (`node == -1`) and
nothing is merged on a guess. That is [iface-espnow](../iface-espnow), which has
no node-level protocol to cluster with. It is NOT iface-lora: that straddle's
own table already does the harder version of this join (announce identities,
0x03 linkages, SUPE associations all ending in one row), so it hands the row
over as the origin key rather than leaving rnsd to guess. `lora n` stays the
richer view of the same nodes — link ids, identity prefixes, SUPE budget,
derived power — none of which belongs in a shape every medium must fill.

**`( TRANSPORT )` is free.** An announce arriving through a node with `hops > 1`
travelled through it from elsewhere, which nothing but a transport node produces.
That test runs *before* the direct-peer test, since it is the one useful thing a
beyond-the-radius announce says.

**A node's lifetime is the transport's statement, not the announces'.** It exists
from the moment the interface says it is reachable and goes when the interface
withdraws it or deregisters — the only thing that can ever say a peer has left,
since nothing announces a departure. Peers age out under it on `s.rnsd.path.ttl`
(a neighbour that has not announced in a whole path lifetime is not a neighbour,
and its interface would re-learn it exactly as the directory does); the node
does not, because a silent peer is still a peer.

**No µR types.** `rnsd_peers.cpp` takes byte arrays and C strings, exactly as a
consumer would, so the tables have no opinion about the protocol engine
underneath. The seam is `rnsd_peers.h`: `rnsdNodeDeclare` and `rnsdPeersObserve`
in, `rnsdIfaceWalk` back out for the registered-interface list.

**Locking.** One mutex. Writes are on the rnsd task (inside `Transport::inbound`);
reads come from the CLI task as well. `rnsdPeersForEach` takes an ORDER under
the lock and then copies one record at a time, releasing it around every
callback: a callback is a printer or a publisher and either can block on its own
transport, and a whole-table snapshot would be near four kilobytes of stack on a
task that has a few. A slot reused between the two passes is skipped rather than
shown under the wrong heading.

**Publication** is `rnsd.nodes.*` / `rnsd.peers.*` on the housekeeping tick's
OTHER phase from `Transport::jobs()` — a neighbourhood moves at announce
intervals and has no claim to share a tick with the sweep — and only when a
generation counter says something changed. Peer indices are table order rather
than recency, so an ordinary announce dirties two keys instead of rewriting every
row; NODE indices are the table slot itself and a withdrawn node's subtree is
deleted rather than the rest compacted, because a peer names its node by that
index and compaction would move the graph's edges under a reader.

## 2. The `rnsd` task

One FreeRTOS task, **core 0, prio 1, 12 KB PSRAM stack**. It owns µR's
`Reticulum` + `Transport`, the interface table, the hosted-destination (our-dest)
ports, the announce fan-out, the link slots, and the probe responder
(`rnstransport.probe`, gated on `s.rnsd.respond_to_probes`, default on).

**Every task in the RNS ecosystem runs at prio 1** — rnsd, every interface
(`tcp`, `auto`, `espnow`, `lora`), and every client (`lxmf`, `nomad`, `rnsh`).
The ecosystem is a pipeline: an interface produces what rnsd consumes, rnsd
produces what a client consumes. FreeRTOS does not time-slice across
priorities, so a producer ranked above its consumer owns the core outright for
as long as it has work, and the consumer never runs to drain it — at which
point back-pressure feeds itself, because the fuller the consumer's link the
more work the producer has failing to fill it, and the only CPU that could
clear it is the one the producer is holding. A flat ecosystem makes the 100 Hz
tick round-robin them in 10 ms slices instead, which is the only arrangement
where that resolves. Rank is for work that should genuinely starve while the
device is busy; nothing that carries packets qualifies. The declaration lives
with the lifecycle contract in `rnsd.h`.

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
  translates; never raw-cast between them. An inbound frame may carry prefixes,
  stripped in the order they are written: the 16-byte origin key first
  (`rx_origin`, §1.3), then the 4-byte signal header (`rx_signal`). Aux ops are
  `RNSD_IFACE_AUX_ANNOUNCE` (replay onto a name prefix) and
  `RNSD_IFACE_AUX_PEER` (declare/withdraw a peer under a multi-peer interface).
- **`RNSD_PORT_DEST` (4)** — opened by `rnsdDestOpen`. Type-tagged frames both
  ways (`RNSD_DEST_*` opcodes in `ports.h`): `OUT_PACKET`/`IN_PACKET` for data,
  `OUT_RESULT` for send outcome, `OUT_STATUS` for aux progress narration,
  `ANNOUNCE` to emit an announce, `LINK_LISTEN` to register for inbound links.
- **`RNSD_PORT_ANNOUNCES` (6)** — connect with `rnsd_announces_connect_t`
  (optional dotted aspect filter). rnsd registers one internal `AnnounceHandler`
  with an empty filter at boot and fans each announce out to matching
  subscribers as one packet-mode message:
  `hops(1) | dest_hash(16) | identity_hash(16) | pubkey(64) | ratchet(32) |
  app_data(N)`.
  The public key rides along because without it a subscriber cannot cache
  anything actionable and must call back into a node-global identity map to
  send — the structural reason that map had to be large in the first place.
  The `ratchet` field is the announce's own ratchet, all-zero when the peer
  advertises none (§4.2). It is a field, never a prefix on `app_data`: rnsd
  slices the tail through `Identity::announce_ratchet()` /
  `announce_app_data_offset()` so no subscriber has to guess at a layout.
  The per-subscriber aspect filter is the announce's **carried name hash**
  matched against one compiled at subscribe time: `validate_announce` has
  already proven `dest_hash == full_hash(carried_name_hash ‖ identity)[:16]`,
  so that is exactly equivalent to re-deriving the destination hash per
  subscriber — a ten-byte compare instead of a SHA-256, which is what used to
  stall the browser transport during announce bursts.
  The `hops` byte is the **announce's own** hop count, passed to the handler
  rather than looked up: a subscriber hears every announce, but a route exists
  only for the ones this node retains, so a routing lookup would report
  `PATHFINDER_M` — "unreachable", 128 — for everything arriving on an interface
  that forwards without keeping.
  Per-slot drop-on-full (`itsSend(..,0)`) — a slow subscriber loses announces, it
  never stalls rnsd.
- **`RNSD_PORT_DIR` (12)** — aux only, no connection. One `rnsd_dir_aux_t` per
  message: assert / touch / drop a claim, or seed a public key learned off the
  network. Every directory write must happen on the rnsd task (single writer is
  what lets every other task read lock-free), and claims originate on app tasks —
  lxmf/nomad/rlpg react to a storage write on their own task — so `rnsdClaim` /
  `rnsdSeedPubkey` marshal here. Fire-and-forget: a claim is advisory, so there
  is no reply to wait for.
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

### 4.1 The announce beat

    app  → rnsd   RNSD_DEST_ANNOUNCE <app_data>      set my stored announce
    rnsd            … 60 s coalesce, then every interface
    iface→ rnsd   RNSD_IFACE_AUX_ANNOUNCE "lora/0"   air it on mine
    rnsd → iface  <announce packet>                  pinned via attached_interface

`RNSD_DEST_ANNOUNCE` **sets** an our-dest's announce (`last_announce_data` +
`want_announce`); it schedules nothing. Everything that airs one goes through
`replayOurDestAnnounces()`, which walks a bitmask of interface slots and emits
each hosted destination's stored bytes — plus the probe destination — **pinned**
to that slot's `mr_iface`. Three things arm it, all through `armDestReplay()`:

| trigger | delay | slots |
|---|---|---|
| `publishIfaceUp` — a registration | 1.5 s | the one that registered |
| `RNSD_IFACE_AUX_ANNOUNCE` — an interface's beat or button | 1.5 s | every slot whose name starts with the prefix |
| `RNSD_DEST_ANNOUNCE` — an application changed what it says | 60 s | every registered slot |

The bits accumulate and the earliest deadline wins, so a registration burst or a
scan that finds three LAN peers at once collapses into one pass.

Two separate deadlines, deliberately. `s_dest_replay_due_tick` is the urgent one
(a freshly linked peer that hears nothing hangs up in seconds — Columba's
central gives a silent link ~5 s); `s_dest_announce_due_tick` is the minute-long
application coalesce, held apart so a peer arriving mid-window still gets its own
1.5 s replay instead of dragging the whole node's sweep forward. Both are checked
on **every** wake and both pull `nextDeadline()` in — the housekeeping cadence
backs off to a minute on an idle node, which would otherwise swallow them.

**rnsd holds no interval.** How often a node says who it is is a property of the
medium, so it lives in each interface straddle (`rnsdAnnounceBeat`, ±10 % jitter)
and its own setting. Applications hold none either: `lxmf`, `rnsh` and `rlpg`
announce once at bring-up and thereafter only when what they advertise changes.
The probe destination is not special — it rides every replay rather than keeping
the private cadence it used to have.

Addressing by **name prefix** rather than by handle is what makes one call per
straddle enough: `ble` matches every per-peer registration, `tcp` matches
`tcp/<n>` and `tcp_in/<addr:port>` alike, `lora/0` matches one radio, `""`
matches the lot. A prefix nothing matches is a no-op, not an error — an
interface whose beat fires while it happens to hold no registration is a normal
state, and it will announce on its next one.

### 4.2 Ratchets

    peer  → us    announce  … random_hash · ratchet(32) · signature · app_data
                                            └ context_flag = FLAG_SET
    us    → peer  DATA      ephemeral_pub · token(ECDH(ephemeral, ratchet))
    peer            tries each retained ratchet private, then its identity key

A ratchet is an ephemeral X25519 key a destination advertises in its announces
and rotates. Senders encrypt to it instead of the destination's long-term
identity key, so traffic already sent stays unreadable when that identity key
later leaks. Links need none — their own handshake is ephemeral both ways — so
this is about **opportunistic packets** and about **store-and-forward payloads**
(`rnsdEncryptFor`), which sit on someone else's node until collected and are
therefore the exposure that matters most.

**Reading a peer's ratchet.** The ratchet is a field of the announce, never part
of `app_data`, and the context flag is what says it is there. Everything that
slices an announce tail goes through `Identity::announce_ratchet()` /
`announce_app_data_offset()` — `validate_announce` (the ratchet is inside the
signature), `recall_app_data`, and the fan-out in `Transport::inbound`. Nothing
stores a ratchet separately: `Identity::get_ratchet(dest)` reads it back out of
the retained raw announce, so a peer's ratchet has exactly the lifetime of the
announce it arrived in and shares one eviction order with routing.
`Destination::encrypt` calls it for every SINGLE OUT send, which is why it costs
an unpack rather than a cache — one per opportunistic packet, never per packet
of a transfer.

**Advertising ours.** `Destination::enable_ratchets(privs, persist)` turns it on
for a hosted destination; `announce()` rotates on
`Type::Destination::RATCHET_INTERVAL`, puts the newest public half between the
random hash and the signature, covers it in the signed data, and sets the
context flag. The flag follows the bytes, not the setting — flagging an announce
that carries no ratchet would fail its signature everywhere.

mR has no storage of its own, so rnsd holds the keys: `ourDestRatchetsLoad` /
`ourDestRatchetsPersist` keep newest-first hex at
`secrets.rnsd.ratchets.<dest_hex>`, loaded before the destination goes up so
mail already in flight to a pre-reboot ratchet still opens, and rewritten from
the persist callback on every rotation. `s.rnsd.ratchets` (default 1) gates it,
live: flipping it reaches destinations already up, and turning it off keeps the
stored privates.

**Opening what arrives.** `Identity::decrypt(token, ratchets)` trial-decrypts —
each retained ratchet private, newest first, then the identity key. There is no
selector in the token, so the retained count is the ceiling on what a junk token
costs. `Destination::decrypt` passes the destination's own set;
`rnsdDecryptSelf(identity_key, dest_hash, …)` looks the set up by destination
hash for payloads handed to us out of band (RLPG envelopes, propagation-node
blobs).

**Ratchet enforcement is deliberately absent.** Upstream can refuse packets
encrypted to the identity key; doing that here would drop mail from every sender
that has not heard a current announce, and upstream leaves it off by default
too.

`RATCHET_COUNT × RATCHET_INTERVAL` is one window read two ways — how far back a
sender's stale announce can still reach us, and how far back a seized device
gives up its traffic. See `Type.h` for the numbers and the trade.

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

### 5.3a The link's round trip is re-measured, not frozen

Every retry timer that rides a link is a multiple of `Link::rtt()`: a channel
envelope's resend deadline (§5.6), a resource's advertisement and part timeouts,
and the `max(rtt × TRAFFIC_TIMEOUT_FACTOR, …)` a `PacketReceipt` gives a proof
before calling it late. Upstream measures that round trip once, during
establishment — on a link that was, by definition, contending for the medium at
the time. On a slow interface one unlucky sample there sets the pace of
everything for the life of the link, and on a LoRa link the difference between a
0.8 s and a 2.5 s reading is the difference between a 5 s stall and a 15 s one.

`Link::rtt_sample()` therefore folds every delivered link proof's own round trip
(`PacketReceipt::_concluded_at − _sent_at`, taken where `validate_link_proof`
concludes) into a smoothed estimate at α = ¼, moving in both directions, and
re-derives the keepalive and stale intervals from it. No sample is discarded for
having been a retransmission: `Packet::resend` re-encrypts, so the resend's
packet hash is new and the proof matching it is unambiguously that
transmission's.

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
- `PROOF_TIMEOUT` (5) — no proof before the deadline (`s.rnsd.proof_timeout_s`,
  default 60, observed by polling the receipt status plus a wall-clock
  backstop). **Not a failure** — the packet may have arrived; the peer may
  simply not prove or the proof was lost.

  rnsd stamps that same window onto the µR receipt (`set_timeout`). µR's own
  default is a per-hop airtime estimate — one MTU transmission plus 6 s — which
  budgets for neither the peer's turnaround nor the CSMA backoff its proof
  waits through; if it expired first, `Transport::jobs` would cull the receipt
  from the list `Transport::inbound` validates proofs against, and a proof
  arriving after that matches nothing. One window, one owner.

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

**The envelope's payload slot is typed by the peer's protocol, not by the
shim.** Reference RNS puts whatever the remote handler returned straight into
the RESPONSE array's second element, so the type varies per path: a NomadNet
page body is a `bin`, an LXMF propagation node answers `/get` with an *array*
(transient ids, or message blobs) and refuses with a bare *int*. `MsgPack.h`'s
`unpack_blob_or_object` therefore hands the consumer a blob's bytes but any
structured element **verbatim, as its own msgpack encoding** — the inbound
mirror of `Link::request`'s `data_packed`, which splices an already-packed
object into the outbound envelope. Consumers that speak a structured protocol
parse the buffer they receive; page fetchers still get plain bytes. **Never
narrow that slot to one type**: the RESPONSE handler catches and logs decode
throws, so a mistyped payload never surfaces as a protocol error — the response
is dropped and the request times out as `REQUEST_FAILED` instead.

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
  bridge sets it to its channel slot). The window moves in `poll()` for the same
  reason: upstream opens it in its delivery callback and closes it in its
  timeout callback, and those are the two branches of the poll loop here.
- **The window is `Channel.py`'s, and the link's round trip sets its ceiling.**
  It opens by one on every delivered envelope and closes by one on every retry,
  between `_window_min` and `_window_max`. The ceiling starts at
  `WINDOW_MAX_SLOW` (5) and is raised to `WINDOW_MAX_MEDIUM` (12) or
  `WINDOW_MAX_FAST` (48) only after `FAST_RATE_THRESHOLD` consecutive
  deliveries whose `Link::rtt()` sits inside `RTT_MEDIUM` (0.75 s) or
  `RTT_FAST` (0.18 s); anything slower resets that count, so a LoRa link lives
  on the slow ceiling. The window is what a round trip can hold in flight, not
  what the sender would like to send: every envelope in it is a link packet
  waiting on its own delivery proof, and one whose proof does not come back
  stops the sender for a whole retry deadline —
  `1.5^(tries-1) × max(rtt × 2.5, 0.025) × (ring + 1.5)`, tens of seconds on a
  radio link. `Channel::poll` names each resend under `rnsd` debug.
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

## 5.7 rx-signal reports & the gateway indicator

Two related radio-signal features, both rnsd-side (the on-wire proof format
lives in µR — see §1.1).

**Gateway signal (`rnsd.gw.*`).** The received quality of the transport node
that last relayed a packet to us. Published centrally from
`onInboundPacketFilter` (registered as µR's `Transport` packet filter, so it
observes every inbound packet — data, link setup, link data, resource — with
rssi/hops already attached) for any packet addressed to one of our hosted
destinations or active links (`rnsdAddressedToUs`), plus the delivery-proof path
(`onOurDestReceiptDelivery`). A sample qualifies only when it arrived on a
signal-capable interface (rssi present) and transited ≥1 transport node. Note
`Transport::inbound` increments hops on every receive, so a **directly**-received
packet reports `hops()==1`; the gateway test is therefore `hops() > 1`, and a
direct packet feeds the per-contact/per-message signal instead, never gw.
Published as `rnsd.gw.{rssi,snr,timestamp}`; kept as the last qualifying sample.

**Per-message rx reports (the "extended proof").** So a sender can learn how
well the recipient heard it, a reticulous node appends its own rx signal and the
power it transmits at to the delivery proofs it emits for messages that reached
it **direct** (`hops ≤ 1`) on radio — `Packet::prove_report` /
`Identity::prove(report_signal=true)`. The trailer is five bytes, big-endian:

```
int16 rssi dBm | int16 snr×10 | int8 txpwr dBm
```

The last byte is the prover's own antenna transmit power, `INT8_MIN` when its
receiving interface has no such notion. It is what turns the reported rssi from
a number into a path loss: the reader already knows what *it* transmitted at, so
`our txpwr − their rssi` and `their txpwr − our rssi` are the two directions of
the same link. rnsd feeds the figure to mR at interface registration
(`rnsd_iface_t.tx_power_known/tx_power_dbm` → `Interface::tx_power_dbm`); the
LoRa straddle states its configured `tx_power` there, not its adaptive per-peer
power, because this is a readout for the operator and not a term in any loop.

The receiver decodes the trailer off the proof into
`PacketReceipt::remote_rssi/remote_snr/remote_txp`, and stamps
`PacketReceipt::local_txp` from the interface the proof arrived on — the radio
the proven packet went out by, so each side's power sits beside the other side's
rssi. rnsd forwards all of it on the DELIVERED `OUT_RESULT` signal trailer
(`local rssi|snr | remote rssi|snr | local_txp | remote_txp`, fixed width), keyed
by send_id, for lxmf to attach to the outbound message or to a Ping.

*Interop.* The append lengthens the proof, which a **vanilla** RNS node
length-rejects (losing its delivered-tick). So `proveInboundWithReport` emits the
extended proof **only to a peer known to accept it** — one that advertised the
rx-report capability (LXMF announce caps bit1). lxmf parses that bit and pushes
it to rnsd via `rnsdSetRxReportCap(dest_hash, capable)`; rnsd keeps it in
`s_peer_caps` (keyed by the peer's lxmf.delivery hash; RAM-only, reboot-reset)
and `proveInboundWithReport` reads it back through `rnsdGetRxReportCap` /
`peerAcceptsRxReport` when it proves an inbound direct radio packet. Reception is
unconditional — we accept a report from anyone. The table
tracks lxmf **contacts**, not every announcer: lxmf preloads it from stored
contacts at boot and updates it on contact creation (including the first message
from a new peer) and on each re-announce — so the set stays bounded and matches
who you actually correspond with. Any other peer — unknown, or advertising no such capability — gets
a plain proof, so a vanilla node never sees a lone extended one. There is no
probing (we never send a speculative extended-then-plain pair): capability comes
from the announce, not from trial. Receiving an rx report is unconditional — we
accept and process one from anyone; the capability gates only what we emit.

The gateway's *own* remote half (the transport node's rx of us) has no source
yet — the rx report is endpoint-direct-only — so the gw indicator is single-set
until a transit-node report mechanism is added.

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

### 6.1 Ecosystem lifecycle (`rns start`/`rns stop`) and what quiesce leaves behind

The whole RNS ecosystem — rnsd plus every interface and client (iface-lora/tcp/
auto/espnow, lxmf, nomad, rlpg, rnsh) — starts and stops as a unit, orchestrated
in one place (`rnsServiceRegister` / `rnsStart` / `rnsStop`, `rnsd.cpp`). A
component registers a start/stop hook pair from its `onInit()` instead of
self-spawning a task that waits on `rns.ready`; the rnsd task, once past the boot
window, calls `rnsStart()` which walks the hooks in registration order (deps
first). `rns stop` walks them in reverse (dependents first) and publishes
`rnsd.up = 0`, the observable up/down signal.

**Stop PARKS the task; it does not delete it.** A stop hook sets an `s_stop` flag
and notifies the task; the task breaks its work loop, tears down its *dynamic*
state (RF off, sockets closed, and — critically — **`itsDisconnect`s every rnsd
connection it holds**: our-dest, announce subs, links), then blocks on
`itsPoll(portMAX_DELAY)` until `rnsStart()` clears `s_stop` and notifies it to
re-bring-up. The task, its ITS slot, its inbox and its boost lock are **reused,
not freed** — because ITS task slots are append-only ("never freed, just inert")
and its task-death hook does **not** reap a dying task's live connections (see
its.cpp — the design assumes immortal tasks). Deleting a client task each stop
therefore leaked ~23 KB of ITS state per cycle and stranded rnsd server-port
slots (an `RNSD_PORT_ANNOUNCES` exhaustion that made rnsd reject reconnects) —
strictly worse than the ~8 KB of stack it reclaimed. Parking sidesteps all of it
and matches the platform's immortal-task model (`service.h`).

**What a stop actually reclaims.** The client's *dynamic* heap — radio
objects/sockets/page-caches that a bring-up reallocates — plus RF and routing:
each client's teardown disconnects its `RNSD_PORT_IFACE` handle, firing
`onTransportDisconnect` → `Transport::deregister_interface`, so Transport is left
with no interfaces to route over. The task stack (bounded, ~6–12 KB) and
`PSRAM_BSS` working state (lxmf's `s_ids`, etc.) stay resident by design — the
task is alive, just parked.

**The disconnect is load-bearing.** rnsd frees an announce-sub / our-dest server
slot only when `onAnnouncesDisconnect` / the our-dest disconnect fires, which
happens when the client `itsDisconnect`s the connection. A parked client MUST
disconnect its rnsd handles in teardown (not merely null them), or the slots leak
across cycles until the port is exhausted.

**What is deliberately NOT reclaimed — the residual.** microReticulum's
`Transport` is a **construct-once, process-lifetime singleton with no teardown**,
so a stop can only *quiesce*, never destruct:

- `Transport`'s state is all static class members — `_interfaces`, `_path_table`,
  `_link_table`/`_pending_links`, `_destinations`, `_control_destinations`,
  `_packet_hashlist`, `_identity`, and the static `_owner` `Reticulum`. There is
  **no `Transport::stop`/`deinit`/`reset`**; `detach_interfaces()` and
  `shared_connection_disappeared()` are commented-out no-op stubs; `exit_handler()`
  only persists the on-disk cache. These tables stay resident and bounded across a
  stop — the path/link/hashlist working set is not returned to the heap.
- `Transport::start()` is **not idempotent** (`// CBA ACCUMULATES` on the control-
  destination inserts), so it must **never** be called a second time. rnsd's own
  task, its `s_identity`/`s_reticulum`, and the five PSRAM tables (`s_ifaces`,
  `s_our_dests`, `s_link_conns`, `s_our_dest_receipts`, `s_chan_conns`) are
  therefore **kept alive** across a stop — rnsd idles rather than exits. The tables
  can't be freed anyway: `s_our_dests` holds `Destination` objects registered into
  `Transport::_destinations`, which has no removal API, so freeing them would leave
  Transport dereferencing freed memory.

So `rns stop` gives you a node that has genuinely left the mesh (no interfaces, no
TX, client tasks gone, their stacks back), and `rns start` re-attaches to the
**same** already-initialized Transport (it does not, and must not, re-`start()`
it). Fully reclaiming rnsd's core + the Transport tables would require adding a
real `Transport::deinit()` (clear every static table, a `_destinations` removal
path) and making `start()` idempotent — surgery inside vendored microReticulum,
deliberately not attempted here.

## 7. Persistence

Storage is the source of truth for the durable layer; the `rnsd.*` runtime tree
is an ephemeral 1 Hz mirror of live state. µR's own `OS::read_file/write_file`
stay no-ops: what rnsd knows about other destinations — identities, routes,
retained announces, compiled claims — persists as the directory image at
`<state>/rnsd/dir.img`, written by spangap-core's persist worker on a debounce
(§1.1.2), never through µR's filesystem shim. The hashlist and the
retransmission queue are not persisted; `rnsd persist` remains a no-op stub for
them. The default identity is `secrets.rnsd.identity`; rnsd does **not**
auto-create an application identity at boot — that is the app's call.

**The image is the live set, budgeted against the partition — not the arena.**
Three rules hold it there, and each exists because breaking it broke a board:

- **Only live records are written**, packed, counts in the header. Writing the
  arena verbatim (holes included) made the file the size of the *budget*, so a
  node that knew twelve destinations still wrote 96 KB.
- **Records go out in eviction order**, most valuable first (`dirCategory` /
  `dirOrder` — the same judgement that decides what to drop under memory
  pressure), so `rdirSnapshot`'s `cap` is a byte budget rather than a failure
  condition. Blobs follow *all* the directory records, so a tight cap gives up
  answering path requests before it gives up knowing who anyone is.
- **The cap comes from `/state`**, an eighth of it by default
  (`s.rnsd.dir.img_max_kb`). The arena budget derives from free PSRAM, and
  PSRAM says nothing about the flash the image lands in: a T3-S3 has 2 MB of
  PSRAM and a 256 KB state partition, sized itself a 96 KB arena, and could
  then never write it — `atomicWriteFile` needs the new copy and the old one
  resident at once, which is 192 KB of a 64-block filesystem. Every write
  failed with `No more free space`, forever.

The guard depth is **never** persisted, and this is a trade, not a free win.
Its replay check is the fingerprint ring plus `emitted` — both absolute, so a
reloaded guard pool *would* suppress announces we forwarded before the reboot.
What it would not do is matter: the pool is 664 slots at the 96 KiB budget, and
a node bridged to a large network hears orders of magnitude more distinct
destinations than that, so it evicts continuously and suppression tends to zero
whether or not it survives a boot. Against that, only its eviction ordering is
salvageable — `local_age` is in uptime minutes (`rnsdDirLocalMinutes`), which
restarts at boot, so a persisted record computes an age of
`(uint16_t)(now - local_age)` ≈ 45 days and sorts oldest — and it would need a
load-time reset to fix. On a small mesh, where suppression would work, the pool
refills within one announce interval. So it stays out of the image, and the
cost is one duplicate forward per destination after a reboot — the same reason
guard churn does not bump `rdirGeneration`.

An image whose `format_ver` differs is discarded whole — it is a cache, and a
node that discards one re-learns by path request at the cost of a round trip
per destination.

## 8. Maintainer pitfalls

- **Run Transport-touching code on the rnsd task.** `request_path`, link
  construction, destination registration off-task silently no-op (the outbound
  packet is dropped). Defer via ITS or a `rnsd.cmd.*` sentinel.
- **One name, one interface.** `Transport::_interfaces` is keyed on
  `Interface::get_hash()`, a hash of the interface's *name* alone, and its
  insert keeps the entry already present. A second interface registering under
  a name already in the table would therefore be accepted by its straddle,
  appear in `rnstatus`, receive inbound packets — and never transmit, because
  Transport still holds the first one. `onTransportConnect` refuses a duplicate
  name outright, and Transport warns if one reaches it anyway.
- **Large tables go in PSRAM, FreeRTOS sync objects do not.** Internal
  DRAM/DMA is scarce on the T-Deck, so ITS metadata, the directory arena, and recv
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
- **Routes are bounded by the directory pool; the snapshot publisher is
  disabled.** The pool's slot count is the hard bound (§1.1.2); `s.rnsd.path.max`
  is a softer target enforced on top of it by `cull_path_table()` at the
  announce-insert site, and a record ages out at `s.rnsd.path.ttl`
  (`Transport::destination_timeout`) — both wired via `NOW_AND_ON_CHANGE`.
  Separately, `publishPathTable()` (which mirrored the table to `rnsd.paths` for
  the browser Nodes window) is `#if 0`'d: O(N)-snapshotting every tick tripped
  the task watchdog *inside* it under churn, even with its 64-row cap and a
  `vTaskDelay(1)` every 8 entries. So **`rnsd.paths` is not published today**;
  the `rnsd.dir.` storage provider is the paged read path, and re-enabling a
  whole-table mirror needs a bounded/yielded walk and ideally storage→SD. Don't
  re-enable it blind.
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
- **No remote-management endpoint.** Upstream rnsd hosts
  `rnstransport.remote.management` so `rnstatus -R` / `rnpath -R` can query a node
  remotely; we don't. Servicing it needs a `register_request_handler` port plus a
  reply shaped as upstream's inline `[stats-dict, link_count]` (µR's
  `Link::handle_request` returns one opaque `bin`). Until then we don't announce
  the aspect at all, rather than advertising an endpoint that drops every request.

## 9. Browser UI

The shared RNS UI lives in this straddle: `modules/rnsd.ts` (Pinia store +
`rnsd:1` DataChannel exposing the directory, identity, and announces),
`panels/NodesWindow.vue` (live nodes) and `panels/MapWindow.vue` (map of
GPS-announcing peers). The rows on the Settings → Reticulum Mesh page itself
are generated from the `settings:` block in [`straddle.yaml`](straddle.yaml), so
there is no hand-written pane. Interface-specific UI is **not** here — each interface
straddle contributes its own settings block.

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
3. version byte `||` msgpack `||` trailing 32-byte ratchet → `v=XX mp=… ratchet=…`
4. none of the above → printable-bytes fallback `="…"`

Shape 3's trailing ratchet is one client's app_data dialect. The announce's own
ratchet is a separate field ahead of the signature (§4.2), logged on its own —
it never appears in app_data, so no shape here looks for one in front.

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

**In-tree peer scripts.** `hw-lilygo-tdeck/tests/peers/echo_peer.py` (+
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
path requests resolve fast. `hw-lilygo-tdeck/scripts/lxmf-stamp-test` is the worked
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
- **`recall()` succeeding still ≠ `has_path()` true.** Identity and route are
  now fields of the same record, so they are acquired and evicted together — but
  a route also expires on its own TTL and is dropped when its interface stops
  resolving, both of which leave the identity behind. Gate any outbound
  link/channel establishment on `has_path() && recall()` and re-`request_path()`
  while waiting — otherwise the link request has no next hop and is silently
  dropped, surfacing only as an `establish_timeout`. This is exactly why the
  device side gates §5.6 the same way.
- **`spangap cli "<cmd>"` is transient-flaky.** Occasional SSH banner timeout /
  "closed by remote host"; retry 2–3×. It also forwards piped stdin into a nested
  interactive command as long as stdin stays open, which is a feature — e.g.
  `( sleep 9; printf 'x\r'; sleep 10 ) | spangap cli "rnsh <dest>"` drives an
  interactive `rnsh` session over the loopback CLI.
