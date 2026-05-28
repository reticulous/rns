# reticulous-core — internals

## The `rnsd` task

One FreeRTOS task on **core 0, prio 2, 12 KB PSRAM stack**. Owns:

- mR's `Reticulum` + `Transport`.
- The interface table (every transport registers here).
- The bidirectional mailbox port (`RNSD_PORT_DEST` — destination
  packets).
- The announce fan-out port (subscribers receive announces filtered
  by app-name + aspects).
- The management destination (`rnstransport.remote.management`).
- The optional probe responder (`rnstransport.probe`, PROVE_ALL,
  gated on `s.rnsd.respond_to_probes`).

**Zero networking/radio dependencies.** Transports talk to it over ITS:

- `RNSD_PORT_REGISTER` — a transport announces itself at startup.
- `RNSD_PORT_TRANSPORT` — packet-mode bidirectional bridge between a
  transport task and rnsd.

## The mR fork — what we changed

Vendored fork of [`attermann/microReticulum`](https://github.com/attermann/microReticulum)
at a pinned commit (see
[components/microreticulum/README.md](esp-idf/components/microreticulum/README.md)).
Our deltas:

- **Crypto rewritten** against mbedTLS plus a software Curve25519 (the
  same X25519 implementation shared with [wg](../../s/wg)).
- **cJSON + msgpack-c** instead of ArduinoJson + MsgPack.
- **spangap logging macros** (`info()` / `warn()` / `dbg()`) instead of
  `Serial.print*`.
- **No-op file I/O** — we own persistence end-to-end via the `rnsd`
  CLI/cron path, so mR's `OS::read_file` / `OS::write_file` are
  no-ops.
- **Event-driven**, no top-level `Reticulum::loop()`.

Patches carried in the fork against upstream behaviour:

- `Transport.cpp`: **RAII guard for `_jobs_locked`** — every early
  return from `Transport::inbound` releases the lock. Upstream leaks it
  on malformed-packet / cache-request / link-MTU-clamp exits,
  permanently disabling `Transport::jobs()`.
- `Transport.cpp`: a requested `PATH_RESPONSE` **bypasses the
  `random_blob` replay guard** in announce ingest. Relays answer from
  a cached announce, so a re-requested path always carries a seen
  blob; upstream escapes via `path_is_unresponsive` (not ported) — we
  key on an outstanding `_path_requests` entry instead. Without this,
  path discovery works exactly once then goes silent.
- `Identity.cpp` + `.h`: **`static std::recursive_mutex
  _known_destinations_mux`** taken by every accessor (`remember` /
  `recall` / `recall_app_data` / `validate_announce` /
  `cull_known_destinations` / save+load). Enables safe cross-task
  `Identity::recall` via rnsd's `rnsdRecallPubkey`.
- `Packet.cpp`: malformed-packet error path now dumps the first ≤ 8
  bytes hex, so we can tell HEADER_1 vs HEADER_2 mis-parse, HDLC
  desync, noise byte, etc.

## Conventions reticulous adds on top of spangap

- **Transports own their own lifecycle.** Each transport task watches
  `s.<name>.enable`, comes up on its own, and registers with rnsd via
  `RNSD_PORT_REGISTER`. Adding a transport = a new task; no rnsd code
  changes.
- **Single wait point per task.** `itsPoll(nextDeadline())` is the
  only blocking call — wakes on ITS messages, task notifications
  (radio ISR, lwIP recv callback), or computed deadlines. Idle CPU
  = 0. No `while (itsPoll(0)) {}` polling drains.
- **rnsd is pure protocol.** No `lwip/`, no RadioLib, no socket
  primitives. It only sees RNS packets via ITS streams.
- **Storage as SoT for the durable layer**, ephemeral 1 Hz mirror for
  live state. Cron-driven `rnsd persist if-transport`. mR's own
  `OS::read_file/write_file` are no-op'd.
- **No TLS for transports** — RNS doesn't have it. IFAC is the per-
  interface access-control primitive (PSK + per-packet HMAC).

## CLI surface

- `rnsd` — top-level subcommands: `up`, `down`, `status`, `persist
  if-transport`, `clink` (open a Link for testing).
- `rnstatus` — interfaces + path-table summary.
- `rnpath <destination>` — query path table / request path.
- `rnprobe <destination>` — send a probe packet.

## Vendored sub-components

```
esp-idf/components/
├── microreticulum/  the fork. README in that dir covers the pinned commit + layout.
└── bzip2/           bzip2 1.0.8 — used by µR's Resource compression path.
```

The consuming app-straddle picks these up via the
`staging/components/*/components/` glob in its top-level
`CMakeLists.txt`.

## Browser shared RNS UI

- `modules/rnsd.ts` — Pinia store + WebRTC DataChannel `rnsd:1`,
  exposes path table, identity state, announces.
- `panels/RnsdPanel.vue` — Settings → Reticulum.
- `panels/NodesWindow.vue` — Status → Reticulum: live nodes seen.
- `panels/MapWindow.vue` — Status → Map (where GPS-equipped peers
  appear if announced).

Transport-specific UI is **not** here — each transport straddle
contributes its own panel under `Settings → Transports → {TCP, ESPnow,
LoRa, AutoInterface}`.

## Authoritative plan

The single source of truth for codebase choice, dependencies, task
layout, ITS surface, storage conventions, and phased rollout lives in
the consuming app straddle: see
[`reticulous-tdeck/docs/component-plan.md`](../reticulous-tdeck/docs/component-plan.md).
That document is more current than any of the planning sketches in
`docs/plans/` — where they disagree, the component-plan wins.
