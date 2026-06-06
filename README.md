# rns

## What is this?

**rns** is the Reticulum (RNS) protocol core for the
[spangap](https://github.com/spangap/spangap) platform: identity,
destinations, the path table, the transport state machine, Links, and
Resources. It is the protocol brain; transport straddles
([tcp](../iface-tcp), [auto](../iface-auto),
[lora](../iface-lora), [espnow](../iface-espnow)) plug their
interfaces in via the `RNSD_PORT_TRANSPORT` ITS surface — rns
itself has **zero** networking / radio dependencies.

[Reticulum](https://reticulum.network) is Mark Qvist's cryptography-
based networking stack for building resilient, self-configuring
networks over anything that can carry packets — LoRa, packet radio,
plain TCP/IP, even a serial wire. There is no central authority and no
assigned addresses: every node is a self-generated cryptographic
identity, links are end-to-end encrypted by default, and the network
keeps routing over cheap, low-bandwidth, intermittently-connected links
where conventional stacks fall over.

## What this straddle owns

```
rns/
├── esp-idf/
│   ├── include/
│   │   ├── rnsd.h        public API (rnsdLinkOpen, rnsdRecallPubkey, …)
│   │   └── ports.h       ITS port constants + DEST opcodes shared with transports
│   ├── src/rnsd.cpp      the rnsd task: identity, Transport, iface table
│   └── components/
│       ├── microreticulum/    vendored fork of attermann/microReticulum
│       └── bzip2/             vendored bzip2 1.0.8
└── browser/
    └── src/
        ├── modules/rnsd.ts          self-registering pinia module + RPC
        ├── panels/RnsdPanel.vue     Reticulum Settings panel
        ├── panels/NodesWindow.vue   live announce / path-table viewer
        └── panels/MapWindow.vue     status floating windows
```

Nested sub-components (`components/microreticulum/`, `components/bzip2/`)
are picked up by consuming buildable straddles through the
`staging/components/*/components/` glob in their top-level
`CMakeLists.txt`.

## How others use it

### Firmware

In your app's `app_main()` after the spangap inits:

```cpp
rnsdInit();
```

`rnsdInit` brings up identity, the mR `Reticulum` + `Transport`, the
iface table, and the announce fan-out. Transports register themselves
via `RNSD_PORT_REGISTER` and `RNSD_PORT_TRANSPORT` — `rnsd` has zero
compile-time knowledge of which transports exist.

### Client API

`rnsd.h` exposes two API halves:

1. **Byte-array primitives** — `sha256`, `sign`, `verify`,
   `destination_hash`, `identity_ops`, `recall`, `request_path`.
   These encapsulate every mR primitive a downstream task needs.
2. **Typed connection-openers** — `rnsdDestOpen()` for destinations,
   `rnsdLinkOpen()` / `rnsdDestListenLinks()` for Links,
   `rnsdLinkRequest()` for request/response Resources.

**Downstream tasks operate on raw byte arrays and storage sentinels;
they never include `RNS::Identity` or other mR types.** That isolation
is what makes [lxmf](../lxmf) and
[nomad](../nomad) testable without dragging mR
into their dep graphs.

### Browser

The shared RNS UI lives in this straddle: the Reticulum Settings panel,
the Nodes window, the Announces window, RNS Pinia state. Transport-
specific UI lives in each transport straddle's `browser/`.

## Dependencies

- [spangap-core](../../s/spangap-core) — base runtime (ITS, storage,
  log, CLI, fs, cron).
- (no networking or radio dep at compile time)

## What it does NOT own

- WiFi / TCP / UDP / LoRa / ESP-NOW — those are transport straddles
  in their own right.
- LXMF messaging — that's [lxmf](../lxmf).
- Nomad pages — that's [nomad](../nomad).
- The app's identity policy — `rnsd` doesn't auto-create an identity
  at boot; that's the app's call.

## Read next

- [INTERNALS.md](INTERNALS.md) — task layout, mR fork patches, storage
  layer, persistence cadence, CLI surface.
- [esp-idf/components/microreticulum/README.md](esp-idf/components/microreticulum/README.md)
  — vendored fork notes: pinned commit, why this commit, donna
  cryptography.
- The hw-tdeck [README](../hw-tdeck/README.md) for the
  bigger picture (this protocol core is only useful inside an app
  straddle).

## Status

Hardware-verified against upstream Reticulum/LXMF. `rnsd` is the large
module here and is real, not scaffolding. The fork is ported and
patched against the pinned µR commit; see
[esp-idf/components/microreticulum/README.md](esp-idf/components/microreticulum/README.md).
