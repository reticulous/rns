# microreticulum (vendored fork)

ESP-IDF managed component holding our Apache-2.0 fork of
[`attermann/microReticulum`](https://github.com/attermann/microReticulum),
pinned at upstream commit `5642ae7fe17de6a8be9dc4891e95cf8a47c6ebe9`
("Restored fallback heap-based path storage", 2026-05-09 — one commit
past tag `0.3.1`).

Authoritative architecture and rollout: [`../../docs/component-plan.md`](../../docs/component-plan.md).

## Why this commit (not the `0.3.1` tag)

Tag `0.3.1` (commit `65e3a77`) hardcoded the path store to
`microStore::BasicFileStore`. The very next day `5642ae7` added an
`#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)` guard so that
without those flags the path store falls back to
`microStore::BasicHeapStore`. We deliberately do NOT define those
flags (we own persistence end-to-end via the `rnsd` CLI/cron path —
plan §10.5), so the heap-store fallback is essential. The 0.3.1 tag
itself would not build correctly for our configuration.

## Vendored layout

```
components/microreticulum/
├── idf_component.yml           # deps: idf, diptych-core
├── CMakeLists.txt              # SRCS list grows as µR files are ported
├── LICENSE.upstream            # Apache-2.0, attermann/microReticulum
├── LICENSE.microstore          # Apache-2.0, attermann/microStore
├── include/microStore/         # microStore headers (vendored alongside)
└── src/
    ├── donna/                  # Foreign crypto primitives, fully wired:
    │   ├── ed25519*, modm-, curve25519-, ed25519-donna-*  (public domain,
    │   │                       Andrew M. <liquidsun@gmail.com>) — Ed25519
    │   │                       sign/verify and key derivation.
    │   ├── ed25519-hash-custom.h        — SHA-512 via mbedTLS
    │   ├── ed25519-randombytes-custom.h — RNG via esp_fill_random
    │   ├── x25519.{c,h}        # MIT, Mike Hamburg / Cryptography Research,
    │   │                       # re-vendored from diptych-core's
    │   │                       # esp_wireguard tree — X25519 ECDH.
    │   └── x25519-license.txt  # MIT attribution for x25519.c
    ├── Cryptography/           # AES, CBC, HKDF, HMAC, Hashes, Ed25519, X25519,
    │                           # Fernet, PKCS7, Random, Token — TODO: wrappers
    │                           # need to call into donna/ + mbedTLS.
    ├── Persistence/            # DestinationEntry — TODO: ArduinoJson swap
    └── Utilities/              # OS, Memory, Crc, Persistence, tlsf
```

`microStore` is vendored under `include/microStore/` rather than declared as
an external dep — it's a tiny header-only sibling library by the same
author, and nothing else in our tree needs it. The Arduino-only adapters
(`FlashFS`, `InternalFS`, `LittleFS`, `SPIFFS`, `SD`) were dropped; the
`Noop`, `Posix`, `Stdio`, and `Universal` adapters remain (all guarded by
`USTORE_USE_*` defines we don't set).

`src/donna/` builds cleanly today as part of the component — see the
compile-time defines (`ED25519_CUSTOMHASH`, `ED25519_CUSTOMRANDOM`,
`ED25519_FORCE_32BIT`, `ED25519_NO_INLINE_ASM`) in [CMakeLists.txt](CMakeLists.txt)
and the warning suppression for the donna sources (the per-source
`-Wno-stringop-overread` is needed for a GCC false positive in
`x25519.c:218` — `mul()` is called with a properly-sized buffer that GCC
fails to track through the inlining).

## Phase 0 — what's done

- ☑ Source vendored at the pinned commit, with `.git` stripped.
- ☑ microStore headers vendored under `include/microStore/`.
- ☑ `idf_component.yml` declares the dep tree (`mbedtls` + `esp_hw_support`
  + `json` + `diptych-core` pulled via `REQUIRES` in `CMakeLists.txt`).
- ☑ `src/Log.cpp` rerouted: `Serial.print*` / `printf` removed; all µR log
  calls now go through diptych's `info()`/`warn()`/`err()`/`dbg()`/`verb()`
  macros (mapping in the file). `getTimeString()` is stubbed — diptych
  prepends its own timestamp.
- ☑ `src/Utilities/OS.h` file-I/O methods no-op'd per plan §10.5
  (`read_file`/`write_file`/`open_file`/etc. all return empty / `false` /
  `0`). `register_filesystem()` left functional in case anything wants to
  attach a real backing store later.
- ☑ Foreign crypto primitives vendored under `src/donna/`:
  - **ed25519-donna** (Andrew M., public domain) for Ed25519 sign/verify
    and key derivation, with custom hooks for SHA-512 (mbedTLS) and RNG
    (esp_fill_random). Compiled with `ED25519_CUSTOMHASH`,
    `ED25519_CUSTOMRANDOM`, `ED25519_FORCE_32BIT`, `ED25519_NO_INLINE_ASM`.
  - **x25519.c** (Mike Hamburg / strobe, MIT) for X25519 ECDH —
    re-vendored rather than depending on diptych-core's `PRIV_INCLUDE`'d
    copy, so we don't need diptych-core to export internal symbols.
  - Both compile clean with no warnings; objects pack into
    `libmicroreticulum.a`. The wrapper rewrite in `src/Cryptography/X25519.cpp`
    + `Ed25519.cpp` will call into these directly.

## Phase 0 — what's NOT done yet

The component compiles as an empty library — `MICRORET_SRCS` in
[CMakeLists.txt](CMakeLists.txt) is empty. Each upstream `.cpp` gets added
to the list as its dependencies are ported. The remaining work is the bulk
of Phase 0:

1. **Crypto rewrite (`src/Cryptography/`).** Upstream's `<AES.h>`,
   `<SHA256.h>`, `<SHA512.h>`, `<Hash.h>`, `<HKDF.h>`, `<Curve25519.h>`,
   `<Ed25519.h>` come from `attermann/Crypto` (a fork of `rweather/Crypto`).
   The wrappers in `src/Cryptography/` need their bodies rewritten against:
   - **mbedTLS** — AES-CBC, HMAC, HKDF, SHA-256/512, Fernet primitives,
     RNG (`mbedtls_ctr_drbg` or `esp_fill_random`). All already linked.
   - **`donna/x25519.h`** — `x25519(out, scalar, point, /*clamp=*/1)` for
     `RNS::Cryptography::X25519PrivateKey::exchange`. Use `x25519_base()`
     for public-key derivation.
   - **`donna/ed25519.h`** — `ed25519_publickey`, `ed25519_sign`,
     `ed25519_sign_open` for `RNS::Cryptography::Ed25519*` wrappers.
   The `RNS::Cryptography::*` wrapper class signatures stay; only the
   bodies change. Bench numbers required (plan §19): X25519 scalar mult,
   Ed25519 sign/verify on the T-Deck S3.

2. **`ArduinoJson → cJSON`.** `ArduinoJson.h` is included by `Bytes.h`,
   `Interface.h`, `Packet.h`, `Utilities/Persistence.h`, and used as a
   serialization backbone in `Packet.cpp`, `Interface.cpp`,
   `Utilities/Persistence.cpp`, with type-conversion specializations in
   the headers. cJSON ships as ESP-IDF's `json` component (already in
   `REQUIRES`); the call sites need source-level rewrites.

3. **`MsgPack → msgpack-c`.** `<MsgPack.h>` (Arduino lib) is used heavily
   in `Link.cpp` for `Packer`/`Unpacker`/`bin_t<uint8_t>` around request
   IDs, request data, response data. msgpack-c needs to be added as a
   managed dep (or vendored); `Link.cpp` rewritten.

4. **Strip remaining `#ifdef ARDUINO` branches** from `Reticulum.cpp`,
   `Packet.cpp`, `Interface.cpp/h`, `Bytes.h`, `Packet.h`, `Log.h`,
   `Memory.cpp`, `OS.h`, `Persistence.h`. None of those branches activate
   without `ARDUINO` defined, so they're inert — but cleaning them up
   reduces surprise during ports.

5. **Wire up `microreticulum` to `main/`.** Currently `main/CMakeLists.txt`
   only requires `diptych-core`; once at least one µR header is consumed
   by `rnsd.cpp`, add `microreticulum` to the REQUIRES list there.

## Resolved design issues

### A. Ed25519 source — RESOLVED (2026-05-10)

esp_wireguard ships only X25519, not Ed25519 (the plan §3 description was
inaccurate — WG doesn't use Ed25519 at all). **Decision: vendor
`floodyberry/ed25519-donna`** under `src/donna/` with custom hooks for
SHA-512 (mbedTLS) and RNG (`esp_fill_random`). Public domain, ref10
lineage, ~10 KB compiled, no platform deps. The wrapper rewrite in
`src/Cryptography/Ed25519.cpp` calls into `ed25519_publickey` / `ed25519_sign`
/ `ed25519_sign_open` directly.

Forward note for the plan: the doc string in [`docs/component-plan.md`](../../docs/component-plan.md)
§3 ("esp_wireguard's Curve25519 (X25519 ECDH, Ed25519 sign/verify)")
should be updated to reflect "ed25519-donna for Ed25519 sign/verify,
re-vendored x25519.c (Mike Hamburg / strobe, MIT) for X25519 ECDH —
both under `src/donna/`."

### B. esp_wireguard symbol export — RESOLVED (2026-05-10)

`esp_wireguard` lives under `PRIV_INCLUDE_DIRS` in diptych-core, so its
X25519 symbols aren't reachable from this component. **Decision: re-vendor
`x25519.c` + `x25519.h`** under `src/donna/` directly. Pragmatic choice
that decouples us from diptych-core's internal layout — a single ~500 LOC
MIT-licensed file with attribution preserved in `src/donna/x25519-license.txt`.

## Open design issues

### D. µR's `Log.h` collides with diptych's `log.h` on case-insensitive filesystems

`src/Log.cpp` works around this by inlining `ESP_LOGx(pcTaskGetName(NULL), ...)`
calls instead of `#include`ing diptych's `log.h` for the err/warn/info/dbg/
verb macros — the component's INCLUDE_DIRS puts `src/` on the compiler's
`-I` list, and on macOS APFS the search resolves `log.h` to the sibling
`Log.h` (µR's own header) regardless of `""` vs `<>` quoting.

The clean fix is to rename µR's `Log.h` (and the per-file `#include "Log.h"`
references — currently 30+ files) to something unique like `RnsLog.h`.
Once renamed, `src/Log.cpp` can switch back to a normal `#include <log.h>`
and the inlined expansion comes out. Tracked here so we don't lose the
context: it's a low-risk rename but cascades enough that it's worth
batching with another session that touches the µR sources.

### C. MsgPack — RESOLVED (2026-05-10): hand-roll when needed

`Link.cpp` is the only file in the µR tree that uses MsgPack
(MessagePack — a binary JSON-shaped serialization format; see
[msgpack.org](https://msgpack.org)). Upstream pulls in `<MsgPack.h>`
from `hideakitai/MsgPack` (Arduino lib, not portable to ESP-IDF).

**Decision: hand-roll a small `src/MsgPack.h` shim when the Link
subsystem actually lands**, rather than vendor `msgpack-c` (~200 KB
library) speculatively. The Link.cpp call surface is tiny and bounded:

| Site | API used |
|---|---|
| RTT advertise/parse ([Link.cpp:381](src/Link.cpp), [:525](src/Link.cpp)) | `Packer.serialize(double)` / `Unpacker.deserialize(double&)` |
| Request frame ([Link.cpp:463](src/Link.cpp), [:945](src/Link.cpp), [:1102](src/Link.cpp)) | `Packer.to_array(double, bin_t<uint8_t>, bin_t<uint8_t>)` / `Unpacker.from_array(...)` |
| Response frame ([Link.cpp:881](src/Link.cpp), [:976](src/Link.cpp), [:1135](src/Link.cpp)) | `Packer.to_array(bin_t<uint8_t>, bin_t<uint8_t>)` / `Unpacker.from_array(...)` |

Wire format is trivial:
- `double` → `0xCB` + 8 bytes (big-endian IEEE 754)
- `bin8/16/32` → `0xC4–0xC6` + length + raw bytes
- fixarray-N (N<16) → `0x90 | N` + N values

Estimated ~80 LOC of header-only C++. Link.cpp's `#include <MsgPack.h>`
would resolve to our shim via the `src/` include path, no upstream
patches needed. `bin_t<uint8_t>` becomes a thin wrapper convertible
to/from `RNS::Bytes`.

**Why deferred:** plan §1 says "No Link / Resource / propagation-node
support in v1". Phase 1 (rnsd + TCP outbound) and Phase 4 (LXMF) both
use opportunistic SINGLE packets, never Links. Link/Resource/Channel/
Buffer ship "eventually" (plan §3) — write the shim then. Until then,
`Link.cpp` stays out of `MICRORET_SRCS` (commented-out line in
[CMakeLists.txt](CMakeLists.txt)).

## Build expectations

With `MICRORET_SRCS` empty, `idf.py build` succeeds — the component is
registered (so its include path becomes available to consumers via
`REQUIRES microreticulum`), but produces no object files. Phase 0's
"task stubs start and log 'task up'" is satisfied: the existing stubs in
[`../../main/`](../../main/) compile and run as before.

As each upstream `.cpp` is ported, add it to `MICRORET_SRCS` and rebuild.
Build failures will surface the next dep to swap.
