# NOTICE — microReticulum (Reticulous fork)

This `microreticulum/` component is a fork of:

> **microReticulum** — © 2023 Chad Attermann
> Source: <https://github.com/attermann/microReticulum>
> License: Apache License, Version 2.0 (see `LICENSE.upstream`)

The fork is pinned at upstream commit
`5642ae7fe17de6a8be9dc4891e95cf8a47c6ebe9` ("Restored fallback heap-based
path storage", 2026-05-09 — one commit past tag `0.3.1`). The `microStore`
sibling library (also © 2023 Chad Attermann; see `LICENSE.microstore`) is
vendored alongside under `include/microStore/`.

All fork modifications are:

> **Copyright (c) 2026 Rop Gonggrijp for Reticulous (<https://github.com/reticulous>)**
> Licensed under the Apache License, Version 2.0.

The modifications themselves are described below, per Apache-2.0 §4(b)
("You must cause any modified files to carry prominent notices stating
that You changed the files") and §4(d) (NOTICE file). Each modified
file carries an in-file `Spangap fork:` notice; this file is the summary.

---

## 1. New files added by the fork

### `src/donna/` — foreign crypto primitives, fully wired

Added so this fork no longer depends on `attermann/Crypto` (a fork of
`rweather/Crypto`, an Arduino-targeted crypto library). The directory
contains:

| File(s) | Origin | License |
|---|---|---|
| `ed25519.{c,h}`, `ed25519-donna*.h`, `modm-donna-32bit.h`, `curve25519-donna-*.h` | Andrew Moon `<liquidsun@gmail.com>` — `floodyberry/ed25519-donna` | Public domain |
| `ed25519-hash.h`, `ed25519-randombytes.h` | Same upstream (donna) | Public domain |
| `x25519.{c,h}` | © 2015–2016 Cryptography Research, Inc. (Mike Hamburg) — re-vendored from `trombik/esp_wireguard` | MIT (see `src/donna/x25519-license.txt`) |
| `ed25519-hash-custom.h` | **New, this fork** — SHA-512 hook routed through ESP-IDF mbedTLS | Apache-2.0 |
| `ed25519-randombytes-custom.h` | **New, this fork** — RNG hook routed through `esp_fill_random` (ESP32-S3 HRNG) | Apache-2.0 |
| `x25519-license.txt` | Attribution carried alongside `x25519.c` | — |

Compile-time defines applied to donna: `ED25519_CUSTOMHASH`,
`ED25519_CUSTOMRANDOM`, `ED25519_FORCE_32BIT`, `ED25519_NO_INLINE_ASM`.
GCC false-positive `-Wno-stringop-overread` suppressed for `x25519.c`.

### Other added files

| File | Purpose |
|---|---|
| `idf_component.yml` | ESP-IDF managed-component manifest (declares deps on `idf`, `spangap-core`) |
| `CMakeLists.txt`    | ESP-IDF build script — replaces upstream's Arduino-targeted build |
| `README.md`         | Fork rationale, vendored layout, phase status |
| `LICENSE.upstream`  | Verbatim Apache-2.0 from `attermann/microReticulum` |
| `LICENSE.microstore`| Verbatim Apache-2.0 from `attermann/microStore` |
| `NOTICE.md`         | *This file.* |

---

## 2. Modified upstream files

Each file below carries a `Spangap fork:` block at the top (or in
context) describing the local change. Summary:

| File | Nature of change |
|---|---|
| `src/Log.cpp` | Upstream's Arduino `Serial.print*` and native `printf` log sinks replaced with spangap's `err()`/`warn()`/`info()`/`dbg()`/`verb()` macros (per-task `[taskname]` prefix preserved). `getTimeString()` stubbed — spangap prepends its own timestamp. |
| `src/Reticulum.cpp` | Removed `<RNG.h>` (rweather/Crypto) include and `RNG.begin()`/`RNG.loop()` call sites — `esp_fill_random` self-seeds from the ESP32-S3 HRNG, no per-task setup or housekeeping needed. |
| `src/Transport.cpp` | Added per-destination cap on `random_blobs` matching upstream RNS (`Transport.py`: `random_blobs = random_blobs[-MAX_RANDOM_BLOBS:]`) — the C++ upstream had no cap, so the list grew without bound. |
| `src/Bytes.h` | ArduinoJson adapters at the bottom of the header dropped (slated for cJSON rewrite in `Utilities/Persistence`). Also: upstream's null-branch in `data()` returned a temporary `Data()` by const-ref (undefined behavior); replaced with a static empty instance. |
| `src/Interface.h` | ArduinoJson include + adapters dropped (same reason as `Bytes.h`). |
| `src/Cryptography/AES.h` | AES-128/256-CBC body rewritten against `mbedtls_aes_crypt_cbc` instead of rweather/Crypto's `CBC<AES128>/CBC<AES256>` template. Public `RNS::Cryptography::*` API unchanged. |
| `src/Cryptography/HKDF.cpp` | Rewritten against `mbedtls_hkdf` (RFC 5869 extract+expand in one call). |
| `src/Cryptography/HMAC.h` | Rewritten against `mbedtls_md_hmac_*`. Public API and `digest()` helper preserved bit-for-bit so callers (Fernet, Token) don't change. |
| `src/Cryptography/Hashes.cpp` | SHA-256/512 backed by mbedTLS (uses the ESP32-S3 SHA peripheral automatically). |
| `src/Cryptography/Ed25519.h` | Backed by `donna/ed25519.{c,h}` (djb-style 32-byte secret + derived 32-byte public, 64-byte signature). |
| `src/Cryptography/X25519.h` | Backed by `donna/x25519.{c,h}`. |
| `src/Cryptography/Random.h` | Random bytes via `esp_fill_random` (HRNG-seeded) instead of rweather/Crypto's `RNG` class. |
| `src/Utilities/OS.h` | File-I/O methods no-op'd per Reticulous component plan §10.5 (`read_file`/`write_file`/`open_file`/etc. return empty / `false` / `0`). `register_filesystem()` left functional in case anything wants to attach a real backing store later. |
| `src/Utilities/Persistence.{h,cpp}` | ArduinoJson dependency removed entirely. Upstream's globals (`JsonDocument _document`, `Bytes _buffer`) gone. `.cpp` retained as compilation placeholder pending the cJSON-based rewrite. |
| `src/Persistence/DestinationEntry.cpp` | `WARNINGF` log demoted on the path-table hot path (`decode()` runs on every `_new_path_table.get(...)` — hundreds of times per second when Transport iterates paths during Link maintenance). |

---

## 3. Upstream dependencies dropped

The fork no longer requires any of the following Arduino-ecosystem
libraries that upstream `attermann/microReticulum` depended on:

| Dropped dep | Replaced with |
|---|---|
| `attermann/Crypto` (fork of `rweather/Crypto`) — AES, SHA, HMAC, HKDF, Curve25519, Ed25519, RNG | mbedTLS (linked via ESP-IDF) + `src/donna/` |
| `<ArduinoJson.h>` (`bblanchon/ArduinoJson`) | cJSON via ESP-IDF's `json` component (rewrite pending — see `README.md`) |
| `<MsgPack.h>` (`hideakitai/MsgPack`) | Planned: hand-rolled ~80 LOC shim alongside the eventual Link subsystem (see `README.md` §C). |
| microStore Arduino adapters (`FlashFS`, `InternalFS`, `LittleFS`, `SPIFFS`, `SD`) | Dropped from `include/microStore/Adapters/`. Non-Arduino adapters (`Noop`, `Posix`, `Stdio`, `Universal`) retained but unused — guarded by `USTORE_USE_*` defines we don't set. |

---

## 4. Build-flag posture

- `RNS_USE_FS` and `RNS_PERSIST_PATHS` are **deliberately not defined** in
  this fork; the path store falls back to `microStore::BasicHeapStore`
  (the reason for pinning to `5642ae7` instead of the `0.3.1` tag).
  Persistence is owned end-to-end by spangap's `rnsd` CLI / cron path
  (Reticulous component plan §10.5).
- `ARDUINO` is never defined; inert `#ifdef ARDUINO` branches still
  litter the upstream sources and are flagged for cleanup (see
  `README.md` §4 of Phase 0 — what's NOT done yet).

---

## 5. Known open items

See `README.md` for the full list. The two items worth surfacing here:

- **`Log.h` case-collision with spangap's `log.h`** on case-insensitive
  filesystems (macOS APFS default). Working around in `src/Log.cpp` by
  inlining the macro expansion instead of `#include`ing spangap's header;
  the clean fix is to rename µR's `Log.h` to `RnsLog.h` across ~30 files.
- **MsgPack shim** to be hand-rolled when the Link subsystem actually
  lands (Link.cpp is the sole consumer in the upstream tree).
