# License

This repository, **reticulous-core** (Reticulum / RNS protocol core for
spangap device apps), is released under the **Apache License, Version 2.0**.

Full license text: <https://www.apache.org/licenses/LICENSE-2.0>

Copyright (c) 2026 by reticulous project contributors.

The Apache-2.0 license applies to the original spangap glue in this repo
(straddle scaffolding, `browser/`, `main/`, the RNSD_PORT_TRANSPORT ITS
surface, README/INTERNALS, build files). The vendored sub-components under
`esp-idf/components/` retain their own licenses as listed below.

## Third-party software

### 1. microReticulum — `esp-idf/components/microreticulum/`

Hard fork of [`attermann/microReticulum`](https://github.com/attermann/microReticulum),
pinned at upstream commit `5642ae7fe17de6a8be9dc4891e95cf8a47c6ebe9`
(one commit past tag `0.3.1`). Modifications are detailed in
[`esp-idf/components/microreticulum/NOTICE.md`](esp-idf/components/microreticulum/NOTICE.md).

| Sub-path | Origin | License |
|---|---|---|
| Bulk of `src/` and `include/` (Reticulum protocol stack) | © 2023 Chad Attermann (`attermann/microReticulum`) | **Apache-2.0** — full text in `microreticulum/LICENSE.upstream` |
| `include/microStore/` | © 2023 Chad Attermann (`attermann/microStore`) | **Apache-2.0** — full text in `microreticulum/LICENSE.microstore` |
| `src/donna/ed25519*.{c,h}`, `modm-donna-*.h`, `curve25519-donna-*.h`, `ed25519-donna-*.h` | Andrew Moon `<liquidsun@gmail.com>` (`floodyberry/ed25519-donna`) | **Public domain** |
| `src/donna/x25519.{c,h}` | © 2015–2016 Cryptography Research, Inc. (Mike Hamburg) | **MIT** — full text in `microreticulum/src/donna/x25519-license.txt` |
| `src/donna/ed25519-hash-custom.h`, `ed25519-randombytes-custom.h` | Spangap fork (this project) | Apache-2.0 |
| `src/Utilities/tlsf.{c,h}` | Matthew Conte, two-level segregated fit allocator | **MIT** (per upstream `tlsf` distribution) |

### 2. bzip2 — `esp-idf/components/bzip2/`

| Sub-path | Origin | License |
|---|---|---|
| `src/blocksort.c`, `bzlib.c`, `compress.c`, `crctable.c`, `decompress.c`, `huffman.c`, `randtable.c`, `include/bzlib.h`, `bzlib_private.h`, `bz_version.h` | © 1996–2010 Julian Seward `<jseward@acm.org>` — bzip2/libbzip2 1.1.0 of 6 September 2010 | **bzip2 license** (4-clause BSD-style; full text in `bzip2/LICENSE`) |
| `src/bz_stub.c` | Spangap fork (this project) — `bz_internal_error()` panic adapter | Apache-2.0 |

### Build-time dependencies

Declared in `esp-idf/idf_component.yml` and `browser/package.json`:

| Component / package | Source | License |
|---|---|---|
| ESP-IDF (platform) | espressif/esp-idf | Apache-2.0 |
| mbedTLS (linked transitively, used by donna custom-hash hook) | ESP-IDF | Apache-2.0 |
| Browser peer deps (Vue, Quasar, Pinia, vue-router) | npm | MIT |
