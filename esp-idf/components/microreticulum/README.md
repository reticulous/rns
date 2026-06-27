# microreticulum (fork)

ESP-IDF component holding our modified fork of
[`attermann/microReticulum`](https://github.com/attermann/microReticulum), the
C++ port of Reticulum.

**What this is, what we changed, and how it's used** lives in the `rns` straddle
docs — see [`../../../README.md`](../../../README.md) and
[`../../../INTERNALS.md`](../../../INTERNALS.md) (the latter's §1 is the full
inventory of our µR modifications). This file only records the facts local to the
vendored copy.

## Pinned commit

Upstream commit `5642ae7fe17de6a8be9dc4891e95cf8a47c6ebe9` ("Restored fallback
heap-based path storage", 2026-05-09 — one commit past tag `0.3.1`).

We pin one commit *past* `0.3.1` because the tag hardcoded the path store to
`microStore::BasicFileStore`; `5642ae7` added an
`#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)` guard so that without
those flags it falls back to `microStore::BasicHeapStore`. We deliberately do
not define those flags (we own persistence end-to-end), so the heap-store
fallback is essential — the `0.3.1` tag would not build correctly for our
configuration.

## Licensing

Attribution for the upstream and the vendored crypto primitives is in the
`LICENSE.*` files alongside this one (`LICENSE.upstream` and `LICENSE.microstore`,
both Apache-2.0; `src/donna/x25519-license.txt`, MIT). `CMakeLists.txt` is the
source of truth for which µR files are compiled.
