# microReticulum vendored fork.
#
# Phase 0 status: source is vendored under src/, microStore headers under
# include/microStore/. The bulk of the µR cpp files wait on per-module
# porting (crypto, JSON, msgpack swaps) and are added to MICRORET_SRCS one
# at a time. The donna/ subdirectory is fully wired and compiles — it
# provides the foreign crypto primitives we re-vendored:
#
#   - ed25519-donna (Andrew M. <liquidsun@gmail.com>, public domain) for
#     Ed25519 sign/verify/key derivation.
#   - x25519.c from Mike Hamburg / strobe (MIT) for X25519 ECDH —
#     re-vendored rather than depending on diptych-core's PRIV_INCLUDE'd
#     copy under src/esp_wireguard/.
#   - SHA-512 backed by mbedTLS, RNG by esp_fill_random — see
#     donna/ed25519-hash-custom.h and donna/ed25519-randombytes-custom.h.
#
# Public include path: src/ + include/. Headers reference each other as
# `#include "Xxx.h"` (sibling) and `#include <microStore/Xxx.h>` (vendored
# subdir). Both work via INCLUDE_DIRS below.

set(MICRORET_SRCS
    # Foreign crypto primitives, re-vendored:
    "src/donna/ed25519.c"
    "src/donna/x25519.c"

    # Cryptography wrappers (all rewritten against mbedTLS + donna):
    "src/Cryptography/Hashes.cpp"
    "src/Cryptography/HKDF.cpp"
    "src/Cryptography/Fernet.cpp"
    "src/Cryptography/Token.cpp"
    "src/Cryptography/X25519.cpp"
    "src/Cryptography/Ed25519.cpp"
    # AES.h, HMAC.h, Random.h, PKCS7.h are header-only.
    # CBC.cpp/h dropped — AES.h calls mbedtls_aes_crypt_cbc directly.

    # Core µR — ArduinoJson surfaces stripped from the headers. Persistence
    # is stubbed (see Utilities/Persistence.h header note).
    "src/Bytes.cpp"
    "src/Log.cpp"
    "src/Utilities/Crc.cpp"
    "src/Utilities/Memory.cpp"
    "src/Utilities/OS.cpp"
    "src/Utilities/Persistence.cpp"
    # tlsf.c is mR's bundled allocator (used only on Arduino-NRF52). On
    # ESP-IDF we use the platform's tlsf via heap_caps; mR's RNS_HEAP_ALLOCATOR
    # path uses ::operator new/delete, so this file is unused. Building it
    # collides with ESP-IDF's heap component (both export tlsf_*).
    "src/Persistence/DestinationEntry.cpp"
    "src/Identity.cpp"
    "src/Destination.cpp"
    "src/Interface.cpp"
    "src/Packet.cpp"
    "src/Resource.cpp"
    "src/Channel.cpp"
    "src/Transport.cpp"
    "src/Reticulum.cpp"

    # Link.cpp stays out until the Link/Resource/Channel/Buffer subsystem
    # is wanted (plan §1: "No Link / Resource / propagation node support
    # in v1"). When it comes in we'll hand-roll a small src/MsgPack.h
    # shim covering Link.cpp's narrow API surface (Packer.serialize /
    # to_array, Unpacker.deserialize / from_array, bin_t<uint8_t>) — see
    # README issue C for the wire-format notes. ~80 LOC, no upstream
    # patches, no msgpack-c vendor dep.
    # "src/Link.cpp"
    # Link_stub.cpp provides link-time stubs for Link methods that
    # Transport.cpp references — none runtime-reachable since we never
    # create Link instances. See file header for details.
    "src/Link_stub.cpp"
)

idf_component_register(
    SRCS ${MICRORET_SRCS}
    INCLUDE_DIRS
        "src"
        "include"
    REQUIRES
        # mbedTLS — for the Cryptography/ rewrite (AES-CBC, HMAC, HKDF, SHA,
        # RNG via mbedtls_ctr_drbg or esp_fill_random) AND for the SHA-512
        # backend wired into ed25519-donna in donna/ed25519-hash-custom.h.
        mbedtls
        # esp_hw_support — for esp_fill_random (RNG backend for ed25519-donna).
        esp_hw_support
        # cJSON ships as ESP-IDF's `json` component — replaces ArduinoJson.
        json
        # diptych-core — for log macros (info/warn/err/...) once Log.cpp is
        # rerouted into the build.
        diptych-core
)

# Plan §2: explicitly do NOT define RNS_USE_FS or RNS_PERSIST_PATHS so that
# Persistence/DestinationEntry.h falls back to microStore::BasicHeapStore.
# mR's hourly autopersist is harmless because OS::read_file/write_file are
# no-op'd (see src/Utilities/OS.h).
#
# ed25519-donna config (see donna/ed25519-donna.h):
#   ED25519_CUSTOMHASH    — use donna/ed25519-hash-custom.h (mbedTLS SHA-512)
#                           instead of the reference SHA-512 or OpenSSL.
#   ED25519_CUSTOMRANDOM  — use donna/ed25519-randombytes-custom.h
#                           (esp_fill_random) instead of OpenSSL RAND_bytes.
#   ED25519_FORCE_32BIT   — ESP32-S3 has no native uint128; pick the 32-bit
#                           limb implementation (curve25519-donna-32bit.h
#                           and modm-donna-32bit.h).
#   ED25519_NO_INLINE_ASM — there's no SSE2 / x86 asm path on Xtensa,
#                           skip the architecture detection entirely.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ED25519_CUSTOMHASH
    ED25519_CUSTOMRANDOM
    ED25519_FORCE_32BIT
    ED25519_NO_INLINE_ASM
)

# Vendored upstream sources have a sprinkling of code-quality warnings
# (missing switch arms in Transport, format-truncation false positives
# in fixed-size path buffers, etc.). We don't want to maintain warning
# patches against upstream — disable the specific -Werror= categories
# that fire across multiple files. Plain `-Wno-error` doesn't work here
# because IDF appends its `-Werror=switch` etc. after our flags, and
# right-most wins.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-error=switch
    -Wno-error=format-truncation
    -Wno-error=stringop-truncation
    -Wno-error=maybe-uninitialized
)

# ed25519-donna's reference impl raises noisy warnings on modern GCC that
# aren't real bugs (unused functions in the table headers, casts in the
# basepoint table, etc.). Silence them just for the donna sources so the
# rest of the component keeps the project's strict warning posture.
set_source_files_properties(
    src/donna/ed25519.c
    src/donna/x25519.c
    PROPERTIES COMPILE_OPTIONS
    "-Wno-unused-function;-Wno-unused-const-variable;-Wno-sign-compare;-Wno-implicit-fallthrough;-Wno-stringop-overread"
)
