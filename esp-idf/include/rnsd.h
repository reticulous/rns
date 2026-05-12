/**
 * rnsd — RNS protocol task.
 *
 * Owns: identity, destinations, path table, transport state machine,
 *       links, resources. Zero networking/radio dependencies — receives
 *       RNS-format packets via ITS streams from transport tasks and
 *       sends them back the same way.
 *
 * This header also exposes a small byte-array C-style API that
 * encapsulates every piece of mR (microReticulum) the rest of the
 * project would otherwise need to know about: SHA-256, identity
 * generate/sign/recall, destination-hash derivation, async path
 * request. Consumers (lxmf, etc.) include only `rnsd.h` and operate
 * on raw byte arrays — never on `RNS::Identity` / `RNS::Bytes` /
 * `RNS::Destination`. The underlying crypto / protocol library can
 * therefore be swapped (mR → upstream RNS, or anything else) without
 * touching consumers.
 *
 * Threading: every function in this header is safe to call from any
 * task. Pure-crypto helpers (sha256/sign/verify/dest_hash) execute
 * inline on the caller's task. The mR-state functions (`recall*`)
 * take a recursive mutex around mR's `_known_destinations` table.
 * `rnsdRequestPath` writes a storage sentinel; the work runs on
 * rnsd's task asynchronously.
 *
 * See docs/component-plan.md §4 / §5.1 / §9 / §11.
 */
#pragma once

#include <cstdint>
#include <cstddef>

/* ──────────────── constants ──────────────── */

constexpr size_t RNSD_DEST_HASH_LEN  = 16;   /* 16-byte destination hash */
constexpr size_t RNSD_IDENT_HASH_LEN = 16;   /* 16-byte truncated identity hash */
constexpr size_t RNSD_PUBKEY_LEN     = 64;   /* Ed25519(32) + X25519(32) public key */
constexpr size_t RNSD_PRIVKEY_LEN    = 64;   /* Ed25519(32) + X25519(32) private key */
constexpr size_t RNSD_SIG_LEN        = 64;   /* Ed25519 signature */
constexpr size_t RNSD_HASH_LEN       = 32;   /* SHA-256 */

/* ──────────────── task bring-up ──────────────── */

/** Bring up the rnsd task. Called from app_main between diptychInit()
 *  and diptychPostAppInit(). */
void rnsdInit(void);

/* ──────────────── pure crypto (caller-task safe) ──────────────── */

/** SHA-256 of arbitrary bytes. Output is exactly RNSD_HASH_LEN. */
void rnsdSha256(const uint8_t* data, size_t n, uint8_t out[RNSD_HASH_LEN]);

/** Compute the conventional 16-byte destination hash for
 *  (identity, app_name, aspect). The identity is loaded from
 *  `identity_key` (a storage path holding the 128-hex private key,
 *  same convention as `rnsd_mailbox_connect_t.identity_key`).
 *  Returns true on success. */
bool rnsdDestinationHash(const char* identity_key,
                         const char* app_name, const char* aspect,
                         uint8_t out[RNSD_DEST_HASH_LEN]);

/** Sign `data` with the private key at `identity_key`. Output is
 *  exactly RNSD_SIG_LEN. Returns true on success. */
bool rnsdSign(const char* identity_key,
              const uint8_t* data, size_t n,
              uint8_t out_sig[RNSD_SIG_LEN]);

/** Verify a signature against a public key. Returns true iff valid. */
bool rnsdVerify(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                const uint8_t* data, size_t n,
                const uint8_t sig[RNSD_SIG_LEN]);

/* ──────────────── identity management ──────────────── */

/** Generate a fresh identity and persist its 64-byte private key
 *  (as 128-hex) at `identity_key`. Returns true on success.
 *  Idempotent: if a valid identity already exists at that key, this
 *  is a no-op and returns true. Use rnsdIdentityErase first to force
 *  a re-generation. */
bool rnsdIdentityGenerate(const char* identity_key);

/** True iff the identity at `identity_key` is present and loadable. */
bool rnsdIdentityExists(const char* identity_key);

/** Compute the 16-byte truncated identity hash for the identity at
 *  `identity_key`. Returns true on success. */
bool rnsdIdentityHash(const char* identity_key,
                      uint8_t out[RNSD_IDENT_HASH_LEN]);

/** Wipe the identity at `identity_key`. */
void rnsdIdentityErase(const char* identity_key);

/* ──────────────── recall / path request ──────────────── */

/** Look up the public key for a destination in rnsd's identity cache
 *  (populated by mR as announces arrive). Takes a recursive mutex
 *  around mR's `_known_destinations` table — safe from any task.
 *  Returns true if known and populates `out_pubkey`; false if not
 *  yet heard. The standard recovery pattern on false is to call
 *  rnsdRequestPath(dest_hash) and retry later. */
bool rnsdRecallPubkey(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                      uint8_t out_pubkey[RNSD_PUBKEY_LEN]);

/** Issue an async path request for `dest_hash`. Writes a storage
 *  sentinel; rnsd's task processes it (mR's Transport::request_path
 *  must run on the task that owns Transport state, otherwise the
 *  outbound packet silently drops). Returns immediately; the request
 *  has no return value — the caller polls via rnsdRecallPubkey or
 *  the path table. */
void rnsdRequestPath(const uint8_t dest_hash[RNSD_DEST_HASH_LEN]);
