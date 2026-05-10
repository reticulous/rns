/*
 * SHA-512 backend for ed25519-donna, routed through ESP-IDF's mbedTLS.
 *
 * ed25519-donna requires the four symbols below when ED25519_CUSTOMHASH is
 * defined (see ed25519-hash.h). mbedtls_sha512_context is opaque enough that
 * we can typedef ed25519_hash_context onto it directly.
 */

#pragma once

#include "mbedtls/sha512.h"

typedef mbedtls_sha512_context ed25519_hash_context;

static inline void ed25519_hash_init(ed25519_hash_context *ctx) {
	mbedtls_sha512_init(ctx);
	mbedtls_sha512_starts(ctx, /*is384=*/0);
}

static inline void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	mbedtls_sha512_update(ctx, in, inlen);
}

static inline void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	mbedtls_sha512_finish(ctx, hash);
	mbedtls_sha512_free(ctx);
}

static inline void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	mbedtls_sha512(in, inlen, hash, /*is384=*/0);
}
