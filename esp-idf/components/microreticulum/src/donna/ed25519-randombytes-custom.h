/*
 * RNG backend for ed25519-donna, routed through spangap-core's DRBG
 * (randomBytes, see spangap-core/docs/random.md).
 *
 * Must match the non-static declaration in ed25519.h (no `static inline`).
 * ed25519-donna only calls this from batch verification (random scalars);
 * we don't use batch verification, but the symbol must resolve.
 */

#pragma once

#include "random.h"

void ED25519_FN(ed25519_randombytes_unsafe)(void *p, size_t len) {
	randomBytes(p, len);
}
