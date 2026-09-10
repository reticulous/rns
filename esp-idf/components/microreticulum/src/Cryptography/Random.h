/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Spangap fork: random bytes from spangap-core's DRBG (randomBytes, see
 * spangap-core/docs/random.md) instead of rweather/Crypto's RNG class. The
 * DRBG is seeded at boot inside an entropy-source window, so it is strong
 * before any radio is up and on nodes that never bring one up — which
 * esp_fill_random on its own is not.
 *
 * Also fixes the upstream randomnum() bug where bytes 1–3 of the random
 * buffer were shadowed by byte 0 (typo: data()[0] used four times).
 */

#pragma once

#include "../Bytes.h"

/* Angle-include on purpose. A quote-include is searched from this file's own
 * directory first, and on a case-insensitive filesystem — a macOS checkout,
 * which a build container bind-mounts as-is — "random.h" matches this very
 * file. #pragma once then makes it a silent no-op and spangap-core's
 * declarations never arrive, so every call below fails to compile. Angle
 * brackets skip the current directory and go straight to the include path. */
#include <random.h>

#include <stdint.h>

namespace RNS { namespace Cryptography {

	// return vector of specified length of random bytes
	inline const Bytes random(size_t length) {
		Bytes rand;
		if (length > 0) {
			randomBytes(rand.writable(length), length);
		}
		return rand;
	}

	// return 32-bit random unsigned int
	inline uint32_t randomnum() {
		return randomU32();
	}

	// return 32-bit random unsigned int between 0 and `max-1`
	inline uint32_t randomnum(uint32_t max) {
		return randomU32() % max;
	}

	// return random float value in [0.0, 1.0]
	inline float random() {
		return (float)(randomU32() / (float)0xffffffffu);
	}

} }
