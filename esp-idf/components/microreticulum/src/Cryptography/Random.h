/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: random bytes via esp_fill_random (HRNG-seeded) instead of
 * rweather/Crypto's RNG class. esp_fill_random is non-blocking and produces
 * cryptographically-strong output once WiFi or Bluetooth has initialized
 * the entropy source — true on all diptych boots before any RNS code runs.
 *
 * Also fixes the upstream randomnum() bug where bytes 1–3 of the random
 * buffer were shadowed by byte 0 (typo: data()[0] used four times).
 */

#pragma once

#include "../Bytes.h"

#include "esp_random.h"

#include <stdint.h>

namespace RNS { namespace Cryptography {

	// return vector of specified length of random bytes
	inline const Bytes random(size_t length) {
		Bytes rand;
		if (length > 0) {
			esp_fill_random(rand.writable(length), length);
		}
		return rand;
	}

	// return 32-bit random unsigned int
	inline uint32_t randomnum() {
		return esp_random();
	}

	// return 32-bit random unsigned int between 0 and `max-1`
	inline uint32_t randomnum(uint32_t max) {
		return esp_random() % max;
	}

	// return random float value in [0.0, 1.0]
	inline float random() {
		return (float)(esp_random() / (float)0xffffffffu);
	}

} }
