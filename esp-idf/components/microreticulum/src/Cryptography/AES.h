/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: AES-128/256-CBC backed by mbedtls_aes_crypt_cbc instead of
 * rweather/Crypto's CBC<AES128>/CBC<AES256> template. The IV passed to
 * mbedtls_aes_crypt_cbc is mutated in place (the implementation tracks the
 * running CBC state through it), so we copy it to a local buffer first.
 * ESP32-S3 hardware AES is used automatically when CONFIG_MBEDTLS_HARDWARE_AES
 * is enabled in ESP-IDF's mbedtls config (the default).
 *
 * CBC.h / CBC.cpp from upstream are no longer needed and stay out of the
 * MICRORET_SRCS list — leave them on disk only as deletable scaffolding.
 */

#pragma once

#include "../Bytes.h"

#include "mbedtls/aes.h"

#include <stdexcept>
#include <cstring>

namespace RNS { namespace Cryptography {

	namespace detail {

		// Common helper for AES-CBC enc/dec. `keybits` is 128 or 256.
		// Plaintext / ciphertext lengths must be a multiple of 16 (PKCS7 padding
		// is the caller's responsibility — see PKCS7.h).
		inline void aes_cbc(int mode, const uint8_t* in, uint8_t* out, size_t len,
		                    const Bytes& key, const Bytes& iv, unsigned int keybits) {
			if (len == 0 || (len % 16) != 0) {
				throw std::invalid_argument("AES-CBC input must be a non-empty multiple of 16 bytes");
			}
			if (key.size() * 8 != keybits) {
				throw std::invalid_argument("AES-CBC key has wrong size for requested mode");
			}
			if (iv.size() != 16) {
				throw std::invalid_argument("AES-CBC IV must be 16 bytes");
			}

			mbedtls_aes_context ctx;
			mbedtls_aes_init(&ctx);

			int ret = (mode == MBEDTLS_AES_ENCRYPT)
				? mbedtls_aes_setkey_enc(&ctx, key.data(), keybits)
				: mbedtls_aes_setkey_dec(&ctx, key.data(), keybits);
			if (ret != 0) {
				mbedtls_aes_free(&ctx);
				throw std::runtime_error("mbedtls_aes_setkey failed");
			}

			// mbedtls_aes_crypt_cbc mutates the IV buffer (rolls forward through
			// the chain), so feed it a private copy.
			uint8_t iv_local[16];
			std::memcpy(iv_local, iv.data(), 16);

			ret = mbedtls_aes_crypt_cbc(&ctx, mode, len, iv_local, in, out);
			mbedtls_aes_free(&ctx);
			if (ret != 0) {
				throw std::runtime_error("mbedtls_aes_crypt_cbc failed");
			}
		}

	} // namespace detail

	class AES_128_CBC {

	public:
		static inline const Bytes encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& iv) {
			Bytes ciphertext;
			detail::aes_cbc(MBEDTLS_AES_ENCRYPT, plaintext.data(),
			                ciphertext.writable(plaintext.size()), plaintext.size(),
			                key, iv, 128);
			return ciphertext;
		}

		static inline const Bytes decrypt(const Bytes& ciphertext, const Bytes& key, const Bytes& iv) {
			Bytes plaintext;
			detail::aes_cbc(MBEDTLS_AES_DECRYPT, ciphertext.data(),
			                plaintext.writable(ciphertext.size()), ciphertext.size(),
			                key, iv, 128);
			return plaintext;
		}

		static inline void inplace_encrypt(Bytes& plaintext, const Bytes& key, const Bytes& iv) {
			detail::aes_cbc(MBEDTLS_AES_ENCRYPT, plaintext.data(),
			                (uint8_t*)plaintext.data(), plaintext.size(),
			                key, iv, 128);
		}

		static inline void inplace_decrypt(Bytes& ciphertext, const Bytes& key, const Bytes& iv) {
			detail::aes_cbc(MBEDTLS_AES_DECRYPT, ciphertext.data(),
			                (uint8_t*)ciphertext.data(), ciphertext.size(),
			                key, iv, 128);
		}

	};

	class AES_256_CBC {

	public:
		static inline const Bytes encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& iv) {
			Bytes ciphertext;
			detail::aes_cbc(MBEDTLS_AES_ENCRYPT, plaintext.data(),
			                ciphertext.writable(plaintext.size()), plaintext.size(),
			                key, iv, 256);
			return ciphertext;
		}

		static inline const Bytes decrypt(const Bytes& ciphertext, const Bytes& key, const Bytes& iv) {
			Bytes plaintext;
			detail::aes_cbc(MBEDTLS_AES_DECRYPT, ciphertext.data(),
			                plaintext.writable(ciphertext.size()), ciphertext.size(),
			                key, iv, 256);
			return plaintext;
		}

		static inline void inplace_encrypt(Bytes& plaintext, const Bytes& key, const Bytes& iv) {
			detail::aes_cbc(MBEDTLS_AES_ENCRYPT, plaintext.data(),
			                (uint8_t*)plaintext.data(), plaintext.size(),
			                key, iv, 256);
		}

		static inline void inplace_decrypt(Bytes& ciphertext, const Bytes& key, const Bytes& iv) {
			detail::aes_cbc(MBEDTLS_AES_DECRYPT, ciphertext.data(),
			                (uint8_t*)ciphertext.data(), ciphertext.size(),
			                key, iv, 256);
		}

	};

} }
