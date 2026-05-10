/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: HMAC backed by mbedtls_md_hmac_* instead of rweather/Crypto.
 * Public API (RNS::Cryptography::HMAC + the free `digest()` helper) is
 * preserved bit-for-bit so callers (Fernet, Token) don't need to change.
 */

#pragma once

#include "../Bytes.h"

#include "mbedtls/md.h"

#include <stdexcept>
#include <memory>

namespace RNS { namespace Cryptography {

	class HMAC {

	public:
		enum Digest {
			DIGEST_NONE,
			DIGEST_SHA256,
			DIGEST_SHA512,
		};

		using Ptr = std::shared_ptr<HMAC>;

	public:
		HMAC(const Bytes& key, const Bytes& msg = {Bytes::NONE}, Digest digest = DIGEST_SHA256) {
			if (digest == DIGEST_NONE) {
				throw std::invalid_argument("Cannot derive key from empty input material");
			}

			const mbedtls_md_info_t* md_info = nullptr;
			switch (digest) {
			case DIGEST_SHA256:
				md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
				_digest_size = 32;
				break;
			case DIGEST_SHA512:
				md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
				_digest_size = 64;
				break;
			default:
				throw std::invalid_argument("Unknown or unsupported digest");
			}

			mbedtls_md_init(&_ctx);
			if (mbedtls_md_setup(&_ctx, md_info, /*hmac=*/1) != 0) {
				mbedtls_md_free(&_ctx);
				throw std::runtime_error("mbedtls_md_setup failed");
			}
			if (mbedtls_md_hmac_starts(&_ctx, key.data(), key.size()) != 0) {
				mbedtls_md_free(&_ctx);
				throw std::runtime_error("mbedtls_md_hmac_starts failed");
			}

			if (msg) {
				update(msg);
			}
		}

		~HMAC() {
			mbedtls_md_free(&_ctx);
		}

		HMAC(const HMAC&) = delete;
		HMAC& operator=(const HMAC&) = delete;

		void update(const Bytes& msg) {
			mbedtls_md_hmac_update(&_ctx, msg.data(), msg.size());
		}

		// Note: upstream's digest() lets callers continue updating after
		// finalization — mbedtls_md_hmac doesn't naturally allow that. We
		// reset the HMAC state with the same key after producing the digest
		// so subsequent update() calls behave as before.
		Bytes digest() {
			Bytes result;
			mbedtls_md_hmac_finish(&_ctx, result.writable(_digest_size));
			mbedtls_md_hmac_reset(&_ctx);
			return result;
		}

		static inline Ptr generate(const Bytes& key, const Bytes& msg = {Bytes::NONE}, Digest digest = DIGEST_SHA256) {
			return Ptr(new HMAC(key, msg, digest));
		}

	private:
		mbedtls_md_context_t _ctx;
		size_t _digest_size = 0;
	};

	inline const Bytes digest(const Bytes& key, const Bytes& msg, HMAC::Digest digest = HMAC::DIGEST_SHA256) {
		HMAC hmac(key, msg, digest);
		hmac.update(msg);
		return hmac.digest();
	}

} }
