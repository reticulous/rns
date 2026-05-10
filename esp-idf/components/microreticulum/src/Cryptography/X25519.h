/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: X25519 backed by the donna x25519 implementation
 * (src/donna/x25519.{c,h}) instead of rweather/Crypto's Curve25519.
 *
 * RFC 7748 clamping is requested via the trailing `1` argument to
 * x25519() / x25519_base() — RNS is interop-compatible with the Python
 * reference's `cryptography.hazmat.primitives.asymmetric.x25519` which
 * always clamps. The X25519PublicKey wrapper stores the raw 32-byte
 * public key; X25519PrivateKey stores the raw 32-byte secret and the
 * derived public key.
 */

#pragma once

#include "../Bytes.h"
#include "../Log.h"

#include "donna/x25519.h"
#include "Random.h"

#include <memory>
#include <stdexcept>
#include <stdint.h>

namespace RNS { namespace Cryptography {

	class X25519PublicKey {

	public:
		using Ptr = std::shared_ptr<X25519PublicKey>;

	public:
		X25519PublicKey(const Bytes& publicKey) : _publicKey(publicKey) {}
		~X25519PublicKey() {}

		static inline Ptr from_public_bytes(const Bytes& publicKey) {
			return Ptr(new X25519PublicKey(publicKey));
		}

		Bytes public_bytes() { return _publicKey; }

	private:
		Bytes _publicKey;
	};

	class X25519PrivateKey {

	public:
		// Constant-time-on-paper exec windows from upstream (also in
		// the Python reference). Used by Identity for ECDH timing
		// equalization — kept here to preserve the public surface.
		const float MIN_EXEC_TIME = 2;     // ms
		const float MAX_EXEC_TIME = 500;   // ms
		const uint8_t DELAY_WINDOW = 10;
		const uint8_t T_MAX = 0;

		using Ptr = std::shared_ptr<X25519PrivateKey>;

	public:
		X25519PrivateKey(const Bytes& privateKey) {
			if (privateKey) {
				if (privateKey.size() != 32) {
					throw std::invalid_argument("X25519 private key must be 32 bytes");
				}
				_privateKey = privateKey;
			} else {
				// Generate a fresh random scalar. RFC 7748 clamping is
				// applied by donna's x25519_base() so the raw bytes here
				// are pre-clamp.
				esp_fill_random(_privateKey.writable(32), 32);
			}
			// Derive public key = X25519_base(scalar)
			::x25519_base(_publicKey.writable(32), _privateKey.data(), /*clamp=*/1);
		}
		~X25519PrivateKey() {}

		// Random secret + derived public.
		static inline Ptr generate() {
			return from_private_bytes({Bytes::NONE});
		}

		static inline Ptr from_private_bytes(const Bytes& privateKey) {
			return Ptr(new X25519PrivateKey(privateKey));
		}

		inline const Bytes& private_bytes() { return _privateKey; }

		inline X25519PublicKey::Ptr public_key() {
			return X25519PublicKey::from_public_bytes(_publicKey);
		}

		// ECDH: shared = peer_pk * scalar. Returns 0 on success, -1 if the
		// peer point was identified as low-order (donna returns nonzero in
		// that case). Upstream throws on failure — preserved here.
		inline const Bytes exchange(const Bytes& peer_public_key) {
			if (peer_public_key.size() != 32) {
				throw std::invalid_argument("X25519 peer public key must be 32 bytes");
			}
			Bytes sharedKey;
			if (::x25519(sharedKey.writable(32), _privateKey.data(), peer_public_key.data(), /*clamp=*/1) != 0) {
				throw std::runtime_error("Peer key is invalid (low-order point)");
			}
			return sharedKey;
		}

	private:
		Bytes _privateKey;
		Bytes _publicKey;
	};

} }
