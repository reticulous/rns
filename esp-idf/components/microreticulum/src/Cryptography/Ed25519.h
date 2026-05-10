/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: Ed25519 backed by ed25519-donna (src/donna/ed25519.{c,h})
 * instead of rweather/Crypto's Ed25519. The donna API is the canonical
 * djb-style: 32-byte secret key + derived 32-byte public key, 64-byte
 * signatures.
 *
 * Naming note: in this codebase, "private key" refers to the 32-byte
 * Ed25519 *secret seed* — donna's `ed25519_secret_key`. donna derives the
 * 64-byte extended secret + nonce from it on each sign() call (via
 * SHA-512), matching the Python reference's behavior.
 */

#pragma once

#include "../Bytes.h"

#include "donna/ed25519.h"
#include "Random.h"

#include <memory>
#include <stdexcept>

namespace RNS { namespace Cryptography {

	class Ed25519PublicKey {

	public:
		using Ptr = std::shared_ptr<Ed25519PublicKey>;

	public:
		Ed25519PublicKey(const Bytes& publicKey) : _publicKey(publicKey) {}
		~Ed25519PublicKey() {}

		static inline Ptr from_public_bytes(const Bytes& publicKey) {
			return Ptr(new Ed25519PublicKey(publicKey));
		}

		inline const Bytes& public_bytes() { return _publicKey; }

		// donna returns 0 on a valid signature, nonzero on rejection.
		inline bool verify(const Bytes& signature, const Bytes& message) {
			if (signature.size() != 64 || _publicKey.size() != 32) {
				return false;
			}
			return ::ed25519_sign_open(message.data(), message.size(),
			                           _publicKey.data(), signature.data()) == 0;
		}

	private:
		Bytes _publicKey;
	};

	class Ed25519PrivateKey {

	public:
		using Ptr = std::shared_ptr<Ed25519PrivateKey>;

	public:
		Ed25519PrivateKey(const Bytes& privateKey) {
			if (privateKey) {
				if (privateKey.size() != 32) {
					throw std::invalid_argument("Ed25519 private key must be 32 bytes");
				}
				_privateKey = privateKey;
			} else {
				esp_fill_random(_privateKey.writable(32), 32);
			}
			::ed25519_publickey(_privateKey.data(), _publicKey.writable(32));
		}
		~Ed25519PrivateKey() {}

		static inline Ptr generate() {
			return Ptr(new Ed25519PrivateKey(Bytes::NONE));
		}

		static inline Ptr from_private_bytes(const Bytes& privateKey) {
			return Ptr(new Ed25519PrivateKey(privateKey));
		}

		inline const Bytes& private_bytes() { return _privateKey; }

		inline Ed25519PublicKey::Ptr public_key() {
			return Ed25519PublicKey::from_public_bytes(_publicKey);
		}

		inline const Bytes sign(const Bytes& message) {
			Bytes signature;
			::ed25519_sign(message.data(), message.size(),
			               _privateKey.data(), _publicKey.data(),
			               signature.writable(64));
			return signature;
		}

	private:
		Bytes _privateKey;
		Bytes _publicKey;
	};

} }
