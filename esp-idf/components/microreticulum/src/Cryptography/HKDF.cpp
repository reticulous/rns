/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: HKDF backed by mbedtls_hkdf instead of rweather/Crypto.
 *
 * mbedtls_hkdf does extract+expand in one call (RFC 5869). The upstream
 * call signature passes salt as a separate argument; if it's missing, we
 * pass nullptr/0 which mbedtls treats as a zero-filled salt of digest size,
 * matching the RFC behavior and the rweather implementation.
 *
 * The `context` arg in the public API maps to HKDF's `info` parameter.
 */

#include "HKDF.h"

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include <stdexcept>

using namespace RNS;

const Bytes RNS::Cryptography::hkdf(size_t length, const Bytes& derive_from, const Bytes& salt /*= {Bytes::NONE}*/, const Bytes& context /*= {Bytes::NONE}*/) {

	if (length == 0) {
		throw std::invalid_argument("Invalid output key length");
	}
	if (!derive_from) {
		throw std::invalid_argument("Cannot derive key from empty input material");
	}

	const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md) {
		throw std::runtime_error("mbedtls SHA-256 not available");
	}

	Bytes derived;
	int ret = mbedtls_hkdf(
		md,
		salt    ? salt.data()    : nullptr, salt    ? salt.size()    : 0,
		derive_from.data(),                 derive_from.size(),
		context ? context.data() : nullptr, context ? context.size() : 0,
		derived.writable(length),           length);
	if (ret != 0) {
		throw std::runtime_error("mbedtls_hkdf failed");
	}
	return derived;
}
