/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Spangap fork: SHA-256/512 backed by mbedTLS instead of rweather/Crypto.
 * mbedTLS is already linked for spangap's TLS + WG. ESP32-S3 hardware
 * SHA peripherals are used automatically when MBEDTLS_SHA256_USE_INTERFACE
 * is enabled in ESP-IDF's mbedtls config (the default).
 */

#include "Hashes.h"

#include "../Bytes.h"

#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

using namespace RNS;

const Bytes RNS::Cryptography::sha256(const Bytes& data) {
	Bytes hash;
	mbedtls_sha256(data.data(), data.size(), hash.writable(32), /*is224=*/0);
	return hash;
}

const Bytes RNS::Cryptography::sha512(const Bytes& data) {
	Bytes hash;
	mbedtls_sha512(data.data(), data.size(), hash.writable(64), /*is384=*/0);
	return hash;
}
