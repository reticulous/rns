/* Host stand-in for mbedTLS's PBKDF2. The community key's DERIVATION is not
 * what these tests exercise — the record path and the resolver are — but
 * netgraph.cpp is compiled whole, so the symbol has to exist.
 *
 * Deliberately NOT a real PBKDF2: a test that derived a key here would be
 * asserting against this file rather than against mbedTLS, and would take the
 * twenty thousand iterations to do it. It fills the output with a cheap
 * function of the inputs, which is enough for "the same inputs give the same
 * key, different inputs do not". */
#pragma once
#include <cstdint>
#include <cstddef>

typedef enum { MBEDTLS_MD_SHA256 = 1 } mbedtls_md_type_t;

inline int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t,
                                         const unsigned char* pw, size_t pwlen,
                                         const unsigned char* salt, size_t saltlen,
                                         unsigned int iters,
                                         size_t keylen, unsigned char* out)
{
    uint32_t h = 2166136261u ^ iters;
    for (size_t i = 0; i < pwlen; i++)   { h ^= pw[i];   h *= 16777619u; }
    for (size_t i = 0; i < saltlen; i++) { h ^= salt[i]; h *= 16777619u; }
    for (size_t i = 0; i < keylen; i++) {
        h ^= (uint32_t)i; h *= 16777619u;
        out[i] = (unsigned char)(h >> 24);
    }
    return 0;
}
