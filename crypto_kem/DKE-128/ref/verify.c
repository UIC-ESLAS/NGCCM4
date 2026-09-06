// Comes from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/verify.c

#include "verify.h"
#include <stddef.h>
#include <stdint.h>

/* Force the compiler to treat b as unknown, so it cannot turn the
 * cmov below into a branch on b (which would not be constant time).
 * Idiom from PQClean's hardening of the Kyber/ML-KEM cmov
 * (see PQCLEAN_PREVENT_BRANCH_HACK in PQClean/common/compat.h). */
#if defined(__GNUC__) || defined(__clang__)
# define DKE_PREVENT_BRANCH(b) __asm__("" : "+r"(b) : /* no inputs */)
#else
# define DKE_PREVENT_BRANCH(b)
#endif

int DKE1_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    return (~(uint64_t)r + 1) >> 63;
}

void DKE1_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;

    DKE_PREVENT_BRANCH(b);

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}


void DKE1_cmov_int16(int16_t *r, int16_t v, uint16_t b) {
    b = -b;
    *r ^= b & ((*r) ^ v);
}
