// Comes from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-768/clean/verify.c

#include "verify.h"
#include <stddef.h>
#include <stdint.h>

/* Force the compiler to treat b as unknown, so it cannot turn the
 * cmov below into a branch on b (which would not be constant time).
 * Idiom from PQClean's hardening of the Kyber/ML-KEM cmov
 * (see PQCLEAN_PREVENT_BRANCH_HACK in PQClean/common/compat.h). */
#if defined(__GNUC__) || defined(__clang__)
#define DKE_PREVENT_BRANCH(b) __asm__("" : "+r"(b) : /* no inputs */)
#else
#define DKE_PREVENT_BRANCH(b)
#endif

extern void DKE_cmov_asm(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
extern int DKE_verify_asm(const uint8_t *a, const uint8_t *b, size_t len);

int DKE2_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    return DKE_verify_asm(a, b, len);
}

void DKE2_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    DKE_PREVENT_BRANCH(b);
    DKE_cmov_asm(r, x, len, b);
}


void DKE2_cmov_int16(int16_t *r, int16_t v, uint16_t b) {
    b = -b;
    *r ^= b & ((*r) ^ v);
}
