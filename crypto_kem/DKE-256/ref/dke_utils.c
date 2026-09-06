#include "parameters.h"
#include "poly.h"
#include "dke_utils.h"
#include "verify.h"
#include <stdint.h>

// Derived from poly_frommsg in https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/poly.c
static void DKE2_rand_to_poly(poly *b, const uint8_t coins[DKE2_N/8]) {
    size_t i, j;
    for (i = 0; i < DKE2_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            b->coeffs[8 * i + j] = 0;
            DKE2_cmov_int16(b->coeffs + 8 * i + j,  -1, (coins[i] >> j) & 1);
        }
    }
}

void DKE2_signal(uint8_t sig[DKE2_SIGNALBYTES],
                 const poly *k,
                 const uint8_t coins[DKE2_N/8]) {
    poly b;
    DKE2_rand_to_poly(&b, coins);
    DKE2_poly_add(&b, &b, k); // k + b
    DKE2_poly_reduce(&b);
    DKE2_getsignal5(sig, &b);
}

static void DKE2_apply_signal(poly *k, const uint8_t sig[DKE2_SIGNALBYTES]) {
    poly wL;
    DKE2_poly_fromsignal5(&wL, sig);
    DKE2_poly_sub(k, k, &wL);     // k - wL
    DKE2_poly_reduce(k);              // maps to {-(q-1)/2,...,(q-1)/2}
}

static void DKE2_mod2(uint8_t ss[DKE2_SSBYTES],  poly *k) {
    unsigned int i, j;
    uint16_t t;
    for (i = 0; i < DKE2_SSBYTES; i++) {
        ss[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = k->coeffs[8 * i + j];
            t &= 1;
            ss[i] |= t << j;
        }
    }
}

void DKE2_derive_ss(uint8_t ss[DKE2_SSBYTES],
                    poly *k,
                    const uint8_t sig[DKE2_SIGNALBYTES]) {
    DKE2_apply_signal(k, sig);
    DKE2_mod2(ss, k);
}
