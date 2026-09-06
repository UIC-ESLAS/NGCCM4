#include "ntt.h"
#include "parameters.h"
#include "poly.h"
#include "polyvec.h"
#include "dke_utils.h"
#include "verify.h"
#include <stdint.h>

// Derived from poly_frommsg in https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/poly.c
static void DKE1_rand_to_poly(poly *b, const uint8_t coins[DKE1_N/8]) {
    size_t i, j;
    for (i = 0; i < DKE1_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            b->coeffs[8 * i + j] = 0;
            DKE1_cmov_int16(b->coeffs + 8 * i + j,  -1, (coins[i] >> j) & 1);
        }
    }
}

void DKE1_signal(uint8_t sig[DKE1_SIGNALBYTES],
                 const poly *k,
                 const uint8_t coins[DKE1_N/8]) {
    poly b;
    DKE1_rand_to_poly(&b, coins);
    DKE1_poly_add(&b, &b, k); // k + b
    DKE1_poly_reduce(&b);
    DKE1_getsignal4(sig, &b);
}

static void DKE1_apply_signal(poly *k, const uint8_t sig[DKE1_SIGNALBYTES]) {
    poly wL;
    DKE1_poly_fromsignal4(&wL, sig);
    DKE1_poly_sub(k, k, &wL);     // k - wL
    DKE1_poly_reduce(k);              // maps to {-(q-1)/2,...,(q-1)/2}
}

static void DKE1_mod2(uint8_t ss[DKE1_SSBYTES],  poly *k) {
    unsigned int i, j;
    uint16_t t;
    for (i = 0; i < DKE1_SSBYTES; i++) {
        ss[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = k->coeffs[8 * i + j];
            t &= 1;
            ss[i] |= t << j;
        }
    }
}

void DKE1_derive_ss(uint8_t ss[DKE1_SSBYTES],
                    poly *k,
                    const uint8_t sig[DKE1_SIGNALBYTES]) {
    DKE1_apply_signal(k, sig);
    DKE1_mod2(ss, k);
}
