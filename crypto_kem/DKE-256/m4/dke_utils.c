#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "parameters.h"
#include "dke_utils.h"
#include <stdint.h>
#include <string.h>

extern void rand_to_poly_asm(int16_t *coeffs, const uint8_t *coins);
extern void mod2_asm(uint8_t *ss, const int16_t *coeffs);

static void DKE2_rand_to_poly(poly *b, const uint8_t coins[DKE2_N/8]) {
    rand_to_poly_asm(b->coeffs, coins);
}

void DKE2_signal(uint8_t sig[DKE2_SIGNALBYTES],
                 const poly *k,
                 const uint8_t coins[DKE2_N/8]) {
    poly b;
    DKE2_rand_to_poly(&b, coins);
    DKE2_poly_add(&b, &b, k);
    DKE2_poly_reduce_mq(&b);
    DKE2_getsignal5(sig, &b);
}

static void DKE2_apply_signal(poly *k, const uint8_t sig[DKE2_SIGNALBYTES]) {
    poly wL;
    DKE2_poly_fromsignal5(&wL, sig);
    DKE2_poly_sub(k, k, &wL);
    DKE2_poly_reduce(k);
}

static void DKE2_mod2(uint8_t ss[DKE2_SSBYTES],  poly *k) {
    mod2_asm(ss, k->coeffs);
}

void DKE2_derive_ss(uint8_t ss[DKE2_SSBYTES],
                    poly *k,
                    const uint8_t sig[DKE2_SIGNALBYTES]) {
    DKE2_apply_signal(k, sig);
    DKE2_mod2(ss, k);
}
