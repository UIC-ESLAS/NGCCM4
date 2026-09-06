// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-768/clean/poly.c

#include "parameters.h"
#include "poly.h"
#include "reduce.h"
#include "ntt.h"
#include <stdint.h>


// Basic arithmetic ----------------------------------------------

void DKE2_poly_reduce(poly *pol) {
    unsigned int i;
    for (i = 0; i < DKE2_N; i++) {
        pol->coeffs[i] = DKE2_barrett_reduce(pol->coeffs[i]);
    }
}

void DKE2_poly_add(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < DKE2_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void DKE2_poly_sub(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < DKE2_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void DKE2_poly_scale2(poly *pol) {
    DKE2_poly_add(pol, pol, pol);
}

// Advanced arithmetic -----------------------------------


void DKE2_poly_ntt(poly *pol) {
    DKE2_ntt(pol->coeffs);  // Apply NTT.
    DKE2_poly_reduce(pol);  // Barret reduction
}

void DKE2_poly_invntt_tomont(poly *pol) {
    DKE2_invntt(pol->coeffs);   // NTT & Montgomery Domain -> Montgomery Domain
}

void DKE2_poly_basemul_montgomery(poly *res, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < DKE2_N / 4; i++) {
        DKE2_basemul(&res->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], DKE2_zetas[64 + i]);
        DKE2_basemul(&res->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -DKE2_zetas[64 + i]);
    }
} // NTT & Montgomery Domain -> NTT & Montgomery Domain

void DKE2_poly_tomont(poly *pol){   // -> Montgomery Domain
    unsigned int i;
    const int16_t f = (1ULL << 32) % DKE2_Q;
    for (i = 0; i < DKE2_N; i++) {
        pol->coeffs[i] = DKE2_montgomery_reduce((int32_t)pol->coeffs[i] * f);
    }
}

// For managing conversion poly <---> bytes ----------------------------

void DKE2_poly_tobytes(uint8_t bytes[DKE2_POLYBYTES], const poly *pol){
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < DKE2_N / 2; i++) {
        // map to positive standard representatives
        t0  = pol->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & DKE2_Q;
        t1 = pol->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & DKE2_Q;
        // We use 3 bytes to store two coefficients
        bytes[3 * i + 0] = (uint8_t)(t0 >> 0);
        bytes[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        bytes[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void DKE2_poly_frombytes(poly *pol, const uint8_t bytes[DKE2_POLYBYTES]) {
    unsigned int i;
    for (i = 0; i < DKE2_N / 2; i++) {
        // We get 2 coefficients from 3 bytes
        pol->coeffs[2 * i]   = ((bytes[3 * i + 0] >> 0) | ((uint16_t)bytes[3 * i + 1] << 8)) & 0xFFF;
        pol->coeffs[2 * i + 1] = ((bytes[3 * i + 1] >> 4) | ((uint16_t)bytes[3 * i + 2] << 4)) & 0xFFF;
    }
}

// We use PQCLean MLKEM1024 compression for implementing DKE1_getsignal5 (l=5)
// This is not valid for other choices of l.
static void PQCLEAN_MLKEM1024_CLEAN_poly_compress(uint8_t r[DKE2_SIGNALBYTES], const poly *a) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];

    for (i = 0; i < DKE2_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            // map to positive standard representatives
            u  = a->coeffs[8 * i + j];
            u += (u >> 15) & DKE2_Q;
            /*    t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31; */
            d0 = u << 5;
            d0 += 1664;
            d0 *= 40318;
            d0 >>= 27;
            t[j] = d0 & 0x1f;
        }

        r[0] = (t[0] >> 0) | (t[1] << 5);
        r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        r[2] = (t[3] >> 1) | (t[4] << 4);
        r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        r[4] = (t[6] >> 2) | (t[7] << 3);
        r += 5;
    }
}


void DKE2_getsignal5(uint8_t sig[DKE2_SIGNALBYTES], const poly *pol) {
    PQCLEAN_MLKEM1024_CLEAN_poly_compress(sig, pol);
}


// Reconstructs w_i * L from a 5-bit signal w_i, where L = (q-1)/2^l.
// Identity: since q = 3329 ≡ 1 (mod 2^5 = 32), floor(w * q / 32) == w * (q-1)/32 == w * L
// for every w in {0,...,31}. So integer-shifted multiplication matches the paper's
// w -> w * L mapping exactly; no rounding constant required. Constant-time:
// only multiplication and shift on the (public) signal byte, no data-dependent branches.
static void DKE2_poly_decompressFloor(poly *r, const uint8_t a[DKE2_SIGNALBYTES]){
    unsigned int i, j;
    uint8_t t[8];
    for (i = 0; i < DKE2_N / 8; i++) {
        t[0] = (a[0] >> 0);
        t[1] = (a[0] >> 5) | (a[1] << 3);
        t[2] = (a[1] >> 2);
        t[3] = (a[1] >> 7) | (a[2] << 1);
        t[4] = (a[2] >> 4) | (a[3] << 4);
        t[5] = (a[3] >> 1);
        t[6] = (a[3] >> 6) | (a[4] << 2);
        t[7] = (a[4] >> 3);
        a += 5;

        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 31) * DKE2_Q) >> 5;
        }
    }
}

void DKE2_poly_fromsignal5(poly *pol, const uint8_t sig[DKE2_SIGNALBYTES]) {
    DKE2_poly_decompressFloor(pol, sig);
}