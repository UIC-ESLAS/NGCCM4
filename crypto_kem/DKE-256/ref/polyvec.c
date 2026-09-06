// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-768/clean/polyvec.c

#include "parameters.h"
#include "poly.h"
#include "polyvec.h"
#include <stdint.h>

// Basic arithmetic ----------------------------------------------

void DKE2_polyvec_reduce(polyvec *v) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_reduce(&v->vec[i]);
    }
}

void DKE2_polyvec_add(polyvec *res, const polyvec *a, const polyvec *b) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_add(&res->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void DKE2_polyvec_scale2(polyvec *v) {
    DKE2_polyvec_add(v, v, v);
}

// Advanced arithmetic ---------------------------------------------

void DKE2_polyvec_ntt(polyvec *v) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_ntt(&v->vec[i]);
    }
}

void DKE2_polyvec_invntt_tomont(polyvec *v) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_invntt_tomont(&v->vec[i]);
    }
}

void DKE2_polyvec_basemul_acc_montgomery(poly *res, const polyvec *a, const polyvec *b) {
    unsigned int i;
    // the sums are accumulated in res
    poly temp;           // auxiliary poly to contain the successive products
    DKE2_poly_basemul_montgomery(res, &a->vec[0], &b->vec[0]);
    for (i = 1; i < DKE2_K; i++) {
        DKE2_poly_basemul_montgomery(&temp, &a->vec[i], &b->vec[i]);
        DKE2_poly_add(res, res, &temp);
    }
    DKE2_poly_reduce(res);  // We return to normal domain from montgomery domain.
}

// For managing conversion polyvec < --- > bytes ----------------------------

void DKE2_polyvec_tobytes(uint8_t bytes[DKE2_POLYVECBYTES], const polyvec *v) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_tobytes(bytes +  i * DKE2_POLYBYTES, &v->vec[i]);
    }
}

void DKE2_polyvec_frombytes(polyvec *v, const uint8_t bytes[DKE2_POLYVECBYTES]) {
    unsigned int i;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_poly_frombytes(&v -> vec[i], bytes + i * DKE2_POLYBYTES);
    }
}

void DKE2_polyvec_compress11(uint8_t bytes[DKE2_PBCOMPRESSEDBYTES], const polyvec *v) {
// https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-1024/clean/polyvec.c
// PQCLEAN_MLKEM1024_CLEAN_polyvec_compress
    unsigned int i, j, k;
    uint64_t d0;

    uint16_t t[8];
    for (i = 0; i < DKE2_K; i++) {
        for (j = 0; j < DKE2_N / 8; j++) { // we process 8 coefficients each time
            for (k = 0; k < 8; k++) {
                t[k]  = v->vec[i].coeffs[8 * j + k];
                t[k] += ((int16_t)t[k] >> 15) & DKE2_Q; // branch-free map to {0,...,q-1}
                // Compress from Zq --> Z2^d definition: round(x · 2^d / q) = floor(x · 2^d / q + 0.5)
                d0 = t[k]; // x
                d0 <<= 11; // x · 2^d
                d0 += 1664;  // x · 2^d + (q/2+0.5)
                d0 *= 645084;   // floor(2^31 / q) => d0 = (x·2^d + q/2 + 0.5)·floor(2^31/q)
                d0 >>= 31; // d0 = floor((x·2^d/q + 0.5)/q)
                t[k] = d0 & 0x7ff; // take the last 11 bits.
            }

            // At this stage, there are 8 coefficients in t
            // We use 11 bytes to store them

            bytes[ 0] = (uint8_t)(t[0] >>  0);
            bytes[ 1] = (uint8_t)((t[0] >>  8) | (t[1] << 3));
            bytes[ 2] = (uint8_t)((t[1] >>  5) | (t[2] << 6));
            bytes[ 3] = (uint8_t)(t[2] >>  2);
            bytes[ 4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
            bytes[ 5] = (uint8_t)((t[3] >>  7) | (t[4] << 4));
            bytes[ 6] = (uint8_t)((t[4] >>  4) | (t[5] << 7));
            bytes[ 7] = (uint8_t)(t[5] >>  1);
            bytes[ 8] = (uint8_t)((t[5] >>  9) | (t[6] << 2));
            bytes[ 9] = (uint8_t)((t[6] >>  6) | (t[7] << 5));
            bytes[10] = (uint8_t)(t[7] >>  3);
            bytes += 11;
        }
    }
}

void DKE2_polyvec_decompress11(polyvec *v, const uint8_t bytes[DKE2_PBCOMPRESSEDBYTES]) {
    // https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-1024/clean/polyvec.c
    // PQCLEAN_MLKEM1024_CLEAN_polyvec_compress

    unsigned int i, j, k;

    uint16_t t[8];
    for (i = 0; i < DKE2_K; i++) {
        for (j = 0; j < DKE2_N / 8; j++) {
            // Bit unpacking
            t[0] = (bytes[0] >> 0) | ((uint16_t)bytes[ 1] << 8);
            t[1] = (bytes[1] >> 3) | ((uint16_t)bytes[ 2] << 5);
            t[2] = (bytes[2] >> 6) | ((uint16_t)bytes[ 3] << 2) | ((uint16_t)bytes[4] << 10);
            t[3] = (bytes[4] >> 1) | ((uint16_t)bytes[ 5] << 7);
            t[4] = (bytes[5] >> 4) | ((uint16_t)bytes[ 6] << 4);
            t[5] = (bytes[6] >> 7) | ((uint16_t)bytes[ 7] << 1) | ((uint16_t)bytes[8] << 9);
            t[6] = (bytes[8] >> 2) | ((uint16_t)bytes[ 9] << 6);
            t[7] = (bytes[9] >> 5) | ((uint16_t)bytes[10] << 3);
            bytes += 11;

            // Round(t q / 2^11)
            for (k = 0; k < 8; k++) {
                v->vec[i].coeffs[8 * j + k] = ((uint32_t)(t[k] & 0x7FF) * DKE2_Q + 1024) >> 11;
            }
        }
    }
}
