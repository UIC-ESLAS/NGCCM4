#include "parameters.h"
#include "poly.h"
#include "ntt.h"
#include <stdint.h>
#include <stddef.h>

extern void poly_reduce_asm(int16_t *r);
extern void poly_reduce_mq_asm(int16_t *r);
extern void asm_fromplant(int16_t *r);
extern void pointwise_add(int16_t *, const int16_t *, const int16_t *);
extern void pointwise_sub(int16_t *, const int16_t *, const int16_t *);
extern void frombytes_mul_asm_acc(int16_t *r, const int16_t *b, const unsigned char *c, const uint32_t zetas[64]);
extern void frombytes_mul_asm(int16_t *r, const int16_t *b, const unsigned char *c, const uint32_t zetas[64]);
extern void poly_tobytes_asm(uint8_t *bytes, const int16_t *coeffs);
extern void basemul_asm_opt_16_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
extern void basemul_asm_acc_opt_32_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
extern void basemul_asm_acc_opt_32_16(int16_t *, const int16_t *, const int16_t *, const int16_t *, const int32_t *);
extern void frombytes_mul_asm_16_32(int32_t *r_tmp, const int16_t *b, const unsigned char *c, const uint32_t zetas[64]);
extern void frombytes_mul_asm_acc_32_32(int32_t *r_tmp, const int16_t *b, const unsigned char *c, const uint32_t zetas[64]);
extern void frombytes_mul_asm_acc_32_16(int16_t *r, const int16_t *b, const unsigned char *c, const uint32_t zetas[64], const int32_t *r_tmp);

void DKE2_poly_reduce(poly *pol) {
    poly_reduce_asm(pol->coeffs);
}

void DKE2_poly_reduce_mq(poly *pol) {
    poly_reduce_mq_asm(pol->coeffs);
}

void DKE2_poly_add(poly *r, const poly *a, const poly *b) {
    pointwise_add(r->coeffs, a->coeffs, b->coeffs);
}

void DKE2_poly_sub(poly *r, const poly *a, const poly *b) {
    pointwise_sub(r->coeffs, a->coeffs, b->coeffs);
}

void DKE2_poly_scale2(poly *pol) {
    pointwise_add(pol->coeffs, pol->coeffs, pol->coeffs);
}

void DKE2_poly_ntt(poly *pol) {
    DKE2_ntt(pol->coeffs);
}

void DKE2_poly_invntt(poly *pol) {
    DKE2_invntt(pol->coeffs);
}

void DKE2_poly_basemul(poly *res, const poly *a, const poly *b) {
    DKE2_basemul(res->coeffs, a->coeffs, b->coeffs);
}

void DKE2_poly_basemul_acc(poly *res, const poly *a, const poly *b) {
    DKE2_basemul_acc(res->coeffs, a->coeffs, b->coeffs);
}

void DKE2_poly_basemul_opt_16_32(int32_t *r_tmp, const poly *a, const poly *b, const poly *a_prime) {
    basemul_asm_opt_16_32(r_tmp, a->coeffs, b->coeffs, a_prime->coeffs);
}

void DKE2_poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime) {
    basemul_asm_acc_opt_32_32(r, a->coeffs, b->coeffs, a_prime->coeffs);
}

void DKE2_poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t *r_tmp) {
    basemul_asm_acc_opt_32_16(r->coeffs, a->coeffs, b->coeffs, a_prime->coeffs, r_tmp);
}

void DKE2_poly_fromplant(poly *pol) {
    asm_fromplant(pol->coeffs);
}

void DKE2_poly_tobytes(uint8_t bytes[DKE2_POLYBYTES], const poly *pol) {
    poly_tobytes_asm(bytes, pol->coeffs);
}

void DKE2_poly_frombytes_mul(poly *r, const poly *b, const unsigned char *a) {
    frombytes_mul_asm(r->coeffs, b->coeffs, a, zetas);
}

void DKE2_poly_frombytes(poly *pol, const uint8_t bytes[DKE2_POLYBYTES]) {
    unsigned int i;
    for (i = 0; i < DKE2_N / 2; i++) {
        // We get 2 coefficients from 3 bytes
        pol->coeffs[2 * i]   = ((bytes[3 * i + 0] >> 0) | ((uint16_t)bytes[3 * i + 1] << 8)) & 0xFFF;
        pol->coeffs[2 * i + 1] = ((bytes[3 * i + 1] >> 4) | ((uint16_t)bytes[3 * i + 2] << 4)) & 0xFFF;
    }
}

void DKE2_poly_frombytes_mul_acc(poly *r, const poly *b, const unsigned char *a) {
    frombytes_mul_asm_acc(r->coeffs, b->coeffs, a, zetas);
}

void DKE2_poly_frombytes_mul_16_32(int32_t *r_tmp, const poly *b, const unsigned char *a) {
    frombytes_mul_asm_16_32(r_tmp, b->coeffs, a, zetas);
}

void DKE2_poly_frombytes_mul_32_32(int32_t *r_tmp, const poly *b, const unsigned char *a) {
    frombytes_mul_asm_acc_32_32(r_tmp, b->coeffs, a, zetas);
}

void DKE2_poly_frombytes_mul_32_16(poly *r, const poly *b, const unsigned char *a, const int32_t *r_tmp) {
    frombytes_mul_asm_acc_32_16(r->coeffs, b->coeffs, a, zetas, r_tmp);
}

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

extern void poly_decompress_floor_asm(int16_t *coeffs, const uint8_t *bytes);
void DKE2_poly_fromsignal5(poly *pol, const uint8_t sig[DKE2_SIGNALBYTES]) {
    poly_decompress_floor_asm(pol->coeffs, sig);
}
