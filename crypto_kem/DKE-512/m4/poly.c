#include "parameters.h"
#include "poly.h"
#include "ntt.h"
#include <stdint.h>

// assembly routines
extern void poly_reduce_asm(int16_t *r);
extern void poly_reduce_mq_asm(int16_t *r);
extern void asm_fromplant(int16_t *r);
extern void pointwise_add(int16_t *c, const int16_t *a, const int16_t *b);
extern void pointwise_sub(int16_t *c, const int16_t *a, const int16_t *b);
extern void basemul_asm_opt_16_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
extern void basemul_asm_acc_opt_32_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
extern void basemul_asm_acc_opt_32_16(int16_t *, const int16_t *, const int16_t *, const int16_t *, const int32_t *);
// Basic arithmetic ----------------------------------------------

void DKE3_poly_reduce(poly *pol)
{
    poly_reduce_asm(pol->coeffs);
}

void DKE3_poly_reduce_mq(poly *pol)
{
    poly_reduce_mq_asm(pol->coeffs);
}

void DKE3_poly_add(poly *r, const poly *a, const poly *b) {
    pointwise_add(r->coeffs, a->coeffs, b->coeffs);
}

void DKE3_poly_sub(poly *r, const poly *a, const poly *b) {
    pointwise_sub(r->coeffs, a->coeffs, b->coeffs);
}

void DKE3_poly_scale2(poly *pol) {
    pointwise_add(pol->coeffs, pol->coeffs, pol->coeffs);
}

// Advanced arithmetic -----------------------------------


void DKE3_poly_ntt(poly *pol) {
    DKE3_ntt(pol->coeffs);  // Apply NTT.
}

void DKE3_poly_invntt(poly *pol) {
    DKE3_invntt(pol->coeffs);  
}

void DKE3_poly_basemul(poly *res, const poly *a, const poly *b) {
    DKE3_basemul(res->coeffs, a->coeffs, b->coeffs);
} 

void DKE3_poly_basemul_acc(poly *res, const poly *a, const poly *b)
{
    DKE3_basemul_acc(res->coeffs, a->coeffs, b->coeffs);
}

void DKE3_poly_basemul_opt_16_32(int32_t *r_tmp, const poly *a, const poly *b, const poly *a_prime)
{
    basemul_asm_opt_16_32(r_tmp, a->coeffs, b->coeffs, a_prime->coeffs);
}

void DKE3_poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime)
{
    basemul_asm_acc_opt_32_32(r, a->coeffs, b->coeffs, a_prime->coeffs);
}

void DKE3_poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t *r_tmp)
{
    basemul_asm_acc_opt_32_16(r->coeffs, a->coeffs, b->coeffs, a_prime->coeffs, r_tmp);
}


void DKE3_poly_fromplant(poly *pol)
{
    asm_fromplant(pol->coeffs);
}
// For managing conversion poly <---> bytes ----------------------------

void DKE3_poly_tobytes(uint8_t bytes[DKE3_POLYBYTES], const poly *pol){
    unsigned int i;
    uint16_t t0, t1, t2, t3, t4, t5, t6, t7;

    for (i = 0; i < DKE3_N / 8; i++) {

        // map to positive standard representatives
        t0 = pol->coeffs[8 * i];
        t1 = pol->coeffs[8 * i + 1];
        t2 = pol->coeffs[8 * i + 2];
        t3 = pol->coeffs[8 * i + 3];
        t4 = pol->coeffs[8 * i + 4];
        t5 = pol->coeffs[8 * i + 5];
        t6 = pol->coeffs[8 * i + 6];
        t7 = pol->coeffs[8 * i + 7];

        // We use 13 bytes to store eight coefficients
        bytes[13 * i + 0] = (uint8_t)(t0 >> 0);
        bytes[13 * i + 1] = (uint8_t)((t0 >> 8)|(t1 << 5));
        bytes[13 * i + 2] = (uint8_t)(t1 >> 3);
        bytes[13 * i + 3] = (uint8_t)((t1 >> 11)|(t2 << 2));
        bytes[13 * i + 4] = (uint8_t)((t2 >> 6)|(t3 << 7));
        bytes[13 * i + 5] = (uint8_t)(t3 >> 1);
        bytes[13 * i + 6] = (uint8_t)((t3 >> 9)|(t4 << 4));
        bytes[13 * i + 7] = (uint8_t)(t4 >> 4);
        bytes[13 * i + 8] = (uint8_t)((t4 >> 12)|(t5 << 1));
        bytes[13 * i + 9] = (uint8_t)((t5 >> 7)|(t6 << 6));
        bytes[13 * i + 10] = (uint8_t)(t6 >> 2);
        bytes[13 * i + 11] = (uint8_t)((t6 >> 10)|(t7 << 3));
        bytes[13 * i + 12] = (uint8_t)(t7 >> 5);

    }
}

void DKE3_poly_frombytes(poly *pol, const uint8_t bytes[DKE3_POLYBYTES]) {
    unsigned int i;
    for (i = 0; i < DKE3_N / 8; i++) {
        // We get 8 coefficients from 13 bytes
        pol->coeffs[8*i]     = ((bytes[13 * i + 0] >> 0) | ((uint16_t)bytes[13 * i + 1] << 8))  & 0x1FFF;
        pol->coeffs[8*i + 1] = ((bytes[13 * i + 1] >> 5) | ((uint16_t)bytes[13 * i + 2] << 3) |
                                                           ((uint16_t)bytes[13 * i + 3] << 11)) & 0x1FFF;
        pol->coeffs[8*i + 2] = ((bytes[13 * i + 3] >> 2) | ((uint16_t)bytes[13 * i + 4] << 6) ) & 0x1FFF;
        pol->coeffs[8*i + 3] = ((bytes[13 * i + 4] >> 7) | ((uint16_t)bytes[13 * i + 5] << 1) |
                                                           ((uint16_t)bytes[13 * i + 6] << 9))  & 0x1FFF;
        pol->coeffs[8*i + 4] = ((bytes[13 * i + 6] >> 4) | ((uint16_t)bytes[13 * i + 7] << 4) |
                                                           ((uint16_t)bytes[13 * i + 8] <<12))  & 0x1FFF;
        pol->coeffs[8*i + 5] = ((bytes[13 * i + 8] >> 1) | ((uint16_t)bytes[13 * i + 9] << 7))  & 0x1FFF;
        pol->coeffs[8*i + 6] = ((bytes[13 * i + 9] >> 6) | ((uint16_t)bytes[13 * i +10] << 2)
                                                         | ((uint16_t)bytes[13 * i +11] <<10))  & 0x1FFF;
        pol->coeffs[8*i + 7] = ((bytes[13 * i +11] >> 3) | ((uint16_t)bytes[13 * i +12] << 5))  & 0x1FFF;
    }
}

void DKE3_getsignal4(uint8_t bytes[DKE3_SIGNALBYTES], const poly *pol) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8]; // each t will contain 4 signal bits
    for (i = 0; i < DKE3_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            // map to positive standard representatives
            u  = pol->coeffs[8 * i + j];
            // u += (u >> 15) & DKE3_Q;
            /*    t[j] = ((((uint16_t)u << 4) + Q/2)/Q) & 0xf */
            d0 = u << 4;
            d0 += 3840; // (q-1)/2
            d0 *= 34948; // round(2^(32 - l) / q)
            d0 >>= 28;  // the 4 most significant bits survive
            t[j] = d0 & 0xf; // mask 0...01111
        }
        // packing
        bytes[0] = t[0] | (t[1] << 4);
        bytes[1] = t[2] | (t[3] << 4);
        bytes[2] = t[4] | (t[5] << 4);
        bytes[3] = t[6] | (t[7] << 4);
        bytes += 4;
    }
}
extern void poly_decompress_floor_asm(int16_t *coeffs, const uint8_t *bytes);

void DKE3_poly_fromsignal4(poly *pol, const uint8_t sig[DKE3_SIGNALBYTES]) {
   poly_decompress_floor_asm(pol->coeffs, sig);
}
