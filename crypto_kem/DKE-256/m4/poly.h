#ifndef POLY_H
#define POLY_H
#include "parameters.h"
#include <stdint.h>

// This file defines the representation of elements in Rq and its arithmetic

typedef struct {
    int16_t coeffs[DKE2_N];
} poly;             // Represents polynomials

// Basic arithmetic -------------------------------------------------------

/// @brief reduces a polynomial mod q in {-(q-1)/2,...,(q-1)/2}
/// @param[in/out] pol pointer to poly pol
void DKE2_poly_reduce(poly *pol);
void DKE2_poly_reduce_mq(poly *pol);

/// @brief Adds two polynomials in Rq
/// @param[in] a        pointer to a poly a
/// @param[in] b        pointer to a poly b
/// @param[out] res     pointer to output poly res = a + b (might not be in Rq)
void DKE2_poly_add(poly *res, const poly *a, const poly *b);
void DKE2_poly_sub(poly *res, const poly *a, const poly *b);

/// @brief Scales a polynomial by a factor of 2
/// @param[in, out] pol  pointer to a poly
/// @remark If pol has small coefficients, this new polynomial belongs to Rq
void DKE2_poly_scale2(poly *pol);

// Advanced arithmetic ----------------------------------------------------

/// @brief Computes the Number-Theoretic Transform (NTT) of a polynomial
/// Transforms the polynomial from coefficient representation to NTT
/// representation.
/// @param[in,out]      pol Pointer to the polynomial to be transformed
void DKE2_poly_ntt(poly *pol);

void DKE2_poly_invntt(poly *pol);

void DKE2_poly_basemul(poly *res, const poly *a, const poly *b);
void DKE2_poly_basemul_acc(poly *res, const poly *a, const poly *b);
void DKE2_poly_fromplant(poly *pol);


// For managing conversion poly < --- > bytes ----------------------------

/// @brief Serialize a polynomial (without compressing).
/// @param[in] pol      pointer to input polynomial
/// @param[out] bytes   pointer to the beginning of the byte array
void DKE2_poly_tobytes(uint8_t bytes[DKE2_POLYBYTES], const poly *pol);
void DKE2_poly_frombytes_mul(poly *pol, const poly *b, const unsigned char *bytes);

/// @brief De-serialize a polynomial (without decompressing).
/// @param[out] pol      pointer to output polynomial
/// @param[in]  bytes     pointer to the beginning of the byte array
void DKE2_poly_frombytes(poly *pol, const uint8_t bytes[DKE2_POLYBYTES]);
void DKE2_poly_basemul_opt_16_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void DKE2_poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void DKE2_poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t *r_tmp);
void DKE2_poly_frombytes_mul_16_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void DKE2_poly_frombytes_mul_32_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void DKE2_poly_frombytes_mul_32_16(poly *r, const poly *b, const unsigned char *a, const int32_t *r_tmp);
void DKE2_poly_frombytes_mul_acc(poly *pol, const poly *b, const unsigned char *bytes);


/// @brief Evaluates the (derandomized) signal function (with parameter DKE_L=5)  from poly.
/// @param[out] sig     array of signal bytes
/// @param[in]  pol     pointer to input polynomial
/// @WARNING    This implementation is **fixed for DKE_L = 4** (matching MLKEM parameters) and optimized accordingly.
///             Changing DKE_L would require rewriting this function, as the current
///             code assumes this specific value for efficiency.
void DKE2_getsignal5(uint8_t sig[DKE2_SIGNALBYTES], const poly *pol);


/// @brief Reconstructs a polynomial from signal: pol = L · (w0 + w1·X + ... + w_255 x^255 )
/// where L = (q-1)/2^l. (l = 5)
/// @param[out] pol     pointer to output polynomial
/// @param[in]  sig     input signal array
void DKE2_poly_fromsignal5(poly *pol, const uint8_t sig[DKE2_SIGNALBYTES]);

#endif //POLY_H
