#ifndef NTT_H
#define NTT_H

#include <stdint.h>

/// @brief Inplace number-theoretic transform (NTT) in Rq = Zq[X]/(x^n+1) where q = 7681 and n = 512,
///         multiplied by Plantard factor R^-1. i.e. ntt(r) = NTT(r)R^-1 mod q
///        input is in standard order, output is in bitreversed order
/// @param[in,out]  r  pointer to input/output vector of elements of Zq
void DKE3_ntt(int16_t r[512]);

/// @brief Inplace inverse number-theoretic transform in Rq and
///         multiplication by R^2. invntt(r) = NTT^-1(r) R^2 mod q.
///         Input is in bitreversed order, output is in standard order
/// @param[in, out] r   pointer to input/output vector of elements of Zq
void DKE3_invntt(int16_t r[512]);


/// consequently: Plantard_reduce(invntt(ntt(f))) = f mod q

/// @brief  Multiplication of polynomials in Zq[X]/(X^2-zeta)
///         used for multiplication of elements in Rq in NTT domain
/// @param[in]  a       pointer to the first factor
/// @param[in]  b       pointer to the second factor
/// @param[in]  zeta    integer defining the reduction polynomial
/// @param[out] r       pointer to the output polynomial
void DKE3_basemul(int16_t r[512], const int16_t a[512], const int16_t b[512]);

/// consequently: Plantard_reduce(invntt(ntt(f))) = f mod q

/// @brief  Multiplication of polynomials in Zq[X]/(X^512-zeta)
///         used for multiplication of elements in Rq in NTT domain
/// @param[in]  a       pointer to the first factor
/// @param[in]  b       pointer to the second factor
/// @param[in]  zeta    integer defining the reduction polynomial
/// @param[out] r       pointer to the output polynomial
void DKE3_basemul_acc(int16_t r[512], const int16_t a[512], const int16_t b[512]);

#endif //NTT_H
