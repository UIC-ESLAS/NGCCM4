#ifndef RANDOM_SAMPLING_H
#define RANDOM_SAMPLING_H

#include "parameters.h"
#include "polyvec.h"
#include "poly.h"
#include "auxfunc.h"

// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-1024/clean

#define DKE2_CBD_BYTES ((2 * DKE2_ETA * DKE2_N) / 8)

/// @brief generates a polynomial in Rq according to the centered binomial distribution
/// with parameter eta = DKE2_ETA.
/// @param[in]  coins   random coins array (we need DKE2_CBD_BYTES bytes
/// since DKE2_ETA random bytes ----> 4 random coeffs in {-eta, ..., eta}):
/// @param[out] pol     pointer to output polynomial
void centered_binomial2(poly* pol, const unsigned char coins[DKE2_CBD_BYTES]);


// As used in the protocol:

void DKE2_cbdA(poly* pol, const unsigned char coins[DKE2_CBD_BYTES]);
void DKE2_cbdB(poly* pol, const unsigned char coins[DKE2_CBD_BYTES]);

void DKE2_getsecretA(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce);
void DKE2_geterrorA(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce);
void DKE2_getsecretB(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce);
void DKE2_geterrorB(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce);

// ---------------------------------------------------------------------------
// Random sampling in Zq:

/// @brief Run rejection sampling on uniform random bytes to generate
///        uniform random integers mod q.
/// @param[in]  len      requested number of 16-bit integers (uniform mod q)
/// @param[in]  buf      pointer to input buffer (assumed to be uniformly random bytes)
/// @param[in]  buflen   length of input buffer in bytes
/// @param[out] res      pointer to output buffer
/// @return     number of sampled 16-bit integers (at most len)
unsigned int rej_uniform(int16_t *res,
                         const unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen);

// ---------------------------------------------------------------------------
// Random sampling in Rq:

/// @brief Deterministically generates the matrix M ∈ R_q^(k×k)
///        from a seed.
///
/// @param[in]  seed         random seed
/// @param[in]  transposed   if zero, the function samples M. If not zero, it samples M^t.
/// @param[out] res          pointer to output consisting on k vectors of polynomials (namely a matrix M over Rq)
#define gen_a(A,B)  DKE2_gen_matrix(A,B,0)
#define gen_at(A,B) DKE2_gen_matrix(A,B,1)
void DKE2_gen_matrix(polyvec *res,
                     const uint8_t seed[DKE2_SEEDBYTES],
                     const int transposed);



#endif //RANDOM_SAMPLING_H
