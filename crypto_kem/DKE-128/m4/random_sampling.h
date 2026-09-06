#ifndef RANDOM_SAMPLING_H
#define RANDOM_SAMPLING_H

#include "parameters.h"
#include "polyvec.h"
#include "poly.h"
#include <stdlib.h>

// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean

#define DKE1_CBD_BYTES ((2 * DKE1_ETA * DKE1_N) / 8)

#ifdef USE_KECCAK
    #include "fips202.h"
    #define DKE1_XOF_BLOCKBYTES SHAKE128_RATE
#else
  #define DKE1_XOF_BLOCKBYTES 192 
#endif
// DKE1_XOF_BLOCKBYTES need to be the multiple of 3. Otherwise, some tails are not considered in matacc assembly implementation.

#define DKE1_GEN_MATRIX_NBLOCKS ((12 * DKE1_N / 8 * (1 << 12) / DKE1_Q + DKE1_XOF_BLOCKBYTES) / DKE1_XOF_BLOCKBYTES)

typedef struct
{
#ifdef USE_KECCAK
  uint8_t extseed[DKE1_SEEDBYTES + 2];
  shake128ctx state;
#else 
  uint8_t extseed[DKE1_SEEDBYTES + 2 + 4]; // seed + x + y + counter (4 bytes)
  unsigned int counter;
#endif
} dke1_xof_state;

/// @brief generates a polynomial in Rq according to the centered binomial distribution
/// with parameter eta = DKE1_ETA.
/// @param[in]  coins   random coins array (we need DKE1_CBD_BYTES bytes
/// since DKE1_ETA random bytes ----> 4 random coeffs in {-eta, ..., eta}):
/// @param[out] pol     pointer to output polynomial
void centered_binomial3(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]);


// As used in the protocol:

void DKE1_cbdA(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]);
void DKE1_cbdB(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]);

void DKE1_getsecretA(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce);
void DKE1_geterrorA(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce);
void DKE1_getsecretB(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce);
void DKE1_geterrorB(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce);

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

/// @brief Deterministically samples a polynomial with coefficients
///        uniformly distributed in Z_q from (seed || i || j).
///
/// The function expands the input seed using pseudoXOF and applies
/// rejection sampling to obtain coefficients in R_q.
/// @param[in] seed     random seed
/// @param[in] i        used to modify seed
/// @param[in] j        used to modify seed
/// @param[out] pol     pointer to output polynomial pol in Rq
void poly_uniform(poly* pol,
                  const uint8_t seed[DKE1_SEEDBYTES],
                  const uint8_t i,
                  const uint8_t j);


/// @brief Deterministically generates the matrix M ∈ R_q^(k×k)
///        from a seed.
/// @param[in]  seed         random seed
/// @param[in]  transposed   if zero, the function samples M. If not zero, it samples M^t.
/// @param[out] res          pointer to output consisting on k vectors of polynomials (namely a matrix M over Rq)

#define gen_a(A,B)  DKE1_gen_matrix(A,B,0)
#define gen_at(A,B) DKE1_gen_matrix(A,B,1)
void DKE1_gen_matrix(polyvec *res,
                     const uint8_t seed[DKE1_SEEDBYTES],
                     const int transposed);

void dke1_xof_squeezeblocks(uint8_t *out,
                            size_t outblocks,
                            dke1_xof_state *state);
void dke1_xof_absorb(dke1_xof_state *state,
                     const uint8_t seed[DKE1_SEEDBYTES],
                     uint8_t x,
                     uint8_t y);
void dke1_xof_release(dke1_xof_state *state);
#endif //RANDOM_SAMPLING_H
