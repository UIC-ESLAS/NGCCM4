#ifndef POLYVEC_H
#define POLYVEC_H
// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/polyvec.h

#include "parameters.h"
#include "poly.h"
#include <stdint.h>

// This file defines the representation of elements in Rq^k and its arithmetic

typedef struct {
    poly vec[DKE2_K];
} polyvec; // Represents vectors in Rq^k

// Basic arithmetic -------------------------------------------------------

/// @brief reduces a vector polynomial mod q in {-(q-1)/2,...,(q-1)/2}
/// @param[in/out] v  pointer to vector polynomial v
void DKE2_polyvec_reduce(polyvec *v);

/// @brief Adds two vectors in Rq^k
/// @param[in] a        pointer to vector a
/// @param[in] b        pointer to vector b
/// @param[out] res     pointer to output vector res = a + b
void DKE2_polyvec_add(polyvec *res, const polyvec *a, const polyvec *b);

/// @brief Scales a vector by a factor of 2
/// @param[in, out]     v  pointer to a vector in Rq^k
void DKE2_polyvec_scale2(polyvec *v);

// Advanced arithmetic -----------------------------------------------------

/// @brief Computes the Number-Theoretic Transform (NTT) of a vector
///        of polynomials in Rq^k.
/// @param[in,out]      v Pointer to the vector to be transformed
void DKE2_polyvec_ntt(polyvec *v);

/// @brief Computes the inverse Number-Theoretic Transform (INTT) and
///        converts coefficients to Montgomery representation in Rq^k
/// @param[in,out]      v Pointer to the vector to be transformed
void DKE2_polyvec_invntt_tomont(polyvec *v);

/// @brief Computes accumulate multiplication in Montgomery Domain, and returns
///         into the common domain (mod q).
/// @param[out]     res  Pointer to output vector in NTT representation
/// @param[in]      a  Pointer to input vector a in NTT representation
/// @param[in]      b  Pointer to input vector b in NTT representation
void DKE2_polyvec_basemul_acc_montgomery(poly *res, const polyvec *a, const polyvec *b);

// For managing conversion polyvec < --- > bytes ----------------------------

/// @brief Serialize a vector Rq^k (without compressing).
/// @param[in] v        pointer to input vector
/// @param[out] bytes   pointer to the beginning of the output byte array
void DKE2_polyvec_tobytes(uint8_t bytes[DKE2_POLYVECBYTES], const polyvec *v);

/// @brief De-serialize a vector in Rq^k (without decompressing).
/// @param[out] v        pointer to output vector
/// @param[in]  bytes    pointer to the beginning of the byte array
void DKE2_polyvec_frombytes(polyvec *v, const uint8_t bytes[DKE2_POLYVECBYTES]);

/// @brief Compress a vector in Rq^k into an array of bytes, in which the representation
///        of each coefficient takes 11 bits.
/// @param[out] bytes     pointer to the beginning of the output byte array
/// @param[in]  v         pointer to input vector
/// @WARNING:   this function is implemented for a fixed value of dB = 11
void DKE2_polyvec_compress11(uint8_t bytes[DKE2_PBCOMPRESSEDBYTES], const polyvec *v);

/// @brief Decompress an array of bytes (in which 11 bits represent a single coefficient)
///        into vector in Rq^k (polyvec).
/// @param[in]  v         pointer to input vector
/// @param[in]  bytes     pointer to the beginning of the output byte array
/// @WARNING:   this function is implemented for a fixed value of dB = 11
void DKE2_polyvec_decompress11(polyvec *v, const uint8_t bytes[DKE2_PBCOMPRESSEDBYTES]);





#endif //POLYVEC_H
