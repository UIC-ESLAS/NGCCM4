#ifndef DKECCA_H
#define DKECCA_H

#include "parameters.h"
#include <stdint.h>

/// @brief Implements DKEM.KeyGen for DKEM-256 with explicit randomness
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKEM256_KeyGen(uint8_t pk[DKE2_PKBYTES],
                          uint8_t sk[DKE2_SKBYTES],
                          const uint8_t coins[DKE2_SEEDBYTES + DKE2_SSBYTES]);

/// @brief Implements DKEM.Internal for DKEM-256
/// @param[out] ct      pointer to output ciphertext
/// @param[out] k      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKEM256_Internal(uint8_t ct[DKE2_CTBYTES],
                        uint8_t k[DKE2_SSBYTES],
                        const uint8_t pk[DKE2_PKBYTES],
                        const uint8_t coins[DKE2_SEEDBYTES]);

/// @brief Implements DKEM.Decaps for DKEM-256
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKEM256_Decaps(uint8_t ss[DKE2_SSBYTES],
                 const uint8_t sk[DKE2_SKBYTES],
                 const uint8_t ct[DKE2_CTBYTES]);

#endif //DKECCA_H