#ifndef DKECCA_H
#define DKECCA_H

#include "parameters.h"
#include <stdint.h>



/// @brief Implements DKEM.KeyGen for DKEM-128 with explicit randomness
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKEM128_KeyGen(uint8_t pk[DKE1_PKBYTES],
                          uint8_t sk[DKE1_SKBYTES],
                          const uint8_t coins[DKE1_SEEDBYTES + DKE1_SSBYTES]);

/// @brief Implements DKEM.Internal for DKEM-128
/// @param[out] ct      pointer to output ciphertext
/// @param[out] k      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKEM128_Internal(uint8_t ct[DKE1_CTBYTES],
                        uint8_t k[DKE1_SSBYTES],
                        const uint8_t pk[DKE1_PKBYTES],
                        const uint8_t coins[DKE1_SEEDBYTES]);

/// @brief Implements DKEM.Decaps for DKEM-128
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKEM128_Decaps(uint8_t ss[DKE1_SSBYTES],
                 const uint8_t sk[DKE1_SKBYTES],
                 const uint8_t ct[DKE1_CTBYTES]);

#endif //DKECCA_H
