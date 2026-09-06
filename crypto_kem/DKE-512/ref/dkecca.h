#ifndef DKECCA_H
#define DKECCA_H

#include "parameters.h"
#include <stdint.h>



/// @brief Implements DKEM.KeyGen for DKEM-512 with explicit randomness
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKEM512_KeyGen(uint8_t pk[DKE3_PKBYTES],
                          uint8_t sk[DKE3_SKBYTES],
                          const uint8_t coins[DKE3_SEEDBYTES + DKE3_SSBYTES]);

/// @brief Implements DKEM.Internal for DKEM-512
/// @param[out] ct      pointer to output ciphertext
/// @param[out] k      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKEM512_Internal(uint8_t ct[DKE3_CTBYTES],
                        uint8_t k[DKE3_SSBYTES],
                        const uint8_t pk[DKE3_PKBYTES],
                        const uint8_t coins[DKE3_SEEDBYTES]);

/// @brief Implements DKEM.Decaps for DKEM-512
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKEM512_Decaps(uint8_t ss[DKE3_SSBYTES],
                 const uint8_t sk[DKE3_SKBYTES],
                 const uint8_t ct[DKE3_CTBYTES]);

#endif //DKECCA_H