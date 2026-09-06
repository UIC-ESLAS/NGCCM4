#include "parameters.h"
#include <stdint.h>

/// @brief Implements DKE.Initiate for DKEM-128
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKE128_Initiate(uint8_t pk[DKE1_PKBYTES],
                      uint8_t sk[DKE1_CPA_SKABYTES],
                      const uint8_t coins[DKE1_SEEDBYTES]);

/// @brief Implements DKE.Response for DKEM-128
/// @param[out] ct      pointer to output ciphertext
/// @param[out] ss      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKE128_Response(uint8_t ct[DKE1_CPA_CTBYTES],
                      uint8_t ss[DKE1_SSBYTES],
                      const uint8_t pk[DKE1_PKBYTES],
                      const uint8_t coins[DKE1_SEEDBYTES + DKE1_N / 8]);

/// @brief Implements DKE.DeriveSecret for DKEM-128
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKE128_DeriveSecret(uint8_t ss[DKE1_SSBYTES],
                          const uint8_t sk[DKE1_CPA_SKABYTES],
                          const uint8_t ct[DKE1_CPA_CTBYTES]);