#include "parameters.h"
#include <stdint.h>

/// @brief Implements DKE.Initiate for DKEM-512
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKE512_Initiate(uint8_t pk[DKE3_PKBYTES],
                      uint8_t sk[DKE3_CPA_SKABYTES],
                      const uint8_t coins[DKE3_SEEDBYTES]);

/// @brief Implements DKE.Response for DKEM-512
/// @param[out] ct      pointer to output ciphertext
/// @param[out] ss      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKE512_Response(uint8_t ct[DKE3_CPA_CTBYTES],
                      uint8_t ss[DKE3_SSBYTES],
                      const uint8_t pk[DKE3_PKBYTES],
                      const uint8_t coins[DKE3_SEEDBYTES + DKE3_N / 8]);

/// @brief Implements DKE.DeriveSecret for DKEM-512
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKE512_DeriveSecret(uint8_t ss[DKE3_SSBYTES],
                          const uint8_t sk[DKE3_CPA_SKABYTES],
                          const uint8_t ct[DKE3_CPA_CTBYTES]);