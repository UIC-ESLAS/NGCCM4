#include "parameters.h"
#include <stdint.h>



/// @brief Implements DKE.Initiate for DKEM-256
/// @param[in]  coins random coins
/// @param[out] pk    public key
/// @param[out] sk    secret key
void DKE256_Initiate(uint8_t pk[DKE2_PKBYTES],
                          uint8_t sk[DKE2_CPA_SKABYTES],
                          const uint8_t coins[DKE2_SEEDBYTES]);


/// @brief Implements DKE.Response for DKEM-256
/// @param[out] ct      pointer to output ciphertext
/// @param[out] ss      pointer to output shared key
/// @param[in]  pk      pointer to input public key
/// @param[in]  coins   pointer to input random coins
void DKE256_Response(uint8_t ct[DKE2_CPA_CTBYTES],
                        uint8_t ss[DKE2_SSBYTES],
                        const uint8_t pk[DKE2_PKBYTES],
                        const uint8_t coins[DKE2_SEEDBYTES + DKE2_N/8]);

/// @brief Implements DKE.DeriveSecret for DKEM-256
/// @param[out] ss      pointer to output shared key
/// @param[in]  sk      pointer to input secret key
/// @param[in]  ct      pointer to input ciphertext
void DKE256_DeriveSecret(uint8_t ss[DKE2_SSBYTES],
                 const uint8_t sk[DKE2_CPA_SKABYTES],
                 const uint8_t ct[DKE2_CPA_CTBYTES]);