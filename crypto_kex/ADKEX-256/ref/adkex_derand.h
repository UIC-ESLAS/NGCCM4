#ifndef ADKEX_DERAND_H
#define ADKEX_DERAND_H

#include <stdint.h>
#include "ADKEX_parameters.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// @brief Derandomized DKEM key pair generation for ADKEX-256 responder
/// @param[out] pk_B  responder encapsulation key
/// @param[out] sk_B  responder decapsulation key
/// @param[in]  coins random coins (SEED || SS)
void ADKEX256_init_b_derand(
    uint8_t pk_B[ADKEX2_PKBITS / 8],
    uint8_t sk_B[ADKEX2_SKBITS / 8],
    const uint8_t coins[ADKEX2_INIT_B_COINBITS / 8]);

/// @brief Derandomized pass-1 (A -> B) for ADKEX-256
/// @param[out] m1    pass-1 message m_1 = M_1 || ct_S
/// @param[out] sta   initiator state sk_e || ss_s || m_1
/// @param[in]  pk_B  responder encapsulation key (pre-distributed)
/// @param[in]  coins random coins (rho_1 || rho_3)
void ADKEX256_pass1_msg_a_derand(
    uint8_t m1[ADKEX2_M1_BITS / 8],
    uint8_t sta[ADKEX2_STA_MAX_BITS / 8],
    const uint8_t pk_B[ADKEX2_PKBITS / 8],
    const uint8_t coins[ADKEX2_PASS1_COINBITS / 8]);

/// @brief Derandomized pass-2 (B -> A) for ADKEX-256
/// @param[out] m2    pass-2 message m_2 = M_2
/// @param[out] stb   responder state ss_e || ss_s || T
/// @param[in]  m1    pass-1 message
/// @param[in]  pk_B  responder encapsulation key
/// @param[in]  sk_B  responder decapsulation key
/// @param[in]  coins random coins (rho_2)
void ADKEX256_pass2_msg_b_derand(
    uint8_t m2[ADKEX2_M2_BITS / 8],
    uint8_t stb[ADKEX2_STB_MAX_BITS / 8],
    const uint8_t m1[ADKEX2_M1_BITS / 8],
    const uint8_t pk_B[ADKEX2_PKBITS / 8],
    const uint8_t sk_B[ADKEX2_SKBITS / 8],
    const uint8_t coins[ADKEX2_PASS2_COINBITS / 8]);

/// @brief ADKEX-256 final shared-key derivation by the initiator
/// @param[out] ss    shared secret
/// @param[in]  m2    last responder message
/// @param[in]  sta   initiator state
/// @param[in]  pk_B  responder encapsulation key
void ADKEX256_derive_ss_a(
    uint8_t ss[ADKEX2_SSBITS / 8],
    const uint8_t m2[ADKEX2_M2_BITS / 8],
    const uint8_t sta[ADKEX2_STA_MAX_BITS / 8],
    const uint8_t pk_B[ADKEX2_PKBITS / 8]);

/// @brief ADKEX-256 final shared-key derivation by the responder
/// @param[out] ss   shared secret
/// @param[in]  stb  responder state (ss_e || ss_s || T)
void ADKEX256_derive_ss_b(
    uint8_t ss[ADKEX2_SSBITS / 8],
    const uint8_t stb[ADKEX2_STB_MAX_BITS / 8]);

#ifdef __cplusplus
}
#endif
#endif /* ADKEX_DERAND_H */
