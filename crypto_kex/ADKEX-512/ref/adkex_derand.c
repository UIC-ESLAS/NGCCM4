#include <string.h>
#include <stdint.h>

#include "adkex_derand.h"
#include "ADKEX_parameters.h"
#include "auxfunc.h"

#include "dkecca.h"

// T <- H(LABEL || pk_B || m_1 || m_2; n).  n=512 so use pseudoXOF.
static void adkex512_transcript(
    uint8_t T[ADKEX3_SSBITS / 8],
    const uint8_t pk_B[ADKEX3_PKBITS / 8],
    const uint8_t m1[ADKEX3_M1_BITS / 8],
    const uint8_t m2[ADKEX3_M2_BITS / 8])
{
    uint8_t buf[ADKEX3_TRANSCRIPT_BITS / 8];
    uint8_t *p = buf;

    memcpy(p, ADKEX3_LABEL, ADKEX3_LABEL_BITS / 8); p += ADKEX3_LABEL_BITS / 8;
    memcpy(p, pk_B,         ADKEX3_PKBITS    / 8);  p += ADKEX3_PKBITS    / 8;
    memcpy(p, m1,           ADKEX3_M1_BITS   / 8);  p += ADKEX3_M1_BITS   / 8;
    memcpy(p, m2,           ADKEX3_M2_BITS   / 8);

    pseudoXOF(ADKEX3_KDF_OUTBITS, buf, ADKEX3_TRANSCRIPT_BITS, T);

    memset(buf, 0, sizeof buf);
}

void ADKEX512_init_b_derand(
    uint8_t pk_B[ADKEX3_PKBITS / 8],
    uint8_t sk_B[ADKEX3_SKBITS / 8],
    const uint8_t coins[ADKEX3_INIT_B_COINBITS / 8])
{
    DKEM512_KeyGen(pk_B, sk_B, coins);
}

void ADKEX512_pass1_msg_a_derand(
    uint8_t m1[ADKEX3_M1_BITS / 8],
    uint8_t sta[ADKEX3_STA_MAX_BITS / 8],
    const uint8_t pk_B[ADKEX3_PKBITS / 8],
    const uint8_t coins[ADKEX3_PASS1_COINBITS / 8])
{
    uint8_t *sk_e      = sta + ADKEX3_STA_OFF_SK_E_BITS / 8;
    uint8_t *ss_s      = sta + ADKEX3_STA_OFF_SS_S_BITS / 8;
    uint8_t *m1_in_sta = sta + ADKEX3_STA_OFF_M1_BITS   / 8;

    // (M_1, sk_e) <- DKEM.KeyGen(rho_1)
    DKEM512_KeyGen(m1, sk_e, coins);

    // (ss_s, ct_S) <- DKEM.Encaps(pk_B, rho_3)
    DKEM512_Internal(m1 + ADKEX3_PKBITS / 8, ss_s, pk_B,
                     coins + ADKEX3_PASS1_KEYGEN_COINBITS / 8);

    // stash m_1 for derive_ss_a's transcript recomputation
    memcpy(m1_in_sta, m1, ADKEX3_M1_BITS / 8);
}

void ADKEX512_pass2_msg_b_derand(
    uint8_t m2[ADKEX3_M2_BITS / 8],
    uint8_t stb[ADKEX3_STB_MAX_BITS / 8],
    const uint8_t m1[ADKEX3_M1_BITS / 8],
    const uint8_t pk_B[ADKEX3_PKBITS / 8],
    const uint8_t sk_B[ADKEX3_SKBITS / 8],
    const uint8_t coins[ADKEX3_PASS2_COINBITS / 8])
{
    const uint8_t *M_1  = m1;
    const uint8_t *ct_S = m1 + ADKEX3_PKBITS / 8;

    uint8_t *ss_e = stb + ADKEX3_STB_OFF_SS_E_BITS / 8;
    uint8_t *ss_s = stb + ADKEX3_STB_OFF_SS_S_BITS / 8;
    uint8_t *T    = stb + ADKEX3_STB_OFF_T_BITS    / 8;

    // (ss_e, M_2) <- DKEM.Encaps(M_1, rho_2)
    DKEM512_Internal(m2, ss_e, M_1, coins);

    // ss_s <- DKEM.Decaps(sk_B, ct_S)
    DKEM512_Decaps(ss_s, sk_B, ct_S);

    adkex512_transcript(T, pk_B, m1, m2);
}

void ADKEX512_derive_ss_a(
    uint8_t ss[ADKEX3_SSBITS / 8],
    const uint8_t m2[ADKEX3_M2_BITS / 8],
    const uint8_t sta[ADKEX3_STA_MAX_BITS / 8],
    const uint8_t pk_B[ADKEX3_PKBITS / 8])
{
    const uint8_t *sk_e = sta + ADKEX3_STA_OFF_SK_E_BITS / 8;
    const uint8_t *ss_s = sta + ADKEX3_STA_OFF_SS_S_BITS / 8;
    const uint8_t *m1   = sta + ADKEX3_STA_OFF_M1_BITS   / 8;

    uint8_t kdf_in[(3 * ADKEX3_SSBITS) / 8];     // ss_e || ss_s || T

    DKEM512_Decaps(kdf_in, sk_e, m2);
    memcpy(kdf_in + ADKEX3_SSBITS / 8, ss_s, ADKEX3_SSBITS / 8);
    adkex512_transcript(kdf_in + 2 * (ADKEX3_SSBITS / 8), pk_B, m1, m2);

    pseudoXOF(ADKEX3_KDF_OUTBITS, kdf_in, 3 * ADKEX3_SSBITS, ss);

    memset(kdf_in, 0, sizeof kdf_in);
}

void ADKEX512_derive_ss_b(
    uint8_t ss[ADKEX3_SSBITS / 8],
    const uint8_t stb[ADKEX3_STB_MAX_BITS / 8])
{
    pseudoXOF(ADKEX3_KDF_OUTBITS, stb, 3 * ADKEX3_SSBITS, ss);
}
