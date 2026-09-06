#ifndef ADKEX_PARAMETERS_H
#define ADKEX_PARAMETERS_H

/*
ADKEX-256 (KEMTLS-PDK) parameters.
Sizes are stated in BITS
*/
#include "parameters.h"

/* Number of protocol passes. */
#define ADKEX2_PASSES_NUM       2

/* Lattice dimension N  */
#define ADKEX2_N                DKE2_N


#define ADKEX2_SEEDBITS         (8 * (DKE2_SEEDBYTES))
#define ADKEX2_SSBITS           (8 * (DKE2_SSBYTES))
#define ADKEX2_PKBITS           (8 * (DKE2_PKBYTES))
#define ADKEX2_SKBITS           (8 * (DKE2_SKBYTES))
#define ADKEX2_CTBITS           (8 * (DKE2_CTBYTES))

/* Final shared-key bit-length. */
#define ADKEX2_KDF_OUTBITS      ADKEX2_SSBITS


#define ADKEX2_M1_BITS          (ADKEX2_PKBITS + ADKEX2_CTBITS)
#define ADKEX2_M2_BITS          (ADKEX2_CTBITS)
#define ADKEX2_TOTAL_MSG_BITS   (ADKEX2_M1_BITS + ADKEX2_M2_BITS)

/* State buffer sizes (BITS).
   st_A = sk_e || ss_s || m_1
   st_B = ss_e || ss_s || T    */
#define ADKEX2_STA_MAX_BITS     (ADKEX2_SKBITS + ADKEX2_SSBITS + ADKEX2_M1_BITS)
#define ADKEX2_STB_MAX_BITS     (3 * ADKEX2_SSBITS)

/* Bit-offsets into st_A (sk_e || ss_s || m_1). */
#define ADKEX2_STA_OFF_SK_E_BITS  0
#define ADKEX2_STA_OFF_SS_S_BITS  (ADKEX2_SKBITS)
#define ADKEX2_STA_OFF_M1_BITS    (ADKEX2_SKBITS + ADKEX2_SSBITS)

/* Bit-offsets into st_B (ss_e || ss_s || T). */
#define ADKEX2_STB_OFF_SS_E_BITS  0
#define ADKEX2_STB_OFF_SS_S_BITS  (ADKEX2_SSBITS)
#define ADKEX2_STB_OFF_T_BITS     (2 * ADKEX2_SSBITS)

/* Randomness consumed by each derandomized call (BITS).
   init_b : DKEM.KeyGen consumes SEED + SS
   pass1  : DKEM.KeyGen (SEED + SS) bundled with DKEM.Encaps (SEED)
   pass2  : DKEM.Encaps consumes SEED */
#define ADKEX2_INIT_B_COINBITS          (ADKEX2_SEEDBITS + ADKEX2_SSBITS)
#define ADKEX2_PASS1_KEYGEN_COINBITS    (ADKEX2_SEEDBITS + ADKEX2_SSBITS)
#define ADKEX2_PASS1_ENCAPS_COINBITS    (ADKEX2_SEEDBITS)
#define ADKEX2_PASS1_COINBITS           (ADKEX2_PASS1_KEYGEN_COINBITS + ADKEX2_PASS1_ENCAPS_COINBITS)
#define ADKEX2_PASS2_COINBITS           (ADKEX2_SEEDBITS)

/* Fixed ASCII domain-separation label */
#define ADKEX2_LABEL            "ADKEX-KEMTLS-256"
#define ADKEX2_LABEL_BITS       128

/* Size of LABEL || pk_B || m_1 || m_2 (BITS). */
#define ADKEX2_TRANSCRIPT_BITS  (ADKEX2_LABEL_BITS + ADKEX2_PKBITS + ADKEX2_M1_BITS + ADKEX2_M2_BITS)

#endif /* ADKEX_PARAMETERS_H */
