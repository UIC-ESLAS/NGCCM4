#ifndef ADKEX_PARAMETERS_H
#define ADKEX_PARAMETERS_H

/*
ADKEX-128 (KEMTLS-PDK) parameters.
Sizes are stated in BITS.

*/
#include "parameters.h"

/* Number of protocol passes. */
#define ADKEX1_PASSES_NUM       2

/* Lattice dimension N */
#define ADKEX1_N                DKE1_N

#define ADKEX1_SEEDBITS         (8 * (DKE1_SEEDBYTES))
#define ADKEX1_SSBITS           (8 * (DKE1_SSBYTES))
#define ADKEX1_PKBITS           (8 * (DKE1_PKBYTES))
#define ADKEX1_SKBITS           (8 * (DKE1_SKBYTES))
#define ADKEX1_CTBITS           (8 * (DKE1_CTBYTES))

/* Final shared-key bit-length (= n in the spec). */
#define ADKEX1_KDF_OUTBITS      ADKEX1_SSBITS

/* Wire-message sizes (BITS). */
#define ADKEX1_M1_BITS          (ADKEX1_PKBITS + ADKEX1_CTBITS)
#define ADKEX1_M2_BITS          (ADKEX1_CTBITS)
#define ADKEX1_TOTAL_MSG_BITS   (ADKEX1_M1_BITS + ADKEX1_M2_BITS)

/* State buffer sizes (BITS).
   st_A = sk_e || ss_s || m_1
   st_B = ss_e || ss_s || T    */
#define ADKEX1_STA_MAX_BITS     (ADKEX1_SKBITS + ADKEX1_SSBITS + ADKEX1_M1_BITS)
#define ADKEX1_STB_MAX_BITS     (3 * ADKEX1_SSBITS)

/* Bit-offsets into st_A (sk_e || ss_s || m_1). */
#define ADKEX1_STA_OFF_SK_E_BITS  0
#define ADKEX1_STA_OFF_SS_S_BITS  (ADKEX1_SKBITS)
#define ADKEX1_STA_OFF_M1_BITS    (ADKEX1_SKBITS + ADKEX1_SSBITS)

/* Bit-offsets into st_B (ss_e || ss_s || T). */
#define ADKEX1_STB_OFF_SS_E_BITS  0
#define ADKEX1_STB_OFF_SS_S_BITS  (ADKEX1_SSBITS)
#define ADKEX1_STB_OFF_T_BITS     (2 * ADKEX1_SSBITS)

/* Randomness consumed by each derandomized call
   init_b : DKEM.KeyGen consumes SEED + SS
   pass1  : DKEM.KeyGen (SEED + SS) bundled with DKEM.Encaps (SEED)
   pass2  : DKEM.Encaps consumes SEED */
#define ADKEX1_INIT_B_COINBITS          (ADKEX1_SEEDBITS + ADKEX1_SSBITS)
#define ADKEX1_PASS1_KEYGEN_COINBITS    (ADKEX1_SEEDBITS + ADKEX1_SSBITS)
#define ADKEX1_PASS1_ENCAPS_COINBITS    (ADKEX1_SEEDBITS)
#define ADKEX1_PASS1_COINBITS           (ADKEX1_PASS1_KEYGEN_COINBITS + ADKEX1_PASS1_ENCAPS_COINBITS)
#define ADKEX1_PASS2_COINBITS           (ADKEX1_SEEDBITS)

/* Fixed ASCII domain-separation label */
#define ADKEX1_LABEL            "ADKEX-KEMTLS-128"
#define ADKEX1_LABEL_BITS       128

/* Size of LABEL || pk_B || m_1 || m_2 (BITS). */
#define ADKEX1_TRANSCRIPT_BITS  (ADKEX1_LABEL_BITS + ADKEX1_PKBITS + ADKEX1_M1_BITS + ADKEX1_M2_BITS)

#endif /* ADKEX_PARAMETERS_H */
