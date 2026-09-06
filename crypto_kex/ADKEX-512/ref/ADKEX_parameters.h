#ifndef ADKEX_PARAMETERS_H
#define ADKEX_PARAMETERS_H

/*
ADKEX-512 (KEMTLS-PDK) parameters.

Sizes are stated in BITS

*/
#include "parameters.h"

/* Number of protocol passes. */
#define ADKEX3_PASSES_NUM       2

/* Lattice dimension N  */
#define ADKEX3_N                DKE3_N

/* Primitive sizes (BITS)*/
#define ADKEX3_SEEDBITS         (8 * (DKE3_SEEDBYTES))
#define ADKEX3_SSBITS           (8 * (DKE3_SSBYTES))
#define ADKEX3_PKBITS           (8 * (DKE3_PKBYTES))
#define ADKEX3_SKBITS           (8 * (DKE3_SKBYTES))
#define ADKEX3_CTBITS           (8 * (DKE3_CTBYTES))

/* Final shared-key bit-length. */
#define ADKEX3_KDF_OUTBITS      ADKEX3_SSBITS


#define ADKEX3_M1_BITS          (ADKEX3_PKBITS + ADKEX3_CTBITS)
#define ADKEX3_M2_BITS          (ADKEX3_CTBITS)
#define ADKEX3_TOTAL_MSG_BITS   (ADKEX3_M1_BITS + ADKEX3_M2_BITS)

/* State buffer sizes (BITS).
   st_A = sk_e || ss_s || m_1
   st_B = ss_e || ss_s || T */
#define ADKEX3_STA_MAX_BITS     (ADKEX3_SKBITS + ADKEX3_SSBITS + ADKEX3_M1_BITS)
#define ADKEX3_STB_MAX_BITS     (3 * ADKEX3_SSBITS)

/* Bit-offsets into st_A (sk_e || ss_s || m_1). */
#define ADKEX3_STA_OFF_SK_E_BITS  0
#define ADKEX3_STA_OFF_SS_S_BITS  (ADKEX3_SKBITS)
#define ADKEX3_STA_OFF_M1_BITS    (ADKEX3_SKBITS + ADKEX3_SSBITS)

/* Bit-offsets into st_B (ss_e || ss_s || T). */
#define ADKEX3_STB_OFF_SS_E_BITS  0
#define ADKEX3_STB_OFF_SS_S_BITS  (ADKEX3_SSBITS)
#define ADKEX3_STB_OFF_T_BITS     (2 * ADKEX3_SSBITS)

/* Randomness consumed by each derandomized call (BITS).
   init_b : DKEM.KeyGen consumes SEED + SS
   pass1  : DKEM.KeyGen (SEED + SS) bundled with DKEM.Encaps (SEED)
   pass2  : DKEM.Encaps consumes SEED */
#define ADKEX3_INIT_B_COINBITS          (ADKEX3_SEEDBITS + ADKEX3_SSBITS)
#define ADKEX3_PASS1_KEYGEN_COINBITS    (ADKEX3_SEEDBITS + ADKEX3_SSBITS)
#define ADKEX3_PASS1_ENCAPS_COINBITS    (ADKEX3_SEEDBITS)
#define ADKEX3_PASS1_COINBITS           (ADKEX3_PASS1_KEYGEN_COINBITS + ADKEX3_PASS1_ENCAPS_COINBITS)
#define ADKEX3_PASS2_COINBITS           (ADKEX3_SEEDBITS)

/* Fixed ASCII domain-separation label, variant-specific
   (16 bytes = 128 bits, no terminator). The variant suffix prevents
   transcript-hash collisions across security levels and across the
   sibling KEX+SIG submission. */
#define ADKEX3_LABEL            "ADKEX-KEMTLS-512"
#define ADKEX3_LABEL_BITS       128

/* Size of LABEL || pk_B || m_1 || m_2 (BITS). */
#define ADKEX3_TRANSCRIPT_BITS  (ADKEX3_LABEL_BITS + ADKEX3_PKBITS + ADKEX3_M1_BITS + ADKEX3_M2_BITS)

#endif /* ADKEX_PARAMETERS_H */
