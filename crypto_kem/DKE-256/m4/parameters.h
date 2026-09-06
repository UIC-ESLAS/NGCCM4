#ifndef PARAMETERS_H
#define PARAMETERS_H

// Protocol parameters--------------------------------------------------------
#define DKE2_N 256  // polynomial's degree
#define DKE2_Q 3329 // modulus
#define DKE2_K 4    // module dimension
#define DKE2_DA 12  // pk rounding parameter
#define DKE2_DB 11  // ct rounding parameter
#define DKE2_L 5    // number of bits for each hint
#define DKE2_ETA 2  // unified centered binomial parameter

// Sizes (bytes)-------------------------------------------------------------
#define DKE2_SEEDBYTES 32

#define DKE2_POLYBYTES 12 * DKE2_N / 8
#define DKE2_POLYVECBYTES DKE2_K *DKE2_POLYBYTES

#define DKE2_PACOMPRESSEDBYTES (DKE2_K * DKE2_DA * DKE2_N) / 8 // pA'
#define DKE2_PBCOMPRESSEDBYTES (DKE2_K * DKE2_DB * DKE2_N) / 8 // pB'
#define DKE2_SIGNALBYTES DKE2_L *DKE2_N / 8

#define DKE2_SSBYTES 32 // Bytes in the shared secret key

// Public keys:
#define DKE2_PKBYTES DKE2_PACOMPRESSEDBYTES + DKE2_SEEDBYTES
#define DKE2_CPA_CTBYTES DKE2_PBCOMPRESSEDBYTES + DKE2_SIGNALBYTES
#define DKE2_CTBYTES DKE2_CPA_CTBYTES + DKE2_SSBYTES // ct + tag

// Secret keys:
#define DKE2_CPA_SKABYTES (DKE2_K * DKE2_N * 12) / 8 // just sA
#define DKE2_CPA_SKBBYTES (DKE2_K * DKE2_N * 12) / 8 // just sB
#define DKE2_SKBYTES DKE2_CPA_SKABYTES + DKE2_PKBYTES + DKE2_SSBYTES
// sk + pk + rejection value (needed for FO)
// ------------------------------------------------------------------------------

#endif // PARAMETERS_H
