#ifndef PARAMETERS_H
#define PARAMETERS_H

#define DKE3_Q 7681
#define DKE3_N 512
#define DKE3_K 4
#define DKE3_DA 13 // pk rounding parameter
#define DKE3_DB 11 // ct rounding parameter
#define DKE3_L 4   // number of bits for each hint
#define DKE3_ETA 3 // unified centered binomial parameter

// Sizes (bytes)-------------------------------------------------------------
#define DKE3_SEEDBYTES 64

#define DKE3_POLYBYTES 13 * DKE3_N / 8
#define DKE3_POLYVECBYTES DKE3_K *DKE3_POLYBYTES

#define DKE3_PACOMPRESSEDBYTES (DKE3_K * DKE3_DA * DKE3_N) / 8 // pA'
#define DKE3_PBCOMPRESSEDBYTES (DKE3_K * DKE3_DB * DKE3_N) / 8 // pB'
#define DKE3_SIGNALBYTES DKE3_L *DKE3_N / 8

#define DKE3_SSBYTES 64 // Bytes in the shared secret key

// Public keys:
#define DKE3_PKBYTES DKE3_PACOMPRESSEDBYTES + DKE3_SEEDBYTES
#define DKE3_CPA_CTBYTES DKE3_PBCOMPRESSEDBYTES + DKE3_SIGNALBYTES
#define DKE3_CTBYTES DKE3_CPA_CTBYTES + DKE3_SSBYTES // ct + tag

// Secret keys:
#define DKE3_CPA_SKABYTES (DKE3_K * DKE3_N * 13) / 8 // just sA
#define DKE3_CPA_SKBBYTES (DKE3_K * DKE3_N * 13) / 8 // just sB
#define DKE3_SKBYTES DKE3_CPA_SKABYTES + DKE3_PKBYTES + DKE3_SSBYTES
// sk + pk + rejection value (needed for FO)
// ------------------------------------------------------------------------------

#endif // PARAMETERS_H
