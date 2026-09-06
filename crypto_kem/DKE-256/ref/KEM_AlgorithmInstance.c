/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "KEM_AlgorithmInstance.h"
#include "parameters.h"

#include "dkecpa.h"
#include "dkecca.h"

// DRNG_ctx for generating pseudorandom numbers within the KEM scheme
#ifdef USE_KECCAK
#include "randombytes.h"
#else
#include "drng.h"
extern DRNG_ctx drng_algorithm;
#endif

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

unsigned long long kem_get_pk_len_bytes()
{
	return DKE2_PKBYTES;
}

unsigned long long kem_get_sk_len_bytes()
{
	return DKE2_SKBYTES;
}

unsigned long long kem_get_ss_len_bytes()
{
	return DKE2_SSBYTES;
}

unsigned long long kem_get_ct_len_bytes()
{
	return DKE2_CTBYTES;
}

int kem_keygen(
	unsigned char *pk, unsigned long long *pk_len_bytes,
	unsigned char *sk, unsigned long long *sk_len_bytes)
{
	// randomization:
	uint8_t coins[DKE2_SEEDBYTES + DKE2_SSBYTES];
#ifdef USE_KECCAK
	randombytes(coins, (DKE2_SEEDBYTES + DKE2_SSBYTES));
#else
	get_random_number(&drng_algorithm, coins, (DKE2_SEEDBYTES + DKE2_SSBYTES) * 8);
#endif
	// SCHEME -------------------------------------------
	DKEM256_KeyGen(pk,sk,coins);
	*pk_len_bytes = DKE2_PKBYTES;
	*sk_len_bytes = DKE2_SKBYTES;
	return 0;
}

int kem_enc(
	unsigned char *pk, unsigned long long pk_len_bytes,
	unsigned char *ss, unsigned long long *ss_len_bytes,
	unsigned char *ct, unsigned long long *ct_len_bytes)
{
	// randomization:
	uint8_t coins[DKE2_SEEDBYTES];
#ifdef USE_KECCAK
	randombytes(coins, DKE2_SEEDBYTES);
#else
	get_random_number(&drng_algorithm, coins, DKE2_SEEDBYTES * 8);
#endif
	// SCHEME -------------------------------------------
	DKEM256_Internal(ct, ss, pk, coins);
	*ss_len_bytes = DKE2_SSBYTES;
	*ct_len_bytes = DKE2_CTBYTES;
	return 0;
}

int kem_dec(
	unsigned char *sk, unsigned long long sk_len_bytes,
	unsigned char *ct, unsigned long long ct_len_bytes,
	unsigned char *ss, unsigned long long *ss_len_bytes)
{
	DKEM256_Decaps(ss, sk, ct);
	*ss_len_bytes = DKE2_SSBYTES;
	return 0;
}