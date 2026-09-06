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
#ifdef USE_KECCAK
#include "randombytes.h"
#else
#include "drng.h"
// DRNG_ctx for generating pseudorandom numbers within the KEM scheme
extern DRNG_ctx drng_algorithm;
#endif
#include "parameters.h"

#include "dkecpa.h"
#include "dkecca.h"

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

unsigned long long kem_get_pk_len_bytes()
{
	return DKE1_PKBYTES;
}

unsigned long long kem_get_sk_len_bytes()
{
	return DKE1_SKBYTES;
}

unsigned long long kem_get_ss_len_bytes()
{
	return DKE1_SSBYTES;
}

unsigned long long kem_get_ct_len_bytes()
{
	return DKE1_CTBYTES;
}

int kem_keygen(
	unsigned char* pk, unsigned long long* pk_len_bytes,
	unsigned char* sk, unsigned long long* sk_len_bytes)
{
	// randomization:
	uint8_t coins[DKE1_SEEDBYTES + DKE1_SSBYTES];
#ifdef USE_KECCAK
    randombytes(coins, (DKE1_SEEDBYTES + DKE1_SSBYTES));
#else
	get_random_number(&drng_algorithm, coins, (DKE1_SEEDBYTES + DKE1_SSBYTES) * 8);
#endif
	// SCHEME -------------------------------------------
	DKEM128_KeyGen(pk, sk, coins);
	*pk_len_bytes = DKE1_PKBYTES;
	*sk_len_bytes = DKE1_SKBYTES;
	return 0;
}

int kem_enc(
	unsigned char* pk, unsigned long long pk_len_bytes,
	unsigned char* ss, unsigned long long* ss_len_bytes,
	unsigned char* ct, unsigned long long* ct_len_bytes)
{
	// randomization:
	uint8_t coins[DKE1_SEEDBYTES];
#ifdef USE_KECCAK
    randombytes(coins, DKE1_SEEDBYTES);
#else
	get_random_number(&drng_algorithm, coins, DKE1_SEEDBYTES * 8);
#endif
	DKEM128_Internal(ct, ss, pk, coins);
	*ss_len_bytes = DKE1_SSBYTES;
	*ct_len_bytes = DKE1_CTBYTES;
	return 0;
}

int kem_dec(
	unsigned char* sk, unsigned long long sk_len_bytes,
	unsigned char* ct, unsigned long long ct_len_bytes,
	unsigned char* ss, unsigned long long* ss_len_bytes)
{
	DKEM128_Decaps(ss, sk, ct);
	*ss_len_bytes = DKE1_SSBYTES;
	return 0;
}
