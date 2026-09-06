#include "parameters.h"
#include "dkecpa.h"
#include "dkecca.h"
#include <stdint.h>
#include <string.h>
#include "verify.h"
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif

void DKEM256_KeyGen(uint8_t pk[DKE2_PKBYTES],
                    uint8_t sk[DKE2_SKBYTES],
                    const uint8_t coins[DKE2_SEEDBYTES + DKE2_SSBYTES])
{
    DKE256_Initiate(pk, sk, coins);
    memcpy(sk + DKE2_CPA_SKABYTES, pk, DKE2_PKBYTES); // sk = (skCPA | pk | rej)
    memcpy(sk + DKE2_CPA_SKABYTES + DKE2_PKBYTES, coins + DKE2_SEEDBYTES, DKE2_SSBYTES);
}

void DKEM256_Internal(uint8_t ct[DKE2_CTBYTES],
                      uint8_t k[DKE2_SSBYTES],
                      const uint8_t pk[DKE2_PKBYTES],
                      const uint8_t coins[DKE2_SEEDBYTES])
{

    uint8_t r[2 * DKE2_SSBYTES]; // will contain r
    uint8_t ss[DKE2_SSBYTES];    // will contain provisional shared secret

    uint8_t buffer[2 * DKE2_SEEDBYTES]; // will contain (coins|seed)

    memcpy(buffer, coins, DKE2_SEEDBYTES);
    memcpy(buffer + DKE2_SEEDBYTES, pk + DKE2_PKBYTES - DKE2_SEEDBYTES, DKE2_SEEDBYTES);

#ifdef USE_KECCAK
    shake256(r, 2 * DKE2_SSBYTES, buffer, 2 * DKE2_SEEDBYTES);
#else
    pseudoXOF(16 * DKE2_SSBYTES, buffer, DKE2_SEEDBYTES * 16, r);
#endif

    // CPA protocol
    DKE256_Response(ct,
                     ss,
                     pk,
                     r);

#ifdef USE_KECCAK
    sha3_256(k, ss, DKE2_SSBYTES);
#else
    sm3hash(256, ss, (DKE2_SSBYTES) * 8, k);
#endif

    // In place one time pad
    unsigned int i = 0;
    for (i = 0; i < DKE2_SSBYTES; i++)
    {
        ss[i] ^= coins[i];
    }

    // Emplace the tag
    memcpy(ct + DKE2_CPA_CTBYTES, ss, DKE2_SSBYTES);
}

void DKEM256_Decaps(uint8_t ss[DKE2_SSBYTES],
                    const uint8_t sk[DKE2_SKBYTES],
                    const uint8_t ct[DKE2_CTBYTES])
{

    int fail;                    // will be 1 if ctA != ctB
    uint8_t coins[DKE2_SSBYTES]; // will contain the tag and,
                                 // after undoing the OTP, the randomness coins
    uint8_t ssA[DKE2_SSBYTES];
    memcpy(coins, ct + DKE2_CPA_CTBYTES, DKE2_SSBYTES);
    // At this stage, coins is yet the tag

    // CPA decryption
    DKE256_DeriveSecret(ssA, sk, ct);

    // Undo in place one time pad
    unsigned int i = 0;
    for (i = 0; i < DKE2_SSBYTES; i++)
    {
        coins[i] ^= ssA[i];
    }

    // Re-encript
    uint8_t ctA[DKE2_CTBYTES];
    uint8_t k[DKE2_SSBYTES]; // will contain true key

    // CPA FO encryption
    DKEM256_Internal(ctA,
                     k,
                     sk + DKE2_CPA_SKABYTES,
                     coins);

    // ct == ctA?
    fail = DKE2_verify(ct, ctA, DKE2_CTBYTES);

    // rejection key: H(rej || tag), where tag = last SSBYTES of ct holds all ct-entropy

    uint8_t rej_buf[2 * DKE2_SSBYTES];
    memcpy(rej_buf, sk + DKE2_SKBYTES - DKE2_SSBYTES, DKE2_SSBYTES);
    memcpy(rej_buf + DKE2_SSBYTES, ct + DKE2_CPA_CTBYTES, DKE2_SSBYTES);

    // rej_key -> ss

#ifdef USE_KECCAK
    sha3_256(ss, rej_buf, 2 * DKE2_SSBYTES);
#else
    sm3hash(256, rej_buf, 2 * (DKE2_SSBYTES) * 8, ss);
#endif

    // Implicit rejection
    DKE2_cmov(ss, k, DKE2_SSBYTES, (uint8_t)(1 - fail));
}
