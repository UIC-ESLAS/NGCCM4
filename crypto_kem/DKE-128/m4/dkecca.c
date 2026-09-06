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

void DKEM128_KeyGen(uint8_t pk[DKE1_PKBYTES],
                    uint8_t sk[DKE1_SKBYTES],
                    const uint8_t coins[DKE1_SEEDBYTES + DKE1_SSBYTES])
{
    DKE128_Initiate(pk, sk, coins);
    memcpy(sk + DKE1_CPA_SKABYTES, pk, DKE1_PKBYTES); // sk = (skCPA | pk | rej)
    memcpy(sk + DKE1_CPA_SKABYTES + DKE1_PKBYTES, coins + DKE1_SEEDBYTES, DKE1_SSBYTES);
}

void DKEM128_Internal(uint8_t ct[DKE1_CTBYTES],
                      uint8_t k[DKE1_SSBYTES],
                      const uint8_t pk[DKE1_PKBYTES],
                      const uint8_t coins[DKE1_SEEDBYTES])
{

    uint8_t r[2 * DKE1_SSBYTES];        // will contain r
    uint8_t ss[DKE1_SSBYTES];           // will contain provisional shared secret
    uint8_t buffer[2 * DKE1_SEEDBYTES]; // will contain (coins|seed)

    memcpy(buffer, coins, DKE1_SEEDBYTES);
    memcpy(buffer + DKE1_SEEDBYTES, pk + DKE1_PKBYTES - DKE1_SEEDBYTES, DKE1_SEEDBYTES);

#ifdef USE_KECCAK
    shake256(r, 2 * DKE1_SSBYTES, buffer, 2 * DKE1_SEEDBYTES);
#else
    pseudoXOF(16 * DKE1_SSBYTES, buffer, DKE1_SEEDBYTES * 16, r);
#endif
    // CPA protocol
    DKE128_Response(ct,
                     ss,
                     pk,
                     r);

#ifdef USE_KECCAK
    sha3_256(k, ss, DKE1_SSBYTES);
#else
    sm3hash(256, ss, (DKE1_SSBYTES) * 8, k);
#endif

    // In place one time pad
    unsigned int i = 0;
    for (i = 0; i < DKE1_SSBYTES; i++)
    {
        ss[i] ^= coins[i];
    }

    // Emplace the tag
    memcpy(ct + DKE1_CPA_CTBYTES, ss, DKE1_SSBYTES);
}

void DKEM128_Decaps(uint8_t ss[DKE1_SSBYTES],
                    const uint8_t sk[DKE1_SKBYTES],
                    const uint8_t ct[DKE1_CTBYTES])
{

    int fail;                    // will be 1 if ctA != ctB
    uint8_t coins[DKE1_SSBYTES]; // will contain the tag and,
                                 // after undoing the OTP, the randomness coins
    uint8_t ssA[DKE1_SSBYTES];
    memcpy(coins, ct + DKE1_CPA_CTBYTES, DKE1_SSBYTES);
    // At this stage, coins is yet the tag

    // CPA decryption
    DKE128_DeriveSecret(ssA, sk, ct);

    // Undo in place one time pad
    unsigned int i = 0;
    for (i = 0; i < DKE1_SSBYTES; i++)
    {
        coins[i] ^= ssA[i];
    }

    // Re-encript
    uint8_t ctA[DKE1_CTBYTES];
    uint8_t k[DKE1_SSBYTES]; // will contain true key

    // CPA FO encryption
    DKEM128_Internal(ctA,
                     k,
                     sk + DKE1_CPA_SKABYTES,
                     coins);

    // ct == ctA?
    fail = DKE1_verify(ct, ctA, DKE1_CTBYTES);

    // rejection key: H(rej || tag), where tag = last SSBYTES of ct holds all ct-entropy

    uint8_t rej_buf[2 * DKE1_SSBYTES];
    memcpy(rej_buf, sk + DKE1_SKBYTES - DKE1_SSBYTES, DKE1_SSBYTES);
    memcpy(rej_buf + DKE1_SSBYTES, ct + DKE1_CPA_CTBYTES, DKE1_SSBYTES);

    // rej_key -> ss
#ifdef USE_KECCAK
    sha3_256(ss, rej_buf, 2 * DKE1_SSBYTES);
#else
    sm3hash(256, rej_buf, 2 * (DKE1_SSBYTES) * 8, ss);
#endif

    // Implicit rejection
    DKE1_cmov(ss, k, DKE1_SSBYTES, (uint8_t)(1 - fail));
}
