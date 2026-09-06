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

void DKEM512_KeyGen(uint8_t pk[DKE3_PKBYTES],
                          uint8_t sk[DKE3_SKBYTES],
                          const uint8_t coins[DKE3_SEEDBYTES + DKE3_SSBYTES]) {
    DKE512_Initiate(pk, sk, coins);
    memcpy(sk + DKE3_CPA_SKABYTES, pk, DKE3_PKBYTES); // sk = (skCPA | pk | rej)
    memcpy(sk + DKE3_CPA_SKABYTES + DKE3_PKBYTES, coins + DKE3_SEEDBYTES, DKE3_SSBYTES);
}

void DKEM512_Internal(uint8_t ct[DKE3_CTBYTES],
                        uint8_t k[DKE3_SSBYTES],
                        const uint8_t pk[DKE3_PKBYTES],
                        const uint8_t coins[DKE3_SEEDBYTES]) {

    uint8_t r[2*DKE3_SSBYTES];      // will contain r
    uint8_t ss[DKE3_SSBYTES];       // will contain provisional shared secret

    uint8_t buffer[2 * DKE3_SEEDBYTES];               // will contain (coins|seed)

    memcpy(buffer, coins, DKE3_SEEDBYTES);
    memcpy(buffer + DKE3_SEEDBYTES, pk + DKE3_PKBYTES - DKE3_SEEDBYTES, DKE3_SEEDBYTES);

#ifdef USE_KECCAK
    shake256(r, 2 * DKE3_SSBYTES, buffer, 2 * DKE3_SEEDBYTES);
#else
    pseudoXOF(16 * DKE3_SSBYTES, buffer, DKE3_SEEDBYTES * 16, r);
#endif

    // CPA protocol
    DKE512_Response(ct,
                       ss,
                       pk,
                       r);

    // pseudohash only for this parameter set
#ifdef USE_KECCAK
    sha3_512(k, ss, DKE3_SSBYTES);
#else
    pseudohash(512, ss, (DKE3_SSBYTES) * 8, k);
#endif

    // In place one time pad
    unsigned int i = 0;
    for (i  = 0; i < DKE3_SSBYTES; i++) {
        ss[i] ^= coins[i];
    }

    // Emplace the tag
    memcpy(ct + DKE3_CPA_CTBYTES, ss, DKE3_SSBYTES);
}

void DKEM512_Decaps(uint8_t ss[DKE3_SSBYTES],
                 const uint8_t sk[DKE3_SKBYTES],
                 const uint8_t ct[DKE3_CTBYTES]) {

    int fail;                       // will be 1 if ctA != ctB
    uint8_t coins[DKE3_SSBYTES];    // will contain the tag and,
                                    // after undoing the OTP, the randomness coins
    uint8_t ssA[DKE3_SSBYTES];
    memcpy(coins, ct + DKE3_CPA_CTBYTES, DKE3_SSBYTES);
    // At this stage, coins is yet the tag

    // CPA decryption
    DKE512_DeriveSecret(ssA, sk, ct);

    // Undo in place one time pad
    unsigned int i = 0;
    for (i  = 0; i < DKE3_SSBYTES; i++) {
        coins[i] ^= ssA[i];
    }

    // Re-encript
    uint8_t ctA[DKE3_CTBYTES];
    uint8_t k[DKE3_SSBYTES];        // will contain true key

    // CPA FO encryption
    DKEM512_Internal(ctA,
                        k,
                        sk + DKE3_CPA_SKABYTES,
                        coins);

    // ct == ctA?
    fail = DKE3_verify(ct, ctA, DKE3_CTBYTES);

    // rejection key: H(rej || tag), where tag = last SSBYTES of ct holds all ct-entropy

    uint8_t rej_buf[2 * DKE3_SSBYTES];
    memcpy(rej_buf, sk + DKE3_SKBYTES - DKE3_SSBYTES, DKE3_SSBYTES);
    memcpy(rej_buf + DKE3_SSBYTES, ct + DKE3_CPA_CTBYTES, DKE3_SSBYTES);

    // rej_key -> ss
    // pseudohash only for this parameter set; otherwise -> sm3hash
#ifdef USE_KECCAK
    sha3_512(ss, rej_buf, 2 * DKE3_SSBYTES);
#else
    pseudohash(512, rej_buf, 2 * (DKE3_SSBYTES) * 8, ss);
#endif

    // Implicit rejection
    DKE3_cmov(ss, k, DKE3_SSBYTES, (uint8_t) (1 - fail));
}