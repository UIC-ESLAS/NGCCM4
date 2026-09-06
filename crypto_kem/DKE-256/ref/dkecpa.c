#include "parameters.h"
#include "dkecpa.h"
#include "poly.h"
#include "polyvec.h"
#include "random_sampling.h"
#include "dke_utils.h"
#include <stdint.h>
#include <string.h>
#include "packing.h"
#include <stdio.h>
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif

void DKE256_Initiate(uint8_t pk[DKE2_PKBYTES],
                          uint8_t sk[DKE2_CPA_SKABYTES],
                          const uint8_t coins[DKE2_SEEDBYTES]) {

    // buffer will contain (seed | rand)  (seed for matrix / rand for secret and noise polyvec)
    uint8_t buffer[2 * DKE2_SEEDBYTES];
    const uint8_t *seed = buffer;
    const uint8_t *rand = buffer + DKE2_SEEDBYTES;

    // init matrix
    polyvec mat[DKE2_K];

    // init vectors
    polyvec pA, eA, sA;

    // expand coins -> buffer = (seed | rand)
    memcpy(buffer, coins, DKE2_SEEDBYTES);
#ifdef USE_KECCAK
    shake256(buffer, 2 * DKE2_SEEDBYTES, buffer, DKE2_SEEDBYTES);
#else
    pseudoXOF(2 * DKE2_SEEDBYTES * 8, buffer, DKE2_SEEDBYTES * 8, buffer); // bytes*8 = bits
#endif

    // generate matrix (1/2)A in NTT domain
    gen_a(mat, seed);

    // generate secret and error vector
    unsigned int i = 0;
    uint8_t nonce = 0;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_getsecretA(&sA.vec[i], rand, nonce++);
    }
    for (i = 0; i < DKE2_K; i++) {
        DKE2_geterrorA(&eA.vec[i], rand, nonce++);
    }

    // Protocol arithmetic (pA construction) ----------------

    DKE2_polyvec_ntt(&sA); // NTT domain (·R^-1 mod q)
    DKE2_polyvec_ntt(&eA); // NTT domain (·R^-1 mod q)


    // acc montgomery multiplication (pA = (1/2)A·sA) in Mont domain
    for (i = 0; i < DKE2_K; i++) {
        DKE2_polyvec_basemul_acc_montgomery(&pA.vec[i], &mat[i], &sA);
        DKE2_poly_tomont(&pA.vec[i]);
    }

    DKE2_polyvec_add(&pA, &pA, &eA);
    DKE2_polyvec_reduce(&pA);

    // WARNING: WE CAN COMMUNICATE pA DIRECTLY ON NTT DOMAIN BECAUSE WE ARE NOT ROUNDING HERE!

    DKE2_packpk(pk, &pA, seed);     // pk = (pA || seed) where pA = (1/2)A sA + eA (in NTT (Mont) domain)
    DKE2_CPA_packsk(sk, &sA);       // sk = sA (in NTT (Mont) domain)


}

// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------

void DKE256_Response(uint8_t ct[DKE2_CPA_CTBYTES],
                        uint8_t ss[DKE2_SSBYTES],
                        const uint8_t pk[DKE2_PKBYTES],
                        const uint8_t coins[DKE2_SEEDBYTES + DKE2_N/8]) {
    // init
    uint8_t seed[DKE2_SEEDBYTES];
    uint8_t sig[DKE2_SIGNALBYTES];
    polyvec matt[DKE2_K]; // (1/2)A^t in NTT(Mont) domain
    polyvec pA, pB, sB, eB;
    poly kB, e;

    // unpackaging
    DKE2_unpackpk(&pA, seed, pk);   // pA is already in NTT domain

    // generate matrix (1/2)A^t in NTT domain
    gen_at(matt, seed);

    // generate secret and error
    unsigned int i = 0;
    uint8_t nonce = 0;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_getsecretB(sB.vec + i, coins, nonce++); // we use the first DKE1_SEEDBYTES from coins
    }
    for (i = 0; i < DKE2_K; i++) {
        DKE2_geterrorB(eB.vec + i, coins, nonce++);
    }

    // Again, there is another approach using a XOF directly for sampling these secrets

    // Arithmetic (computing pB) ------------------------------------------------------------------
    DKE2_polyvec_ntt(&sB);
    // WE ARE NOT DOING DKE1_polyvec_ntt(&eB) SINCE WE OUPUT pB in NORMAL DOMAIN
    for (i = 0; i < DKE2_K; i++) {
        DKE2_polyvec_basemul_acc_montgomery(&pB.vec[i], &matt[i], &sB);
    }
    DKE2_polyvec_invntt_tomont(&pB); // exits from NTT
    DKE2_polyvec_add(&pB, &pB, &eB);   // pB = (1/2)A^tsB + eB
    DKE2_polyvec_reduce(&pB);

    // Arithmetic (computing kB) -------------------------------------------------------------------
    DKE2_polyvec_basemul_acc_montgomery(&kB, &pA, &sB);
    DKE2_poly_invntt_tomont(&kB);      // Exit NTT domain
    DKE2_geterrorA(&e, coins, nonce++);  // Sampling extra error term
    DKE2_poly_add(&kB, &kB, &e);   // kB = (1/2) sA A sB  + noise
    DKE2_poly_scale2(&kB);             // kB =  sA A sB  + 2 noise
    DKE2_poly_reduce(&kB);

    // get signal
    DKE2_signal(sig, &kB, coins + DKE2_SEEDBYTES);
    // packaging
    DKE2_CPA_packciphertext(ct, &pB, sig);
    // derive ss
    DKE2_derive_ss(ss, &kB, sig);

}
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------


void DKE256_DeriveSecret(uint8_t ss[DKE2_SSBYTES],
                 const uint8_t sk[DKE2_CPA_SKABYTES],
                 const uint8_t ct[DKE2_CPA_CTBYTES]) {
    // init
    polyvec sA, pB; // sA is in NTT domain. pB is in normal domain
    uint8_t sig[DKE2_SIGNALBYTES];
    poly kA;

    // unpackaging
    DKE2_CPA_unpacksk(&sA, sk);
    DKE2_CPA_unpackciphertext(&pB, sig, ct);

    // Arithmetic (computing kA) -------------------------------------------------------------------
    DKE2_polyvec_ntt(&pB);
    DKE2_polyvec_basemul_acc_montgomery(&kA, &sA, &pB);
    DKE2_poly_invntt_tomont(&kA);      // Exit NTT domain. At this stage: kA = (1/2) sA A sB  + noise
    DKE2_poly_scale2(&kA);             // kB =  sA A sB  + 2 noise
    DKE2_poly_reduce(&kA);

    // derive ss
    DKE2_derive_ss(ss, &kA, sig);
}

