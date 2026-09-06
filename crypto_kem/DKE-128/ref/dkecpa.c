#include "parameters.h"
#include "dkecpa.h"
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif
#include "poly.h"
#include "polyvec.h"
#include "random_sampling.h"
#include "dke_utils.h"
#include <stdint.h>
#include <string.h>
#include "packing.h"

void DKE128_Initiate(uint8_t pk[DKE1_PKBYTES],
                          uint8_t sk[DKE1_CPA_SKABYTES],
                          const uint8_t coins[DKE1_SEEDBYTES]) {

    // buffer will contain (seed | rand)  (seed for matrix / rand for secret and noise polyvec)
    uint8_t buffer[2 * DKE1_SEEDBYTES];
    const uint8_t *seed = buffer;
    const uint8_t *rand = buffer + DKE1_SEEDBYTES;

    // init matrix
    polyvec mat[DKE1_K];

    // init vectors
    polyvec pA, eA, sA;

    // expand coins -> buffer = (seed | rand)
    memcpy(buffer, coins, DKE1_SEEDBYTES);
#ifdef USE_KECCAK
    shake256(buffer, 2 * DKE1_SEEDBYTES, buffer, DKE1_SEEDBYTES);
#else
    pseudoXOF(2 * DKE1_SEEDBYTES * 8, buffer, DKE1_SEEDBYTES * 8, buffer); // bytes*8 = bits
#endif

    // generate matrix (1/2)A in NTT domain
    gen_a(mat, seed);

    // generate secret and error vector ----------------------------------------------------

    // One approach using a nonce (PQClean)
    unsigned int i = 0;
    uint8_t nonce = 0;
    for (i = 0; i < DKE1_K; i++) {
        DKE1_getsecretA(&sA.vec[i], rand, nonce++);
    }
    for (i = 0; i < DKE1_K; i++) {
        DKE1_geterrorA(&eA.vec[i], rand, nonce++);
    }

    // Protocol arithmetic (pA construction) ----------------

    DKE1_polyvec_ntt(&sA); // NTT  domain (·R^-1 mod q)
    DKE1_polyvec_ntt(&eA); // NTT  domain (·R^-1 mod q)


    // acc montgomery multiplication (pA = (1/2)A·sA) in Mont domain
    for (i = 0; i < DKE1_K; i++) {
        DKE1_polyvec_basemul_acc_montgomery(&pA.vec[i], &mat[i], &sA);
        DKE1_poly_tomont(&pA.vec[i]);
    }

    DKE1_polyvec_add(&pA, &pA, &eA);
    DKE1_polyvec_reduce(&pA);

    // WARNING: WE CAN COMMUNICATE pA DIRECTLY ON NTT DOMAIN BECAUSE WE ARE NOT ROUNDING HERE!

    DKE1_packpk(pk, &pA, seed);     // pk = (pA || seed) where pA = A sA + eA (in NTT (Mont) domain)
    DKE1_CPA_packsk(sk, &sA);       // sk = sA (in NTT (Mont) domain)


}

// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------


void DKE128_Response(uint8_t ct[DKE1_CPA_CTBYTES],
                        uint8_t ss[DKE1_SSBYTES],
                        const uint8_t pk[DKE1_PKBYTES],
                        const uint8_t coins[DKE1_SEEDBYTES + DKE1_N/8]) {
    // init
    uint8_t seed[DKE1_SEEDBYTES];
    uint8_t sig[DKE1_SIGNALBYTES];
    polyvec matt[DKE1_K]; // A^t in NTT(Mont) domain
    polyvec pA, pB, sB, eB;
    poly kB, e;

    // unpackaging
    DKE1_unpackpk(&pA, seed, pk);   // pA is already in NTT domain

    // generate matrix A^t in NTT domain
    gen_at(matt, seed);

    // generate secret and error
    unsigned int i = 0;
    uint8_t nonce = 0;
    for (i = 0; i < DKE1_K; i++) {
        DKE1_getsecretB(sB.vec + i, coins, nonce++); // we use the first DKE1_SEEDBYTES from coins
    }
    for (i = 0; i < DKE1_K; i++) {
        DKE1_geterrorB(eB.vec + i, coins, nonce++);
    }


    // Arithmetic (computing pB) ------------------------------------------------------------------
    DKE1_polyvec_ntt(&sB);

    for (i = 0; i < DKE1_K; i++) {
        DKE1_polyvec_basemul_acc_montgomery(&pB.vec[i], &matt[i], &sB);
    }
    DKE1_polyvec_invntt_tomont(&pB); // exits from NTT
    DKE1_polyvec_add(&pB, &pB, &eB);   // pB = A^tsB + eB
    DKE1_polyvec_reduce(&pB);

    // Arithmetic (computing kB) -------------------------------------------------------------------
    DKE1_polyvec_basemul_acc_montgomery(&kB, &pA, &sB);
    DKE1_poly_invntt_tomont(&kB);      // Exit NTT domain
    DKE1_geterrorA(&e, coins, nonce++);  // Sampling extra error term
    DKE1_poly_add(&kB, &kB, &e);   // kB = sA A sB  + noise
    DKE1_poly_scale2(&kB);             // kB =  2 sA A sB  + 2 noise
    DKE1_poly_reduce(&kB);

    // get signal
    DKE1_signal(sig, &kB, coins + DKE1_SEEDBYTES);
    // packaging
    DKE1_CPA_packciphertext(ct, &pB, sig);
    // derive ss
    DKE1_derive_ss(ss, &kB, sig);

}
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------


void DKE128_DeriveSecret(uint8_t ss[DKE1_SSBYTES],
                 const uint8_t sk[DKE1_CPA_SKABYTES],
                 const uint8_t ct[DKE1_CPA_CTBYTES]) {
    // init
    polyvec sA, pB; // sA is in NTT domain. pB is in normal domain
    uint8_t sig[DKE1_SIGNALBYTES];
    poly kA;

    // unpackaging
    DKE1_CPA_unpacksk(&sA, sk);
    DKE1_CPA_unpackciphertext(&pB, sig, ct);

    // Arithmetic (computing kA) -------------------------------------------------------------------
    DKE1_polyvec_ntt(&pB);
    DKE1_polyvec_basemul_acc_montgomery(&kA, &sA, &pB);
    DKE1_poly_invntt_tomont(&kA);      // Exit NTT domain. At this stage: kA = sA A sB  + noise
    DKE1_poly_scale2(&kA);             // kB =  2 sA A sB  + 2 noise
    DKE1_poly_reduce(&kA);

    // derive ss
    DKE1_derive_ss(ss, &kA, sig);

}

