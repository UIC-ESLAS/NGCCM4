#include "parameters.h"
#include "dkecpa.h"
#include "poly.h"
#include "polyvec.h"
#include "random_sampling.h"
#include "dke_utils.h"
#include <stdint.h>
#include <string.h>
#include "packing.h"
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif

void DKE512_Initiate(uint8_t pk[DKE3_PKBYTES],
                      uint8_t sk[DKE3_CPA_SKABYTES],
                      const uint8_t coins[DKE3_SEEDBYTES])
{

    // buffer will contain (seed | rand)  (seed for matrix / rand for secret and noise polyvec)
    uint8_t buffer[2 * DKE3_SEEDBYTES];
    const uint8_t *seed = buffer;
    const uint8_t *rand = buffer + DKE3_SEEDBYTES;

    // init matrix
    polyvec mat[DKE3_K];

    // init vectors
    polyvec pA, eA, sA;

    // expand coins -> buffer = (seed | rand) ---------------------------------------------
    memcpy(buffer, coins, DKE3_SEEDBYTES);

    // Another approach (using pseudo XOF):
#ifdef USE_KECCAK
    shake256(buffer, 2 * DKE3_SEEDBYTES, buffer, DKE3_SEEDBYTES);
#else
    pseudoXOF(2 * DKE3_SEEDBYTES*8, buffer, DKE3_SEEDBYTES*8, buffer); //bytes*8 = bits
#endif

    // generate matrix A in NTT domain
    gen_a(mat, seed);

    // generate secret and error vector ----------------------------------------------------

    // One approach using a nonce (PQClean)
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE3_K; i++) {
        DKE3_getsecretA(&sA.vec[i], rand, nonce++);
    }
    for (i = 0; i < DKE3_K; i++) {
        DKE3_geterrorA(&eA.vec[i], rand, nonce++);
    }

    // Protocol arithmetic (pA construction) ----------------

    DKE3_polyvec_ntt(&sA); // NTT  domain (·R^-1 mod q)
    DKE3_polyvec_ntt(&eA); // NTT  domain (·R^-1 mod q)
    // 8*0.5q = 4.5q
    
    // acc Plantard multiplication (pA = A·sA) in Plantard domain
    for (i = 0; i < DKE3_K; i++) {
        DKE3_polyvec_basemul_acc(&pA.vec[i], &mat[i], &sA);
        DKE3_poly_fromplant(&pA.vec[i]); // exit from Plantard domain
    }
    DKE3_polyvec_add(&pA, &pA, &eA);
    
    
    // WARNING: WE CAN COMMUNICATE pA DIRECTLY ON NTT DOMAIN BECAUSE WE ARE NOT ROUNDING HERE!

    DKE3_polyvec_reduce_mq(&sA);
    DKE3_polyvec_reduce_mq(&pA);
    DKE3_packpk(pk, &pA, seed);     // pk = (pA || seed) where pA = A sA + eA (in NTT domain)
    DKE3_CPA_packsk(sk, &sA);       // sk = sA (in NTT domain)
}

// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------

void DKE512_Response(uint8_t ct[DKE3_CPA_CTBYTES],
                      uint8_t ss[DKE3_SSBYTES],
                      const uint8_t pk[DKE3_PKBYTES],
                      const uint8_t coins[DKE3_SEEDBYTES + DKE3_N / 8])
{
    // init
    uint8_t seed[DKE3_SEEDBYTES];
    uint8_t sig[DKE3_SIGNALBYTES];
    polyvec matt[DKE3_K]; // A^t in NTT(Mont) domain
    polyvec pA, pB, sB, eB;
    poly kB, e;

    // unpackaging
    DKE3_unpackpk(&pA, seed, pk); // pA is already in NTT domain

    // generate matrix A^t in NTT domain
    gen_at(matt, seed);

    // generate secret and error
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE3_K; i++) {
        DKE3_getsecretB(sB.vec + i, coins, nonce++); // we use the first DKE3_SEEDBYTES from coins
    }
    for (i = 0; i < DKE3_K; i++) {
        DKE3_geterrorB(eB.vec + i, coins, nonce++);
    }


    // Arithmetic (computing pB) ------------------------------------------------------------------
    DKE3_polyvec_ntt(&sB);
    // WE ARE NOT DOING DKE1_polyvec_ntt(&eB) SINCE WE OUPUT pB in NORMAL DOMAIN
    for (i = 0; i < DKE3_K; i++) {
        DKE3_polyvec_basemul_acc(&pB.vec[i], &matt[i], &sB);
    }
    DKE3_polyvec_invntt(&pB); // exits from NTT
    DKE3_polyvec_add(&pB, &pB, &eB);   // pB = A^tsB + eB
    DKE3_polyvec_reduce_mq(&pB);

    // Arithmetic (computing kB) -------------------------------------------------------------------

    DKE3_polyvec_basemul_acc(&kB, &pA, &sB);

    DKE3_poly_invntt(&kB);      // Exit NTT domain
    DKE3_geterrorA(&e, coins, nonce++);  // Sampling extra error term
    DKE3_poly_add(&kB, &kB, &e);   // kB =  sA A sB  + noise
    DKE3_poly_scale2(&kB);             // kB =  sA A sB  + 2 noise
    // DKE3_poly_reduce(&kB);

    // get signal
    DKE3_signal(sig, &kB, coins + DKE3_SEEDBYTES);
    // packaging
    DKE3_CPA_packciphertext(ct, &pB, sig);
    // derive ss
    DKE3_derive_ss(ss, &kB, sig);
}
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------

void DKE512_DeriveSecret(uint8_t ss[DKE3_SSBYTES],
                          const uint8_t sk[DKE3_CPA_SKABYTES],
                          const uint8_t ct[DKE3_CPA_CTBYTES])
{
    // init
    polyvec sA, pB; // sA is in NTT domain. pB is in normal domain
    uint8_t sig[DKE3_SIGNALBYTES];
    poly kA;

    // unpackaging
    DKE3_CPA_unpacksk(&sA, sk);
    DKE3_CPA_unpackciphertext(&pB, sig, ct);

    // Arithmetic (computing kA) -------------------------------------------------------------------
    DKE3_polyvec_ntt(&pB);
    DKE3_polyvec_basemul_acc(&kA, &sA, &pB);
    DKE3_poly_invntt(&kA);      // Exit NTT domain. At this stage: kA =  sA A sB  + noise
    DKE3_poly_scale2(&kA);             // kB =  sA A sB  + 2 noise
    DKE3_poly_reduce(&kA);

    // derive ss
    DKE3_derive_ss(ss, &kA, sig);
}
