#include "parameters.h"
#include "dkecpa.h"
#include "poly.h"
#include "polyvec.h"
#include "random_sampling.h"
#include "matacc.h"
#include "dke_utils.h"
#include "hal.h"
#include "sendfn.h"
#include <stdint.h>
#include <string.h>
#include "packing.h"
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif

void DKE256_Initiate(uint8_t pk[DKE2_PKBYTES],
                      uint8_t sk[DKE2_CPA_SKABYTES],
                      const uint8_t coins[DKE2_SEEDBYTES])
{

    // buffer will contain (seed | rand)  (seed for matrix / rand for secret and noise polyvec)
    uint8_t buffer[2 * DKE2_SEEDBYTES];
    const uint8_t *seed = buffer;
    const uint8_t *rand = buffer + DKE2_SEEDBYTES;

    // init matrix
    // polyvec mat[DKE2_K];
    poly pkp;
    // init vectors
    polyvec eA, sA, sA_prime;

    // expand coins -> buffer = (seed | rand) ---------------------------------------------
    memcpy(buffer, coins, DKE2_SEEDBYTES);
    // One approach (using pseudo XOF):

#ifdef USE_KECCAK
    shake256(buffer, 2 * DKE2_SEEDBYTES, buffer, DKE2_SEEDBYTES);
#else  
    pseudoXOF(2 * DKE2_SEEDBYTES*8, buffer, DKE2_SEEDBYTES*8, buffer); //bytes*8 = bits
#endif

    // generate secret and error vector ----------------------------------------------------

    // One approach using a nonce (PQClean)
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_getsecretA(&sA.vec[i], rand, nonce++);
    }
    for (i = 0; i < DKE2_K; i++) {
        DKE2_geterrorA(&eA.vec[i], rand, nonce++);
    }


    // Protocol arithmetic (pA construction) ----------------

    DKE2_polyvec_ntt(&sA); // NTT  domain (·R^-1 mod q)
    DKE2_polyvec_ntt(&eA); // NTT  domain (·R^-1 mod q)

    matacc_cache32(&pkp, &sA, &sA_prime, 0, seed, 0);
    DKE2_poly_fromplant(&pkp);
    DKE2_poly_add(&pkp, &pkp, &eA.vec[0]);
    DKE2_poly_reduce_mq(&pkp);
    DKE2_poly_tobytes(pk, &pkp); // packing the first polynomial of pA

    // Plantard-backed pointwise accumulation in the NTT domain.
    for (i = 1; i < DKE2_K; i++) {
        matacc_opt32(&pkp, &sA, &sA_prime, i, seed, 0);
        DKE2_poly_fromplant(&pkp);
        DKE2_poly_add(&pkp, &pkp, &eA.vec[i]);
        DKE2_poly_reduce_mq(&pkp);
        DKE2_poly_tobytes(pk + i * DKE2_POLYBYTES, &pkp);
    }

    // Preserve the original public-key layout: packed pA followed by seed.
    memcpy(pk + DKE2_PACOMPRESSEDBYTES, seed, DKE2_SEEDBYTES);

    // DKE2_polyvec_add(&pA, &pA, &eA);
    // DKE2_polyvec_reduce_mq(&pA);

    // WARNING: WE CAN COMMUNICATE pA DIRECTLY ON NTT DOMAIN BECAUSE WE ARE NOT ROUNDING HERE!

    // DKE2_packpk(pk, &pA, seed);     // pk = (pA || seed) where pA = (1/2)A sA + eA (in Plantard-backed NTT domain)
    DKE2_polyvec_reduce_mq(&sA);
    DKE2_CPA_packsk(sk, &sA);       // sk = sA (in Plantard-backed NTT domain)
}

// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------

void DKE256_Response(uint8_t ct[DKE2_CPA_CTBYTES],
                      uint8_t ss[DKE2_SSBYTES],
                      const uint8_t pk[DKE2_PKBYTES],
                      const uint8_t coins[DKE2_SEEDBYTES + DKE2_N / 8])
{
    // init
    uint8_t seed[DKE2_SEEDBYTES];
    uint8_t sig[DKE2_SIGNALBYTES];
    // polyvec matt[DKE2_K]; // (1/2)A^t in NTT domain
    poly pkp;
    polyvec pB, sB, eB, sB_prime;
    poly kB, e;

    // unpackaging
    memcpy(seed, pk + DKE2_PACOMPRESSEDBYTES, DKE2_SEEDBYTES);

    // generate matrix (1/2)A^t in NTT domain
    // gen_at(matt, seed);

    // generate secret and error
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE2_K; i++) {
        DKE2_getsecretB(sB.vec + i, coins, nonce++); // we use the first DKE2_SEEDBYTES from coins
    }
    for (i = 0; i < DKE2_K; i++) {
        DKE2_geterrorB(eB.vec + i, coins, nonce++);
    }

    // Again, there is another approach using a XOF directly for sampling these secrets

    // Arithmetic (computing pB) ------------------------------------------------------------------
    DKE2_polyvec_ntt(&sB);
    matacc_cache32(&pB.vec[0], &sB, &sB_prime, 0, seed, 1);
    DKE2_poly_invntt(&pB.vec[0]); // exits from NTT
    DKE2_poly_add(&pB.vec[0], &pB.vec[0], &eB.vec[0]);   // pB[0] = (1/2)A^tsB + eB[0]
    for (i = 1; i < DKE2_K; i++) {
        matacc_opt32(&pB.vec[i], &sB, &sB_prime, i, seed, 1);
        DKE2_poly_invntt(&pB.vec[i]); // exits from NTT
        DKE2_poly_add(&pB.vec[i], &pB.vec[i], &eB.vec[i]);   // pB[i] = (1/2)A^tsB + eB[i]
    }
    // WE ARE NOT DOING DKE2_polyvec_ntt(&eB) SINCE WE OUPUT pB in NORMAL DOMAIN
    
    DKE2_polyvec_reduce_mq(&pB);

    // Arithmetic (computing kB) -------------------------------------------------------------------
    int32_t v_tmp[DKE2_N];
    DKE2_poly_frombytes(&kB, pk);
    DKE2_poly_basemul_opt_16_32(v_tmp, &sB.vec[0], &kB, &sB_prime.vec[0]);
    // DKE2_poly_frombytes_mul(&kB, &sB.vec[0], pk);
    for (i = 1; i < DKE2_K - 1; i++)
    {
        DKE2_poly_frombytes(&pkp, pk + i * DKE2_POLYBYTES);
        DKE2_poly_basemul_acc_opt_32_32(v_tmp, &sB.vec[i], &pkp, &sB_prime.vec[i]);
        // DKE2_poly_frombytes_mul_acc(&kB, &sB.vec[i], pk + i * DKE2_POLYBYTES);
    }
    DKE2_poly_frombytes(&pkp, pk + i * DKE2_POLYBYTES);
    DKE2_poly_basemul_acc_opt_32_16(&kB, &sB.vec[i], &pkp, &sB_prime.vec[i], v_tmp);

    DKE2_poly_invntt(&kB);      // Exit NTT domain
    DKE2_geterrorA(&e, coins, nonce++);  // Sampling extra error term
    DKE2_poly_add(&kB, &kB, &e);   // kB = (1/2) sA A sB  + noise
    DKE2_poly_scale2(&kB);             // kB =  sA A sB  + 2 noise

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
                          const uint8_t ct[DKE2_CPA_CTBYTES])
{
    // init
    polyvec pB; // sA is in NTT domain. pB is in normal domain
    uint8_t sig[DKE2_SIGNALBYTES];
    poly kA;
    int32_t r_tmp[DKE2_N];
    int i;
    // unpackaging
    // DKE2_CPA_unpacksk(&sA, sk);
    DKE2_CPA_unpackciphertext(&pB, sig, ct);

    // Arithmetic (computing kA) -------------------------------------------------------------------
    DKE2_polyvec_ntt(&pB);

    DKE2_poly_frombytes_mul_16_32(r_tmp, &pB.vec[0], sk);
    for (i = 1; i < DKE2_K-1; i++)
    {
        DKE2_poly_frombytes_mul_32_32(r_tmp, &pB.vec[i], sk + i * DKE2_POLYBYTES);
    }
    DKE2_poly_frombytes_mul_32_16(&kA, &pB.vec[i], sk + i * DKE2_POLYBYTES, r_tmp);

    DKE2_poly_invntt(&kA);      // Exit NTT domain. At this stage: kA = (1/2) sA A sB  + noise
    DKE2_poly_scale2(&kA);             // kB =  sA A sB  + 2 noise

    // derive ss
    DKE2_derive_ss(ss, &kA, sig);
}
