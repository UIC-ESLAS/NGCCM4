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

void DKE128_Initiate(uint8_t pk[DKE1_PKBYTES],
                      uint8_t sk[DKE1_CPA_SKABYTES],
                      const uint8_t coins[DKE1_SEEDBYTES])
{

    // buffer will contain (seed | rand)  (seed for matrix / rand for secret and noise polyvec)
    uint8_t buffer[2 * DKE1_SEEDBYTES];
    const uint8_t *seed = buffer;
    const uint8_t *rand = buffer + DKE1_SEEDBYTES;

    // init matrix
    // polyvec mat[DKE1_K];
    poly pkp;
    // init vectors
    polyvec eA, sA, sA_prime;

    // expand coins -> buffer = (seed | rand) ---------------------------------------------
    memcpy(buffer, coins, DKE1_SEEDBYTES);
    // One approach (using pseudo XOF):

#ifdef USE_KECCAK
    shake256(buffer, 2 * DKE1_SEEDBYTES, buffer, DKE1_SEEDBYTES);
#else  
    pseudoXOF(2 * DKE1_SEEDBYTES*8, buffer, DKE1_SEEDBYTES*8, buffer); //bytes*8 = bits
#endif
    // generate secret and error vector ----------------------------------------------------

    // One approach using a nonce (PQClean)
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE1_K; i++) {
        DKE1_getsecretA(&sA.vec[i], rand, nonce++);
    }
    for (i = 0; i < DKE1_K; i++) {
        DKE1_geterrorA(&eA.vec[i], rand, nonce++);
    }


    // Protocol arithmetic (pA construction) ----------------

    DKE1_polyvec_ntt(&sA); // NTT  domain (·R^-1 mod q)
    DKE1_polyvec_ntt(&eA); // NTT  domain (·R^-1 mod q)

    matacc_cache32(&pkp, &sA, &sA_prime, 0, seed, 0);
    DKE1_poly_fromplant(&pkp);
    DKE1_poly_add(&pkp, &pkp, &eA.vec[0]);
    DKE1_poly_reduce_mq(&pkp);
    DKE1_poly_tobytes(pk, &pkp); // packing the first polynomial of pA

    // Plantard-backed pointwise accumulation in the NTT domain.
    for (i = 1; i < DKE1_K; i++) {
        matacc_opt32(&pkp, &sA, &sA_prime, i, seed, 0);
        DKE1_poly_fromplant(&pkp);
        DKE1_poly_add(&pkp, &pkp, &eA.vec[i]);
        DKE1_poly_reduce_mq(&pkp);
        DKE1_poly_tobytes(pk + i * DKE1_POLYBYTES, &pkp);
    }

    // Preserve the original public-key layout: packed pA followed by seed.
    memcpy(pk + DKE1_PACOMPRESSEDBYTES, seed, DKE1_SEEDBYTES);

    // DKE1_polyvec_add(&pA, &pA, &eA);
    // DKE1_polyvec_reduce_mq(&pA);

    // WARNING: WE CAN COMMUNICATE pA DIRECTLY ON NTT DOMAIN BECAUSE WE ARE NOT ROUNDING HERE!

    // DKE1_packpk(pk, &pA, seed);     // pk = (pA || seed) where pA = A sA + eA (in Plantard-backed NTT domain)
    DKE1_polyvec_reduce_mq(&sA);
    DKE1_CPA_packsk(sk, &sA);       // sk = sA (in Plantard-backed NTT domain)
}

// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------------

void DKE128_Response(uint8_t ct[DKE1_CPA_CTBYTES],
                      uint8_t ss[DKE1_SSBYTES],
                      const uint8_t pk[DKE1_PKBYTES],
                      const uint8_t coins[DKE1_SEEDBYTES + DKE1_N / 8])
{
    // init
    uint8_t seed[DKE1_SEEDBYTES];
    uint8_t sig[DKE1_SIGNALBYTES];
    poly pkp;
    polyvec pB, sB, eB, sB_prime;
    poly kB, e;

    // unpackaging
    memcpy(seed, pk + DKE1_PACOMPRESSEDBYTES, DKE1_SEEDBYTES);

    // generate secret and error
    unsigned int i = 0;
    unsigned int nonce = 0;
    for (i = 0; i < DKE1_K; i++) {
        DKE1_getsecretB(sB.vec + i, coins, nonce++); // we use the first DKE1_SEEDBYTES from coins
    }
    for (i = 0; i < DKE1_K; i++) {
        DKE1_geterrorB(eB.vec + i, coins, nonce++);
    }

    // Again, there is another approach using a XOF directly for sampling these secrets

    // Arithmetic (computing pB) ------------------------------------------------------------------
    DKE1_polyvec_ntt(&sB);
    matacc_cache32(&pB.vec[0], &sB, &sB_prime, 0, seed, 1);
    DKE1_poly_invntt(&pB.vec[0]); // exits from NTT
    DKE1_poly_add(&pB.vec[0], &pB.vec[0], &eB.vec[0]);   // pB[0] = A^tsB + eB[0]
    for (i = 1; i < DKE1_K; i++) {
        matacc_opt32(&pB.vec[i], &sB, &sB_prime, i, seed, 1);
        DKE1_poly_invntt(&pB.vec[i]); // exits from NTT
        DKE1_poly_add(&pB.vec[i], &pB.vec[i], &eB.vec[i]);   // pB[i] = A^tsB + eB[i]
    }
    // WE ARE NOT DOING DKE1_polyvec_ntt(&eB) SINCE WE OUPUT pB in NORMAL DOMAIN
    
    DKE1_polyvec_reduce_mq(&pB);

    // Arithmetic (computing kB) -------------------------------------------------------------------
    int32_t v_tmp[DKE1_N];
    DKE1_poly_frombytes(&kB, pk);
    DKE1_poly_basemul_opt_16_32(v_tmp, &sB.vec[0], &kB, &sB_prime.vec[0]);
    // DKE1_poly_frombytes_mul(&kB, &sB.vec[0], pk);
    for (i = 1; i < DKE1_K - 1; i++)
    {
        DKE1_poly_frombytes(&pkp, pk + i * DKE1_POLYBYTES);
        DKE1_poly_basemul_acc_opt_32_32(v_tmp, &sB.vec[i], &pkp, &sB_prime.vec[i]);
        // DKE1_poly_frombytes_mul_acc(&kB, &sB.vec[i], pk + i * DKE1_POLYBYTES);
    }
    DKE1_poly_frombytes(&pkp, pk + i * DKE1_POLYBYTES);
    DKE1_poly_basemul_acc_opt_32_16(&kB, &sB.vec[i], &pkp, &sB_prime.vec[i], v_tmp);

    DKE1_poly_invntt(&kB);      // Exit NTT domain
    DKE1_geterrorA(&e, coins, nonce++);  // Sampling extra error term
    DKE1_poly_add(&kB, &kB, &e);   // kB = sA A sB  + noise
    DKE1_poly_scale2(&kB);             // kB =  2 sA A sB  + 2 noise

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
                          const uint8_t ct[DKE1_CPA_CTBYTES])
{
    // init
    polyvec pB; // sA is in NTT domain. pB is in normal domain
    uint8_t sig[DKE1_SIGNALBYTES];
    poly kA;
    int32_t r_tmp[DKE1_N];
    int i;
    // unpackaging
    // DKE1_CPA_unpacksk(&sA, sk);
    DKE1_CPA_unpackciphertext(&pB, sig, ct);

    // Arithmetic (computing kA) -------------------------------------------------------------------
    DKE1_polyvec_ntt(&pB);

    DKE1_poly_frombytes_mul_16_32(r_tmp, &pB.vec[0], sk);
    for (i = 1; i < DKE1_K-1; i++)
    {
        DKE1_poly_frombytes_mul_32_32(r_tmp, &pB.vec[i], sk + i * DKE1_POLYBYTES);
    }
    DKE1_poly_frombytes_mul_32_16(&kA, &pB.vec[i], sk + i * DKE1_POLYBYTES, r_tmp);

    DKE1_poly_invntt(&kA);      // Exit NTT domain. At this stage: kA = sA A sB  + noise
    DKE1_poly_scale2(&kA);             // kB =  2 sA A sB  + 2 noise

    // derive ss
    DKE1_derive_ss(ss, &kA, sig);
}
