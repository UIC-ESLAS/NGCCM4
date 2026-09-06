#include "random_sampling.h"

#include <stdint.h>
#include <string.h> // for mempcy
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif
#include <limits.h>
#include <stdlib.h>

#if DKE2_ETA != 2
#error "centered_binomial2 is specialized for DKE2_ETA = 2"
#endif
// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/cbd.c

/// @brief load 4 bytes into a 32-bit integer
///        in little-endian order.
///
/// @param[in]  x pointer to input byte array
/// @return     r 32-bit unsigned integer loaded from x (most significant byte is zero)
static uint32_t load32_littleendian(const uint8_t x[4])
{
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

void centered_binomial2(poly *pol, const unsigned char coins[DKE2_CBD_BYTES])
{
    // Preliminar implmentation (PQClean: https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-1024/clean/cbd.c)
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < DKE2_N / 8; i++)
    {
        t = load32_littleendian(coins + (2 * DKE2_ETA) * i);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++)
        {
            a = (d >> (4 * j + 0)) & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            pol->coeffs[8 * i + j] = a - b;
        }
    }
}

void DKE2_cbdA(poly *pol, const unsigned char coins[DKE2_CBD_BYTES])
{
    centered_binomial2(pol, coins);
}
void DKE2_cbdB(poly *pol, const unsigned char coins[DKE2_CBD_BYTES])
{
    centered_binomial2(pol, coins);
}

void DKE2_getsecretA(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce) {
    // msg will be (rand | nonce)
    uint8_t msg[DKE2_SEEDBYTES + 1];
    uint8_t coins[DKE2_CBD_BYTES];
    memcpy(msg, rand, DKE2_SEEDBYTES);
    msg[DKE2_SEEDBYTES] = nonce;
#ifdef USE_KECCAK
    shake256(coins, DKE2_CBD_BYTES, msg, DKE2_SEEDBYTES + 1);
#else
    pseudoXOF(DKE2_CBD_BYTES*8, msg,(DKE2_SEEDBYTES + 1)*8, coins); // bytes*8 = bits
#endif
    centered_binomial2(pol, coins);
}
void DKE2_geterrorA(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce) {
    DKE2_getsecretA(pol, rand, nonce);
}
void DKE2_getsecretB(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce) {
    DKE2_getsecretA(pol, rand, nonce);
}
void DKE2_geterrorB(poly* pol, const unsigned char rand[DKE2_SEEDBYTES], const uint8_t nonce) {
    DKE2_getsecretA(pol, rand, nonce);
}




unsigned int rej_uniform(int16_t *res,
                         unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;
    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < DKE2_Q) {
            res[ctr++] = val0;
        }
        if (ctr < len && val1 < DKE2_Q) {
            res[ctr++] = val1;
        }
    }
    return ctr;
}


// Improving XOF utilities: --------------------------------------------------------------------------------------



// storing seed and matrix coordinates for later squeezes
void dke2_xof_absorb(dke2_xof_state *state,
                           const uint8_t seed[DKE2_SEEDBYTES],
                           uint8_t x,
                           uint8_t y) {
    memcpy(state->extseed, seed, DKE2_SEEDBYTES);
    state->extseed[DKE2_SEEDBYTES + 0] = x;
    state->extseed[DKE2_SEEDBYTES + 1] = y;
#ifdef USE_KECCAK
    shake128_absorb(&state->state, state->extseed, DKE2_SEEDBYTES + 2);
#else
    state->counter = 1;
#endif
}

// rebuilding the requested prefix with pseudoXOF and returning the fresh tail
void dke2_xof_squeezeblocks(uint8_t *out,
                                  size_t outblocks,
                                  dke2_xof_state *state) {
#ifdef USE_KECCAK
    shake128_squeezeblocks(out, outblocks, &state->state);
#else
    size_t outlen = outblocks * (size_t)DKE2_XOF_BLOCKBYTES;
    if (outlen == 0) {
        return;
    }

    pseudoXOF_squeeze((unsigned long long)outlen * 8ULL,
                      state->extseed,
                      (unsigned long long)(DKE2_SEEDBYTES + 2) * 8ULL,
                      &state->counter,
                      out);
#endif
}

// clearing the local xof bookkeeping
void dke2_xof_release(dke2_xof_state *state) {
#ifdef USE_KECCAK
    shake128_ctx_release(&state->state);
#else
    state->counter = 0;
#endif
}

// -----------------------------------------------------------------------------------------

// rebuilding matrix bytes with a local squeeze flow over pseudoXOF
void DKE2_gen_matrix(polyvec *res,
                     const uint8_t seed[DKE2_SEEDBYTES],
                     const int transposed) {

    unsigned int ctr;
    unsigned int buflen;
    dke2_xof_state state;
    uint8_t buf[DKE2_GEN_MATRIX_NBLOCKS * DKE2_XOF_BLOCKBYTES];

    for (unsigned int i = 0; i < DKE2_K; ++i) {
        for (unsigned int j = 0; j < DKE2_K; ++j) {
            if (transposed) {
                dke2_xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            }
            else {
                dke2_xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            dke2_xof_squeezeblocks(buf, DKE2_GEN_MATRIX_NBLOCKS, &state);
            buflen = DKE2_GEN_MATRIX_NBLOCKS * DKE2_XOF_BLOCKBYTES;
            ctr = rej_uniform(res[i].vec[j].coeffs, DKE2_N, buf, buflen);

            while (ctr < DKE2_N) {
                dke2_xof_squeezeblocks(buf, 1, &state);
                buflen = DKE2_XOF_BLOCKBYTES;
                ctr += rej_uniform(res[i].vec[j].coeffs + ctr,
                                   DKE2_N - ctr,
                                   buf,
                                   buflen);
            }

            dke2_xof_release(&state);
        }
    }
}
