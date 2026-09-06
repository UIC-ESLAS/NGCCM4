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

// Derived from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/cbd.c


/// @brief load 3 bytes into a 32-bit integer
///        in little-endian order.
///
/// @param[in]  x pointer to input byte array
/// @return     r 32-bit unsigned integer loaded from x (most significant byte is zero)
static uint32_t load24_littleendian(const uint8_t x[3]) {
    // Preliminar implmentation (PQClean: https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/cbd.c)
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}

void centered_binomial3(poly *pol, const unsigned char coins[DKE3_CBD_BYTES])
{
    // Preliminar implmentation (PQClean: https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/cbd.c)
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < DKE3_N / 4; i++) {
        t = load24_littleendian(coins + DKE3_ETA * i);
        d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            pol->coeffs[4 * i + j] = a - b;
        }
    }
}

void DKE3_cbdA(poly* pol, const unsigned char coins[DKE3_CBD_BYTES]) {
    centered_binomial3(pol, coins);
}
void DKE3_cbdB(poly* pol, const unsigned char coins[DKE3_CBD_BYTES]) {
    centered_binomial3(pol, coins);
}


void DKE3_getsecretA(poly* pol, const unsigned char rand[DKE3_SEEDBYTES], const uint8_t nonce) {
    // msg will be (rand | nonce)
    uint8_t msg[DKE3_SEEDBYTES + 1];
    uint8_t coins[DKE3_CBD_BYTES];
    memcpy(msg, rand, DKE3_SEEDBYTES);
    msg[DKE3_SEEDBYTES] = nonce;
#ifdef USE_KECCAK
    shake256(coins, DKE3_CBD_BYTES, msg, DKE3_SEEDBYTES + 1);
#else
    pseudoXOF(DKE3_CBD_BYTES*8, msg,(DKE3_SEEDBYTES + 1)*8, coins); // bytes*8 = bits
#endif
    centered_binomial3(pol, coins);
}
void DKE3_geterrorA(poly* pol, const unsigned char rand[DKE3_SEEDBYTES], const uint8_t nonce) {
    DKE3_getsecretA(pol, rand, nonce);
}
void DKE3_getsecretB(poly* pol, const unsigned char rand[DKE3_SEEDBYTES], const uint8_t nonce) {
    DKE3_getsecretA(pol, rand, nonce);
}
void DKE3_geterrorB(poly* pol, const unsigned char rand[DKE3_SEEDBYTES], const uint8_t nonce) {
    DKE3_getsecretA(pol, rand, nonce);
}

unsigned int rej_uniform(int16_t *res,
                         unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen)
{
    unsigned int ctr, pos;
    uint16_t val0, val1, val2, val3, val4, val5, val6, val7;
    ctr = pos = 0;
    while (ctr < len && pos + 13 <= buflen)
    {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0x1FFF;
        val1 = ((buf[pos + 1] >> 5) | ((uint16_t)buf[pos + 2] << 3) |
                ((uint16_t)buf[pos + 3] << 11)) &
               0x1FFF;
        val2 = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1FFF;
        val3 = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) |
                ((uint16_t)buf[pos + 6] << 9)) &
               0x1FFF;
        val4 = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) |
                ((uint16_t)buf[pos + 8] << 12)) &
               0x1FFF;
        val5 = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1FFF;
        val6 = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1FFF;
        val7 = ((buf[pos + 11] >> 3) | ((uint16_t)buf[pos + 12] << 5)) & 0x1FFF;
        pos += 13;

        if (val0 < DKE3_Q)
        {
            res[ctr++] = val0;
        }
        if (ctr < len && val1 < DKE3_Q)
        {
            res[ctr++] = val1;
        }
        if (ctr < len && val2 < DKE3_Q)
        {
            res[ctr++] = val2;
        }
        if (ctr < len && val3 < DKE3_Q)
        {
            res[ctr++] = val3;
        }
        if (ctr < len && val4 < DKE3_Q)
        {
            res[ctr++] = val4;
        }
        if (ctr < len && val5 < DKE3_Q)
        {
            res[ctr++] = val5;
        }
        if (ctr < len && val6 < DKE3_Q)
        {
            res[ctr++] = val6;
        }
        if (ctr < len && val7 < DKE3_Q)
        {
            res[ctr++] = val7;
        }
    }
    return ctr;
}

// Improving XOF utilities: -----------------------------------------------------------------------------------



// storing seed and matrix coordinates for later squeezes
void DKE3_xof_absorb(DKE3_xof_state *state,
                           const uint8_t seed[DKE3_SEEDBYTES],
                           uint8_t x,
                           uint8_t y) {
    memcpy(state->extseed, seed, DKE3_SEEDBYTES);
    state->extseed[DKE3_SEEDBYTES + 0] = x;
    state->extseed[DKE3_SEEDBYTES + 1] = y;
#ifdef USE_KECCAK
    shake128_absorb(&state->state, state->extseed, DKE3_SEEDBYTES + 2);
#else
    state->counter = 1;
#endif
}

// rebuilding the requested prefix with pseudoXOF and returning the fresh tail
void DKE3_xof_squeezeblocks(uint8_t *out,
                                  size_t outblocks,
                                  DKE3_xof_state *state) {
#ifdef USE_KECCAK
    shake128_squeezeblocks(out, outblocks, &state->state);
#else
    size_t outlen = outblocks * (size_t)DKE3_XOF_BLOCKBYTES;
    if (outlen == 0) {
        return;
    }

    pseudoXOF_squeeze((unsigned long long)outlen * 8ULL,
                      state->extseed,
                      (unsigned long long)(DKE3_SEEDBYTES + 2) * 8ULL,
                      &state->counter,
                      out);
#endif
}

// clearing the local xof bookkeeping
void DKE3_xof_release(DKE3_xof_state *state) {
#ifdef USE_KECCAK
    shake128_ctx_release(&state->state);
#else
    state->counter = 0;
#endif
}

// -----------------------------------------------------------------------------------------

// rebuilding matrix bytes with a local squeeze flow over pseudoXOF
void DKE3_gen_matrix(polyvec *res,
                     const uint8_t seed[DKE3_SEEDBYTES],
                     const int transposed) {

    unsigned int ctr;
    unsigned int buflen;
    DKE3_xof_state state;
    uint8_t buf[DKE3_GEN_MATRIX_NBLOCKS * DKE3_XOF_BLOCKBYTES];

    for (unsigned int i = 0; i < DKE3_K; ++i) {
        for (unsigned int j = 0; j < DKE3_K; ++j) {
            if (transposed) {
                DKE3_xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            }
            else {
                DKE3_xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            DKE3_xof_squeezeblocks(buf, DKE3_GEN_MATRIX_NBLOCKS, &state);
            buflen = DKE3_GEN_MATRIX_NBLOCKS * DKE3_XOF_BLOCKBYTES;
            ctr = rej_uniform(res[i].vec[j].coeffs, DKE3_N, buf, buflen);

            while (ctr < DKE3_N) {
                DKE3_xof_squeezeblocks(buf, 1, &state);
                buflen = DKE3_XOF_BLOCKBYTES;
                ctr += rej_uniform(res[i].vec[j].coeffs + ctr,
                                   DKE3_N - ctr,
                                   buf,
                                   buflen);
            }

            DKE3_xof_release(&state);
        }
    }
}
