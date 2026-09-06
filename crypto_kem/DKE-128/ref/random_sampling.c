#include "random_sampling.h"
#ifdef USE_KECCAK
#include "fips202.h"
#else
#include "auxfunc.h"
#endif
#include <stdint.h>
#include <string.h> // for mempcy

#include <limits.h>
#include <stdlib.h>

#if DKE1_ETA != 3
#error "centered_binomial3 is specialized for DKE1_ETA = 3"
#endif

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


void centered_binomial3(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]) {
    // Preliminar implmentation (PQClean: https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-512/clean/cbd.c)
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < DKE1_N / 4; i++) {
        t  = load24_littleendian(coins + DKE1_ETA * i);
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

void DKE1_cbdA(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]) {
    centered_binomial3(pol, coins);
}
void DKE1_cbdB(poly* pol, const unsigned char coins[DKE1_CBD_BYTES]) {
    centered_binomial3(pol, coins);
}


void DKE1_getsecretA(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce) {
    // msg will be (rand | nonce)
    uint8_t msg[DKE1_SEEDBYTES + 1];
    uint8_t coins[DKE1_CBD_BYTES];
    memcpy(msg, rand, DKE1_SEEDBYTES);
    msg[DKE1_SEEDBYTES] = nonce;
#ifdef USE_KECCAK
    shake256(coins, DKE1_CBD_BYTES, msg, DKE1_SEEDBYTES + 1);
#else
    pseudoXOF(DKE1_CBD_BYTES * 8, msg, (DKE1_SEEDBYTES + 1) * 8, coins); // bytes*8 = bits
#endif
    centered_binomial3(pol, coins);
}
void DKE1_geterrorA(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce) {
    DKE1_getsecretA(pol, rand, nonce);
}
void DKE1_getsecretB(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce) {
    DKE1_getsecretA(pol, rand, nonce);
}
void DKE1_geterrorB(poly* pol, const unsigned char rand[DKE1_SEEDBYTES], const uint8_t nonce) {
    DKE1_getsecretA(pol, rand, nonce);
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

        if (val0 < DKE1_Q) {
            res[ctr++] = val0;
        }
        if (ctr < len && val1 < DKE1_Q) {
            res[ctr++] = val1;
        }
    }
    return ctr;
}



// Improving XOF utilities: --------------------------------------------------------------------------------------

#ifdef USE_KECCAK
#define DKE1_XOF_BLOCKBYTES SHAKE128_RATE
#else
#define DKE1_XOF_BLOCKBYTES 192
#endif
#define DKE1_GEN_MATRIX_NBLOCKS ((12 * DKE1_N / 8 * (1 << 12) / DKE1_Q + DKE1_XOF_BLOCKBYTES) / DKE1_XOF_BLOCKBYTES)

typedef struct {
    uint8_t extseed[DKE1_SEEDBYTES + 2];
#ifdef USE_KECCAK
    shake128ctx state;
#else
    size_t generated_bytes;
#endif
} dke1_xof_state;       // (seed | x | y)

#ifndef USE_KECCAK
// copying just the newly requested slice
static void dke1_xof_copy_slice(uint8_t *out,
                               size_t start,
                               size_t count,
                               const uint8_t *prefix) {
    if (count == 0) {
        return;
    }

    memcpy(out, prefix + start, count);
}
#endif

// storing seed and matrix coordinates for later squeezes
static void dke1_xof_absorb(dke1_xof_state *state,
                           const uint8_t seed[DKE1_SEEDBYTES],
                           uint8_t x,
                           uint8_t y) {
    memcpy(state->extseed, seed, DKE1_SEEDBYTES);
    state->extseed[DKE1_SEEDBYTES + 0] = x;
    state->extseed[DKE1_SEEDBYTES + 1] = y;
#ifdef USE_KECCAK
    shake128_absorb(&state->state, state->extseed, DKE1_SEEDBYTES + 2);
#else
    state->generated_bytes = 0;
#endif
}

// rebuilding the requested prefix with pseudoXOF and returning the fresh tail
static void dke1_xof_squeezeblocks(uint8_t *out,
                                  size_t outblocks,
                                  dke1_xof_state *state) {
#ifdef USE_KECCAK
    shake128_squeezeblocks(out, outblocks, &state->state);
#else
    size_t outlen = outblocks * (size_t)DKE1_XOF_BLOCKBYTES;
    size_t needed = state->generated_bytes + outlen;
    unsigned char *prefix;

    if (outlen == 0) {
        return;
    }

    if (needed > (size_t)(ULLONG_MAX / 8ULL)) {
        memset(out, 0, outlen);
        return;
    }

    prefix = (unsigned char *)malloc(needed);
    if (prefix == NULL) {
        memset(out, 0, outlen);
        return;
    }

    if (pseudoXOF((unsigned long long)needed * 8ULL,
                  state->extseed,
                  (unsigned long long)sizeof(state->extseed) * 8ULL,
                  prefix) != 0) {
        memset(out, 0, outlen);
        free(prefix);
        return;
                  }

    dke1_xof_copy_slice(out, state->generated_bytes, outlen, prefix);
    state->generated_bytes += outlen;
    free(prefix);
#endif
}

// clearing the local xof bookkeeping
static void dke1_xof_release(dke1_xof_state *state) {
#ifdef USE_KECCAK
    shake128_ctx_release(&state->state);
#else
    state->generated_bytes = 0;
#endif
}

// -----------------------------------------------------------------------------------------

static void dke1_sample_poly(poly *pol, const uint8_t seed[DKE1_SEEDBYTES], uint8_t x, uint8_t y) {
    unsigned int ctr, buflen;
    dke1_xof_state state;
    uint8_t buf[DKE1_GEN_MATRIX_NBLOCKS * DKE1_XOF_BLOCKBYTES];

    dke1_xof_absorb(&state, seed, x, y);
    dke1_xof_squeezeblocks(buf, DKE1_GEN_MATRIX_NBLOCKS, &state);
    buflen = DKE1_GEN_MATRIX_NBLOCKS * DKE1_XOF_BLOCKBYTES;
    ctr = rej_uniform(pol->coeffs, DKE1_N, buf, buflen);

    while (ctr < DKE1_N) {
        dke1_xof_squeezeblocks(buf, 1, &state);
        buflen = DKE1_XOF_BLOCKBYTES;
        ctr += rej_uniform(pol->coeffs + ctr, DKE1_N - ctr, buf, buflen);
    }
    dke1_xof_release(&state);
}

void DKE1_gen_matrix(polyvec *res,
                     const uint8_t seed[DKE1_SEEDBYTES],
                     const int transposed) {
    for (unsigned int i = 0; i < DKE1_K; ++i) {
        for (unsigned int j = 0; j < DKE1_K; ++j) {
            if (transposed) {
                dke1_sample_poly(&res[i].vec[j], seed, (uint8_t)i, (uint8_t)j);
            }
            else {
                dke1_sample_poly(&res[i].vec[j], seed, (uint8_t)j, (uint8_t)i);
            }
        }
    }
}