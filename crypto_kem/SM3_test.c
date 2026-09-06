#include <stdint.h>
#include <string.h>
#include "auxfunc.h"
#include "hal.h"
#include "sendfn.h"
#define print_u32(S, U) send_unsigned((S), (U))
#define printcycles(S, U) send_unsignedll((S), (U))

static void print_poly_u32(const uint32_t *a, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        print_u32(", ", a[i]);
    }
    hal_send_str("\n");
}

#define FF1(x, y, z) ((x) ^ (y) ^ (z))
#define FF2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) ((x) ^ (y) ^ (z))
#define GG2(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define L_SHIFT(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define P0(x) ((x) ^ L_SHIFT((x), 9) ^ L_SHIFT((x), 17))
#define P1(x) ((x) ^ L_SHIFT((x), 15) ^ L_SHIFT((x), 23))

extern void sm3_bit_compress_asm(uint32_t dgst[8], const unsigned char *msg,
                                 unsigned long long blocks);

static const uint32_t sm3_iv[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};

static void fail_and_halt(const char *reason)
{
    hal_send_str(reason);
#ifdef MPS2_AN386
    __builtin_trap();
#endif
    while (1) {
    }
}


static void sm3_bit_compress_c(uint32_t dgst[8], const unsigned char *msg,
                               unsigned long long blocks)
{
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t W[68];
    uint32_t W_prime[64];
    uint32_t SS1, SS2, TT1, TT2;
    int i;

    while (blocks--) {
        for (i = 0; i < 16; i++) {
            W[i] = ((uint32_t)(msg + i * 4)[0] << 24) |
                   ((uint32_t)(msg + i * 4)[1] << 16) |
                   ((uint32_t)(msg + i * 4)[2] << 8) |
                   ((uint32_t)(msg + i * 4)[3]);
        }
        for (; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ L_SHIFT(W[i - 3], 15)) ^
                   L_SHIFT(W[i - 13], 7) ^ W[i - 6];
        }
        for (i = 0; i < 64; i++) {
            W_prime[i] = W[i] ^ W[i + 4];
        }

        A = dgst[0];
        B = dgst[1];
        C = dgst[2];
        D = dgst[3];
        E = dgst[4];
        F = dgst[5];
        G = dgst[6];
        H = dgst[7];

        for (i = 0; i < 64; i++) {
            if (i < 16) {
                SS1 = L_SHIFT(L_SHIFT(A, 12) + E +
                              L_SHIFT(0x79cc4519U, i & 0x1f), 7);
                TT1 = FF1(A, B, C) + D;
                TT2 = GG1(E, F, G) + H;
            } else {
                SS1 = L_SHIFT(L_SHIFT(A, 12) + E +
                              L_SHIFT(0x7a879d8aU, i & 0x1f), 7);
                TT1 = FF2(A, B, C) + D;
                TT2 = GG2(E, F, G) + H;
            }
            SS2 = SS1 ^ L_SHIFT(A, 12);
            TT1 += SS2 + W_prime[i];
            TT2 += SS1 + W[i];

            D = C;
            C = L_SHIFT(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = L_SHIFT(F, 19);
            F = E;
            E = P0(TT2);
        }

        dgst[0] ^= A;
        dgst[1] ^= B;
        dgst[2] ^= C;
        dgst[3] ^= D;
        dgst[4] ^= E;
        dgst[5] ^= F;
        dgst[6] ^= G;
        dgst[7] ^= H;
        msg += 64;
    }
}

static void fill_test_msg(unsigned char *msg, unsigned long long len,
                          uint32_t seed)
{
    unsigned long long i;

    for (i = 0; i < len; i++) {
        seed = seed * 1664525U + 1013904223U;
        msg[i] = (unsigned char)((seed >> 24) ^ (seed >> 11) ^ i);
    }
}

static int run_compress_case(const char *name, const uint32_t init[8],
                             unsigned char *msg,
                             unsigned long long blocks)
{
    uint32_t c_state[76];
    uint32_t asm_state[76];
    unsigned int i;
    unsigned long long t0, t1;
    memcpy(c_state, init, sizeof(c_state));
    memset(asm_state, 0, sizeof(asm_state));
    memcpy(asm_state, init, 8 * sizeof(uint32_t));

    t0 = hal_get_time();
    sm3_bit_compress(asm_state, msg, blocks);
    t1 = hal_get_time();
    printcycles("sm3_bit_compress", t1 - t0);

    memset(asm_state, 0, sizeof(asm_state));
    memcpy(asm_state, init, 8 * sizeof(uint32_t));
    t0 = hal_get_time();
    sm3_bit_compress_c(c_state, msg, blocks);
    t1 = hal_get_time();
    printcycles("sm3_bit_compress_c", t1-t0);

    t0 = hal_get_time();
    sm3_bit_compress_asm(asm_state, msg, blocks);
    t1 = hal_get_time();
    printcycles("sm3_bit_compress_asm", t1 - t0);

    for (i = 0; i < 8; i++) {
        if (c_state[i] != asm_state[i]) {
            hal_send_str("SM3 mismatch:");
            hal_send_str(name);
            send_unsigned(" word=", i);
            send_unsigned(" c=", c_state[i]);
            send_unsigned(" asm=", asm_state[i]);
            return -1;
        }
    }

    hal_send_str("SM3 case ok:");
    hal_send_str(name);
    return 0;
}

#include "random_sampling.h"
#include "auxfunc.h"
/*static int pseudoXOF_test()
{
    uint8_t digest[512];
    unsigned char msg[3 * 64]="abc";

    unsigned long long t0, t1;
    unsigned int ct = 1;

    dke1_xof_state state1, state2;
    dke1_xof_absorb(&state1, (const uint8_t *)msg, 0, 0);
    dke1_xof_absorb(&state2, (const uint8_t *)msg, 0, 0);

    t0 = hal_get_time();
    pseudoXOF(512 * 8, state1.extseed, (unsigned long long)(DKE1_SEEDBYTES + 2) * 8ULL, digest);
    t1 = hal_get_time();
    printcycles("pseudoXOF", t1 - t0);
    // print_poly_u32(digest, 512 / 4);

    t0 = hal_get_time();
    dke1_xof_squeezeblocks(digest, 2, &state1);
    t1 = hal_get_time();
    printcycles("dke1_xof_squeezeblocks", t1 - t0);
    // print_poly_u32(digest, 512/4);

    t0 = hal_get_time();
    dke1_xof_squeezeblocks(digest, 1, &state2);
    dke1_xof_squeezeblocks(digest+256, 1, &state2);
    t1 = hal_get_time();
    printcycles("dke1_xof_squeezeblocks separate", t1 - t0);
    // print_poly_u32(digest, 512/4);

    return 0;
}*/

#include "auxfunc.h"
#include "internal-sha256.h"
extern void sha256_transform(sha256_state_t *state);
int SM3_test(const char *name, uint32_t digest[16],
              unsigned char *msg,
              unsigned long long blocks)
{
    unsigned long long t0, t1;
    t0=hal_get_time();
    sha256_state_t state;
    state.h[0] = 0x6a09e667U;
    state.h[1] = 0xbb67ae85U;
    state.h[2] = 0x3c6ef372U;
    state.h[3] = 0xa54ff53aU,
    state.h[4] = 0x510e527fU;
    state.h[5] = 0x9b05688cU;
    state.h[6] = 0x1f83d9abU;
    state.h[7] = 0x5be0cd19U;
    state.length = 0;
    state.posn = 0;
    sha256_transform(&state);
    t1=hal_get_time();
    printcycles("sha256hash", t1 - t0);

    unsigned int ct = 1;
    t0 = hal_get_time();
    sm3hash(256, msg, sizeof(msg), (unsigned char *)digest);
    t1 = hal_get_time();
    printcycles("sm3hash", t1 - t0);

    t0 = hal_get_time();
    pseudohash(512, msg, sizeof(msg), (unsigned char *)digest);
    t1 = hal_get_time();
    printcycles("pseudohash", t1 - t0);

    t0 = hal_get_time();
    pseudoXOF_squeeze(500, msg, sizeof(msg)-4, &ct, (unsigned char *)digest);
    t1 = hal_get_time();
    printcycles("pseudoXOF_squeeze", t1 - t0);

    t0=hal_get_time();
    pseudoXOF(500, msg, sizeof(msg)-4, (unsigned char *)digest);
    t1=hal_get_time();
    printcycles("pseudoXOF", t1 - t0);

    return 0;
}

#include "fips202.h"
void speedSM3_Keccak()
{
    uint64_t t0;
    uint64_t t1;
    unsigned char output[1344];
    unsigned char input[32];
    int i;

    for (i = 0; i < 32; i++)
    {
        input[i] = (unsigned char)i;
    }
#ifdef USE_KECCAK
    shake128ctx ctx;
    shake256ctx ctx256;
    shake128_absorb(&ctx, input, 32);
    shake256_absorb(&ctx256, input, 32);
#else
    dke1_xof_state xof_ctx;
    dke1_xof_absorb(&xof_ctx, input, 0, 0);
#endif
    
    for (i = 0; i < NGCC_ITERATIONS; i++)
    {
#ifdef USE_KECCAK
        t0 = hal_get_time();
        sha3_256(output, input, 32);
        t1 = hal_get_time();
        printcycles("sha3_256 cycles:", t1 - t0);

        t0 = hal_get_time();
        shake128_squeezeblocks(output, 1, &ctx);
        t1 = hal_get_time();
        printcycles("shake128 168 bytes cycles:", t1 - t0);

        t0 = hal_get_time();
        shake128_squeezeblocks(output, 1344 / SHAKE128_RATE, &ctx);
        t1 = hal_get_time();
        printcycles("shake128 1344 bytes cycles:", t1 - t0);

        t0 = hal_get_time();
        shake256_squeezeblocks(output, 1, &ctx256);
        t1 = hal_get_time();
        printcycles("shake256 136 bytes cycles:", t1 - t0);

        t0 = hal_get_time();
        shake256_squeezeblocks(output, 1344 / SHAKE256_RATE, &ctx256);
        t1 = hal_get_time();
        printcycles("shake256 1344 bytes cycles:", t1 - t0);
#else
        t0 = hal_get_time();
        dke1_xof_squeezeblocks(output, 1, &xof_ctx);
        t1 = hal_get_time();
        printcycles("dke1_xof 192 bytes cycles:", t1 - t0);

        t0 = hal_get_time();
        dke1_xof_squeezeblocks(output, 1344 / DKE1_XOF_BLOCKBYTES, &xof_ctx);
        t1 = hal_get_time();
        printcycles("dke1_xof 1344 bytes cycles:", t1 - t0);
#endif    
        hal_send_str("+");
    
    }
    return;
}

int main(void)
{
    unsigned char msg[3 * 64];

    static const uint32_t non_iv_state[8] = {
        0x01234567U, 0x89abcdefU, 0xfedcba98U, 0x76543210U,
        0x0f1e2d3cU, 0x4b5a6978U, 0x88776655U, 0x44332211U
    };
    uint32_t digest[16];
    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");
    hal_send_str("SM3 asm/c test");

    fill_test_msg(msg, sizeof(msg), 0x6e676363U);

    if (run_compress_case("zero-block", sm3_iv, msg, 0) != 0) {
        fail_and_halt("SM3 zero-block failed");
    }
    if (run_compress_case("one-block-iv", sm3_iv, msg, 1) != 0) {
        fail_and_halt("SM3 one-block iv failed");
    }
    if (run_compress_case("one-block-non-iv", non_iv_state, msg + 64, 1) != 0) {
        fail_and_halt("SM3 one-block non-iv failed");
    }
    if (run_compress_case("two-block", sm3_iv, msg, 2) != 0) {
        fail_and_halt("SM3 two-block failed");
    }
    if (run_compress_case("three-block", non_iv_state, msg, 3) != 0) {
        fail_and_halt("SM3 three-block failed");
    }
    if (SM3_test("sm3hash", digest, msg, 1) != 0)
    {
        fail_and_halt("SM3 hash failed");
    }
    
    //pseudoXOF_test();
    speedSM3_Keccak();

    hal_send_str("SM3 asm/c tests OK");
    hal_send_str("+");
    hal_send_str("#");
    return 0;
}
