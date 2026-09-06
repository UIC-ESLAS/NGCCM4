#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "poly.h"
#include "params.h"

static const unsigned char speed_seed[] = {
    0x6e, 0x67, 0x63, 0x63, 0x6d, 0x34, 0x2d, 0x73,
    0x70, 0x65, 0x65, 0x64, 0x2d, 0x73, 0x65, 0x65, 0x64
};

static void fail_and_halt(const char *reason) {
    hal_send_str(reason);
#ifdef MPS2_AN386
    __builtin_trap();
#endif
    while (1) {
    }
}

#define DEFINE_MUL_IN_R2_SMALL(N, MASKN)                     \
    void mul_in_R2_##N(int16_t *a, int16_t *b, int16_t *res) \
    {                                                        \
        unsigned int i;                                      \
        uint64_t B;                                          \
        uint64_t R;                                          \
        uint64_t mask;                                       \
        uint64_t wrap;                                       \
                                                             \
        B = 0;                                               \
        R = 0;                                               \
                                                             \
        for (i = 0; i < (N); i++)                            \
        {                                                    \
            B |= ((uint64_t)((uint16_t)b[i] & 1u)) << i;     \
        }                                                    \
                                                             \
        B &= (MASKN);                                        \
                                                             \
        for (i = 0; i < (N); i++)                            \
        {                                                    \
            mask = 0ULL - ((uint64_t)((uint16_t)a[i] & 1u)); \
            R ^= B & mask;                                   \
                                                             \
            wrap = (B >> ((N) - 1)) & 1ULL;                  \
            B = ((B << 1) | wrap) & (MASKN);                 \
        }                                                    \
                                                             \
        for (i = 0; i < (N); i++)                            \
        {                                                    \
            res[i] = (int16_t)((R >> i) & 1ULL);             \
        }                                                    \
    }
DEFINE_MUL_IN_R2_SMALL(2, 0x0000000000000003ULL)
DEFINE_MUL_IN_R2_SMALL(4, 0x000000000000000FULL)
DEFINE_MUL_IN_R2_SMALL(8, 0x00000000000000FFULL)
DEFINE_MUL_IN_R2_SMALL(16, 0x000000000000FFFFULL)
DEFINE_MUL_IN_R2_SMALL(32, 0x00000000FFFFFFFFULL)
DEFINE_MUL_IN_R2_SMALL(64, UINT64_MAX)

#if __has_include("radix16_r2.h")
#include "radix16_r2.h"
#define ZENSPEED_HAVE_RADIX16 1
#else
#define ZENSPEED_HAVE_RADIX16 0
#endif

extern void r2_radix16_mul_2_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_4_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_8_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_16_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_32_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_64_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_128_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_256_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_256x128_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);

int main(void) {
    uint64_t t0;
    uint64_t t1;
	int32_t i;
    int16_t a[ZEN_N], b[ZEN_N], res[ZEN_N];
#if ZENSPEED_HAVE_RADIX16
    uint32_t rad_a[R2_RADIX16_WORDS(ZEN_N)], rad_b[R2_RADIX16_WORDS(ZEN_N)], rad_res[R2_RADIX16_WORDS(ZEN_N)];
#endif
    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");


    for (i = 0; i < NGCC_ITERATIONS; i++) {
        t0 = hal_get_time();
        mul_in_R2_2(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_2 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        mul_in_R2_4(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_4 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        mul_in_R2_8(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_8 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        mul_in_R2_16(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_16 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        mul_in_R2_32(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_32 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        mul_in_R2_64(a, b, res);
        t1 = hal_get_time();
        send_unsignedll("mul_in_R2_64 cycles:", (unsigned long long)(t1 - t0));

#if ZENSPEED_HAVE_RADIX16
        t0 = hal_get_time();
        r2_radix16_mul_2_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 2 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_4_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 4 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_8_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 8 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_16_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 16 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_32_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 32 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_64_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 64 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_128_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 128 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_256_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 256 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        r2_radix16_mul_256x128_asm(rad_res, rad_a, rad_b);
        t1 = hal_get_time();
        send_unsignedll("r2_radix16_mul 256x128 cycles:", (unsigned long long)(t1 - t0));
#endif
        hal_send_str("+");
    }

    hal_send_str("#");
    return 0;
}
