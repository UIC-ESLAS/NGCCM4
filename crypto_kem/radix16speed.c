#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"

#ifndef __has_include
#define __has_include(x) 0
#endif

#if __has_include("radix16_r2.h")
#include "radix16_r2.h"
#define HAVE_RADIX16_R2 1
#endif

#ifndef R2_RADIX16_WORDS
#define R2_RADIX16_WORDS(n) (((n) + 7u) >> 3)
#endif

#ifndef R2_RADIX16_MAX_N
#define R2_RADIX16_MAX_N 256u
#endif

#ifndef RADIX16SPEED_ITERS
#define RADIX16SPEED_ITERS 1000u
#endif

#ifndef RADIX16SPEED_CHECKS
#define RADIX16SPEED_CHECKS 128u
#endif

#ifndef R2_RADIX16_LANE_MASK
#define R2_RADIX16_LANE_MASK 0x11111111u
#endif

#define RADIX16SPEED_MAX_WORDS R2_RADIX16_WORDS(R2_RADIX16_MAX_N)

static uint32_t a_rad[RADIX16SPEED_MAX_WORDS];
static uint32_t b_rad[RADIX16SPEED_MAX_WORDS];
static uint32_t r_rad[RADIX16SPEED_MAX_WORDS];
static uint32_t ref_rad[RADIX16SPEED_MAX_WORDS];
static volatile uint32_t checksum_sink;

#if defined(HAVE_RADIX16_R2)
extern void r2_radix16_mul_2_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_4_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_8_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_16_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_32_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_64_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_128_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
extern void r2_radix16_mul_256_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
#if R2_RADIX16_MAX_N >= 512u
extern void r2_radix16_mul_512_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
#endif
#if R2_RADIX16_MAX_N >= 1024u
extern void r2_radix16_mul_1024_asm(uint32_t *res, const uint32_t *a, const uint32_t *b);
#endif
#endif

static uint32_t next_word(uint32_t *state)
{
    uint32_t x = *state;

    x = x * 1664525u + 1013904223u;
    *state = x;
    return x & R2_RADIX16_LANE_MASK;
}

static void fill_inputs(uint32_t *state, size_t words)
{
    size_t i;

    for (i = 0; i < words; i++) {
        a_rad[i] = next_word(state);
        b_rad[i] = next_word(state);
        r_rad[i] = 0;
        ref_rad[i] = 0;
    }
    for (; i < RADIX16SPEED_MAX_WORDS; i++) {
        a_rad[i] = 0;
        b_rad[i] = 0;
        r_rad[i] = 0;
        ref_rad[i] = 0;
    }
}

static void init_inputs(void)
{
    uint32_t state = 0x72616431u;

    fill_inputs(&state, RADIX16SPEED_MAX_WORDS);
}

static uint32_t checksum_words(const uint32_t *x, size_t words)
{
    uint32_t acc = 0x9e3779b9u;
    size_t i;

    for (i = 0; i < words; i++) {
        acc ^= x[i] & R2_RADIX16_LANE_MASK;
        acc = (acc << 5) | (acc >> 27);
    }
    return acc;
}

static uint32_t packed_coeff(const uint32_t *a, size_t idx)
{
    return (a[idx >> 3] >> (4u * (idx & 7u))) & 1u;
}

static void packed_xor_coeff(uint32_t *a, size_t idx, uint32_t bit)
{
    a[idx >> 3] ^= (bit & 1u) << (4u * (idx & 7u));
}

static void ref_mul_packed(uint32_t *res,
                           const uint32_t *a,
                           const uint32_t *b,
                           size_t n)
{
    size_t words = (n + 7u) >> 3;
    size_t i, j;

    memset(res, 0, words * sizeof(uint32_t));
    for (i = 0; i < n; i++) {
        uint32_t mask = 0u - packed_coeff(a, i);

        for (j = 0; j < n; j++) {
            size_t idx = i + j;
            uint32_t bit = packed_coeff(b, j) & mask;

            if (idx >= n) {
                idx -= n;
            }
            packed_xor_coeff(res, idx, bit);
        }
    }
}

#if defined(HAVE_RADIX16_R2)
static int check_mul(const char *label, size_t n, size_t words)
{
    uint32_t state = 0x63686b31u ^ (uint32_t)n;
    unsigned int t;
    size_t i;

    for (t = 0; t < RADIX16SPEED_CHECKS; t++) {
        fill_inputs(&state, words);
        ref_mul_packed(ref_rad, a_rad, b_rad, n);
        r2_radix16_mul(r_rad, a_rad, b_rad, n);

        for (i = 0; i < words; i++) {
            uint32_t ref = ref_rad[i] & R2_RADIX16_LANE_MASK;
            uint32_t got = r_rad[i] & R2_RADIX16_LANE_MASK;

            if (ref != got) {
                hal_send_str(label);
                send_unsigned("case:", t);
                send_unsigned("word:", (unsigned int)i);
                return 0;
            }
        }
    }
    return 1;
}
#endif

static __attribute__((noinline)) unsigned long long
time_mul(void (*fn)(uint32_t *, const uint32_t *, const uint32_t *), size_t words)
{
    uint64_t t0;
    uint64_t t1;
    unsigned int i;

    t0 = hal_get_time();
    for (i = 0; i < RADIX16SPEED_ITERS; i++) {
        fn(r_rad, a_rad, b_rad);
    }
    t1 = hal_get_time();

    checksum_sink ^= checksum_words(r_rad, words);
    return (unsigned long long)((t1 - t0) / RADIX16SPEED_ITERS);
}

int main(void)
{
    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");

#if !defined(HAVE_RADIX16_R2)
    hal_send_str("radix16 asm unavailable");
    hal_send_str("#");
    return 0;
#else
    if (!check_mul("mul8 mismatch", 8u, 1u)) {
        hal_send_str("#");
        return -1;
    }
    if (!check_mul("mul16 mismatch", 16u, 2u)) {
        hal_send_str("#");
        return -1;
    }
    if (!check_mul("mul32 mismatch", 32u, 4u)) {
        hal_send_str("#");
        return -1;
    }
    if (!check_mul("mul64 mismatch", 64u, 8u)) {
        hal_send_str("#");
        return -1;
    }
    if (!check_mul("mul128 mismatch", 128u, 16u)) {
        hal_send_str("#");
        return -1;
    }
    if (!check_mul("mul256 mismatch", 256u, 32u)) {
        hal_send_str("#");
        return -1;
    }
#if R2_RADIX16_MAX_N >= 512u
    if (!check_mul("mul512 mismatch", 512u, 64u)) {
        hal_send_str("#");
        return -1;
    }
#endif
#if R2_RADIX16_MAX_N >= 1024u
    if (!check_mul("mul1024 mismatch", 1024u, 128u)) {
        hal_send_str("#");
        return -1;
    }
#endif

    init_inputs();
    send_unsignedll("mul2 cycles:", time_mul(r2_radix16_mul_2_asm, 1u));
    send_unsignedll("mul4 cycles:", time_mul(r2_radix16_mul_4_asm, 1u));
    send_unsignedll("mul8 cycles:", time_mul(r2_radix16_mul_8_asm, 1u));
    send_unsignedll("mul16 cycles:", time_mul(r2_radix16_mul_16_asm, 2u));
    send_unsignedll("mul32 cycles:", time_mul(r2_radix16_mul_32_asm, 4u));
    send_unsignedll("mul64 cycles:", time_mul(r2_radix16_mul_64_asm, 8u));
    send_unsignedll("mul128 cycles:", time_mul(r2_radix16_mul_128_asm, 16u));
    send_unsignedll("mul256 cycles:", time_mul(r2_radix16_mul_256_asm, 32u));
#if R2_RADIX16_MAX_N >= 512u
    send_unsignedll("mul512 cycles:", time_mul(r2_radix16_mul_512_asm, 64u));
#endif
#if R2_RADIX16_MAX_N >= 1024u
    send_unsignedll("mul1024 cycles:", time_mul(r2_radix16_mul_1024_asm, 128u));
#endif
    send_unsigned("checksum:", checksum_sink);
    hal_send_str("#");
    return 0;
#endif
}
