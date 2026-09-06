#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "params.h"
#include "ntt.h"
#include "poly.h"

#ifndef __has_include
#define __has_include(x) 0
#endif

#if __has_include("radix16_r2.h")
#include "radix16_r2.h"
#define ZENSPEED_HAVE_RADIX16 1
#else
#define ZENSPEED_HAVE_RADIX16 0
#endif

#if ZENSPEED_HAVE_RADIX16
#ifndef R2_RADIX16_MAX_N
#define R2_RADIX16_MAX_N ZEN_N2
#endif
#if R2_RADIX16_MAX_N < ZEN_N2
#define ZENSPEED_RADIX16_MAX_N R2_RADIX16_MAX_N
#else
#define ZENSPEED_RADIX16_MAX_N ZEN_N2
#endif
#endif

#ifndef ZENSPEED_ITERS
#define ZENSPEED_ITERS 32u
#endif

#if ZENSPEED_HAVE_RADIX16
#define ZENSPEED_HAVE_MUL_IN_R2_N 0
#else
#define ZENSPEED_HAVE_MUL_IN_R2_N 1
#endif

static int16_t in_a[ZEN_N];
static int16_t in_b[ZEN_N];
static int16_t work[ZEN_N];
static int16_t out[ZEN_N];
static int16_t r2_a[ZEN_N2];
static int16_t r2_b[ZEN_N2];
static int16_t r2_out[ZEN_N2];
static volatile uint32_t checksum_sink;

#if ZENSPEED_HAVE_RADIX16
static uint32_t rad_a[R2_RADIX16_WORDS(ZENSPEED_RADIX16_MAX_N)];
static uint32_t rad_b[R2_RADIX16_WORDS(ZENSPEED_RADIX16_MAX_N)];
static uint32_t rad_out[R2_RADIX16_WORDS(ZENSPEED_RADIX16_MAX_N)];
#endif

typedef void (*poly_unary_fn)(int16_t *);
typedef void (*poly_binary_fn)(int16_t *, int16_t *, int16_t *);

static void send_cycles(const char *label, unsigned long long cycles);

#if ZENSPEED_HAVE_MUL_IN_R2_N && ZEN_N4 == 256
void mul_in_R2_256(int16_t *a, int16_t *b, int16_t *res);
#endif

#if ZENSPEED_HAVE_MUL_IN_R2_N
#if ZEN_N4 == 128
#define ZENSPEED_MUL_IN_R2_N4_LABEL "mul_in_R2_128 cycles:"
#elif ZEN_N4 == 256
#define ZENSPEED_MUL_IN_R2_N4_LABEL "mul_in_R2_256 cycles:"
#elif ZEN_N4 == 512
#define ZENSPEED_MUL_IN_R2_N4_LABEL "mul_in_R2_512 cycles:"
#endif
#if ZEN_N2 == 256
#define ZENSPEED_MUL_IN_R2_N2_LABEL "mul_in_R2_256 cycles:"
#elif ZEN_N2 == 512
#define ZENSPEED_MUL_IN_R2_N2_LABEL "mul_in_R2_512 cycles:"
#elif ZEN_N2 == 1024
#define ZENSPEED_MUL_IN_R2_N2_LABEL "mul_in_R2_1024 cycles:"
#endif
#endif

static void fail_and_halt(const char *label)
{
    hal_send_str(label);
    hal_send_str("#");
#ifdef MPS2_AN386
    __builtin_trap();
#endif
    while (1) {
    }
}

static void fill_q_poly(int16_t *a, size_t n, uint32_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        uint32_t x = seed + (uint32_t)i * 37u + ((uint32_t)i >> 4) * 19u;

        a[i] = (int16_t)(x % ZEN_Q);
    }
}

static void fill_binary_poly(int16_t *a, size_t n, uint32_t seed)
{
    size_t i;
    uint16_t parity = 0;

    for (i = 0; i < n; i++) {
        uint16_t bit = (uint16_t)(((seed + (uint32_t)i * 13u + ((uint32_t)i >> 3)) >> (i & 7u)) & 1u);

        a[i] = (int16_t)bit;
        parity ^= bit;
    }
    a[0] ^= (int16_t)(parity ^ 1u);
}

static uint32_t checksum_i16(const int16_t *a, size_t n)
{
    uint32_t acc = 0x9e3779b9u;
    size_t i;

    for (i = 0; i < n; i++) {
        acc ^= (uint16_t)a[i];
        acc = (acc << 5) | (acc >> 27);
    }
    return acc;
}

#if ZENSPEED_HAVE_RADIX16
static uint32_t checksum_u32(const uint32_t *a, size_t n)
{
    uint32_t acc = 0x85ebca6bu;
    size_t i;

    for (i = 0; i < n; i++) {
        acc ^= a[i];
        acc = (acc << 7) | (acc >> 25);
    }
    return acc;
}
#endif

static __attribute__((noinline)) void call_poly_ntt(int16_t *a)
{
    poly_ntt(a);
}

static __attribute__((noinline)) void call_poly_ntt_mq(int16_t *a)
{
    poly_ntt_mq(a);
}

static __attribute__((noinline)) void call_poly_intt(int16_t *a)
{
    poly_intt(a);
}

static __attribute__((noinline)) void call_empty_i16(int16_t *a)
{
    __asm__ volatile ("" : : "r"(a) : "memory");
}

static __attribute__((noinline)) void call_poly_basemul_ntt(int16_t *r, int16_t *a, int16_t *b)
{
    poly_basemul_ntt(r, a, b);
}

static __attribute__((noinline)) void call_poly_basemul_ntt_mq(int16_t *r, int16_t *a, int16_t *b)
{
    poly_basemul_ntt_mq(r, a, b);
}

static __attribute__((noinline)) void call_poly_baseinv_ntt(int16_t *r, int16_t *a)
{
    poly_baseinv_ntt(r, a);
}

static __attribute__((noinline)) unsigned int call_check_poly_inv_Zq(int16_t *a)
{
    return (unsigned int)check_poly_inv_Zq(a);
}

static __attribute__((noinline)) unsigned int call_check_poly_inv_Z2(int16_t *a)
{
#if ZENSPEED_HAVE_RADIX16 && ZEN_N == 1024
    return (unsigned int)check_poly_inv_Z2_asm(a);
#else
    return (unsigned int)check_poly_inv_Z2(a);
#endif
}

#if ZENSPEED_HAVE_MUL_IN_R2_N
static __attribute__((noinline)) void call_mul_in_R2_N4(void)
{
#if ZEN_N4 == 128
    mul_in_R2_128(r2_a, r2_b, r2_out);
#elif ZEN_N4 == 256
    mul_in_R2_256(r2_a, r2_b, r2_out);
#elif ZEN_N4 == 512
    mul_in_R2_512(r2_a, r2_b, r2_out);
#else
#error Unsupported ZEN_N4 for zenspeed mul_in_R2_N4
#endif
}

static __attribute__((noinline)) void call_mul_in_R2_N2(void)
{
#if ZEN_N2 == 256
    mul_in_R2_256(r2_a, r2_b, r2_out);
#elif ZEN_N2 == 512
    mul_in_R2_512(r2_a, r2_b, r2_out);
#elif ZEN_N2 == 1024
    mul_in_R2_1024(r2_a, r2_b, r2_out);
#else
#error Unsupported ZEN_N2 for zenspeed mul_in_R2_N2
#endif
}
#endif

static __attribute__((noinline)) void call_fastinversion(void)
{
#if ZENSPEED_HAVE_RADIX16
    FastInversion(rad_out, rad_a);
#else
    FastInversion(r2_out, r2_a);
#endif
}

#if ZENSPEED_HAVE_RADIX16
static __attribute__((noinline)) void call_poly_xor4_radix16(void)
{
    checksum_sink ^= (uint32_t)poly_xor4_radix16(rad_out, in_a);
}

#endif

static __attribute__((noinline)) unsigned long long
time_poly_unary_copy(poly_unary_fn fn, const int16_t *input, size_t n)
{
    uint64_t t0;
    uint64_t t1;

    memcpy(work, input, n * sizeof(int16_t));
    t0 = hal_get_time();
    fn(work);
    t1 = hal_get_time();
    checksum_sink ^= checksum_i16(work, n);
    return (unsigned long long)(t1 - t0);
}

static __attribute__((noinline)) unsigned long long
time_poly_unary_out(void (*fn)(int16_t *, int16_t *),
                    int16_t *dst,
                    int16_t *src,
                    size_t n)
{
    uint64_t t0;
    uint64_t t1;

    t0 = hal_get_time();
    fn(dst, src);
    t1 = hal_get_time();
    checksum_sink ^= checksum_i16(dst, n);
    return (unsigned long long)(t1 - t0);
}

static __attribute__((noinline)) unsigned long long
time_poly_binary(poly_binary_fn fn, int16_t *dst, int16_t *a, int16_t *b, size_t n)
{
    uint64_t t0;
    uint64_t t1;

    t0 = hal_get_time();
    fn(dst, a, b);
    t1 = hal_get_time();
    checksum_sink ^= checksum_i16(dst, n);
    return (unsigned long long)(t1 - t0);
}

#if ZENSPEED_HAVE_MUL_IN_R2_N
static __attribute__((noinline)) unsigned long long
time_void_call(void (*fn)(void), const int16_t *check_src, size_t check_n)
{
    uint64_t t0;
    uint64_t t1;

    t0 = hal_get_time();
    fn();
    t1 = hal_get_time();

    if (check_src != NULL) {
        checksum_sink ^= checksum_i16(check_src, check_n);
    }
    return (unsigned long long)(t1 - t0);
}
#endif

static __attribute__((noinline)) unsigned long long
time_check(unsigned int (*fn)(int16_t *), int16_t *a)
{
    uint64_t t0;
    uint64_t t1;
    unsigned int v;

    t0 = hal_get_time();
    v = fn(a);
    t1 = hal_get_time();

    checksum_sink ^= v;
    return (unsigned long long)(t1 - t0);
}

#if ZENSPEED_HAVE_RADIX16
static __attribute__((noinline)) unsigned long long
time_void_radix(void (*fn)(void), const uint32_t *check_src, size_t words)
{
    uint64_t t0;
    uint64_t t1;

    t0 = hal_get_time();
    fn();
    t1 = hal_get_time();
    checksum_sink ^= checksum_u32(check_src, words);
    return (unsigned long long)(t1 - t0);
}

static __attribute__((noinline)) unsigned long long
time_r2_radix16_mul(size_t n)
{
    uint64_t t0;
    uint64_t t1;
    size_t words = R2_RADIX16_WORDS(n);

    t0 = hal_get_time();
    r2_radix16_mul(rad_out, rad_a, rad_b, n);
    t1 = hal_get_time();
    checksum_sink ^= checksum_u32(rad_out, words);
    return (unsigned long long)(t1 - t0);
}

static void send_r2_radix16_mul_cycles(const char *label, size_t n)
{
    if (n <= ZENSPEED_RADIX16_MAX_N) {
        send_cycles(label, time_r2_radix16_mul(n));
    }
}
#endif

static void prepare_ntt_domain_inputs(void)
{
    fill_q_poly(in_a, ZEN_N, 19u);
    fill_q_poly(in_b, ZEN_N, 41u);
    call_poly_ntt_mq(in_a);
    call_poly_ntt_mq(in_b);
}

static void prepare_baseinv_input(void)
{
    uint32_t seed;

    for (seed = 101u; seed < 1000u; seed++) {
        fill_q_poly(in_a, ZEN_N, seed);
        call_poly_ntt_mq(in_a);
        if (call_check_poly_inv_Zq(in_a) == 0u) {
            return;
        }
    }

    fail_and_halt("baseinv_input_failed");
}

static void prepare_binary_inputs(void)
{
    fill_binary_poly(r2_a, ZEN_N2, 0x13579bdfu);
    fill_binary_poly(r2_b, ZEN_N2, 0x2468ace0u);
    memset(r2_out, 0, sizeof(r2_out));

#if ZENSPEED_HAVE_RADIX16
    r2_radix16_pack(rad_a, r2_a, ZENSPEED_RADIX16_MAX_N);
    r2_radix16_pack(rad_b, r2_b, ZENSPEED_RADIX16_MAX_N);
    memset(rad_out, 0, sizeof(rad_out));
#endif
}

static void send_cycles(const char *label, unsigned long long cycles)
{
    send_unsignedll(label, cycles);
}

int main(void)
{
    unsigned long long call_overhead;
    unsigned long long raw_cycles;
    unsigned int i;

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");
    send_unsigned("ZEN_N:", ZEN_N);
    send_unsigned("iters:", ZENSPEED_ITERS);
    send_unsigned("radix16:", ZENSPEED_HAVE_RADIX16);

    for (i = 0; i < ZENSPEED_ITERS; i++) {
        fill_q_poly(in_a, ZEN_N, 7u);
        call_overhead = time_poly_unary_copy(call_empty_i16, in_a, ZEN_N);
        send_cycles("timer_call_overhead cycles:", call_overhead);

        raw_cycles = time_poly_unary_copy(call_poly_ntt, in_a, ZEN_N);
        send_cycles("poly_ntt cycles:", raw_cycles);

        raw_cycles = time_poly_unary_copy(call_poly_ntt_mq, in_a, ZEN_N);
        send_cycles("poly_ntt_mq cycles:", raw_cycles);

        memcpy(out, in_a, sizeof(in_a));
        call_poly_ntt_mq(out);
        raw_cycles = time_poly_unary_copy(call_poly_intt, out, ZEN_N);
        send_cycles("poly_intt cycles:", raw_cycles);

        prepare_ntt_domain_inputs();
        send_cycles("poly_basemul_ntt cycles:",
                    time_poly_binary(call_poly_basemul_ntt, out, in_a, in_b, ZEN_N));
        send_cycles("poly_basemul_ntt_mq cycles:",
                    time_poly_binary(call_poly_basemul_ntt_mq, out, in_a, in_b, ZEN_N));

        prepare_baseinv_input();
        send_cycles("poly_baseinv_ntt cycles:",
                    time_poly_unary_out(call_poly_baseinv_ntt, out, in_a, ZEN_N));
        send_cycles("check_poly_inv_Zq cycles:", time_check(call_check_poly_inv_Zq, in_a));

        prepare_binary_inputs();
        send_cycles("check_poly_inv_Z2 cycles:", time_check(call_check_poly_inv_Z2, r2_a));

#if ZENSPEED_HAVE_MUL_IN_R2_N
        send_cycles(ZENSPEED_MUL_IN_R2_N4_LABEL, time_void_call(call_mul_in_R2_N4, r2_out, ZEN_N4));
        send_cycles(ZENSPEED_MUL_IN_R2_N2_LABEL, time_void_call(call_mul_in_R2_N2, r2_out, ZEN_N2));
#else
        send_cycles("poly_xor4_radix16 cycles:",
                    time_void_radix(call_poly_xor4_radix16, rad_out, R2_RADIX16_WORDS(ZEN_N4)));
        send_r2_radix16_mul_cycles("r2_radix16_mul_2 cycles:", 2u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_4 cycles:", 4u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_8 cycles:", 8u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_16 cycles:", 16u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_32 cycles:", 32u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_64 cycles:", 64u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_128 cycles:", 128u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_256 cycles:", 256u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_512 cycles:", 512u);
        send_r2_radix16_mul_cycles("r2_radix16_mul_1024 cycles:", 1024u);
#endif

#if ZENSPEED_HAVE_RADIX16
        send_cycles("FastInversion cycles:",
                    time_void_radix(call_fastinversion, rad_out, R2_RADIX16_WORDS(ZEN_N4)));
#else
        send_cycles("FastInversion cycles:", time_void_call(call_fastinversion, r2_out, ZEN_N4));
#endif
        checksum_sink += i + 1u;
        hal_send_str("+");
    }

    send_unsigned("checksum:", checksum_sink);
    hal_send_str("#");
    return 0;
}
