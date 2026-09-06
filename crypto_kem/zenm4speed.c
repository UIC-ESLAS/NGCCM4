#include <stdint.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "params.h"
#include "ntt.h"
#include "poly.h"

static void opt_poly_ntt(int16_t *a) { poly_ntt(a); }
static void opt_poly_ntt_mq(int16_t *a) { poly_ntt_mq(a); }
static void opt_poly_intt(int16_t *a) { poly_intt(a); }
static void opt_poly_basemul_ntt(int16_t *r, int16_t *a, int16_t *b)
{
    poly_basemul_ntt(r, a, b);
}
static void opt_poly_basemul_ntt_mq(int16_t *r, int16_t *a, int16_t *b)
{
    poly_basemul_ntt_mq(r, a, b);
}
static void opt_poly_baseinv_ntt(int16_t *r, int16_t *a)
{
    poly_baseinv_ntt(r, a);
}

#undef poly_ntt
#undef poly_ntt_mq
#undef poly_intt
#undef poly_basemul_ntt
#undef poly_basemul_ntt_mq
#undef poly_baseinv_ntt

#define montgomery_reduce ref_montgomery_reduce
#define poly_ntt ref_poly_ntt
#define poly_ntt_mq ref_poly_ntt_mq
#define poly_intt ref_poly_intt
#define poly_basemul_ntt ref_poly_basemul_ntt
#define poly_basemul_ntt_mq ref_poly_basemul_ntt_mq
#define poly_baseinv_ntt ref_poly_baseinv_ntt
#undef NTT_H
#if ZEN_N == 512
#include "DAWN_Prime_128/ref/ntt.c"
#elif ZEN_N == 1024
#include "DAWN_Prime_256/ref/ntt.c"
#else
#error "zenm4speed supports the 512- and 1024-coefficient ZEN/DAWN backends"
#endif
#undef montgomery_reduce
#undef poly_ntt
#undef poly_ntt_mq
#undef poly_intt
#undef poly_basemul_ntt
#undef poly_basemul_ntt_mq
#undef poly_baseinv_ntt

#define poly_ntt opt_poly_ntt
#define poly_ntt_mq opt_poly_ntt_mq
#define poly_intt opt_poly_intt
#define poly_basemul_ntt opt_poly_basemul_ntt
#define poly_basemul_ntt_mq opt_poly_basemul_ntt_mq
#define poly_baseinv_ntt opt_poly_baseinv_ntt

#ifndef ZENM4SPEED_ITERS
#define ZENM4SPEED_ITERS 32u
#endif

static int16_t in_a[ZEN_N];
static int16_t in_b[ZEN_N];
static int16_t work[ZEN_N];
static int16_t got[ZEN_N];
static int16_t ref[ZEN_N];
static volatile uint32_t checksum_sink;

static int16_t freeze_q32(int32_t x)
{
    int32_t r = x % ZEN_Q;

    if (r < 0) {
        r += ZEN_Q;
    }
    return (int16_t)r;
}

static int16_t freeze_q(int16_t x)
{
    return freeze_q32(x);
}

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

static void fill_poly(int16_t *a, unsigned int seed)
{
    unsigned int i;

    for (i = 0; i < ZEN_N; i++) {
        a[i] = (int16_t)((seed * 113u + i * 37u + (i >> 4) * 19u) % ZEN_Q);
    }
}

static uint32_t checksum_poly(const int16_t *a)
{
    uint32_t acc = 0x9e3779b9u;
    unsigned int i;

    for (i = 0; i < ZEN_N; i++) {
        acc ^= (uint16_t)a[i];
        acc = (acc << 5) | (acc >> 27);
    }
    return acc;
}

static int equal_modq(const int16_t *a, const int16_t *b)
{
    unsigned int i;

    for (i = 0; i < ZEN_N; i++) {
        if (freeze_q(a[i]) != freeze_q(b[i])) {
            send_unsigned("idx:", i);
            send_unsigned("ref:", (unsigned int)freeze_q(a[i]));
            send_unsigned("got:", (unsigned int)freeze_q(b[i]));
            return 0;
        }
    }
    return 1;
}

static int equal_raw_basemul_scaled(const int16_t *c_ref, const int16_t *c_opt)
{
    unsigned int i;

    for (i = 0; i < ZEN_N; i++) {
        if (freeze_q32(-9 * (int32_t)c_ref[i]) != freeze_q(c_opt[i])) {
            send_unsigned("idx:", i);
            send_unsigned("ref_scaled:", (unsigned int)freeze_q32(-9 * (int32_t)c_ref[i]));
            send_unsigned("got:", (unsigned int)freeze_q(c_opt[i]));
            return 0;
        }
    }
    return 1;
}

static int is_invertible_ntt_input(const int16_t *a)
{
    unsigned int i;

    for (i = 0; i < ZEN_N; i += 16) {
        int32_t sum = a[i]      + a[i + 1]  + a[i + 2]  + a[i + 3]
                    + a[i + 4]  + a[i + 5]  + a[i + 6]  + a[i + 7]
                    + a[i + 8]  + a[i + 9]  + a[i + 10] + a[i + 11]
                    + a[i + 12] + a[i + 13] + a[i + 14] + a[i + 15];

        if (sum == 0) {
            return 0;
        }
    }
    return 1;
}

static void prepare_ntt_inputs(void)
{
    fill_poly(in_a, 7u);
    fill_poly(in_b, 19u);
    ref_poly_ntt_mq(in_a);
    ref_poly_ntt_mq(in_b);
}

static void prepare_baseinv_input(void)
{
    unsigned int seed = 41u;

    do {
        fill_poly(in_a, seed++);
        ref_poly_ntt_mq(in_a);
    } while (!is_invertible_ntt_input(in_a));
}

static void check_correctness(void)
{
    fill_poly(in_a, 3u);
    memcpy(got, in_a, sizeof(got));
    memcpy(ref, in_a, sizeof(ref));
    poly_ntt_mq(got);
    ref_poly_ntt_mq(ref);
    if (!equal_modq(ref, got)) {
        fail_and_halt("poly_ntt_mq mismatch");
    }

    prepare_ntt_inputs();
    poly_basemul_ntt(got, in_a, in_b);
    ref_poly_basemul_ntt(ref, in_a, in_b);
    if (!equal_raw_basemul_scaled(ref, got)) {
        fail_and_halt("poly_basemul_ntt mismatch");
    }

    poly_basemul_ntt_mq(got, in_a, in_b);
    ref_poly_basemul_ntt_mq(ref, in_a, in_b);
    if (!equal_modq(ref, got)) {
        fail_and_halt("poly_basemul_ntt_mq mismatch");
    }

    prepare_baseinv_input();
    poly_baseinv_ntt(got, in_a);
    ref_poly_baseinv_ntt(ref, in_a);
    if (!equal_modq(ref, got)) {
        fail_and_halt("poly_baseinv_ntt mismatch");
    }
}

static __attribute__((noinline)) unsigned long long
time_unary_copy(void (*fn)(int16_t *), const int16_t *input)
{
    uint64_t t0;
    uint64_t t1;
    unsigned int i;

    t0 = hal_get_time();
    for (i = 0; i < ZENM4SPEED_ITERS; i++) {
        memcpy(work, input, sizeof(work));
        fn(work);
    }
    t1 = hal_get_time();

    checksum_sink ^= checksum_poly(work);
    return (unsigned long long)((t1 - t0) / ZENM4SPEED_ITERS);
}

static __attribute__((noinline)) unsigned long long
time_unary_out(void (*fn)(int16_t *, int16_t *), int16_t *out, int16_t *input)
{
    uint64_t t0;
    uint64_t t1;
    unsigned int i;

    t0 = hal_get_time();
    for (i = 0; i < ZENM4SPEED_ITERS; i++) {
        fn(out, input);
    }
    t1 = hal_get_time();

    checksum_sink ^= checksum_poly(out);
    return (unsigned long long)((t1 - t0) / ZENM4SPEED_ITERS);
}

static __attribute__((noinline)) unsigned long long
time_ternary(void (*fn)(int16_t *, int16_t *, int16_t *),
             int16_t *out,
             int16_t *a,
             int16_t *b)
{
    uint64_t t0;
    uint64_t t1;
    unsigned int i;

    t0 = hal_get_time();
    for (i = 0; i < ZENM4SPEED_ITERS; i++) {
        fn(out, a, b);
    }
    t1 = hal_get_time();

    checksum_sink ^= checksum_poly(out);
    return (unsigned long long)((t1 - t0) / ZENM4SPEED_ITERS);
}

static void report_cycles(const char *label,
                          unsigned long long opt_cycles,
                          unsigned long long ref_cycles)
{
    unsigned long long speedup_x100 = 0;

    if (opt_cycles != 0) {
        speedup_x100 = (ref_cycles * 100u + opt_cycles / 2u) / opt_cycles;
    }

    hal_send_str(label);
    send_unsignedll("opt cycles:", opt_cycles);
    send_unsignedll("ref cycles:", ref_cycles);
    send_unsignedll("speedup_x100:", speedup_x100);
}

int main(void)
{
    unsigned long long opt_cycles;
    unsigned long long ref_cycles;

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");
    send_unsigned("iters:", ZENM4SPEED_ITERS);

    check_correctness();

    fill_poly(in_a, 101u);
    opt_cycles = time_unary_copy(poly_ntt, in_a);
    ref_cycles = time_unary_copy(ref_poly_ntt, in_a);
    report_cycles("poly_ntt", opt_cycles, ref_cycles);

    fill_poly(in_a, 103u);
    opt_cycles = time_unary_copy(poly_ntt_mq, in_a);
    ref_cycles = time_unary_copy(ref_poly_ntt_mq, in_a);
    report_cycles("poly_ntt_mq", opt_cycles, ref_cycles);

    fill_poly(in_a, 107u);
    ref_poly_ntt(in_a);
    opt_cycles = time_unary_copy(poly_intt, in_a);
    ref_cycles = time_unary_copy(ref_poly_intt, in_a);
    report_cycles("poly_intt", opt_cycles, ref_cycles);

    prepare_ntt_inputs();
    opt_cycles = time_ternary(poly_basemul_ntt, got, in_a, in_b);
    ref_cycles = time_ternary(ref_poly_basemul_ntt, ref, in_a, in_b);
    report_cycles("poly_basemul_ntt", opt_cycles, ref_cycles);

    opt_cycles = time_ternary(poly_basemul_ntt_mq, got, in_a, in_b);
    ref_cycles = time_ternary(ref_poly_basemul_ntt_mq, ref, in_a, in_b);
    report_cycles("poly_basemul_ntt_mq", opt_cycles, ref_cycles);

    prepare_baseinv_input();
    opt_cycles = time_unary_out(poly_baseinv_ntt, got, in_a);
    ref_cycles = time_unary_out(ref_poly_baseinv_ntt, ref, in_a);
    report_cycles("poly_baseinv_ntt", opt_cycles, ref_cycles);

    send_unsigned("checksum:", checksum_sink);
    hal_send_str("#");
    return 0;
}
