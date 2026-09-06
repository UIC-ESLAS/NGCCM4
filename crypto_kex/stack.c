#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "hal.h"
#include "sendfn.h"
#include "KEX_AlgorithmInstance.h"

#ifndef MAX_STACK_SIZE
#define MAX_STACK_SIZE hal_get_stack_size()
#endif

#ifndef STACK_SIZE_INCR
#define STACK_SIZE_INCR 0x1000
#endif

DRNG_ctx drng_algorithm;

static const unsigned char stack_seed[] = {
    0x6e, 0x67, 0x63, 0x63, 0x6d, 0x34, 0x2d, 0x6b,
    0x65, 0x78, 0x2d, 0x73, 0x74, 0x61, 0x63, 0x6b,
    0x2d, 0x73, 0x65, 0x65, 0x64
};

static unsigned int canary_size;
static volatile unsigned char *p;
static unsigned int c;
static unsigned char canary = 0x42;

static unsigned int stack_init_a;
static unsigned int stack_init_b;
static unsigned int stack_pass1;
static unsigned int stack_pass2;
static unsigned int stack_pass3;
static unsigned int stack_derive_a;
static unsigned int stack_derive_b;

static inline uintptr_t current_stack_pointer(void)
{
    uintptr_t sp;
    __asm__ volatile ("mov %0, sp" : "=r" (sp));
    return sp;
}

#define FILL_STACK() \
    p = (volatile unsigned char *)current_stack_pointer(); \
    while (p > (volatile unsigned char *)(current_stack_pointer() - canary_size)) *(--p) = canary;

#define CHECK_STACK() \
    p = (volatile unsigned char *)(current_stack_pointer() - canary_size); \
    c = canary_size; \
    while (p < (volatile unsigned char *)current_stack_pointer() && *p == canary) { p++; c--; }

static unsigned char *alloc_buffer(unsigned long long len)
{
    size_t alloc_len = (len == 0) ? 1u : (size_t)len;
    return malloc(alloc_len);
}

static int check_measured_stack(void)
{
    return c < canary_size ? 0 : -1;
}

static __attribute__((noinline)) int test_exchange(
    unsigned char *pka, unsigned char *ska,
    unsigned char *pkb, unsigned char *skb,
    unsigned char *sta, unsigned char *stb,
    unsigned char *ssa, unsigned char *ssb,
    unsigned char *m1, unsigned char *m2, unsigned char *m3)
{
    unsigned long long pass = kex_get_passes_num();
    unsigned long long pka_len = kex_get_pk_len_bytes();
    unsigned long long ska_len = kex_get_sk_len_bytes();
    unsigned long long pkb_len = kex_get_pk_len_bytes();
    unsigned long long skb_len = kex_get_sk_len_bytes();
    unsigned long long sta_len = kex_get_sta_len_bytes();
    unsigned long long stb_len = kex_get_stb_len_bytes();
    unsigned long long ssa_len = kex_get_ss_len_bytes();
    unsigned long long ssb_len = kex_get_ss_len_bytes();
    unsigned long long m1_len = 0;
    unsigned long long m2_len = 0;
    unsigned long long m3_len = 0;
    unsigned char *ma;
    unsigned long long ma_len;
    int rc;

    FILL_STACK()
    rc = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    if (rc < 0) {
        hal_send_str("init_a failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_init_a = c;

    FILL_STACK()
    rc = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    if (rc < 0) {
        hal_send_str("init_b failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_init_b = c;

    FILL_STACK()
    rc = kex_generate_pass1_msg_a(
        ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
    if (rc != 0) {
        hal_send_str("pass1 failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_pass1 = c;

    FILL_STACK()
    rc = kex_generate_pass2_msg_b(
        skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len, m2, &m2_len);
    if (rc != (pass == 2 ? 1 : 0)) {
        hal_send_str("pass2 failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_pass2 = c;
    ma = m1;
    ma_len = m1_len;

    if (pass == 3) {
        FILL_STACK()
        rc = kex_generate_pass3_msg_a(
            ska, ska_len, pkb, pkb_len, m2, m2_len, sta, &sta_len,
            m3, &m3_len);
        if (rc != 1) {
            hal_send_str("pass3 failed");
            return -1;
        }
        CHECK_STACK()
        if (check_measured_stack() != 0) {
            return -1;
        }
        stack_pass3 = c;
        ma = m3;
        ma_len = m3_len;
    }

    FILL_STACK()
    rc = kex_derive_ss_a(
        ska, ska_len, pkb, pkb_len, m2, m2_len, sta, sta_len,
        ssa, &ssa_len);
    if (rc < 0) {
        hal_send_str("derive_a failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_derive_a = c;

    FILL_STACK()
    rc = kex_derive_ss_b(
        skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len,
        ssb, &ssb_len);
    if (rc < 0) {
        hal_send_str("derive_b failed");
        return -1;
    }
    CHECK_STACK()
    if (check_measured_stack() != 0) {
        return -1;
    }
    stack_derive_b = c;

    if (ssa_len != ssb_len || memcmp(ssa, ssb, (size_t)ssa_len) != 0) {
        hal_send_str("shared secret mismatch");
        return -1;
    }

    send_unsigned("init_a stack usage:", stack_init_a);
    send_unsigned("init_b stack usage:", stack_init_b);
    send_unsigned("pass1 stack usage:", stack_pass1);
    send_unsigned("pass2 stack usage:", stack_pass2);
    if (pass == 3) {
        send_unsigned("pass3 stack usage:", stack_pass3);
    }
    send_unsigned("derive_a stack usage:", stack_derive_a);
    send_unsigned("derive_b stack usage:", stack_derive_b);
    hal_send_str("OK KEYS");
    return 0;
}

int main(void)
{
    unsigned long long pass = kex_get_passes_num();
    unsigned long long pka_len = kex_get_pk_len_bytes();
    unsigned long long ska_len = kex_get_sk_len_bytes();
    unsigned long long pkb_len = kex_get_pk_len_bytes();
    unsigned long long skb_len = kex_get_sk_len_bytes();
    unsigned long long sta_len = kex_get_sta_len_bytes();
    unsigned long long stb_len = kex_get_stb_len_bytes();
    unsigned long long ss_len = kex_get_ss_len_bytes();
    unsigned long long total_len = kex_get_total_msg_len_bytes();
    unsigned char *pka;
    unsigned char *ska;
    unsigned char *pkb;
    unsigned char *skb;
    unsigned char *sta;
    unsigned char *stb;
    unsigned char *ssa;
    unsigned char *ssb;
    unsigned char *m1;
    unsigned char *m2;
    unsigned char *m3;

    hal_setup(CLOCK_FAST);
    hal_send_str("==========================");

    if (pass != 2 && pass != 3) {
        hal_send_str("unsupported_pass_count");
        return -1;
    }

    pka = alloc_buffer(pka_len);
    ska = alloc_buffer(ska_len);
    pkb = alloc_buffer(pkb_len);
    skb = alloc_buffer(skb_len);
    sta = alloc_buffer(sta_len);
    stb = alloc_buffer(stb_len);
    ssa = alloc_buffer(ss_len);
    ssb = alloc_buffer(ss_len);
    m1 = alloc_buffer(total_len);
    m2 = alloc_buffer(total_len);
    m3 = alloc_buffer(total_len);

    if (pka == NULL || ska == NULL || pkb == NULL || skb == NULL ||
        sta == NULL || stb == NULL || ssa == NULL || ssb == NULL ||
        m1 == NULL || m2 == NULL || m3 == NULL) {
        hal_send_str("alloc failed");
        free(pka);
        free(ska);
        free(pkb);
        free(skb);
        free(sta);
        free(stb);
        free(ssa);
        free(ssb);
        free(m1);
        free(m2);
        free(m3);
        return -1;
    }

    if (init_random_number(&drng_algorithm, stack_seed, sizeof(stack_seed)) != 0) {
        hal_send_str("drng_init_failed");
        free(pka);
        free(ska);
        free(pkb);
        free(skb);
        free(sta);
        free(stb);
        free(ssa);
        free(ssb);
        free(m1);
        free(m2);
        free(m3);
        return -1;
    }

    canary_size = STACK_SIZE_INCR;
    while (test_exchange(pka, ska, pkb, skb, sta, stb, ssa, ssb, m1, m2, m3) != 0) {
        if (canary_size == MAX_STACK_SIZE) {
            hal_send_str("failed to measure stack usage.");
            break;
        }
        canary_size += STACK_SIZE_INCR;
        if (canary_size >= MAX_STACK_SIZE) {
            canary_size = MAX_STACK_SIZE;
        }
    }

    free(pka);
    free(ska);
    free(pkb);
    free(skb);
    free(sta);
    free(stb);
    free(ssa);
    free(ssb);
    free(m1);
    free(m2);
    free(m3);

    hal_send_str("#");
    return 0;
}
