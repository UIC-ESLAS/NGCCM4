#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "hal.h"
#include "sendfn.h"
#include "KEX_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static const unsigned char speed_seed[] = {
    0x6e, 0x67, 0x63, 0x63, 0x6d, 0x34, 0x2d, 0x6b,
    0x65, 0x78, 0x2d, 0x73, 0x70, 0x65, 0x65, 0x64,
    0x2d, 0x73, 0x65, 0x65, 0x64
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

static unsigned char *alloc_buffer(unsigned long long len)
{
    size_t alloc_len = (len == 0) ? 1u : (size_t)len;
    return malloc(alloc_len);
}

int main(void)
{
    unsigned long long pass = kex_get_passes_num();
    unsigned long long pka_len_max = kex_get_pk_len_bytes();
    unsigned long long ska_len_max = kex_get_sk_len_bytes();
    unsigned long long pkb_len_max = kex_get_pk_len_bytes();
    unsigned long long skb_len_max = kex_get_sk_len_bytes();
    unsigned long long sta_len_max = kex_get_sta_len_bytes();
    unsigned long long stb_len_max = kex_get_stb_len_bytes();
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
    unsigned int i;

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");

    if (pass != 2 && pass != 3) {
        fail_and_halt("unsupported_pass_count");
    }
    if (init_random_number(&drng_algorithm, speed_seed, sizeof(speed_seed)) != 0) {
        fail_and_halt("drng_init_failed");
    }

    pka = alloc_buffer(pka_len_max);
    ska = alloc_buffer(ska_len_max);
    pkb = alloc_buffer(pkb_len_max);
    skb = alloc_buffer(skb_len_max);
    sta = alloc_buffer(sta_len_max);
    stb = alloc_buffer(stb_len_max);
    ssa = alloc_buffer(ss_len);
    ssb = alloc_buffer(ss_len);
    m1 = alloc_buffer(total_len);
    m2 = alloc_buffer(total_len);
    m3 = alloc_buffer(total_len);
    if (pka == NULL || ska == NULL || pkb == NULL || skb == NULL ||
        sta == NULL || stb == NULL || ssa == NULL || ssb == NULL ||
        m1 == NULL || m2 == NULL || m3 == NULL) {
        fail_and_halt("alloc_failed");
    }

    for (i = 0; i < NGCC_ITERATIONS; i++) {
        unsigned long long pka_len = pka_len_max;
        unsigned long long ska_len = ska_len_max;
        unsigned long long pkb_len = pkb_len_max;
        unsigned long long skb_len = skb_len_max;
        unsigned long long sta_len = sta_len_max;
        unsigned long long stb_len = stb_len_max;
        unsigned long long ssa_len = ss_len;
        unsigned long long ssb_len = ss_len;
        unsigned long long m1_len = 0;
        unsigned long long m2_len = 0;
        unsigned long long m3_len = 0;
        unsigned char *ma;
        unsigned long long ma_len;
        uint64_t t0;
        uint64_t t1;
        int rtn;

        t0 = hal_get_time();
        rtn = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
        t1 = hal_get_time();
        if (rtn < 0) {
            fail_and_halt("kex_init_a_failed");
        }
        send_unsignedll("init_a cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        rtn = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
        t1 = hal_get_time();
        if (rtn < 0) {
            fail_and_halt("kex_init_b_failed");
        }
        send_unsignedll("init_b cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        rtn = kex_generate_pass1_msg_a(
            ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
        t1 = hal_get_time();
        if (rtn != 0) {
            fail_and_halt("kex_pass1_failed");
        }
        send_unsignedll("pass1 cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        rtn = kex_generate_pass2_msg_b(
            skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len,
            m2, &m2_len);
        t1 = hal_get_time();
        if (rtn != (pass == 2 ? 1 : 0)) {
            fail_and_halt("kex_pass2_failed");
        }
        send_unsignedll("pass2 cycles:", (unsigned long long)(t1 - t0));
        ma = m1;
        ma_len = m1_len;
        if (pass == 3) {
            t0 = hal_get_time();
            rtn = kex_generate_pass3_msg_a(
                ska, ska_len, pkb, pkb_len, m2, m2_len, sta, &sta_len,
                m3, &m3_len);
            t1 = hal_get_time();
            if (rtn != 1) {
                fail_and_halt("kex_pass3_failed");
            }
            send_unsignedll("pass3 cycles:", (unsigned long long)(t1 - t0));
            ma = m3;
            ma_len = m3_len;
        }

        t0 = hal_get_time();
        rtn = kex_derive_ss_a(
            ska, ska_len, pkb, pkb_len, m2, m2_len, sta, sta_len,
            ssa, &ssa_len);
        t1 = hal_get_time();
        if (rtn < 0) {
            fail_and_halt("kex_derive_a_failed");
        }
        send_unsignedll("derive_a cycles:", (unsigned long long)(t1 - t0));

        t0 = hal_get_time();
        rtn = kex_derive_ss_b(
            skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len,
            ssb, &ssb_len);
        t1 = hal_get_time();
        if (rtn < 0) {
            fail_and_halt("kex_derive_b_failed");
        }
        send_unsignedll("derive_b cycles:", (unsigned long long)(t1 - t0));

        if (ssa_len != ssb_len || memcmp(ssa, ssb, (size_t)ssa_len) != 0) {
            fail_and_halt("ERROR KEYS");
        }
        hal_send_str("OK KEYS");
        hal_send_str("+");
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
