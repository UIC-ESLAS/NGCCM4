#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "hal.h"
#include "sendfn.h"
#include "KEX_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static const unsigned char test_seed[] = {
    0x6e, 0x67, 0x63, 0x63, 0x6d, 0x34, 0x2d, 0x6b,
    0x65, 0x78, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d,
    0x73, 0x65, 0x65, 0x64
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

static int test_exchange(void)
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
    unsigned long long total_len = kex_get_total_msg_len_bytes();
    unsigned long long m1_len = 0;
    unsigned long long m2_len = 0;
    unsigned long long m3_len = 0;
    unsigned char *pka = alloc_buffer(pka_len);
    unsigned char *ska = alloc_buffer(ska_len);
    unsigned char *pkb = alloc_buffer(pkb_len);
    unsigned char *skb = alloc_buffer(skb_len);
    unsigned char *sta = alloc_buffer(sta_len);
    unsigned char *stb = alloc_buffer(stb_len);
    unsigned char *ssa = alloc_buffer(ssa_len);
    unsigned char *ssb = alloc_buffer(ssb_len);
    unsigned char *m1 = alloc_buffer(total_len);
    unsigned char *m2 = alloc_buffer(total_len);
    unsigned char *m3 = alloc_buffer(total_len);
    unsigned char *ma;
    unsigned long long ma_len;
    int ret = -1;
    int rtn;

    if (pka == NULL || ska == NULL || pkb == NULL || skb == NULL ||
        sta == NULL || stb == NULL || ssa == NULL || ssb == NULL ||
        m1 == NULL || m2 == NULL || m3 == NULL) {
        goto cleanup;
    }
    if (pass != 2 && pass != 3) {
        goto cleanup;
    }
    rtn = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    if (rtn < 0) {
        goto cleanup;
    }
    rtn = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    if (rtn < 0) {
        goto cleanup;
    }
    rtn = kex_generate_pass1_msg_a(
        ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
    if (rtn != 0) {
        goto cleanup;
    }
    rtn = kex_generate_pass2_msg_b(
        skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len, m2, &m2_len);
    if (rtn != (pass == 2 ? 1 : 0)) {
        goto cleanup;
    }
    ma = m1;
    ma_len = m1_len;
    if (pass == 3) {
        rtn = kex_generate_pass3_msg_a(
            ska, ska_len, pkb, pkb_len, m2, m2_len, sta, &sta_len,
            m3, &m3_len);
        if (rtn != 1) {
            goto cleanup;
        }
        ma = m3;
        ma_len = m3_len;
    }

    rtn = kex_derive_ss_a(
        ska, ska_len, pkb, pkb_len, m2, m2_len, sta, sta_len,
        ssa, &ssa_len);
    if (rtn < 0) {
        goto cleanup;
    }
    rtn = kex_derive_ss_b(
        skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len,
        ssb, &ssb_len);
    if (rtn < 0) {
        goto cleanup;
    }
    if (ssa_len != ssb_len || memcmp(ssa, ssb, (size_t)ssa_len) != 0) {
        goto cleanup;
    }
    ret = 0;

cleanup:
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
    return ret;
}

int main(void)
{
    int i;

    hal_setup(CLOCK_FAST);
    hal_send_str("==========================");

    if (init_random_number(&drng_algorithm, test_seed, sizeof(test_seed)) != 0) {
        fail_and_halt("drng_init_failed");
    }

    for (i = 0; i < NGCC_ITERATIONS; i++) {
        if (test_exchange() != 0) {
            hal_send_str("ERROR KEYS");
            return -1;
        }
        hal_send_str("OK KEYS");
        hal_send_str("+");
    }

    hal_send_str("#");
    return 0;
}
