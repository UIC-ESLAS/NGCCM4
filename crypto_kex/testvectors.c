#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "hal.h"
#include "KEX_AlgorithmInstance.h"
#ifdef USE_KECCAK
#include "randombytes.h"
#endif

#define SEED_LEN_BYTES 64

DRNG_ctx drng_algorithm;
unsigned char tv_seed[SEED_LEN_BYTES];

static unsigned char *alloc_buffer(unsigned long long len)
{
    size_t alloc_len = (len == 0) ? 1u : (size_t)len;
    return malloc(alloc_len);
}

static void printbytes(const unsigned char *x, unsigned long long xlen)
{
    static const char hex[] = "0123456789abcdef";
    char *outs = malloc((size_t)(2 * xlen + 1));
    unsigned long long i;

    if (outs == NULL) {
        hal_send_str("alloc_failed");
        return;
    }
    for (i = 0; i < xlen; i++) {
        outs[2 * i] = hex[(x[i] >> 4) & 0xF];
        outs[2 * i + 1] = hex[x[i] & 0xF];
    }
    outs[2 * xlen] = 0;
    hal_send_str(outs);
    free(outs);
}

static int run_vector(const unsigned char seed[SEED_LEN_BYTES])
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
        hal_send_str("alloc_failed");
        goto cleanup;
    }
    if (pass != 2 && pass != 3) {
        hal_send_str("unsupported_pass_count");
        goto cleanup;
    }
    if (init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES) != 0) {
        hal_send_str("drng_init_failed");
        goto cleanup;
    }

    printbytes(seed, SEED_LEN_BYTES);

    rtn = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    if (rtn < 0) {
        hal_send_str("kex_init_a_failed");
        goto cleanup;
    }
    printbytes(pka, pka_len);
    printbytes(ska, ska_len);
    printbytes(sta, sta_len);

    rtn = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    if (rtn < 0) {
        hal_send_str("kex_init_b_failed");
        goto cleanup;
    }
    printbytes(pkb, pkb_len);
    printbytes(skb, skb_len);
    printbytes(stb, stb_len);

    rtn = kex_generate_pass1_msg_a(
        ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
    if (rtn != 0) {
        hal_send_str("kex_pass1_failed");
        goto cleanup;
    }
    printbytes(sta, sta_len);
    printbytes(m1, m1_len);

    rtn = kex_generate_pass2_msg_b(
        skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len, m2, &m2_len);
    if (rtn != (pass == 2 ? 1 : 0)) {
        hal_send_str("kex_pass2_failed");
        goto cleanup;
    }
    printbytes(stb, stb_len);
    printbytes(m2, m2_len);
    ma = m1;
    ma_len = m1_len;
    if (pass == 3) {
        rtn = kex_generate_pass3_msg_a(
            ska, ska_len, pkb, pkb_len, m2, m2_len, sta, &sta_len,
            m3, &m3_len);
        if (rtn != 1) {
            hal_send_str("kex_pass3_failed");
            goto cleanup;
        }
        printbytes(sta, sta_len);
        printbytes(m3, m3_len);
        ma = m3;
        ma_len = m3_len;
    }

    rtn = kex_derive_ss_a(
        ska, ska_len, pkb, pkb_len, m2, m2_len, sta, sta_len,
        ssa, &ssa_len);
    if (rtn < 0) {
        hal_send_str("kex_derive_a_failed");
        goto cleanup;
    }
    rtn = kex_derive_ss_b(
        skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len,
        ssb, &ssb_len);
    if (rtn < 0) {
        hal_send_str("kex_derive_b_failed");
        goto cleanup;
    }
    if (ssa_len != ssb_len || memcmp(ssa, ssb, (size_t)ssa_len) != 0) {
        hal_send_str("ERROR");
        goto cleanup;
    }
    printbytes(ssa, ssa_len);
    printbytes(ssb, ssb_len);
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
    unsigned char seed[SEED_LEN_BYTES];
    int i;
#ifndef USE_KECCAK
    DRNG_ctx drng_seed;
#endif

    hal_setup(CLOCK_FAST);
    hal_send_str("==========================");

#ifndef USE_KECCAK
    for (i = 0; i < SEED_LEN_BYTES / 4; i++) {
        memcpy(tv_seed + 4 * i, "seed", 4);
    }
    if (init_random_number(&drng_seed, tv_seed, sizeof(tv_seed)) != 0) {
        hal_send_str("drng_init_failed");
        return -1;
    }
#endif

    for (i = 0; i < NGCC_ITERATIONS; i++) {
#ifdef USE_KECCAK
        randombytes(seed, SEED_LEN_BYTES);
#else
        get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8);
#endif
        if (run_vector(seed) != 0) {
            return -1;
        }
        hal_send_str("+");
    }

    hal_send_str("#");
    return 0;
}
