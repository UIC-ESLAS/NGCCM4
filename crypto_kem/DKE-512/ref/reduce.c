#include "parameters.h"
#include <stdint.h>
#include "reduce.h"

int16_t DKE3_montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)a * DKE3_QINV;
    t = (a - (int32_t)t * DKE3_Q) >> 16;
    return (int16_t)t;
}

int16_t DKE3_barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + DKE3_Q / 2) / DKE3_Q;
    t  = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= DKE3_Q;
    return a - t;
}
