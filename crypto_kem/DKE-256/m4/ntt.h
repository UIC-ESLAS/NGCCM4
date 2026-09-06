#ifndef NTT_H
#define NTT_H

#include <stdint.h>

extern const uint32_t zetas[64];

void DKE2_ntt(int16_t r[256]);
void DKE2_invntt(int16_t r[256]);
void DKE2_basemul(int16_t r[256], const int16_t a[256], const int16_t b[256]);
void DKE2_basemul_acc(int16_t r[256], const int16_t a[256], const int16_t b[256]);

#endif
