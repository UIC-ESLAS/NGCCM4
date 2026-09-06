#ifndef VERIFY_H
#define VERIFY_H

// Comes from https://github.com/PQClean/PQClean/blob/master/crypto_kem/ml-kem-1024/clean/verify.h

#include <stddef.h>
#include <stdint.h>

int DKE3_verify(const uint8_t *a, const uint8_t *b, size_t len);
void DKE3_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
void DKE3_cmov_int16(int16_t *r, int16_t v, uint16_t b);

#endif //VERIFY_H
