#include "packing.h"
#include "parameters.h"
#include "polyvec.h"
#include <stdint.h>
#include <string.h>



void DKE3_packpk(uint8_t bytes[DKE3_PKBYTES],
             const polyvec *pk,
             const uint8_t seed[DKE3_SEEDBYTES]) {
    DKE3_polyvec_tobytes(bytes, pk);
    memcpy(bytes + DKE3_PACOMPRESSEDBYTES, seed, DKE3_SEEDBYTES);
}
void DKE3_unpackpk(polyvec *pk,
               uint8_t seed[DKE3_SEEDBYTES],
               const uint8_t bytes[DKE3_PKBYTES]) {

    DKE3_polyvec_frombytes(pk, bytes);
    memcpy(seed, bytes + DKE3_PACOMPRESSEDBYTES, DKE3_SEEDBYTES);
}

void DKE3_CPA_unpacksk(polyvec *sk,
               const uint8_t bytes[DKE3_SKBYTES]) {
    DKE3_polyvec_frombytes(sk, bytes);
}

void DKE3_CPA_packsk(uint8_t bytes[DKE3_CPA_SKABYTES],
                 polyvec *sk) {
    DKE3_polyvec_tobytes(bytes, sk);
}


void DKE3_CPA_packciphertext(uint8_t bytes[DKE3_CPA_CTBYTES],
                         polyvec *pb,
                         uint8_t sig[DKE3_SIGNALBYTES]) {
    DKE3_polyvec_compress11(bytes, pb);
    memcpy(bytes + DKE3_PBCOMPRESSEDBYTES, sig, DKE3_SIGNALBYTES);
}

void DKE3_CPA_unpackciphertext(polyvec *pb,
                           uint8_t sig[DKE3_SIGNALBYTES],
                           const uint8_t bytes[DKE3_CPA_CTBYTES]) {
    DKE3_polyvec_decompress11(pb, bytes);
    memcpy(sig, bytes + DKE3_PBCOMPRESSEDBYTES, DKE3_SIGNALBYTES);
}


