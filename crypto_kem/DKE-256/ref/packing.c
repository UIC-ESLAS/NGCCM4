#include "packing.h"
#include "parameters.h"
#include "polyvec.h"
#include <stdint.h>
#include <string.h>



void DKE2_packpk(uint8_t bytes[DKE2_PKBYTES],
             const polyvec *pk,
             const uint8_t seed[DKE2_SEEDBYTES]) {
    DKE2_polyvec_tobytes(bytes, pk);
    memcpy(bytes + DKE2_PACOMPRESSEDBYTES, seed, DKE2_SEEDBYTES);
}
void DKE2_unpackpk(polyvec *pk,
               uint8_t seed[DKE2_SEEDBYTES],
               const uint8_t bytes[DKE2_PKBYTES]) {

    DKE2_polyvec_frombytes(pk, bytes);
    memcpy(seed, bytes + DKE2_PACOMPRESSEDBYTES, DKE2_SEEDBYTES);
}

void DKE2_CPA_unpacksk(polyvec *sk,
               const uint8_t bytes[DKE2_SKBYTES]) {
    DKE2_polyvec_frombytes(sk, bytes);
}

void DKE2_CPA_packsk(uint8_t bytes[DKE2_CPA_SKABYTES],
                 polyvec *sk) {
    DKE2_polyvec_tobytes(bytes, sk);
}


void DKE2_CPA_packciphertext(uint8_t bytes[DKE2_CPA_CTBYTES],
                         polyvec *pb,
                         uint8_t sig[DKE2_SIGNALBYTES]) {
    DKE2_polyvec_compress11(bytes, pb);
    memcpy(bytes + DKE2_PBCOMPRESSEDBYTES, sig, DKE2_SIGNALBYTES);
}

void DKE2_CPA_unpackciphertext(polyvec *pb,
                           uint8_t sig[DKE2_SIGNALBYTES],
                           const uint8_t bytes[DKE2_CPA_CTBYTES]) {
    DKE2_polyvec_decompress11(pb, bytes);
    memcpy(sig, bytes + DKE2_PBCOMPRESSEDBYTES, DKE2_SIGNALBYTES);
}

