#ifndef PACKING_H
#define PACKING_H

#include "parameters.h"
#include "polyvec.h"
#include <stdint.h>


// For keygen -------------------------------------------

// CPA and CCA
void DKE3_packpk(uint8_t bytes[DKE3_PKBYTES],
             const polyvec *pk,
             const uint8_t seed[DKE3_SEEDBYTES]);

// CPA
void DKE3_CPA_packsk(uint8_t r[DKE3_CPA_SKABYTES],
             polyvec *sk);

// For enc ------------------------------------------------

// CPA and CCA
void DKE3_unpackpk(polyvec *pk,
               uint8_t seed[DKE3_SEEDBYTES],
               const uint8_t bytes[DKE3_PKBYTES]);

// CPA
void DKE3_CPA_packciphertext(uint8_t bytes[DKE3_CPA_CTBYTES],
                         polyvec *pb,
                         uint8_t sig[DKE3_SIGNALBYTES]);

// For dec  ------------------------------------------------

// CPA
void DKE3_CPA_unpacksk(polyvec *sk,
                       const uint8_t bytes[DKE3_CPA_SKABYTES]);

// CPA
void DKE3_CPA_unpackciphertext(polyvec *pb,
                           uint8_t sig[DKE3_SIGNALBYTES],
                           const uint8_t bytes[DKE3_CPA_CTBYTES]);

#endif //PACKING_H