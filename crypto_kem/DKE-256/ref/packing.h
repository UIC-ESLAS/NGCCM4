#ifndef PACKING_H
#define PACKING_H

#include "parameters.h"
#include "polyvec.h"
#include <stdint.h>


// For keygen -------------------------------------------

// CPA and CCA
void DKE2_packpk(uint8_t bytes[DKE2_PKBYTES],
             const polyvec *pk,
             const uint8_t seed[DKE2_SEEDBYTES]);

// CPA
void DKE2_CPA_packsk(uint8_t r[DKE2_CPA_SKABYTES],
             polyvec *sk);

// For enc ------------------------------------------------

// CPA and CCA
void DKE2_unpackpk(polyvec *pk,
               uint8_t seed[DKE2_SEEDBYTES],
               const uint8_t bytes[DKE2_PKBYTES]);

// CPA
void DKE2_CPA_packciphertext(uint8_t bytes[DKE2_CPA_CTBYTES],
                         polyvec *pb,
                         uint8_t sig[DKE2_SIGNALBYTES]);

// For dec  ------------------------------------------------

// CPA
void DKE2_CPA_unpacksk(polyvec *sk,
               const uint8_t bytes[DKE2_SKBYTES]);


// CPA
void DKE2_CPA_unpackciphertext(polyvec *pb,
                           uint8_t sig[DKE2_SIGNALBYTES],
                           const uint8_t bytes[DKE2_CPA_CTBYTES]);

#endif //PACKING_H