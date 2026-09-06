#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

#define DKE3_MONT (-3593)  // auxiliary modulus R = (2^16 mod q)
#define DKE3_QINV (-7679) // q^-1 mod 2^16

/// @brief Performs montgomery reduction mod q
/// @param[in] a an integer in {-q2^15,...,q2^15-1}
/// @return    a*R^-1 mod q in  {-q+1,...,q-1}.
int16_t DKE3_montgomery_reduce(int32_t a);


/// @brief Performs barret reduction mod q
/// @param[in] a an integer
/// @return    a mod q in {-(q-1)/2,...,(q-1)/2}
int16_t DKE3_barrett_reduce(int16_t a);

#endif //REDUCE_H
