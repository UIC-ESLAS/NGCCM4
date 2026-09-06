#include <stdint.h>

#include "hal.h"
#include "sendfn.h"
#include "parameters.h"
#include "poly.h"
#include "KEM_AlgorithmInstance.h"
#define print_u32(S, U) send_unsigned((S), (U))
#define printcycles(S, U) send_unsignedll((S), (U))
#if defined(DKE3_N)
#define DKE_N DKE3_N
#define DKE_Q DKE3_Q
#define DKE_poly_reduce DKE3_poly_reduce
#define DKE_poly_ntt DKE3_poly_ntt
#define DKE_poly_invntt DKE3_poly_invntt
#define DKE_poly_invntt_tomont DKE3_poly_invntt_tomont
#define DKE_poly_basemul DKE3_poly_basemul
#define DKE_poly_basemul_montgomery DKE3_poly_basemul_montgomery
#define DKE_poly_tomont DKE3_poly_tomont
#elif defined(DKE2_N)
#define DKE_N DKE2_N
#define DKE_Q DKE2_Q
#define DKE_poly_reduce DKE2_poly_reduce
#define DKE_poly_ntt DKE2_poly_ntt
#define DKE_poly_invntt DKE2_poly_invntt
#define DKE_poly_invntt_tomont DKE2_poly_invntt_tomont
#define DKE_poly_basemul DKE2_poly_basemul
#define DKE_poly_basemul_montgomery DKE2_poly_basemul_montgomery
#define DKE_poly_tomont DKE2_poly_tomont
#elif defined(DKE1_N)
#define DKE_N DKE1_N
#define DKE_Q DKE1_Q
#define DKE_poly_reduce DKE1_poly_reduce
#define DKE_poly_ntt DKE1_poly_ntt
#define DKE_poly_invntt DKE1_poly_invntt
#define DKE_poly_invntt_tomont DKE1_poly_invntt_tomont
#define DKE_poly_basemul DKE1_poly_basemul
#define DKE_poly_basemul_montgomery DKE1_poly_basemul_montgomery
#define DKE_poly_tomont DKE1_poly_tomont
#else
#error "ALGORITHM_INSTANCE not supported"
#endif
static void print_poly_u32(const int16_t *a, int len)
{
	for (size_t i = 0; i < len; i++)
	{
		if(a[i] < 0) {
			print_u32(", ", (uint32_t)(uint16_t)(a[i]+8*DKE_Q) % DKE_Q);
		} else {
			print_u32(", ", (uint32_t)(uint16_t)a[i]);
		}
	}
	hal_send_str("\n");
}
static int16_t freeze(int16_t a) {
	int32_t r = a;

	r %= DKE_Q;
	if (r < 0) {
		r += DKE_Q;
	}
	return (int16_t)r;
}

static void fill_poly(poly *a, unsigned int seed) {
	unsigned int i;

	for (i = 0; i < DKE_N; i++) {
		a->coeffs[i] = (int16_t)((seed * 811u + i * 257u) % DKE_Q);
	}
}

static int equal_poly_modq(poly *a, poly *b) {
	unsigned int i;

	DKE_poly_reduce(a);
	DKE_poly_reduce(b);

	for (i = 0; i < DKE_N; i++) {
		if (freeze(a->coeffs[i]) != freeze(b->coeffs[i])) {
			return -1;
		}
	}
	return 0;
}

int test_ntt_identity(unsigned int seed) {
	unsigned int i;
	poly a, one, product, r;

	fill_poly(&a, seed);
	for (i = 0; i < DKE_N; i++) {
		r.coeffs[i]=a.coeffs[i];
		one.coeffs[i] = 1;
	}
	one.coeffs[0] = 1;

	DKE_poly_ntt(&r);
	hal_send_str("NTT(a): ");
	DKE_poly_reduce(&r);
	print_poly_u32(r.coeffs, DKE_N);

	DKE_poly_ntt(&one);
	DKE_poly_reduce(&one);
	hal_send_str("NTT(1): ");
	print_poly_u32(one.coeffs, DKE_N);
#ifdef M4
	DKE_poly_basemul(&product, &r, &one);
#else
	DKE_poly_basemul_montgomery(&product, &r, &one);
#endif
	r = product;
	hal_send_str("NTT(a) * NTT(1): ");
	DKE_poly_reduce(&r);
	print_poly_u32(r.coeffs, DKE_N);
#ifdef M4
	DKE_poly_invntt(&r);
#else
	DKE_poly_invntt_tomont(&r);
#endif
	hal_send_str("INVNTT(NTT(a) * NTT(1)): ");
	DKE_poly_reduce(&r);
	print_poly_u32(r.coeffs, DKE_N);
	return equal_poly_modq(&r, &a);
}

int main(void) {
    int i;

    hal_setup(CLOCK_FAST);
    hal_send_str("==========================");

    for (i = 0; i < NGCC_ITERATIONS; i++) {
		if (test_ntt_identity((unsigned int)i) != 0) {
            hal_send_str("ERROR IDENTITY");
        } else {
            hal_send_str("OK NTT");
        }
        hal_send_str("+");
    }

    hal_send_str("#");
    return 0;
}
