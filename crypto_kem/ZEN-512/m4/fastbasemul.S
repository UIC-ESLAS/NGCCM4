/**
 * ZEN_512 16-coefficient NTT base multiplication.
 *
 * Each block is multiplied modulo x^16 = zeta.  The top-level block product
 * uses one Karatsuba split into three direct 8x8 schoolbook products.  Product
 * coefficients stay in high-half Plantard form until the final store, matching
 * the existing public ABI:
 *   basemul16_karatsuba_asm(r, a, b, zetas_769)
 *   basemul16_karatsuba_mq_asm(r, a, b, zetas_769)
 */

#include "macros.i"

.syntax unified
.cpu cortex-m4
.thumb

.equ BM_P0, 0
.equ BM_P1, 60
.equ BM_PM, 120
.equ BM_AS, 180
.equ BM_BS, 196
.equ BM_TMP, 212
.equ BM_SAVE_R, 240
.equ BM_SAVE_A, 244
.equ BM_SAVE_B, 248
.equ BM_SAVE_Z, 252
.equ BM_FRAME_SIZE, 256

.equ BI_PE15, 0
.equ BI_PO15, 32
.equ BI_AE, 64
.equ BI_AO, 80
.equ BI_H, 96
.equ BI_HE, 112
.equ BI_HO, 120
.equ BI_PE7, 128
.equ BI_PO7, 144
.equ BI_B, 160
.equ BI_C, 168
.equ BI_F, 172
.equ BI_G, 180
.equ BI_AS, 196
.equ BI_BS, 212
.equ BI_TMP, 228
.equ BI_SAVE_R, 244
.equ BI_SAVE_A, 248
.equ BI_SAVE_Z, 252
.equ BI_SAVE_QTAB, 256
.equ BI_FRAME_SIZE, 264

.macro make_sum8 as, bs, a, b, t0, t1
    ldr.w \t0, [\a, #0]
    ldr.w \t1, [\a, #16]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\as, #0]
    ldr.w \t0, [\b, #0]
    ldr.w \t1, [\b, #16]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\bs, #0]

    ldr.w \t0, [\a, #0+4*1]
    ldr.w \t1, [\a, #16+4*1]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\as, #0+4*1]
    ldr.w \t0, [\b, #0+4*1]
    ldr.w \t1, [\b, #16+4*1]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\bs, #0+4*1]

    ldr.w \t0, [\a, #0+4*2]
    ldr.w \t1, [\a, #16+4*2]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\as, #0+4*2]
    ldr.w \t0, [\b, #0+4*2]
    ldr.w \t1, [\b, #16+4*2]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\bs, #0+4*2]

    ldr.w \t0, [\a, #0+4*3]
    ldr.w \t1, [\a, #16+4*3]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\as, #0+4*3]
    ldr.w \t0, [\b, #0+4*3]
    ldr.w \t1, [\b, #16+4*3]
    sadd16.w \t0, \t0, \t1
    str.w \t0, [\bs, #0+4*3]
.endm


// Compute the full 8x8 convolution into fifteen signed 16-bit high-half
// Plantard coefficients. Inputs are four packed 16-bit words for each operand.
.macro mul8_schoolbook_plant_hh out, a, b, q, qa, qinv, a01, a23, a45, a67, b01, b23, b45, b67, even, odd
    ldr.w \a01, [\a, #0]
    ldr.w \a23, [\a, #4]
    ldr.w \a45, [\a, #8]
    ldr.w \a67, [\a, #12]
    ldr.w \b01, [\b, #0]
    ldr.w \b23, [\b, #4]
    ldr.w \b45, [\b, #8]
    ldr.w \b67, [\b, #12]

    // c0, c1
    smulbb \even, \a01, \b01
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \b01
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(0 * 2)]

    // c2, c3
    smulbb \even, \a01, \b23
    smlatt \even, \a01, \b01, \even
    smlabb \even, \a23, \b01, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \b23
    smladx \odd, \a23, \b01, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(2 * 2)]

    // c4, c5
    smulbb \even, \a01, \b45
    smlatt \even, \a01, \b23, \even
    smlabb \even, \a23, \b23, \even
    smlatt \even, \a23, \b01, \even
    smlabb \even, \a45, \b01, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \b45
    smladx \odd, \a23, \b23, \odd
    smladx \odd, \a45, \b01, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(4 * 2)]

    // c6, c7
    smulbb \even, \a01, \b67
    smlatt \even, \a01, \b45, \even
    smlabb \even, \a23, \b45, \even
    smlatt \even, \a23, \b23, \even
    smlabb \even, \a45, \b23, \even
    smlatt \even, \a45, \b01, \even
    smlabb \even, \a67, \b01, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \b67
    smladx \odd, \a23, \b45, \odd
    smladx \odd, \a45, \b23, \odd
    smladx \odd, \a67, \b01, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(6 * 2)]

    // c8, c9
    smultt \even, \a01, \b67
    smlabb \even, \a23, \b67, \even
    smlatt \even, \a23, \b45, \even
    smlabb \even, \a45, \b45, \even
    smlatt \even, \a45, \b23, \even
    smlabb \even, \a67, \b23, \even
    smlatt \even, \a67, \b01, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a23, \b67
    smladx \odd, \a45, \b45, \odd
    smladx \odd, \a67, \b23, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(8 * 2)]

    // c10, c11
    smultt \even, \a23, \b67
    smlabb \even, \a45, \b67, \even
    smlatt \even, \a45, \b45, \even
    smlabb \even, \a67, \b45, \even
    smlatt \even, \a67, \b23, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a45, \b67
    smladx \odd, \a67, \b45, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(10 * 2)]

    // c12, c13
    smultt \even, \a45, \b67
    smlabb \even, \a67, \b67, \even
    smlatt \even, \a67, \b45, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a67, \b67
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(12 * 2)]

    // c14
    smultt \even, \a67, \b67
    plant_red \q, \qa, \qinv, \even
    asr.w \even, \even, #16
    strh.w \even, [\out, #(14 * 2)]
.endm

.macro mul8_plant_hh_direct out, a, b, q, qa, qinv, a01, a23, a45, a67, b01, b23, b45, b67, even, odd
    mul8_schoolbook_plant_hh \out, \a, \b, \q, \qa, \qinv, \a01, \a23, \a45, \a67, \b01, \b23, \b45, \b67, \even, \odd
.endm

// Square an 8-coefficient block into fifteen signed 16-bit high-half Plantard
// coefficients.  This keeps pairs packed and uses symmetric cross terms
// directly instead of routing through the recursive Karatsuba helper.
.macro sqr8_plant_hh_direct out, a, q, qa, qinv, a01, a23, a45, a67, even, odd, tmp
    ldr.w \a01, [\a, #0]
    ldr.w \a23, [\a, #4]
    ldr.w \a45, [\a, #8]
    ldr.w \a67, [\a, #12]

    // c0, c1
    smulbb \even, \a01, \a01
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \a01
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(0 * 2)]

    // c2, c3
    smulbb \even, \a01, \a23
    add.w \even, \even, \even
    smlatt \even, \a01, \a01, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \a23
    add.w \odd, \odd, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(2 * 2)]

    // c4, c5
    smulbb \even, \a01, \a45
    smlatt \even, \a01, \a23, \even
    add.w \even, \even, \even
    smlabb \even, \a23, \a23, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \a45
    add.w \odd, \odd, \odd
    smuadx \tmp, \a23, \a23
    add.w \odd, \odd, \tmp
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(4 * 2)]

    // c6, c7
    smulbb \even, \a01, \a67
    smlatt \even, \a01, \a45, \even
    smlabb \even, \a23, \a45, \even
    add.w \even, \even, \even
    smlatt \even, \a23, \a23, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a01, \a67
    smladx \odd, \a23, \a45, \odd
    add.w \odd, \odd, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(6 * 2)]

    // c8, c9
    smultt \even, \a01, \a67
    smlabb \even, \a23, \a67, \even
    smlatt \even, \a23, \a45, \even
    add.w \even, \even, \even
    smlabb \even, \a45, \a45, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a23, \a67
    add.w \odd, \odd, \odd
    smuadx \tmp, \a45, \a45
    add.w \odd, \odd, \tmp
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(8 * 2)]

    // c10, c11
    smultt \even, \a23, \a67
    smlabb \even, \a45, \a67, \even
    add.w \even, \even, \even
    smlatt \even, \a45, \a45, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a45, \a67
    add.w \odd, \odd, \odd
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(10 * 2)]

    // c12, c13
    smultt \even, \a45, \a67
    add.w \even, \even, \even
    smlabb \even, \a67, \a67, \even
    plant_red \q, \qa, \qinv, \even
    smuadx \odd, \a67, \a67
    plant_red \q, \qa, \qinv, \odd
    pkhtb \even, \odd, \even, asr #16
    str.w \even, [\out, #(12 * 2)]

    // c14
    smultt \even, \a67, \a67
    plant_red \q, \qa, \qinv, \even
    asr.w \even, \even, #16
    strh.w \even, [\out, #(14 * 2)]
.endm

.macro compute_block_products
    str.w r0, [sp, #BM_SAVE_R]
    str.w r1, [sp, #BM_SAVE_A]
    str.w r2, [sp, #BM_SAVE_B]
    str.w r3, [sp, #BM_SAVE_Z]

    movw r8, #0
    movt r8, #769       @ q in the top halfword
    movw r9, #64769
    movt r9, #58632     @ Plantard qinv
    movw r10, #24608    @ qa

    add.w r0, sp, #BM_P0
    ldr.w r1, [sp, #BM_SAVE_A]
    ldr.w r2, [sp, #BM_SAVE_B]
    mul8_schoolbook_plant_hh r0, r1, r2, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12, lr, r1, r2

    add.w r0, sp, #BM_P1
    ldr.w r1, [sp, #BM_SAVE_A]
    add.w r1, r1, #16
    ldr.w r2, [sp, #BM_SAVE_B]
    add.w r2, r2, #16
    mul8_schoolbook_plant_hh r0, r1, r2, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12, lr, r1, r2

    add.w r11, sp, #BM_AS
    add.w r12, sp, #BM_BS
    ldr.w r1, [sp, #BM_SAVE_A]
    ldr.w r2, [sp, #BM_SAVE_B]
    make_sum8 r11, r12, r1, r2, r4, r5

    add.w r0, sp, #BM_PM
    mov r1, r11
    mov r2, r12
    mul8_schoolbook_plant_hh r0, r1, r2, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12, lr, r1, r2
.endm

.macro setup_combine_ptrs
    add.w r0, sp, #BM_P0
    add.w r1, sp, #BM_P1
    add.w r2, sp, #BM_PM
    ldr.w r3, [sp, #BM_SAVE_R]
    ldr.w r7, [sp, #BM_SAVE_Z]
.endm

.macro cross_pair dst, idx, tmp
    ldr.w \dst, [r2, #(\idx * 2)]
    ldr.w \tmp, [r0, #(\idx * 2)]
    ssub16 \dst, \dst, \tmp
    ldr.w \tmp, [r1, #(\idx * 2)]
    ssub16 \dst, \dst, \tmp
.endm

.macro cross_lane dst, idx, tmp
    ldrh.w \dst, [r2, #(\idx * 2)]
    ldrh.w \tmp, [r0, #(\idx * 2)]
    ssub16 \dst, \dst, \tmp
    ldrh.w \tmp, [r1, #(\idx * 2)]
    ssub16 \dst, \dst, \tmp
.endm

.macro store_mq_pair val, idx, tmp, qtmp
    mul_twiddle_plant_mq \val, r11, \tmp, r8, r10, \qtmp
    str.w \val, [r3, #(\idx * 2)]
.endm

.macro store_mq_lane val, idx, tmp, qtmp
    smulwb \val, r11, \val
    smlabt \val, \val, r8, r10
    and \qtmp, r8, \val, asr #31
    sadd16 \val, \val, \qtmp
    asr \val, \val, #16
    strh.w \val, [r3, #(\idx * 2)]
.endm

.macro combine_low_pair_raw idx
    ldr.w r4, [r0, #(\idx * 2)]
    ldr.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_pair r6, (\idx + 8), r12
    mul_twiddle_plant r6, r7, r12, r8, r10
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    str.w r4, [r3, #(\idx * 2)]
.endm

.macro combine_low_pair_mq idx
    ldr.w r4, [r0, #(\idx * 2)]
    ldr.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_pair r6, (\idx + 8), r12
    mul_twiddle_plant r6, r7, r12, r8, r10
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    store_mq_pair r4, \idx, r5, r12
.endm

.macro combine_low_lane_raw idx
    ldrh.w r4, [r0, #(\idx * 2)]
    ldrh.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_lane r6, (\idx + 8), r12
    mul_twiddle_plant r6, r7, r12, r8, r10
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    strh.w r4, [r3, #(\idx * 2)]
.endm

.macro combine_low_lane_mq idx
    ldrh.w r4, [r0, #(\idx * 2)]
    ldrh.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_lane r6, (\idx + 8), r12
    mul_twiddle_plant r6, r7, r12, r8, r10
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    store_mq_lane r4, \idx, r5, r12
.endm

.macro combine_7_raw
    ldrh.w r4, [r0, #(7 * 2)]
    ldrh.w r5, [r1, #(7 * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    sadd16 r4, r4, r5
    strh.w r4, [r3, #(7 * 2)]
.endm

.macro combine_7_mq
    ldrh.w r4, [r0, #(7 * 2)]
    ldrh.w r5, [r1, #(7 * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    sadd16 r4, r4, r5
    store_mq_lane r4, 7, r5, r12
.endm

.macro combine_high_pair_raw idx
    ldr.w r4, [r0, #(\idx * 2)]
    ldr.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_pair r6, (\idx - 8), r12
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    str.w r4, [r3, #(\idx * 2)]
.endm

.macro combine_high_pair_mq idx
    ldr.w r4, [r0, #(\idx * 2)]
    ldr.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_pair r6, (\idx - 8), r12
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    store_mq_pair r4, \idx, r5, r12
.endm

.macro combine_high_lane_raw idx
    ldrh.w r4, [r0, #(\idx * 2)]
    ldrh.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_lane r6, (\idx - 8), r12
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    strh.w r4, [r3, #(\idx * 2)]
.endm

.macro combine_high_lane_mq idx
    ldrh.w r4, [r0, #(\idx * 2)]
    ldrh.w r5, [r1, #(\idx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    cross_lane r6, (\idx - 8), r12
    sadd16 r4, r4, r5
    sadd16 r4, r4, r6
    store_mq_lane r4, \idx, r5, r12
.endm

.macro combine_15_raw
    cross_lane r4, 7, r12
    strh.w r4, [r3, #(15 * 2)]
.endm

.macro combine_15_mq
    cross_lane r4, 7, r12
    store_mq_lane r4, 15, r5, r12
.endm

.macro split_evenodd16 ae, ao, a, t0, t1, t2, t3
    ldr.w \t0, [\a, #0]
    ldr.w \t1, [\a, #4]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\ae, #0]
    str.w \t3, [\ao, #0]

    ldr.w \t0, [\a, #8]
    ldr.w \t1, [\a, #12]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\ae, #4]
    str.w \t3, [\ao, #4]

    ldr.w \t0, [\a, #16]
    ldr.w \t1, [\a, #20]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\ae, #8]
    str.w \t3, [\ao, #8]

    ldr.w \t0, [\a, #24]
    ldr.w \t1, [\a, #28]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\ae, #12]
    str.w \t3, [\ao, #12]
.endm

.macro split_evenodd8 he, ho, h, t0, t1, t2, t3
    ldr.w \t0, [\h, #0]
    ldr.w \t1, [\h, #4]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\he, #0]
    str.w \t3, [\ho, #0]

    ldr.w \t0, [\h, #8]
    ldr.w \t1, [\h, #12]
    pkhbt \t2, \t0, \t1, lsl #16
    pkhtb \t3, \t1, \t0, asr #16
    str.w \t2, [\he, #4]
    str.w \t3, [\ho, #4]
.endm

.macro h_recompose_0 pe, po, h
    ldrh.w r4, [\pe, #(0 * 2)]
    ldrh.w r5, [\pe, #(8 * 2)]
    ldrh.w r6, [\po, #(7 * 2)]
    ssub16 r5, r5, r6
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\h, #(0 * 2)]
.endm

.macro h_recompose_mid pe, po, h, idx
    ldrh.w r4, [\pe, #(\idx * 2)]
    ldrh.w r6, [\po, #((\idx - 1) * 2)]
    ssub16 r4, r4, r6
    ldrh.w r5, [\pe, #((\idx + 8) * 2)]
    ldrh.w r6, [\po, #((\idx + 7) * 2)]
    ssub16 r5, r5, r6
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\h, #(\idx * 2)]
.endm

.macro h_recompose_7 pe, po, h
    ldrh.w r4, [\pe, #(7 * 2)]
    ldrh.w r6, [\po, #(6 * 2)]
    ssub16 r4, r4, r6
    ldrh.w r5, [\po, #(14 * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    sadd16 r4, r4, r5
    strh.w r4, [\h, #(7 * 2)]
.endm

.macro b_recompose_0 pe, po, b
    ldrh.w r4, [\pe, #(0 * 2)]
    ldrh.w r5, [\pe, #(4 * 2)]
    ldrh.w r6, [\po, #(3 * 2)]
    ssub16 r5, r5, r6
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\b, #(0 * 2)]
.endm

.macro b_recompose_mid pe, po, b, idx
    ldrh.w r4, [\pe, #(\idx * 2)]
    ldrh.w r6, [\po, #((\idx - 1) * 2)]
    ssub16 r4, r4, r6
    ldrh.w r5, [\pe, #((\idx + 4) * 2)]
    ldrh.w r6, [\po, #((\idx + 3) * 2)]
    ssub16 r5, r5, r6
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\b, #(\idx * 2)]
.endm

.macro b_recompose_3 pe, po, b
    ldrh.w r4, [\pe, #(3 * 2)]
    ldrh.w r6, [\po, #(2 * 2)]
    ssub16 r4, r4, r6
    ldrh.w r5, [\po, #(6 * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    sadd16 r4, r4, r5
    strh.w r4, [\b, #(3 * 2)]
.endm

.macro g_even pe, g, ridx, loidx, hiidx
    ldrh.w r4, [\pe, #(\loidx * 2)]
    ldrh.w r5, [\pe, #(\hiidx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\g, #(\ridx * 2)]
.endm

.macro g_odd po, g, ridx, loidx, hiidx
    ldrh.w r4, [\po, #(\hiidx * 2)]
    mul_twiddle_plant r4, r7, r12, r8, r10
    ldrh.w r5, [\po, #(\loidx * 2)]
    ssub16 r4, r4, r5
    strh.w r4, [\g, #(\ridx * 2)]
.endm

.macro final_even pe, out, ridx, loidx, hiidx
    ldrh.w r4, [\pe, #(\loidx * 2)]
    ldrh.w r5, [\pe, #(\hiidx * 2)]
    mul_twiddle_plant r5, r7, r12, r8, r10
    ssub16 r4, r4, r5
    strh.w r4, [\out, #(\ridx * 2)]
.endm

.macro final_odd po, out, ridx, loidx, hiidx
    ldrh.w r4, [\po, #(\hiidx * 2)]
    mul_twiddle_plant r4, r7, r12, r8, r10
    ldrh.w r5, [\po, #(\loidx * 2)]
    ssub16 r4, r4, r5
    strh.w r4, [\out, #(\ridx * 2)]
.endm

// Direct inverse of one degree-7 block modulo x^8 + zeta.  The input and
// output coefficients are signed 16-bit high-half Plantard values.  This is
// the ZEN-256 base inversion dataflow specialized as an internal helper for
// ZEN-512's top-level degree-16 split.
.macro baseinv8_plant_direct out, in, zeta, qtab, q, qa, qinv, poly0, poly1, poly2, poly3, tmp, tmp2
    vmov s13, \qtab

    ldr.w \poly0, [\in, #0]   // a0||a1
    ldr.w \poly1, [\in, #4]   // a2||a3
    ldr.w \poly2, [\in, #8]   // a4||a5
    ldr.w \poly3, [\in, #12]  // a6||a7

    // b0 = ((a1a7 + a3a5 - a2a6)*2 - a4^2) * zeta + a0^2
    smultt \tmp, \poly0, \poly3
    smlatt \tmp, \poly1, \poly2, \tmp
    smulbb \tmp2, \poly1, \poly3
    sub.w \tmp, \tmp, \tmp2
    lsl.w \tmp, \tmp, #1
    smulbb \tmp2, \poly2, \poly2
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbb \tmp2, \poly0, \poly0
    plant_red \q, \qa, \qinv, \tmp2
    sadd16 \tmp, \tmp, \tmp2
    vmov s4, \tmp

    // b1 = ((a3a7 - a4a6)*2 + a5^2) * zeta + 2a0a2 - a1^2
    smultt \tmp, \poly1, \poly3
    smulbb \tmp2, \poly2, \poly3
    sub.w \tmp, \tmp, \tmp2
    lsl.w \tmp, \tmp, #1
    smlatt \tmp, \poly2, \poly2, \tmp
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbb \tmp2, \poly0, \poly1
    lsl.w \tmp2, \tmp2, #1
    smultt \qtab, \poly0, \poly0
    sub.w \tmp2, \tmp2, \qtab
    plant_red \q, \qa, \qinv, \tmp2
    sadd16 \tmp, \tmp, \tmp2
    vmov s5, \tmp

    // b2 = (2a5a7 - a6^2) * zeta + 2(a0a4 - a1a3) + a2^2
    smultt \tmp, \poly2, \poly3
    lsl.w \tmp, \tmp, #1
    smulbb \tmp2, \poly3, \poly3
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbb \tmp2, \poly0, \poly2
    smultt \qtab, \poly0, \poly1
    sub.w \tmp2, \tmp2, \qtab
    lsl.w \tmp2, \tmp2, #1
    smlabb \tmp2, \poly1, \poly1, \tmp2
    plant_red \q, \qa, \qinv, \tmp2
    sadd16 \tmp, \tmp, \tmp2
    vmov s6, \tmp

    // b3 = a7^2 * zeta + 2(a0a6 + a2a4 - a1a5) - a3^2
    smulwt \tmp, \zeta, \poly3
    smlabt \tmp, \tmp, \q, \qa
    smultt \tmp, \tmp, \poly3
    smulbb \tmp2, \poly0, \poly3
    smlabb \tmp2, \poly1, \poly2, \tmp2
    smultt \qtab, \poly0, \poly2
    sub.w \tmp2, \tmp2, \qtab
    lsl.w \tmp2, \tmp2, #1
    smultt \qtab, \poly1, \poly1
    sub.w \tmp2, \tmp2, \qtab
    add.w \tmp2, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp2

    vmov \tmp, s6
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov s9, \tmp              // b2||b3
    vmov \tmp, s4
    vmov \tmp2, s5
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov s8, \tmp              // b0||b1

    // c0 = (2b1b3 - b2^2) * zeta + b0^2
    vmov \poly2, s8
    vmov \poly3, s9
    smultt \tmp, \poly2, \poly3
    lsl.w \tmp, \tmp, #1
    smulbb \tmp2, \poly3, \poly3
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbb \tmp2, \poly2, \poly2
    plant_red \q, \qa, \qinv, \tmp2
    sadd16 \tmp, \tmp, \tmp2
    vmov s10, \tmp

    // c1 = b3^2 * zeta + 2b0b2 - b1^2
    smulwt \tmp, \zeta, \poly3
    smlabt \tmp, \tmp, \q, \qa
    smultt \tmp, \tmp, \poly3
    smulbb \tmp2, \poly2, \poly3
    add.w \tmp, \tmp, \tmp2, lsl #1
    smultt \tmp2, \poly2, \poly2
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    vmov s11, \tmp

    // det = c1^2 * zeta + c0^2
    smulwt \tmp2, \zeta, \tmp
    smlabt \tmp2, \tmp2, \q, \qa
    smultt \tmp, \tmp2, \tmp
    vmov \tmp2, s10
    smlatt \tmp, \tmp2, \tmp2, \tmp
    plant_red \q, \qa, \qinv, \tmp

    sxth \tmp, \tmp, ror #16
    movw \qtab, #769
    and.w \tmp2, \qtab, \tmp, asr #31
    add.w \tmp, \tmp, \tmp2
    vmov \qtab, s13
    add.w \qtab, \qtab, \tmp, lsl #2
    ldr.w \qtab, [\qtab]

    // c0 <- det^-1*c0, c1 <- -171*det^-1*c1
    vmov \tmp, s10
    smulwt \tmp, \qtab, \tmp
    smlabt \tmp, \tmp, \q, \qa
    vmov \tmp2, s11
    neg.w \qtab, \qtab
    smulwt \tmp2, \qtab, \tmp2
    smlabt \tmp2, \tmp2, \q, \qa
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov s12, \tmp             // c0||c1

    // f = (c0 - x*c1) * (b0 - x*b1 + x^2*b2 - x^3*b3)
    vmov \poly2, s12
    vmov \poly3, s9
    smulwb \tmp, \zeta, \poly3
    smlabt \tmp, \tmp, \q, \qa
    smultt \tmp, \poly2, \tmp
    vmov \poly3, s8
    smulbb \tmp2, \poly2, \poly3
    sub.w \tmp, \tmp2, \tmp
    plant_red \q, \qa, \qinv, \tmp
    vmov s4, \tmp

    vmov \poly3, s9
    smulwt \tmp, \zeta, \poly3
    smlabt \tmp, \tmp, \q, \qa
    smultt \tmp, \poly2, \tmp
    vmov \poly3, s8
    smulbt \tmp2, \poly2, \poly3
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    vmov s5, \tmp

    vmov \poly3, s9
    smulbb \tmp, \poly2, \poly3
    vmov \poly3, s8
    smlatb \tmp, \poly2, \poly3, \tmp
    plant_red \q, \qa, \qinv, \tmp
    vmov s6, \tmp

    vmov \poly3, s9
    smulbt \tmp, \poly2, \poly3
    vmov \poly3, s8
    smlatt \tmp, \poly2, \poly3, \tmp
    neg.w \tmp2, \tmp
    plant_red \q, \qa, \qinv, \tmp2
    vmov s7, \tmp2

    vmov \tmp, s6
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov s11, \tmp             // f2||f3
    vmov \tmp, s4
    vmov \tmp2, s5
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov s10, \tmp             // f0||f1

    ldr.w \qtab, [\in, #8]     // a4||a5
    ldr.w \tmp2, [\in, #12]    // a6||a7
    vmov s12, \tmp2
    vmov \poly2, s10
    vmov \poly3, s11

    // r0 = f0*a0 - zeta*(f1*a6 + f2*a4 + f3*a2)
    vmov \tmp2, s12
    smultb \tmp, \poly2, \tmp2
    smlabb \tmp, \poly3, \qtab, \tmp
    smlatb \tmp, \poly3, \poly1, \tmp
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbb \tmp2, \poly2, \poly0
    plant_red \q, \qa, \qinv, \tmp2
    ssub16 \tmp2, \tmp2, \tmp
    vmov s4, \tmp2

    // r1 = zeta*(f1*a7 + f2*a5 + f3*a3) - f0*a1
    vmov \tmp2, s12
    smultt \tmp, \poly2, \tmp2
    smlabt \tmp, \poly3, \qtab, \tmp
    smlatt \tmp, \poly3, \poly1, \tmp
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbt \tmp2, \poly2, \poly0
    plant_red \q, \qa, \qinv, \tmp2
    ssub16 \tmp, \tmp, \tmp2
    vmov s5, \tmp

    // r2 = f0*a2 + f1*a0 - zeta*(f2*a6 + f3*a4)
    smulbb \tmp, \poly2, \poly1
    smlatb \tmp, \poly2, \poly0, \tmp
    plant_red \q, \qa, \qinv, \tmp
    vmov \tmp2, s12
    smulbb \tmp2, \poly3, \tmp2
    smlatb \tmp2, \poly3, \qtab, \tmp2
    plant_red \q, \qa, \qinv, \tmp2
    smulwt \tmp2, \zeta, \tmp2
    smlabt \tmp2, \tmp2, \q, \qa
    ssub16 \tmp, \tmp, \tmp2
    vmov s6, \tmp

    // r3 = zeta*(f2*a7 + f3*a5) - (f0*a3 + f1*a1)
    vmov \tmp2, s12
    smulbt \tmp, \poly3, \tmp2
    smlatt \tmp, \poly3, \qtab, \tmp
    plant_red \q, \qa, \qinv, \tmp
    smulwt \tmp, \zeta, \tmp
    smlabt \tmp, \tmp, \q, \qa
    smulbt \tmp2, \poly2, \poly1
    smlatt \tmp2, \poly2, \poly0, \tmp2
    plant_red \q, \qa, \qinv, \tmp2
    ssub16 \tmp, \tmp, \tmp2
    vmov s7, \tmp

    // r4 = f0*a4 + f1*a2 + f2*a0 - zeta*(f3*a6)
    smulbb \tmp, \poly2, \qtab
    smlatb \tmp, \poly2, \poly1, \tmp
    smlabb \tmp, \poly3, \poly0, \tmp
    vmov \tmp2, s12
    smulwb \tmp2, \zeta, \tmp2
    smlabt \tmp2, \tmp2, \q, \qa
    smultt \tmp2, \poly3, \tmp2
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    vmov s0, \tmp

    // r5 = zeta*(f3*a7) - (f0*a5 + f1*a3 + f2*a1)
    vmov \tmp2, s12
    smulwt \tmp, \zeta, \tmp2
    smlabt \tmp, \tmp, \q, \qa
    smultt \tmp, \poly3, \tmp
    smulbt \tmp2, \poly2, \qtab
    smlatt \tmp2, \poly2, \poly1, \tmp2
    smlabt \tmp2, \poly3, \poly0, \tmp2
    sub.w \tmp, \tmp, \tmp2
    plant_red \q, \qa, \qinv, \tmp
    vmov s1, \tmp

    // r6 = f0*a6 + f1*a4 + f2*a2 + f3*a0
    vmov \tmp2, s12
    smultb \tmp, \poly2, \qtab
    smlabb \tmp, \poly3, \poly1, \tmp
    smlatb \tmp, \poly3, \poly0, \tmp
    smlabb \tmp, \poly2, \tmp2, \tmp
    plant_red \q, \qa, \qinv, \tmp
    vmov s2, \tmp

    // r7 = -(f0*a7 + f1*a5 + f2*a3 + f3*a1)
    vmov \tmp2, s12
    smulbt \tmp, \poly2, \tmp2
    smlatt \tmp, \poly2, \qtab, \tmp
    smlabt \tmp, \poly3, \poly1, \tmp
    smlatt \tmp, \poly3, \poly0, \tmp
    neg.w \tmp, \tmp
    plant_red \q, \qa, \qinv, \tmp
    vmov s3, \tmp

    vmov \tmp, s4
    vmov \tmp2, s5
    pkhtb \tmp, \tmp2, \tmp, asr #16
    vmov \poly0, s6
    vmov \poly1, s7
    pkhtb \poly0, \poly1, \poly0, asr #16
    vmov \poly2, s0
    vmov \poly3, s1
    pkhtb \poly2, \poly3, \poly2, asr #16
    vmov \poly3, s2
    vmov \tmp2, s3
    pkhtb \poly3, \tmp2, \poly3, asr #16

    str.w \tmp, [\out, #0]
    str.w \poly0, [\out, #4]
    str.w \poly2, [\out, #8]
    str.w \poly3, [\out, #12]
.endm

.align 2
.thumb_func
.type basemul16_block_raw, %function
basemul16_block_raw:
    push.w {r4-r11, lr}
    sub.w sp, sp, #BM_FRAME_SIZE

    compute_block_products
    setup_combine_ptrs

    combine_low_pair_raw 0
    combine_low_pair_raw 2
    combine_low_pair_raw 4
    combine_low_lane_raw 6
    combine_7_raw
    combine_high_pair_raw 8
    combine_high_pair_raw 10
    combine_high_pair_raw 12
    combine_high_lane_raw 14
    combine_15_raw

    add.w sp, sp, #BM_FRAME_SIZE
    pop.w {r4-r11, pc}

.align 2
.thumb_func
.type basemul16_block_raw_mq, %function
basemul16_block_raw_mq:
    push.w {r4-r11, lr}
    sub.w sp, sp, #BM_FRAME_SIZE

    compute_block_products
    setup_combine_ptrs
    movw r11, #50793
    movt r11, #63916    @ beta^2*qinv conversion to normal domain

    combine_low_pair_mq 0
    combine_low_pair_mq 2
    combine_low_pair_mq 4
    combine_low_lane_mq 6
    combine_7_mq
    combine_high_pair_mq 8
    combine_high_pair_mq 10
    combine_high_pair_mq 12
    combine_high_lane_mq 14
    combine_15_mq

    add.w sp, sp, #BM_FRAME_SIZE
    pop.w {r4-r11, pc}

.align 2
.thumb_func
.type baseinv16_block_plant, %function
baseinv16_block_plant:
    push.w {r4-r11, lr}
    sub.w sp, sp, #BI_FRAME_SIZE

    str.w r0, [sp, #BI_SAVE_R]
    str.w r1, [sp, #BI_SAVE_A]
    str.w r2, [sp, #BI_SAVE_Z]
    str.w r3, [sp, #BI_SAVE_QTAB]

    movw r8, #0
    movt r8, #769
    movw r9, #64769
    movt r9, #58632
    movw r10, #24608

    add.w r11, sp, #BI_AE
    add.w r12, sp, #BI_AO
    ldr.w r0, [sp, #BI_SAVE_A]
    split_evenodd16 r11, r12, r0, r4, r5, r6, r7

    add.w r0, sp, #BI_PE15
    add.w r1, sp, #BI_AE
    sqr8_plant_hh_direct r0, r1, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12

    add.w r0, sp, #BI_PO15
    add.w r1, sp, #BI_AO
    sqr8_plant_hh_direct r0, r1, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12

    add.w r0, sp, #BI_PE15
    add.w r1, sp, #BI_PO15
    add.w r2, sp, #BI_H
    ldr.w r7, [sp, #BI_SAVE_Z]
    h_recompose_0 r0, r1, r2
    h_recompose_mid r0, r1, r2, 1
    h_recompose_mid r0, r1, r2, 2
    h_recompose_mid r0, r1, r2, 3
    h_recompose_mid r0, r1, r2, 4
    h_recompose_mid r0, r1, r2, 5
    h_recompose_mid r0, r1, r2, 6
    h_recompose_7 r0, r1, r2

    add.w r0, sp, #BI_G
    add.w r1, sp, #BI_H
    ldr.w r7, [sp, #BI_SAVE_Z]
    ldr.w lr, [sp, #BI_SAVE_QTAB]
    baseinv8_plant_direct r0, r1, r7, lr, r8, r10, r9, r4, r5, r6, r3, r11, r12

    add.w r0, sp, #BI_PE15
    add.w r1, sp, #BI_G
    add.w r2, sp, #BI_AE
    mul8_plant_hh_direct r0, r1, r2, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12, lr, r1, r2

    add.w r0, sp, #BI_PO15
    add.w r1, sp, #BI_G
    add.w r2, sp, #BI_AO
    mul8_plant_hh_direct r0, r1, r2, r8, r10, r9, r3, r4, r5, r6, r7, r11, r12, lr, r1, r2

    add.w r0, sp, #BI_PE15
    add.w r1, sp, #BI_PO15
    ldr.w r2, [sp, #BI_SAVE_R]
    ldr.w r7, [sp, #BI_SAVE_Z]
    final_even r0, r2, 0, 0, 8
    final_odd r1, r2, 1, 0, 8
    final_even r0, r2, 2, 1, 9
    final_odd r1, r2, 3, 1, 9
    final_even r0, r2, 4, 2, 10
    final_odd r1, r2, 5, 2, 10
    final_even r0, r2, 6, 3, 11
    final_odd r1, r2, 7, 3, 11
    final_even r0, r2, 8, 4, 12
    final_odd r1, r2, 9, 4, 12
    final_even r0, r2, 10, 5, 13
    final_odd r1, r2, 11, 5, 13
    final_even r0, r2, 12, 6, 14
    final_odd r1, r2, 13, 6, 14
    ldrh.w r4, [r0, #(7 * 2)]
    strh.w r4, [r2, #(14 * 2)]
    ldrh.w r4, [r1, #(7 * 2)]
    sxth r4, r4
    neg.w r4, r4
    strh.w r4, [r2, #(15 * 2)]

    add.w sp, sp, #BI_FRAME_SIZE
    pop.w {r4-r11, pc}

.align 2
.thumb_func
.global baseinv16_karatsuba_asm
.type baseinv16_karatsuba_asm, %function
baseinv16_karatsuba_asm:
    push.w {r4-r8, lr}

    mov r4, r0
    mov r5, r1
    mov r6, r2
    mov r7, r3
    movs r8, #64

.Lbaseinv16_poly_loop:
    ldr.w r2, [r6], #4
    neg.w r2, r2
    mov r0, r4
    mov r1, r5
    mov r3, r7
    bl baseinv16_block_plant

    adds r4, r4, #32
    adds r5, r5, #32

    ldr.w r2, [r6, #-4]
    mov r0, r4
    mov r1, r5
    mov r3, r7
    bl baseinv16_block_plant

    adds r4, r4, #32
    adds r5, r5, #32
    subs r8, r8, #1
    bne.w .Lbaseinv16_poly_loop

    pop.w {r4-r8, pc}

.align 2
.thumb_func
.global basemul16_karatsuba_asm
.type basemul16_karatsuba_asm, %function
basemul16_karatsuba_asm:
    push.w {r4-r8, lr}

    mov r4, r0          @ r pointer
    mov r5, r1          @ a pointer
    mov r6, r2          @ b pointer
    mov r7, r3          @ Plantard zeta table, zetas_769
    movs r8, #64        @ ZEN_N / 32

.Lraw_poly_loop:
    ldr.w r3, [r7], #4
    mov r0, r4
    mov r1, r5
    mov r2, r6
    bl basemul16_block_raw

    adds r4, r4, #32
    adds r5, r5, #32
    adds r6, r6, #32

    ldr.w r3, [r7, #-4]
    neg.w r3, r3
    mov r0, r4
    mov r1, r5
    mov r2, r6
    bl basemul16_block_raw

    adds r4, r4, #32
    adds r5, r5, #32
    adds r6, r6, #32
    subs r8, r8, #1
    bne.w .Lraw_poly_loop

    pop.w {r4-r8, pc}

.align 2
.thumb_func
.global basemul16_karatsuba_mq_asm
.type basemul16_karatsuba_mq_asm, %function
basemul16_karatsuba_mq_asm:
    push.w {r4-r8, lr}

    mov r4, r0          @ r pointer
    mov r5, r1          @ a pointer
    mov r6, r2          @ b pointer
    mov r7, r3          @ Plantard zeta table, zetas_769
    movs r8, #64        @ ZEN_N / 32

.Lmq_poly_loop:
    ldr.w r3, [r7], #4
    mov r0, r4
    mov r1, r5
    mov r2, r6
    bl basemul16_block_raw_mq

    adds r4, r4, #32
    adds r5, r5, #32
    adds r6, r6, #32

    ldr.w r3, [r7, #-4]
    neg.w r3, r3
    mov r0, r4
    mov r1, r5
    mov r2, r6
    bl basemul16_block_raw_mq

    adds r4, r4, #32
    adds r5, r5, #32
    adds r6, r6, #32
    subs r8, r8, #1
    bne.w .Lmq_poly_loop

    pop.w {r4-r8, pc}
