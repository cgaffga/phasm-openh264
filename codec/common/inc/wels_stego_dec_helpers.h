// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego decoder-side emit helpers. Included by decoder TUs
// (parse_mb_syn_cabac.cpp) to dispatch the `dec_post_read` callback
// for each parsed stego-domain bin.
//
// These helpers complement the encoder-side helpers in
// `codec/encoder/core/inc/wels_stego_internal.h`. Implementations live
// in `codec/encoder/core/src/wels_stego.cpp` (where the global
// callback table is defined); they are exposed to libdecoder via the
// aggregate `libopenh264` link, which link_whole's both libencoder
// and libdecoder.
//
// Phase B.9.2.1: declarations only (no insertion sites yet).
// Phase B.9.2.2 — B.9.2.5 wire these into the decoder parse path:
//   - phasm_dec_emit_coeff_sign        → ParseSignificantCoeffCabac:1390
//   - phasm_dec_emit_coeff_suffix_lsb  → DecodeUEGLevelCabac suffix-LSB
//   - phasm_dec_emit_mvd_sign          → DecodeMvdComponentCabac sign read
//   - phasm_dec_emit_mvd_suffix_lsb    → DecodeMvdComponentCabac UEG3 suffix LSB
//
// Each helper:
//   - is a no-op if no `dec_post_read` callback is registered
//   - reads `frame_num` from the global set by WelsStegoSetFrameNum
//   - constructs a PhasmStegoPos with the correct per-domain fields
//   - dispatches to the registered callback with the parsed bit value
//
// Pure observation: no return value, no encoder-state modification.
// Safe to call from any thread that the decoder runs on.

#ifndef WELS_STEGO_DEC_HELPERS_H
#define WELS_STEGO_DEC_HELPERS_H

#include "wels_stego.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * phasm_dec_emit_coeff_sign
 *
 * Fire `dec_post_read` for a parsed coefficient sign bypass bit.
 *
 *   block_cat: ECtxBlockCat (0=LUMA_DC, 1=LUMA_AC, 2=LUMA_4x4,
 *              3=CHROMA_DC, 4=CHROMA_AC). Same enum as the encoder
 *              uses; matches the iResProperty argument to
 *              ParseSignificantCoeffCabac.
 *   sub_block: 0..15. Spatial sub-block index within the MB. Matches
 *              iIndex/iSubBlockIdx in ParseResidualBlockCabac caller.
 *   coeff_idx: 0..15. CABAC reverse-scan position of the sign bit.
 *              For LUMA_DC/AC the encoder uses raster index; the
 *              consumer's translation function maps to walker scan.
 *   sign_bit:  the parsed value (0 or 1).
 * ------------------------------------------------------------------ */
void phasm_dec_emit_coeff_sign(uint16_t mb_x, uint16_t mb_y,
                               uint8_t  block_cat,
                               uint8_t  sub_block,
                               uint8_t  coeff_idx,
                               int32_t  sign_bit);

/* ---------------------------------------------------------------------
 * phasm_dec_emit_coeff_suffix_lsb
 *
 * Fire `dec_post_read` for the LSB of a UEG suffix when the coefficient
 * magnitude triggers the escape (|coeff| ≥ 15). Same position fields
 * as coeff_sign; only the domain differs.
 * ------------------------------------------------------------------ */
void phasm_dec_emit_coeff_suffix_lsb(uint16_t mb_x, uint16_t mb_y,
                                     uint8_t  block_cat,
                                     uint8_t  sub_block,
                                     uint8_t  coeff_idx,
                                     int32_t  lsb_bit);

/* ---------------------------------------------------------------------
 * phasm_dec_emit_mvd_sign
 *
 *   list:          0 = L0, 1 = L1
 *   partition_idx: 0..3 within MB (16x16, 16x8, 8x16, 8x8 partition)
 *   mv_component:  0 = X, 1 = Y
 *   sign_bit:      the parsed value
 * ------------------------------------------------------------------ */
void phasm_dec_emit_mvd_sign(uint16_t mb_x, uint16_t mb_y,
                             uint8_t  list,
                             uint8_t  partition_idx,
                             uint8_t  mv_component,
                             uint8_t  ref_idx,
                             int32_t  sign_bit);

/* ---------------------------------------------------------------------
 * phasm_dec_emit_mvd_suffix_lsb
 *
 * Same positional fields as mvd_sign. Fires only when |MVD| ≥ 9
 * (UEG3 escape activates).
 * ------------------------------------------------------------------ */
void phasm_dec_emit_mvd_suffix_lsb(uint16_t mb_x, uint16_t mb_y,
                                   uint8_t  list,
                                   uint8_t  partition_idx,
                                   uint8_t  mv_component,
                                   uint8_t  ref_idx,
                                   int32_t  lsb_bit);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_DEC_HELPERS_H */
