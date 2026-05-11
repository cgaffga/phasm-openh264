// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego internal helper API. Not part of the public wels_stego.h
// ABI. Consumed by encoder TUs (svc_encode_mb.cpp, svc_base_layer_md.cpp)
// once Phase A.5 stages 1-7 wire the hooks. Stage 0 ships the helper
// implementations plus gtest unit-test coverage; later stages just call
// these from the right insertion points per
// docs/design/video/h264/openh264-hook-sites.md (consumer repo).

#ifndef WELS_STEGO_INTERNAL_H
#define WELS_STEGO_INTERNAL_H

#include "wels_stego.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* JVT-O079 zero-out suppression thresholds. The encoder skips emit if
 * the per-MB or per-8x8 nonzero count drops below these. A coefficient
 * hook MUST NOT push a sub-block below its floor (or it must explicitly
 * reset the CBP/NZC state — Stage 0 helpers conservatively refuse). */
#define PHASM_JVT_LUMA_MB_FLOOR    6
#define PHASM_JVT_LUMA_8x8_FLOOR   4
#define PHASM_JVT_CHROMA_FLOOR     7

/* MVD context for the unified per-partition hook. The caller fills this
 * in at each insertion point in svc_base_layer_md.cpp (one Ctx per
 * (partition_idx, mv_component) pair fired in Stage 6/7).
 *
 *   - mv_x_qpel / mv_y_qpel: pointers to the MV component on pCurMb
 *     (sP16x16Mv / sP16x8Mv[i] / sP8x16Mv[i] / sP8x8Mv[i]). REQUIRED.
 *   - mvList_x_qpel / mvList_y_qpel: pointers to the temporal-MV
 *     predictor entry pCurLayer->pDecPic->sMvList[mbXY]. Only valid for
 *     P_16x16 / P_Skip / P_Background paths (sMvList is per-MB, not
 *     per-partition). NULL otherwise.
 *   - mvp_x_qpel / mvp_y_qpel: predicted MV components (output of
 *     PredMv) — used to compute MVD = MV - MVp for the LSB hook.
 *   - pred_skip_mv_x / pred_skip_mv_y: PredSkipMv (used by
 *     WelsMdInterDoubleCheckPskip) — if the hooked MV would equal this,
 *     refuse hook (would silently demote to Skip, dropping the bit).
 *     Only meaningful when check_pskip_collision is true (P_16x16 path).
 */
typedef struct PhasmMvHookCtx {
  uint32_t frame_num;
  uint16_t mb_x;
  uint16_t mb_y;
  uint8_t  partition_idx;
  uint8_t  ref_idx;
  uint8_t  check_pskip_collision;  /* bool: only for P_16x16 / Skip path */
  uint8_t  _reserved;
  int16_t  mvp_x_qpel;
  int16_t  mvp_y_qpel;
  int16_t  pred_skip_mv_x;
  int16_t  pred_skip_mv_y;
  int16_t* mv_x_qpel;       /* required */
  int16_t* mv_y_qpel;       /* required */
  int16_t* mvList_x_qpel;   /* optional, NULL OK */
  int16_t* mvList_y_qpel;   /* optional, NULL OK */
} PhasmMvHookCtx;

/* ---------------------------------------------------------------------
 * phasm_apply_coeff_hooks
 *
 * Fire coeff_sign + coeff_suffix_lsb hooks on a single non-zero
 * quantized coefficient stored in ONE array. Used by intra HOOK-A
 * (I_16x16 luma DC, stack array), HOOK-B (I_16x16 luma AC, raster),
 * HOOK-E (I_4x4 luma, single per-block array).
 *
 * Caller pre-fills pos_template with frame_num + mb_x + mb_y +
 * partition_idx. Helper sets the remaining fields per-domain call.
 *
 * Returns true if *level was modified.
 *
 * Skips hook dispatch (returns false) when *level == 0.
 *
 * Contract enforcement: refuses any override that would produce zero
 * level (preserves phasm "non-zero in / non-zero out" invariant), or
 * a sign-bit return outside {0,1,-1}, or a suffix-LSB return outside
 * {0,1,-1}. Refusal = no modification.
 * ------------------------------------------------------------------ */
int /*bool*/ phasm_apply_coeff_hooks(PhasmStegoPos* pos_template,
                                     uint8_t sub_block,
                                     uint8_t coeff_idx_scanned,
                                     uint8_t block_cat,
                                     int16_t* level);

/* ---------------------------------------------------------------------
 * phasm_apply_coeff_hooks_dual
 *
 * Same as phasm_apply_coeff_hooks but writes the modified value to
 * TWO arrays. Used by inter HOOK-F (P luma: pCoeffLevel raster +
 * iLumaBlock zigzag), HOOK-G (P chroma), and intra HOOK-C/D where
 * the chroma DC ST64 dual-write is needed (caller maps the chroma DC
 * aDct2x2[4] AND iChromaDc[] aliases here).
 *
 * Both pointers must alias the same logical coefficient. Helper
 * sanity-asserts they hold the same value before applying any
 * modification (failing this assertion in a debug build flags
 * caller-side scan-index bugs).
 * ------------------------------------------------------------------ */
int /*bool*/ phasm_apply_coeff_hooks_dual(PhasmStegoPos* pos_template,
                                          uint8_t sub_block,
                                          uint8_t coeff_idx_scanned,
                                          uint8_t block_cat,
                                          int16_t* level_a,
                                          int16_t* level_b);

/* ---------------------------------------------------------------------
 * phasm_apply_mvd_hooks
 *
 * Fire MVD sign + MVD suffix LSB hooks on a single MV partition.
 * Helper handles:
 *   - bit-to-value translation per domain
 *     (sign flip → reflect MV around MVp; suffix-LSB flip → |MVD| ±1)
 *   - sMvList refresh (if context provides the pointer pair)
 *   - PredSkipMv collision check (refuse if hook would coincide with
 *     P_Skip MV inferred by neighbours)
 *
 * Returns true if any MV component was modified.
 *
 * Skips hook dispatch (returns false) when both MVD components are 0
 * (sign bit isn't emitted for MVD=0 components).
 * ------------------------------------------------------------------ */
int /*bool*/ phasm_apply_mvd_hooks(const PhasmMvHookCtx* ctx);

/* ---------------------------------------------------------------------
 * phasm_mvd_would_collide_with_pskip
 *
 * Predicate: would (mv_x, mv_y) trigger WelsMdInterDoubleCheckPskip's
 * silent Skip demote? Used internally by phasm_apply_mvd_hooks; exposed
 * for callers that want to query before computing the hook.
 * ------------------------------------------------------------------ */
int /*bool*/ phasm_mvd_would_collide_with_pskip(int16_t mv_x, int16_t mv_y,
                                                int16_t pred_skip_mv_x,
                                                int16_t pred_skip_mv_y);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_INTERNAL_H */
