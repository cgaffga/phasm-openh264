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
 * Internal accessors for the registered callback state. Used by hook
 * bodies in svc_encode_mb.cpp + svc_base_layer_md.cpp (Stages 1-7) to
 * read the current frame number set via WelsStegoSetFrameNum, etc.
 * ------------------------------------------------------------------ */
uint32_t                PhasmStegoGetFrameNum(void);
PhasmStegoEncPreEmitFn  PhasmStegoGetEncPreEmit(void);
PhasmStegoDecPostReadFn PhasmStegoGetDecPostRead(void);
PhasmStegoMdCostFn      PhasmStegoGetMdCostCapture(void);
PhasmStegoDualReconFn   PhasmStegoGetDualReconObserve(void);
void*                   PhasmStegoGetUserData(void);

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

/* ---------------------------------------------------------------------
 * phasm_emit_md_cost
 *
 * Fire the registered md_cost_capture callback (if any) with the
 * winning mb_type + CBP for one MB. Called from svc_encode_slice.cpp
 * AFTER mode decision finalizes and BEFORE the bitstream writer emits
 * the MB. The MB's `uiMbType` and `uiCbp` are read from `pCurMb`.
 *
 * Translates OpenH264's internal MB_TYPE_* bitfield into a small
 * PHASM_MB_TYPE_* classification so the consumer's filter-by-block_cat
 * logic stays trivial (one byte-lookup, no enum-bitfield arithmetic).
 *
 * No-op if no callback is registered. The hot path is one frame_num +
 * mb_x + mb_y read, a 6-way switch on uiMbType, and the dispatch.
 * ------------------------------------------------------------------ */
void phasm_emit_md_cost(uint16_t mb_x, uint16_t mb_y,
                        uint32_t internal_mb_type, uint8_t cbp);

/* ---------------------------------------------------------------------
 * phasm_dual_recon_writeback (Phase C.8.2+)
 *
 * Single entry point called by C.8.3-8 per-mode recon hook bodies
 * once they have computed BOTH the clean and stego pixel blocks for a
 * given reconstruction commit. Performs two memcpys:
 *
 *   memcpy clean_pixels -> clean_dst[pixel_y*dst_stride + pixel_x]
 *   memcpy stego_pixels -> stego_dst[pixel_y*dst_stride + pixel_x]
 *
 * (row-by-row, block_h rows of block_w bytes, hopping `dst_stride`
 * between row starts on the dest side and `src_stride` on the source
 * side). After both copies complete, fires the registered
 * `dual_recon_observe` callback if one is set; pure no-op otherwise.
 *
 * The caller is responsible for resolving `clean_dst` / `stego_dst`
 * from the encoder context: typically
 *
 *   clean_dst = pCurDq->pCsData[plane]              (aliases pDecPic)
 *   stego_dst = pCurDq->pVisualRecPic->pData[plane]
 *   dst_stride= pCurDq->iCsStride[plane]            (== pVisualRecPic
 *                                                    line stride at
 *                                                    same width)
 *
 * `pixel_x` / `pixel_y` are pixel coordinates in the plane (frame
 * coordinates, not MB-local). The caller derives them from
 * `mb_x * (16 >> shift_x)` + per-block offset, etc.
 *
 * `plane`: 0=Y, 1=U, 2=V. Used only for the observe callback
 * dispatch; the helper itself is plane-agnostic and operates purely
 * on byte arrays.
 *
 * Safe to call with stego_dst==NULL or pVisualRecPic unallocated: the
 * helper skips the stego memcpy in that case (so callers don't have
 * to gate on stego-active state). The clean memcpy always runs.
 *
 * Inlining cost: ~12 LOC body, two memcpy loops + null-check +
 * callback dispatch. Hot path with no callback is ~5 instructions
 * beyond the memcpys themselves.
 * ------------------------------------------------------------------ */
void phasm_dual_recon_writeback(uint16_t mb_x,
                                uint16_t mb_y,
                                uint8_t  plane,
                                int32_t  pixel_x,
                                int32_t  pixel_y,
                                int32_t  block_w,
                                int32_t  block_h,
                                uint8_t* clean_dst,
                                uint8_t* stego_dst,
                                int32_t  dst_stride,
                                const uint8_t* clean_pixels,
                                const uint8_t* stego_pixels,
                                int32_t  src_stride);

/* ---------------------------------------------------------------------
 * Chroma per-MB clean snapshot stash (Phase C.8.5+)
 *
 * WelsEncRecUV captures the clean post-quant + post-dequant + post-DC-
 * reinject chroma residual (64 int16_t per plane × 2 planes) into a
 * process-global static. The IDCT-site caller in svc_encode_slice.cpp
 * reads it via `phasm_get_chroma_clean_pres()` to recompute a clean
 * reconstruction alongside the live stego one. Stash content is
 * EQUIVALENT to what the live pRes holds at the IDCT call site, but
 * computed from pre-HOOK snapshot. The IDCT runs on it directly.
 *
 * Scope: per-MB. iUV ∈ {0=Cb, 1=Cr}. Single-threaded (iMultipleThread
 * Idc=1, phasm-stego default; #339 tracks the multi-thread revisit).
 * ------------------------------------------------------------------ */
void           phasm_stash_chroma_clean_pres(int32_t iUV, const int16_t* clean_pres64);
const int16_t* phasm_get_chroma_clean_pres(int32_t iUV);

/* ---------------------------------------------------------------------
 * P-frame luma per-MB clean snapshot stash (Phase C.8.6)
 *
 * WelsEncInterY captures the clean post-quant + (mirror of suppression +
 * dequant) luma residual (256 int16_t per MB = 4 8x8 blocks × 64 entries)
 * into a process-global static. The IDCT-site caller in svc_encode_slice
 * .cpp's OutputPMbWithoutConstructCsRsNoCopy reads it via
 * `phasm_get_p_luma_clean_pres()` to recompute a clean luma
 * reconstruction alongside the live stego one. Same scope rules as the
 * chroma stash.
 * ------------------------------------------------------------------ */
void           phasm_stash_p_luma_clean_pres(const int16_t* clean_pres256);
const int16_t* phasm_get_p_luma_clean_pres(void);

/* ---------------------------------------------------------------------
 * Phase C.9.1 Path A v2 (#449) per-MB dirty flags for P-frame inter +
 * chroma. The snapshot site (in svc_encode_mb.cpp) OR-accumulates every
 * coeff-hook return on this plane and calls `phasm_set_*_dirty(...)`;
 * the consume site (in svc_encode_slice.cpp's OutputPMbWithout
 * ConstructCsRsNoCopy P-frame branch) reads the flags and skips the
 * entire dual-recon snapshot/restore/IDCT cycle when no plane is dirty
 * and the MV override isn't active. `phasm_reset_dirty_flags()` is
 * called after consuming so a stale set doesn't leak to the next MB.
 * ------------------------------------------------------------------ */
void           phasm_set_p_luma_dirty(int dirty);
int            phasm_get_p_luma_dirty(void);
void           phasm_set_chroma_dirty(int32_t iUV, int dirty);
int            phasm_get_chroma_dirty(int32_t iUV);
void           phasm_reset_dirty_flags(void);

/* ---------------------------------------------------------------------
 * Phase C.9.0 (#482) — Pass-1 visual_recon disable.
 *
 * Toggles whether InitDqLayers allocates the pVisualRef[] mirror pool.
 * When disabled, pVisualDecPic / pVisualRecPic stay NULL for the
 * encoder's lifetime and every per-MB mirror site plus the C.8.8 dual
 * deblock pass short-circuits via the existing NULL guards. Used by the
 * Pass-1 cover probe (whose bitstream is walked then discarded).
 *
 * MUST be called BEFORE phasm_encoder_initialize for the flag to take
 * effect. Default 1 (enabled = current C.8 baseline behavior).
 * ------------------------------------------------------------------ */
void           phasm_set_dual_recon_enabled(int enabled);
int            phasm_get_dual_recon_enabled(void);

/* ---------------------------------------------------------------------
 * Phase C.9.2 (#450) — per-slice override counter.
 *
 * Incremented by phasm_apply_coeff_hooks / *_dual / phasm_apply_mvd_hooks
 * at their return-1 site (where a value was actually modified). Read at
 * the start of DeblockingFilterSliceAvcbase to decide whether the C.8.8
 * second deblock pass on pVisualRecPic can be skipped (when the count is
 * 0 the pre-deblock pVisualRecPic is byte-identical to pre-deblock
 * pDecPic, so the second deblock would produce the same result the first
 * one already wrote). Reset at the end of every deblock pass (slice and
 * frame variants) so the next slice starts at 0.
 * ------------------------------------------------------------------ */
void           phasm_inc_slice_override_count(void);
int            phasm_get_slice_override_count(void);
void           phasm_reset_slice_override_count(void);

/* ---------------------------------------------------------------------
 * MvdSign cascade-break MC stash (Phase C.8.7)
 *
 * HOOK-H1 (svc_base_layer_md.cpp) and partition MVD sites mutate the
 * P-frame MV and re-run MC at the STEGO MV so the bitstream is decoder-
 * consistent. That writes STEGO_MC into pMemPredLuma → pDecPic carries
 * STEGO_MC + residual = polluted next-frame reference. To restore a
 * clean encoder reference WHILE keeping the wire correct, HOOK-H1 also
 * computes MC at the PRE-override (clean) MV into these stashes:
 *   - luma:  256 packed bytes (stride 16, 16x16)
 *   - chroma: 64 packed bytes per plane (stride 8, 8x8); iUV ∈ {0=Cb, 1=Cr}
 *
 * The `active` flag is sticky per-MB: HOOK-H1 sets it to 1 if the helper
 * actually overrode the MV. OutputPMbWithoutConstructCsRsNoCopy in
 * svc_encode_slice.cpp reads it; if active, shifts pDecPic by
 * (CLEAN_MC − STEGO_MC) so the encoder reference is restored to clean,
 * then clears the flag. pVisualRecPic mirrors the actual decoder
 * reconstruction (STEGO_MC + stego_residual).
 *
 * Scope: per-MB. Single-threaded encoder default (#339 multi-thread
 * revisit). For C.8.7 v1.0, only P_16x16 (HOOK-H1) populates these;
 * partitioned modes (HOOK-H2..H7) come later when v1.0 ships.
 * ------------------------------------------------------------------ */
void           phasm_set_mv_override_active(int active);
int            phasm_get_mv_override_active(void);
void           phasm_stash_mv_clean_mc_luma(const uint8_t* clean_mc_256);
const uint8_t* phasm_get_mv_clean_mc_luma(void);
void           phasm_stash_mv_clean_mc_chroma(int32_t iUV, const uint8_t* clean_mc_64);
const uint8_t* phasm_get_mv_clean_mc_chroma(int32_t iUV);

/* C.8.7 v1.1 — partitioned-mode slot population for the MvdSign cascade
 * stash. Partitions write their slice (w × h) starting at (dst_x, dst_y)
 * within the 16×16 (luma) or 8×8 (chroma) packed stash buffer. Caller
 * computes the slot offset from g_kuiSmb4AddrIn256[iIdx] and the
 * partition shape (16x8, 8x16, 8x8, sub-MB types). Bounds-checked. */
void phasm_stash_mv_clean_mc_luma_slot(int32_t dst_x, int32_t dst_y,
                                        int32_t w, int32_t h,
                                        const uint8_t* src, int32_t src_stride);
void phasm_stash_mv_clean_mc_chroma_slot(int32_t iUV,
                                          int32_t dst_x, int32_t dst_y,
                                          int32_t w, int32_t h,
                                          const uint8_t* src, int32_t src_stride);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_INTERNAL_H */
