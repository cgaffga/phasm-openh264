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
  /* B-full.2b (#895): opaque PhasmStegoState* (pCtx->pPhasmStego) for
   * the per-encoder bypass scratch; NULL ⇒ mutation path. Set by the
   * MB-encode caller (svc_base_layer_md.cpp, which has sWelsEncCtx*). */
  void*    stego;
} PhasmMvHookCtx;

/* ---------------------------------------------------------------------
 * Internal accessors for the registered callback state. Used by hook
 * bodies in svc_encode_mb.cpp + svc_base_layer_md.cpp (Stages 1-7) to
 * read the current frame number set via WelsStegoSetFrameNum, etc.
 * ------------------------------------------------------------------ */
uint32_t                       PhasmStegoGetFrameNum(void);
PhasmStegoEncPreEmitFn         PhasmStegoGetEncPreEmit(void);
PhasmStegoDecPostReadFn        PhasmStegoGetDecPostRead(void);
PhasmStegoMdCostFn             PhasmStegoGetMdCostCapture(void);
PhasmStegoDualReconFn          PhasmStegoGetDualReconObserve(void);
/* Pass-2 replay architecture (Option A) accessors. */
PhasmStegoCaptureMbDecisionFn  PhasmStegoGetCaptureMbDecision(void);
PhasmStegoReplayMbDecisionFn   PhasmStegoGetReplayMbDecision(void);
PhasmStegoPassMode             PhasmStegoGetPassMode(void);
void*                          PhasmStegoGetUserData(void);

/* ---------------------------------------------------------------------
 * B-full.3 (#895): per-encoder session-state accessors + setters.
 *
 * frame_num / pass_mode / user_data migrate off the libcommon process-
 * globals onto the per-encoder PhasmStegoState (pCtx->pPhasmStego) so
 * concurrent encoder instances (parallel-GOP, 4b) don't collide. The
 * callback FUNCTION POINTERS stay global (identical Rust trampolines —
 * race-free); only the per-session DATA varies per instance.
 *
 * The get-helpers take the opaque PhasmStegoState* and return the per-
 * instance value when the instance is "session-active" (any setter was
 * called), else fall back to the libcommon global so the dormant decoder
 * + whole-video test paths keep working unchanged. NULL stego ⇒ global.
 *
 * The setters are called from the Rust orchestrator (with the void* from
 * phasm_encoder_get_stego_state) AFTER Encoder::new.
 * ------------------------------------------------------------------ */
uint32_t           phasm_stego_get_frame_num(void* stego);
PhasmStegoPassMode phasm_stego_get_pass_mode(void* stego);
void*              phasm_stego_get_user_data(void* stego);
void phasm_stego_state_set_frame_num(void* stego, uint32_t frame_num);
void phasm_stego_state_set_pass_mode(void* stego, PhasmStegoPassMode mode);
void phasm_stego_state_set_user_data(void* stego, void* user_data);

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
/* B-full.2b (#895): `stego` = opaque PhasmStegoState* (pCtx->pPhasmStego)
 * for the per-encoder bypass-override scratch; NULL ⇒ no scratch (the
 * mutation path / passthrough). Threaded from the MB-encode call sites
 * which carry sWelsEncCtx*. */
int /*bool*/ phasm_apply_coeff_hooks(PhasmStegoPos* pos_template,
                                     uint8_t sub_block,
                                     uint8_t coeff_idx_scanned,
                                     uint8_t block_cat,
                                     int16_t* level,
                                     void* stego);

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
                                          int16_t* level_b,
                                          void* stego);

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
                        uint32_t internal_mb_type, uint8_t cbp,
                        void* stego);

/* ---------------------------------------------------------------------
 * phasm_emit_mb_decision (#533.2 Pass-2 replay)
 *
 * Fire the registered `capture_mb_decision` callback (if any) with a
 * caller-built per-MB decision record. Caller in svc_encode_slice.cpp
 * builds the struct from `pCurMb` at the same MB boundary where
 * md_cost fires (after WelsMdIntraMb / pfInterMd finalizes mb_type +
 * partition + MVs + intra pred modes, before residual emit).
 *
 * No-op unless `WelsStegoSetPassMode(PHASM_PASS_CAPTURE)` is in
 * effect and a `capture_mb_decision` callback is registered. The
 * hot path on disabled pass-mode is two function-pointer reads.
 * ------------------------------------------------------------------ */
void phasm_emit_mb_decision(const PhasmStegoMbDecision* decision, void* stego);

/* ---------------------------------------------------------------------
 * phasm_fetch_replay_decision (#533.3 Pass-2 replay)
 *
 * If pass_mode == PHASM_PASS_REPLAY and a replay_mb_decision callback
 * is registered, invoke it with the current frame_num + (mb_x, mb_y).
 * On hit (callback returns 1), `*out_decision` is populated with the
 * cached decision and this function returns 1. On miss / disabled
 * pass / no callback, returns 0 and *out_decision is untouched.
 *
 * Callers in svc_base_layer_md.cpp use the result to short-circuit
 * RDO/ME and reconstruct from the cached decision directly. Cache
 * miss falls back to the normal mode-decision path. */
int phasm_fetch_replay_decision(uint16_t mb_x, uint16_t mb_y,
                                PhasmStegoMbDecision* out_decision,
                                void* stego);

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
 * Phase 4.5 (#538) — bypass-bin scratch table.
 *
 * Dense per-MB storage for stego bin overrides, read at CABAC emit
 * time by `phasm_apply_bypass_bin_override` (in wels_stego.h public
 * ABI) and populated by the Phase 4.5.b+ migrations of the mutating
 * hooks (apply_coeff_hooks_to_level / phasm_apply_mvd_hooks /
 * phasm_apply_h_partition_hook).
 *
 *   - `phasm_reset_bypass_overrides`: clear all slots back to "no
 *     override". Intended call site: top of each per-MB encode
 *     function, before any populate hook can fire. Wired in 4.5.b.
 *
 *   - `phasm_set_bypass_override(domain, pos, bin)`: write a single
 *     override bin (0 or 1) at the slot keyed by (domain + pos's
 *     domain-relevant fields). Out-of-range domains / positions /
 *     bins are silently no-op'd. Called from the migrated hook
 *     helpers; not currently called from outside wels_stego.cpp,
 *     but declared here so future cross-TU callers can find it.
 *
 * Pre-4.5.b: no callers populate, scratch stays zero-init, and the
 * Phase 4.2-4.4 emit-side hooks return orig_bin unconditionally.
 * Byte-identical to the Phase 4.4 ship. */
/* B-full.2b (#895): all three take `stego` = opaque PhasmStegoState*
 * (pCtx->pPhasmStego) — the per-encoder bypass scratch home. NULL ⇒
 * no-op / passthrough. */
void phasm_reset_bypass_overrides(void* stego);
void phasm_set_bypass_override(uint8_t domain,
                                const PhasmStegoPos* pos,
                                int override_bin,
                                void* stego);

/* ---------------------------------------------------------------------
 * Phase 4.5.b (#538) — wire-only mode gate.
 *
 * When OFF (default), the mutating-hook helpers keep their pre-4.5
 * behaviour: invoke the Rust callback, mutate *level / MV in place.
 * When ON, those helpers route override decisions to the scratch
 * table via `phasm_set_bypass_override` and DO NOT mutate encoder
 * state — Pass-2's pDecPic stays byte-identical to Pass-1's, and the
 * stego override only manifests on the wire via the Phase 4.2-4.4
 * bypass-bin emit hooks.
 *
 * Phase 4.5.b ships the gate + the MVD-hook (`phasm_apply_mvd_hooks`)
 * branch only. Coeff hooks migrate in 4.5.c+. Default stays OFF so
 * the 19 lib tests that register `enc_pre_emit` callbacks and verify
 * mutated-state behaviour stay green. Phase 4.6 wires a forged-flip
 * test that toggles ON; Phase 5 (#539) flips the default once
 * C.8.x dual-recon machinery is gone. */
void phasm_set_use_wire_only_overrides(int enabled);
int  phasm_get_use_wire_only_overrides(void);

/* ---------------------------------------------------------------------
 * B-full.1 (#895) — per-encoder stego state container.
 *
 * Bundles the encoder-only process-global stego statics so they can move
 * onto sWelsEncCtx (per-instance) — the prerequisite for thread-safe
 * concurrent stego encode (parallel-GOP, doc §12). `create` allocates a
 * zero-initialized state; `destroy` frees it (NULL-safe). This increment
 * only wires alloc/free into WelsInitEncoderExt / FreeMemorySvc; no reads
 * are redirected yet, so the encoded bitstream is byte-identical. B-full.2+
 * migrate the statics + their accessors onto `sWelsEncCtx::pPhasmStego`.
 * ------------------------------------------------------------------ */
void* phasm_stego_state_create(void);
void  phasm_stego_state_destroy(void* p);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_INTERNAL_H */
