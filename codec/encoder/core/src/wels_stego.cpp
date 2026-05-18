// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego encoder-side hook helpers. The process-global callback
// table, registration entry points, accessors, and decoder-side emit
// helpers all live in `codec/common/src/wels_stego_common.cpp`
// (compiled into libcommon). This file holds only the encoder-side
// helpers that are called from svc_encode_mb.cpp and
// svc_base_layer_md.cpp during emission.
//
// History: split out of the original wels_stego.cpp in Phase B.9.2.2
// when the decoder TU started needing direct access to the global
// callback table via dec_post_read.

#include "wels_stego.h"
#include "wels_stego_internal.h"

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>

// =====================================================================
// Phase C.8.13(b) debug counters (#455).
//
// Atomic counters for `phasm_apply_coeff_hooks_dual` to narrow the
// residual cascade-leak. Read via `phasm_get_hook_dual_*` extern "C"
// getters; reset via `phasm_reset_hook_dual_counters`.
//
// These have zero impact when the stego callbacks aren't registered
// (we increment unconditionally on the dual-write path, but that path
// is only ever entered when an enc_pre_emit callback exists). Cost is
// ~3 ns/fire amortised — negligible vs the surrounding quant+scan
// work. Stays in the source long-term; counters are an ABI-compatible
// addition (new symbols, no struct changes).
// =====================================================================

static std::atomic<uint64_t> g_phasm_hook_dual_fires_total{0};
static std::atomic<uint64_t> g_phasm_hook_dual_bail_level_a_zero{0};
static std::atomic<uint64_t> g_phasm_hook_dual_bail_level_mismatch{0};
static std::atomic<uint64_t> g_phasm_hook_dual_applied{0};

// Single-write helper (HOOK-A/B/E for intra) gets its own counters.
// HOOK-E fires for I_4x4 intra Luma — and may be the path producing the
// residual missed-flip divergences if the MB's winning mode was intra
// rather than inter in a P-frame.
static std::atomic<uint64_t> g_phasm_hook_single_fires_total{0};
static std::atomic<uint64_t> g_phasm_hook_single_bail_level_zero{0};
static std::atomic<uint64_t> g_phasm_hook_single_applied{0};

// =====================================================================
// Phase A.5 Stage 0+ encoder-side helpers.
//
// These read the global callback state through the accessor functions
// declared in wels_stego_internal.h (defined in libcommon's
// wels_stego_common.cpp). The accessors are extern "C" with no
// namespace, so the linker resolves them across libcommon ↔ libencoder.
//
// Hot-path overhead per hook fire: 1 accessor call (cross-TU function,
// no inlining without LTO) + 1 nullptr check. The accessor result is
// cached in a local variable to avoid repeated calls within a single
// helper invocation.
// =====================================================================

namespace {

// Translate a sign-bit override into a flipped level.
int16_t apply_sign_override(int16_t level, int new_sign_bit) {
  int16_t abs_level = (level < 0) ? (int16_t)-level : level;
  return new_sign_bit ? (int16_t)-abs_level : abs_level;
}

// Translate a suffix-LSB override into a level with the new LSB.
//
// #505 fix 2026-05-16: at the threshold (|mag|=16), force the mutation
// to go UP to 17 rather than DOWN to 15. The phasm walker enrolls
// SuffixLsb cover positions only when `|coeff| >= 16` (see
// `core/src/codec/h264/stego/inject.rs::COEFF_SUFFIX_LSB_THRESHOLD`),
// so dropping below 16 would silently remove the position from the
// walker's cover vector — shifting the combined-cover layout by 1
// and breaking STC syndrome extraction. Mirrors the walker's
// `flipped_magnitude(abs, threshold)` boundary-handling.
//
// The bit formula `(mag - 15) & 1` is equivalent to the walker's
// `((mag & 1) ^ 1)` for all mag, so cover-bit observation stays
// consistent across the boundary. Only the mutation direction at
// mag=16 needs the special case.
int16_t apply_suffix_lsb_coeff(int16_t level, int new_lsb_bit) {
  int16_t sign  = (level < 0) ? (int16_t)-1 : (int16_t)1;
  int16_t mag   = (level < 0) ? (int16_t)-level : level;
  int      cur_lsb = (mag - 15) & 1;
  if (cur_lsb == new_lsb_bit) return level;
  int16_t new_mag;
  if (mag == 16) {
    new_mag = (int16_t)(mag + 1);
  } else {
    new_mag = (cur_lsb == 0) ? (int16_t)(mag + 1) : (int16_t)(mag - 1);
  }
  return (int16_t)(sign * new_mag);
}

// Dispatch a single hook call. Returns the callback's return value, or
// -1 if no callback registered. Sets pos->domain before calling.
int32_t dispatch_hook(PhasmStegoPos* pos, PhasmStegoDomain domain,
                      int32_t original_bit) {
  PhasmStegoEncPreEmitFn cb = PhasmStegoGetEncPreEmit();
  if (cb == nullptr) return -1;
  pos->domain = (uint8_t)domain;
  return cb(pos, original_bit, PhasmStegoGetUserData());
}

// Apply coefficient sign + suffix-LSB hooks to a single non-zero level.
int16_t apply_coeff_hooks_to_level(PhasmStegoPos* pos,
                                   uint8_t sub_block,
                                   uint8_t coeff_idx_scanned,
                                   uint8_t block_cat,
                                   int16_t level) {
  pos->sub_block    = sub_block;
  pos->coeff_idx    = coeff_idx_scanned;
  pos->block_cat    = block_cat;
  pos->ref_idx      = 0xff;
  pos->mv_component = 0xff;
  pos->_reserved    = 0;

  int32_t orig_sign = (level < 0) ? 1 : 0;
  int32_t override_sign = dispatch_hook(pos, PHASM_DOMAIN_COEFF_SIGN, orig_sign);
  if (override_sign == 0 || override_sign == 1) {
    if (override_sign != orig_sign) {
      int16_t new_level = apply_sign_override(level, override_sign);
      if (new_level != 0) {
        level = new_level;
      }
    }
  }

  int16_t abs_level = (level < 0) ? (int16_t)-level : level;
  // #505 fix 2026-05-16: threshold tightened from 15 to 16 to match the
  // phasm walker's COEFF_SUFFIX_LSB_THRESHOLD = 16 in
  // `core/src/codec/h264/stego/inject.rs`. Walker doesn't enroll
  // cover positions at |coeff|=15 (the EG0(0) terminator-bin case),
  // so firing the hook there created a divergence: fork would mutate
  // |coeff|=16 → 15, position would vanish from walker's cover, cover
  // layout shifts by 1, STC syndrome extraction breaks. Full analysis:
  // `memory/h264_chroma_csl_cascade_gap_504.md`.
  if (abs_level >= 16) {
    int32_t orig_lsb = (abs_level - 15) & 1;
    int32_t override_lsb = dispatch_hook(pos, PHASM_DOMAIN_COEFF_SUFFIX_LSB, orig_lsb);
    if (override_lsb == 0 || override_lsb == 1) {
      if (override_lsb != orig_lsb) {
        int16_t new_level = apply_suffix_lsb_coeff(level, override_lsb);
        if (new_level != 0) {
          level = new_level;
        }
      }
    }
  }
  return level;
}

int16_t apply_mvd_sign_override(int16_t mv_component, int16_t mvp_component) {
  return (int16_t)(2 * (int32_t)mvp_component - (int32_t)mv_component);
}

int16_t apply_mvd_suffix_lsb(int16_t mv_component, int16_t mvp_component,
                             int new_lsb_bit) {
  int32_t mvd = (int32_t)mv_component - (int32_t)mvp_component;
  int32_t sign = (mvd < 0) ? -1 : 1;
  int32_t mag  = (mvd < 0) ? -mvd : mvd;
  int     cur_lsb = (mag - 9) & 1;
  if (cur_lsb == new_lsb_bit) return mv_component;
  int32_t new_mag = (cur_lsb == 0) ? (mag + 1) : (mag - 1);
  int32_t new_mvd = sign * new_mag;
  return (int16_t)((int32_t)mvp_component + new_mvd);
}

}  // namespace

extern "C" {

int phasm_apply_coeff_hooks(PhasmStegoPos* pos_template,
                            uint8_t sub_block,
                            uint8_t coeff_idx_scanned,
                            uint8_t block_cat,
                            int16_t* level) {
  if (level == nullptr) return 0;
  if (PhasmStegoGetEncPreEmit() == nullptr) return 0;

  g_phasm_hook_single_fires_total.fetch_add(1, std::memory_order_relaxed);
  if (*level == 0) {
    g_phasm_hook_single_bail_level_zero.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  int16_t old_level = *level;
  *level = apply_coeff_hooks_to_level(pos_template, sub_block,
                                      coeff_idx_scanned, block_cat,
                                      old_level);
  if (*level != old_level) {
    g_phasm_hook_single_applied.fetch_add(1, std::memory_order_relaxed);
    phasm_inc_slice_override_count();  // C.9.2 (#450)
    return 1;
  }
  return 0;
}

int phasm_apply_coeff_hooks_dual(PhasmStegoPos* pos_template,
                                 uint8_t sub_block,
                                 uint8_t coeff_idx_scanned,
                                 uint8_t block_cat,
                                 int16_t* level_a,
                                 int16_t* level_b) {
  if (level_a == nullptr || level_b == nullptr) return 0;
  if (PhasmStegoGetEncPreEmit() == nullptr) return 0;

  // C.8.13(b) #455 — count total dual-write fires that pass the
  // null + callback-registered gates so the bail rates below are
  // meaningful denominators.
  g_phasm_hook_dual_fires_total.fetch_add(1, std::memory_order_relaxed);

  if (*level_a == 0) {
    g_phasm_hook_dual_bail_level_a_zero.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  if (*level_a != *level_b) {
    g_phasm_hook_dual_bail_level_mismatch.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  int16_t old_level = *level_a;
  int16_t new_level = apply_coeff_hooks_to_level(pos_template, sub_block,
                                                  coeff_idx_scanned, block_cat,
                                                  old_level);
  if (new_level != old_level) {
    *level_a = new_level;
    *level_b = new_level;
    g_phasm_hook_dual_applied.fetch_add(1, std::memory_order_relaxed);
    phasm_inc_slice_override_count();  // C.9.2 (#450)
    return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------
// Phase C.8.13(b) (#455) — debug counters for dual-write hook narrowing.
// ---------------------------------------------------------------------

uint64_t phasm_get_hook_dual_fires_total(void) {
  return g_phasm_hook_dual_fires_total.load(std::memory_order_relaxed);
}

uint64_t phasm_get_hook_dual_bail_level_a_zero(void) {
  return g_phasm_hook_dual_bail_level_a_zero.load(std::memory_order_relaxed);
}

uint64_t phasm_get_hook_dual_bail_level_mismatch(void) {
  return g_phasm_hook_dual_bail_level_mismatch.load(std::memory_order_relaxed);
}

uint64_t phasm_get_hook_dual_applied(void) {
  return g_phasm_hook_dual_applied.load(std::memory_order_relaxed);
}

void phasm_reset_hook_dual_counters(void) {
  g_phasm_hook_dual_fires_total.store(0, std::memory_order_relaxed);
  g_phasm_hook_dual_bail_level_a_zero.store(0, std::memory_order_relaxed);
  g_phasm_hook_dual_bail_level_mismatch.store(0, std::memory_order_relaxed);
  g_phasm_hook_dual_applied.store(0, std::memory_order_relaxed);
  // Reset the single-write counters in the same call — callers use one
  // function before each measured encode.
  g_phasm_hook_single_fires_total.store(0, std::memory_order_relaxed);
  g_phasm_hook_single_bail_level_zero.store(0, std::memory_order_relaxed);
  g_phasm_hook_single_applied.store(0, std::memory_order_relaxed);
}

uint64_t phasm_get_hook_single_fires_total(void) {
  return g_phasm_hook_single_fires_total.load(std::memory_order_relaxed);
}

uint64_t phasm_get_hook_single_bail_level_zero(void) {
  return g_phasm_hook_single_bail_level_zero.load(std::memory_order_relaxed);
}

uint64_t phasm_get_hook_single_applied(void) {
  return g_phasm_hook_single_applied.load(std::memory_order_relaxed);
}

int phasm_mvd_would_collide_with_pskip(int16_t mv_x, int16_t mv_y,
                                       int16_t pred_skip_mv_x,
                                       int16_t pred_skip_mv_y) {
  return (mv_x == pred_skip_mv_x && mv_y == pred_skip_mv_y) ? 1 : 0;
}

void phasm_emit_md_cost(uint16_t mb_x, uint16_t mb_y,
                        uint32_t internal_mb_type, uint8_t cbp) {
  PhasmStegoMdCostFn cb = PhasmStegoGetMdCostCapture();
  if (cb == nullptr) return;

  uint8_t klass;
  if (internal_mb_type & 0x100u /* MB_TYPE_SKIP */) {
    klass = PHASM_MB_TYPE_SKIP;
  } else if (internal_mb_type & 0x02u /* MB_TYPE_INTRA16x16 */) {
    klass = PHASM_MB_TYPE_I_16x16;
  } else if (internal_mb_type & 0x01u /* MB_TYPE_INTRA4x4 */) {
    klass = PHASM_MB_TYPE_I_4x4;
  } else if (internal_mb_type & 0x04u /* MB_TYPE_INTRA8x8 */) {
    klass = PHASM_MB_TYPE_I_8x8;
  } else if (internal_mb_type & 0x000000F8u /* INTER 16x16|16x8|8x16|8x8|8x8_REF0 */) {
    klass = PHASM_MB_TYPE_INTER;
  } else {
    klass = PHASM_MB_TYPE_OTHER;
  }

  PhasmStegoMdCost cost;
  cost.frame_num   = PhasmStegoGetFrameNum();
  cost.mb_x        = mb_x;
  cost.mb_y        = mb_y;
  cost.mb_type     = klass;
  cost.cbp         = cbp;
  cost._reserved   = 0;
  cost.capacity[0] = 0;
  cost.capacity[1] = 0;
  cost.capacity[2] = 0;
  cost.capacity[3] = 0;
  cb(&cost, PhasmStegoGetUserData());
}

void phasm_emit_mb_decision(const PhasmStegoMbDecision* decision) {
  if (decision == nullptr) return;
  if (PhasmStegoGetPassMode() != PHASM_PASS_CAPTURE) return;
  PhasmStegoCaptureMbDecisionFn cb = PhasmStegoGetCaptureMbDecision();
  if (cb == nullptr) return;
  cb(decision, PhasmStegoGetUserData());
}

int phasm_fetch_replay_decision(uint16_t mb_x, uint16_t mb_y,
                                PhasmStegoMbDecision* out_decision) {
  if (out_decision == nullptr) return 0;
  if (PhasmStegoGetPassMode() != PHASM_PASS_REPLAY) return 0;
  PhasmStegoReplayMbDecisionFn cb = PhasmStegoGetReplayMbDecision();
  if (cb == nullptr) return 0;
  return cb(PhasmStegoGetFrameNum(), mb_x, mb_y, out_decision,
            PhasmStegoGetUserData());
}

int phasm_apply_mvd_hooks(const PhasmMvHookCtx* ctx) {
  if (ctx == nullptr || ctx->mv_x_qpel == nullptr || ctx->mv_y_qpel == nullptr) {
    return 0;
  }
  PhasmStegoEncPreEmitFn cb = PhasmStegoGetEncPreEmit();
  if (cb == nullptr) return 0;
  void* user_data = PhasmStegoGetUserData();

  PhasmStegoPos pos;
  pos.frame_num     = ctx->frame_num;
  pos.mb_x          = ctx->mb_x;
  pos.mb_y          = ctx->mb_y;
  pos.partition_idx = ctx->partition_idx;
  pos.sub_block     = 0xff;
  pos.coeff_idx     = 0xff;
  pos.block_cat     = 0xff;
  pos.ref_idx       = ctx->ref_idx;
  pos._reserved     = 0;

  int16_t mv_in[2]  = { *(ctx->mv_x_qpel), *(ctx->mv_y_qpel) };
  int16_t mv_out[2] = { mv_in[0], mv_in[1] };
  int16_t mvp[2]    = { ctx->mvp_x_qpel, ctx->mvp_y_qpel };

  for (int comp = 0; comp < 2; ++comp) {
    int16_t mvd_in = (int16_t)((int32_t)mv_in[comp] - (int32_t)mvp[comp]);
    if (mvd_in == 0) continue;

    pos.mv_component = (uint8_t)comp;

    int32_t orig_sign = (mvd_in < 0) ? 1 : 0;
    pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SIGN;
    int32_t ovr_sign = cb(&pos, orig_sign, user_data);
    if ((ovr_sign == 0 || ovr_sign == 1) && ovr_sign != orig_sign) {
      mv_out[comp] = apply_mvd_sign_override(mv_in[comp], mvp[comp]);
    }

    int16_t cur_mvd = (int16_t)((int32_t)mv_out[comp] - (int32_t)mvp[comp]);
    int16_t abs_mvd = (cur_mvd < 0) ? (int16_t)-cur_mvd : cur_mvd;
    if (abs_mvd >= 9) {
      int32_t orig_lsb = (abs_mvd - 9) & 1;
      pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
      int32_t ovr_lsb = cb(&pos, orig_lsb, user_data);
      if ((ovr_lsb == 0 || ovr_lsb == 1) && ovr_lsb != orig_lsb) {
        mv_out[comp] = apply_mvd_suffix_lsb(mv_out[comp], mvp[comp], ovr_lsb);
      }
    }
  }

  const int16_t new_x = mv_out[0];
  const int16_t new_y = mv_out[1];

  if (new_x == mv_in[0] && new_y == mv_in[1]) {
    return 0;
  }

  if (ctx->check_pskip_collision &&
      phasm_mvd_would_collide_with_pskip(new_x, new_y,
                                          ctx->pred_skip_mv_x,
                                          ctx->pred_skip_mv_y)) {
    return 0;
  }

  *(ctx->mv_x_qpel) = new_x;
  *(ctx->mv_y_qpel) = new_y;

  if (ctx->mvList_x_qpel != nullptr && ctx->mvList_y_qpel != nullptr) {
    *(ctx->mvList_x_qpel) = new_x;
    *(ctx->mvList_y_qpel) = new_y;
  }

  phasm_inc_slice_override_count();  // C.9.2 (#450)
  return 1;
}

/* Phase 4 (#538) Step 4.5.a — Bypass-bin scratch table.
 *
 * Per-MB dense storage for stego bin overrides. Populated by the
 * mutating-hook successors (`phasm_set_bypass_override`, wired in
 * later 4.5 sub-steps) and read at CABAC emit time by
 * `phasm_apply_bypass_bin_override` (Phase 4.2-4.4 hook sites).
 *
 * Encoding: each slot is one byte.
 *   0 = no override (emit bin = orig_bin)
 *   1 = override bin to 0
 *   2 = override bin to 1
 *
 * Default zero-init means "no override" without any explicit reset
 * at startup — the table is safe to read from the moment it exists.
 * `phasm_reset_bypass_overrides` is intended to be called at MB
 * boundary by callers wired in 4.5.b+; until then the table is never
 * populated, so contents stay zero and the bypass-bin override hook
 * is a pure orig_bin passthrough (byte-identical to pre-4.5).
 *
 * Sizing:
 *   - coeff_* : [5 block_cats][16 sub_blocks][16 coeff_idx] = 1280 bytes / domain
 *   - mvd_*   : [16 partitions][2 components] = 32 bytes / domain
 *   - total   : ~2624 bytes static. Per-MB single-threaded scope
 *     (matches the rest of the phasm-stego TU; #339 tracks
 *     multi-thread revisit).
 *
 * Indexing reconciliation (Phase 4.5.b+ TODO): emit-side
 * `iNonZeroIdx` in svc_set_mb_syn_cabac.cpp is the *compressed* index
 * into the non-zero-coefficient array `iLevel[]`, NOT the AC scan
 * position. The populate-side `coeff_idx_scanned` passed to
 * `phasm_apply_coeff_hooks*` is sometimes raster (HOOK-B) and
 * sometimes scan-position-equivalent (HOOK-A DC, where coeff_idx is
 * always 0). The 4.5.b migration step needs to converge both sides
 * on ONE canonical scheme. Until then the dense table is allocated
 * but no callers populate it. */

#define PHASM_SCRATCH_BLOCK_CAT_COUNT 5
#define PHASM_SCRATCH_SUB_BLOCK_MAX   16
#define PHASM_SCRATCH_COEFF_IDX_MAX   16
#define PHASM_SCRATCH_PARTITION_MAX   16
#define PHASM_SCRATCH_MV_COMP_MAX     2

struct PhasmBypassOverrides {
  uint8_t coeff_sign      [PHASM_SCRATCH_BLOCK_CAT_COUNT]
                          [PHASM_SCRATCH_SUB_BLOCK_MAX]
                          [PHASM_SCRATCH_COEFF_IDX_MAX];
  uint8_t coeff_suffix_lsb[PHASM_SCRATCH_BLOCK_CAT_COUNT]
                          [PHASM_SCRATCH_SUB_BLOCK_MAX]
                          [PHASM_SCRATCH_COEFF_IDX_MAX];
  uint8_t mvd_sign        [PHASM_SCRATCH_PARTITION_MAX]
                          [PHASM_SCRATCH_MV_COMP_MAX];
  uint8_t mvd_suffix_lsb  [PHASM_SCRATCH_PARTITION_MAX]
                          [PHASM_SCRATCH_MV_COMP_MAX];
};

static PhasmBypassOverrides g_phasm_bypass_overrides;

/* Internal helper: validate slot indices for the given domain and
 * return a pointer to the slot byte, or nullptr if any index is out
 * of range. Used by both the populate side (`phasm_set_bypass_override`)
 * and the read side (`phasm_apply_bypass_bin_override`). */
static uint8_t* phasm_scratch_slot(uint8_t domain,
                                    const PhasmStegoPos* pos) {
  if (pos == nullptr) return nullptr;
  switch (domain) {
    case PHASM_DOMAIN_COEFF_SIGN:
    case PHASM_DOMAIN_COEFF_SUFFIX_LSB: {
      if (pos->block_cat >= PHASM_SCRATCH_BLOCK_CAT_COUNT) return nullptr;
      if (pos->sub_block >= PHASM_SCRATCH_SUB_BLOCK_MAX)   return nullptr;
      if (pos->coeff_idx >= PHASM_SCRATCH_COEFF_IDX_MAX)   return nullptr;
      if (domain == PHASM_DOMAIN_COEFF_SIGN) {
        return &g_phasm_bypass_overrides
                  .coeff_sign[pos->block_cat][pos->sub_block][pos->coeff_idx];
      } else {
        return &g_phasm_bypass_overrides
                  .coeff_suffix_lsb[pos->block_cat][pos->sub_block][pos->coeff_idx];
      }
    }
    case PHASM_DOMAIN_MVD_SIGN:
    case PHASM_DOMAIN_MVD_SUFFIX_LSB: {
      if (pos->partition_idx >= PHASM_SCRATCH_PARTITION_MAX) return nullptr;
      if (pos->mv_component >= PHASM_SCRATCH_MV_COMP_MAX)    return nullptr;
      if (domain == PHASM_DOMAIN_MVD_SIGN) {
        return &g_phasm_bypass_overrides
                  .mvd_sign[pos->partition_idx][pos->mv_component];
      } else {
        return &g_phasm_bypass_overrides
                  .mvd_suffix_lsb[pos->partition_idx][pos->mv_component];
      }
    }
    default:
      return nullptr;
  }
}

void phasm_reset_bypass_overrides(void) {
  /* Zero-init = "no override" across the whole table. memset is
   * cheap (~2.6 KB, fits in one cache line per array element row). */
  std::memset(&g_phasm_bypass_overrides, 0, sizeof(g_phasm_bypass_overrides));
}

/* Populate a single slot. Caller passes the OVERRIDE BIN (0 or 1);
 * this function stores it as 1/2 in the scratch byte (0 reserved for
 * "no override"). Out-of-range domains, positions, or override bins
 * are silently no-op'd — populates that can't fit the dense table
 * just stay un-overridden (defensive, matches the pre-4.5 hook
 * helpers' behaviour of silently refusing illegal mutations). */
void phasm_set_bypass_override(uint8_t domain,
                                const PhasmStegoPos* pos,
                                int override_bin) {
  if (override_bin != 0 && override_bin != 1) return;
  uint8_t* slot = phasm_scratch_slot(domain, pos);
  if (slot == nullptr) return;
  *slot = (uint8_t)(override_bin + 1);  /* 0→1, 1→2 */
}

/* Phase 4.5.a wire-up: read scratch at emit time. */
int phasm_apply_bypass_bin_override (uint8_t domain,
                                      const PhasmStegoPos* pos,
                                      int orig_bin) {
  uint8_t* slot = phasm_scratch_slot(domain, pos);
  if (slot == nullptr) return orig_bin;
  const uint8_t v = *slot;
  if (v == 0) return orig_bin;
  return (int)(v - 1);  /* 1→0, 2→1 */
}

}  // extern "C"
