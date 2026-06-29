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

/* Phase 4.5.b — wire-only mode gate (definition; full doc on the
 * extern "C" setter/getter near the end of this file). Lives here
 * so `phasm_apply_mvd_hooks` (defined below) can read it without a
 * forward declaration dance. */
static int g_phasm_use_wire_only_overrides = 0;

/* Phase 4.5.e — automatic per-MB scratch reset.
 *
 * Scratch slots are keyed by (block_cat, sub_block, coeff_idx) for
 * coeff domains and (partition_idx, mv_component) for MVD domains.
 * NEITHER scheme includes mb_x/mb_y, so without a per-MB reset,
 * stale slots from the previous MB would leak into the current MB
 * at positions the current MB doesn't itself populate.
 *
 * Approach: at the start of every populate-side hook entry
 * (apply_coeff_hooks_to_level + phasm_apply_mvd_hooks), check
 * whether (frame_num, mb_x, mb_y) differs from the last seen. If
 * yes, clear scratch via `phasm_reset_bypass_overrides`. First
 * populate-hook fire of each MB triggers a reset; subsequent fires
 * within the same MB are no-ops.
 *
 * Gated on `g_phasm_use_wire_only_overrides` so flag OFF (default)
 * path stays cycle-equivalent to pre-4.5.e.
 *
 * Sentinel initial values (`0xFFFFFFFF` / `0xFFFF`) ensure the very
 * first populate-hook fire of every encoder lifetime triggers a
 * reset — startup state always starts clean. */
/* B-full.2b (#895): the (frame_num, mb_x, mb_y) sentinels + the bypass
 * scratch they guard now live per-encoder on PhasmStegoState
 * (pCtx->pPhasmStego), not in process-globals — the prerequisite for
 * thread-safe concurrent stego encode (parallel-GOP, doc §12). The
 * wire_only gate (read below) stays a process-global until B-full.5.
 * phasm_maybe_reset_for_mb is forward-declared here (it needs the
 * PhasmStegoState definition, which appears further down) and defined
 * just after that struct. */
struct PhasmStegoState;
static void phasm_maybe_reset_for_mb(void* stego_v,
                                     uint32_t frame_num,
                                     uint16_t mb_x,
                                     uint16_t mb_y);

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

/* #538 Phase 4.5.d.3 — inverse 4x4 zigzag (raster → scan). Inverse
 * of g_phasm_zigzag_scan_4x4 in svc_set_mb_syn_cabac.cpp. Computed
 * once from the table:
 *   g_zigzag[scan] = raster
 *     {0,1,4,8,5,2,3,6,9,12,13,10,7,11,14,15}
 *   ↓
 *   inv_zigzag[raster] = scan
 *     {0,1,5,6,2,4,7,12,3,8,11,13,9,10,14,15}
 *
 * Used in the wire-only branch of apply_coeff_hooks_to_level to
 * convert populate-side RASTER coeff_idx (0..15 within a 4x4 block)
 * to the canonical SCAN position the emit-side scratch lookup
 * keys on. For AC blocks (LUMA_AC, CHROMA_AC, where iStartIdx=1)
 * the AC scan position is `inv_zigzag[raster] - 1` (full scan
 * position minus 1, since AC scan 0 = full scan 1 = raster 1).
 * For full blocks (LUMA_4x4) it's `inv_zigzag[raster]` directly.
 *
 * The Rust callback (dispatch_hook) is ALWAYS invoked with the
 * unmodified pos (raster coeff_idx) — only the scratch-table key
 * passed to phasm_set_bypass_override is scan-converted. This
 * preserves the existing callback contract (raster) while making
 * the scratch lookup canonical (scan) so the emit-side hook
 * (which has scan via iLevelScanPos) finds the slot. */
static const uint8_t inv_zigzag_full_4x4[16] = {
  0, 1, 5, 6, 2, 4, 7, 12, 3, 8, 11, 13, 9, 10, 14, 15
};

// Apply coefficient sign + suffix-LSB hooks to a single non-zero level.
//
// Phase 4.5.c branch: when `g_phasm_use_wire_only_overrides` is ON,
// the function populates `phasm_set_bypass_override` instead of
// mutating *level. Original level is returned unchanged so the
// encoder's stored coefficient stays clean. Decoder reads the
// flipped wire bin and applies the same flip in its parser state,
// regenerating the stego'd pixel value during decode. With flag OFF
// (default), behaviour matches pre-4.5 — mutate-then-return.
//
// Indexing caveat (#538 4.5.b TODO): in wire-only mode, the
// populate-side slot key is (block_cat, sub_block, coeff_idx_scanned)
// straight off the caller. For HOOK-A (LUMA_DC) coeff_idx_scanned is
// always 0, so the slot matches the emit-side key cleanly. For
// HOOK-B / -E / -F / -G the populate-side `coeff_idx_scanned` is
// RASTER index 0..15 while the emit-side bypass-bin hook keys by
// `iNonZeroIdx` (compressed index into the scan-ordered iLevel[]
// array). Until Phase 4.5.d wires the raster→scan translation, the
// wire-only override for non-DC coeff sites will silently no-op
// (slot populated at one address, emit reads from another). This is
// safe — never wrong — but means HOOK-B/E/F/G overrides won't fire
// on the wire until the reconciliation lands. Tracked at the design
// memo. Phase 4.6 forged-flip test must use HOOK-A positions only
// until 4.5.d ships.
int16_t apply_coeff_hooks_to_level(PhasmStegoPos* pos,
                                   uint8_t sub_block,
                                   uint8_t coeff_idx_scanned,
                                   uint8_t block_cat,
                                   int16_t level,
                                   void* stego) {
  pos->sub_block    = sub_block;
  pos->coeff_idx    = coeff_idx_scanned;
  pos->block_cat    = block_cat;
  pos->ref_idx      = 0xff;
  pos->mv_component = 0xff;
  pos->_reserved    = 0;

  const int wire_only = g_phasm_use_wire_only_overrides;
  /* Phase 4.5.e — clear stale scratch from previous MB before this
   * MB's first populate-hook fires. No-op on subsequent fires
   * within the same MB; pure no-op under flag OFF. B-full.2b: scratch
   * + sentinels are per-encoder (stego); NULL ⇒ no-op. */
  phasm_maybe_reset_for_mb(stego, pos->frame_num, pos->mb_x, pos->mb_y);

  /* Phase 4.5.d.3 + #538.4.7 chroma fix — per-block_cat key derivation
   * for the scratch-table slot. The Rust PositionKey contract is
   * preserved on `pos` (sent to dispatch_hook unmodified); a separate
   * `scratch_*` local computes the slot key, then is applied to a
   * scratch_pos copy of pos right before phasm_set_bypass_override.
   *
   * Callers pass `coeff_idx_scanned` with the convention DIFFERING by
   * block_cat (matches what the Rust PositionKey expects):
   *
   *   0 LUMA_DC    : coeff_idx = 0 (unused); sub_block = raster 0..15
   *   1 LUMA_AC    : coeff_idx = RASTER 1..15; sub_block = raster 0..15
   *   2 LUMA_4x4   : coeff_idx = RASTER 0..15; sub_block = raster 0..15
   *   3 CHROMA_DC  : coeff_idx = HADAMARD 0..3; sub_block = 0 (unused)
   *                  partition_idx = plane (0=Cb, 1=Cr)
   *   4 CHROMA_AC  : coeff_idx = SCAN 0..14; sub_block = block-within-plane 0..3
   *                  partition_idx = plane (0=Cb, 1=Cr)
   *
   * Emit-side keys it derives:
   *
   *   0 LUMA_DC    : sb = raster (via g_zigzag),       ci = 0
   *   1 LUMA_AC    : sb = raster (via cache→raster),   ci = scan 0..14
   *   2 LUMA_4x4   : sb = raster (via cache→raster),   ci = scan 0..15
   *   3 CHROMA_DC  : sb = Hadamard idx + plane*4,      ci = 0
   *   4 CHROMA_AC  : sb = raster + plane*4,            ci = scan 0..14
   *
   * Scratch slot keys are made to match emit:
   *   - LUMA_AC/4x4: coeff_idx is raster, convert via inv_zigzag.
   *   - CHROMA_AC:   coeff_idx is ALREADY scan (no conversion);
   *                  sub_block += plane*4 for Cb↔Cr disambiguation.
   *   - CHROMA_DC:   sub_block ↔ coeff_idx swap (Hadamard idx moves
   *                  from coeff_idx into sub_block); plane*4 bias.
   */
  uint8_t scratch_sub_block       = sub_block;
  uint8_t scratch_coeff_idx       = coeff_idx_scanned;
  if (wire_only) {
    const uint8_t chroma_plane_off =
        (block_cat == 3 || block_cat == 4) && pos->partition_idx < 2
            ? (uint8_t)(pos->partition_idx * 4)
            : (uint8_t)0;
    switch (block_cat) {
      case 1: /* LUMA_AC: coeff_idx is RASTER 1..15 → scan 0..14. */
        if (coeff_idx_scanned >= 1 && coeff_idx_scanned < 16) {
          scratch_coeff_idx = (uint8_t)(inv_zigzag_full_4x4[coeff_idx_scanned] - 1);
        }
        break;
      case 2: /* LUMA_4x4: coeff_idx is RASTER 0..15 → scan 0..15. */
        if (coeff_idx_scanned < 16) {
          scratch_coeff_idx = inv_zigzag_full_4x4[coeff_idx_scanned];
        }
        break;
      case 4: /* CHROMA_AC: coeff_idx is already SCAN. Add plane bias. */
        scratch_sub_block = (uint8_t)(sub_block + chroma_plane_off);
        /* scratch_coeff_idx stays = coeff_idx_scanned (scan). */
        break;
      case 3: /* CHROMA_DC: swap (sb=0, ci=had) → (sb=had+plane*4, ci=0). */
        scratch_sub_block = (uint8_t)(coeff_idx_scanned + chroma_plane_off);
        scratch_coeff_idx = 0;
        break;
      case 0: /* LUMA_DC: sub_block=raster (caller), coeff_idx=0 already. */
      default:
        break;
    }
  }

  int32_t orig_sign = (level < 0) ? 1 : 0;
  int32_t override_sign = dispatch_hook(pos, PHASM_DOMAIN_COEFF_SIGN, orig_sign);
  if (override_sign == 0 || override_sign == 1) {
    if (override_sign != orig_sign) {
      if (wire_only) {
        /* Populate scratch with the per-block_cat scratch keys derived
         * above (raster→scan / Cb↔Cr plane bias / CHROMA_DC sb↔ci swap).
         * Pos passed to dispatch_hook keeps the Rust-callback contract
         * unchanged — only the scratch slot key is canonicalised here. */
        PhasmStegoPos scratch_pos = *pos;
        scratch_pos.sub_block = scratch_sub_block;
        scratch_pos.coeff_idx = scratch_coeff_idx;
        phasm_set_bypass_override((uint8_t)PHASM_DOMAIN_COEFF_SIGN, &scratch_pos, override_sign, stego);
      } else {
        int16_t new_level = apply_sign_override(level, override_sign);
        if (new_level != 0) {
          level = new_level;
        }
      }
    }
  }

  /* For the suffix-LSB magnitude check: in wire-only mode the
   * encoder's *level stays at the original value, so the wire's
   * "is there a suffix?" branch reads ORIGINAL |level|. The
   * encoder's CABAC emit decides "if (|coeff|<15) emit decision
   * 0 else emit UEG suffix" based on the unmodified iLevel[] entry,
   * so the suffix-LSB override only fires when the original |level|
   * is already in the |>=16| range. Mutation mode reads the
   * post-sign-override level, but for sign flips that just swap
   * positive↔negative the magnitude is unchanged anyway. */
  int16_t abs_level_for_check = level;
  if (wire_only) {
    /* Re-derive absolute value from the input parameter (`level`
     * here still holds the input value because we never mutated it
     * above). */
    abs_level_for_check = (level < 0) ? (int16_t)-level : level;
  } else {
    abs_level_for_check = (level < 0) ? (int16_t)-level : level;
  }

  // #505 fix 2026-05-16: threshold tightened from 15 to 16 to match the
  // phasm walker's COEFF_SUFFIX_LSB_THRESHOLD = 16 in
  // `core/src/codec/h264/stego/inject.rs`. Walker doesn't enroll
  // cover positions at |coeff|=15 (the EG0(0) terminator-bin case),
  // so firing the hook there created a divergence: fork would mutate
  // |coeff|=16 → 15, position would vanish from walker's cover, cover
  // layout shifts by 1, STC syndrome extraction breaks. Full analysis:
  // `memory/h264_chroma_csl_cascade_gap_504.md`.
  if (abs_level_for_check >= 16) {
    int32_t orig_lsb = (abs_level_for_check - 15) & 1;
    int32_t override_lsb = dispatch_hook(pos, PHASM_DOMAIN_COEFF_SUFFIX_LSB, orig_lsb);
    if (override_lsb == 0 || override_lsb == 1) {
      if (override_lsb != orig_lsb) {
        if (wire_only) {
          /* Same scratch key as the sign branch above.
           *
           * #533.4.9 ROOT CAUSE FIX (2026-05-18): walker_bit ↔ wire LSB
           * inversion for CSL. The walker computes its cover bit as
           * `(abs & 1) ^ 1` (inject.rs:357 `suffix_lsb_bit_for_magnitude`)
           * and flips |coeff| magnitude by ±1 to override
           * (`apply_coeff_suffix_lsb_overrides` at inject.rs:398). The
           * encoder's UEG0 emit, however, writes the actual suffix LSB
           * bin which equals `|coeff| & 1` (= walker_bit XOR 1) — wire
           * LSB and walker_bit are inverted for CSL.
           *
           * `orig_lsb = (|coeff|-15)&1` happens to equal walker_bit (both
           * reflect |coeff| parity the same way), so the dispatch_hook
           * comparison `override_lsb != orig_lsb` is in walker_bit
           * representation. The scratch slot, however, is read at emit
           * AS the wire LSB to write (via `phasm_apply_bypass_bin_override`
           * → `WelsCabacEncodeBypassOne` directly emits the byte as a
           * bypass bin). Writing the walker_bit verbatim corresponds to
           * a no-op flip on the wire (wire stays at orig |coeff|, walker
           * decodes the unchanged magnitude). XOR-1 converts walker_bit
           * → wire LSB so the emitted wire bit decodes to the planned
           * |coeff|±1, which is what the walker's cover allocation
           * assumes. Sign domain does not need this (walker bit ==
           * wire bin for sign). */
          PhasmStegoPos scratch_pos = *pos;
          scratch_pos.sub_block = scratch_sub_block;
          scratch_pos.coeff_idx = scratch_coeff_idx;
          phasm_set_bypass_override((uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB, &scratch_pos, override_lsb ^ 1, stego);
        } else {
          int16_t new_level = apply_suffix_lsb_coeff(level, override_lsb);
          if (new_level != 0) {
            level = new_level;
          }
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
                            int16_t* level,
                            void* stego) {
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
                                      old_level, stego);
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
                                 int16_t* level_b,
                                 void* stego) {
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
                                                  old_level, stego);
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

  /* Phase 4.5.e — clear stale scratch from previous MB. Pure no-op
   * under flag OFF. */
  phasm_maybe_reset_for_mb(ctx->stego, ctx->frame_num, ctx->mb_x, ctx->mb_y);

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

  /* Phase 4.5.b — branch on the wire-only flag. */
  const int wire_only = g_phasm_use_wire_only_overrides;
  int wire_only_any_override = 0;

  for (int comp = 0; comp < 2; ++comp) {
    int16_t mvd_in = (int16_t)((int32_t)mv_in[comp] - (int32_t)mvp[comp]);
    if (mvd_in == 0) continue;

    pos.mv_component = (uint8_t)comp;

    int32_t orig_sign = (mvd_in < 0) ? 1 : 0;
    pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SIGN;
    int32_t ovr_sign = cb(&pos, orig_sign, user_data);
    if ((ovr_sign == 0 || ovr_sign == 1) && ovr_sign != orig_sign) {
      if (wire_only) {
        /* Populate scratch — emit-side bypass-bin hook will flip
         * the wire bit. Encoder state stays unchanged. */
        phasm_set_bypass_override((uint8_t)PHASM_DOMAIN_MVD_SIGN, &pos, ovr_sign, ctx->stego);
        wire_only_any_override = 1;
      } else {
        mv_out[comp] = apply_mvd_sign_override(mv_in[comp], mvp[comp]);
      }
    }

    /* Suffix LSB path: in mutation mode, MVD magnitude check reads
     * mv_out (post-sign-override) so a sign-flipped MVD that now
     * has |MVD|>=9 picks up a suffix override. In wire-only mode,
     * the wire's prefix-vs-suffix split is decided from the ORIGINAL
     * MVD magnitude (encoder state unchanged), so the suffix bin
     * only exists when the original |MVD|>=9. Branch accordingly. */
    int16_t check_mvd = wire_only ? mvd_in
                                  : (int16_t)((int32_t)mv_out[comp] - (int32_t)mvp[comp]);
    int16_t abs_mvd = (check_mvd < 0) ? (int16_t)-check_mvd : check_mvd;
    if (abs_mvd >= 9) {
      int32_t orig_lsb = (abs_mvd - 9) & 1;
      pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
      int32_t ovr_lsb = cb(&pos, orig_lsb, user_data);
      if ((ovr_lsb == 0 || ovr_lsb == 1) && ovr_lsb != orig_lsb) {
        if (wire_only) {
          phasm_set_bypass_override((uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB, &pos, ovr_lsb, ctx->stego);
          wire_only_any_override = 1;
        } else {
          mv_out[comp] = apply_mvd_suffix_lsb(mv_out[comp], mvp[comp], ovr_lsb);
        }
      }
    }
  }

  /* Wire-only path: scratch populated, encoder state untouched.
   * Skip the MV-mutation tail (pskip-collision check is moot — we
   * didn't change the MV — and sMvList stays in sync with mv_in). */
  if (wire_only) {
    /* #549 Bug 3 fix (2026-05-19): always return 0 in wire_only=1
     * regardless of wire_only_any_override. Closed-loop walker test
     * `pass2_walker_sees_mvdsign_only_real_carplane_480p` confirmed:
     * 105 MvdSign overrides → +1817 CS positions in Pass 2 (cascade).
     * Returning 1 signals the caller (phasm_apply_h_partition_hook in
     * svc_base_layer_md.cpp) to do redundant MC via pMcLumaFunc, which
     * perturbs encoder state even though MV stayed clean. Slice override
     * counter increment is kept (C.9.2 deblock-skip optimization gate)
     * but the return value no longer triggers downstream side effects. */
    if (wire_only_any_override) {
      phasm_inc_slice_override_count();  // C.9.2 (#450) — gate kept
    }
    return 0;
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

/* B-full.2b (#895): the bypass-override scratch table moved off this
 * process-global into PhasmStegoState::bypass_overrides (per-encoder) —
 * so concurrent encoders (parallel-GOP, doc §12) don't collide. The
 * wire-only gate stays a file-scope global until B-full.5. */

/* Phase 4.5.b — wire-only mode gate setters/getter (extern "C"). The
 * static variable itself is defined at file scope earlier in this TU
 * so `phasm_apply_mvd_hooks` can read it without a forward declaration
 * dance. See doc on `g_phasm_use_wire_only_overrides` near the top. */
void phasm_set_use_wire_only_overrides(int enabled) {
  g_phasm_use_wire_only_overrides = (enabled != 0) ? 1 : 0;
}

int phasm_get_use_wire_only_overrides(void) {
  return g_phasm_use_wire_only_overrides;
}

// B-full.1 (#895): per-encoder stego state container. Defined here so it can
// hold PhasmBypassOverrides (file-local above) by value. This increment only
// allocates/frees it from WelsInitEncoderExt / FreeMemorySvc — nothing reads
// it yet, so the bitstream is byte-identical. B-full.2+ migrate the encoder
// statics (bypass scratch, last-MB sentinels, wire-only flag, then the
// libcommon-shared callbacks/frame_num/pass_mode) onto this struct so each
// encoder instance carries its own stego state.
struct PhasmStegoState {
  PhasmBypassOverrides bypass_overrides;
  uint32_t             last_mb_frame_num;
  uint16_t             last_mb_x;
  uint16_t             last_mb_y;
  int                  use_wire_only_overrides;
};

extern "C" void* phasm_stego_state_create(void) {
  return new PhasmStegoState();  // value-init zeroes the POD members
}

extern "C" void phasm_stego_state_destroy(void* p) {
  delete static_cast<PhasmStegoState*>(p);  // delete nullptr is a no-op
}

/* B-full.2b (#895) — per-MB scratch reset, now keyed off the per-encoder
 * PhasmStegoState (forward-declared at the top of this TU). NULL stego ⇒
 * no-op (non-phasm encode). Still gated on the process-global wire_only
 * flag, which migrates to per-instance in B-full.5. */
static void phasm_maybe_reset_for_mb(void* stego_v,
                                     uint32_t frame_num,
                                     uint16_t mb_x,
                                     uint16_t mb_y) {
  if (!g_phasm_use_wire_only_overrides) return;
  PhasmStegoState* st = static_cast<PhasmStegoState*>(stego_v);
  if (st == nullptr) return;
  if (frame_num != st->last_mb_frame_num ||
      mb_x      != st->last_mb_x ||
      mb_y      != st->last_mb_y) {
    phasm_reset_bypass_overrides(stego_v);
    st->last_mb_frame_num = frame_num;
    st->last_mb_x         = mb_x;
    st->last_mb_y         = mb_y;
  }
}

/* Internal helper: validate slot indices for the given domain and
 * return a pointer to the slot byte, or nullptr if any index is out
 * of range. Used by both the populate side (`phasm_set_bypass_override`)
 * and the read side (`phasm_apply_bypass_bin_override`). */
static uint8_t* phasm_scratch_slot(uint8_t domain,
                                    const PhasmStegoPos* pos,
                                    void* stego_v) {
  if (pos == nullptr) return nullptr;
  /* B-full.2b: the scratch table is per-encoder (PhasmStegoState).
   * NULL stego ⇒ no scratch (non-phasm encode) ⇒ no slot. */
  PhasmStegoState* st = static_cast<PhasmStegoState*>(stego_v);
  if (st == nullptr) return nullptr;
  PhasmBypassOverrides& ov = st->bypass_overrides;
  switch (domain) {
    case PHASM_DOMAIN_COEFF_SIGN:
    case PHASM_DOMAIN_COEFF_SUFFIX_LSB: {
      if (pos->block_cat >= PHASM_SCRATCH_BLOCK_CAT_COUNT) return nullptr;
      if (pos->sub_block >= PHASM_SCRATCH_SUB_BLOCK_MAX)   return nullptr;
      if (pos->coeff_idx >= PHASM_SCRATCH_COEFF_IDX_MAX)   return nullptr;
      if (domain == PHASM_DOMAIN_COEFF_SIGN) {
        return &ov.coeff_sign[pos->block_cat][pos->sub_block][pos->coeff_idx];
      } else {
        return &ov.coeff_suffix_lsb[pos->block_cat][pos->sub_block][pos->coeff_idx];
      }
    }
    case PHASM_DOMAIN_MVD_SIGN:
    case PHASM_DOMAIN_MVD_SUFFIX_LSB: {
      if (pos->partition_idx >= PHASM_SCRATCH_PARTITION_MAX) return nullptr;
      if (pos->mv_component >= PHASM_SCRATCH_MV_COMP_MAX)    return nullptr;
      if (domain == PHASM_DOMAIN_MVD_SIGN) {
        return &ov.mvd_sign[pos->partition_idx][pos->mv_component];
      } else {
        return &ov.mvd_suffix_lsb[pos->partition_idx][pos->mv_component];
      }
    }
    default:
      return nullptr;
  }
}

/* Phase 4.6 NEGATIVE-result diagnostic counters. Track writes /
 * reads / hits / resets on the bypass scratch to bisect why the
 * forged-flip test sees byte-identical bitstreams despite 16
 * dispatched flips. Removed once 4.6 closes positively. */
static std::atomic<uint64_t> g_phasm_diag_set_calls{0};
static std::atomic<uint64_t> g_phasm_diag_set_writes{0};
static std::atomic<uint64_t> g_phasm_diag_set_rejected_oob{0};
static std::atomic<uint64_t> g_phasm_diag_apply_calls{0};
static std::atomic<uint64_t> g_phasm_diag_apply_hits{0};
static std::atomic<uint64_t> g_phasm_diag_reset_calls{0};

uint64_t phasm_diag_get_set_calls(void)         { return g_phasm_diag_set_calls.load(); }
uint64_t phasm_diag_get_set_writes(void)        { return g_phasm_diag_set_writes.load(); }
uint64_t phasm_diag_get_set_rejected_oob(void)  { return g_phasm_diag_set_rejected_oob.load(); }
uint64_t phasm_diag_get_apply_calls(void)       { return g_phasm_diag_apply_calls.load(); }
uint64_t phasm_diag_get_apply_hits(void)        { return g_phasm_diag_apply_hits.load(); }
uint64_t phasm_diag_get_reset_calls(void)       { return g_phasm_diag_reset_calls.load(); }
void phasm_diag_reset_counters(void) {
  g_phasm_diag_set_calls.store(0);
  g_phasm_diag_set_writes.store(0);
  g_phasm_diag_set_rejected_oob.store(0);
  g_phasm_diag_apply_calls.store(0);
  g_phasm_diag_apply_hits.store(0);
  g_phasm_diag_reset_calls.store(0);
}

void phasm_reset_bypass_overrides(void* stego_v) {
  /* Zero-init = "no override" across the whole table. memset is
   * cheap (~2.6 KB, fits in one cache line per array element row).
   * B-full.2b: the table is per-encoder; NULL stego ⇒ no-op. */
  PhasmStegoState* st = static_cast<PhasmStegoState*>(stego_v);
  if (st == nullptr) return;
  std::memset(&st->bypass_overrides, 0, sizeof(st->bypass_overrides));
  g_phasm_diag_reset_calls.fetch_add(1, std::memory_order_relaxed);
}

/* #548 v1.0 BLOCKER fix (2026-05-18) — Reset libencoder-private phasm
 * state at the start of every new encode session. The original bug was a
 * cross-call state-leak: a second sequential
 * `encode_yuv_with_pre_framed_bits_4domain` produced 541 ChromaAc CS Sign
 * diffs (vs 0 on the first call) because a phasm-fork global held state
 * across the encoder-instance teardown.
 *
 * B-full.2b (#895): the scratch table + the (frame_num,mb_x,mb_y)
 * sentinels are now per-encoder (PhasmStegoState), allocated fresh +
 * zero-init in WelsInitEncoderExt and freed in FreeMemorySvc. The
 * cross-call leak is therefore IMPOSSIBLE by construction — each new
 * encoder owns clean state — so this function no longer resets them
 * (there's no instance to reach from here anyway; it's called on the
 * orchestrator thread with no handle). It still clears the process-global
 * wire_only flag (migrates to per-instance in B-full.5) + diag counters.
 *
 * Caller (the Rust orchestrator) still resets the libcommon-side state
 * (`phasm_reset_dirty_flags()`, `phasm_clear_mv_clean_mc_stash()`, …) via
 * their own extern "C" entry points in wels_stego_common.cpp. */
void phasm_reset_encoder_session_state(void) {
  g_phasm_use_wire_only_overrides = 0;
  g_phasm_diag_reset_calls.fetch_add(1, std::memory_order_relaxed);
}

/* Populate a single slot. Caller passes the OVERRIDE BIN (0 or 1);
 * this function stores it as 1/2 in the scratch byte (0 reserved for
 * "no override"). Out-of-range domains, positions, or override bins
 * are silently no-op'd — populates that can't fit the dense table
 * just stay un-overridden (defensive, matches the pre-4.5 hook
 * helpers' behaviour of silently refusing illegal mutations). */
void phasm_set_bypass_override(uint8_t domain,
                                const PhasmStegoPos* pos,
                                int override_bin,
                                void* stego) {
  g_phasm_diag_set_calls.fetch_add(1, std::memory_order_relaxed);
  if (override_bin != 0 && override_bin != 1) return;
  uint8_t* slot = phasm_scratch_slot(domain, pos, stego);
  if (slot == nullptr) {
    g_phasm_diag_set_rejected_oob.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  *slot = (uint8_t)(override_bin + 1);  /* 0→1, 1→2 */
  g_phasm_diag_set_writes.fetch_add(1, std::memory_order_relaxed);
}

/* Phase 4.5.a wire-up: read scratch at emit time. */
int phasm_apply_bypass_bin_override (uint8_t domain,
                                      const PhasmStegoPos* pos,
                                      int orig_bin,
                                      void* stego) {
  g_phasm_diag_apply_calls.fetch_add(1, std::memory_order_relaxed);
  uint8_t* slot = phasm_scratch_slot(domain, pos, stego);
  if (slot == nullptr) return orig_bin;
  const uint8_t v = *slot;
  if (v == 0) return orig_bin;
  g_phasm_diag_apply_hits.fetch_add(1, std::memory_order_relaxed);
  return (int)(v - 1);  /* 1→0, 2→1 */
}

}  // extern "C"
