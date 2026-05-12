// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego helper TU. Holds the process-global callback table and
// per-frame state. Phase A.3 ships only the registration entry points;
// the actual hook invocations from inside `svc_encode_mb.cpp` +
// `svc_base_layer_md.cpp` land in Phase A.5 per
// `docs/design/video/h264/openh264-hook-sites.md` (consumer repo).
//
// All globals here are static (file-scope) so that other TUs can call
// the C ABI registration functions but cannot touch the state pointer
// directly. Phase A.5's hook bodies will live in this TU too — they'll
// dispatch to the registered callback via these statics, plus implement
// the dual-array writeback + JVT-O079 floor protection + sMvList
// refresh per the audit.

#include "wels_stego.h"
#include "wels_stego_internal.h"
#include "wels_stego_dec_helpers.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>

namespace {

// Process-global callback state. NULL pointers = hook disabled.
PhasmStegoCallbacks g_phasm_callbacks = { 0, nullptr, nullptr, nullptr };
void*               g_phasm_user_data = nullptr;

// Per-frame state. Caller sets via WelsStegoSetFrameNum at the start
// of each frame.
uint32_t            g_phasm_frame_num = 0;

}  // namespace

extern "C" {

int WelsRegisterPhasmStegoCallbacks(const PhasmStegoCallbacks* callbacks,
                                    void* user_data) {
  if (callbacks == nullptr) {
    // Reset to no-hooks state.
    g_phasm_callbacks.struct_size     = 0;
    g_phasm_callbacks.enc_pre_emit    = nullptr;
    g_phasm_callbacks.dec_post_read   = nullptr;
    g_phasm_callbacks.md_cost_capture = nullptr;
    g_phasm_user_data = nullptr;
    return 0;
  }

  // The caller's struct_size must be at least as large as the smallest
  // version we support. For ABI 1.0.0 that floor IS the current size;
  // future ABI revisions may grow the struct and accept smaller sizes
  // for backward compatibility (zero-fill the missing tail).
  if (callbacks->struct_size < sizeof(PhasmStegoCallbacks)) {
    return -1;
  }

  // Copy only the fields we know about, in case the caller's struct is
  // larger (future-compatible).
  std::memset(&g_phasm_callbacks, 0, sizeof(g_phasm_callbacks));
  g_phasm_callbacks.struct_size     = sizeof(PhasmStegoCallbacks);
  g_phasm_callbacks.enc_pre_emit    = callbacks->enc_pre_emit;
  g_phasm_callbacks.dec_post_read   = callbacks->dec_post_read;
  g_phasm_callbacks.md_cost_capture = callbacks->md_cost_capture;
  g_phasm_user_data = user_data;
  return 0;
}

void WelsStegoSetFrameNum(uint32_t frame_num) {
  g_phasm_frame_num = frame_num;
}

uint32_t WelsStegoAbiVersion(void) {
  return PHASM_STEGO_ABI_VERSION;
}

}  // extern "C"

// ---------------------------------------------------------------------
// Internal accessors (consumed by Phase A.5 hook bodies in this TU).
// Not part of the public ABI. Kept in an anonymous namespace inside
// the encoder library so other encoder TUs can include this header
// via a sibling .h once A.5 wires the hooks. For Phase A.3 the
// accessors are unused — but defined so the API surface compiles +
// links + is exercised by a smoke test.
// ---------------------------------------------------------------------

namespace WelsEnc {

extern "C" {

// Internal: returns the registered pre-emit callback or NULL. Used by
// Phase A.5 hook bodies in svc_encode_mb.cpp + svc_base_layer_md.cpp.
PhasmStegoEncPreEmitFn PhasmStegoGetEncPreEmit(void) {
  return g_phasm_callbacks.enc_pre_emit;
}

PhasmStegoDecPostReadFn PhasmStegoGetDecPostRead(void) {
  return g_phasm_callbacks.dec_post_read;
}

PhasmStegoMdCostFn PhasmStegoGetMdCostCapture(void) {
  return g_phasm_callbacks.md_cost_capture;
}

void* PhasmStegoGetUserData(void) {
  return g_phasm_user_data;
}

uint32_t PhasmStegoGetFrameNum(void) {
  return g_phasm_frame_num;
}

}  // extern "C"

}  // namespace WelsEnc

// =====================================================================
// Phase A.5 Stage 0: Helper implementations.
//
// These are the helpers that Phase A.5 stages 1-7 will call from
// insertion points in svc_encode_mb.cpp + svc_base_layer_md.cpp. Stage 0
// ships the helpers + gtest unit-test coverage; later stages just wire
// these from the right call sites per the audit
// (docs/design/video/h264/openh264-hook-sites.md in consumer repo).
// =====================================================================

namespace {

// Translate a sign-bit override into a flipped level.
// Returns the modified level (sign reflected, magnitude preserved).
int16_t apply_sign_override(int16_t level, int new_sign_bit) {
  // new_sign_bit: 0 = positive, 1 = negative.
  int16_t abs_level = (level < 0) ? (int16_t)-level : level;
  return new_sign_bit ? (int16_t)-abs_level : abs_level;
}

// Translate a suffix-LSB override into a level with the new LSB.
// Caller must ensure |level| >= 15 (coeff) or >= 9 (MVD) per-domain
// floor before calling. Returns modified level with same sign + new LSB.
int16_t apply_suffix_lsb_coeff(int16_t level, int new_lsb_bit) {
  // For coeffs: suffix value = |level| - 15. LSB flip → |level| ± 1.
  int16_t sign  = (level < 0) ? (int16_t)-1 : (int16_t)1;
  int16_t mag   = (level < 0) ? (int16_t)-level : level;
  int      cur_lsb = (mag - 15) & 1;
  if (cur_lsb == new_lsb_bit) return level;
  // Flip to new LSB: increase if cur=0, decrease if cur=1.
  int16_t new_mag = (cur_lsb == 0) ? (int16_t)(mag + 1) : (int16_t)(mag - 1);
  return (int16_t)(sign * new_mag);
}

// Dispatch a single hook call. Returns the callback's return value, or
// -1 if no callback registered. Sets pos->domain before calling.
int32_t dispatch_hook(PhasmStegoPos* pos, PhasmStegoDomain domain,
                      int32_t original_bit) {
  PhasmStegoEncPreEmitFn cb = g_phasm_callbacks.enc_pre_emit;
  if (cb == nullptr) return -1;
  pos->domain = (uint8_t)domain;
  return cb(pos, original_bit, g_phasm_user_data);
}

// Apply coefficient sign + suffix-LSB hooks to a single non-zero level.
// Returns the (possibly modified) level. Refuses any override that would
// produce zero, or any callback return outside {-1, 0, 1}.
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

  // Sign domain (always fires on non-zero coeff).
  int32_t orig_sign = (level < 0) ? 1 : 0;
  int32_t override_sign = dispatch_hook(pos, PHASM_DOMAIN_COEFF_SIGN, orig_sign);
  if (override_sign == 0 || override_sign == 1) {
    if (override_sign != orig_sign) {
      int16_t new_level = apply_sign_override(level, override_sign);
      if (new_level != 0) {  // contract: non-zero in / non-zero out
        level = new_level;
      }
    }
  }

  // Suffix-LSB domain (only when |level| >= 15 — below that no suffix emitted).
  int16_t abs_level = (level < 0) ? (int16_t)-level : level;
  if (abs_level >= 15) {
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

// Translate an MVD-sign-bit override into a reflected MV component.
// Reflection: new_mv = 2*mvp - mv (so MVD flips sign while MVp is fixed).
int16_t apply_mvd_sign_override(int16_t mv_component, int16_t mvp_component) {
  return (int16_t)(2 * (int32_t)mvp_component - (int32_t)mv_component);
}

// Translate an MVD-suffix-LSB override into an MV component with the new LSB.
// Caller ensures |MVD| >= 9 before calling.
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

// =====================================================================
// Phase B.9.2.1: Decoder-side emit helpers.
//
// Declared in codec/common/inc/wels_stego_dec_helpers.h so decoder TUs
// can include + call. Implementations live here because they need
// access to file-scope globals (g_phasm_callbacks, g_phasm_user_data,
// g_phasm_frame_num). Resolved at link time via libopenh264's
// link_whole(libencoder + libdecoder + ...).
//
// These helpers are pure observation — no encoder-state modification.
// Each is a no-op when no dec_post_read callback is registered. The hot
// path is one nullptr check + one PhasmStegoPos stack alloc + dispatch.
//
// Phase B.9.2.2-.5 insert calls into parse_mb_syn_cabac.cpp.
// Phase B.9.2.1 (this commit) ships infrastructure only — no decoder TU
// references these helpers yet, but the symbols are present so future
// phases compile cleanly and the encoder TU continues to link.
// =====================================================================

void phasm_dec_emit_coeff_sign(uint16_t mb_x, uint16_t mb_y,
                               uint8_t  block_cat,
                               uint8_t  sub_block,
                               uint8_t  coeff_idx,
                               int32_t  sign_bit) {
  PhasmStegoDecPostReadFn cb = g_phasm_callbacks.dec_post_read;
  if (cb == nullptr) return;

  PhasmStegoPos pos;
  pos.frame_num     = g_phasm_frame_num;
  pos.mb_x          = mb_x;
  pos.mb_y          = mb_y;
  pos.domain        = (uint8_t)PHASM_DOMAIN_COEFF_SIGN;
  pos.partition_idx = 0;
  pos.sub_block     = sub_block;
  pos.coeff_idx     = coeff_idx;
  pos.block_cat     = block_cat;
  pos.ref_idx       = 0xff;
  pos.mv_component  = 0xff;
  pos._reserved     = 0;

  cb(&pos, sign_bit, g_phasm_user_data);
}

void phasm_dec_emit_coeff_suffix_lsb(uint16_t mb_x, uint16_t mb_y,
                                     uint8_t  block_cat,
                                     uint8_t  sub_block,
                                     uint8_t  coeff_idx,
                                     int32_t  lsb_bit) {
  PhasmStegoDecPostReadFn cb = g_phasm_callbacks.dec_post_read;
  if (cb == nullptr) return;

  PhasmStegoPos pos;
  pos.frame_num     = g_phasm_frame_num;
  pos.mb_x          = mb_x;
  pos.mb_y          = mb_y;
  pos.domain        = (uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB;
  pos.partition_idx = 0;
  pos.sub_block     = sub_block;
  pos.coeff_idx     = coeff_idx;
  pos.block_cat     = block_cat;
  pos.ref_idx       = 0xff;
  pos.mv_component  = 0xff;
  pos._reserved     = 0;

  cb(&pos, lsb_bit, g_phasm_user_data);
}

void phasm_dec_emit_mvd_sign(uint16_t mb_x, uint16_t mb_y,
                             uint8_t  list,
                             uint8_t  partition_idx,
                             uint8_t  mv_component,
                             uint8_t  ref_idx,
                             int32_t  sign_bit) {
  PhasmStegoDecPostReadFn cb = g_phasm_callbacks.dec_post_read;
  if (cb == nullptr) return;

  /* list (L0=0, L1=1) is encoded into the high nibble of partition_idx
   * to match the encoder-side convention (the consumer's translation
   * function reads partition_idx and demuxes). For ABI 1.1.0 there is
   * no dedicated list field on PhasmStegoPos; reusing partition_idx's
   * top bit is the same convention encoder hooks H1-H7 already use. */
  PhasmStegoPos pos;
  pos.frame_num     = g_phasm_frame_num;
  pos.mb_x          = mb_x;
  pos.mb_y          = mb_y;
  pos.domain        = (uint8_t)PHASM_DOMAIN_MVD_SIGN;
  pos.partition_idx = (uint8_t)((list << 4) | (partition_idx & 0x0F));
  pos.sub_block     = 0xff;
  pos.coeff_idx     = 0xff;
  pos.block_cat     = 0xff;
  pos.ref_idx       = ref_idx;
  pos.mv_component  = mv_component;
  pos._reserved     = 0;

  cb(&pos, sign_bit, g_phasm_user_data);
}

void phasm_dec_emit_mvd_suffix_lsb(uint16_t mb_x, uint16_t mb_y,
                                   uint8_t  list,
                                   uint8_t  partition_idx,
                                   uint8_t  mv_component,
                                   uint8_t  ref_idx,
                                   int32_t  lsb_bit) {
  PhasmStegoDecPostReadFn cb = g_phasm_callbacks.dec_post_read;
  if (cb == nullptr) return;

  PhasmStegoPos pos;
  pos.frame_num     = g_phasm_frame_num;
  pos.mb_x          = mb_x;
  pos.mb_y          = mb_y;
  pos.domain        = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
  pos.partition_idx = (uint8_t)((list << 4) | (partition_idx & 0x0F));
  pos.sub_block     = 0xff;
  pos.coeff_idx     = 0xff;
  pos.block_cat     = 0xff;
  pos.ref_idx       = ref_idx;
  pos.mv_component  = mv_component;
  pos._reserved     = 0;

  cb(&pos, lsb_bit, g_phasm_user_data);
}

// =====================================================================
// Phase A.5 Stage 0+ encoder-side helpers (existing).
// =====================================================================

int phasm_apply_coeff_hooks(PhasmStegoPos* pos_template,
                            uint8_t sub_block,
                            uint8_t coeff_idx_scanned,
                            uint8_t block_cat,
                            int16_t* level) {
  if (level == nullptr || *level == 0) return 0;
  if (g_phasm_callbacks.enc_pre_emit == nullptr) return 0;
  int16_t old_level = *level;
  *level = apply_coeff_hooks_to_level(pos_template, sub_block,
                                      coeff_idx_scanned, block_cat,
                                      old_level);
  return (*level != old_level) ? 1 : 0;
}

int phasm_apply_coeff_hooks_dual(PhasmStegoPos* pos_template,
                                 uint8_t sub_block,
                                 uint8_t coeff_idx_scanned,
                                 uint8_t block_cat,
                                 int16_t* level_a,
                                 int16_t* level_b) {
  if (level_a == nullptr || level_b == nullptr) return 0;
  if (*level_a == 0) return 0;  // contract: hook on non-zero only
  if (g_phasm_callbacks.enc_pre_emit == nullptr) return 0;

  // Sanity: callers MUST pass aliased pointers (same logical coeff in
  // two arrays). If they differ the caller has a scan-index bug.
  if (*level_a != *level_b) return 0;  // silently refuse rather than crash

  int16_t old_level = *level_a;
  int16_t new_level = apply_coeff_hooks_to_level(pos_template, sub_block,
                                                  coeff_idx_scanned, block_cat,
                                                  old_level);
  if (new_level != old_level) {
    *level_a = new_level;
    *level_b = new_level;
    return 1;
  }
  return 0;
}

int phasm_mvd_would_collide_with_pskip(int16_t mv_x, int16_t mv_y,
                                       int16_t pred_skip_mv_x,
                                       int16_t pred_skip_mv_y) {
  return (mv_x == pred_skip_mv_x && mv_y == pred_skip_mv_y) ? 1 : 0;
}

void phasm_emit_md_cost(uint16_t mb_x, uint16_t mb_y,
                        uint32_t internal_mb_type, uint8_t cbp) {
  PhasmStegoMdCostFn cb = g_phasm_callbacks.md_cost_capture;
  if (cb == nullptr) return;

  /* Translate OpenH264's MB_TYPE_* bitfield (codec/common/inc/
   * wels_common_defs.h) into a phasm classification byte. Mapping is
   * defined to mirror EMITTED-RESIDUAL shape so the consumer's filter
   * is one block_cat / mb_type table lookup.
   *
   *   MB_TYPE_INTRA4x4    0x01 -> I_4x4
   *   MB_TYPE_INTRA16x16  0x02 -> I_16x16
   *   MB_TYPE_INTRA8x8    0x04 -> I_8x8
   *   MB_TYPE_16x16/16x8/8x16/8x8/8x8_REF0 -> INTER
   *   MB_TYPE_SKIP        0x100 -> SKIP
   *   any other / mixed -> OTHER
   *
   * Test MB_TYPE_SKIP first (it can co-occur with other flags on some
   * code paths, and we always want "no residual" semantics).
   */
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
  cost.frame_num   = g_phasm_frame_num;
  cost.mb_x        = mb_x;
  cost.mb_y        = mb_y;
  cost.mb_type     = klass;
  cost.cbp         = cbp;
  cost._reserved   = 0;
  cost.capacity[0] = 0;  /* ABI 1.1.0: capacity counts deferred to v1.x+ */
  cost.capacity[1] = 0;
  cost.capacity[2] = 0;
  cost.capacity[3] = 0;
  cb(&cost, g_phasm_user_data);
}

int phasm_apply_mvd_hooks(const PhasmMvHookCtx* ctx) {
  if (ctx == nullptr || ctx->mv_x_qpel == nullptr || ctx->mv_y_qpel == nullptr) {
    return 0;
  }
  PhasmStegoEncPreEmitFn cb = g_phasm_callbacks.enc_pre_emit;
  if (cb == nullptr) return 0;

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

  // Compute candidate MVs in local scratch. Don't write to ctx pointers
  // until the PredSkipMv check passes (so we can refuse atomically).
  int16_t mv_in[2]  = { *(ctx->mv_x_qpel), *(ctx->mv_y_qpel) };
  int16_t mv_out[2] = { mv_in[0], mv_in[1] };
  int16_t mvp[2]    = { ctx->mvp_x_qpel, ctx->mvp_y_qpel };

  for (int comp = 0; comp < 2; ++comp) {
    int16_t mvd_in = (int16_t)((int32_t)mv_in[comp] - (int32_t)mvp[comp]);
    if (mvd_in == 0) continue;  // sign bit not emitted for MVD=0 components

    pos.mv_component = (uint8_t)comp;

    // Sign domain (always fires on non-zero MVD).
    int32_t orig_sign = (mvd_in < 0) ? 1 : 0;
    pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SIGN;
    int32_t ovr_sign = cb(&pos, orig_sign, g_phasm_user_data);
    if ((ovr_sign == 0 || ovr_sign == 1) && ovr_sign != orig_sign) {
      mv_out[comp] = apply_mvd_sign_override(mv_in[comp], mvp[comp]);
    }

    // Suffix-LSB domain (only when |MVD| >= 9, evaluated on the
    // possibly-sign-flipped candidate).
    int16_t cur_mvd = (int16_t)((int32_t)mv_out[comp] - (int32_t)mvp[comp]);
    int16_t abs_mvd = (cur_mvd < 0) ? (int16_t)-cur_mvd : cur_mvd;
    if (abs_mvd >= 9) {
      int32_t orig_lsb = (abs_mvd - 9) & 1;
      pos.domain = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
      int32_t ovr_lsb = cb(&pos, orig_lsb, g_phasm_user_data);
      if ((ovr_lsb == 0 || ovr_lsb == 1) && ovr_lsb != orig_lsb) {
        mv_out[comp] = apply_mvd_suffix_lsb(mv_out[comp], mvp[comp], ovr_lsb);
      }
    }
  }

  const int16_t new_x = mv_out[0];
  const int16_t new_y = mv_out[1];

  if (new_x == mv_in[0] && new_y == mv_in[1]) {
    return 0;  // no override happened
  }

  // PredSkipMv collision pre-empt: if the override would produce an MV
  // that matches the predicted-skip MV, refuse (else WelsMdInterDouble-
  // CheckPskip silently demotes to Skip and our bits are dropped).
  if (ctx->check_pskip_collision &&
      phasm_mvd_would_collide_with_pskip(new_x, new_y,
                                          ctx->pred_skip_mv_x,
                                          ctx->pred_skip_mv_y)) {
    return 0;
  }

  // Commit.
  *(ctx->mv_x_qpel) = new_x;
  *(ctx->mv_y_qpel) = new_y;

  // sMvList refresh (for P_16x16 + Skip/Background paths where the
  // temporal-MV predictor is read by the next P-frame's MdPmv).
  if (ctx->mvList_x_qpel != nullptr && ctx->mvList_y_qpel != nullptr) {
    *(ctx->mvList_x_qpel) = new_x;
    *(ctx->mvList_y_qpel) = new_y;
  }

  return 1;
}

}  // extern "C"
