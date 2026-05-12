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

#include <cstddef>
#include <cstdlib>
#include <cstring>

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
int16_t apply_suffix_lsb_coeff(int16_t level, int new_lsb_bit) {
  int16_t sign  = (level < 0) ? (int16_t)-1 : (int16_t)1;
  int16_t mag   = (level < 0) ? (int16_t)-level : level;
  int      cur_lsb = (mag - 15) & 1;
  if (cur_lsb == new_lsb_bit) return level;
  int16_t new_mag = (cur_lsb == 0) ? (int16_t)(mag + 1) : (int16_t)(mag - 1);
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
  if (level == nullptr || *level == 0) return 0;
  if (PhasmStegoGetEncPreEmit() == nullptr) return 0;
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
  if (*level_a == 0) return 0;
  if (PhasmStegoGetEncPreEmit() == nullptr) return 0;

  if (*level_a != *level_b) return 0;

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

  return 1;
}

}  // extern "C"
