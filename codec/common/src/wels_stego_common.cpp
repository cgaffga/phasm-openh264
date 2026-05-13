// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego common TU. Holds the process-global callback table and
// per-frame state, plus the decoder-side emit helpers. Compiled into
// libcommon so both libencoder and libdecoder TUs can call into the
// state via accessor functions (encoder side) or directly via the
// decoder helpers (decoder side).
//
// History: this file was carved out of `codec/encoder/core/src/
// wels_stego.cpp` in Phase B.9.2.2 when the fork decoder started
// firing `dec_post_read` from inside `parse_mb_syn_cabac.cpp`. The
// encoder-side helpers (apply_coeff_hooks / apply_mvd_hooks /
// emit_md_cost) stayed in libencoder and now reach the globals via
// accessor functions defined here.
//
// All globals here are static (file-scope) so other TUs cannot touch
// the state directly; the accessor functions below are the only
// authorized read path.

#include "wels_stego.h"
#include "wels_stego_dec_helpers.h"

#include <cstddef>
#include <cstring>

namespace {

// Process-global callback state. NULL pointers = hook disabled.
PhasmStegoCallbacks g_phasm_callbacks = { 0, nullptr, nullptr, nullptr, nullptr };
void*               g_phasm_user_data = nullptr;

// Per-frame state. Caller sets via WelsStegoSetFrameNum at the start
// of each frame.
uint32_t            g_phasm_frame_num = 0;

}  // namespace

extern "C" {

// ---------------------------------------------------------------------
// Public registration API (declared in codec/api/wels/wels_stego.h).
// ---------------------------------------------------------------------

int WelsRegisterPhasmStegoCallbacks(const PhasmStegoCallbacks* callbacks,
                                    void* user_data) {
  if (callbacks == nullptr) {
    g_phasm_callbacks.struct_size       = 0;
    g_phasm_callbacks.enc_pre_emit      = nullptr;
    g_phasm_callbacks.dec_post_read     = nullptr;
    g_phasm_callbacks.md_cost_capture   = nullptr;
    g_phasm_callbacks.dual_recon_observe= nullptr;
    g_phasm_user_data = nullptr;
    return 0;
  }

  // The caller's struct_size must be at least as large as the smallest
  // version we support. For ABI 1.x that floor IS the current size;
  // future ABI revisions may grow the struct and accept smaller sizes
  // for backward compatibility (zero-fill the missing tail).
  if (callbacks->struct_size < sizeof(PhasmStegoCallbacks)) {
    return -1;
  }

  std::memset(&g_phasm_callbacks, 0, sizeof(g_phasm_callbacks));
  g_phasm_callbacks.struct_size       = sizeof(PhasmStegoCallbacks);
  g_phasm_callbacks.enc_pre_emit      = callbacks->enc_pre_emit;
  g_phasm_callbacks.dec_post_read     = callbacks->dec_post_read;
  g_phasm_callbacks.md_cost_capture   = callbacks->md_cost_capture;
  g_phasm_callbacks.dual_recon_observe= callbacks->dual_recon_observe;
  g_phasm_user_data = user_data;
  return 0;
}

void WelsStegoSetFrameNum(uint32_t frame_num) {
  g_phasm_frame_num = frame_num;
}

uint32_t WelsStegoAbiVersion(void) {
  return PHASM_STEGO_ABI_VERSION;
}

// ---------------------------------------------------------------------
// Internal accessors. Consumed by encoder-side hook bodies in
// libencoder (svc_encode_mb.cpp, svc_base_layer_md.cpp,
// wels_stego.cpp's encoder helpers). These are extern "C" without a
// surrounding namespace so the linker sees them as plain-C symbols
// callable from any TU in libopenh264.
// ---------------------------------------------------------------------

PhasmStegoEncPreEmitFn PhasmStegoGetEncPreEmit(void) {
  return g_phasm_callbacks.enc_pre_emit;
}

PhasmStegoDecPostReadFn PhasmStegoGetDecPostRead(void) {
  return g_phasm_callbacks.dec_post_read;
}

PhasmStegoMdCostFn PhasmStegoGetMdCostCapture(void) {
  return g_phasm_callbacks.md_cost_capture;
}

PhasmStegoDualReconFn PhasmStegoGetDualReconObserve(void) {
  return g_phasm_callbacks.dual_recon_observe;
}

void* PhasmStegoGetUserData(void) {
  return g_phasm_user_data;
}

}  // close extern "C" for namespace-private static

namespace {
// Per-MB chroma clean snapshot stash (Phase C.8.5). 64 int16_t per
// plane × 2 planes = 256 bytes total. Single-threaded encoder default
// (iMultipleThreadIdc=1), so a single process-global is safe.
int16_t g_phasm_chroma_clean_pres[2][64] = {{0}, {0}};

// P-frame luma per-MB clean snapshot stash (Phase C.8.6). 256 int16_t =
// 4 8x8 blocks × 64 entries (matches WelsIDctT4RecOnMb's coefficient
// layout). Single-threaded encoder default (#339 tracks revisit).
int16_t g_phasm_p_luma_clean_pres[256] = {0};

// C.8.7 MvdSign cascade-break stashes: when a P_16x16 MV is mutated by
// HOOK-H1 (apply_mvd_sign_override), the encoder's MC pred buffer is
// re-computed at the STEGO MV so the wire is internally consistent. But
// the encoder's pDecPic then carries STEGO_MC + residual = polluted
// reference for next-frame ME. To cascade-break: also compute MC at the
// CLEAN (pre-override) MV into these stashes; OutputPMb later shifts
// pDecPic by (CLEAN_MC − STEGO_MC) so the encoder reference stays clean,
// while pVisualRecPic captures the actual decoder reconstruction.
//
// Active flag is sticky per-MB: HOOK-H1 sets to 1 if it fires; OutputPMb
// clears to 0 after consuming. 256 bytes luma, 64+64 chroma; matches the
// MC pred layout passed to pMcLumaFunc / pMcChromaFunc with stride 16/8.
uint8_t g_phasm_mv_clean_mc_luma[256] = {0};
uint8_t g_phasm_mv_clean_mc_chroma[2][64] = {{0}, {0}};
int     g_phasm_mv_override_active = 0;
}  // namespace

extern "C" {

void phasm_stash_chroma_clean_pres(int32_t iUV, const int16_t* clean_pres64) {
  if (iUV < 0 || iUV > 1 || clean_pres64 == nullptr) return;
  std::memcpy(g_phasm_chroma_clean_pres[iUV], clean_pres64, sizeof(int16_t) * 64);
}

const int16_t* phasm_get_chroma_clean_pres(int32_t iUV) {
  if (iUV < 0 || iUV > 1) return nullptr;
  return g_phasm_chroma_clean_pres[iUV];
}

void phasm_stash_p_luma_clean_pres(const int16_t* clean_pres256) {
  if (clean_pres256 == nullptr) return;
  std::memcpy(g_phasm_p_luma_clean_pres, clean_pres256, sizeof(int16_t) * 256);
}

const int16_t* phasm_get_p_luma_clean_pres(void) {
  return g_phasm_p_luma_clean_pres;
}

void phasm_set_mv_override_active(int active) {
  g_phasm_mv_override_active = (active != 0) ? 1 : 0;
}

int phasm_get_mv_override_active(void) {
  return g_phasm_mv_override_active;
}

void phasm_stash_mv_clean_mc_luma(const uint8_t* clean_mc_256) {
  if (clean_mc_256 == nullptr) return;
  std::memcpy(g_phasm_mv_clean_mc_luma, clean_mc_256, 256);
}

const uint8_t* phasm_get_mv_clean_mc_luma(void) {
  return g_phasm_mv_clean_mc_luma;
}

void phasm_stash_mv_clean_mc_chroma(int32_t iUV, const uint8_t* clean_mc_64) {
  if (iUV < 0 || iUV > 1 || clean_mc_64 == nullptr) return;
  std::memcpy(g_phasm_mv_clean_mc_chroma[iUV], clean_mc_64, 64);
}

const uint8_t* phasm_get_mv_clean_mc_chroma(int32_t iUV) {
  if (iUV < 0 || iUV > 1) return nullptr;
  return g_phasm_mv_clean_mc_chroma[iUV];
}

void phasm_stash_mv_clean_mc_luma_slot(int32_t dst_x, int32_t dst_y,
                                        int32_t w, int32_t h,
                                        const uint8_t* src, int32_t src_stride) {
  if (src == nullptr || w <= 0 || h <= 0) return;
  if (dst_x < 0 || dst_y < 0 || dst_x + w > 16 || dst_y + h > 16) return;
  for (int32_t row = 0; row < h; ++row) {
    std::memcpy(&g_phasm_mv_clean_mc_luma[(dst_y + row) * 16 + dst_x],
                src + (size_t)row * (size_t)src_stride,
                (size_t)w);
  }
}

void phasm_stash_mv_clean_mc_chroma_slot(int32_t iUV,
                                          int32_t dst_x, int32_t dst_y,
                                          int32_t w, int32_t h,
                                          const uint8_t* src, int32_t src_stride) {
  if (iUV < 0 || iUV > 1 || src == nullptr || w <= 0 || h <= 0) return;
  if (dst_x < 0 || dst_y < 0 || dst_x + w > 8 || dst_y + h > 8) return;
  for (int32_t row = 0; row < h; ++row) {
    std::memcpy(&g_phasm_mv_clean_mc_chroma[iUV][(dst_y + row) * 8 + dst_x],
                src + (size_t)row * (size_t)src_stride,
                (size_t)w);
  }
}

// ---------------------------------------------------------------------
// phasm_dual_recon_writeback — internal helper (Phase C.8.2+)
//
// Defined here rather than in wels_stego.cpp (libencoder) so the
// decoder side can also call it without dragging the encoder library
// into the link. The helper is plane/buffer-agnostic; it operates on
// raw byte pointers + strides supplied by the caller.
// ---------------------------------------------------------------------
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
                                int32_t  src_stride) {
  // Guard nonsensical geometry: zero-size or negative block is a no-op.
  if (block_w <= 0 || block_h <= 0) return;

  // Clean copy: always required. clean_dst NULL is a caller bug; we
  // accept it gracefully (skip rather than crash) for defensive purposes
  // — but in normal operation pCsData[plane] is always non-NULL once
  // WelsInitCurrentLayer runs.
  if (clean_dst != nullptr && clean_pixels != nullptr) {
    uint8_t*       d = clean_dst + (size_t)pixel_y * (size_t)dst_stride + (size_t)pixel_x;
    const uint8_t* s = clean_pixels;
    for (int32_t y = 0; y < block_h; ++y) {
      std::memcpy(d, s, (size_t)block_w);
      d += dst_stride;
      s += src_stride;
    }
  }

  // Stego mirror copy: optional. Caller may pass stego_dst=NULL when
  // pVisualRecPic isn't allocated (defensive in C.8.1 builds before any
  // dual-write hook fires). Same for stego_pixels.
  if (stego_dst != nullptr && stego_pixels != nullptr) {
    uint8_t*       d = stego_dst + (size_t)pixel_y * (size_t)dst_stride + (size_t)pixel_x;
    const uint8_t* s = stego_pixels;
    for (int32_t y = 0; y < block_h; ++y) {
      std::memcpy(d, s, (size_t)block_w);
      d += dst_stride;
      s += src_stride;
    }
  }

  // Observe-side dispatch: pure no-op when no callback registered. Fires
  // even if either dst pointer was NULL (caller still wanted the
  // pre-commit pixel snapshot reported).
  PhasmStegoDualReconFn cb = g_phasm_callbacks.dual_recon_observe;
  if (cb != nullptr && clean_pixels != nullptr && stego_pixels != nullptr) {
    cb(g_phasm_frame_num, mb_x, mb_y, plane, pixel_x, pixel_y,
       block_w, block_h, clean_pixels, stego_pixels, src_stride,
       g_phasm_user_data);
  }
}

uint32_t PhasmStegoGetFrameNum(void) {
  return g_phasm_frame_num;
}

// ---------------------------------------------------------------------
// Decoder-side emit helpers (declared in
// codec/common/inc/wels_stego_dec_helpers.h). Implementations live
// here in libcommon so decoder TUs see them as direct calls without
// pulling libencoder into the link.
// ---------------------------------------------------------------------

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

  /* list (L0=0, L1=1) packed into the high nibble of partition_idx
   * to match the encoder-side convention (consumer translates back). */
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

}  // extern "C"
