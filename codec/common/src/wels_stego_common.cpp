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
PhasmStegoCallbacks g_phasm_callbacks = {};
void*               g_phasm_user_data = nullptr;

// Per-frame state. Caller sets via WelsStegoSetFrameNum at the start
// of each frame.
uint32_t            g_phasm_frame_num = 0;

// Pass mode. PASSTHROUGH = no capture/replay; encoder runs normally.
// CAPTURE = Pass-1, capture callback fires per MB. REPLAY = Pass-2,
// replay callback supplies cached decisions, encoder skips RDO/ME.
PhasmStegoPassMode  g_phasm_pass_mode = PHASM_PASS_PASSTHROUGH;

}  // namespace

extern "C" {

// ---------------------------------------------------------------------
// Public registration API (declared in codec/api/wels/wels_stego.h).
// ---------------------------------------------------------------------

int WelsRegisterPhasmStegoCallbacks(const PhasmStegoCallbacks* callbacks,
                                    void* user_data) {
  if (callbacks == nullptr) {
    g_phasm_callbacks   = PhasmStegoCallbacks{};
    g_phasm_user_data   = nullptr;
    g_phasm_pass_mode   = PHASM_PASS_PASSTHROUGH;
    return 0;
  }

  // Caller's struct_size must match the current ABI exactly. phasm
  // owns both sides of this boundary (the fork is vendored, the
  // bindings live in core-openh264-sys, both ship together) so we
  // don't carry version-tolerance machinery. A mismatch means the
  // bindings are out of sync with the fork — fix the caller.
  if (callbacks->struct_size != sizeof(PhasmStegoCallbacks)) {
    return -1;
  }

  g_phasm_callbacks = *callbacks;
  g_phasm_user_data = user_data;
  g_phasm_pass_mode = PHASM_PASS_PASSTHROUGH;
  return 0;
}

void WelsStegoSetFrameNum(uint32_t frame_num) {
  g_phasm_frame_num = frame_num;
}

void WelsStegoSetPassMode(PhasmStegoPassMode mode) {
  g_phasm_pass_mode = mode;
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

// ABI 1.3.0+ accessors.
PhasmStegoCaptureMbDecisionFn PhasmStegoGetCaptureMbDecision(void) {
  return g_phasm_callbacks.capture_mb_decision;
}

PhasmStegoReplayMbDecisionFn PhasmStegoGetReplayMbDecision(void) {
  return g_phasm_callbacks.replay_mb_decision;
}

PhasmStegoPassMode PhasmStegoGetPassMode(void) {
  return g_phasm_pass_mode;
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

// Phase C.9.1 Path A v2 (#449) per-MB dirty flags for the P-frame inter
// + chroma stashes. Each setter is called at the snapshot+hook site (in
// svc_encode_mb.cpp) with the OR-accumulated return of every coeff hook
// fired on that plane; the consume site (in svc_encode_slice.cpp) gates
// the dual-recon dance on (luma_dirty || chroma[0] || chroma[1] ||
// mv_override_active). When all four are zero the encoder's pDecPic
// already holds the clean recon (no hook flipped anything), so the
// consume site just memcpys pDec → pVisualRecPic at the MB offset and
// skips the entire snapshot/restore/IDCT-recompute cycle.
int     g_phasm_p_luma_dirty = 0;
int     g_phasm_chroma_dirty[2] = {0, 0};

// Phase C.9.0 (#482) — Pass-1 visual_recon disable. Default 1 (enabled =
// the C.8 baseline). When 0, the InitDqLayers allocator in encoder_ext.cpp
// skips the pVisualRef[] pool, leaving pVisualDecPic/pVisualRecPic NULL
// for the lifetime of this encoder instance. Every per-MB mirror site
// and the C.8.8 dual deblock pass already gate on `pVisualRecPic !=
// NULL`, so disabling here cleanly bypasses ALL visual_recon work without
// any per-site branching. Used by the openh264_stego orchestrator's
// Pass-1 cover probe (whose bitstream is walked then discarded — no mp4
// output, no fsnr observation).
//
// Set BEFORE phasm_encoder_initialize; the shim's wrapper threads the
// flag through and the global is read inside InitDqLayers. Single-
// threaded encoder default (#339 tracks revisit).
int     g_phasm_dual_recon_enabled = 1;

// Phase C.9.2 (#450) — per-slice override counter for deblock skip-on-
// clean. Incremented inside phasm_apply_coeff_hooks / *_dual and
// phasm_apply_mvd_hooks at the return-1 site (where a value was actually
// modified). Read at the start of DeblockingFilterSliceAvcbase; if 0 we
// skip the C.8.8 second deblock pass over pVisualRecPic since the
// pre-deblock pVisualRecPic equals pDecPic byte-for-byte (every mirror
// write was a clean=stego identity copy). Reset at the end of every
// deblock pass (slice + frame variants) so the counter starts at 0 for
// the next slice. Single-threaded; see #339 for multi-thread plan.
int     g_phasm_slice_override_count = 0;
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

// Phase C.9.1 Path A v2 dirty-flag accessors. The setter is called once
// per MB at the snapshot site after every coeff hook for the plane has
// fired (OR-accumulated). The consume site reads them and clears with
// phasm_reset_dirty_flags() after consuming, so a stale set from the
// previous MB doesn't leak forward.
void phasm_set_p_luma_dirty(int dirty) {
  g_phasm_p_luma_dirty = (dirty != 0) ? 1 : 0;
}

int phasm_get_p_luma_dirty(void) {
  return g_phasm_p_luma_dirty;
}

void phasm_set_chroma_dirty(int32_t iUV, int dirty) {
  if (iUV < 0 || iUV > 1) return;
  g_phasm_chroma_dirty[iUV] = (dirty != 0) ? 1 : 0;
}

int phasm_get_chroma_dirty(int32_t iUV) {
  if (iUV < 0 || iUV > 1) return 0;
  return g_phasm_chroma_dirty[iUV];
}

void phasm_reset_dirty_flags(void) {
  g_phasm_p_luma_dirty = 0;
  g_phasm_chroma_dirty[0] = 0;
  g_phasm_chroma_dirty[1] = 0;
}

// Phase C.9.0 (#482) dual_recon_enabled setter / getter. Set by the shim
// before phasm_encoder_initialize so InitDqLayers reads the flag when
// deciding whether to allocate the pVisualRef[] mirror pool.
void phasm_set_dual_recon_enabled(int enabled) {
  g_phasm_dual_recon_enabled = (enabled != 0) ? 1 : 0;
}

int phasm_get_dual_recon_enabled(void) {
  return g_phasm_dual_recon_enabled;
}

// P3.3a (2026-05-25) — process-global pDecPic Y plane capture for
// post-frame DPB correction. Set by ref_list_mgr after DPB promotion;
// read by the shim's phasm_encoder_get_dec_pic_y.
static uint8_t* g_phasm_dec_pic_y_ptr    = nullptr;
static int32_t  g_phasm_dec_pic_y_stride = 0;

void phasm_set_dec_pic_y(uint8_t* y, int32_t stride) {
  g_phasm_dec_pic_y_ptr    = y;
  g_phasm_dec_pic_y_stride = stride;
}

bool phasm_encoder_get_enc_dec_pic(void* /*enc*/, uint8_t** y, int32_t* stride) {
  if (!g_phasm_dec_pic_y_ptr) return false;
  *y = g_phasm_dec_pic_y_ptr;
  *stride = g_phasm_dec_pic_y_stride;
  return true;
}

// P3.3b — post-quant callback + coefficient replay mode.
static PhasmPostQuantCallback g_phasm_post_quant_cb = nullptr;
static int g_phasm_coeff_replay_mode = 0;
static const int16_t* g_phasm_replay_coeffs = nullptr;
static int32_t g_phasm_replay_coeff_count = 0;

void phasm_set_post_quant_callback(PhasmPostQuantCallback cb) {
  g_phasm_post_quant_cb = cb;
}

void phasm_set_coeff_replay_mode(int enabled) {
  g_phasm_coeff_replay_mode = (enabled != 0) ? 1 : 0;
}

void phasm_set_replay_coeffs(const int16_t* coeffs, int32_t count) {
  g_phasm_replay_coeffs = coeffs;
  g_phasm_replay_coeff_count = count;
}

PhasmPostQuantCallback phasm_get_post_quant_callback(void) {
  return g_phasm_post_quant_cb;
}

int phasm_get_coeff_replay_mode(void) {
  return g_phasm_coeff_replay_mode;
}

const int16_t* phasm_get_replay_coeffs(int32_t* count) {
  if (count) *count = g_phasm_replay_coeff_count;
  return g_phasm_replay_coeffs;
}

// Phase C.9.2 (#450) per-slice override counter. Incremented inside the
// apply_*_hooks return-1 site. Reset at the end of every deblock pass
// (slice + frame variants). Read at the START of DeblockingFilterSlice
// Avcbase to decide whether the C.8.8 second deblock pass on pVisualRec
// Pic can be skipped.
void phasm_inc_slice_override_count(void) {
  g_phasm_slice_override_count++;
}

int phasm_get_slice_override_count(void) {
  return g_phasm_slice_override_count;
}

void phasm_reset_slice_override_count(void) {
  g_phasm_slice_override_count = 0;
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
