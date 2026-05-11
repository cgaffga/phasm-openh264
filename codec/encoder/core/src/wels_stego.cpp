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

#include <cstddef>
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
