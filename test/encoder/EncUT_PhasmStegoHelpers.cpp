// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// Phase A.5 Stage 0 unit tests. Exercises the helper functions in
// wels_stego.cpp via synthetic inputs. No real encoder is invoked.

#include "wels_stego.h"
#include "wels_stego_internal.h"

#include <gtest/gtest.h>
#include <cstring>
#include <cstdint>

namespace {

// ---------------------------------------------------------------------
// Mock callback infrastructure. Tests configure the mock via these
// globals, then invoke a helper, then assert on outcomes.
//
// The callback returns whatever `g_mock_return_value` is set to.
// Each invocation appends a record to `g_mock_history` for tests that
// want to assert on the call sequence (e.g. "sign hook fired with
// original=1, then suffix LSB hook fired with original=0").
// ---------------------------------------------------------------------

struct MockCall {
  PhasmStegoPos pos;
  int32_t       original_bit;
};

constexpr size_t kMaxMockCalls = 64;
MockCall g_mock_history[kMaxMockCalls];
size_t   g_mock_history_count = 0;
int32_t  g_mock_return_values[kMaxMockCalls];  // per-call return values
size_t   g_mock_return_idx     = 0;

int32_t mock_pre_emit_cb(const PhasmStegoPos* pos, int32_t original, void* /*user*/) {
  if (g_mock_history_count < kMaxMockCalls) {
    g_mock_history[g_mock_history_count].pos          = *pos;
    g_mock_history[g_mock_history_count].original_bit = original;
    g_mock_history_count++;
  }
  int32_t rv = -1;
  if (g_mock_return_idx < kMaxMockCalls) {
    rv = g_mock_return_values[g_mock_return_idx++];
  }
  return rv;
}

// Register the mock with a sequence of return values.
// Pass {-1, -1, ...} for "no-override always". Pass {0, 1} for
// "first call returns 0, second returns 1", etc.
void RegisterMock(std::initializer_list<int32_t> returns) {
  g_mock_history_count = 0;
  g_mock_return_idx    = 0;
  std::memset(g_mock_history,       0, sizeof(g_mock_history));
  for (size_t i = 0; i < kMaxMockCalls; ++i) g_mock_return_values[i] = -1;
  size_t i = 0;
  for (int32_t r : returns) {
    if (i < kMaxMockCalls) g_mock_return_values[i++] = r;
  }
  PhasmStegoCallbacks cbs;
  std::memset(&cbs, 0, sizeof(cbs));
  cbs.struct_size  = sizeof(cbs);
  cbs.enc_pre_emit = mock_pre_emit_cb;
  ASSERT_EQ(0, WelsRegisterPhasmStegoCallbacks(&cbs, nullptr));
}

void TearDownMock() {
  WelsRegisterPhasmStegoCallbacks(nullptr, nullptr);
}

PhasmStegoPos MakeBasePos() {
  PhasmStegoPos pos = {};
  pos.frame_num     = 7;
  pos.mb_x          = 3;
  pos.mb_y          = 5;
  pos.partition_idx = 0;
  pos.sub_block     = 0xff;
  pos.coeff_idx     = 0xff;
  pos.block_cat     = 0xff;
  pos.ref_idx       = 0xff;
  pos.mv_component  = 0xff;
  return pos;
}

PhasmMvHookCtx MakeBaseMvCtx(int16_t* mvx, int16_t* mvy) {
  PhasmMvHookCtx ctx = {};
  ctx.frame_num             = 1;
  ctx.mb_x                  = 2;
  ctx.mb_y                  = 4;
  ctx.partition_idx         = 0;
  ctx.ref_idx               = 0;
  ctx.check_pskip_collision = 0;
  ctx.mvp_x_qpel            = 0;
  ctx.mvp_y_qpel            = 0;
  ctx.pred_skip_mv_x        = 0;
  ctx.pred_skip_mv_y        = 0;
  ctx.mv_x_qpel             = mvx;
  ctx.mv_y_qpel             = mvy;
  ctx.mvList_x_qpel         = nullptr;
  ctx.mvList_y_qpel         = nullptr;
  return ctx;
}

}  // namespace

// =====================================================================
// ABI surface smoke tests
// =====================================================================

TEST(PhasmStegoAbi, VersionNotZero) {
  EXPECT_NE(0u, WelsStegoAbiVersion());
  EXPECT_EQ(PHASM_STEGO_ABI_VERSION, WelsStegoAbiVersion());
}

TEST(PhasmStegoAbi, RegisterAndReset) {
  PhasmStegoCallbacks cbs;
  std::memset(&cbs, 0, sizeof(cbs));
  cbs.struct_size  = sizeof(cbs);
  cbs.enc_pre_emit = mock_pre_emit_cb;
  EXPECT_EQ(0, WelsRegisterPhasmStegoCallbacks(&cbs, nullptr));
  EXPECT_EQ(0, WelsRegisterPhasmStegoCallbacks(nullptr, nullptr));
}

TEST(PhasmStegoAbi, RegisterRejectsOldStructSize) {
  PhasmStegoCallbacks cbs;
  std::memset(&cbs, 0, sizeof(cbs));
  cbs.struct_size  = 4;  // smaller than current struct
  cbs.enc_pre_emit = mock_pre_emit_cb;
  EXPECT_NE(0, WelsRegisterPhasmStegoCallbacks(&cbs, nullptr));
}

// =====================================================================
// Coefficient hooks: phasm_apply_coeff_hooks (single-array path)
// =====================================================================

TEST(PhasmCoeffHooks, NoOverrideLeavesLevelUnchanged) {
  RegisterMock({-1, -1, -1, -1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, /*sub_block=*/0, /*coeff_idx=*/0, /*block_cat=*/0, &level, /*stego=*/nullptr));
  EXPECT_EQ(5, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, ZeroLevelSkipsHookDispatch) {
  RegisterMock({0, 1});  // would override if called
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 0;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(0, level);
  EXPECT_EQ(0u, g_mock_history_count);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SignFlipFromPositive) {
  // For |level|=5: sign domain is the only domain (|level|<15 so no suffix).
  // Sign override returns 1 (negative).
  RegisterMock({1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(-5, level);
  EXPECT_EQ(1u, g_mock_history_count);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN, g_mock_history[0].pos.domain);
  EXPECT_EQ(0, g_mock_history[0].original_bit);  // original sign of +5 is 0
  TearDownMock();
}

TEST(PhasmCoeffHooks, SignFlipFromNegative) {
  RegisterMock({0});  // override to positive
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = -7;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(7, level);
  EXPECT_EQ(1u, g_mock_history_count);
  EXPECT_EQ(1, g_mock_history[0].original_bit);  // original sign of -7 is 1
  TearDownMock();
}

TEST(PhasmCoeffHooks, SignNoOpWhenOverrideMatches) {
  RegisterMock({0});  // already positive
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 7;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(7, level);
  TearDownMock();
}

// =====================================================================
// #505 / 2026-05-16 — suffix-LSB hook fires at |level| >= 16, matching
// the phasm walker's COEFF_SUFFIX_LSB_THRESHOLD = 16 in
// core/src/codec/h264/stego/inject.rs. Walker doesn't enroll cover
// positions at |coeff|=15, so firing the hook there caused a layout
// divergence (encoder mutated 16→15, walker missed the position, STC
// syndrome shifted). Boundary protection at mag==16 forces +1 to
// mag=17 instead of -1 to mag=15, keeping the level above threshold.
// =====================================================================

TEST(PhasmCoeffHooks, SuffixLsbDoesNotFireBelowThreshold) {
  // |level|=14 (below threshold 16): only sign domain dispatched.
  RegisterMock({-1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 14;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(1u, g_mock_history_count);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN, g_mock_history[0].pos.domain);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbDoesNotFireAtLevel15) {
  // |level|=15 (just below threshold 16 per #505): only sign domain
  // dispatches. Pre-#505 this fired the suffix-LSB hook and walker
  // missed the position.
  RegisterMock({-1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 15;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(1u, g_mock_history_count);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN, g_mock_history[0].pos.domain);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbFlipFrom16PromotesTo17) {
  // |level|=16 has suffix value (16-15)=1, LSB=1. Override LSB=0 would
  // normally decrement to mag=15 — but #505 boundary protection forces
  // +1 instead, sending |level|=17. Keeps the position at-or-above
  // walker threshold.
  RegisterMock({-1, 0});  // sign no-op, suffix→0
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 16;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(17, level);
  EXPECT_EQ(2u, g_mock_history_count);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN,        g_mock_history[0].pos.domain);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB,  g_mock_history[1].pos.domain);
  EXPECT_EQ(1, g_mock_history[1].original_bit);  // original LSB of |16-15|=1 is 1
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbFlipFrom17To18) {
  // |level|=17 has suffix value (17-15)=2, LSB=0. Override LSB=1 →
  // normal +1 increment to |level|=18 (no boundary special case here).
  RegisterMock({-1, 1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 17;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(18, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbPreservesNegativeSign) {
  // |level|=-17, override LSB=1 → |level|=18, sign preserved → -18.
  RegisterMock({-1, 1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = -17;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(-18, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, BothSignAndSuffixFireInOrder) {
  // Sign override + Suffix LSB override on the same coeff. With #505
  // threshold = 16, start at |level|=17 so suffix hook fires.
  RegisterMock({1, 1});  // sign→1 (negate), suffix→1 (flip LSB)
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 17;  // positive
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  // Sign first: 17 → -17. Suffix second on -17: |level|=17, LSB=0 →
  // flip to LSB=1 → |level|=18, sign preserved → -18.
  EXPECT_EQ(-18, level);
  EXPECT_EQ(2u, g_mock_history_count);
  TearDownMock();
}

TEST(PhasmCoeffHooks, InvalidReturnTreatedAsNoOp) {
  RegisterMock({2});  // not in {-1, 0, 1}
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level, /*stego=*/nullptr));
  EXPECT_EQ(5, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, PositionFieldsPopulatedCorrectly) {
  RegisterMock({-1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  phasm_apply_coeff_hooks(&pos, /*sub_block=*/11, /*coeff_idx=*/4, /*block_cat=*/2, &level, /*stego=*/nullptr);
  EXPECT_EQ(11,   g_mock_history[0].pos.sub_block);
  EXPECT_EQ(4,    g_mock_history[0].pos.coeff_idx);
  EXPECT_EQ(2,    g_mock_history[0].pos.block_cat);
  EXPECT_EQ(0xff, g_mock_history[0].pos.ref_idx);
  EXPECT_EQ(0xff, g_mock_history[0].pos.mv_component);
  EXPECT_EQ(3,    g_mock_history[0].pos.mb_x);  // from base pos template
  EXPECT_EQ(5,    g_mock_history[0].pos.mb_y);
  TearDownMock();
}

// =====================================================================
// Coefficient hooks: phasm_apply_coeff_hooks_dual (raster + zigzag)
// =====================================================================

TEST(PhasmCoeffHooksDual, NoOverrideLeavesBothUnchanged) {
  RegisterMock({-1, -1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 5, b = 5;
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b, /*stego=*/nullptr));
  EXPECT_EQ(5, a);
  EXPECT_EQ(5, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, SignFlipUpdatesBoth) {
  RegisterMock({1});  // sign override
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 5, b = 5;
  EXPECT_EQ(1, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b, /*stego=*/nullptr));
  EXPECT_EQ(-5, a);
  EXPECT_EQ(-5, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, MismatchedAliasesRefuses) {
  RegisterMock({1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 5, b = 6;  // intentionally desynced
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b, /*stego=*/nullptr));
  EXPECT_EQ(5, a);  // refused
  EXPECT_EQ(6, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, ZeroSkipsDispatch) {
  RegisterMock({1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 0, b = 0;
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b, /*stego=*/nullptr));
  EXPECT_EQ(0u, g_mock_history_count);
  TearDownMock();
}

// =====================================================================
// MVD hooks: phasm_apply_mvd_hooks
// =====================================================================

TEST(PhasmMvdHooks, NullCtxIsNoOp) {
  RegisterMock({1, 1, 1, 1});
  EXPECT_EQ(0, phasm_apply_mvd_hooks(nullptr));
  TearDownMock();
}

TEST(PhasmMvdHooks, ZeroMvdSkipsHookDispatch) {
  // mv == mvp → mvd == 0 → no hook should fire for that component.
  RegisterMock({1, 1, 1, 1});
  int16_t mvx = 5, mvy = 5;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  ctx.mvp_x_qpel = 5;
  ctx.mvp_y_qpel = 5;
  EXPECT_EQ(0, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(5, mvx);
  EXPECT_EQ(5, mvy);
  EXPECT_EQ(0u, g_mock_history_count);
  TearDownMock();
}

TEST(PhasmMvdHooks, SignFlipReflectsAroundMvp) {
  // mvp=10, mv=15 → mvd=+5. Sign flip → mvd=-5 → new mv=5.
  RegisterMock({1, -1, -1, -1});  // x: sign→1 (negate), no suffix domain since |mvd|<9
                                   // y: no-op (mvd=0)
  int16_t mvx = 15, mvy = 10;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  ctx.mvp_x_qpel = 10;
  ctx.mvp_y_qpel = 10;
  EXPECT_EQ(1, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(5,  mvx);  // 2*10 - 15 = 5
  EXPECT_EQ(10, mvy);
  TearDownMock();
}

TEST(PhasmMvdHooks, SuffixLsbFlipChangesMvdMagnitudeByOne) {
  // mvp=0, mv=9 → mvd=+9, |mvd|=9, suffix value=0, LSB=0.
  // Sign no-op; suffix LSB override → 1 → |mvd|=10 → mv=10.
  RegisterMock({-1, 1});
  int16_t mvx = 9, mvy = 0;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  EXPECT_EQ(1, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(10, mvx);
  EXPECT_EQ(0,  mvy);  // mvd=0 → no hook
  TearDownMock();
}

TEST(PhasmMvdHooks, PredSkipMvCollisionRefuses) {
  // mv=10, mvp=8 → mvd=+2. Sign flip → mv=6.
  // PredSkipMv=(6,0). The override would coincide → refuse.
  RegisterMock({1, -1});
  int16_t mvx = 10, mvy = 0;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  ctx.mvp_x_qpel            = 8;
  ctx.check_pskip_collision = 1;
  ctx.pred_skip_mv_x        = 6;
  ctx.pred_skip_mv_y        = 0;
  EXPECT_EQ(0, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(10, mvx);  // unchanged
  EXPECT_EQ(0,  mvy);
  TearDownMock();
}

TEST(PhasmMvdHooks, MvListPointerIsRefreshed) {
  RegisterMock({1, -1});
  int16_t mvx = 5, mvy = 0;
  int16_t list_x = 5, list_y = 0;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  ctx.mvList_x_qpel = &list_x;
  ctx.mvList_y_qpel = &list_y;
  EXPECT_EQ(1, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(-5, mvx);
  EXPECT_EQ(-5, list_x);  // sMvList refreshed in lockstep with mv
  TearDownMock();
}

TEST(PhasmMvdHooks, NullMvListPointerOnlyUpdatesPrimary) {
  RegisterMock({1, -1});
  int16_t mvx = 5, mvy = 0;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  // mvList_x_qpel + mvList_y_qpel default to nullptr.
  EXPECT_EQ(1, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(-5, mvx);
  TearDownMock();
}

TEST(PhasmMvdHooks, NoCallbackIsNoOp) {
  TearDownMock();  // ensure unregistered
  int16_t mvx = 5, mvy = 0;
  PhasmMvHookCtx ctx = MakeBaseMvCtx(&mvx, &mvy);
  EXPECT_EQ(0, phasm_apply_mvd_hooks(&ctx));
  EXPECT_EQ(5, mvx);
}

// =====================================================================
// PredSkipMv collision predicate
// =====================================================================

TEST(PhasmMvdCollision, ExactMatchTrue) {
  EXPECT_EQ(1, phasm_mvd_would_collide_with_pskip(4, 7, 4, 7));
}

TEST(PhasmMvdCollision, XDiffersFalse) {
  EXPECT_EQ(0, phasm_mvd_would_collide_with_pskip(4, 7, 5, 7));
}

TEST(PhasmMvdCollision, YDiffersFalse) {
  EXPECT_EQ(0, phasm_mvd_would_collide_with_pskip(4, 7, 4, 8));
}

// =====================================================================
// Dual-recon writeback helper (Phase C.8.2+)
// =====================================================================

namespace {

// Capture buffer for the dual_recon_observe callback. Records the last
// fire's geometry + a hash of the two pixel blocks so tests can verify
// the callback fired with consistent state.
struct DualReconCapture {
  uint32_t frame_num;
  uint16_t mb_x;
  uint16_t mb_y;
  uint8_t  plane;
  int32_t  pixel_x;
  int32_t  pixel_y;
  int32_t  block_w;
  int32_t  block_h;
  int32_t  src_stride;
  uint32_t clean_hash;
  uint32_t stego_hash;
  int      fire_count;
};

DualReconCapture g_capture = {};

extern "C" void mock_dual_recon_cb(uint32_t frame_num,
                                   uint16_t mb_x, uint16_t mb_y,
                                   uint8_t  plane,
                                   int32_t  pixel_x, int32_t pixel_y,
                                   int32_t  block_w, int32_t block_h,
                                   const uint8_t* clean_pixels,
                                   const uint8_t* stego_pixels,
                                   int32_t  src_stride,
                                   void* /*user_data*/) {
  g_capture.frame_num = frame_num;
  g_capture.mb_x      = mb_x;
  g_capture.mb_y      = mb_y;
  g_capture.plane     = plane;
  g_capture.pixel_x   = pixel_x;
  g_capture.pixel_y   = pixel_y;
  g_capture.block_w   = block_w;
  g_capture.block_h   = block_h;
  g_capture.src_stride= src_stride;
  // FNV-1a 32-bit over each block, row-by-row.
  uint32_t h_clean = 2166136261u;
  uint32_t h_stego = 2166136261u;
  for (int32_t y = 0; y < block_h; ++y) {
    const uint8_t* rc = clean_pixels + (size_t)y * (size_t)src_stride;
    const uint8_t* rs = stego_pixels + (size_t)y * (size_t)src_stride;
    for (int32_t x = 0; x < block_w; ++x) {
      h_clean = (h_clean ^ rc[x]) * 16777619u;
      h_stego = (h_stego ^ rs[x]) * 16777619u;
    }
  }
  g_capture.clean_hash = h_clean;
  g_capture.stego_hash = h_stego;
  g_capture.fire_count++;
}

void ResetDualReconCapture() {
  std::memset(&g_capture, 0, sizeof(g_capture));
}

}  // namespace

TEST(PhasmDualRecon, WritebackCopiesBothBuffersWhenSet) {
  // Pre-fill destination buffers with sentinel byte so we can detect
  // whether the writeback actually copied.
  constexpr int W = 16, H = 16, STRIDE = 32;
  uint8_t clean_dst[STRIDE * H];
  uint8_t stego_dst[STRIDE * H];
  std::memset(clean_dst, 0x55, sizeof(clean_dst));
  std::memset(stego_dst, 0x55, sizeof(stego_dst));

  uint8_t clean_src[W * H];
  uint8_t stego_src[W * H];
  for (int i = 0; i < W * H; ++i) {
    clean_src[i] = (uint8_t)(i & 0xFF);
    stego_src[i] = (uint8_t)((i + 0x80) & 0xFF);
  }

  phasm_dual_recon_writeback(/*mb_x*/ 0, /*mb_y*/ 0, /*plane*/ 0,
                             /*pixel_x*/ 0, /*pixel_y*/ 0,
                             /*block_w*/ W, /*block_h*/ H,
                             clean_dst, stego_dst, /*dst_stride*/ STRIDE,
                             clean_src, stego_src, /*src_stride*/ W);

  // Verify copy happened on both buffers.
  for (int y = 0; y < H; ++y) {
    for (int x = 0; x < W; ++x) {
      EXPECT_EQ(clean_src[y * W + x], clean_dst[y * STRIDE + x])
        << "clean mismatch at (" << x << "," << y << ")";
      EXPECT_EQ(stego_src[y * W + x], stego_dst[y * STRIDE + x])
        << "stego mismatch at (" << x << "," << y << ")";
    }
    // Out-of-block padding should still be sentinel.
    EXPECT_EQ(0x55, clean_dst[y * STRIDE + W]);
    EXPECT_EQ(0x55, stego_dst[y * STRIDE + W]);
  }
}

TEST(PhasmDualRecon, WritebackSkipsStegoWhenDstNull) {
  constexpr int W = 4, H = 4, STRIDE = 8;
  uint8_t clean_dst[STRIDE * H];
  std::memset(clean_dst, 0xAA, sizeof(clean_dst));

  uint8_t clean_src[W * H];
  uint8_t stego_src[W * H];
  for (int i = 0; i < W * H; ++i) {
    clean_src[i] = (uint8_t)(i + 1);
    stego_src[i] = (uint8_t)(i + 0x40);
  }

  // stego_dst = nullptr → only clean copy fires.
  phasm_dual_recon_writeback(0, 0, 0, 0, 0, W, H,
                             clean_dst, nullptr, STRIDE,
                             clean_src, stego_src, W);

  for (int y = 0; y < H; ++y) {
    for (int x = 0; x < W; ++x) {
      EXPECT_EQ(clean_src[y * W + x], clean_dst[y * STRIDE + x]);
    }
  }
}

TEST(PhasmDualRecon, ObserveCallbackFires) {
  ResetDualReconCapture();

  PhasmStegoCallbacks cbs;
  std::memset(&cbs, 0, sizeof(cbs));
  cbs.struct_size       = sizeof(cbs);
  cbs.dual_recon_observe= mock_dual_recon_cb;
  ASSERT_EQ(0, WelsRegisterPhasmStegoCallbacks(&cbs, nullptr));

  WelsStegoSetFrameNum(42);

  constexpr int W = 8, H = 8, STRIDE = 16;
  uint8_t clean_dst[STRIDE * H];
  uint8_t stego_dst[STRIDE * H];
  std::memset(clean_dst, 0, sizeof(clean_dst));
  std::memset(stego_dst, 0, sizeof(stego_dst));

  uint8_t clean_src[W * H];
  uint8_t stego_src[W * H];
  for (int i = 0; i < W * H; ++i) {
    clean_src[i] = (uint8_t)(i * 2);
    stego_src[i] = (uint8_t)(i * 2 + 1);
  }

  phasm_dual_recon_writeback(/*mb_x*/ 11, /*mb_y*/ 22, /*plane*/ 1,
                             /*pixel_x*/ 100, /*pixel_y*/ 200,
                             W, H,
                             clean_dst, stego_dst, STRIDE,
                             clean_src, stego_src, W);

  EXPECT_EQ(1, g_capture.fire_count);
  EXPECT_EQ(42u, g_capture.frame_num);
  EXPECT_EQ(11, g_capture.mb_x);
  EXPECT_EQ(22, g_capture.mb_y);
  EXPECT_EQ(1, g_capture.plane);
  EXPECT_EQ(100, g_capture.pixel_x);
  EXPECT_EQ(200, g_capture.pixel_y);
  EXPECT_EQ(W, g_capture.block_w);
  EXPECT_EQ(H, g_capture.block_h);
  // Clean and stego hashes differ — the callback got distinct buffers.
  EXPECT_NE(g_capture.clean_hash, g_capture.stego_hash);

  WelsRegisterPhasmStegoCallbacks(nullptr, nullptr);
}

TEST(PhasmDualRecon, ObserveCallbackOptional) {
  // With no callback registered, writeback must still do the memcpys
  // and complete without crashing.
  PhasmStegoCallbacks cbs;
  std::memset(&cbs, 0, sizeof(cbs));
  cbs.struct_size = sizeof(cbs);
  ASSERT_EQ(0, WelsRegisterPhasmStegoCallbacks(&cbs, nullptr));

  uint8_t dst_c[64], dst_s[64];
  std::memset(dst_c, 0, sizeof(dst_c));
  std::memset(dst_s, 0, sizeof(dst_s));
  uint8_t src_c[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t src_s[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

  phasm_dual_recon_writeback(0, 0, 0, 0, 0, 4, 4,
                             dst_c, dst_s, 8,
                             src_c, src_s, 4);

  EXPECT_EQ(1, dst_c[0]);
  EXPECT_EQ(16, dst_s[0]);

  WelsRegisterPhasmStegoCallbacks(nullptr, nullptr);
}
