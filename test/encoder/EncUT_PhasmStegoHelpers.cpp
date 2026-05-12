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
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, /*sub_block=*/0, /*coeff_idx=*/0, /*block_cat=*/0, &level));
  EXPECT_EQ(5, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, ZeroLevelSkipsHookDispatch) {
  RegisterMock({0, 1});  // would override if called
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 0;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
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
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
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
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(7, level);
  EXPECT_EQ(1u, g_mock_history_count);
  EXPECT_EQ(1, g_mock_history[0].original_bit);  // original sign of -7 is 1
  TearDownMock();
}

TEST(PhasmCoeffHooks, SignNoOpWhenOverrideMatches) {
  RegisterMock({0});  // already positive
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 7;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(7, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbFiresOnlyWhenAbsAtLeast15) {
  // |level|=14: no suffix domain → only sign domain dispatched.
  RegisterMock({-1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 14;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(1u, g_mock_history_count);  // only one (sign) call
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN, g_mock_history[0].pos.domain);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbFlipFrom15To16) {
  // |level|=15 has suffix value 0, LSB=0. Override LSB=1 → |level|=16.
  RegisterMock({-1, 1});  // sign no-op, suffix→1
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 15;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(16, level);
  EXPECT_EQ(2u, g_mock_history_count);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SIGN,        g_mock_history[0].pos.domain);
  EXPECT_EQ((uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB,  g_mock_history[1].pos.domain);
  EXPECT_EQ(0, g_mock_history[1].original_bit);  // original LSB of |15-15|=0 is 0
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbFlipFrom16To15PreservesNonZero) {
  RegisterMock({-1, 0});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 16;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(15, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, SuffixLsbPreservesNegativeSign) {
  RegisterMock({-1, 1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = -15;
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(-16, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, BothSignAndSuffixFireInOrder) {
  // Sign override + Suffix LSB override on the same coeff.
  RegisterMock({1, 1});  // sign→1 (negate), suffix→1 (flip LSB)
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 15;  // positive
  EXPECT_EQ(1, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  // Sign first: 15 → -15. Suffix second on -15: |level|=15, LSB=0 → flip to LSB=1
  // → |level|=16, sign preserved → -16.
  EXPECT_EQ(-16, level);
  EXPECT_EQ(2u, g_mock_history_count);
  TearDownMock();
}

TEST(PhasmCoeffHooks, InvalidReturnTreatedAsNoOp) {
  RegisterMock({2});  // not in {-1, 0, 1}
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  EXPECT_EQ(0, phasm_apply_coeff_hooks(&pos, 0, 0, 0, &level));
  EXPECT_EQ(5, level);
  TearDownMock();
}

TEST(PhasmCoeffHooks, PositionFieldsPopulatedCorrectly) {
  RegisterMock({-1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t level = 5;
  phasm_apply_coeff_hooks(&pos, /*sub_block=*/11, /*coeff_idx=*/4, /*block_cat=*/2, &level);
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
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b));
  EXPECT_EQ(5, a);
  EXPECT_EQ(5, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, SignFlipUpdatesBoth) {
  RegisterMock({1});  // sign override
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 5, b = 5;
  EXPECT_EQ(1, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b));
  EXPECT_EQ(-5, a);
  EXPECT_EQ(-5, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, MismatchedAliasesRefuses) {
  RegisterMock({1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 5, b = 6;  // intentionally desynced
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b));
  EXPECT_EQ(5, a);  // refused
  EXPECT_EQ(6, b);
  TearDownMock();
}

TEST(PhasmCoeffHooksDual, ZeroSkipsDispatch) {
  RegisterMock({1});
  PhasmStegoPos pos = MakeBasePos();
  int16_t a = 0, b = 0;
  EXPECT_EQ(0, phasm_apply_coeff_hooks_dual(&pos, 0, 0, 0, &a, &b));
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
