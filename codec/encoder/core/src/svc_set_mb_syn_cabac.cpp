/*!
 * \copy
 *     Copyright (c)  2009-2013, Cisco Systems
 *     All rights reserved.
 *
 *     Redistribution and use in source and binary forms, with or without
 *     modification, are permitted provided that the following conditions
 *     are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in
 *          the documentation and/or other materials provided with the
 *          distribution.
 *
 *     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *     "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *     LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *     FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *     COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *     INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *     BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *     CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *     LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *     ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *     POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * \file    svc_set_mb_syn_cabac.cpp
 *
 * \brief   wrtie cabac syntax
 *
 * \date    9/28/2014 Created
 *
 *************************************************************************************
 */
#include "svc_set_mb_syn.h"
#include "set_mb_syn_cabac.h"
#include "svc_enc_golomb.h"
#include "wels_stego_internal.h"  /* phasm_apply_bypass_bin_override (Phase 4.2) */

using namespace WelsEnc;

namespace {

static const uint16_t uiSignificantCoeffFlagOffset[5] = {0, 15, 29, 44, 47};
static const uint16_t uiLastCoeffFlagOffset[5] = {0, 15, 29, 44, 47};
static const uint16_t uiCoeffAbsLevelMinus1Offset[5] = {0, 10, 20, 30, 39};
static const uint16_t uiCodecBlockFlagOffset[5] = {0, 4, 8, 12, 16};

/* #538 Phase 4.5.d.1b — 4x4 zigzag scan table for emit-side
 * scratch-key conversion. Derived from WelsScan4x4DcAc_c in
 * encode_mb_aux.cpp: pLevel[scan_pos] = pDct[g_phasm_zigzag_scan[scan_pos]].
 * Used in WelsWriteBlockResidualCabac to map scan position → raster
 * sub-block index for DC-type blocks (LUMA_DC, CHROMA_DC), where the
 * "logical sub-block" the DC entry represents IS the raster sub-block
 * idx in the MB. Populate-side HOOK-A keys by raster sub-block idx;
 * this table lets emit produce the same key. */
static const uint8_t g_phasm_zigzag_scan_4x4[16] = {
  0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15
};

/* 2x2 chroma DC zigzag — identity (4 entries in raster order). */
static const uint8_t g_phasm_zigzag_scan_2x2[4] = { 0, 1, 2, 3 };

/* #538 Phase 4.6 + 4.7v3 — convert OpenH264's "cache offset" iIdx
 * (the value stored at g_kuiCache48CountScan4Idx[i] for the i-th
 * 4x4 block in encoding order over the MB) back to the Z-SCAN
 * block index `i` that populate-side hooks pass as `sub_block`.
 *
 * The cache is a 6x8 grid (LDC layout); luma 4x4 blocks live at
 * rows 1..4 cols 1..4 — but in Z-SCAN encoding order (the 4 4x4
 * blocks within each 8x8 quadrant come first, then the next 8x8
 * quadrant in Z order). Cb at rows 1..2 cols 6..7, Cr at rows
 * 4..5 cols 6..7 (Z-scan within plane is 2x2 = identity).
 *
 * Populate-side (HOOK-E in svc_encode_mb.cpp:486 passes uiI4x4Idx,
 * HOOK-F at :693 passes phasm_sb iterating 0..15) uses Z-SCAN i.
 * The Rust walker keys on `block_idx = pos.sub_block` opaquely
 * (see encoder_pos_to_phasm_position_key Luma4x4 branch); the
 * convention is Z-scan because that's what the encoder fires with.
 *
 * v2 (raster) was WRONG: at Z-scan index 11 (raster 13), 12 (raster
 * 10), 2 (raster 4), etc., the conversion produced raster but
 * populate uses Z-scan — keys diverged at 12 of 16 luma block
 * positions where Z-scan ≠ raster. 3 of the 4 residual diffs after
 * v2 chroma fixes were Luma4x4 at blocks 11 and 12.
 *
 * #538.4.7 plane bias: CHROMA_AC Cb → 0..3, Cr → 4..7 (encodes
 * plane in sub_block since phasm_scratch_slot doesn't index by
 * partition_idx for coeff domains). Populate mirrors via
 * apply_coeff_hooks_to_level's chroma plane-bias logic. */
static inline uint8_t phasm_cache_offset_to_block_idx(int32_t iIdx,
                                                       ECtxBlockCat eCtxBlockCat) {
  const int32_t row = iIdx / 8;
  const int32_t col = iIdx % 8;
  if (eCtxBlockCat == LUMA_AC || eCtxBlockCat == LUMA_4x4) {
    /* Z-scan over 8x8 quadrants (i ∈ 0..3 covers top-left, etc.).
     * Within each 8x8: Z-scan over its 4 4x4 blocks. */
    const int32_t big_row   = (row - 1) >> 1;
    const int32_t big_col   = (col - 1) >> 1;
    const int32_t small_row = (row - 1) & 1;
    const int32_t small_col = (col - 1) & 1;
    return (uint8_t)((big_row * 2 + big_col) * 4 + (small_row * 2 + small_col));
  }
  if (eCtxBlockCat == CHROMA_AC) {
    /* Chroma 4x4: Cb (rows 1-2) → plane=0, Cr (rows 4-5) → plane=1.
     * Within plane the 2x2 layout is identity Z-scan.
     * Plane-bias: Cb i=0..3, Cr i=4..7. */
    const int32_t is_cr = (row >= 4) ? 1 : 0;
    const int32_t start_row = is_cr ? 4 : 1;
    const int32_t i_within = (row - start_row) * 2 + (col - 6);
    return (uint8_t)(i_within + is_cr * 4);
  }
  /* DC types are not routed through this helper. */
  return (uint8_t)iIdx;
}

/* #538 Phase 4.4 — UEG bypass with phasm LSB override.
 *
 * Same emit sequence as WelsCabacEncodeUeBypass (set_mb_syn_cabac.cpp)
 * but the LAST bin emitted (the LSB of the suffix value, the k==0
 * iteration of the inner loop) routes through the wire-only override
 * hook. Used at the 2 stego-relevant UEG sites:
 *
 *   - MVD long-form suffix (UEG3): MvdSuffixLsb domain
 *   - Coeff level long-form suffix (UEG0): CoeffSuffixLsb domain
 *
 * Stub-only at this point: `phasm_apply_bypass_bin_override` returns
 * `orig_bin` unconditionally, so this is byte-identical to
 * WelsCabacEncodeUeBypass. Phase 4.5 wires the scratch backing.
 *
 * Note: when `uiVal == 0` (the iSufS < (1<<k) branch fires immediately
 * with k == iExpBits), the suffix emit collapses to a single 0 bin
 * followed by `iExpBits` zero bins; the k==0 iteration still emits
 * the LSB through the override hook. When `iExpBits == 0` the do-while
 * exits without entering the inner `while (k--)`, so no override fires
 * for that emit — see the dispatch comment at the call site.
 */
static inline void WelsCabacEncodeUeBypassWithPhasmLsbOverride (
    SCabacCtx* pCbCtx, int32_t iExpBits, uint32_t uiVal,
    uint8_t phasm_domain, const PhasmStegoPos* phasm_pos) {
  int32_t iSufS = (int32_t)uiVal;
  int32_t iStopLoop = 0;
  int32_t k = iExpBits;
  do {
    if (iSufS >= (1 << k)) {
      WelsCabacEncodeBypassOne (pCbCtx, 1);
      iSufS = iSufS - (1 << k);
      k++;
    } else {
      WelsCabacEncodeBypassOne (pCbCtx, 0);
      while (k--) {
        const int32_t orig_bin = (iSufS >> k) & 1;
        if (k == 0) {
          /* LSB iteration — route through phasm hook. */
          const int phasm_bin = phasm_apply_bypass_bin_override (
              phasm_domain, phasm_pos, (int)orig_bin, pCbCtx->pPhasmStego);
          WelsCabacEncodeBypassOne (pCbCtx, phasm_bin);
        } else {
          WelsCabacEncodeBypassOne (pCbCtx, orig_bin);
        }
      }
      iStopLoop = 1;
    }
  } while (!iStopLoop);
}


static void WelsCabacMbType (SCabacCtx* pCabacCtx, SMB* pCurMb, SMbCache* pMbCache, int32_t iMbWidth,
                             EWelsSliceType eSliceType) {

  if (eSliceType == I_SLICE) {
    uint32_t uiNeighborAvail = pCurMb->uiNeighborAvail;
    SMB* pLeftMb = pCurMb - 1 ;
    SMB* pTopMb = pCurMb - iMbWidth;
    int32_t iCtx = 3;
    if ((uiNeighborAvail & LEFT_MB_POS) && !IS_INTRA4x4 (pLeftMb->uiMbType))
      iCtx++;
    if ((uiNeighborAvail & TOP_MB_POS) && !IS_INTRA4x4 (pTopMb->uiMbType))  //TOP MB
      iCtx++;

    if (pCurMb->uiMbType == MB_TYPE_INTRA4x4) {
      WelsCabacEncodeDecision (pCabacCtx, iCtx, 0);
    } else {
      int32_t iCbpChroma = pCurMb->uiCbp >> 4;
      int32_t iCbpLuma   = pCurMb->uiCbp & 15;
      int32_t iPredMode = g_kiMapModeI16x16[pMbCache->uiLumaI16x16Mode];

      WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
      WelsCabacEncodeTerminate (pCabacCtx, 0);
      if (iCbpLuma)
        WelsCabacEncodeDecision (pCabacCtx, 6, 1);
      else
        WelsCabacEncodeDecision (pCabacCtx, 6, 0);

      if (iCbpChroma == 0)
        WelsCabacEncodeDecision (pCabacCtx, 7, 0);
      else {
        WelsCabacEncodeDecision (pCabacCtx, 7, 1);
        WelsCabacEncodeDecision (pCabacCtx, 8, iCbpChroma >> 1);
      }
      WelsCabacEncodeDecision (pCabacCtx, 9, iPredMode >> 1);
      WelsCabacEncodeDecision (pCabacCtx, 10, iPredMode & 1);
    }
  } else if (eSliceType == P_SLICE) {
    uint32_t uiMbType = pCurMb->uiMbType;
    if (uiMbType == MB_TYPE_16x16) {
      WelsCabacEncodeDecision (pCabacCtx, 14, 0);
      WelsCabacEncodeDecision (pCabacCtx, 15, 0);
      WelsCabacEncodeDecision (pCabacCtx, 16, 0);
    } else if ((uiMbType == MB_TYPE_16x8) || (uiMbType == MB_TYPE_8x16)) {

      WelsCabacEncodeDecision (pCabacCtx, 14, 0);
      WelsCabacEncodeDecision (pCabacCtx, 15, 1);
      WelsCabacEncodeDecision (pCabacCtx, 17, pCurMb->uiMbType == MB_TYPE_16x8);

    } else if ((uiMbType  == MB_TYPE_8x8) || (uiMbType  == MB_TYPE_8x8_REF0)) {
      WelsCabacEncodeDecision (pCabacCtx, 14, 0);
      WelsCabacEncodeDecision (pCabacCtx, 15, 0);
      WelsCabacEncodeDecision (pCabacCtx, 16, 1);
    } else if (pCurMb->uiMbType == MB_TYPE_INTRA4x4) {
      WelsCabacEncodeDecision (pCabacCtx, 14, 1);
      WelsCabacEncodeDecision (pCabacCtx, 17, 0);
    } else {

      int32_t iCbpChroma = pCurMb->uiCbp >> 4;
      int32_t iCbpLuma   = pCurMb->uiCbp & 15;
      int32_t iPredMode = g_kiMapModeI16x16[pMbCache->uiLumaI16x16Mode];
      //prefix
      WelsCabacEncodeDecision (pCabacCtx, 14, 1);

      //suffix
      WelsCabacEncodeDecision (pCabacCtx, 17, 1);
      WelsCabacEncodeTerminate (pCabacCtx, 0);
      if (iCbpLuma)
        WelsCabacEncodeDecision (pCabacCtx, 18, 1);
      else
        WelsCabacEncodeDecision (pCabacCtx, 18, 0);
      if (iCbpChroma == 0)
        WelsCabacEncodeDecision (pCabacCtx, 19, 0);
      else {
        WelsCabacEncodeDecision (pCabacCtx, 19, 1);
        WelsCabacEncodeDecision (pCabacCtx, 19, iCbpChroma >> 1);
      }
      WelsCabacEncodeDecision (pCabacCtx, 20, iPredMode >> 1);
      WelsCabacEncodeDecision (pCabacCtx, 20, iPredMode & 1);

    }
  }

}
void WelsCabacMbIntra4x4PredMode (SCabacCtx* pCabacCtx, SMbCache* pMbCache) {

  for (int32_t iMode = 0; iMode < 16; iMode++) {

    bool bPredFlag = pMbCache->pPrevIntra4x4PredModeFlag[iMode];
    int8_t iRemMode  = pMbCache->pRemIntra4x4PredModeFlag[iMode];

    if (bPredFlag)
      WelsCabacEncodeDecision (pCabacCtx, 68, 1);
    else {
      WelsCabacEncodeDecision (pCabacCtx, 68, 0);

      WelsCabacEncodeDecision (pCabacCtx, 69, iRemMode & 0x01);
      WelsCabacEncodeDecision (pCabacCtx, 69, (iRemMode >> 1) & 0x01);
      WelsCabacEncodeDecision (pCabacCtx, 69, (iRemMode >> 2));
    }
  }
}

void WelsCabacMbIntraChromaPredMode (SCabacCtx* pCabacCtx, SMB* pCurMb, SMbCache* pMbCache, int32_t iMbWidth) {
  uint32_t uiNeighborAvail = pCurMb->uiNeighborAvail;
  SMB* pLeftMb = pCurMb - 1 ;
  SMB* pTopMb = pCurMb - iMbWidth;

  int32_t iPredMode = g_kiMapModeIntraChroma[pMbCache->uiChmaI8x8Mode];
  int32_t iCtx = 64;
  if ((uiNeighborAvail & LEFT_MB_POS) && g_kiMapModeIntraChroma[pLeftMb->uiChromPredMode] != 0)
    iCtx++;
  if ((uiNeighborAvail & TOP_MB_POS) && g_kiMapModeIntraChroma[pTopMb->uiChromPredMode] != 0)
    iCtx++;

  if (iPredMode == 0) {
    WelsCabacEncodeDecision (pCabacCtx, iCtx, 0);
  } else if (iPredMode == 1) {
    WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
    WelsCabacEncodeDecision (pCabacCtx, 67, 0);
  } else if (iPredMode == 2) {
    WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
    WelsCabacEncodeDecision (pCabacCtx, 67, 1);
    WelsCabacEncodeDecision (pCabacCtx, 67, 0);
  } else {
    WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
    WelsCabacEncodeDecision (pCabacCtx, 67, 1);
    WelsCabacEncodeDecision (pCabacCtx, 67, 1);
  }
}

void WelsCabacMbCbp (SMB* pCurMb, int32_t iMbWidth, SCabacCtx* pCabacCtx) {
  int32_t iCbpBlockLuma[4] = { (pCurMb->uiCbp) & 1, (pCurMb->uiCbp >> 1) & 1, (pCurMb->uiCbp >> 2) & 1, (pCurMb->uiCbp >> 3) & 1};
  int32_t iCbpChroma = pCurMb->uiCbp >> 4;
  int32_t iCbpBlockLeft[4] = {0, 0, 0, 0};
  int32_t iCbpBlockTop[4] = {0, 0, 0, 0};
  int32_t iCbpLeftChroma  = 0;
  int32_t iCbpTopChroma = 0;
  int32_t iCbp = 0;
  int32_t iCtx = 0;
  uint32_t uiNeighborAvail = pCurMb->uiNeighborAvail;
  if (uiNeighborAvail & LEFT_MB_POS) {
    iCbp = (pCurMb - 1)->uiCbp;
    iCbpBlockLeft[0] = ! (iCbp & 1);
    iCbpBlockLeft[1] = ! ((iCbp >> 1) & 1);
    iCbpBlockLeft[2] = ! ((iCbp >> 2) & 1);
    iCbpBlockLeft[3] = ! ((iCbp >> 3) & 1);
    iCbpLeftChroma = iCbp >> 4;
    if (iCbpLeftChroma)
      iCtx += 1;
  }
  if (uiNeighborAvail & TOP_MB_POS) {
    iCbp = (pCurMb - iMbWidth)->uiCbp;
    iCbpBlockTop[0] = ! (iCbp & 1);
    iCbpBlockTop[1] = ! ((iCbp >> 1) & 1);
    iCbpBlockTop[2] = ! ((iCbp >> 2) & 1);
    iCbpBlockTop[3] = ! ((iCbp >> 3) & 1);
    iCbpTopChroma = iCbp >> 4;
    if (iCbpTopChroma)
      iCtx += 2;
  }
  WelsCabacEncodeDecision (pCabacCtx, 73 + iCbpBlockLeft[1] + iCbpBlockTop[2] * 2, iCbpBlockLuma[0]);
  WelsCabacEncodeDecision (pCabacCtx, 73 + !iCbpBlockLuma[0] + iCbpBlockTop[3] * 2, iCbpBlockLuma[1]);
  WelsCabacEncodeDecision (pCabacCtx, 73 + iCbpBlockLeft[3] + (!iCbpBlockLuma[0]) * 2 , iCbpBlockLuma[2]);
  WelsCabacEncodeDecision (pCabacCtx, 73 + !iCbpBlockLuma[2] + (!iCbpBlockLuma[1]) * 2, iCbpBlockLuma[3]);


  //chroma
  if (iCbpChroma) {
    WelsCabacEncodeDecision (pCabacCtx, 77 + iCtx, 1);
    WelsCabacEncodeDecision (pCabacCtx, 81 + (iCbpLeftChroma >> 1) + ((iCbpTopChroma >> 1) * 2), iCbpChroma > 1);
  } else {
    WelsCabacEncodeDecision (pCabacCtx, 77 + iCtx, 0);
  }
}

void WelsCabacMbDeltaQp (SMB* pCurMb, SCabacCtx* pCabacCtx, bool bFirstMbInSlice) {
  SMB* pPrevMb = NULL;
  int32_t iCtx = 0;

  if (!bFirstMbInSlice) {
    pPrevMb = pCurMb - 1;
    pCurMb->iLumaDQp = pCurMb->uiLumaQp - pPrevMb->uiLumaQp;

    if (IS_SKIP (pPrevMb->uiMbType) || ((pPrevMb->uiMbType != MB_TYPE_INTRA16x16) && (!pPrevMb->uiCbp))
        || (!pPrevMb->iLumaDQp))
      iCtx = 0;
    else
      iCtx = 1;
  }

  if (pCurMb->iLumaDQp) {
    int32_t iValue = pCurMb->iLumaDQp < 0 ? (-2 * pCurMb->iLumaDQp) : (2 * pCurMb->iLumaDQp - 1);
    WelsCabacEncodeDecision (pCabacCtx, 60 + iCtx, 1);
    if (iValue == 1) {
      WelsCabacEncodeDecision (pCabacCtx, 60 + 2, 0);
    } else {
      WelsCabacEncodeDecision (pCabacCtx, 60 + 2, 1);
      iValue--;
      while ((--iValue) > 0)
        WelsCabacEncodeDecision (pCabacCtx, 60 + 3, 1);
      WelsCabacEncodeDecision (pCabacCtx, 60 + 3, 0);
    }
  } else {
    WelsCabacEncodeDecision (pCabacCtx, 60 + iCtx, 0);
  }
}

void WelsMbSkipCabac (SCabacCtx* pCabacCtx, SMB* pCurMb, int32_t iMbWidth, EWelsSliceType eSliceType,
                      int16_t bSkipFlag) {
  int32_t iCtx = (eSliceType == P_SLICE) ? 11 : 24;
  uint32_t uiNeighborAvail = pCurMb->uiNeighborAvail;
  if (uiNeighborAvail & LEFT_MB_POS) { //LEFT MB
    if (!IS_SKIP ((pCurMb - 1)->uiMbType))
      iCtx++;
  }
  if (uiNeighborAvail & TOP_MB_POS) { //TOP MB
    if (!IS_SKIP ((pCurMb - iMbWidth)->uiMbType))
      iCtx++;
  }
  WelsCabacEncodeDecision (pCabacCtx, iCtx, bSkipFlag);

  if (bSkipFlag) {
    for (int  i = 0; i < 16; i++) {
      pCurMb->sMvd[i].iMvX = 0;
      pCurMb->sMvd[i].iMvY = 0;
    }
    pCurMb->uiCbp = pCurMb->iCbpDc  = 0;
  }
}

void WelsCabacMbRef (SCabacCtx* pCabacCtx, SMB* pCurMb, SMbCache* pMbCache, int16_t iIdx) {
  SMVComponentUnit* pMvComp = &pMbCache->sMvComponents;
  const int16_t iRefIdxA = pMvComp->iRefIndexCache[iIdx + 6];
  const int16_t iRefIdxB = pMvComp->iRefIndexCache[iIdx + 1];
  int16_t iRefIdx  = pMvComp->iRefIndexCache[iIdx + 7];
  int16_t iCtx  = 0;

  if ((iRefIdxA > 0) && (!pMbCache->bMbTypeSkip[3]))
    iCtx++;
  if ((iRefIdxB > 0) && (!pMbCache->bMbTypeSkip[1]))
    iCtx += 2;

  while (iRefIdx > 0) {
    WelsCabacEncodeDecision (pCabacCtx, 54 + iCtx, 1);
    iCtx = (iCtx >> 2) + 4;
    iRefIdx--;
  }
  WelsCabacEncodeDecision (pCabacCtx, 54 + iCtx, 0);
}

/* #538 Phase 4.3 — MvdSign wire-only override.
 *
 * Extended signature: pCurMb_iMbX / pCurMb_iMbY / partition_idx /
 * mv_component thread the position context from the call site
 * (WelsCabacMbMvd, two levels up) into the bypass-bin emit so the
 * hook can build a complete PhasmStegoPos. The function stays
 * `inline` — same compiler treatment, just more registers.
 *
 * Stub (`phasm_apply_bypass_bin_override`) returns `orig_bin`
 * unconditionally; byte-identical to pre-Phase-4.3. */
/* #549 Bug 5 fix (2026-05-19): renamed `phasm_partition_idx` to
 * `phasm_partition_id` to signal the new contract: callers pass the
 * H.264 spec `mbPartIdx * 4 + subMbPartIdx` (0..15, packed) instead
 * of the raster 4x4 index of the partition's top-left block. The
 * walker side (pure-Rust `decode_one_mvd_pair_p` /
 * `decode_sub_mb_mvds`) uses the same spec convention, so the
 * orchestrator's `enc_pre_emit` key lookup now matches without any
 * additional translation. `i4x4ScanIdx` is no longer overloaded for
 * the hook identifier — `WelsCabacMbMvd`'s neighbour lookups still
 * use it, but it no longer doubles as the partition_id. */
inline void WelsCabacMbMvdLx (SCabacCtx* pCabacCtx, int32_t sMvd, int32_t iCtx, int32_t iPredMvd,
                              uint16_t phasm_mb_x, uint16_t phasm_mb_y,
                              uint8_t  phasm_partition_id, uint8_t phasm_mv_component) {
  const int32_t iAbsMvd = WELS_ABS (sMvd);
  int32_t iCtxInc = 0;
  int32_t iPrefix = WELS_MIN (iAbsMvd, 9);
  int32_t i = 0;

  if (iPredMvd > 32)
    iCtxInc += 2;
  else if (iPredMvd > 2)
    iCtxInc += 1;

  if (iPrefix) {
    PhasmStegoPos phasm_pos;
    phasm_pos.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos.mb_x          = phasm_mb_x;
    phasm_pos.mb_y          = phasm_mb_y;
    phasm_pos.partition_idx = phasm_partition_id;
    phasm_pos.sub_block     = 0xff;
    phasm_pos.coeff_idx     = 0xff;
    phasm_pos.block_cat     = 0xff;
    phasm_pos.ref_idx       = 0;
    phasm_pos.mv_component  = phasm_mv_component;
    phasm_pos.domain        = (uint8_t)PHASM_DOMAIN_MVD_SIGN;
    phasm_pos._reserved     = 0;
    const int phasm_orig_sign = (sMvd < 0) ? 1 : 0;
    if (iPrefix < 9) {
      WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 1);
      iCtxInc = 3;
      for (i = 0; i < iPrefix - 1; i++) {
        WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 1);
        if (i < 3)
          iCtxInc++;
      }
      WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 0);
      const int phasm_bin = phasm_apply_bypass_bin_override (
          (uint8_t)PHASM_DOMAIN_MVD_SIGN, &phasm_pos, phasm_orig_sign, pCabacCtx->pPhasmStego);
      WelsCabacEncodeBypassOne (pCabacCtx, phasm_bin);
    } else {
      WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 1);
      iCtxInc = 3;
      for (i = 0; i < (9 - 1); i++) {
        WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 1);
        if (i < 3)
          iCtxInc++;
      }
      /* #538 Phase 4.4 — MvdSuffixLsb wire-only override.
       *
       * UEG3 suffix for long-form |MVD|>=9. The LSB of the suffix
       * value (uiVal = iAbsMvd - 9) becomes the |MVD| LSB on the
       * wire, which is the cover bit phasm's MvdSuffixLsb domain
       * targets. Stub returns orig_bin -> byte-identical. */
      PhasmStegoPos phasm_pos_msl = phasm_pos;
      phasm_pos_msl.domain = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
      WelsCabacEncodeUeBypassWithPhasmLsbOverride (
          pCabacCtx, 3, (uint32_t)(iAbsMvd - 9),
          (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB, &phasm_pos_msl);
      const int phasm_bin = phasm_apply_bypass_bin_override (
          (uint8_t)PHASM_DOMAIN_MVD_SIGN, &phasm_pos, phasm_orig_sign, pCabacCtx->pPhasmStego);
      WelsCabacEncodeBypassOne (pCabacCtx, phasm_bin);
    }
  } else {
    WelsCabacEncodeDecision (pCabacCtx, iCtx + iCtxInc, 0);
  }
}
SMVUnitXY WelsCabacMbMvd (SCabacCtx* pCabacCtx, SMB* pCurMb, uint32_t iMbWidth,
                          SMVUnitXY sCurMv, SMVUnitXY sPredMv, int16_t i4x4ScanIdx,
                          uint8_t phasm_partition_id) {
  /* #549 Bug 5 fix (2026-05-19): `i4x4ScanIdx` keeps its OpenH264
   * meaning — raster 4x4 index, used for sMvd neighbour lookups
   * below. `phasm_partition_id` is the new spec partition_id
   * (mbPartIdx*4 + subMbPartIdx) passed straight to the hook. */
  uint32_t iAbsMvd0, iAbsMvd1;
  uint8_t uiNeighborAvail = pCurMb->uiNeighborAvail;
  SMVUnitXY sMvd;
  SMVUnitXY sMvdLeft;
  SMVUnitXY sMvdTop;

  sMvdLeft.iMvX = sMvdLeft.iMvY = sMvdTop.iMvX = sMvdTop.iMvY = 0;
  sMvd.sDeltaMv (sCurMv, sPredMv);
  if ((i4x4ScanIdx < 4) && (uiNeighborAvail & TOP_MB_POS)) { //top row blocks
    sMvdTop.sAssignMv ((pCurMb - iMbWidth)->sMvd[i4x4ScanIdx + 12]);
  } else if (i4x4ScanIdx >= 4) {
    sMvdTop.sAssignMv (pCurMb->sMvd[i4x4ScanIdx - 4]);
  }
  if ((! (i4x4ScanIdx & 0x03)) && (uiNeighborAvail & LEFT_MB_POS)) { //left column blocks
    sMvdLeft.sAssignMv ((pCurMb - 1)->sMvd[i4x4ScanIdx + 3]);
  } else if (i4x4ScanIdx & 0x03) {
    sMvdLeft.sAssignMv (pCurMb->sMvd[i4x4ScanIdx - 1]);
  }

  iAbsMvd0 = WELS_ABS (sMvdLeft.iMvX) + WELS_ABS (sMvdTop.iMvX);
  iAbsMvd1 = WELS_ABS (sMvdLeft.iMvY) + WELS_ABS (sMvdTop.iMvY);

  /* #549 Bug 5: forward the H.264-spec partition_id, NOT i4x4ScanIdx.
   * Walker and encoder now agree on this value. See WelsCabacMbMvdLx
   * doc-comment for the convention. */
  WelsCabacMbMvdLx (pCabacCtx, sMvd.iMvX, 40, iAbsMvd0,
                    (uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY,
                    phasm_partition_id, /*mv_component=*/0);
  WelsCabacMbMvdLx (pCabacCtx, sMvd.iMvY, 47, iAbsMvd1,
                    (uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY,
                    phasm_partition_id, /*mv_component=*/1);

  /* CASCADE.V2 §A.1.10b — keep the neighbour mvd ctxIdxInc cache symmetric
   * with the decoder. A wire-only MvdSuffixLsb override changes the |MVD|
   * the DECODER reads (±1); that |MVD| then feeds the NEXT MB's mvd bin0
   * ctxIdxInc (|sMvdLeft|+|sMvdTop| vs the 32 threshold). wire_only did NOT
   * mutate the MV, so the encoder's sMvd cache would otherwise hold the
   * pre-override magnitude and the two sides pick different CABAC contexts →
   * desync (the iphone7 "cascade ceiling"). Store the OVERRIDDEN magnitude in
   * the returned sMvd (→ pCurMb->sMvd[]). Context-only: sCurMv still holds the
   * true MV, so MC / PMV / reconstruction are untouched — no predictor
   * cascade. Mirrors the pure-Rust path (encoder_hook.rs:158-163). No-ops when
   * no override fired (emitted == orig_lsb) → byte-identical without stego. */
  {
    int32_t aphasm_mvd[2] = { sMvd.iMvX, sMvd.iMvY };
    for (int aphasm_c = 0; aphasm_c < 2; ++aphasm_c) {
      const int32_t aphasm_abs = WELS_ABS (aphasm_mvd[aphasm_c]);
      if (aphasm_abs < 9) continue;
      PhasmStegoPos aphasm_pos;
      aphasm_pos.frame_num     = PhasmStegoGetFrameNum();
      aphasm_pos.mb_x          = (uint16_t)pCurMb->iMbX;
      aphasm_pos.mb_y          = (uint16_t)pCurMb->iMbY;
      aphasm_pos.partition_idx = phasm_partition_id;
      aphasm_pos.sub_block     = 0xff;
      aphasm_pos.coeff_idx     = 0xff;
      aphasm_pos.block_cat     = 0xff;
      aphasm_pos.ref_idx       = 0;
      aphasm_pos.mv_component  = (uint8_t)aphasm_c;
      aphasm_pos.domain        = (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB;
      aphasm_pos._reserved     = 0;
      const int32_t aphasm_orig_lsb = (aphasm_abs - 9) & 1;
      const int32_t aphasm_emitted = phasm_apply_bypass_bin_override (
          (uint8_t)PHASM_DOMAIN_MVD_SUFFIX_LSB, &aphasm_pos, aphasm_orig_lsb, pCabacCtx->pPhasmStego);
      if (aphasm_emitted != aphasm_orig_lsb) {
        const int32_t aphasm_new = (aphasm_orig_lsb == 0) ? (aphasm_abs + 1)
                                                          : (aphasm_abs - 1);
        aphasm_mvd[aphasm_c] = (aphasm_mvd[aphasm_c] < 0) ? -aphasm_new
                                                          :  aphasm_new;
      }
    }
    sMvd.iMvX = aphasm_mvd[0];
    sMvd.iMvY = aphasm_mvd[1];
  }
  return sMvd;
}
static void WelsCabacSubMbType (SCabacCtx* pCabacCtx, SMB* pCurMb) {
  for (int32_t i8x8Idx = 0; i8x8Idx < 4; ++i8x8Idx) {
    uint32_t uiSubMbType = pCurMb->uiSubMbType[i8x8Idx];
    if (SUB_MB_TYPE_8x8 == uiSubMbType) {
      WelsCabacEncodeDecision (pCabacCtx, 21, 1);
      continue;
    }
    WelsCabacEncodeDecision (pCabacCtx, 21, 0);
    if (SUB_MB_TYPE_8x4 == uiSubMbType) {
      WelsCabacEncodeDecision (pCabacCtx, 22, 0);
    } else {
      WelsCabacEncodeDecision (pCabacCtx, 22, 1);
      WelsCabacEncodeDecision (pCabacCtx, 23, SUB_MB_TYPE_4x8 == uiSubMbType);
    }
  } //for
}

static void WelsCabacSubMbMvd (SCabacCtx* pCabacCtx, SMB* pCurMb, SMbCache* pMbCache, const int kiMbWidth) {
  SMVUnitXY sMvd;
  int32_t i8x8Idx, i4x4ScanIdx;
  /* #549 Bug 5 fix (2026-05-19): each WelsCabacMbMvd call now also
   * receives phasm_partition_id = mbPartIdx * 4 + subMbPartIdx, where
   * mbPartIdx == i8x8Idx for P_8x8 and subMbPartIdx is the index
   * within the 8x8 (0 for SUB_8x8; 0..1 for SUB_8x4/SUB_4x8; 0..3
   * for SUB_4x4). The walker's `decode_sub_mb_mvds` uses the same
   * formula via its `p()` helper. */
  for (i8x8Idx = 0; i8x8Idx < 4; ++i8x8Idx) {
    uint32_t uiSubMbType = pCurMb->uiSubMbType[i8x8Idx];
    if (SUB_MB_TYPE_8x8 == uiSubMbType) {
      i4x4ScanIdx = g_kuiMbCountScan4Idx[i8x8Idx << 2];
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, kiMbWidth, pCurMb->sMv[i4x4ScanIdx], pMbCache->sMbMvp[i4x4ScanIdx],
                             i4x4ScanIdx, (uint8_t)(i8x8Idx * 4 + 0));
      pCurMb->sMvd[    i4x4ScanIdx].sAssignMv (sMvd);
      pCurMb->sMvd[1 + i4x4ScanIdx].sAssignMv (sMvd);
      pCurMb->sMvd[4 + i4x4ScanIdx].sAssignMv (sMvd);
      pCurMb->sMvd[5 + i4x4ScanIdx].sAssignMv (sMvd);
    } else if (SUB_MB_TYPE_4x4 == uiSubMbType) {
      for (int32_t i4x4Idx = 0; i4x4Idx < 4; ++i4x4Idx) {
        i4x4ScanIdx = g_kuiMbCountScan4Idx[ (i8x8Idx << 2) + i4x4Idx];
        sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, kiMbWidth, pCurMb->sMv[i4x4ScanIdx], pMbCache->sMbMvp[i4x4ScanIdx],
                               i4x4ScanIdx, (uint8_t)(i8x8Idx * 4 + i4x4Idx));
        pCurMb->sMvd[i4x4ScanIdx].sAssignMv (sMvd);
      }
    } else if (SUB_MB_TYPE_8x4 == uiSubMbType) {
      for (int32_t i8x4Idx = 0; i8x4Idx < 2; ++i8x4Idx) {
        i4x4ScanIdx = g_kuiMbCountScan4Idx[ (i8x8Idx << 2) + (i8x4Idx << 1)];
        sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, kiMbWidth, pCurMb->sMv[i4x4ScanIdx], pMbCache->sMbMvp[i4x4ScanIdx],
                               i4x4ScanIdx, (uint8_t)(i8x8Idx * 4 + i8x4Idx));
        pCurMb->sMvd[    i4x4ScanIdx].sAssignMv (sMvd);
        pCurMb->sMvd[1 + i4x4ScanIdx].sAssignMv (sMvd);
      }
    } else if (SUB_MB_TYPE_4x8 == uiSubMbType) {
      for (int32_t i4x8Idx = 0; i4x8Idx < 2; ++i4x8Idx) {
        i4x4ScanIdx = g_kuiMbCountScan4Idx[ (i8x8Idx << 2) + i4x8Idx];
        sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, kiMbWidth, pCurMb->sMv[i4x4ScanIdx], pMbCache->sMbMvp[i4x4ScanIdx],
                               i4x4ScanIdx, (uint8_t)(i8x8Idx * 4 + i4x8Idx));
        pCurMb->sMvd[    i4x4ScanIdx].sAssignMv (sMvd);
        pCurMb->sMvd[4 + i4x4ScanIdx].sAssignMv (sMvd);
      }
    }
  }
}

int16_t WelsGetMbCtxCabac (SMbCache* pMbCache, SMB* pCurMb, uint32_t iMbWidth, ECtxBlockCat eCtxBlockCat,
                           int16_t iIdx) {
  int16_t iNzA = -1, iNzB = -1;
  int8_t* pNonZeroCoeffCount = pMbCache->iNonZeroCoeffCount;
  int32_t bIntra = IS_INTRA (pCurMb->uiMbType);
  int32_t iCtxInc = 0;
  switch (eCtxBlockCat) {
  case LUMA_AC:
  case CHROMA_AC:
  case LUMA_4x4:
    iNzA = pNonZeroCoeffCount[iIdx - 1];
    iNzB = pNonZeroCoeffCount[iIdx - 8];
    break;
  case LUMA_DC:
  case CHROMA_DC:
    if (pCurMb->uiNeighborAvail & LEFT_MB_POS)
      iNzA = (pCurMb - 1)->iCbpDc & (1 << iIdx);
    if (pCurMb->uiNeighborAvail & TOP_MB_POS)
      iNzB = (pCurMb - iMbWidth)->iCbpDc & (1 << iIdx);
    break;
  default:
    break;
  }
  if (((iNzA == -1) && bIntra) || (iNzA > 0))
    iCtxInc += 1;
  if (((iNzB == -1) && bIntra) || (iNzB > 0))
    iCtxInc += 2;
  return 85 + uiCodecBlockFlagOffset[eCtxBlockCat] + iCtxInc;
}

void  WelsWriteBlockResidualCabac (SMbCache* pMbCache, SMB* pCurMb, uint32_t iMbWidth, SCabacCtx* pCabacCtx,
                                   ECtxBlockCat eCtxBlockCat, int16_t  iIdx, int16_t iNonZeroCount, int16_t* pBlock, int16_t iEndIdx) {
  int32_t iCtx = WelsGetMbCtxCabac (pMbCache, pCurMb, iMbWidth, eCtxBlockCat, iIdx);
  if (iNonZeroCount) {
    int16_t iLevel[16];
    /* #538 Phase 4.5.d.1 — parallel scan-position tracking for the
     * compressed iLevel[] array. iLevel[k] = pBlock[scan_pos_k]; the
     * scratch-table emit hooks below need scan_pos_k (not k) as the
     * canonical coeff_idx key so populate-side hooks can target it
     * via inverse-zigzag in 4.5.d.2+. Per-block_cat semantics:
     *   LUMA_DC   : scan_pos = raster idx in 4x4 DC vector (no scan
     *               applied by the encoder for DC pre-Hadamard? — the
     *               scan_position here is the position WelsWriteBlockResidualCabac
     *               iterates over pBlock[i]; that's where the canonical
     *               key lives regardless of upstream raster/scan ops).
     *   LUMA_AC   : scan_pos = 1..15 (DC skipped, iStartIdx=1)
     *   LUMA_4x4  : scan_pos = 0..15
     *   CHROMA_DC : scan_pos = 0..3 (2x2 DC vector)
     *   CHROMA_AC : scan_pos = 1..15
     */
    int32_t iLevelScanPos[16];
    const int32_t iCtxSig = 105 + uiSignificantCoeffFlagOffset[eCtxBlockCat];
    const int32_t iCtxLast = 166 + uiLastCoeffFlagOffset[eCtxBlockCat];
    const int32_t iCtxLevel = 227 + uiCoeffAbsLevelMinus1Offset[eCtxBlockCat];
    int32_t iNonZeroIdx = 0;
    int32_t i = 0;

    WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
    while (1) {
      if (pBlock[i]) {
        iLevel[iNonZeroIdx]        = pBlock[i];
        iLevelScanPos[iNonZeroIdx] = i;

        iNonZeroIdx++;
        WelsCabacEncodeDecision (pCabacCtx, iCtxSig + i, 1);
        if (iNonZeroIdx != iNonZeroCount)
          WelsCabacEncodeDecision (pCabacCtx, iCtxLast + i, 0);
        else {
          WelsCabacEncodeDecision (pCabacCtx, iCtxLast + i, 1);
          break;
        }
      } else
        WelsCabacEncodeDecision (pCabacCtx, iCtxSig + i, 0);
      i++;
      if (i == iEndIdx) {
        iLevel[iNonZeroIdx]        = pBlock[i];
        iLevelScanPos[iNonZeroIdx] = i;
        iNonZeroIdx++;
        break;
      }
    }

    int32_t iNumAbsLevelGt1 = 0;
    int32_t iCtx1 = iCtxLevel + 1;

    do {
      int32_t iPrefix = 0;
      iNonZeroIdx--;
      iPrefix = WELS_ABS (iLevel[iNonZeroIdx]) - 1;
      if (iPrefix) {
        iPrefix = WELS_MIN (iPrefix, 14);
        iCtx = WELS_MIN (iCtxLevel + 4, iCtx1);
        WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
        iNumAbsLevelGt1++;
        iCtx = iCtxLevel + 4 + WELS_MIN (5 - (eCtxBlockCat == CHROMA_DC), iNumAbsLevelGt1);
        for (i = 1; i < iPrefix; i++)
          WelsCabacEncodeDecision (pCabacCtx, iCtx, 1);
        if (WELS_ABS (iLevel[iNonZeroIdx]) < 15)
          WelsCabacEncodeDecision (pCabacCtx, iCtx, 0);
        else {
          /* #538 Phase 4.4 — CoeffSuffixLsb wire-only override.
           *
           * UEG0 suffix for |coeff| >= 15. The LSB of the suffix
           * value (uiVal = |coeff| - 15) becomes the |coeff| LSB
           * on the wire; phasm's CoeffSuffixLsb domain targets it.
           * Phase 4.5.d.1/d.1b — per-block_cat canonical key:
           *   DC types : sub_block = g_zigzag[scan_pos] (the raster
           *              sub-block idx the DC entry represents),
           *              coeff_idx = 0.
           *   AC types : sub_block = iIdx (block idx in MB),
           *              coeff_idx = scan_pos.
           * This matches populate-side hook semantics in
           * svc_encode_mb.cpp once 4.5.d.2-d.6 migrate the AC
           * populate sites raster→scan. */
          const int32_t phasm_scan_pos = iLevelScanPos[iNonZeroIdx];
          uint8_t phasm_sub_block_csl;
          uint8_t phasm_coeff_idx_csl;
          if (eCtxBlockCat == LUMA_DC) {
            phasm_sub_block_csl = g_phasm_zigzag_scan_4x4[phasm_scan_pos];
            phasm_coeff_idx_csl = 0;
          } else if (eCtxBlockCat == CHROMA_DC) {
            /* #538.4.7 fix: bias sub_block by plane (iIdx=1 → Cb +0,
             * iIdx=2 → Cr +4). Mirrors HOOK-C populate-side bias. */
            const uint8_t phasm_plane_off_csl = (iIdx == 2) ? 4 : 0;
            phasm_sub_block_csl = (uint8_t)(g_phasm_zigzag_scan_2x2[phasm_scan_pos] + phasm_plane_off_csl);
            phasm_coeff_idx_csl = 0;
          } else {
            /* #538 Phase 4.6 — iIdx is a CACHE OFFSET (e.g. 9, 10, 17,
             * 18, ...) not a raster sub-block index. Convert it.
             * For CHROMA_AC the helper also biases by plane
             * (Cb=0..3, Cr=4..7) — see #538.4.7. */
            phasm_sub_block_csl = phasm_cache_offset_to_block_idx(iIdx, eCtxBlockCat);
            phasm_coeff_idx_csl = (uint8_t)phasm_scan_pos;
          }
          PhasmStegoPos phasm_pos_csl;
          phasm_pos_csl.frame_num     = PhasmStegoGetFrameNum();
          phasm_pos_csl.mb_x          = (uint16_t)pCurMb->iMbX;
          phasm_pos_csl.mb_y          = (uint16_t)pCurMb->iMbY;
          phasm_pos_csl.partition_idx = 0;
          phasm_pos_csl.sub_block     = phasm_sub_block_csl;
          phasm_pos_csl.coeff_idx     = phasm_coeff_idx_csl;
          phasm_pos_csl.block_cat     = (uint8_t)eCtxBlockCat;
          phasm_pos_csl.ref_idx       = 0xff;
          phasm_pos_csl.mv_component  = 0xff;
          phasm_pos_csl.domain        = (uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB;
          phasm_pos_csl._reserved     = 0;
          WelsCabacEncodeUeBypassWithPhasmLsbOverride (
              pCabacCtx, 0,
              (uint32_t) (WELS_ABS (iLevel[iNonZeroIdx]) - 15),
              (uint8_t)PHASM_DOMAIN_COEFF_SUFFIX_LSB, &phasm_pos_csl);
        }
        iCtx1 = iCtxLevel;
      } else {
        iCtx = WELS_MIN (iCtxLevel + 4, iCtx1);
        WelsCabacEncodeDecision (pCabacCtx, iCtx, 0);
        iCtx1 += iNumAbsLevelGt1 == 0;
      }
      /* #538 Phase 4.2 — wire-only CoeffSign override hook.
       *
       * Phase 4.5.d.1/d.1b — same per-block_cat canonical key
       * derivation as the CoeffSuffixLsb site above:
       *   DC types : sub_block = g_zigzag[scan_pos], coeff_idx = 0.
       *   AC types : sub_block = iIdx, coeff_idx = scan_pos. */
      {
        const int32_t phasm_scan_pos = iLevelScanPos[iNonZeroIdx];
        uint8_t phasm_sub_block;
        uint8_t phasm_coeff_idx;
        if (eCtxBlockCat == LUMA_DC) {
          phasm_sub_block = g_phasm_zigzag_scan_4x4[phasm_scan_pos];
          phasm_coeff_idx = 0;
        } else if (eCtxBlockCat == CHROMA_DC) {
          /* #538.4.7 fix: bias sub_block by plane (iIdx=1 → Cb +0,
           * iIdx=2 → Cr +4). Mirrors HOOK-C populate-side bias. */
          const uint8_t phasm_plane_off = (iIdx == 2) ? 4 : 0;
          phasm_sub_block = (uint8_t)(g_phasm_zigzag_scan_2x2[phasm_scan_pos] + phasm_plane_off);
          phasm_coeff_idx = 0;
        } else {
          /* #538 Phase 4.6 — iIdx is a CACHE OFFSET (e.g. 9, 10, 17,
           * 18, ...) not a raster sub-block index. Convert it.
           * For CHROMA_AC the helper also biases by plane
           * (Cb=0..3, Cr=4..7) — see #538.4.7. */
          phasm_sub_block = phasm_cache_offset_to_block_idx(iIdx, eCtxBlockCat);
          phasm_coeff_idx = (uint8_t)phasm_scan_pos;
        }
        PhasmStegoPos phasm_pos;
        phasm_pos.frame_num     = PhasmStegoGetFrameNum();
        phasm_pos.mb_x          = (uint16_t)pCurMb->iMbX;
        phasm_pos.mb_y          = (uint16_t)pCurMb->iMbY;
        phasm_pos.partition_idx = 0;
        phasm_pos.sub_block     = phasm_sub_block;
        phasm_pos.coeff_idx     = phasm_coeff_idx;
        phasm_pos.block_cat     = (uint8_t)eCtxBlockCat;
        phasm_pos.ref_idx       = 0xff;
        phasm_pos.mv_component  = 0xff;
        phasm_pos.domain        = (uint8_t)PHASM_DOMAIN_COEFF_SIGN;
        phasm_pos._reserved     = 0;
        const int phasm_orig_sign = (iLevel[iNonZeroIdx] < 0) ? 1 : 0;
        const int phasm_bin = phasm_apply_bypass_bin_override (
            (uint8_t)PHASM_DOMAIN_COEFF_SIGN, &phasm_pos, phasm_orig_sign, pCabacCtx->pPhasmStego);
        WelsCabacEncodeBypassOne (pCabacCtx, phasm_bin);
      }
    } while (iNonZeroIdx > 0);

  } else {
    WelsCabacEncodeDecision (pCabacCtx, iCtx, 0);
  }


}
int32_t WelsCalNonZeroCount2x2Block (int16_t* pBlock) {
  return (pBlock[0] != 0)
         + (pBlock[1] != 0)
         + (pBlock[2] != 0)
         + (pBlock[3] != 0);
}
int32_t WelsWriteMbResidualCabac (SWelsFuncPtrList* pFuncList, SSlice* pSlice, SMbCache* sMbCacheInfo, SMB* pCurMb,
                                  SCabacCtx* pCabacCtx,
                                  int16_t iMbWidth, uint32_t uiChromaQpIndexOffset) {

  const uint16_t uiMbType = pCurMb->uiMbType;
  SMbCache* pMbCache = &pSlice->sMbCacheInfo;
  int16_t i = 0;
  int8_t* pNonZeroCoeffCount = pMbCache->iNonZeroCoeffCount;
  SSliceHeaderExt* pSliceHeadExt = &pSlice->sSliceHeaderExt;
  const int32_t iSliceFirstMbXY = pSliceHeadExt->sSliceHeader.iFirstMbInSlice;


  pCurMb->iCbpDc = 0;
  pCurMb->iLumaDQp = 0;

  if ((pCurMb->uiCbp > 0) || (uiMbType == MB_TYPE_INTRA16x16)) {
    int32_t iCbpChroma = pCurMb->uiCbp >> 4;
    int32_t iCbpLuma   = pCurMb->uiCbp & 15;

    pCurMb->iLumaDQp = pCurMb->uiLumaQp - pSlice->uiLastMbQp;
    WelsCabacMbDeltaQp (pCurMb, pCabacCtx, (pCurMb->iMbXY == iSliceFirstMbXY));
    pSlice->uiLastMbQp = pCurMb->uiLumaQp;

    if (uiMbType == MB_TYPE_INTRA16x16) {
      //Luma DC
      int iNonZeroCount = pFuncList->pfGetNoneZeroCount (pMbCache->pDct->iLumaI16x16Dc);
      WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, LUMA_DC, 0, iNonZeroCount,
                                   pMbCache->pDct->iLumaI16x16Dc, 15);
      if (iNonZeroCount)
        pCurMb->iCbpDc |= 1;
      //Luma AC

      if (iCbpLuma) {
        for (i = 0; i < 16; i++) {
          int32_t iIdx = g_kuiCache48CountScan4Idx[i];
          WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, LUMA_AC, iIdx,
                                       pNonZeroCoeffCount[iIdx], pMbCache->pDct->iLumaBlock[i], 14);
        }
      }
    } else {
      //Luma AC
      for (i = 0; i < 16; i++) {
        if (iCbpLuma & (1 << (i >> 2))) {
          int32_t iIdx = g_kuiCache48CountScan4Idx[i];
          WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, LUMA_4x4, iIdx,
                                       pNonZeroCoeffCount[iIdx], pMbCache->pDct->iLumaBlock[i], 15);
        }

      }
    }

    if (iCbpChroma) {
      int32_t iNonZeroCount = 0;
      //chroma DC
      iNonZeroCount = WelsCalNonZeroCount2x2Block (pMbCache->pDct->iChromaDc[0]);
      if (iNonZeroCount)
        pCurMb->iCbpDc |= 0x2;
      WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, CHROMA_DC, 1, iNonZeroCount,
                                   pMbCache->pDct->iChromaDc[0], 3);

      iNonZeroCount = WelsCalNonZeroCount2x2Block (pMbCache->pDct->iChromaDc[1]);
      if (iNonZeroCount)
        pCurMb->iCbpDc |= 0x4;
      WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, CHROMA_DC, 2, iNonZeroCount,
                                   pMbCache->pDct->iChromaDc[1], 3);
      if (iCbpChroma & 0x02) {
        const uint8_t* g_kuiCache48CountScan4Idx_16base = &g_kuiCache48CountScan4Idx[16];
        //Cb AC
        for (i = 0; i < 4; i++) {
          int32_t iIdx = g_kuiCache48CountScan4Idx_16base[i];
          WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, CHROMA_AC, iIdx,
                                       pNonZeroCoeffCount[iIdx], pMbCache->pDct->iChromaBlock[i], 14);

        }

        //Cr AC

        for (i = 0; i < 4; i++) {
          int32_t iIdx = 24 + g_kuiCache48CountScan4Idx_16base[i];
          WelsWriteBlockResidualCabac (pMbCache, pCurMb, iMbWidth, pCabacCtx, CHROMA_AC, iIdx,
                                       pNonZeroCoeffCount[iIdx], pMbCache->pDct->iChromaBlock[4 + i], 14);
        }
      }
    }
  } else {
    pCurMb->iLumaDQp = 0;
    pCurMb->uiLumaQp = pSlice->uiLastMbQp;
    pCurMb->uiChromaQp = g_kuiChromaQpTable[CLIP3_QP_0_51 (pCurMb->uiLumaQp + uiChromaQpIndexOffset)];
  }
  return 0;
}

} // anon ns.

namespace WelsEnc {

void WelsInitSliceCabac (sWelsEncCtx* pEncCtx, SSlice* pSlice) {
  /* alignment needed */
  SBitStringAux* pBs = pSlice->pSliceBsa;
  BsAlign (pBs);

  /* init cabac */
  WelsCabacContextInit (pEncCtx, &pSlice->sCabacCtx, pSlice->iCabacInitIdc);
  WelsCabacEncodeInit (&pSlice->sCabacCtx, pBs->pCurBuf, pBs->pEndBuf);
  /* B-full.2 (#895) — carry the per-encoder stego state onto the slice
   * CABAC context so the leaf bypass-bin emit hooks can reach the
   * per-instance override scratch without a process-global. pEncCtx is
   * the worker thread's own encoder; copying the pointer here (once per
   * slice init, on the slice-worker thread) is the cross-thread-safe
   * carrier the FFI set-thread can't reach directly. */
  pSlice->sCabacCtx.pPhasmStego = pEncCtx->pPhasmStego;
}

int32_t WelsSpatialWriteMbSynCabac (sWelsEncCtx* pEncCtx, SSlice* pSlice, SMB* pCurMb) {
  SCabacCtx* pCabacCtx = &pSlice->sCabacCtx;
  SMbCache* pMbCache = &pSlice->sMbCacheInfo;
  const uint16_t uiMbType = pCurMb->uiMbType;
  SSliceHeaderExt* pSliceHeadExt = &pSlice->sSliceHeaderExt;
  uint32_t uiNumRefIdxL0Active = pSliceHeadExt->sSliceHeader.uiNumRefIdxL0Active - 1;
  const int32_t iSliceFirstMbXY = pSliceHeadExt->sSliceHeader.iFirstMbInSlice;
  int16_t i = 0;
  int16_t iMbWidth = pEncCtx->pCurDqLayer->iMbWidth;
  uint32_t uiChromaQpIndexOffset = pEncCtx->pCurDqLayer->sLayerInfo.pPpsP->uiChromaQpIndexOffset;
  SMVUnitXY sMvd;
  int32_t iRet = 0;
  if (pCurMb->iMbXY > iSliceFirstMbXY)
    WelsCabacEncodeTerminate (&pSlice->sCabacCtx, 0);

  if (IS_SKIP (pCurMb->uiMbType)) {
    pCurMb->uiLumaQp = pSlice->uiLastMbQp;
    pCurMb->uiChromaQp = g_kuiChromaQpTable[CLIP3_QP_0_51 (pCurMb->uiLumaQp + uiChromaQpIndexOffset)];
    WelsMbSkipCabac (&pSlice->sCabacCtx, pCurMb, iMbWidth, pEncCtx->eSliceType, 1);

  } else {
    //skip flag
    if (pEncCtx->eSliceType != I_SLICE)
      WelsMbSkipCabac (&pSlice->sCabacCtx, pCurMb, iMbWidth, pEncCtx->eSliceType, 0);

    //write mb type
    WelsCabacMbType (pCabacCtx, pCurMb, pMbCache, iMbWidth, pEncCtx->eSliceType);

    if (IS_INTRA (uiMbType)) {
      if (uiMbType == MB_TYPE_INTRA4x4) {
        WelsCabacMbIntra4x4PredMode (pCabacCtx, pMbCache);
      }
      WelsCabacMbIntraChromaPredMode (pCabacCtx, pCurMb, pMbCache, iMbWidth);
      sMvd.iMvX = sMvd.iMvY = 0;
      for (i = 0; i < 16; ++i) {
        pCurMb->sMvd[i].sAssignMv (sMvd);
      }

    } else if (uiMbType == MB_TYPE_16x16) {

      if (uiNumRefIdxL0Active > 0) {
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 0);
      }
      /* #549 Bug 5: phasm_partition_id = mbPart(0)*4 + subPart(0) = 0. */
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, iMbWidth, pCurMb->sMv[0], pMbCache->sMbMvp[0], 0, /*phasm_partition_id=*/0);

      for (i = 0; i < 16; ++i) {
        pCurMb->sMvd[i].sAssignMv (sMvd);
      }

    } else if (uiMbType == MB_TYPE_16x8) {
      if (uiNumRefIdxL0Active > 0) {
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 0);
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 12);
      }
      /* #549 Bug 5: mbPart 0 (top) → id=0; mbPart 1 (bottom) → id=4. */
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, iMbWidth , pCurMb->sMv[0], pMbCache->sMbMvp[0], 0, /*phasm_partition_id=*/0);
      for (i = 0; i < 8; ++i) {
        pCurMb->sMvd[i].sAssignMv (sMvd);
      }
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, iMbWidth, pCurMb->sMv[8], pMbCache->sMbMvp[1], 8, /*phasm_partition_id=*/4);
      for (i = 8; i < 16; ++i) {
        pCurMb->sMvd[i].sAssignMv (sMvd);
      }
    } else  if (uiMbType == MB_TYPE_8x16) {
      if (uiNumRefIdxL0Active > 0) {
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 0);
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 2);
      }
      /* #549 Bug 5: mbPart 0 (left) → id=0; mbPart 1 (right) → id=4. */
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, iMbWidth, pCurMb->sMv[0], pMbCache->sMbMvp[0], 0, /*phasm_partition_id=*/0);
      for (i = 0; i < 16; i += 4) {
        pCurMb->sMvd[i    ].sAssignMv (sMvd);
        pCurMb->sMvd[i + 1].sAssignMv (sMvd);
      }
      sMvd = WelsCabacMbMvd (pCabacCtx, pCurMb, iMbWidth,  pCurMb->sMv[2], pMbCache->sMbMvp[1], 2, /*phasm_partition_id=*/4);
      for (i = 0; i < 16; i += 4) {
        pCurMb->sMvd[i + 2].sAssignMv (sMvd);
        pCurMb->sMvd[i + 3].sAssignMv (sMvd);
      }
    } else if ((uiMbType == MB_TYPE_8x8) || (uiMbType == MB_TYPE_8x8_REF0)) {
      //write sub_mb_type
      WelsCabacSubMbType (pCabacCtx, pCurMb);

      if (uiNumRefIdxL0Active > 0) {
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 0);
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 2);
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 12);
        WelsCabacMbRef (pCabacCtx, pCurMb, pMbCache, 14);
      }
      //write sub8x8 mvd
      WelsCabacSubMbMvd (pCabacCtx, pCurMb, pMbCache, iMbWidth);
    }
    if (uiMbType != MB_TYPE_INTRA16x16) {
      WelsCabacMbCbp (pCurMb, iMbWidth, pCabacCtx);
    }
    iRet = WelsWriteMbResidualCabac (pEncCtx->pFuncList, pSlice, pMbCache, pCurMb, pCabacCtx, iMbWidth,
                                     uiChromaQpIndexOffset);
  }
  if (!IS_INTRA (pCurMb->uiMbType))
    pCurMb->uiChromPredMode = 0;

  return iRet;
}


}
