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
 * \file    encode_mb.c
 *
 * \brief   Implementaion for pCurMb encoding
 *
 * \date    05/19/2009 Created
 *************************************************************************************
 */


#include "svc_encode_mb.h"
#include "encode_mb_aux.h"
#include "decode_mb_aux.h"
#include "ls_defines.h"
#include "wels_stego_internal.h"

namespace WelsEnc {

/* phasm-stego: ECtxBlockCat enum is in set_mb_syn_cavlc.h; the hook
 * helper only consumes the integer pass-through. Literal values match
 * the enum (LUMA_DC=0, LUMA_AC=1, LUMA_4x4=2, CHROMA_DC=3, CHROMA_AC=4). */
#define PHASM_BLOCK_CAT_LUMA_DC     0
#define PHASM_BLOCK_CAT_LUMA_AC     1
#define PHASM_BLOCK_CAT_LUMA_4x4    2
#define PHASM_BLOCK_CAT_CHROMA_DC   3
#define PHASM_BLOCK_CAT_CHROMA_AC   4

/* H.264 zigzag scan permutations. Used by Stage 4 inter hooks (HOOK-F,
 * HOOK-G) to map a scanned-order index back to the raster-order index
 * for dual-array writeback. Each table is the (scanned_idx → raster_idx)
 * mapping. Hard-coded to match the inline scan implementations in
 * encode_mb_aux.cpp (WelsScan4x4DcAc_c lines 371-384, WelsScan4x4Ac_c
 * lines 386-399). Sanity-asserted at the hook call site via the
 * helper's level_a == level_b precondition. */
static const uint8_t kPhasmLumaZigzag[16] = {
  0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15
};
static const uint8_t kPhasmChromaAcZigzag[15] = {
  1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15
};
void WelsDctMb (int16_t* pRes, uint8_t* pEncMb, int32_t iEncStride, uint8_t* pBestPred, PDctFunc pfDctFourT4) {
  pfDctFourT4 (pRes,       pEncMb,                      iEncStride, pBestPred,       16);
  pfDctFourT4 (pRes + 64,  pEncMb + 8,                  iEncStride, pBestPred + 8,   16);
  pfDctFourT4 (pRes + 128, pEncMb + 8 * iEncStride,     iEncStride, pBestPred + 128, 16);
  pfDctFourT4 (pRes + 192, pEncMb + 8 * iEncStride + 8, iEncStride, pBestPred + 136, 16);
}

void WelsEncRecI16x16Y (sWelsEncCtx* pEncCtx, SMB* pCurMb, SMbCache* pMbCache) {
  ENFORCE_STACK_ALIGN_1D (int16_t, aDctT4Dc, 16, 16)
  /* phasm-stego C.8.3 dual-recon snapshots. Held on the stack uncondition-
   * ally for simplicity; the recompute branch below is gated on the
   * encoder pre-emit callback being registered, so when no stego session
   * is active the snapshots+recompute are skipped entirely.
   *
   * `phasm_dr_active` is captured here ONCE so the rest of the function
   * doesn't pay the global accessor cost on every line. */
  ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_aDctT4Dc, 16, 16)
  ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_pRes,    256, 16)
  ENFORCE_STACK_ALIGN_1D (uint8_t, phasm_dr_stego_recon,   256, 16)
  const bool phasm_dr_active = (PhasmStegoGetEncPreEmit() != NULL)
                               && (pEncCtx->pCurDqLayer->pVisualRecPic != NULL);

  SWelsFuncPtrList* pFuncList   = pEncCtx->pFuncList;
  SDqLayer* pCurDqLayer         = pEncCtx->pCurDqLayer;
  const int32_t kiEncStride     = pCurDqLayer->iEncStride[0];
  int16_t* pRes                 = pMbCache->pCoeffLevel;
  uint8_t* pPred                = pMbCache->SPicData.pCsMb[0];
  const int32_t kiRecStride     = pCurDqLayer->iCsStride[0];
  int16_t* pBlock               = pMbCache->pDct->iLumaBlock[0];
  uint8_t* pBestPred            = pMbCache->pMemPredLuma;
  const uint8_t* kpNoneZeroCountIdx = &g_kuiMbCountScan4Idx[0];
  uint8_t i, uiQp               = pCurMb->uiLumaQp;
  uint32_t uiNoneZeroCount, uiNoneZeroCountMbAc = 0, uiCountI16x16Dc;

  const int16_t* pMF = g_kiQuantMF[uiQp];
  const int16_t* pFF = g_iQuantIntraFF[uiQp];

  WelsDctMb (pRes,  pMbCache->SPicData.pEncMb[0], kiEncStride, pBestPred, pEncCtx->pFuncList->pfDctFourT4);

  pFuncList->pfTransformHadamard4x4Dc (aDctT4Dc, pRes);
  pFuncList->pfQuantizationDc4x4 (aDctT4Dc, pFF[0] << 1, pMF[0]>>1);

  /* phasm-stego C.8.3: snapshot post-quant clean DC before HOOK-A may
   * mutate aDctT4Dc. The 16 16-bit entries map one-per-4x4-sub-block,
   * raster-within-MB order. */
  if (phasm_dr_active) {
    memcpy(phasm_dr_clean_aDctT4Dc, aDctT4Dc, sizeof(int16_t) * 16);
  }

  /* phasm-stego HOOK-A: I_16x16 luma DC, post-quant pre-scan. Each of
   * the 16 entries in aDctT4Dc holds the (Hadamard-transformed,
   * quantized) DC of one 4x4 sub-block. The subsequent scan at line
   * below writes the array into pMbCache->pDct->iLumaI16x16Dc (CABAC's
   * input). The dequant at end-of-function (WelsIHadamard4x4Dc +
   * pfDequantizationIHadamard4x4) reads the same aDctT4Dc array for the
   * recon path. So modifying any entry here propagates into BOTH the
   * bitstream AND the encoder's reference frame consistently — no
   * dual-write needed. See docs/design/video/h264/openh264-hook-sites-
   * intra.md (consumer repo) for the audit. */
  {
    PhasmStegoPos phasm_pos;
    phasm_pos.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos.mb_x          = (uint16_t)pCurMb->iMbX;
    phasm_pos.mb_y          = (uint16_t)pCurMb->iMbY;
    phasm_pos.partition_idx = 0;
    phasm_pos.sub_block     = 0;
    phasm_pos.coeff_idx     = 0;
    phasm_pos.block_cat     = 0;
    phasm_pos.ref_idx       = 0xff;
    phasm_pos.mv_component  = 0xff;
    phasm_pos._reserved     = 0;
    for (uint8_t phasm_k = 0; phasm_k < 16; ++phasm_k) {
      phasm_apply_coeff_hooks (&phasm_pos,
                               /*sub_block=*/phasm_k,
                               /*coeff_idx=*/0,
                               PHASM_BLOCK_CAT_LUMA_DC,
                               &aDctT4Dc[phasm_k]);
    }
  }

  pFuncList->pfScan4x4 (pMbCache->pDct->iLumaI16x16Dc, aDctT4Dc);
  uiCountI16x16Dc = pFuncList->pfGetNoneZeroCount (pMbCache->pDct->iLumaI16x16Dc);

  for (i = 0; i < 4; i++) {
    pFuncList->pfQuantizationFour4x4 (pRes, pFF,  pMF);

    /* phasm-stego C.8.3: snapshot the 64-entry post-quant clean AC strip
     * before HOOK-B fires. Strip i covers raster sub-blocks (i*4)..(i*4+3),
     * 16 entries each. */
    if (phasm_dr_active) {
      memcpy(phasm_dr_clean_pRes + i * 64, pRes, sizeof(int16_t) * 64);
    }

    /* phasm-stego HOOK-B: I_16x16 luma AC, post-quant pre-scan, ×4 strips.
     * pRes points to the current strip (64 ints). Each strip holds 4 sub-
     * blocks at pRes[0..15], pRes[16..31], pRes[32..47], pRes[48..63] in
     * raster-within-sub-block order. We skip raster index 0 of each sub-
     * block (DC re-injection slot — line 154-169 below copies aDctT4Dc[]
     * into these positions AFTER our hook fires, so any AC override here
     * would be overwritten). Hook on raster 1..15 only.
     * Both readers of pRes after this point — the 4 pfScan4x4Ac calls
     * below (CABAC path) and the per-strip pfDequantizationFour4x4 at
     * line ~150 (recon path) — see the modified values. Single-write
     * suffices. */
    {
      PhasmStegoPos phasm_pos_b;
      phasm_pos_b.frame_num     = PhasmStegoGetFrameNum();
      phasm_pos_b.mb_x          = (uint16_t)pCurMb->iMbX;
      phasm_pos_b.mb_y          = (uint16_t)pCurMb->iMbY;
      phasm_pos_b.partition_idx = 0;
      phasm_pos_b.sub_block     = 0;
      phasm_pos_b.coeff_idx     = 0;
      phasm_pos_b.block_cat     = 0;
      phasm_pos_b.ref_idx       = 0xff;
      phasm_pos_b.mv_component  = 0xff;
      phasm_pos_b._reserved     = 0;
      for (uint8_t phasm_sb = 0; phasm_sb < 4; ++phasm_sb) {
        for (uint8_t phasm_c = 1; phasm_c < 16; ++phasm_c) {  /* skip DC slot */
          phasm_apply_coeff_hooks (&phasm_pos_b,
                                   /*sub_block=*/(uint8_t)(i * 4 + phasm_sb),
                                   /*coeff_idx=*/phasm_c,
                                   PHASM_BLOCK_CAT_LUMA_AC,
                                   &pRes[phasm_sb * 16 + phasm_c]);
        }
      }
    }

    pFuncList->pfScan4x4Ac (pBlock,      pRes);
    pFuncList->pfScan4x4Ac (pBlock + 16, pRes + 16);
    pFuncList->pfScan4x4Ac (pBlock + 32, pRes + 32);
    pFuncList->pfScan4x4Ac (pBlock + 48, pRes + 48);
    pRes += 64;
    pBlock += 64;
  }
  pRes -= 256;
  pBlock -= 256;

  for (i = 0; i < 16; i++) {
    uiNoneZeroCount = pFuncList->pfGetNoneZeroCount (pBlock);
    pCurMb->pNonZeroCount[*kpNoneZeroCountIdx++] = uiNoneZeroCount;
    uiNoneZeroCountMbAc += uiNoneZeroCount;
    pBlock += 16;
  }

  if (uiCountI16x16Dc > 0) {
    if (uiQp < 12) {
      WelsIHadamard4x4Dc (aDctT4Dc);
      WelsDequantLumaDc4x4 (aDctT4Dc, uiQp);
    } else
      pFuncList->pfDequantizationIHadamard4x4 (aDctT4Dc, g_kuiDequantCoeff[uiQp][0] >> 2);
  }

  if (uiNoneZeroCountMbAc > 0) {
    pCurMb->uiCbp = 15;
    pFuncList->pfDequantizationFour4x4 (pRes, g_kuiDequantCoeff[uiQp]);
    pFuncList->pfDequantizationFour4x4 (pRes + 64, g_kuiDequantCoeff[uiQp]);
    pFuncList->pfDequantizationFour4x4 (pRes + 128, g_kuiDequantCoeff[uiQp]);
    pFuncList->pfDequantizationFour4x4 (pRes + 192, g_kuiDequantCoeff[uiQp]);

    pRes[0]  = aDctT4Dc[0];
    pRes[16] = aDctT4Dc[1];
    pRes[32] = aDctT4Dc[4];
    pRes[48] = aDctT4Dc[5];
    pRes[64] = aDctT4Dc[2];
    pRes[80] = aDctT4Dc[3];
    pRes[96] = aDctT4Dc[6];
    pRes[112] = aDctT4Dc[7];
    pRes[128] = aDctT4Dc[8];
    pRes[144] = aDctT4Dc[9];
    pRes[160] = aDctT4Dc[12];
    pRes[176] = aDctT4Dc[13];
    pRes[192] = aDctT4Dc[10];
    pRes[208] = aDctT4Dc[11];
    pRes[224] = aDctT4Dc[14];
    pRes[240] = aDctT4Dc[15];

    pFuncList->pfIDctFourT4 (pPred,                       kiRecStride, pBestPred,        16, pRes);
    pFuncList->pfIDctFourT4 (pPred + 8,                   kiRecStride, pBestPred + 8,    16, pRes + 64);
    pFuncList->pfIDctFourT4 (pPred + kiRecStride * 8,     kiRecStride, pBestPred + 128,  16, pRes + 128);
    pFuncList->pfIDctFourT4 (pPred + kiRecStride * 8 + 8, kiRecStride, pBestPred + 136,  16, pRes + 192);
  } else if (uiCountI16x16Dc > 0) {
    pFuncList->pfIDctI16x16Dc (pPred, kiRecStride, pBestPred, 16, aDctT4Dc);
  } else {
    pFuncList->pfCopy16x16Aligned (pPred, kiRecStride, pBestPred, 16);
  }

  /* ----------------------------------------------------------------- *
   * phasm-stego C.8.3: I_16x16 dual-recon post-pass.
   *
   * At this point `pPred` (= pDecPic at the MB offset) carries the
   * STEGO-flipped reconstruction -- the encoder's recon path consumed
   * the post-HOOK aDctT4Dc + pRes. To break the cascade, we need
   * pDecPic to carry the CLEAN reconstruction instead. Stego pixels
   * still need to be tracked (for cascade-verify) so they go into
   * pVisualRecPic.
   *
   * The recompute reuses the encoder's own dequant + DC re-injection
   * + IDCT helpers on the snapshotted clean post-quant arrays. It's
   * the same code path as lines 188-227 above, run on
   * phasm_dr_clean_aDctT4Dc + phasm_dr_clean_pRes scratch.
   *
   * Cost: ~one extra dequant pass + four pfIDctFourT4 (CBP>0 case) or
   * one pfIDctI16x16Dc (DC-only). CBP=0 case is a no-op for the
   * clean recompute (pPred already holds pBestPred); just the
   * stego-mirror copy. v1.1+ optimization (#449): delta-IDCT instead
   * of full recompute.
   * ----------------------------------------------------------------- */
  if (phasm_dr_active) {
    /* (1) Snapshot the current stego recon block at pPred (16x16, with
     *     the layer's encode stride between rows) into a contiguous
     *     stride-16 scratch. This is the picture pVisualRecPic will
     *     receive at the end. */
    for (int32_t phasm_y = 0; phasm_y < 16; ++phasm_y) {
      memcpy(phasm_dr_stego_recon + phasm_y * 16,
             pPred + (size_t)phasm_y * (size_t)kiRecStride,
             16);
    }

    /* (2) Recompute the clean recon by re-running the encoder's own
     *     dequant + DC reinject + IDCT on the snapshot post-quant
     *     arrays. The work buffers must be local (writable copies of
     *     the snapshots) since the IDCT helpers mutate in place. */
    if (uiNoneZeroCountMbAc > 0) {
      ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_dc_work,  16, 16)
      ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_res_work, 256, 16)
      /* Note: ENFORCE_STACK_ALIGN_1D declares the name as a `int16_t*`
       * pointer (not an array), so sizeof(name) is the pointer size.
       * Use explicit element-count byte size here and below. */
      memcpy(phasm_dr_clean_dc_work,  phasm_dr_clean_aDctT4Dc, sizeof(int16_t) * 16);
      memcpy(phasm_dr_clean_res_work, phasm_dr_clean_pRes,     sizeof(int16_t) * 256);

      if (uiCountI16x16Dc > 0) {
        if (uiQp < 12) {
          WelsIHadamard4x4Dc (phasm_dr_clean_dc_work);
          WelsDequantLumaDc4x4 (phasm_dr_clean_dc_work, uiQp);
        } else {
          pFuncList->pfDequantizationIHadamard4x4 (phasm_dr_clean_dc_work,
                                                   g_kuiDequantCoeff[uiQp][0] >> 2);
        }
      }
      pFuncList->pfDequantizationFour4x4 (phasm_dr_clean_res_work,       g_kuiDequantCoeff[uiQp]);
      pFuncList->pfDequantizationFour4x4 (phasm_dr_clean_res_work + 64,  g_kuiDequantCoeff[uiQp]);
      pFuncList->pfDequantizationFour4x4 (phasm_dr_clean_res_work + 128, g_kuiDequantCoeff[uiQp]);
      pFuncList->pfDequantizationFour4x4 (phasm_dr_clean_res_work + 192, g_kuiDequantCoeff[uiQp]);

      phasm_dr_clean_res_work[0]   = phasm_dr_clean_dc_work[0];
      phasm_dr_clean_res_work[16]  = phasm_dr_clean_dc_work[1];
      phasm_dr_clean_res_work[32]  = phasm_dr_clean_dc_work[4];
      phasm_dr_clean_res_work[48]  = phasm_dr_clean_dc_work[5];
      phasm_dr_clean_res_work[64]  = phasm_dr_clean_dc_work[2];
      phasm_dr_clean_res_work[80]  = phasm_dr_clean_dc_work[3];
      phasm_dr_clean_res_work[96]  = phasm_dr_clean_dc_work[6];
      phasm_dr_clean_res_work[112] = phasm_dr_clean_dc_work[7];
      phasm_dr_clean_res_work[128] = phasm_dr_clean_dc_work[8];
      phasm_dr_clean_res_work[144] = phasm_dr_clean_dc_work[9];
      phasm_dr_clean_res_work[160] = phasm_dr_clean_dc_work[12];
      phasm_dr_clean_res_work[176] = phasm_dr_clean_dc_work[13];
      phasm_dr_clean_res_work[192] = phasm_dr_clean_dc_work[10];
      phasm_dr_clean_res_work[208] = phasm_dr_clean_dc_work[11];
      phasm_dr_clean_res_work[224] = phasm_dr_clean_dc_work[14];
      phasm_dr_clean_res_work[240] = phasm_dr_clean_dc_work[15];

      /* IDCT clean into pPred (overwriting the stego we snapshotted). */
      pFuncList->pfIDctFourT4 (pPred,                       kiRecStride, pBestPred,        16, phasm_dr_clean_res_work);
      pFuncList->pfIDctFourT4 (pPred + 8,                   kiRecStride, pBestPred + 8,    16, phasm_dr_clean_res_work + 64);
      pFuncList->pfIDctFourT4 (pPred + kiRecStride * 8,     kiRecStride, pBestPred + 128,  16, phasm_dr_clean_res_work + 128);
      pFuncList->pfIDctFourT4 (pPred + kiRecStride * 8 + 8, kiRecStride, pBestPred + 136,  16, phasm_dr_clean_res_work + 192);
    } else if (uiCountI16x16Dc > 0) {
      ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_dc_work, 16, 16)
      memcpy(phasm_dr_clean_dc_work, phasm_dr_clean_aDctT4Dc, sizeof(int16_t) * 16);
      if (uiQp < 12) {
        WelsIHadamard4x4Dc (phasm_dr_clean_dc_work);
        WelsDequantLumaDc4x4 (phasm_dr_clean_dc_work, uiQp);
      } else {
        pFuncList->pfDequantizationIHadamard4x4 (phasm_dr_clean_dc_work,
                                                 g_kuiDequantCoeff[uiQp][0] >> 2);
      }
      pFuncList->pfIDctI16x16Dc (pPred, kiRecStride, pBestPred, 16, phasm_dr_clean_dc_work);
    }
    /* CBP=0 branch: pPred already holds pBestPred (no coeffs to flip,
     * clean and stego are identical). No clean-recompute needed.    */

    /* (3) Mirror the snapshotted stego recon into pVisualRecPic at the
     *     MB offset. The clean side has already been written into pPred
     *     above (or never moved off pBestPred for CBP=0), so we pass
     *     clean_dst=NULL to the helper -- pDecPic doesn't need a second
     *     memcpy. The dual_recon_observe callback intentionally does
     *     NOT fire here (helper requires both clean+stego pointers); a
     *     v1.1+ enhancement could snapshot the recomputed clean to pass
     *     it through. */
    {
      const int32_t phasm_dr_px = pCurMb->iMbX * 16;
      const int32_t phasm_dr_py = pCurMb->iMbY * 16;
      phasm_dual_recon_writeback (
          (uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY, /*plane=*/0,
          phasm_dr_px, phasm_dr_py, /*block_w=*/16, /*block_h=*/16,
          /*clean_dst=*/NULL,
          /*stego_dst=*/pCurDqLayer->pVisualRecPic->pData[0],
          /*dst_stride=*/kiRecStride,
          /*clean_pixels=*/NULL,
          /*stego_pixels=*/phasm_dr_stego_recon,
          /*src_stride=*/16);
    }
  }
}
void WelsEncRecI4x4Y (sWelsEncCtx* pEncCtx, SMB* pCurMb, SMbCache* pMbCache, uint8_t uiI4x4Idx) {
  SWelsFuncPtrList* pFuncList   = pEncCtx->pFuncList;
  SDqLayer* pCurDqLayer         = pEncCtx->pCurDqLayer;
  int32_t iEncStride            = pCurDqLayer->iEncStride[0];
  uint8_t uiQp                  = pCurMb->uiLumaQp;

  int16_t* pResI4x4 = pMbCache->pCoeffLevel;
  uint8_t* pPredI4x4;

  uint8_t* pPred     = pMbCache->SPicData.pCsMb[0];
  int32_t iRecStride = pCurDqLayer->iCsStride[0];

  uint32_t uiOffset = g_kuiMbCountScan4Idx[uiI4x4Idx];
  uint8_t* pEncMb = pMbCache->SPicData.pEncMb[0];
  uint8_t* pBestPred = pMbCache->pBestPredI4x4Blk4;
  int16_t* pBlock = pMbCache->pDct->iLumaBlock[uiI4x4Idx];

  const int16_t* pMF = g_kiQuantMF[uiQp];
  const int16_t* pFF = g_iQuantIntraFF[uiQp];

  int32_t* pStrideEncBlockOffset = pEncCtx->pStrideTab->pStrideEncBlockOffset[pEncCtx->uiDependencyId];
  int32_t* pStrideDecBlockOffset = pEncCtx->pStrideTab->pStrideDecBlockOffset[pEncCtx->uiDependencyId][0 ==
                                   pEncCtx->uiTemporalId];
  int32_t iNoneZeroCount = 0;

  /* phasm-stego C.8.4 dual-recon: per-sub-block snapshot + scratch. The
   * scope here is ONE 4x4 sub-block; the caller (WelsMdI4x4 / Fast) runs
   * this function once per iI4x4Idx ∈ 0..15 inside its own loop. */
  ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_pRes4x4, 16, 16)
  ENFORCE_STACK_ALIGN_1D (uint8_t, phasm_dr_stego_i4x4,    16, 4)
  const bool phasm_dr_active = (PhasmStegoGetEncPreEmit() != NULL)
                               && (pCurDqLayer->pVisualRecPic != NULL);

  pFuncList->pfDctT4 (pResI4x4, & (pEncMb[pStrideEncBlockOffset[uiI4x4Idx]]), iEncStride, pBestPred, 4);
  pFuncList->pfQuantization4x4 (pResI4x4, pFF, pMF);

  /* phasm-stego C.8.4: snapshot post-quant clean before HOOK-E may mutate.
   * pResI4x4 holds 16 quantized coefficients in raster within-sub-block
   * order (same view HOOK-E modifies + the dequant+IDCT below reads). */
  if (phasm_dr_active) {
    memcpy(phasm_dr_clean_pRes4x4, pResI4x4, sizeof(int16_t) * 16);
  }

  /* phasm-stego HOOK-E: I_4x4 luma, post-quant pre-scan. Called per
   * 4x4 sub-block (uiI4x4Idx 0..15). pResI4x4 holds 16 quantized
   * coefficients in raster within-sub-block order. Both readers of
   * pResI4x4 after this point — the pfScan4x4 below (CABAC path) and
   * the pfDequantization4x4 at line ~280 (recon path, which then
   * pfIDctT4's into pPredI4x4 = pCsMb[sub-block offset]) — see the
   * modified values. The reconstructed pixels written into pCsMb feed
   * the intra-prediction of subsequent 4x4 sub-blocks within the same
   * MB (intra-MB cascade per the audit). The contract — non-zero in /
   * non-zero out — preserves nz count + CBP. */
  {
    PhasmStegoPos phasm_pos_e;
    phasm_pos_e.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos_e.mb_x          = (uint16_t)pCurMb->iMbX;
    phasm_pos_e.mb_y          = (uint16_t)pCurMb->iMbY;
    phasm_pos_e.partition_idx = 0;
    phasm_pos_e.sub_block     = 0;
    phasm_pos_e.coeff_idx     = 0;
    phasm_pos_e.block_cat     = 0;
    phasm_pos_e.ref_idx       = 0xff;
    phasm_pos_e.mv_component  = 0xff;
    phasm_pos_e._reserved     = 0;
    for (uint8_t phasm_c = 0; phasm_c < 16; ++phasm_c) {
      phasm_apply_coeff_hooks (&phasm_pos_e,
                               /*sub_block=*/uiI4x4Idx,
                               /*coeff_idx=*/phasm_c,
                               PHASM_BLOCK_CAT_LUMA_4x4,
                               &pResI4x4[phasm_c]);
    }
  }

  pFuncList->pfScan4x4 (pBlock, pResI4x4);

  iNoneZeroCount = pFuncList->pfGetNoneZeroCount (pBlock);
  pCurMb->pNonZeroCount[uiOffset] = iNoneZeroCount;

  pPredI4x4 = pPred + pStrideDecBlockOffset[uiI4x4Idx];
  if (iNoneZeroCount > 0) {
    pCurMb->uiCbp |= 1 << (uiI4x4Idx >> 2);
    pFuncList->pfDequantization4x4 (pResI4x4, g_kuiDequantCoeff[uiQp]);
    pFuncList->pfIDctT4 (pPredI4x4, iRecStride, pBestPred, 4, pResI4x4);
  } else
    pFuncList->pfCopy4x4 (pPredI4x4, iRecStride, pBestPred, 4);

  /* ----------------------------------------------------------------- *
   * phasm-stego C.8.4: I_4x4 sub-block dual-recon post-pass.
   *
   * pPredI4x4 (= pDecPic at sub-block offset) currently holds STEGO
   * pixels (the IDCT/copy above consumed post-HOOK-E coefficients).
   * The audit §1 lock states that within-MB intra-pred neighbour reads
   * for subsequent 4x4 sub-blocks must read CLEAN pixels, so we restore
   * pDecPic to clean here, ahead of the next loop iteration in the
   * caller (WelsMdI4x4 / Fast).
   *
   * Cost: one extra pfDequantization4x4 + pfIDctT4 per sub-block when
   * nNz > 0; pure memcpy when nNz == 0.
   * ----------------------------------------------------------------- */
  if (phasm_dr_active) {
    /* (1) Snapshot stego sub-block (4 rows × 4 bytes, picture stride). */
    for (int32_t phasm_y = 0; phasm_y < 4; ++phasm_y) {
      memcpy(phasm_dr_stego_i4x4 + phasm_y * 4,
             pPredI4x4 + (size_t)phasm_y * (size_t)iRecStride,
             4);
    }

    if (iNoneZeroCount > 0) {
      /* (2) Recompute clean: dequant snapshot + IDCT into pPredI4x4
       *     (overwrites the stego we just snapshotted). Note that
       *     ENFORCE_STACK_ALIGN_1D yields a `int16_t*` named symbol
       *     (not an array), so sizeof(...) returns the pointer size;
       *     pass the explicit byte count to memcpy below. */
      ENFORCE_STACK_ALIGN_1D (int16_t, phasm_dr_clean_work, 16, 16)
      memcpy(phasm_dr_clean_work, phasm_dr_clean_pRes4x4, sizeof(int16_t) * 16);
      pFuncList->pfDequantization4x4 (phasm_dr_clean_work, g_kuiDequantCoeff[uiQp]);
      pFuncList->pfIDctT4 (pPredI4x4, iRecStride, pBestPred, 4, phasm_dr_clean_work);
    }
    /* CBP=0 branch: pPredI4x4 already holds the prediction copy (clean
     * == stego at sub-block level). No clean recompute needed. */

    /* (3) Mirror stego sub-block into pVisualRecPic at the same byte
     *     offset. The two pictures share the same iLineSize so a single
     *     sub-block offset (pPredI4x4 - pCsData[0]) maps both. */
    {
      const ptrdiff_t phasm_dr_plane_off = pPredI4x4 - pCurDqLayer->pCsData[0];
      const int32_t phasm_dr_py = (int32_t)(phasm_dr_plane_off / iRecStride);
      const int32_t phasm_dr_px = (int32_t)(phasm_dr_plane_off % iRecStride);
      phasm_dual_recon_writeback (
          (uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY, /*plane=*/0,
          phasm_dr_px, phasm_dr_py, /*block_w=*/4, /*block_h=*/4,
          /*clean_dst=*/NULL,
          /*stego_dst=*/pCurDqLayer->pVisualRecPic->pData[0],
          /*dst_stride=*/iRecStride,
          /*clean_pixels=*/NULL,
          /*stego_pixels=*/phasm_dr_stego_i4x4,
          /*src_stride=*/4);
    }
  }
}

void WelsEncInterY (SWelsFuncPtrList* pFuncList, SMB* pCurMb, SMbCache* pMbCache) {
  PQuantizationMaxFunc pfQuantizationFour4x4Max         = pFuncList->pfQuantizationFour4x4Max;
  PSetMemoryZero pfSetMemZeroSize8                      = pFuncList->pfSetMemZeroSize8;
  PSetMemoryZero pfSetMemZeroSize64                     = pFuncList->pfSetMemZeroSize64;
  PScanFunc pfScan4x4                                   = pFuncList->pfScan4x4;
  PCalculateSingleCtrFunc pfCalculateSingleCtr4x4       = pFuncList->pfCalculateSingleCtr4x4;
  PGetNoneZeroCountFunc pfGetNoneZeroCount              = pFuncList->pfGetNoneZeroCount;
  PDeQuantizationFunc pfDequantizationFour4x4           = pFuncList->pfDequantizationFour4x4;
  int16_t* pRes = pMbCache->pCoeffLevel;
  int32_t iSingleCtrMb = 0, iSingleCtr8x8[4];
  int16_t* pBlock = pMbCache->pDct->iLumaBlock[0];
  uint8_t uiQp = pCurMb->uiLumaQp;
  const int16_t* pMF = g_kiQuantMF[uiQp];
  const int16_t* pFF = g_kiQuantInterFF[uiQp];
  int16_t aMax[16];
  int32_t i, j, iNoneZeroCount = 0;

  for (i = 0; i < 4; i++) {
    pfQuantizationFour4x4Max (pRes, pFF,  pMF, aMax + (i << 2));
    iSingleCtr8x8[i] = 0;
    for (j = 0; j < 4; j++) {
      if (aMax[ (i << 2) + j] == 0)
        pfSetMemZeroSize8 (pBlock, 32);
      else {
        pfScan4x4 (pBlock, pRes);
        if (aMax[ (i << 2) + j] > 1)
          iSingleCtr8x8[i] += 9;
        else if (iSingleCtr8x8[i] < 6)
          iSingleCtr8x8[i] += pfCalculateSingleCtr4x4 (pBlock);
      }
      pRes += 16;
      pBlock += 16;
    }
    iSingleCtrMb += iSingleCtr8x8[i];
  }
  pBlock -= 256;
  pRes -= 256;

  /* phasm-stego C.8.6: snapshot CLEAN post-quant pre-HOOK-F luma pRes
   * (256 int16_t = 16 4x4 sub-blocks). This is in QUANT domain; the
   * stash recompute below will mirror suppression + dequant after the
   * live path runs them. */
  const bool phasm_dr_active_y = (PhasmStegoGetEncPreEmit() != NULL);
  int16_t phasm_dr_clean_luma[256];
  if (phasm_dr_active_y) {
    memcpy(phasm_dr_clean_luma, pRes, sizeof(int16_t) * 256);
  }

  /* phasm-stego HOOK-F: P luma inter, post-quant POST-scan, dual-array
   * writeback. Per the audit (openh264-hook-sites-inter-coeff.md), this
   * site sits between the scan loop above and the JVT-O079 suppression
   * decision below. At this point:
   *   - pRes (= pMbCache->pCoeffLevel)        holds raster-order levels
   *   - pBlock (= pMbCache->pDct->iLumaBlock) holds zigzag-scanned levels
   * Both arrays must be kept consistent because:
   *   - CABAC writer (WelsWriteMbResidualCabac) reads iLumaBlock zigzag
   *   - IDCT recon (OutputPMbWithoutConstructCsRsNoCopy via
   *     pfDequantizationFour4x4 + WelsIDctT4RecOnMb) reads pCoeffLevel
   *
   * Helper phasm_apply_coeff_hooks_dual does the dual-write atomically
   * and sanity-asserts level_a == level_b (catches scan-index bugs).
   *
   * Note: per the audit, modifications must respect JVT-O079 floors
   * (iSingleCtrMb < 6 → full MB zeroed; iSingleCtr8x8[i] < 4 → 8x8
   * group zeroed). The phasm-side callback contract (non-zero in /
   * non-zero out, magnitude preservation for suffix-LSB) keeps
   * iSingleCtr8x8 contribution unchanged so suppression decisions
   * survive. Sign-flips preserve |level| so aMax stays stable too.
   *
   * iSingleCtrMb is already computed above and stable for our
   * non-zero-preserving hook. Suppression below runs against the
   * pre-hook count, which is fine because we don't change zero-ness. */
  if (PhasmStegoGetEncPreEmit() != NULL) {
    PhasmStegoPos phasm_pos_f;
    phasm_pos_f.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos_f.mb_x          = (uint16_t)pCurMb->iMbX;
    phasm_pos_f.mb_y          = (uint16_t)pCurMb->iMbY;
    phasm_pos_f.partition_idx = 0;
    phasm_pos_f.sub_block     = 0;
    phasm_pos_f.coeff_idx     = 0;
    phasm_pos_f.block_cat     = 0;
    phasm_pos_f.ref_idx       = 0xff;
    phasm_pos_f.mv_component  = 0xff;
    phasm_pos_f._reserved     = 0;
    for (uint8_t phasm_sb = 0; phasm_sb < 16; ++phasm_sb) {
      int16_t* phasm_pres   = pRes   + (int32_t)phasm_sb * 16;
      int16_t* phasm_pblock = pBlock + (int32_t)phasm_sb * 16;
      for (uint8_t phasm_s = 0; phasm_s < 16; ++phasm_s) {
        uint8_t phasm_r = kPhasmLumaZigzag[phasm_s];
        phasm_apply_coeff_hooks_dual(&phasm_pos_f,
                                     /*sub_block=*/phasm_sb,
                                     /*coeff_idx=*/phasm_s,
                                     PHASM_BLOCK_CAT_LUMA_4x4,
                                     /*level_a (raster)=*/&phasm_pres[phasm_r],
                                     /*level_b (zigzag)=*/&phasm_pblock[phasm_s]);
      }
    }
  }

  memset (pCurMb->pNonZeroCount, 0, 16);


  if (iSingleCtrMb < 6) {  //from JVT-O079
    pfSetMemZeroSize64 (pRes,  768); // confirmed_safe_unsafe_usage
  } else {
    const uint8_t* kpNoneZeroCountIdx = g_kuiMbCountScan4Idx;
    for (i = 0; i < 4; i++) {
      if (iSingleCtr8x8[i] >= 4) {
        for (j = 0; j < 4; j++) {
          iNoneZeroCount = pfGetNoneZeroCount (pBlock);
          pCurMb->pNonZeroCount[*kpNoneZeroCountIdx++] = iNoneZeroCount;
          pBlock += 16;
        }
        pfDequantizationFour4x4 (pRes, g_kuiDequantCoeff[uiQp]);
        pCurMb->uiCbp |= 1 << i;
      } else { // set zero for an 8x8 pBlock
        pfSetMemZeroSize64 (pRes, 128); // confirmed_safe_unsafe_usage
        kpNoneZeroCountIdx += 4;
        pBlock += 64;
      }
      pRes += 64;
    }
  }

  /* phasm-stego C.8.6: mirror suppression + dequant on the clean
   * snapshot (in QUANT domain after the snapshot above) so the stash
   * holds the same DEQUANT-domain content that the IDCT site expects
   * minus the HOOK-F sign/suffix overrides. Suppression decisions
   * (iSingleCtrMb / iSingleCtr8x8) are based on PRE-hook counts which
   * the hook contract preserves, so the suppression mask is identical
   * between live and clean paths. */
  if (phasm_dr_active_y) {
    if (iSingleCtrMb < 6) {
      memset(phasm_dr_clean_luma, 0, sizeof(int16_t) * 256);
    } else {
      for (i = 0; i < 4; i++) {
        if (iSingleCtr8x8[i] >= 4) {
          pfDequantizationFour4x4(phasm_dr_clean_luma + i * 64, g_kuiDequantCoeff[uiQp]);
        } else {
          memset(phasm_dr_clean_luma + i * 64, 0, sizeof(int16_t) * 64);
        }
      }
    }
    phasm_stash_p_luma_clean_pres(phasm_dr_clean_luma);
  }
}

void    WelsEncRecUV (SWelsFuncPtrList* pFuncList, SMB* pCurMb, SMbCache* pMbCache, int16_t* pRes, int32_t iUV) {
  PQuantizationHadamardFunc pfQuantizationHadamard2x2   = pFuncList->pfQuantizationHadamard2x2;
  PQuantizationMaxFunc pfQuantizationFour4x4Max         = pFuncList->pfQuantizationFour4x4Max;
  PSetMemoryZero pfSetMemZeroSize8                      = pFuncList->pfSetMemZeroSize8;
  PSetMemoryZero pfSetMemZeroSize64                     = pFuncList->pfSetMemZeroSize64;
  PScanFunc pfScan4x4Ac                                 = pFuncList->pfScan4x4Ac;
  PCalculateSingleCtrFunc pfCalculateSingleCtr4x4       = pFuncList->pfCalculateSingleCtr4x4;
  PGetNoneZeroCountFunc pfGetNoneZeroCount              = pFuncList->pfGetNoneZeroCount;
  PDeQuantizationFunc pfDequantizationFour4x4           = pFuncList->pfDequantizationFour4x4;
  const int32_t kiInterFlag                             = !IS_INTRA (pCurMb->uiMbType);
  const uint8_t kiQp                                    = pCurMb->uiChromaQp;
  uint8_t i, uiNoneZeroCount, uiNoneZeroCountMbDc       = 0;
  uint8_t uiNoneZeroCountOffset                         = (iUV - 1) << 1;   //UV==1 or 2
  uint8_t uiSubMbIdx                                    = 16 + ((iUV - 1) << 2); //uiSubMbIdx == 16 or 20
  int16_t* iChromaDc = pMbCache->pDct->iChromaDc[iUV - 1], *pBlock = pMbCache->pDct->iChromaBlock[ (iUV - 1) << 2];
  int16_t aDct2x2[4], j, aMax[4];
  int32_t iSingleCtr8x8 = 0;
  const int16_t* pMF = g_kiQuantMF[kiQp];
  const int16_t* pFF = g_kiQuantInterFF[ (!kiInterFlag) * 6 + kiQp];

  /* phasm-stego C.8.5 dual-recon snapshots. The clean post-quant chroma
   * DC + AC are captured here so the IDCT-site caller in
   * svc_encode_slice.cpp can recompute a clean reconstruction alongside
   * the live stego one. Gated on a stego session being registered so
   * non-stego encodes stay byte-identical to upstream. */
  const bool phasm_dr_active = (PhasmStegoGetEncPreEmit() != NULL);
  int16_t phasm_dr_clean_aDct2x2[4]   = {0, 0, 0, 0};
  int16_t phasm_dr_clean_acres[64];

  uiNoneZeroCountMbDc = pfQuantizationHadamard2x2 (pRes, pFF[0] << 1, pMF[0]>>1, aDct2x2, iChromaDc);

  /* phasm-stego C.8.5: snapshot post-Hadamard-quant clean DC before
   * HOOK-C may mutate aDct2x2 + iChromaDc. */
  if (phasm_dr_active) {
    phasm_dr_clean_aDct2x2[0] = aDct2x2[0];
    phasm_dr_clean_aDct2x2[1] = aDct2x2[1];
    phasm_dr_clean_aDct2x2[2] = aDct2x2[2];
    phasm_dr_clean_aDct2x2[3] = aDct2x2[3];
  }

  /* phasm-stego HOOK-C: chroma DC post-Hadamard-quant, dual-array writeback.
   * Per the audit (openh264-hook-sites-intra.md §"Chroma DC hook"), this
   * site sits immediately after pfQuantizationHadamard2x2 returns. The
   * Hadamard quantizer writes the 4 post-quant DC entries to BOTH:
   *   - aDct2x2[4]            (stack) — used below for dequant +
   *                                       re-injection into pRes (line
   *                                       ~480: pRes[0,16,32,48] = aDct2x2)
   *                                       which then feeds IDCT in
   *                                       OutputPMbWithoutConstructCsRsNoCopy
   *   - iChromaDc = pMbCache->pDct->iChromaDc[iUV - 1] — read directly
   *                                       by CABAC at svc_set_mb_syn_cabac.cpp
   *                                       (~line 587 for Cb / 593 for Cr)
   *
   * The audit notes pfQuantizationHadamard2x2 writes BOTH simultaneously
   * via ST64 inside the C reference (encode_mb_aux.cpp:272). Both arrays
   * hold the same 4 levels at the call return, in Hadamard-domain order
   * (which IS the scan order for chroma DC — no separate scan step).
   * Helper phasm_apply_coeff_hooks_dual sanity-asserts level_a == level_b
   * and writes the modified value to BOTH atomically.
   *
   * Position descriptor:
   *   block_cat    = CHROMA_DC (3)
   *   partition_idx = iUV - 1 (0=Cb, 1=Cr) — disambiguates plane
   *   sub_block    = 0 (chroma DC has no sub-block; the 4 entries are
   *                     the Hadamard-domain coefs of the 2x2 DC block)
   *   coeff_idx    = 0..3 (Hadamard order)
   *
   * Contract: non-zero-in/non-zero-out preserves uiNoneZeroCountMbDc and
   * the CBP-DC bit decision at line ~487 (pCurMb->uiCbp |= 0x10 if
   * uiNoneZeroCountMbDc > 0). Sign-flips preserve |level| so the
   * dequant + re-injection chain produces a symmetric perturbation in
   * the recon. */
  if (PhasmStegoGetEncPreEmit() != NULL) {
    PhasmStegoPos phasm_pos_c;
    phasm_pos_c.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos_c.mb_x          = (uint16_t)pCurMb->iMbX;
    phasm_pos_c.mb_y          = (uint16_t)pCurMb->iMbY;
    phasm_pos_c.partition_idx = (uint8_t)(iUV - 1);
    phasm_pos_c.sub_block     = 0;
    phasm_pos_c.coeff_idx     = 0;
    phasm_pos_c.block_cat     = 0;
    phasm_pos_c.ref_idx       = 0xff;
    phasm_pos_c.mv_component  = 0xff;
    phasm_pos_c._reserved     = 0;
    for (uint8_t phasm_c = 0; phasm_c < 4; ++phasm_c) {
      phasm_apply_coeff_hooks_dual(&phasm_pos_c,
                                   /*sub_block=*/0,
                                   /*coeff_idx=*/phasm_c,
                                   PHASM_BLOCK_CAT_CHROMA_DC,
                                   /*level_a (aDct2x2/stack)=*/&aDct2x2[phasm_c],
                                   /*level_b (iChromaDc/heap)=*/&iChromaDc[phasm_c]);
    }
  }

  pfQuantizationFour4x4Max (pRes, pFF,  pMF, aMax);

  /* phasm-stego C.8.5: snapshot post-quant clean AC strip (64 entries
   * spanning the 4 sub-blocks of this plane) before HOOK-G may mutate.
   * Raster slots 0/16/32/48 carry pre-DC-reinject scratch that gets
   * overwritten by the DC-reinject step below; we re-inject from the
   * separate DC snapshot for the clean recompute, so capturing
   * pre-DC-reinject is the right moment. */
  if (phasm_dr_active) {
    memcpy(phasm_dr_clean_acres, pRes, sizeof(int16_t) * 64);
  }

  for (j = 0; j < 4; j++) {
    if (aMax[j] == 0)
      pfSetMemZeroSize8 (pBlock, 32);
    else {
      pfScan4x4Ac (pBlock, pRes);
      if (kiInterFlag) {
        if (aMax[j] > 1)
          iSingleCtr8x8 += 9;
        else if (iSingleCtr8x8 < 7)
          iSingleCtr8x8 += pfCalculateSingleCtr4x4 (pBlock);
      } else
        iSingleCtr8x8 = INT_MAX;
    }
    pRes += 16;
    pBlock += 16;
  }
  pRes -= 64;

  /* phasm-stego HOOK-G: chroma AC inter (and intra by inheritance — Stage 5
   * will validate the intra side from the same site), post-quant POST-scan,
   * dual-array writeback. Per the audit (openh264-hook-sites-inter-coeff.md
   * §"Hook insertion point — chroma"), this site sits between the AC scan
   * j-loop above (which writes both pRes raster and pBlock zigzag-AC) and
   * the JVT-O079 chroma suppression test below (iSingleCtr8x8 < 7).
   *
   * At this point:
   *   - pRes points at chroma plane base (pCoeffLevel+256 for Cb, +320 Cr)
   *   - pBlock has advanced 64 (4 blocks * 16 entries); the iChromaBlock
   *     base for this plane is pMbCache->pDct->iChromaBlock[(iUV-1)<<2].
   *
   * Chroma AC zigzag scan (WelsScan4x4Ac_c) skips raster idx 0 (the DC
   * slot, which is overwritten by Hadamard-DC dequant re-injection at
   * lines 307-310). The 15 AC positions map scanned 0..14 → raster 1..15
   * via kPhasmChromaAcZigzag. pBlock[15] is hard-zeroed by the scan; we
   * don't hook scanned_idx=15.
   *
   * Position descriptor:
   *   block_cat    = CHROMA_AC (4)
   *   partition_idx = iUV-1 (0=Cb, 1=Cr) — disambiguates plane for the
   *                   phasm-side callback
   *   sub_block    = block_idx_within_plane (0..3)
   *   coeff_idx    = scanned_idx (0..14)
   *
   * The helper enforces non-zero-in/non-zero-out, so sign-flips and
   * suffix-LSB on |level|>=15 preserve iSingleCtr8x8 contribution. JVT
   * suppression decision below uses the pre-hook count which stays
   * stable for our contract. Chroma DC is a separate path
   * (HOOK-C, Stage 5) and is unaffected by this hook. */
  if (PhasmStegoGetEncPreEmit() != NULL) {
    PhasmStegoPos phasm_pos_g;
    phasm_pos_g.frame_num     = PhasmStegoGetFrameNum();
    phasm_pos_g.mb_x          = (uint16_t)pCurMb->iMbX;
    phasm_pos_g.mb_y          = (uint16_t)pCurMb->iMbY;
    phasm_pos_g.partition_idx = (uint8_t)(iUV - 1);
    phasm_pos_g.sub_block     = 0;
    phasm_pos_g.coeff_idx     = 0;
    phasm_pos_g.block_cat     = 0;
    phasm_pos_g.ref_idx       = 0xff;
    phasm_pos_g.mv_component  = 0xff;
    phasm_pos_g._reserved     = 0;
    int16_t* phasm_pblock_base = pMbCache->pDct->iChromaBlock[(iUV - 1) << 2];
    for (uint8_t phasm_sb = 0; phasm_sb < 4; ++phasm_sb) {
      int16_t* phasm_pres   = pRes              + (int32_t)phasm_sb * 16;
      int16_t* phasm_pblock = phasm_pblock_base + (int32_t)phasm_sb * 16;
      for (uint8_t phasm_s = 0; phasm_s < 15; ++phasm_s) {
        uint8_t phasm_r = kPhasmChromaAcZigzag[phasm_s];
        phasm_apply_coeff_hooks_dual(&phasm_pos_g,
                                     /*sub_block=*/phasm_sb,
                                     /*coeff_idx=*/phasm_s,
                                     PHASM_BLOCK_CAT_CHROMA_AC,
                                     /*level_a (raster)=*/&phasm_pres[phasm_r],
                                     /*level_b (zigzag)=*/&phasm_pblock[phasm_s]);
      }
    }
  }

  if (iSingleCtr8x8 < 7) { //from JVT-O079
    pfSetMemZeroSize64 (pRes, 128); // confirmed_safe_unsafe_usage
    ST16 (&pCurMb->pNonZeroCount[16 + uiNoneZeroCountOffset], 0);
    ST16 (&pCurMb->pNonZeroCount[20 + uiNoneZeroCountOffset], 0);
  } else {
    const uint8_t* kpNoneZeroCountIdx = &g_kuiMbCountScan4Idx[uiSubMbIdx];
    pBlock -= 64;
    for (i = 0; i < 4; i++) {
      uiNoneZeroCount = pfGetNoneZeroCount (pBlock);
      pCurMb->pNonZeroCount[*kpNoneZeroCountIdx++] = uiNoneZeroCount;
      pBlock += 16;
    }
    pfDequantizationFour4x4 (pRes, g_kuiDequantCoeff[pCurMb->uiChromaQp]);
    pCurMb->uiCbp &= 0x0F;
    pCurMb->uiCbp |= 0x20;
  }

  if (uiNoneZeroCountMbDc > 0) {
    WelsDequantIHadamard2x2Dc (aDct2x2, g_kuiDequantCoeff[kiQp][0]);
    if (2 != (pCurMb->uiCbp >> 4))
      pCurMb->uiCbp |= (0x01 << 4) ;
    pRes[0]  = aDct2x2[0];
    pRes[16] = aDct2x2[1];
    pRes[32] = aDct2x2[2];
    pRes[48] = aDct2x2[3];
  }

  /* ----------------------------------------------------------------- *
   * phasm-stego C.8.5: build CLEAN pre-IDCT pRes from snapshot for the
   * caller's dual-recon at the chroma IDCT site. Mirrors the live-stego
   * dequant + DC re-injection path on phasm_dr_clean_acres +
   * phasm_dr_clean_aDct2x2 (the snapshots captured pre-HOOK-C/G). The
   * IDCT-site caller pulls this clean buffer via
   * phasm_get_chroma_clean_pres() and runs pfIDctFourT4 on it.
   *
   * Note: pfDequantizationFour4x4 dequantizes FOUR 4x4 blocks (64
   * int16_t entries) per call. Chroma plane = 4 sub-blocks × 16 = 64
   * entries, so one call covers it.
   * ----------------------------------------------------------------- */
  if (phasm_dr_active) {
    if (iSingleCtr8x8 < 7) {
      /* Live path zeros pRes via pfSetMemZeroSize64 when JVT-O079
       * suppression fires. Mirror that on the clean snapshot. */
      memset(phasm_dr_clean_acres, 0, sizeof(phasm_dr_clean_acres));
    } else {
      pfDequantizationFour4x4 (phasm_dr_clean_acres, g_kuiDequantCoeff[pCurMb->uiChromaQp]);
    }

    if (uiNoneZeroCountMbDc > 0) {
      int16_t phasm_dr_clean_dc_work[4];
      phasm_dr_clean_dc_work[0] = phasm_dr_clean_aDct2x2[0];
      phasm_dr_clean_dc_work[1] = phasm_dr_clean_aDct2x2[1];
      phasm_dr_clean_dc_work[2] = phasm_dr_clean_aDct2x2[2];
      phasm_dr_clean_dc_work[3] = phasm_dr_clean_aDct2x2[3];
      WelsDequantIHadamard2x2Dc (phasm_dr_clean_dc_work, g_kuiDequantCoeff[kiQp][0]);
      phasm_dr_clean_acres[0]  = phasm_dr_clean_dc_work[0];
      phasm_dr_clean_acres[16] = phasm_dr_clean_dc_work[1];
      phasm_dr_clean_acres[32] = phasm_dr_clean_dc_work[2];
      phasm_dr_clean_acres[48] = phasm_dr_clean_dc_work[3];
    }

    phasm_stash_chroma_clean_pres((int32_t)(iUV - 1), phasm_dr_clean_acres);
  }
}


void    WelsRecPskip (SDqLayer* pCurLayer, SWelsFuncPtrList* pFuncList, SMB* pCurMb, SMbCache* pMbCache) {
  int32_t* iRecStride   = pCurLayer->iCsStride;
  uint8_t** pCsMb       = &pMbCache->SPicData.pCsMb[0];

  pFuncList->pfCopy16x16Aligned (pCsMb[0],  *iRecStride++,  pMbCache->pSkipMb,       16);
  pFuncList->pfCopy8x8Aligned (pCsMb[1],    *iRecStride++,  pMbCache->pSkipMb + 256, 8);
  pFuncList->pfCopy8x8Aligned (pCsMb[2],    *iRecStride,    pMbCache->pSkipMb + 320, 8);
  pFuncList->pfSetMemZeroSize8 (pCurMb->pNonZeroCount,  24);

  /* phasm-stego C.8.5 dual-recon for Pskip (Site C-7). Pskip has no
   * residual emitted -- clean == stego on all three planes. Just mirror
   * the same Skip prediction (which the existing pfCopy*Aligned calls
   * already wrote into pCsMb[0..2] = pDecPic) into pVisualRecPic at
   * the same MB offset. */
  if (PhasmStegoGetEncPreEmit() != NULL && pCurLayer->pVisualRecPic != NULL) {
    int32_t* pStrideAll = pCurLayer->iCsStride;
    const ptrdiff_t y_off  = pCsMb[0] - pCurLayer->pCsData[0];
    const ptrdiff_t cb_off = pCsMb[1] - pCurLayer->pCsData[1];
    const ptrdiff_t cr_off = pCsMb[2] - pCurLayer->pCsData[2];
    phasm_dual_recon_writeback ((uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY,
                                /*plane=*/0,
                                (int32_t)(y_off % pStrideAll[0]),
                                (int32_t)(y_off / pStrideAll[0]),
                                /*w=*/16, /*h=*/16,
                                /*clean_dst=*/NULL,
                                pCurLayer->pVisualRecPic->pData[0], pStrideAll[0],
                                /*clean_pixels=*/NULL,
                                pMbCache->pSkipMb, /*src_stride=*/16);
    phasm_dual_recon_writeback ((uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY,
                                /*plane=*/1,
                                (int32_t)(cb_off % pStrideAll[1]),
                                (int32_t)(cb_off / pStrideAll[1]),
                                8, 8, NULL,
                                pCurLayer->pVisualRecPic->pData[1], pStrideAll[1],
                                NULL, pMbCache->pSkipMb + 256, 8);
    phasm_dual_recon_writeback ((uint16_t)pCurMb->iMbX, (uint16_t)pCurMb->iMbY,
                                /*plane=*/2,
                                (int32_t)(cr_off % pStrideAll[2]),
                                (int32_t)(cr_off / pStrideAll[2]),
                                8, 8, NULL,
                                pCurLayer->pVisualRecPic->pData[2], pStrideAll[2],
                                NULL, pMbCache->pSkipMb + 320, 8);
  }
}

bool WelsTryPYskip (sWelsEncCtx* pEncCtx, SMB* pCurMb, SMbCache* pMbCache) {
  int32_t iSingleCtrMb = 0;
  int16_t* pRes = pMbCache->pCoeffLevel;
  const uint8_t kuiQp = pCurMb->uiLumaQp;

  int16_t* pBlock = pMbCache->pDct->iLumaBlock[0];
  uint16_t aMax[4], i, j;
  const int16_t* pMF = g_kiQuantMF[kuiQp];
  const int16_t* pFF = g_kiQuantInterFF[kuiQp];

  for (i = 0; i < 4; i++) {
    pEncCtx->pFuncList->pfQuantizationFour4x4Max (pRes, pFF,  pMF, (int16_t*)aMax);

    for (j = 0; j < 4; j++) {
      if (aMax[j] > 1) return false; // iSingleCtrMb += 9, can't be P_SKIP
      else if (aMax[j] == 1) {
        pEncCtx->pFuncList->pfScan4x4 (pBlock, pRes); //
        iSingleCtrMb += pEncCtx->pFuncList->pfCalculateSingleCtr4x4 (pBlock);
      }
      if (iSingleCtrMb >= 6) return false; //from JVT-O079
      pRes += 16;
      pBlock += 16;
    }
  }
  return true;
}

bool    WelsTryPUVskip (sWelsEncCtx* pEncCtx, SMB* pCurMb, SMbCache* pMbCache, int32_t iUV) {
  int16_t* pRes = ((iUV == 1) ? & (pMbCache->pCoeffLevel[256]) : & (pMbCache->pCoeffLevel[256 + 64]));

  const uint8_t kuiQp = g_kuiChromaQpTable[CLIP3_QP_0_51 (pCurMb->uiLumaQp +
                        pEncCtx->pCurDqLayer->sLayerInfo.pPpsP->uiChromaQpIndexOffset)];

  const int16_t* pMF = g_kiQuantMF[kuiQp];
  const int16_t* pFF = g_kiQuantInterFF[kuiQp];

  if (pEncCtx->pFuncList->pfQuantizationHadamard2x2Skip (pRes, pFF[0] << 1, pMF[0]>>1))
    return false;
  else {
    uint16_t aMax[4], j;
    int32_t iSingleCtrMb = 0;
    int16_t* pBlock = pMbCache->pDct->iChromaBlock[ (iUV - 1) << 2];
    pEncCtx->pFuncList->pfQuantizationFour4x4Max (pRes, pFF,  pMF, (int16_t*)aMax);

    for (j = 0; j < 4; j++) {
      if (aMax[j] > 1) return false;   // iSingleCtrMb += 9, can't be P_SKIP
      else if (aMax[j] == 1) {
        pEncCtx->pFuncList->pfScan4x4Ac (pBlock, pRes);
        iSingleCtrMb += pEncCtx->pFuncList->pfCalculateSingleCtr4x4 (pBlock);
      }
      if (iSingleCtrMb >= 7) return false; //from JVT-O079
      pRes += 16;
      pBlock += 16;
    }
    return true;
  }
}

} // namespace WelsEnc
