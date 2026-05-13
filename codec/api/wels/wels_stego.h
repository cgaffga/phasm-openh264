// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego C ABI for OpenH264.
//
// This header is the public surface phasm.app uses to instrument an
// OpenH264 encoder + decoder for steganographic bit override + cover
// state capture. Four callback families:
//
//   1. Encoder pre-emit hook (4 stego domains).
//      Fires after each candidate bin's value is decided but BEFORE the
//      encoder commits it to either the bitstream OR the reconstructed
//      reference frame. The callback can return -1 (no override; emit
//      original) or 0/1 (override with this bit). Override propagates
//      into both the CABAC writer AND the encoder's recon buffer per the
//      audit in `docs/design/video/h264/openh264-hook-sites.md` (in the
//      phasm consumer repo).
//
//   2. Decoder post-read hook (4 stego domains).
//      Fires after each candidate bin is parsed by the decoder. Pure
//      observation; no return value. Used by phasm's extraction path to
//      recover the message.
//
//   3. Mode-decision cost-vector capture (per-MB).
//      Fires once per MB after the encoder picks the final mb_type +
//      partition layout. Used by phasm's STC + cascade-safety planner to
//      pick positions across the encode that minimize visible distortion
//      while satisfying the message-bit count.
//
//   4. Dual-recon observation hook (per-block, Phase C.8.2+).
//      Fires from within the C.8.3-8 per-mode recon paths AFTER the
//      encoder has committed BOTH the clean reconstruction (into the
//      reference frame buffer pDecPic) AND the stego-mirrored
//      reconstruction (into pVisualRecPic). Pure observation; carries
//      pointers to both pixel blocks for cascade-verify, PSNR, and
//      visual-debug consumers. Default behaviour with no callback
//      registered: dual-recon still happens internally (memcpy clean →
//      pDecPic, stego → pVisualRecPic); only the observe-side notify is
//      skipped.
//
// All callbacks are optional. Setting a callback pointer to NULL or
// leaving the field zero-initialized disables that hook with zero
// per-bin overhead beyond a single null-check.
//
// Threading: callbacks are invoked from the encoder/decoder threads
// (single-threaded after Phase A.4 since iMultipleThreadIdc=1 in
// phasm-stego's deterministic defaults). Callers should not assume
// callback ordering across encode sessions; ordering WITHIN one encode
// session is deterministic (Phase A.4 ships byte-determinism).
//
// State model: registration is process-global for v1.0 (one phasm
// encoder instance per process). v1.x+ will switch to per-encoder
// opaque context once we have a multi-encoder use case to drive the
// design.

#ifndef WELS_STEGO_H
#define WELS_STEGO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * 1. Stego domain enum
 *
 * Must match the corresponding Rust enum in phasm-core. The integer
 * values are part of the ABI; do NOT renumber.
 * ------------------------------------------------------------------ */

typedef enum PhasmStegoDomain {
  PHASM_DOMAIN_COEFF_SUFFIX_LSB = 0,  /* LSB of EG suffix when |level| >= 15. */
  PHASM_DOMAIN_COEFF_SIGN       = 1,  /* Sign bit of each non-zero quantized coefficient. */
  PHASM_DOMAIN_MVD_SIGN         = 2,  /* Sign bit of each non-zero MVD component (x or y). */
  PHASM_DOMAIN_MVD_SUFFIX_LSB   = 3,  /* LSB of EG suffix when |MVD component| >= 9. */
  PHASM_DOMAIN__COUNT_           = 4
} PhasmStegoDomain;

/* ---------------------------------------------------------------------
 * 2. Position descriptor (encoder + decoder hooks share this)
 *
 * Identifies a single candidate stego bin uniquely in (frame, MB,
 * partition, sub-block, coefficient/MV-component) space. Fields not
 * meaningful for a given domain are set to 0xff (one byte) or 0xffff
 * (two bytes) by the producer. The struct is 16 bytes; layout is fixed
 * to keep the Rust FFI safe.
 *
 * Field validity per domain:
 *
 *   |                | COEFF_*  | MVD_*    |
 *   |---------------:|:--------:|:--------:|
 *   | frame_num      |    ✓     |    ✓     |
 *   | mb_x, mb_y     |    ✓     |    ✓     |
 *   | domain         |    ✓     |    ✓     |
 *   | partition_idx  |   0..3¹  |   0..3   |
 *   | sub_block      |   0..15  |   0xff   |
 *   | coeff_idx      |   0..15  |   0xff   |
 *   | block_cat      | ECtxBC²  |   0xff   |
 *   | ref_idx        |   0xff   |   0..15  |
 *   | mv_component   |   0xff   |   0|1³   |
 *
 *   ¹ For intra MBs, partition_idx is always 0.
 *   ² ECtxBlockCat enum value from codec/encoder/core/inc — one of
 *     LUMA_DC, LUMA_AC, LUMA_4x4, CHROMA_DC, CHROMA_AC.
 *   ³ 0 = MVD_x component, 1 = MVD_y component.
 * ------------------------------------------------------------------ */

typedef struct PhasmStegoPos {
  uint32_t frame_num;       /* set via WelsStegoSetFrameNum before each frame */
  uint16_t mb_x;            /* macroblock column (in MB units) */
  uint16_t mb_y;            /* macroblock row */
  uint8_t  domain;          /* PhasmStegoDomain */
  uint8_t  partition_idx;   /* inter: 0..3; intra: 0 */
  uint8_t  sub_block;       /* coeff: 0..15 sub-block index; MVD: 0xff */
  uint8_t  coeff_idx;       /* coeff: 0..15 scan position; MVD: 0xff */
  uint8_t  block_cat;       /* coeff: ECtxBlockCat enum; MVD: 0xff */
  uint8_t  ref_idx;         /* MVD: list-0 ref_idx 0..15; coeff: 0xff */
  uint8_t  mv_component;    /* MVD: 0=x,1=y; coeff: 0xff */
  uint8_t  _reserved;       /* pad to 4-byte boundary */
} PhasmStegoPos;  /* 16 bytes */

/* ---------------------------------------------------------------------
 * 3. Mode-decision cost descriptor (cost-vector capture hook)
 *
 * One per MB, fired after mode decision finalizes. Provides the chosen
 * mb_type + the estimated number of bins available per stego domain in
 * this MB. The planner uses this for cross-domain capacity accounting.
 *
 * Detailed per-mode rate-distortion costs (SAD/SATD/SSD per candidate
 * mode) are deferred to v1.x+ when STC's rate model is ready to consume
 * them. For v1.0, the planner uses coarse capacity counts + a
 * fixed-cost-per-bin heuristic (matching the existing pure-Rust encoder
 * planner's model in `core/src/codec/h264/stego/`).
 * ------------------------------------------------------------------ */

/* mb_type classification — phasm-defined, NOT the H.264 spec mb_type.
 * Carries the information a consumer needs to filter pre-emit hook fires
 * by block_cat consistency (since the encoder may evaluate multiple
 * candidate modes per MB but only the winner's coefficients reach the
 * wire). Each value names the EMITTED-RESIDUAL shape:
 *
 *   PHASM_MB_TYPE_I_4x4    : intra 4x4 luma residual (block_cat 2) +
 *                            chroma DC/AC (block_cat 3/4).
 *   PHASM_MB_TYPE_I_16x16  : intra 16x16 luma DC (block_cat 0) +
 *                            luma AC (block_cat 1) + chroma DC/AC.
 *   PHASM_MB_TYPE_I_8x8    : intra 8x8 luma residual (block_cat 5)
 *                            + chroma. (High-profile only.)
 *   PHASM_MB_TYPE_INTER    : inter prediction with 4x4 luma residual
 *                            (block_cat 2) + chroma.
 *   PHASM_MB_TYPE_SKIP     : P_Skip / B_Skip / B_Direct — no residual
 *                            emitted. Drop all coefficient hook fires
 *                            for this MB.
 */
#define PHASM_MB_TYPE_I_4x4    0
#define PHASM_MB_TYPE_I_16x16  1
#define PHASM_MB_TYPE_I_8x8    2
#define PHASM_MB_TYPE_INTER    3
#define PHASM_MB_TYPE_SKIP     4
#define PHASM_MB_TYPE_OTHER    5

typedef struct PhasmStegoMdCost {
  uint32_t frame_num;
  uint16_t mb_x;
  uint16_t mb_y;
  uint8_t  mb_type;         /* PHASM_MB_TYPE_* classification */
  uint8_t  cbp;             /* CBP nibble: low 4 = luma 8x8 CBP, high 4 = chroma. 0 in ABI 1.1.0. */
  uint16_t _reserved;
  uint16_t capacity[PHASM_DOMAIN__COUNT_];  /* per-domain bin count, 0 in ABI 1.1.0 */
} PhasmStegoMdCost;  /* 24 bytes */

/* ---------------------------------------------------------------------
 * 4. Encoder pre-emit callback
 *
 * Called for each candidate stego bin BEFORE it is committed to either
 * the bitstream or the reconstructed reference frame. The callback can
 * inspect the position descriptor + the bit value the encoder would
 * emit without intervention, then return:
 *
 *   -1   : no override; emit `original`.
 *    0|1 : override; emit this value AND propagate it into the
 *          encoder's reconstruction path (so the next MB's intra
 *          prediction / next P-frame's MC sees the modified value).
 *
 * Any return value outside {-1, 0, 1} is treated as -1 (no override).
 *
 * Contract:
 *   - The callback MUST NOT block. Encoders may call this thousands of
 *     times per frame.
 *   - The callback MUST be deterministic per (pos, original) tuple if
 *     called multiple times in one encode (the encoder has VLC overflow
 *     re-encode loops that can replay an MB).
 *   - For COEFF domains: phasm contracts that the input level and the
 *     output level must both be non-zero. The encoder helper enforces
 *     this — if a return value would set the level to zero, it is
 *     treated as -1 (no override).
 * ------------------------------------------------------------------ */

typedef int32_t (*PhasmStegoEncPreEmitFn)(const PhasmStegoPos* pos,
                                          int32_t original,
                                          void* user_data);

/* ---------------------------------------------------------------------
 * 5. Decoder post-read callback
 *
 * Fires after each stego-domain bin is read by the decoder during
 * parsing. Pure observation; no return value. The decoded bit value
 * is delivered via `bit_value`. Used by phasm to extract the embedded
 * message.
 * ------------------------------------------------------------------ */

typedef void (*PhasmStegoDecPostReadFn)(const PhasmStegoPos* pos,
                                        int32_t bit_value,
                                        void* user_data);

/* ---------------------------------------------------------------------
 * 6. Mode-decision cost-capture callback
 *
 * Fires once per MB after mode decision finalizes, immediately before
 * the bitstream writer emits the MB. Pure observation; no return value.
 *
 * Primary use case (ABI 1.1.0): consumers can pair this with the
 * pre-emit callback to filter hook fires by `block_cat` ↔ `mb_type`
 * consistency. The encoder evaluates I_4x4 candidate for every intra
 * MB (firing block_cat=2 hooks), then may switch to I_16x16 if the
 * cost is lower. Without `mb_type` it is impossible to distinguish
 * the losing-mode candidate fires from the winner-mode wire emissions.
 *
 * Future use case: `capacity[]` will carry per-domain bin counts so a
 * cross-MB cost-vector planner can size its STC plan against the
 * full encode without re-running mode decision.
 * ------------------------------------------------------------------ */

typedef void (*PhasmStegoMdCostFn)(const PhasmStegoMdCost* cost,
                                   void* user_data);

/* ---------------------------------------------------------------------
 * 6.5 Dual-recon observation callback (Phase C.8.2+)
 *
 * Fires from the internal `phasm_dual_recon_writeback` helper AFTER it
 * has committed clean pixels to pDecPic AND stego pixels to
 * pVisualRecPic. Pure observation; no return value.
 *
 * Parameters:
 *   frame_num     : current frame number set via WelsStegoSetFrameNum
 *   mb_x, mb_y    : macroblock coordinates of the containing MB
 *   plane         : 0 = luma (Y), 1 = chroma U (Cb), 2 = chroma V (Cr)
 *   pixel_x       : pixel x-offset within the frame plane (in pixels)
 *   pixel_y       : pixel y-offset within the frame plane
 *   block_w       : width of the committed block (4, 8, or 16 in v1.0)
 *   block_h       : height of the committed block
 *   clean_pixels  : pointer to the clean (un-flipped) recon block,
 *                   `block_w * block_h` bytes, rows packed with
 *                   `src_stride` between row starts. Valid for the
 *                   duration of the call only; copy if needed beyond.
 *   stego_pixels  : pointer to the stego-flipped recon block; same
 *                   layout, also valid for the call duration only.
 *   src_stride    : byte distance between consecutive rows of both
 *                   `clean_pixels` and `stego_pixels`. Caller chooses;
 *                   typically equals block_w for contiguous scratch.
 *   user_data     : opaque pointer registered alongside the callbacks
 *
 * Used by phasm tests + cascade-verify orchestrator to diff clean vs
 * stego per block, compute PSNR, and dump per-MB stego deltas. In
 * production builds the callback is null and the helper does the
 * memcpys alone with no observation overhead.
 * ------------------------------------------------------------------ */

typedef void (*PhasmStegoDualReconFn)(uint32_t frame_num,
                                      uint16_t mb_x,
                                      uint16_t mb_y,
                                      uint8_t  plane,
                                      int32_t  pixel_x,
                                      int32_t  pixel_y,
                                      int32_t  block_w,
                                      int32_t  block_h,
                                      const uint8_t* clean_pixels,
                                      const uint8_t* stego_pixels,
                                      int32_t  src_stride,
                                      void*    user_data);

/* ---------------------------------------------------------------------
 * 7. Callback table
 *
 * Caller fills in only the callbacks it cares about; NULL means "no
 * hook for this domain". The struct can grow in future ABI revisions
 * by appending fields; the `struct_size` first field carries the size
 * the caller compiled against so the encoder can detect old callers.
 * ------------------------------------------------------------------ */

typedef struct PhasmStegoCallbacks {
  size_t                   struct_size;       /* sizeof(PhasmStegoCallbacks) at compile time */
  PhasmStegoEncPreEmitFn   enc_pre_emit;      /* encoder bin pre-emit */
  PhasmStegoDecPostReadFn  dec_post_read;     /* decoder bin post-read */
  PhasmStegoMdCostFn       md_cost_capture;   /* per-MB cost capture */
  PhasmStegoDualReconFn    dual_recon_observe;/* per-block dual-recon observe (ABI 1.2.0+) */
} PhasmStegoCallbacks;

/* ---------------------------------------------------------------------
 * 8. Registration API
 *
 * Process-global callback table. Re-registration replaces. NULL
 * `callbacks` resets to all-NULL (no hooks).
 *
 * `user_data` is passed to each callback unchanged. Caller owns
 * lifetime; library does not copy or free.
 *
 * Returns 0 on success, non-zero on failure (e.g. struct_size is older
 * than the library's minimum supported version).
 * ------------------------------------------------------------------ */

int WelsRegisterPhasmStegoCallbacks(const PhasmStegoCallbacks* callbacks,
                                    void* user_data);

/* ---------------------------------------------------------------------
 * 9. Per-frame state
 *
 * Caller must set the current frame number before each frame is encoded
 * (or decoded). Goes into the `frame_num` field of every PhasmStegoPos
 * + PhasmStegoMdCost delivered to callbacks for that frame. Reset to 0
 * at the start of each new encode/decode session.
 * ------------------------------------------------------------------ */

void WelsStegoSetFrameNum(uint32_t frame_num);

/* ---------------------------------------------------------------------
 * 10. Library version probe
 *
 * Returns the wels_stego ABI version this library was built with.
 * Format: (MAJOR << 16) | (MINOR << 8) | PATCH. MAJOR bumps on
 * breaking changes; MINOR on additive (new callback fields appended
 * to the end of structs); PATCH on doc-only changes.
 *
 * Current version: 1.2.0 (0x010200). 1.2.0 adds the
 * `dual_recon_observe` callback (Phase C.8.2) for per-block visibility
 * into the clean-vs-stego reconstruction pair the encoder commits to
 * pDecPic + pVisualRecPic respectively. 1.1.0 wired `md_cost_capture`;
 * 1.0.0 shipped the original 3 callbacks.
 * ------------------------------------------------------------------ */

#define PHASM_STEGO_ABI_VERSION 0x010200u
uint32_t WelsStegoAbiVersion(void);

/* ---------------------------------------------------------------------
 * 11. Phase C.8.13(b) debug counters (#455)
 *
 * Atomic counters for `phasm_apply_coeff_hooks_dual` to narrow the
 * residual cascade-leak. All read-only from the host; reset via the
 * dedicated entry point. Counters increment on the hook helper hot
 * path with `std::memory_order_relaxed` — ~3 ns/fire overhead, kept
 * unconditional so the host doesn't need a build flag to enable.
 *
 * Usage: encode once, read counters, compare against observed wire
 * divergences. If `mismatch_bails == diverge_count`, the precondition
 * is the leak. If 0, look elsewhere (RDO sim, JVT-O079 boundary, …).
 * ------------------------------------------------------------------ */

uint64_t phasm_get_hook_dual_fires_total(void);
uint64_t phasm_get_hook_dual_bail_level_a_zero(void);
uint64_t phasm_get_hook_dual_bail_level_mismatch(void);
uint64_t phasm_get_hook_dual_applied(void);
void     phasm_reset_hook_dual_counters(void);

/* Single-write helper counters (HOOK-A I_16x16 DC, HOOK-B I_16x16 AC,
 * HOOK-E I_4x4). HOOK-E in particular is the suspect for the residual
 * cascade leak — when a P-frame MB picks the I_4x4 intra mode as its
 * winning candidate, HOOK-E runs instead of HOOK-F. `phasm_reset_hook
 * _dual_counters` resets the single-write counters too. */
uint64_t phasm_get_hook_single_fires_total(void);
uint64_t phasm_get_hook_single_bail_level_zero(void);
uint64_t phasm_get_hook_single_applied(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_H */
