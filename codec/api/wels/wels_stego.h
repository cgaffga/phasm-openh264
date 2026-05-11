// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Christoph Gaffga (phasm.app stego extension)
//
// phasm-stego C ABI for OpenH264.
//
// This header is the public surface phasm.app uses to instrument an
// OpenH264 encoder + decoder for steganographic bit override + cover
// state capture. Three callback families:
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

typedef struct PhasmStegoMdCost {
  uint32_t frame_num;
  uint16_t mb_x;
  uint16_t mb_y;
  uint8_t  mb_type;         /* mb_type enum value (I_16x16 / I_4x4 / P_16x16 / ... ) */
  uint8_t  cbp;             /* CBP nibble: low 4 bits = luma 8x8 CBP, high 4 = chroma CBP */
  uint16_t _reserved;
  uint16_t capacity[PHASM_DOMAIN__COUNT_];  /* candidate bin count per domain */
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
 * Fires once per MB after mode decision finalizes. Pure observation;
 * no return value. Used by phasm's planner to estimate per-MB capacity
 * across the encode before committing to position allocation.
 * ------------------------------------------------------------------ */

typedef void (*PhasmStegoMdCostFn)(const PhasmStegoMdCost* cost,
                                   void* user_data);

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
 * Current version: 1.0.0 (0x010000).
 * ------------------------------------------------------------------ */

#define PHASM_STEGO_ABI_VERSION 0x010000u
uint32_t WelsStegoAbiVersion(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_H */
