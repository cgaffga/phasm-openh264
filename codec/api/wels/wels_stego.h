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

/* ---------------------------------------------------------------------
 * 6.7 Pass-2 replay architecture
 *
 * Option A — see `docs/design/video/h264/pass2-replay-architecture.md`
 * in the phasm repo. Closes the cascade-safety whack-a-mole loop by
 * letting Pass-1 capture the encoder's complete per-MB mode decision
 * and Pass-2 force-replay those decisions, short-circuiting RDO/ME.
 *
 * `PhasmStegoMbDecision` is the per-MB cache record. Fields not
 * relevant to the chosen mb_type are unused by the encoder during
 * replay (e.g. intra-pred-mode arrays are ignored for P_16x16; MV
 * arrays are ignored for intra MBs). The caller cache MUST round-trip
 * the bytes through itself without interpreting them — anything the
 * encoder writes during capture, it expects to read back during
 * replay verbatim.
 *
 * `PhasmStegoPassMode` selects encoder behaviour:
 *   PASSTHROUGH (0) = default; no capture/replay fires.
 *   CAPTURE     (1) = encoder runs RDO/ME, calls capture callback
 *                     once per MB with finalized decision.
 *   REPLAY      (2) = encoder calls replay callback at each MB entry;
 *                     if returns 1, populates state from
 *                     *out_decision and skips RDO/ME; if 0, falls
 *                     back to RDO/ME (e.g. cache miss).
 * ------------------------------------------------------------------ */

typedef enum PhasmStegoPassMode {
  PHASM_PASS_PASSTHROUGH = 0,
  PHASM_PASS_CAPTURE     = 1,
  PHASM_PASS_REPLAY      = 2,
} PhasmStegoPassMode;

typedef struct PhasmStegoMbDecision {
  /* === Identity === */
  uint32_t frame_num;              /* set via WelsStegoSetFrameNum */
  uint16_t mb_x;                   /* macroblock column (MB units) */
  uint16_t mb_y;                   /* macroblock row */

  /* === Top-level mb_type ===
   * `ui_mb_type` holds the OH264-internal `Mb_Type` bitfield value
   * verbatim (lower 16 bits). It can be set directly on
   * `pCurMb->uiMbType` during replay. uint16_t covers all baseline +
   * Main-profile flags through MB_TYPE_P1L1 (0x8000); the upper bits
   * of the underlying uint32_t are not used by phasm. */
  uint16_t ui_mb_type;             /* OH264 MB_TYPE_* bitfield value */
  uint8_t  mb_type;                /* PHASM_MB_TYPE_* classification */
  int8_t   qp_delta;               /* signed; 0 in CQP mode */
  uint8_t  sub_mb_type[4];         /* P_8x8 / B_8x8 per-8x8 sub-mode */

  /* === Motion (per 4x4 sub-block × 2 reference lists) ===
   * mv_x/y[4x4_scan_idx][list]. For non-B-slice modes, list-1 entries
   * are zero. For partition modes (16x16, 16x8, 8x16, 8x8 + subs),
   * the 4x4 slots within a partition share the same MV — the encoder
   * writes the same value to all relevant 4x4 entries during capture
   * so replay just copies them back to pCurMb->sMv[]. */
  int16_t  mv_x[16][2];            /* qpel MV x per 4x4 per list */
  int16_t  mv_y[16][2];            /* qpel MV y */
  int8_t   ref_idx[4][2];          /* per-partition × list */
  uint8_t  bipred_dir[4];          /* B-slice per partition: 0=L0 1=L1 2=Bi 3=Direct */

  /* === Intra prediction === */
  uint8_t  intra16_pred_mode;      /* I_16x16 only (0..3) */
  uint8_t  i4x4_pred_mode[16];     /* I_4x4 only (per 4x4 sub-block, 0..8) */
  uint8_t  chroma_pred_mode;       /* I-slice + intra-in-P */

  /* === Padding / future expansion === */
  uint8_t  _reserved[6];
} PhasmStegoMbDecision;  /* 180 bytes (4-byte aligned) */

/* Pass-1 capture callback. Fires once per MB AFTER mode decision is
 * finalized and BEFORE WelsInterMbEncode / WelsIMbChromaEncode runs
 * the residual + CABAC emit pipeline. Pure observation; no return.
 * Consumer copies `decision` into its own cache keyed by (frame_num,
 * mb_x, mb_y).
 *
 * Lifetime: `decision` is valid only for the call duration. Copy.
 * Reentrancy: the encoder may evaluate multiple candidate modes per
 * MB during RDO and call capture multiple times for the same MB; the
 * caller should accept "last write wins" semantics. */
typedef void (*PhasmStegoCaptureMbDecisionFn)(
    const PhasmStegoMbDecision* decision,
    void* user_data);

/* Pass-2 replay callback. Fires at the START of each MB's mode
 * decision in the encoder. Consumer fills *out_decision with the
 * cached decision and returns 1; returns 0 if no cache entry for
 * this MB (encoder falls back to running RDO/ME as usual).
 *
 * Determinism: returning 1 with a partially-filled decision is a
 * caller bug; the consumer MUST fill every field the encoder will
 * read. Phasm's cache is per-GOP and populated by Pass-1, so misses
 * indicate a frame_num / coordinate mismatch — return 0 and let
 * RDO/ME run (gate harness flags it). */
typedef int (*PhasmStegoReplayMbDecisionFn)(
    uint32_t frame_num,
    uint16_t mb_x,
    uint16_t mb_y,
    PhasmStegoMbDecision* out_decision,
    void* user_data);

/* Set encoder's pass mode for the next encode() call. Caller sets
 * before each pass (typically: CAPTURE for Pass-1, REPLAY for
 * Pass-2). Default after fresh registration is PASSTHROUGH. */
void WelsStegoSetPassMode(PhasmStegoPassMode mode);

typedef struct PhasmStegoCallbacks {
  size_t                          struct_size;            /* sizeof(PhasmStegoCallbacks) at compile time */
  PhasmStegoEncPreEmitFn          enc_pre_emit;           /* encoder bin pre-emit */
  PhasmStegoDecPostReadFn         dec_post_read;          /* decoder bin post-read */
  PhasmStegoMdCostFn              md_cost_capture;        /* per-MB cost capture */
  PhasmStegoDualReconFn           dual_recon_observe;     /* per-block dual-recon observe (ABI 1.2.0+) */
  PhasmStegoCaptureMbDecisionFn   capture_mb_decision;    /* Pass-1 capture (ABI 1.3.0+) */
  PhasmStegoReplayMbDecisionFn    replay_mb_decision;     /* Pass-2 replay (ABI 1.3.0+) */
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
 * Build-time sanity check that the linked fork matches the bindings.
 * Bumped on every public ABI change. Phasm owns both sides of this
 * boundary — fork + Rust bindings ship together — so a mismatch
 * here means someone forgot to bump the SHA pin.
 * ------------------------------------------------------------------ */

#define PHASM_STEGO_ABI_VERSION 0x010301u
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

/* ---------------------------------------------------------------------
 * Phase C.9.0 (#482) — Pass-1 visual_recon disable. Set BEFORE encoder
 * InitializeExt; default 1 (the C.8 baseline). When 0, InitDqLayers
 * skips the pVisualRef[] mirror-pool allocation, leaving pVisualDecPic /
 * pVisualRecPic NULL for this encoder instance. Every per-MB mirror site
 * and the C.8.8 dual deblock pass already gate on `pVisualRecPic !=
 * NULL`, so disabling here cleanly bypasses ALL visual_recon work.
 * Intended for cover-probe passes whose bitstream is walked then
 * discarded (no mp4 mux, no fsnr observation).
 * ------------------------------------------------------------------ */
void phasm_set_dual_recon_enabled(int enabled);
int  phasm_get_dual_recon_enabled(void);

/* P3.3a (2026-05-25) — pDecPic Y plane capture for post-frame DPB
 * correction. phasm_set_dec_pic_y is called by the fork's ref_list_mgr
 * after DPB promotion. phasm_encoder_get_enc_dec_pic is called by the
 * shim to expose the pointer to Rust. */
void phasm_set_dec_pic_y(uint8_t* y, int32_t stride);
bool phasm_encoder_get_enc_dec_pic(void* enc, uint8_t** y, int32_t* stride);

/* P3.3b (2026-05-25) — post-quant coefficient capture + replay mode.
 *
 * Capture: phasm_set_post_quant_callback registers a function that
 * receives the quantized coefficient buffer (pCoeffLevel, 384 int16_t)
 * after each MB's quantization completes. The callback fires between
 * quantize and dequant+IDCT in svc_encode_mb.cpp. Pass NULL to
 * unregister.
 *
 * Replay: phasm_set_coeff_replay_mode(1) puts the encoder in replay
 * mode. In replay mode, the encoder skips its own quantize step and
 * reads coefficients from the buffer set by phasm_set_replay_coeffs.
 * Prediction + CABAC emit + dequant + IDCT still run. Call
 * phasm_set_replay_coeffs before each MB's encode to supply the
 * (possibly STC-flipped) coefficient array. */
typedef void (*PhasmPostQuantCallback)(
    uint32_t frame_num, uint16_t mb_x, uint16_t mb_y,
    const int16_t* coeffs, int32_t coeff_count,
    uint8_t cbp_luma, uint8_t cbp_chroma, int32_t qp);

void phasm_set_post_quant_callback(PhasmPostQuantCallback cb);
void phasm_set_coeff_replay_mode(int enabled);
void phasm_set_replay_coeffs(const int16_t* coeffs, int32_t count);
PhasmPostQuantCallback phasm_get_post_quant_callback(void);
int phasm_get_coeff_replay_mode(void);
const int16_t* phasm_get_replay_coeffs(int32_t* count);

/* ---------------------------------------------------------------------
 * Phase 4 (#538) — Wire-only bypass-bin override (Layer 2 of Pass-2).
 *
 * The mutating hook lineage (`apply_coeff_hooks_to_level`,
 * `phasm_apply_mvd_hooks`) writes the encoder's stored level / MV
 * before CABAC emit, so the natural CABAC encoding produces the
 * desired wire bin. The side effect is that the encoder's pDecPic
 * reflects the override — a cascade waiting to break the next MB.
 *
 * Phase 4 keeps the encoder state CLEAN. The override applies at
 * the CABAC bypass-bin emit site only: the caller computes the
 * desired bin from the current encoder state (clean Pass-1 value)
 * and the registered override map, then `WelsCabacEncodeBypassOne`
 * emits the OVERRIDDEN bin. The encoder's stored level / MV never
 * mutates. pDecPic stays at clean Pass-1 recon by construction.
 *
 * Step 4.1 (this commit) — plumbing only. Adds the dispatch entry
 * point. Stub returns `orig_bin` (no-op). Steps 4.2-4.5 progressively
 * patch the 4 emit sites (CoeffSign / CoeffSuffixLsb / MvdSign /
 * MvdSuffixLsb) and migrate the mutating hooks to populate scratch
 * instead of mutating. Full design at
 * `docs/design/video/h264/pass2-replay-phase4-plan.md`.
 * ------------------------------------------------------------------ */

/* Dispatched at each CABAC bypass-bin emit site that phasm overrides.
 * Returns the bin to emit: `orig_bin` when no override is registered
 * for this position+domain, or 0/1 when the consumer's override map
 * specifies otherwise.
 *
 * `pos` carries the position identifying fields (sub_block,
 * coeff_idx, mv_component, ref_idx, mb_x, mb_y, frame_num, …) that
 * the emit-site caller fills in. `domain` is one of the four stego
 * domains the function targets (`PHASM_DOMAIN_COEFF_SIGN` /
 * `_COEFF_SUFFIX_LSB` / `_MVD_SIGN` / `_MVD_SUFFIX_LSB`).
 *
 * Returning `-1` is reserved for callbacks that don't want to
 * override; the caller treats it as "emit `orig_bin`". */
int phasm_apply_bypass_bin_override (uint8_t domain,
                                      const PhasmStegoPos* pos,
                                      int orig_bin);

/* Phase 4.5.b (#538) — wire-only override mode gate.
 *
 * When enabled (set to non-zero), the mutating-hook helpers route
 * stego override decisions into the per-MB scratch table (read by
 * `phasm_apply_bypass_bin_override` at CABAC emit) and do NOT
 * mutate the encoder's stored level / MV state. Pass-2's pDecPic
 * stays byte-identical to Pass-1's, and the stego override only
 * manifests on the wire via the bypass-bin emit hooks.
 *
 * When disabled (default), the helpers keep their pre-4.5
 * behaviour: invoke the Rust callback, mutate *level / MV state
 * in place. Required for backwards compatibility with the C.8.x
 * dual-recon machinery and the 19 lib tests that verify the
 * mutated-state path.
 *
 * Default OFF. Set to non-zero before encoding to opt into the
 * wire-only path. Phase 5 (#539) flips the default to ON once
 * the C.8.x machinery is deleted. */
void phasm_set_use_wire_only_overrides (int enabled);
int  phasm_get_use_wire_only_overrides (void);

/* #548 v1.0 BLOCKER fix (2026-05-18) — Reset libencoder-side phasm
 * statics at start of a new encode session. Call from the Rust
 * orchestrator before each `encode_yuv_with_pre_framed_bits_4domain`
 * invocation so consecutive calls don't share scratch / last-MB /
 * wire-only flag state. The libcommon-side state has separate entry
 * points (`phasm_reset_dirty_flags`, etc.) — call those too if you
 * need a full fork-state wipe. */
void phasm_reset_encoder_session_state (void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* WELS_STEGO_H */
