# phasm-openh264 — OpenH264 fork with steganography hooks

This is a fork of Cisco's [OpenH264](http://www.openh264.org/) v2.6.0 with
a custom C ABI surface (`wels_stego.h`) that lets external callers
override coefficient and motion-vector bits during H.264 encoding +
read them back during decoding.

The fork exists to power H.264 video steganography in
[phasm.app](https://phasm.app) — a steganography app that hides
encrypted text messages in JPEG photos and (with this fork) MP4
videos. The unmodified upstream encoder + decoder are preserved; the
stego hooks are additive and inert unless callbacks are registered.

If you're looking for the upstream codec, go to
[github.com/cisco/openh264](https://github.com/cisco/openh264) — this
fork is not a general-purpose codec replacement.

## Status

- **Phase D shipped 2026-05-18 → v1.0 production default in
  [phasm-core](https://crates.io/crates/phasm-core).** Production
  wire_only orchestrator default (commit `14ad952`), Phase 4 replay
  wireup + Phase 5 cascade-safety closed, full 53/53 corpus +
  visual_psnr + cascade_safety + pass2_replay + streaming + 4domain
  + pure_rust_per_gop + lib gates green at 1080p. Used by
  [phasm-core v0.3.0+](https://crates.io/crates/phasm-core) as the
  default H.264 backend.
- **Sibling forks (AV1) shipped 2026-05-21**:
  [phasm-rav1e](https://github.com/cgaffga/phasm-rav1e) (encoder) +
  [phasm-dav1d](https://github.com/cgaffga/phasm-dav1d) (decoder)
  follow the same hook-surface pattern for AV1 video stego. AV1
  forks are royalty-free per AOM AV1; this OpenH264 fork retains
  the Via LA AVC patent-pool posture.
- **Phase A.5 (hook surface, Stages 0–8): SHIPPED.** 15 stego hooks
  across encoder paths (intra coeffs, inter coeffs, single + partitioned
  MVDs).
- **Phase C.8 (visual_recon cascade-break, C.8.0–C.8.11): SHIPPED
  2026-05-13.** Dual `pVisualRecPic` mirror keeps the encoder's
  reference DPB pristine (cover-side) while a parallel reconstruction
  path tracks the stego-modified pixels. Closes the inter-frame leak
  class where a flipped-coefficient MB on frame N could pollute the
  motion-compensation references for frames N+1..GOP-end.
- **v1.0 state:** hook ABI + dual-recon + wire_only orchestrator path
  are stable. Pinned at fork branch `phasm-stego`. Tagged as
  `phasm-stego-v0.1.0` for the hook-surface freeze.
- **C.8.13(b) CLOSED 2026-05-13:** the round-trip flake was two
  bugs — one fork-side, one orchestrator-side. (1) HOOK-F (P-luma
  inter dual-write) was passing `coeff_idx_scanned` where the
  consumer's BC=2 canonical-key translation expected raster
  (fork commit `222457ce`, closed ~32%). (2) The remaining ~68% was
  a Rust-side mb_type filter race between `md_cost` (fires after
  the hook) and HOOK-F (reads pre-frame mb_type), fixed
  downstream by bypassing the filter. 32-seed audit went 38 → 26 →
  **0** divergences. All consumer round-trip tests green.

## What this fork adds

A public C ABI at [`codec/api/wels/wels_stego.h`](codec/api/wels/wels_stego.h)
with two entry points:

```c
void WelsRegisterPhasmStegoCallbacks(
    const PhasmStegoCallbacks* cbs,
    void* user_data);

void WelsStegoSetFrameNum(uint32_t frame_num);
```

The callbacks fire from 15 instrumented sites across the encoder
(`codec/encoder/core/src/svc_encode_mb.cpp` for intra + inter
coefficients, `codec/encoder/core/src/svc_base_layer_md.cpp` for
motion-vector differences) and one site in the decoder (post-read on
the bypass-bin fast path).

Hook complement (Phase A.5 Stages 0–8, shipped):

| Hook ID  | Stage | Mode                                | File / anchor                                    |
|----------|-------|-------------------------------------|---------------------------------------------------|
| A        | 1     | I_16x16 luma DC                     | `svc_encode_mb.cpp:74→`                           |
| B        | 2     | I_16x16 luma AC (×4 strips)         | `svc_encode_mb.cpp:79→`                           |
| C        | 5     | Chroma DC (2x2 Hadamard)            | `svc_encode_mb.cpp:264→`                          |
| D        | 5     | Chroma AC                           | `svc_encode_mb.cpp:266→`                          |
| E        | 3     | I_4x4 luma intra-MB cascade         | `svc_encode_mb.cpp:165→`                          |
| F        | 4     | P luma inter (dual-array)           | `svc_encode_mb.cpp:217–221`                       |
| G        | 4     | P chroma inter (dual-array)         | `svc_encode_mb.cpp:285`                           |
| H1       | 6     | P_16x16 single MV (MvdSign)         | `svc_base_layer_md.cpp:1598–1599`                 |
| H2       | 7     | P_16x8 MVD (×2 partitions)          | `svc_base_layer_md.cpp` (partitioned MvdSign)     |
| H3       | 7     | P_8x16 MVD (×2 partitions)          | `svc_base_layer_md.cpp` (partitioned MvdSign)     |
| H4       | 7     | P_8x8 SUB_MB_TYPE_8x8 (×4)          | `svc_base_layer_md.cpp` (partitioned MvdSign)     |
| H5/H6/H7 | —     | P_8x8 SUB_8x4/4x8/4x4 (closed-by-design*) | `svc_mode_decision.cpp:628`                 |

(*H5/H6/H7 are **closed-by-design**: upstream OpenH264 itself wraps
the sub-8x8 partition search in `#if 0` at
`svc_mode_decision.cpp:628`, so those mb-types are never emitted by
the stock encoder. The phasm hook surface explicitly does not wire
them.)

### Visual-recon cascade-break (Phase C.8)

The hook surface above flips bits in the emitted bitstream. Without
further work the encoder's own internal reconstruction (used as the
reference for the *next* P-frame's motion compensation) would still
see the *cover* pixels, while the decoder reconstructs from the
*stego* pixels. The two diverge starting from the first inter-frame
prediction after a flipped MB, and the divergence cascades through
the GOP.

Phase C.8 closes that gap by running two reconstruction paths in
parallel inside the encoder:

- `pDecPic` — cover-side, used by the encoder's own ME / mode
  decision against pristine pixels. Unchanged from upstream.
- `pVisualRecPic` — stego-side mirror, updated by dual-pass hooks
  for every domain (I_16x16 luma DC/AC, I_4x4 luma cascade, chroma
  DC/AC, P-frame coefficients, MvdSign motion compensation, deblock
  filter). Promoted to the DPB alongside `pDecPic` at frame boundary.

Phase C.8 substages (all shipped 2026-05-13):

| Substage | Scope                                                              |
|----------|--------------------------------------------------------------------|
| C.8.0    | Source audit of OpenH264 reconstruction paths                      |
| C.8.1    | Buffer allocator for `pVisualRecPic`                               |
| C.8.2    | Dual-recon hook ABI extension                                      |
| C.8.3    | I_16x16 luma DC + AC dual-recon                                    |
| C.8.4    | I_4x4 luma intra-MB cascade dual-recon                             |
| C.8.5    | Chroma DC + AC dual-recon                                          |
| C.8.6    | P-frame coefficient dual-recon (luma + chroma inter)               |
| C.8.7    | MvdSign motion-compensation dual-pass (v1.0 single MV + v1.1 partitioned) |
| C.8.8    | Deblock filter dual-pass for `pVisualRecPic`                       |
| C.8.9    | Cascade-safety runtime assertions at DPB promotion                 |
| C.8.10   | `fsnr` redirected to `pVisualDecPic` for stego output paths        |
| C.8.11   | Multi-frame cascade verification: 3 IDRs × 24 frames, **0** cascade leaks across 128 730 blocks |

Each fire passes a 16-byte `PhasmStegoPos` descriptor identifying the
MB, partition, sub-block, and coefficient (or MV component). The
callback returns the new bit value; helper code in
`codec/encoder/core/src/wels_stego.cpp` enforces a non-zero-in /
non-zero-out contract, handles JVT-O079 zero-out floor protection,
performs inverse-zigzag dual-array writeback for inter coefficients,
and refuses MVD overrides that would collide with `PredSkipMv` (which
would silently demote the MB to Skip and drop the steganographic
bits).

Without registered callbacks the entire surface compiles to a single
predictable branch per hook site and has zero observable effect on
the bitstream.

## Branch + tag layout

- **`master`** — read-only mirror of upstream Cisco master.
- **`phasm-stego`** — production branch with the stego hooks applied
  plus the Phase C.8 dual-recon cascade-break. Pinned to upstream
  v2.6.0 baseline.
- **`phasm-stego-v0.1.0`** — first stable tag of the hook surface
  (commit `5d657c83`, 2026-05-11). ABI frozen at this revision; the
  later C.8 work is additive and does not change the public callback
  signature.

## Building

Identical to upstream OpenH264 for the codec proper. To build with
the stego hooks compiled in:

```sh
git clone --branch phasm-stego https://github.com/cgaffga/phasm-openh264.git
cd phasm-openh264
meson setup _build
ninja -C _build
```

Run the test suite:

```sh
meson test -C _build
```

You should see 5/5 OpenH264 lib suites green plus 30 phasm helper
gtests passing.

The `wels_stego.h` header lives at `codec/api/wels/wels_stego.h` and
gets exported alongside the standard OpenH264 public API (`codec_api.h`,
`codec_app_def.h`, etc.).

For instructions on building the upstream codec for Windows / macOS /
Linux / Android / iOS, NASM dependencies, and platform-specific
caveats, see the
[upstream OpenH264 README](https://github.com/cisco/openh264#building-the-library)
— our fork is binary-compatible at the build level.

## Continuous integration

`.github/workflows/phasm-stego-ci.yml` runs every push to the
`phasm-stego` branch on Ubuntu + macOS-latest. The workflow runs the
full meson test suite plus an inline C++ determinism gate over a
synthetic 320x240 fixture.

**No binary artifacts are produced or uploaded by CI.** Patent
licensing for H.264 encoders falls under the Via LA AVC pool — see
the "Patent licensing" section below.

## Patent licensing

H.264 / AVC is covered by the Via LA AVC patent pool. Cisco's
upstream OpenH264 is itself licensed under [Cisco's OpenH264
license](https://www.openh264.org/BINARY_LICENSE.txt) for Cisco-built
binaries that qualify for the Cisco-provided patent shield. **This
fork does not inherit the binary patent shield** because we
distribute source and the user builds locally — the shield only
applies to Cisco-distributed binaries downloaded over HTTPS.

Anyone shipping this fork as part of an end-user product should:
1. Self-evaluate AVC pool licensing obligations against their
   distribution model and unit volume.
2. Not redistribute pre-built binaries of this fork without
   independent legal review.
3. Note the free-tier coverage threshold (per Via LA's published
   policy as of 2026 — historically <100k units/year per licensee
   has been at zero cost).

This fork is consumed by [phasm.app](https://phasm.app) under that
self-evaluation. Phasm is open-source (the consumer crate is GPL-3.0)
and the user-facing CLI is built locally from source for users
wanting H.264 stego — there are no Cisco-style binary downloads of
phasm CLI containing the H.264 encoder.

## License

This fork inherits the upstream [BSD-2-Clause license](LICENSE) from
Cisco's OpenH264. The phasm-stego additions
(`codec/api/wels/wels_stego.h`,
`codec/encoder/core/src/wels_stego.cpp`,
`codec/encoder/core/inc/wels_stego_internal.h`, the 15 hook
insertions in the existing encoder TUs, and the Phase C.8 dual-recon
plumbing) are released under the same BSD-2-Clause license with
explicit SPDX headers.

The phasm consumer code that calls into this fork lives in a separate
repository ([github.com/cgaffga/phasmcore](https://github.com/cgaffga/phasmcore))
and is licensed GPL-3.0. Both licenses are compatible for distribution
under the GPL-3.0 source distribution.

## Cross-references

- Phasm consumer repo (Rust side that registers the callbacks):
  [cgaffga/phasmcore](https://github.com/cgaffga/phasmcore)
- Upstream Cisco OpenH264: [cisco/openh264](https://github.com/cisco/openh264)
- phasm.app project site: [phasm.app](https://phasm.app)
- Design documents (in the phasm monorepo):
    - `docs/design/video/h264/openh264-hook-sites.md` (umbrella + Phase A.5 ship status)
    - `docs/design/video/h264/openh264-hook-sites-intra.md`
    - `docs/design/video/h264/openh264-hook-sites-inter-coeff.md`
    - `docs/design/video/h264/openh264-hook-sites-mvd.md`
    - `docs/design/video/h264/openh264-adaptation.md` (engineering notebook)
    - Phase C.8 visual_recon dual-recon design + audit notes
      (`docs/design/video/h264/` Phase C.8.0–C.8.11)

## Upstream OpenH264 details

Reproduced from the original upstream README for convenience:

OpenH264 is a codec library which supports H.264 encoding and decoding.
It is suitable for use in real time applications such as WebRTC.
See <http://www.openh264.org/> for more details.

### Encoder Features

- Constrained Baseline Profile up to Level 5.2 (max frame size 36864 macroblocks)
- Arbitrary resolution, not constrained to multiples of 16x16
- Rate control with adaptive quantization, or constant quantization
- Slice options: 1 slice per frame, N slices per frame, N macroblocks per slice, or N bytes per slice
- Multiple threads automatically used for multiple slices
- Temporal scalability up to 4 layers in a dyadic hierarchy
- Simulcast AVC up to 4 resolutions from a single input
- Spatial simulcast up to 4 resolutions from a single input
- Long Term Reference (LTR) frames
- Memory Management Control Operation (MMCO)
- Reference picture list modification
- Single reference frame for inter prediction
- Multiple reference frames when using LTR and/or 3-4 temporal layers
- Periodic and on-demand Instantaneous Decoder Refresh (IDR) frame insertion
- Dynamic changes to bit rate, frame rate, and resolution
- Annex B byte stream output
- YUV 4:2:0 planar input

### Decoder Features

- Constrained Baseline Profile up to Level 5.2
- Arbitrary resolution
- Single thread for all slices
- Long Term Reference (LTR) frames + MMCO + reference picture list modification
- Multiple reference frames when specified in SPS
- Annex B byte stream input
- YUV 4:2:0 planar output

### Platform support

- Windows / macOS / Linux / Android / iOS (32-bit + 64-bit)
- macOS ARM64
- Verified on x86 (MMX/SSE), ARMv7 (NEON), AArch64 (NEON), and C/C++ fallback architectures
- Known build target: ppc64el

For platform-specific build commands (Android NDK, iOS xcodebuild,
Linux cross-compile, Windows AutoBuildForWindows.bat), follow the
upstream README at <https://github.com/cisco/openh264>.

### Known upstream issues

See the upstream issue tracker at
<https://github.com/cisco/openh264/issues>. Notably:

- Encoder errors when resolution exceeds 3840x2160
- Encoder errors when compressed frame size exceeds half uncompressed size
- Decoder errors when compressed frame size exceeds 1MB
- Encoder RC requires frame skipping to be enabled to hit the target bitrate

None of these are introduced by this fork; they apply equally to
upstream Cisco OpenH264.
