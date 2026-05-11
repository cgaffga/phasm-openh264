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

## What this fork adds

A public C ABI at [`codec/api/wels/wels_stego.h`](codec/api/wels/wels_stego.h)
with two entry points:

```c
void WelsRegisterPhasmStegoCallbacks(
    const PhasmStegoCallbacks* cbs,
    void* user_data);

void WelsStegoSetFrameNum(uint32_t frame_num);
```

The callbacks fire from 13 instrumented sites across the encoder
(`codec/encoder/core/src/svc_encode_mb.cpp` for intra + inter
coefficients, `codec/encoder/core/src/svc_base_layer_md.cpp` for
motion-vector differences) and one site in the decoder (post-read on
the bypass-bin fast path).

Hook complement:

| Hook ID  | Mode                          | File                       |
|----------|-------------------------------|-----------------------------|
| A        | I_16x16 luma DC               | `svc_encode_mb.cpp`         |
| B        | I_16x16 luma AC               | `svc_encode_mb.cpp`         |
| C        | Chroma DC (2x2 Hadamard, ST64)| `svc_encode_mb.cpp`         |
| E        | I_4x4 luma intra-MB cascade   | `svc_encode_mb.cpp`         |
| F        | P luma inter (dual-array)     | `svc_encode_mb.cpp`         |
| G        | P chroma inter (dual-array)   | `svc_encode_mb.cpp`         |
| H1       | P_16x16 MVD                   | `svc_base_layer_md.cpp`     |
| H2       | P_16x8 MVD (×2 partitions)    | `svc_base_layer_md.cpp`     |
| H3       | P_8x16 MVD (×2 partitions)    | `svc_base_layer_md.cpp`     |
| H4       | P_8x8 SUB_MB_TYPE_8x8 (×4)    | `svc_base_layer_md.cpp`     |
| H5/H6/H7 | P_8x8 SUB_4x4/8x4/4x8 (dead*) | `svc_base_layer_md.cpp`     |

(*H5/H6/H7 are wired but unreachable in stock v2.6.0:
`WelsMdInterFinePartitionVaa` pins to `SUB_MB_TYPE_8x8`.)

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
- **`phasm-stego`** — production branch with the stego hooks applied.
  Pinned to upstream v2.6.0 baseline.
- **`phasm-stego-v0.1.0`** — first stable tag of the hook surface
  (commit `5d657c83`, 2026-05-11). API frozen at this revision.

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
`codec/encoder/core/inc/wels_stego_internal.h`, and the 13 hook
insertions in the existing encoder TUs) are released under the same
BSD-2-Clause license with explicit SPDX headers.

The phasm consumer code that calls into this fork lives in a separate
repository ([github.com/cgaffga/phasm](https://github.com/cgaffga/phasm))
and is licensed GPL-3.0. Both licenses are compatible for distribution
under the GPL-3.0 source distribution.

## Cross-references

- Phasm consumer repo: [cgaffga/phasm](https://github.com/cgaffga/phasm)
- Upstream Cisco OpenH264: [cisco/openh264](https://github.com/cisco/openh264)
- phasm.app project site: [phasm.app](https://phasm.app)
- Design documents (in consumer repo):
    - `docs/design/video/h264/openh264-hook-sites.md` (umbrella + Phase A.5 ship status)
    - `docs/design/video/h264/openh264-hook-sites-intra.md`
    - `docs/design/video/h264/openh264-hook-sites-inter-coeff.md`
    - `docs/design/video/h264/openh264-hook-sites-mvd.md`
    - `docs/design/video/h264/openh264-adaptation.md` (engineering notebook)

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
