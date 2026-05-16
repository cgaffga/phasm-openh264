# phasm-openh264 — phasm-stego fork of Cisco OpenH264

This repository is a fork of [Cisco OpenH264](https://github.com/cisco/openh264)
with a small set of patches that expose hooks needed by
[phasm.app](https://phasm.app)'s video steganography pipeline.

## Branches

- **`master`** — verbatim mirror of `cisco/openh264:master`. We do NOT
  push changes here. We fetch upstream periodically when there are fixes
  worth pulling.
- **`phasm-stego`** — our working branch. Branched from a Cisco stable
  tag (currently `v2.6.0`). Carries the phasm-stego patches.

## Tag naming

`v<X.Y.Z>-phasm.<N>` — the Cisco upstream tag we branched from,
suffixed with a per-iteration counter. Example: `v2.6.0-phasm.1` is the
first publishable cut on top of Cisco `v2.6.0`.

## What's patched

See `docs/PHASM-PATCHES.md` for the patch index (added by the
phasm-stego branch). Patches touch only C++ source — never the ASM
kernels (DCT, MC, intra prediction, quantization, SAD/SATD). All speed
advantages of OpenH264's SIMD paths are preserved.

The phasm-stego patches add:
- A C ABI surface (`codec/api/wels/wels_stego.h`) for registering
  encode-side and decode-side callbacks.
- **Encoder-side override hooks at four bypass-coded domains**, implemented
  at two distinct points in the encoder pipeline:
  - **Coefficient sign + coefficient suffix LSB**: fired at CABAC
    bin pre-emit time during residual writes, via stage-specific
    HOOK-A..HOOK-G sites in `codec/encoder/core/src/svc_encode_mb.cpp`.
    The callback's return value overrides the bypass bit about to
    be emitted, with a dual-recon mirror keeping pDecPic clean.
  - **MVD sign + MVD suffix LSB**: fired at motion-decision time
    (after `MeRefineFracPixel` finalizes the qpel MV, before the
    MB commits its motion info) via HOOK-H1..H7 in
    `codec/encoder/core/src/svc_base_layer_md.cpp` + the
    `phasm_apply_mvd_hooks` helper in `codec/encoder/core/src/wels_stego.cpp`.
    The callback receives the would-be MVD sign / suffix-LSB; the
    helper mutates the qpel MV in place if the override differs, and
    the encoder re-runs MC at the modified MV. The CABAC bin emitted
    later in `WelsCabacMbMvdLx` reflects the modified MV by
    construction (sMvd is recomputed from the updated sMv − sMvp).
    The C.8.7 v1.1 cascade-break stashes the CLEAN-MV MC and lets
    `OutputPMb` shift pDecPic by `(CLEAN_MC − STEGO_MC)`, keeping
    the encoder reference clean for next-frame ME while
    `pVisualRecPic` captures the actual decoder-equivalent recon.
- Mode-decision cost-vector capture for stego rate-distortion planning.
- **Decoder-side bin-read post-hooks at four bypass-coded domains**
  (coefficient sign, coefficient suffix LSB, MVD sign, MVD suffix LSB)
  in `codec/decoder/core/src/parse_mb_syn_cabac.cpp` — extracted
  bits drive phasm's STC decode.
- Deterministic-build defaults (single-thread, scene-change detection
  off, etc.) for cross-platform reproducibility.

## License

Cisco's original OpenH264 code is under BSD 2-Clause; see `LICENSE`.

The phasm-stego additions (modifications to Cisco files + new files
authored for the phasm hooks) are also under BSD 2-Clause; see
`LICENSE-phasm-stego` for the addendum with Christoph Gaffga's
copyright and scope statement.

Both licenses are BSD-2-Clause and fully compatible. Redistributors of
source or binaries must preserve both copyright notices per BSD-2-Clause
attribution requirements.

H.264 / AVC patent obligations (Via LA AVC pool) are independent of
this software license and are not granted or waived by either BSD-2.
Downstream binary distributors assemble their own patent-compliance
posture. Cisco's signed openh264.org binary distribution program does
NOT cover derivative binaries built from this fork.

## Upstream sync

When we choose to pull upstream fixes:

```sh
git fetch cisco-upstream
# evaluate; if there's something we want:
git checkout phasm-stego
git rebase cisco-upstream/master   # or `git rebase <newer-cisco-tag>`
# resolve conflicts in our patch sites if Cisco touched them (rare)
git tag v<X.Y.Z>-phasm.<N+1>
git push --force-with-lease origin phasm-stego
git push origin v<X.Y.Z>-phasm.<N+1>
```

No formal relationship with Cisco. We never push to `cisco/openh264`.
The `cisco-upstream` remote is read-only.

## Consumer

This fork is consumed by [phasmcore](https://github.com/cgaffga/phasmcore)
(public CLI source distribution) and the private phasm monorepo via git
submodule. See `docs/design/video/h264/two-encoder-architecture.md` and
`docs/design/video/h264/openh264-adaptation.md` in the phasm repo for
the full design.
