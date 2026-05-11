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
- CABAC bin pre-emit hooks at four bypass-coded domains: coefficient
  sign, coefficient suffix LSB, MVD sign, MVD suffix LSB.
- Mode-decision cost-vector capture for stego rate-distortion planning.
- Decoder-side bin-read post-hooks for stego extraction.
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
