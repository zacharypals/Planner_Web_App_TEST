# LP Planner — Task Color Palette Options (Nov 2026)

Reference for task/event background palettes explored on 2026-11-01. Colors were built in OKLCH (perceptual lightness/chroma/hue) against the "Dusk Violet" theme (hue ~295). Every option keeps dark text (#2a2538) at ≥8.5:1 contrast. Slots are listed in auto-color order (slot 0 is the first color a new task gets on a day).

Mockup images from the session: `task-colors-mock.png`, `light-task-color-options.png`, `light-color-schemes.png`, `calm-tonal-variations.png`. A browsable copy of all of these lives in the test repo at `design/palette-options.html`.

## In use
- **Light — "Calm tonal, defined" (chosen, app v4.5.1).** Soft violets/blues from the theme with a few warm accents, one step deeper than "Calm tonal" so neighbouring tasks separate clearly.
  - Tasks (18): `#dad6fa` `#b5d4fc` `#f8d4a4` `#d3c1eb` `#bde1f3` `#f9c1bf` `#bcc5ec` `#e7cdec` `#a6ded2` `#bccef3` `#dfd5f5` `#b1d6f6` `#aedfe1` `#efc2da` `#fdccac` `#cacaee` `#bcdfc2` `#b2d7ee`
  - Events (16, lighter): `#f5dcf2` `#cbe4ff` `#f7e6c3` `#dfd9f6` `#c7eeea` `#ffdad3` `#d3ddf9` `#daefd6` `#c5e8f4` `#fed9e6` `#d9dcf6` `#ffe2c6` `#cae6fa` `#ecdff7` `#c8eadd` `#cfdff9`
- **Dark — "Dark proposed" (chosen, v4.5.0).** Deep, saturated versions of the original pastel families (L≈0.40, C≈0.085 OKLCH; yellows L 0.43), ~7:1 with #e8e6ef text. CSS vars `--tc-0…17` / `--ec-0…15` under `[data-theme="dark"]`. Slot families follow the ORIGINAL light palette (sage, blush, yellow, sky…), not Calm tonal.
  - Tasks: `#1f542e` `#6d323f` `#5e4f07` `#1f4a73` `#4e3c6f` `#683c0b` `#005648` `#5e3661` `#3a5018` `#6e3429` `#005168` `#515413` `#673352` `#684a09` `#00555a` `#6c371d` `#384475` `#6e3236`
  - Events: `#582d42` `#43345c` `#223e61` `#0b4834` `#544310` `#593215` `#00474e` `#4f2f51` `#31441a` `#5c2c31` `#333962` `#4e4612` `#5b301c` `#004845` `#5a2c3c` `#234725`

## Previous light palette (v3.x – v4.5.0)
Original pastels (sage green, blush pink, warm yellow, sky blue, soft lavender, apricot, seafoam, orchid, leaf green, coral, cyan, pastel olive, soft plum, marigold, teal mist, warm taupe, periwinkle, watermelon):
`#d4edda` `#f8d7da` `#fff3cd` `#cce5ff` `#e2d9f3` `#ffdab3` `#b2f2e5` `#f3d9fa` `#c8e6c9` `#ffccbc` `#b3e5fc` `#f0e68c` `#e1bee7` `#ffe0b2` `#b2dfdb` `#d7ccc8` `#c5cae9` `#ffcdd2`

## Round 1 — saturation levels of the original families (12 slots shown)
- A touch more saturated (L≈0.905, C 0.075): `#bdeec6` `#ffccd6` `#f4e5ac` `#bae4ff` `#e5d6ff` `#ffd5ad` `#a9f1e0` `#facffc` `#d1eab5` `#ffcec1` `#a8ecff` `#e5eab1`
- Dusk mist (L 0.935, C 0.042, hues nudged 12° toward violet): `#d2f3e1` `#ffdfea` `#f7e8ca` `#daeaff` `#ebe5ff` `#ffe2d1` `#cbf3f0` `#f4e2fe` `#dbf1d6` `#ffdfde` `#cfefff` `#f0ebcb`
- Jewel (L≈0.86, C 0.09, violet-friendly hues): `#8fe5ce` `#ffb9be` `#f5d594` `#a9d4ff` `#dac4ff` `#ffc298` `#85e4e3` `#f3bced` `#b2e0a8` `#ffbca9` `#91ddff` `#e1dd97`

## Round 2 — color-theory schemes with purple (12 slots)
- Twilight — analogous (blues → violets → magentas → pinks): `#c1e2ff` `#f6d0f1` `#cbcbfe` `#c0eefa` `#fcc5de` `#e7d5ff` `#abd8f3` `#f4dafa` `#c6d7ff` `#ffd1dc` `#d6cdf8` `#c7edef`
- Golden hour — split-complementary (amber/gold + teal/sage around violet): `#fedca5` `#aee8e0` `#ddd4ff` `#ffd2a9` `#bcebd1` `#f3e5b0` `#a9e4e7` `#edd4f3` `#ffcbaf` `#d0eacb` `#cbdaff` `#e6e9bb`
- Botanical — triadic (violet, terracotta, sage): `#c4e5ca` `#fbcbba` `#dcd5f9` `#d9e8c4` `#fdd5b7` `#e7cdec` `#b5dfcf` `#ffd5d1` `#d3ddf9` `#dfddb7` `#f6d9b2` `#f1cbdf`
- Calm tonal — Material-style tonal (theme violets/blue-greys + few warm accents): `#e7e4fe` `#c8e0ff` `#fde0b9` `#ded1f0` `#d5ecf8` `#fed2d0` `#ccd3ef` `#efdef3` `#bbe9df` `#cedbf6` `#ebe4fa` `#c3e2fe`

## Round 3 — Calm tonal variations (12 slots)
- Calm tonal (reference): `#e7e4fe` `#c8e0ff` `#fde0b9` `#ded1f0` `#d5ecf8` `#fed2d0` `#ccd3ef` `#efdef3` `#bbe9df` `#cedbf6` `#ebe4fa` `#c3e2fe`
- Cool tonal (no warm accents; violets, periwinkle, blue-grey, teal): `#e7e4fe` `#c6e1ff` `#b9e4e6` `#dfd0f3` `#d5ecf8` `#c0e8dc` `#cad3f3` `#f1ddf2` `#c8e8f0` `#ccdcf6` `#ebe4fa` `#bde8e4`
- Lavender & sage (violet base + sage/mint): `#e9e4fe` `#cdead2` `#ced6f6` `#deeacd` `#ead6f3` `#c5e7da` `#d3d0ed` `#dceed8` `#d0e3fc` `#c5e3d2` `#ece3f8` `#e6e8c6`
- Rose & sand (violet base + dusty rose, blush, sand): `#e9e4fe` `#fed6d8` `#f9e1c0` `#d1d5f5` `#f7d7e5` `#fbd5c1` `#daceea` `#f2e7ca` `#d2e2fd` `#fbd4cd` `#f1e2f5` `#fcdec7`
- Calm tonal, defined (chosen; first 12 of the 18 above): `#dad6fa` `#b5d4fc` `#f8d4a4` `#d3c1eb` `#bde1f3` `#f9c1bf` `#bcc5ec` `#e7cdec` `#a6ded2` `#bccef3` `#dfd5f5` `#b1d6f6`

## Notes for future changes
- Palettes live in `TASK_COLORS` / `EVENT_COLORS` (light) and `--tc-N` / `--ec-N` (dark). Tasks store only `colorIndex`, so swapping a palette recolors existing tasks without touching data.
- If light and dark should share color families per slot, regenerate the dark vars from the light hues (same hue, L≈0.40, C≈0.085).
- Auto-color picks the first unused slot each day (`pickTaskColorIndex`), so slots 0–5 are the ones seen most.
