# Visual identity

Sealr's mark is a continuous lowercase `s` inside one closed, rounded boundary.
The wordmark uses quiet lowercase lettering. The same shapes work in small
documentation headers, terminal examples, and release artwork.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/sealr-wordmark-dark.svg">
  <img alt="Sealr wordmark: a rounded enclosure containing a continuous s, followed by lowercase lettering." src="assets/brand/sealr-wordmark-light.svg" width="256">
</picture>

## Assets

| Use | Light background | Dark background | One color |
|---|---|---|---|
| Full wordmark | [SVG](assets/brand/sealr-wordmark-light.svg) | [SVG](assets/brand/sealr-wordmark-dark.svg) | [SVG](assets/brand/sealr-wordmark-mono.svg) |
| Standalone mark | [SVG](assets/brand/sealr-mark-light.svg) | [SVG](assets/brand/sealr-mark-dark.svg) | [SVG](assets/brand/sealr-mark-mono.svg) |

The SVG files contain only geometry and outlined lettering. They require no
font download, script, external reference, or network connection. View the
[identity specimen](brand/index.html) for both themes and small-size examples.

## Use consistently

- Keep the proportions and orientation. Leave at least a quarter of the mark's
  width clear on every side.
- Use the standalone mark at 24 CSS pixels or larger. At 16 pixels, use it only
  where a compact icon is necessary. Use the full wordmark at 128 pixels or larger.
- Use the supplied dark variant on dark backgrounds. Use the one-color variant
  where color is unavailable. Avoid shadows, gradients, rotations, and added borders.
- Write `Sealr` in prose and `sealr` in commands, crate names, and the wordmark.
- Give standalone images the alt text `Sealr`. When nearby text already names
  the project, decorative duplicate images use empty alt text.

## Palette and typography

| Role | Light | Dark |
|---|---|---|
| Canvas | `#f6f8f7` | `#101917` |
| Surface | `#ffffff` | `#17231f` |
| Text | `#162724` | `#eef6f3` |
| Secondary text | `#53675f` | `#a6bbb1` |
| Border | `#d9e3dd` | `#34483e` |
| Brand accent | `#0f766e` | `#5eead4` |

Use a system sans serif for explanations and a system monospace for commands,
paths, identities, and measured values. Keep headings short, body text readable,
and spacing on a four-pixel grid. Terminal examples use restrained surfaces,
clear prompts, and a visible distinction between command, result, and evidence.

The accent identifies the project and commands. It does not mean an archive
passed verification. Show outcomes in text (`allowed`, `rejected`, `wrote`) and
use separate success and refusal colors. Never make color the only indication.

## Screenshots and release artwork

Use Linux shell prompts in documentation captures. Derive every displayed
result from the executable walkthrough and keep the measured version visible.
The [walkthrough](walkthrough.md) explains how transcripts and screenshots are
produced and verified. Put detailed explanations under `docs/` and keep the
README focused on the project, one example, and the next useful action.

Branding is presentation. The mark does not certify an artifact, authenticate
a receipt, or imply that an admitted program is safe to execute.
