# CLI walkthrough

Inspect an archive, reject a parent path, and publish the verified tree. These
examples use Linux terminal notation and the current Alpha.15 CLI.

The images are rendered summaries of measured JSON view and receipt streams.
They are paired with copyable commands and expected outcomes. They do not show
raw terminal output or a future human interface.

## 1. Inspect without writing

```sh
target/release/sealr target/readme-walkthrough/fixtures/allowed.zip
```

Expected result: exit `0`, verdict `allowed`, `wrote: false`, and two sorted members with their measured sizes and SHA-256 digests.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme-walkthrough/sealr-inspect-allowed-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png">
  <img alt="Screenshot of sealr allowing a two-member ZIP inspection while reporting that no files were written." src="assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png" width="1000">
</picture>

## 2. Reject a parent path

```sh
target/release/sealr target/readme-walkthrough/fixtures/rejected-parent-path.zip \
  --dest target/readme-walkthrough/blocked
```

Expected result: exit `2`, verdict `rejected`, finding `path.dotdot` for `../outside.txt`, and neither the destination nor the outside file exists.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme-walkthrough/sealr-reject-parent-path-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/readme-walkthrough/sealr-reject-parent-path-terminal-light.png">
  <img alt="Screenshot of sealr rejecting a parent-path member and confirming that no destination was created." src="assets/readme-walkthrough/sealr-reject-parent-path-terminal-light.png" width="1000">
</picture>

## 3. Materialize the approved tree

```sh
target/release/sealr target/readme-walkthrough/fixtures/allowed.zip \
  --dest target/readme-walkthrough/materialized
```

Expected result: exit `0`, verdict `allowed`, `wrote: true`, and exactly the two inspected members exist in the new destination.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme-walkthrough/sealr-materialize-allowed-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/readme-walkthrough/sealr-materialize-allowed-terminal-light.png">
  <img alt="Screenshot of sealr materializing two approved members into a new destination after inspection." src="assets/readme-walkthrough/sealr-materialize-allowed-terminal-light.png" width="1000">
</picture>

## Reproduce and refresh

From the repository root, run the native release build and semantic assertions:

```sh
pwsh -NoLogo -NoProfile -File scripts/walkthrough.ps1
pwsh -NoLogo -NoProfile -File scripts/render_walkthrough.ps1
pwsh -NoLogo -NoProfile -File scripts/verify_walkthrough_assets.ps1
```

PowerShell 7 is used only to orchestrate these repository checks. The screenshots
are captured from a Linux run with `$` prompts and shell line continuations.
Sealr itself has no PowerShell runtime dependency.

The walkthrough checks the two fixture digests, separates stdout view JSON from
stderr receipt JSON, asserts exit codes and filesystem effects, and saves the
raw evidence and transcripts in `target/readme-walkthrough/`. The HTML renderer
checks the measured tool version and produces both light and dark themes.

CI checks fixture and native transcript hashes against the committed asset
manifest, then verifies all six PNG hashes, dimensions, density, size, and
metadata policy. Review the saved PNGs themselves after capture, including the
panel's full size and readable text in both themes. File dimensions alone do
not detect content captured at the wrong browser scale. CI does not
claim a pixel comparison. See the [capture policy](usage.md#documentation-capture-policy).
