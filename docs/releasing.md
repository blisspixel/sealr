# Release process

GitHub releases come only from the protected `main` commit selected by their immutable tag. The tag workflow stages an attested draft. It never publishes. A trusted local promotion script revalidates live repository controls and publishes only the exact verified draft through the operator's existing administrative GitHub session. A source-crate publication for that same release must be planned in the tagged documentation and reproduce the tagged source package through the separate procedure below; it does not publish the moving default branch.

Verification commands for the current published prerelease are maintained in [release-verification.md](release-verification.md). Each new immutable GitHub release body is taken exactly from its tagged release-note file.

The workflow and promotion script are intentionally pinned to one preview version at a time.

## Preconditions

Before creating a tag:

1. Update the workspace version, lockfile, changelog, release notes, workflow `RELEASE_VERSION`, and promotion-script constants together.
2. Confirm the local checkout, `origin/main`, and intended release commit are identical and clean.
3. Confirm every protected `main` check passed on that exact commit.
4. Dispatch the fuzz workflow for that exact commit and require all fourteen named bounded jobs in the release workflow to pass.
5. Confirm there are no open release-blocking pull requests or security advisories.
6. Confirm every action in the release workflow is pinned to a reviewed full commit hash.
7. Run the walkthrough, asset verification, ordinary CI gates, and actionlint from a clean checkout.
8. Confirm the operator's `gh` session has repository administration access and no reusable administrative credential is stored in the repository.
9. Enable repository release immutability and read it back:

```powershell
gh api --method PUT -H 'X-GitHub-Api-Version: 2026-03-10' `
  repos/blisspixel/sealr/immutable-releases
gh api -H 'X-GitHub-Api-Version: 2026-03-10' `
  repos/blisspixel/sealr/immutable-releases
```

The readback must report `enabled: true`. Do not create the release tag before this control is active.

## Walkthrough gate

Run:

```powershell
pwsh -NoLogo -NoProfile -File scripts/walkthrough.ps1
pwsh -NoLogo -NoProfile -File scripts/render_walkthrough.ps1
pwsh -NoLogo -NoProfile -File scripts/verify_walkthrough_assets.ps1
```

The six committed PNGs must match the verified transcripts in both themes. Each image is 1000 by 560 pixels at 144 DPI, no larger than 250 KB, and contains no local identity, absolute path, date, cursor, credit, or text metadata.

## Third-party license gate

The three committed third-party license bundles cover the exact locked normal and build dependency closure for the supported Linux, macOS, and Windows release targets. Development dependencies are excluded. Each bundle includes the selected license texts plus every root `NOTICE*` and `COPYRIGHT*` file from its target graph. Generation is offline and locked, output uses deterministic ordering and LF line endings, and unresolved licenses or non-crates.io packages stop the process.

Install the pinned build tool, regenerate after dependency changes, then verify that regeneration is byte-identical:

```powershell
cargo install cargo-about --version 0.9.1 --locked --features cli
pwsh -NoLogo -NoProfile -File scripts/generate_third_party_licenses.ps1
pwsh -NoLogo -NoProfile -File scripts/verify_third_party_licenses.ps1
```

This tool is used only to build release notices. It is not a sealr runtime dependency.

## Stage the draft

Create an annotated tag at the verified commit and push only that tag. For `0.1.0-alpha.13`, the tag is `v0.1.0-alpha.13`.

The tag workflow:

1. verifies the annotated tag, workspace version, clean checkout, and identity with current `main`;
2. waits for the exact `main` CI run at that commit and requires all six promotion jobs to succeed; the later promotion script separately verifies the stable `Required CI` branch-protection check and live protection rules;
3. requires all fourteen successful bounded fuzz campaigns on that exact commit;
4. tests optimized workspace builds on standard Ubuntu, Windows, and macOS runners;
5. builds and packages the native CLI and independent evidence verifier with README, changelog, the Apache-2.0 project license, and the verified target-specific third-party license bundle, including upstream root notice and copyright files;
6. extracts every package, checks both executables' version and help output, and proves canonical producer-verifier success plus tamper refusal;
7. creates and verifies `SHA256SUMS` for exactly three native archives;
8. records build provenance for those archives;
9. creates or safely resumes the exact expected prerelease draft by numeric release ID;
10. reads back its body, state, four-asset set, sizes, and API digests;
11. stops without publishing.

An existing published release, mismatched draft, unexpected asset, tag drift, or exact-CI failure stops the workflow.

If an annotated tag must be moved while its draft is still private, GitHub can rename the draft to an `untagged-*` placeholder. The workflow recovers only one bot-owned orphan that matches the exact title, notes, state, and safe expected asset subset. It pins that numeric release ID, verifies the live annotated tag and protected `main`, then rebinds the draft to the expected tag. Any near-match, duplicate, unexpected asset, or identity change stops before asset mutation. The promotion script never performs orphan recovery.

## Promote the verified draft

After the Release workflow succeeds, use the trusted script from a clean checkout of the same `main` commit:

```powershell
pwsh -NoLogo -NoProfile -File scripts/publish_release.ps1
pwsh -NoLogo -NoProfile -File scripts/publish_release.ps1 -Publish -Confirm:$false
```

The first invocation performs the complete read-only verification. The second repeats every check and explicitly authorizes publication.

The script accepts no repository, tag, or release parameters. Before changing the draft, it requires:

- a clean, unmodified checkout whose `HEAD` equals remote `main` and the annotated release tag;
- exact workspace version and tagged release notes;
- unchanged strict branch protection, enforced administrators, pull requests, linear history, resolved conversations, and the exact GitHub Actions `Required CI` check that aggregates all six promotion jobs;
- successful exact-commit `main` CI, exact-commit on-demand fuzz, and exact-tag Release workflow runs;
- repository release immutability enabled;
- the exact draft ID, title, notes, prerelease state, and four expected assets;
- strict checksum agreement among downloaded bytes, `SHA256SUMS`, and API digests;
- valid build provenance for every native archive.

It repeats mutable repository, CI, tag, draft, and asset checks immediately before publication. It then changes only `draft` and `prerelease` on the recorded release ID.

## Post-publication verification

The promotion script polls the published release and requires:

- the same release and asset IDs;
- `draft: false`, `prerelease: true`, and `immutable: true`;
- unchanged title, tag, body, sizes, and digests;
- a non-null publication time;
- successful `gh release verify` for GitHub's immutable-release attestation;
- successful build-provenance verification for all three downloaded archives;
- the release tag still resolving to the captured protected `main` commit.

The final operator record includes the release URL and ID, tag commit, CI run ID, Release workflow run ID, and asset digests.

## Publish the source crate for the pilot

> Status as of 2026-09-01: no pilot release is assigned or published. Alpha.13 is a verified technical baseline, not the upload candidate. Its immutable packaged README says it is GitHub-only, so it must not be retroactively published to crates.io. The GitHub release workflow and `publish_release.ps1` do not publish source crates.

Select the adopter and exact pilot scope before assigning a new prerelease. The candidate must update its workspace version, lockfile, copied handoff pin, changelog, release notes, release workflow constants, and [adopter contract](adopter-pilot.md) together. Its tagged README must accurately describe both the crates.io source distribution and the matching authenticated native release. Required CI and the ordinary GitHub release process must pass before source upload.

crates.io versions cannot be overwritten. Publish only from a clean detached checkout of the new immutable release tag, using the package toolchain pinned by that release. Never upload from the moving default branch, a dirty checkout, an older tag whose documentation denies publication, or a repackaged source tree.

Before upload, require all of the following:

1. The registry name and exact candidate version have the expected state. If the name has become occupied by an unintended owner, stop and revise the distribution plan rather than publishing under an inferred alternative.
2. `HEAD`, the dereferenced candidate tag, the GitHub release tag, and the contract commit are identical, and `git status --short` is empty.
3. The tagged README and release notes describe crates.io publication accurately and contain no obsolete GitHub-only claim for the candidate.
4. `cargo --version` reports the release's pinned Cargo version.
5. `scripts/verify_crate_package.ps1` passes from that checkout.
6. `cargo publish --locked -p sealr --dry-run` passes.
7. The resulting `.crate` size and SHA-256 are recorded before upload, and a second clean package run reproduces both exactly.
8. The authenticated crates.io session belongs to the intended publisher. Do not supply a token on the command line, print it, or store it in this repository.

The final mutation is deliberately one command with no version override:

```powershell
cargo publish --locked -p sealr
```

Immediately afterward, query crates.io from outside the Sealr workspace so Cargo cannot satisfy the request from the local package. Require all of the following before declaring the source half available:

- `cargo info --registry crates-io sealr@<VERSION>` resolves the exact candidate version;
- the crates.io index entry names that version and its checksum equals the pre-upload package digest;
- the downloaded registry `.crate` has the recorded size and digest;
- `cargo owner --list sealr` contains exactly the intended owner set;
- a fresh copy of the candidate's PyPA handoff generates its lockfile without `patch.crates-io`, builds with `--locked`, resolves the registry checksum, and activates no internal Sealr feature;
- the authenticated native archive reports the same release version and still passes its checksum and provenance verification.

If upload state is ambiguous, do not retry blindly. Read the registry and index first. After successful readback, update the machine contract's delivery and top-level status, update the adopter documentation, and preserve the registry checksum, package digest, owner list, and clean-consumer result. Those documentation changes report the completed mutation; they do not authorize it.

The public repository uses only standard GitHub-hosted runners. Do not select larger runners or paid external release services without a separate cost review.
