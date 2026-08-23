# Release process

Releases come only from the current protected `main` commit. The tag workflow stages an attested draft. It never publishes. A trusted local promotion script revalidates live repository controls and publishes only the exact verified draft through the operator's existing administrative GitHub session.

Verification commands for the current published prerelease are maintained in [release-verification.md](release-verification.md). Historical release notes remain identical to their immutable GitHub release bodies.

The workflow and promotion script are intentionally pinned to one preview version at a time.

## Preconditions

Before creating a tag:

1. Update the workspace version, lockfile, changelog, release notes, workflow `RELEASE_VERSION`, and promotion-script constants together.
2. Confirm the local checkout, `origin/main`, and intended release commit are identical and clean.
3. Confirm every protected `main` check passed on that exact commit.
4. Confirm there are no open release-blocking pull requests or security advisories.
5. Confirm every action in the release workflow is pinned to a reviewed full commit hash.
6. Run the walkthrough, asset verification, ordinary CI gates, and actionlint from a clean checkout.
7. Confirm the operator's `gh` session has repository administration access and no reusable administrative credential is stored in the repository.
8. Enable repository release immutability and read it back:

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

Create an annotated tag at the verified commit and push only that tag. For `0.1.0-alpha.4`, the tag is `v0.1.0-alpha.4`.

The tag workflow:

1. verifies the annotated tag, workspace version, clean checkout, and identity with current `main`;
2. waits for the exact protected `main` CI run at that commit and requires all five protected jobs to succeed;
3. tests optimized workspace builds on standard Ubuntu, Windows, and macOS runners;
4. builds and packages each native executable with README, changelog, the Apache-2.0 project license, and the verified target-specific third-party license bundle, including upstream root notice and copyright files;
5. extracts every package and smoke-tests its version and help output;
6. creates and verifies `SHA256SUMS` for exactly three native archives;
7. records build provenance for those archives;
8. creates or safely resumes the exact expected prerelease draft by numeric release ID;
9. reads back its body, state, four-asset set, sizes, and API digests;
10. stops without publishing.

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
- unchanged strict branch protection, enforced administrators, pull requests, linear history, resolved conversations, and the exact five GitHub Actions checks;
- successful exact-commit `main` CI and successful exact-tag Release workflow runs;
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

The public repository uses only standard GitHub-hosted runners. Do not select larger runners or paid external release services without a separate cost review.
