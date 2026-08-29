# Python wheel consumer profile v1

> Status: supported Alpha.8 preview through `sealr::wheel`. The API evaluates an already verified archive and produces a bounded artifact and scheme-relative plan without installing, resolving, executing, or reopening the wheel. The Alpha.7 repository laboratory remains immutable historical evidence and the CLI does not expose wheel installation.

The first consumer should force Sealr to prove its category: another tool receives one admitted representation and does not open the ZIP again. Python wheels are a strong target because wheel installation has archive semantics, package metadata, an internal content manifest, relocations, and target-dependent transformations.

## Implemented boundary

```text
exact artifact filename + SourceSnapshot
    -> ZIP interpretation under sealr.profile.zip.portable-utf8.v1
    -> fully verified ArchiveIR
    -> bounded wheel metadata evaluation
    -> WheelArtifactIR
    -> scheme-relative WheelInstallPlan
```

The evaluator is pure. It does not select an environment, install a package, resolve dependencies, execute metadata, or write a destination.

## Semantic inputs

The consumer request must bind:

- the exact outer artifact filename, because distribution, version, build, Python, ABI, and platform tags are not inside the ZIP container identity;
- the source, interpretation profile, resource budget, and `python-wheel.v1` consumer profile;
- the supported wheel and core-metadata specification snapshots;
- no implicit host target. A target model is supplied separately only when a caller binds later realization evidence.

Renaming identical ZIP bytes can therefore change consumer identity or make wheel admission fail. Source identity and archive-tree identity remain unchanged.

## Required capability

The wheel evaluator consumes an opaque verified archive capability. It reads bounded verified members from the existing interpretation and never:

- reopens the original artifact path;
- invokes Python `zipfile`, another Rust ZIP parser, or an external extractor;
- inflates one member again through a second interpretation;
- treats a caller-constructed serializable IR as proof of admission.

The verification pass can retain bounded semantic members such as `WHEEL`, `METADATA`, `RECORD`, and `entry_points.txt`, or provide verified reads from the immutable snapshot. The chosen mechanism must preserve one parse and one measured content result.

Current main supplies the generic mechanism for both halves of this boundary. `VerifiedArchive` retains the snapshot and IR, prevents caller construction, and supports caller-bounded revalidated reads. `RetentionPlan` selects an exact canonical path set under independent per-member and aggregate content limits; `apply_with_options` captures successful selections during the original checked stream. Central creator-system and external-attribute words remain outside `sealrTreeV1` but are available as immutable container facts so the laboratory can reproduce PyPA installer 0.7.0 executable detection exactly.

The supported evaluator uses independent byte caps for the outer filename, every semantic member class, parsed header and CSV structure, tag expansion, script inspection, and aggregate semantic or plan-inspection bytes. Cap failures become typed consumer findings. Failures of the verified read authority remain infrastructure failures and cannot become artifact denial evidence.

## Container profile

The supported evaluator requires [`sealr.profile.zip.portable-utf8.v1`](zip-portable-utf8-v1.md):

- ZIP32 with Store and Deflate;
- exact covering and exact Deflate input consumption;
- member names encoded as strict UTF-8, with bit 11 required for non-ASCII names;
- no legacy CP437 fallback inside this profile;
- no Unicode Path extra-field override;
- an exhaustive 65,536-value flag language in which only data-descriptor bit 3 and UTF-8 bit 11 are admitted;
- an exhaustive 65,536-ID extra-field language in which every extra field is denied;
- NFC paths with no dot component, non-ASCII control, non-ASCII whitespace, or bidi control;
- Unicode 16.0 full default case-fold followed by NFC, with exact repertoire, case-fold, and normalization dependencies bound by the portable profile;
- a dual component ceiling of 255 UTF-8 bytes and 255 UTF-16 code units;
- no encryption, ZIP64, spanned records, links, devices, recovery parsing, or archive mode restoration.

The profile's canonical JSON and SHA-256 `acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e` are committed with the independent identity conformance vectors. Legacy CP437 remains a separate future profile decision and cannot be selected implicitly by the wheel evaluator.

## `WheelArtifactIR`

The public, non-exhaustive artifact object records:

- parsed outer filename and expanded compatibility tags;
- normalized distribution and version;
- exactly one matching `.dist-info` directory;
- at most one matching `.data` directory;
- parsed `WHEEL` and `METADATA` fields under pinned specification snapshots;
- strict `RECORD` rows and their binding to verified archive members;
- executable intent needed for later script handling;
- bounded entry-point metadata when the selected consumer scope includes it;
- exact consumer, specification-snapshot, container-profile, and member-fact bindings.

This object describes the distribution artifact. It is not an installed environment and does not claim target compatibility merely because the artifact is structurally valid.

## Supported admission rules

The v1 consumer implements these rules:

1. The outer filename parses and agrees with normalized distribution, version, build, and expanded `WHEEL` tags. The admitted PEP 440 syntax is the case-insensitive canonical subset `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+L(.L)*]`, where numeric fields are required and local segments are nonempty ASCII alphanumerics separated by dots. The exact `pep440_rs` 0.7.3 parser distinguishes other valid PEP 440 forms as unsupported from malformed versions as denied.
2. Exactly one matching `.dist-info` directory contains regular-file `METADATA`, `WHEEL`, and `RECORD` members.
3. `Wheel-Version` support is explicit. A greater unsupported major version is unsupported, not a policy denial.
4. `Metadata-Version` support is an explicit pinned list. The `pypa-wheel-core-metadata-2026-08-28` snapshot admits Core Metadata 2.1 through 2.6; any other declared version — earlier, later, or malformed-but-parseable — is unsupported, not denied. Widening this list changes the specification snapshot identifier and therefore the consumer profile digest and downstream artifact identities.
5. `Root-Is-Purelib` is present and exact.
6. Metadata header names are ASCII case-insensitive, duplicate detection occurs after name folding, and header count and line limits are enforced while streaming before fields are retained. `RECORD` uses a strict bounded CSV grammar and has one row per archive file, with only specification-defined exemptions.
7. Every non-exempt row has an approved secure hash and exact size matching the already verified member. The `RECORD` row itself has empty hash and size fields. Only exact `RECORD.jws` and `RECORD.p7s` siblings under the selected `.dist-info` root may remain outside `RECORD`; a row that lists either file is denied.
8. `RECORD` paths are canonical archive-relative forward-slash paths. The broader installed-project grammar is not reused as authority for archive lookup or deletion.
9. Phantom, absolute, parent-relative, duplicate, and normalized-collision rows reject.
10. `.data` contains only supported scheme keys, and relocation is collision-free after mapping, including exact and portable-folded file-ancestor topology within each target scheme.
11. Entry-point objects use dotted ASCII Python `module:attribute` references with explicitly parsed legacy extras. Command names and generated target names pass a separate target-path policy. Archive path admission alone does not sanitize generated names.
12. Script-scheme members are classified by the `script-prefix-classification.v1` rule: a verified bounded 1,024-byte prefix — streamed through complete size, CRC32, and SHA-256 re-verification of the whole member before any byte is released — decides between the exact `#!python`/`#!pythonw` first-line launcher rewrite and a verbatim copy. Launcher rewriting is a first-line property of the specification, so a native executable of any size is planned as a verbatim copy whose hash and size come from admission evidence, while each script charges only its retained prefix against the plan-inspection aggregate. The supervised Linux backend does not yet represent prefix reads and fails typed rather than diverging.
13. Deprecated `RECORD` signature files, if admitted at all, are explicit legacy objects and are never treated as verified signatures.
14. Metadata, row count, line length, field count, tag expansion, and retained semantic bytes have independent checked caps.

These rules are a supported prerelease contract. Additive output fields may be introduced through non-exhaustive types, while changes to interpreted meaning, identity encodings, or denial classification require a new versioned profile or encoding.

## Identities

Four identities must not be collapsed:

| Identity | Meaning |
|---|---|
| Source | Exact wheel archive bytes |
| Archive tree | Canonical verified ZIP member paths and bytes |
| Wheel artifact | Archive tree plus exact artifact filename, parsed wheel metadata, `RECORD`, and consumer profile |
| Install plan | Target-independent scheme-relative relocation and transformation intent under a versioned plan model |

A realized installed tree is a later target-specific effect. Wheel installation may relocate `.data`, rewrite `#!python` scripts, generate wrappers, write installer metadata, rewrite installed `RECORD`, and compile bytecode. Those operations depend on interpreter, scheme, platform, and installer policy. The generic archive content root is not a universal installed-tree root.

## `WheelInstallPlan`

The first plan should remain scheme-relative:

- root members target either `purelib` or `platlib` according to `Root-Is-Purelib`;
- `.data/{purelib,platlib,scripts,headers,data}` members target labeled schemes;
- collision detection occurs after relocation as well as before it;
- script rewrite intent and executable disposition are explicit;
- wrapper generation, installed `RECORD`, bytecode, and other generated files remain separate target realization actions.

The plan does not query the host for scheme paths. Its fields are externally read-only and it cannot be deserialized into evaluator authority. A caller supplies a versioned target model later, and `realize_identity` validates canonical, collision-free output evidence, complete plan-target coverage, and exact bytes for copy actions before producing an identity. This validates the claim structure; it does not perform or independently observe installation.

## Corpus program

The benign corpus is byte-addressed and reproducible rather than committed wholesale.

The acquisition manifest records:

- selection cohort and query date;
- normalized project and release;
- artifact filename and URL;
- SHA-256, size, and upload time from the index;
- provenance URL when published;
- producer and platform cohort where derivable;
- redistribution status;
- expected acquisition and profile result.

Sampling should cover pure and platform wheels, common build backends, operating-system tags, `.data` use, Unicode names, metadata versions, secure `RECORD` hash algorithms, and a range of sizes. The report publishes acceptance, rejection rules, producer distribution, investigated clusters, and the exact domain to which percentages apply.

The initial [20-wheel compatibility pilot](../wheel-compatibility-pilot.md) covers eight universal artifacts and twelve native artifacts across Linux x86_64, Windows x86_64, macOS arm64, and macOS universal2. It is a judgmental sample of named current releases, not a prevalence estimate. Under `sealr.profile.zip.strict-ascii.v2`, 19 artifacts are admitted. The SciPy artifact is denied by three `quota.ratio` findings on test-data members with declared expansion above the default `100:1` limit. Across the 19 interpreted artifacts, all 4,504 members use Store or Deflate, all general-purpose flags are zero, and no extra fields occur. Every interpreted artifact has one top-level `.dist-info` path, but Setuptools carries twelve additional nested vendored `.dist-info` paths. This confirms that selection must match the normalized outer filename at the top level; counting every `.dist-info` suffix is not a valid wheel rule.

The predecessor-bound [v2 semantic inventory](../wheel-compatibility-v2.md) evaluates the same exact bytes through the wheel profile and bounded consumer. Sixteen are admitted, two denied, and two unsupported. It inventories Core Metadata 2.1 and 2.4 among admitted artifacts, ten exact generator strings, expanded filename tags, creator systems, and 61 executable members. No artifact in this judgmental pilot uses `.data` or Unicode paths, so hostile fixtures provide those rule consequences. The cffi duplicate `Generator`, Core Metadata 2.5 in Hatchling and wheel, and SciPy ratio ceiling are individually investigated rather than collapsed into an acceptance percentage.

The additive [v3 supported-preview inventory](../wheel-compatibility-v3.md) replays the same 90,417,280 exact source bytes through `sealr.profile.zip.portable-utf8.v1` and the shipped `sealr::wheel` evaluator. The outcome remains sixteen admitted, two denied, and two unsupported. It records 60 source-executable members instead of 61 because the supported model requires ZIP creator system 3 before Unix mode bits become executable authority. The removed orjson observation came from creator system 0. The v2 bytes remain unchanged as the exact PyPA installer 0.7.0 research result.

That predecessor result supports the closed ASCII v2 contract but was deliberately insufficient by itself to choose the wheel-oriented UTF-8 profile. The implemented profile therefore derives its exact UTF-8, NFC, flag, extra-field, and collision rules from a closed specification decision plus hostile boundary fixtures, not from prevalence in the benign sample. The next corpus increment should target producers and historical artifacts known to exercise UTF-8 flag handling, data descriptors, timestamps, platform extras, `.data` trees, and Unicode paths. Ratio-boundary sampling remains a separate resource-policy study so a benign compatibility observation cannot silently weaken the interpretation profile or default adversarial budget.

The hostile corpus includes:

- known ZIP parser-differential constructions adapted to wheel shape;
- interleaved headers, descriptors, comments, unknown extras, Unicode Path extras, NUL names, and normalized aliases;
- missing, extra, duplicate, traversing, absolute, or hash-mismatched `RECORD` rows;
- `.data` relocation collisions;
- unsafe generated entry-point names;
- executable-mode and script-rewrite edge cases;
- artifact filename and internal metadata disagreement.

Every discovered failure becomes a minimized deterministic regression with an expected phase and finding.

## Canonical consumer proof

The canonical-consumer integration makes the original wheel unavailable after admission, then completes its work through the admitted capability and plan. An audit hook verifies that no ZIP parser reopens the source.

The laboratory pins PyPA `installer` 0.7.0 by version and wheel SHA-256. Rust stages bounded blobs only through `VerifiedArchive::read_member`, deletes the original fixture wheel before Python starts, and passes no source-wheel path or ZIP descriptor to the external process. The Python adapter receives only a bounded verified-member and plan descriptor, installs an audit hook before importing installer, rejects every `.whl` open, validates `RECORD`, proves repeatable `WheelSource` iteration, and compares installer writes, relocations, shebang rewrites, generated wrappers, and final `RECORD` placement with the Rust plan. The resulting target outputs receive a separate realization identity.

The supported API has its own downstream integration contract. It ingests a path through the portable profile, clones only the opaque `VerifiedArchive`, deletes the original wheel, evaluates an NFC Unicode member through `sealr::wheel::evaluate_wheel`, repeats the evaluation, and requires byte-identical identities and plan output. A separate regression gives the evaluator a verified archive under the Alpha.7 research profile and requires `Unsupported`, never `Denied`.

A GitHub Action that checks a wheel and then lets another tool unzip the original does not pass this test. It is a useful gate, not a canonical consumer.

## Non-goals for the first profile

- dependency resolution;
- source-distribution builds;
- executing package code or metadata;
- malware classification;
- support for every core-metadata or wheel version;
- ZIP64 or additional codecs;
- universal launcher generation;
- bytecode compilation;
- a platform-independent claim about final installed bytes;
- patching pip internals;
- treating `RECORD.jws` or `RECORD.p7s` as current trust evidence;
- package signing before unsigned consumer claim bytes and the broader evidence verifier stabilize.

## Preview promotion evidence

The supported preview requires:

- the wheel-oriented ZIP profile has an exhaustive rule table and cross-platform vectors;
- verified-member access works without reopening the source or invoking a second ZIP parser;
- the artifact filename is bound into consumer identity;
- strict `RECORD` bijection, hash, size, relocation, and path tests pass;
- artifact and plan identities are byte-identical across supported platforms;
- the compatibility report is reproducible and every material rejection cluster is investigated.

Alpha.8 meets these gates through the portable profile vector, exhaustive flag and extra-field checks, the public capability-only evaluator, downstream source-deletion regression, hostile fixtures inherited from the Alpha.7 laboratory, distinct identity domains, and the predecessor-bound v3 inventory. Alpha.8 release promotion requires the final surface to pass Required CI on Linux, macOS, and Windows.

This is supported prerelease evaluation, not stable wheel installation. A stable API requires a larger targeted corpus with benign `.data`, Unicode, and descriptor-bearing artifacts; an explicit Core Metadata version policy; long-running cross-platform evidence; broader public API review; and the remaining production-readiness gates in the roadmap.

## Primary sources

- [Python wheel binary distribution format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
- [Recording installed projects and `RECORD`](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)
- [PyPI response to wheel archive confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [2026 Python wheel parser differential advisory](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
- [PyPI Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
- [PyPI public BigQuery datasets](https://docs.pypi.org/api/bigquery/)
- [PyPA installer concepts](https://installer.pypa.io/en/stable/concepts/)
- [PyPA installer `WheelSource` API](https://installer.pypa.io/en/stable/api/sources/)
