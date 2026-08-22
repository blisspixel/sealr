# Python wheel consumer profile draft

> Status: design and corpus plan only. Alpha.3 does not recognize wheels as a consumer type, parse wheel metadata, validate `RECORD`, or produce an installation plan. No finding or identity name on this page is a shipped contract.

The first consumer should force Sealr to prove its category: another tool receives one admitted representation and does not open the ZIP again. Python wheels are a strong target because wheel installation has archive semantics, package metadata, an internal content manifest, relocations, and target-dependent transformations.

## Proposed boundary

```text
exact artifact filename + SourceSnapshot
    -> ZIP interpretation under an exact wheel-oriented profile
    -> fully verified ArchiveIR
    -> bounded wheel metadata evaluation
    -> WheelArtifactIR
    -> optional scheme-relative WheelInstallPlan
```

The evaluator is pure. It does not select an environment, install a package, resolve dependencies, execute metadata, or write a destination.

## Semantic inputs

The consumer request must bind:

- the exact outer artifact filename, because distribution, version, build, Python, ABI, and platform tags are not inside the ZIP container identity;
- the source, interpretation profile, resource budget, and `python-wheel.v1` consumer profile;
- the supported wheel and core-metadata specification snapshots;
- an optional explicit target model for compatibility or install planning.

Renaming identical ZIP bytes can therefore change consumer identity or make wheel admission fail. Source identity and archive-tree identity remain unchanged.

## Required capability

The wheel evaluator consumes an opaque verified archive capability. It reads bounded verified members from the existing interpretation and never:

- reopens the original artifact path;
- invokes Python `zipfile`, another Rust ZIP parser, or an external extractor;
- inflates one member again through a second interpretation;
- treats a caller-constructed serializable IR as proof of admission.

The verification pass may retain bounded semantic members such as `WHEEL`, `METADATA`, `RECORD`, and `entry_points.txt`, or provide verified reads from the immutable snapshot. The chosen mechanism must preserve one parse and one measured content result.

## Container profile

The planned wheel container profile is narrower than general ZIP compatibility:

- ZIP32 with Store and Deflate first;
- exact covering and exact Deflate input consumption;
- member names encoded as strict UTF-8 under the wheel specification;
- no legacy CP437 fallback inside this profile;
- no Unicode Path extra-field override;
- exhaustive flags and extra-field dispositions;
- canonical path, normalization, case, and target-collision rules selected from published vectors and compatibility data;
- no encryption, ZIP64, spanned records, links, devices, recovery parsing, or archive mode restoration.

The exact profile identifier is assigned only after its rule table and conformance vectors are complete. The generic legacy CP437 question remains a separate profile decision and does not block a wheel-specific UTF-8 language.

## `WheelArtifactIR`

The proposed artifact object records, at minimum:

- parsed outer filename and expanded compatibility tags;
- normalized distribution and version;
- exactly one matching `.dist-info` directory;
- at most one matching `.data` directory;
- parsed `WHEEL` and `METADATA` fields under pinned specification snapshots;
- strict `RECORD` rows and their binding to verified archive members;
- executable intent needed for later script handling;
- bounded entry-point metadata when the selected consumer scope includes it;
- consumer findings, normalization decisions, and verification completeness.

This object describes the distribution artifact. It is not an installed environment and does not claim target compatibility merely because the artifact is structurally valid.

## Candidate admission rules

The research corpus and specification review must settle these rules before implementation is called supported:

1. The outer filename parses and agrees with normalized distribution, version, build, and expanded `WHEEL` tags.
2. Exactly one matching `.dist-info` directory contains regular-file `METADATA`, `WHEEL`, and `RECORD` members.
3. `Wheel-Version` support is explicit. A greater unsupported major version is unsupported, not a policy denial.
4. `Root-Is-Purelib` is present and exact.
5. `RECORD` uses a strict bounded CSV grammar and has one row per archive file, with only specification-defined exemptions.
6. Every non-exempt row has an approved secure hash and exact size matching the already verified member. The `RECORD` row itself and any explicitly admitted signature-file row follow the specification's empty hash and size exception.
7. `RECORD` paths are canonical archive-relative forward-slash paths. The broader installed-project grammar is not reused as authority for archive lookup or deletion.
8. Phantom, absolute, parent-relative, duplicate, and normalized-collision rows reject.
9. `.data` contains only supported scheme keys, and relocation is collision-free after mapping.
10. Entry-point command names and generated target names pass a separate target-path policy. Archive path admission alone does not sanitize generated names.
11. Deprecated `RECORD` signature files, if admitted at all, are explicit legacy objects and are never treated as verified signatures.
12. Metadata, row count, line length, field count, tag expansion, and retained semantic bytes have independent checked caps.

Candidate rules remain draft until compatibility measurement and hostile fixtures establish their consequences.

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

The plan does not query the host for scheme paths. A caller supplies a versioned target model later, and effect evidence records the realized mapping.

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

The eventual integration must make the original wheel unavailable after admission, then complete its work through the admitted capability or plan. An open-hook or process trace verifies that no ZIP parser reopens the source.

A PyPA `installer` `WheelSource` adapter is a promising experimental bridge because it can represent an alternative verified wheel source. Its API stability and upstream fit must be evaluated before it becomes a supported dependency or integration.

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
- package signing before unsigned consumer claim bytes and an independent verifier stabilize.

## Promotion gates

The design becomes experimental admission only when:

- the wheel-oriented ZIP profile has an exhaustive rule table and cross-platform vectors;
- verified-member access works without reparsing or reinflating;
- the artifact filename is bound into consumer identity;
- strict `RECORD` bijection, hash, size, relocation, and path tests pass;
- artifact and plan identities are byte-identical across supported platforms;
- the compatibility report is reproducible and every material rejection cluster is investigated.

It becomes the canonical-consumer proof only when an external tool consumes the admitted representation while denied access to the original wheel.

## Primary sources

- [Python wheel binary distribution format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
- [Recording installed projects and `RECORD`](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)
- [PyPI response to wheel archive confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [2026 Python wheel parser differential advisory](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
- [PyPI Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
- [PyPI public BigQuery datasets](https://docs.pypi.org/api/bigquery/)
- [PyPA installer concepts](https://installer.pypa.io/en/stable/concepts/)
- [PyPA installer `WheelSource` API](https://installer.pypa.io/en/stable/api/sources/)
