# Near-term execution plan

> Status: active plan from the Alpha.4 baseline. This page turns the long-range [roadmap](../ROADMAP.md) into release-sized work and records completed gates where they constrain the next increment.

The next work should produce thin, independently reviewable trust increments. Each increment must finish with a useful artifact, explicit evidence, and a bounded claim. Work that merely makes the codebase larger does not count as progress.

## Decisions that change the previous sequence

Three dependencies are now explicit:

1. **The private file-backed source snapshot precedes the worker.** The worker must receive an immutable, bounded archive capability. Designing IPC around a whole-archive `Vec<u8>` would make the protocol temporary and would test the wrong resource model.
2. **Assurance starts now.** Pure interval, quota, path, and lifecycle properties are prerequisites for worker, Unicode, and random-access changes. They cannot wait for a late assurance phase.
3. **Wheel research starts now, but wheel support does not.** A non-shipping laboratory will measure real wheels and pressure-test the semantic API. A supported consumer profile still waits for its exact ZIP profile, verified-member access, canonical paths, and consumer identities.

The result is one primary delivery stream and two parallel research streams:

```text
Primary       semantic closure -> private snapshot -> Linux worker
Assurance     property models  -> fuzz and Kani    -> native stress
Wheel lab     corpus inventory -> profile draft    -> pure admission pilot
```

The assurance and wheel lanes may add test, corpus, and research tooling. They do not add a fallback parser or silently widen the shipped profile.

## Delivery map

| Target | Outcome | Primary exit evidence |
|---|---|---|
| Alpha.4 | Measured semantic contract | Exact profile rules, adopter-safe capability boundary, independent identity vectors, property gates, first wheel compatibility report |
| Alpha.5 | Bounded immutable input | Private file-backed snapshot, checked random access, mutation resistance, memory budget, fuzzable worker protocol |
| Alpha.6 | Reduced-authority Linux execution | Enforced worker, minimum Landlock rights, descriptor audit, supervisor re-audit, native race evidence |

Version labels are delivery targets, not permission to cut a release with a red gate. If an increment changes identity or interpretation, it receives a new profile or schema identifier and preserves prior identifiers as immutable historical contracts.

## Alpha.4: measured semantic contract

Alpha.4 closes the contract before another public surface becomes accidental API.

Current main has completed the Alpha.4 measured-contract gate. It removes public `ArchiveIR` construction and mutation, exposes read-only evidence and an opaque `VerifiedArchive`, supports independently bounded exact-path retention during the original verification pass, preserves caller-bounded fallback reads, and tests a separate consumer against the extracted packaged crate. Six finite-domain property families run in required CI. A separate workspace verifier with no Sealr dependency checks a four-case conformance bundle, validates the recorded covering without discovery or inflation, and independently reproduces two exact profile digests plus three layout and three content roots. ZIP discovery and the codec-free covering audit share one checked interval and partition kernel, while declared and actual quota transitions use one atomic kernel. The reproducible 20-wheel pilot records 19 admissions plus one investigated ratio denial under the new closed strict ASCII v2 profile. The profile and identities remain preview contracts until their documented stability bar is met.

### Semantic profile

1. Build a reproducible benign wheel corpus before choosing the next extra-field policy. The acquisition manifest records artifact filename, URL, SHA-256, size, upload time, selection cohort, and provenance URL when available. Raw artifacts are not committed when redistribution is unclear. **Initial pilot landed:** 20 non-yanked PyPI wheels across universal, Linux x86_64, Windows x86_64, macOS arm64, and macOS universal2 cohorts are pinned by exact bytes and reproducible acquisition metadata.
2. Inventory flags, extra-field identifiers by local and central site, compression methods, filename encodings, path shapes, producer metadata, and current admission findings. **Initial inventory landed:** 19 artifacts and 4,504 members produced an IR; every observed member used Store or Deflate with flags `0x0000`, and no extra fields were observed. Each interpreted artifact has one top-level `.dist-info` path, while Setuptools also contains twelve nested vendored `.dist-info` paths. The only denied artifact had three `quota.ratio` findings on highly compressible SciPy test data. Because the pilot contains no nonzero flag or extra-field observations, it narrows the next sampling question but does not justify a new permit rule.
3. Define a new strict profile with an exhaustive flag and extra-field table. Every field is semantic, explicitly permitted as nonsemantic, or denied. There is no catch-all `ignored` disposition. **Landed:** [`sealr.profile.zip.strict-ascii.v2`](profiles/zip-strict-ascii-v2.md) permits only semantic data-descriptor bit 3, denies the other 15 flag bits, and denies all 65,536 extra-field identifiers at both sites.
4. Keep `sealr.profile.zip.strict-ascii.v1` unchanged. A correction to interpretation creates a new profile identity instead of changing old bytes under an old name.
5. Publish the measured acceptance rate and investigated rejection clusters. The objective is a documented domain, not maximum acceptance. **Initial report landed:** the [wheel compatibility pilot](wheel-compatibility-pilot.md) reports `19/20` admission, separates affected-artifact counts from finding occurrences, and retains the default `100:1` limit pending broader evidence and adversarial-cost analysis.

### Adopter-safe Rust boundary

1. Separate serializable evidence from authority. A public IR view may describe a tree, but downstream code must not be able to construct a value that claims admission or verification.
2. Introduce an opaque admitted or verified archive capability with bounded verified-member reads. A consumer must not need to reopen the ZIP to read `WHEEL`, `METADATA`, or `RECORD`.
3. Keep `apply()` as the alpha compatibility facade while the capability API is evaluated.
4. Replace direct construction of evolving configuration with validated constructors or builders. Mark evolving public enums and records non-exhaustive where exhaustive downstream matching is not part of the contract.
5. Add a downstream compile fixture, packaged-crate build, rustdoc examples, and an explicit MSRV policy. Keep crates unpublished until this API review is complete.

The first two capability increments are now implemented on main. `VerifiedArchive` is Sealr-constructed, retains the exact snapshot and verified IR, and supports canonical-path reads with a caller-supplied maximum. `apply_with_options` can also request exact canonical paths through a validated `RetentionPlan`. Selection is deterministic in canonical-path order and bounded by 64 paths, 4,096 bytes per path, 16,384 total path bytes, and caller-selected per-member and aggregate content ceilings. Selected content is captured during the original verification stream, including the materialization stream. A retained borrow performs no reopen, parse, inflation, allocation, or hash. Retention failure is reported per path and never weakens archive admission. Non-retained `read_member` calls preserve the original re-inflate and revalidate behavior. The packaged consumer and Rust 1.98 MSRV policy are required-CI contracts.

### Executable conformance

1. Define a versioned conformance-case manifest that binds source digest, profile ID and digest, semantic axes, findings, member manifest, layout root, and content root when available. **Initial bundle landed:** `sealr.identity-conformance.v1` embeds exact bytes for four small cases and the complete serializable IR evidence when available.
2. Add an independent identity verifier that implements the documented preimages without calling the production encoder. It verifies evidence; it does not parse or inflate ZIP. **Landed for identity v1:** the standalone workspace tool has no Sealr dependency, follows only claimed ranges, checks the ZIP32 covering certificate, and reproduces every committed profile and tree vector. It does not independently execute interpretation or codecs.
3. Extract pure checked kernels for ranges and partitions, quota transitions, strict-profile path topology, and outcome or materialization lifecycle transitions. **Range, partition, and quota kernels landed:** ZIP discovery and the codec-free covering audit use the same checked half-open interval and exact-partition implementation. Declared, actual, remaining, and member counters use one atomic quota transition that does not mutate state on failure.
4. Test each kernel against a deliberately simpler independent oracle. **Range and quota oracles landed:** checked offset-plus-length arithmetic and quota transitions are compared with `u128`, and exact partitions are compared with a bounded per-byte bitmap model. Discovered counterexamples become committed deterministic regressions.
5. Keep the added required-CI cost bounded and measured. Tool-only dependencies do not enter the release binary.

### Alpha.4 exit gate

**Status: complete on current main.** The next release may be cut only after the release-candidate and exact-main gates pass.

- The new profile has no unspecified flag or extra-field behavior.
- Every material wheel rejection cluster above the documented review threshold is investigated.
- Independent code reproduces every published profile, layout, and content identity vector.
- At least five named generated property families run in required CI with persisted regressions.
- A separate Cargo fixture uses only the intended packaged public API.
- No consumer example reconstructs an admitted IR or reopens the source ZIP.
- README and API language continue to call the profile and identities preview contracts unless their stability bar is actually met.

## Alpha.5: bounded immutable input

Alpha.5 makes the source capability real before it crosses a process boundary.

**Current main status:** the backend-neutral access substrate and first private spool have landed. Magic detection, ZIP discovery, central and local metadata reads, descriptor checks, covering audit, original member verification, and later verified-member reads use checked `u64` ranges or range-limited readers. Central-directory buffering occurs only after the metadata cap passes, and compressed payloads stream in fixed buffers. A path is opened once and copied under the source cap into a random native-private directory through a fixed 64 KiB buffer while SHA-256 is computed. Sealr validates the opened source length and native change fingerprint, reopens only its own file read-only, removes its filename, and retains that unnamed capability. Windows denies write sharing during the copy. Private-file and borrowed-memory runs produce byte-identical semantic evidence. Same-length mutation, physically sparse 128 MiB, isolated peak-memory, and 3 GiB native matrix gates have landed. The bounded protocol codec, malformed-frame suite, seed manifest, and pinned fuzz workflow have landed. A clean scheduled fuzz campaign remains before Alpha.5 release.

### Snapshot backend

1. Make the first file-backed source a Sealr-owned private spool: copy once while hashing and enforcing the source cap, retain the resulting object, and stop relying on the original path.
2. Give interpretation and verification read-only random access to that retained object. No later phase reopens the input path. **Landed for path and byte inputs.**
3. Keep offsets and lengths as checked `u64`, with explicit bounded conversion at each I/O boundary. **Landed for memory and private-file backends and every parser/verifier call path.**
4. Bind the snapshot to its exact length and source digest. A partial copy never receives the digest of a bounded prefix as though it were the whole source. **Landed for the first private spool; failures before exact EOF keep the digest unavailable.**
5. Prefer the simple copy, hash, retain design over direct mmap or unproven filesystem immutability. Content-addressed reuse and zero-copy backends can follow measured need.

### Resource and mutation evidence

1. Test truncation, growth, in-place source mutation, path replacement, stale handles, short reads, and copy interruption. **Landed:** the suite covers length mismatch, cap growth, deterministic same-length mutation, Windows writer exclusion, replacement after the source handle opens, repeated short reads, interruption retry, private-directory cleanup, original-path deletion, and retained reads.
2. Verify that memory stays within a declared budget independently of archive size. **Landed as a required regression gate:** isolated child processes apply physically sparse valid 1 MiB and 128 MiB ZIPs. Tracked heap allocation is capped at 8 MiB with a 1 MiB size-related delta; peak resident memory is capped at 256 MiB with a 64 MiB delta. The latest Windows run measured 210,367 tracked heap bytes for both and about 7.3 MiB peak resident memory for each.
3. Inspect a large sparse valid fixture without a proportionally large allocation. **Landed as scheduled evidence:** a locally executed 3 GiB sparse ZIP32 case used 131,072 allocated source bytes and 210,427 tracked heap bytes. The exact ignored regression runs monthly on Linux, macOS, and Windows so the expensive native measurement does not burden every pull request.
4. Require the memory-backed and file-backed snapshots to produce byte-identical IR, findings, and roots for the same bytes. **Landed for the current borrowed-memory and private-file backends.**

### Protocol preparation

1. Specify a bounded, versioned supervisor-worker control frame over snapshot and stage capabilities. The frame does not contain the archive blob. **Landed:** [worker protocol v1](worker-protocol.md) uses fixed versioned framing and out-of-band capability slots.
2. Bound every message, member count, string, range list, and response before allocating. **Landed for protocol v1:** the whole frame, counts, fixed minimum encoding, strings, manifest, and findings have explicit limits and fallible allocation. Version 1 carries no range list.
3. Fuzz the frame and response decoders alongside inspect-only ZIP bytes, path topology, and covering plus codec boundaries. **Protocol slice landed:** the first target covers arbitrary start and result frames plus input-directed mutations of valid frames. ZIP, topology, covering, and codec targets remain later assurance increments.
4. Pin fuzz tool versions and toolchains, record resource limits and seed-manifest digests, and promote every reproducible crash into a deterministic regression. **Landed for the protocol target:** required CI verifies exact tool, seed, dictionary, time, input, timeout, memory, job, and artifact-retention configuration. The bounded AddressSanitizer campaign runs weekly and on demand.

### Alpha.5 exit gate

**Status: awaiting scheduled evidence.** The snapshot, mutation, backend-parity, required resource, scheduled multi-gigabyte, bounded protocol, and deterministic malformed-frame gates are complete. The first clean scheduled AddressSanitizer protocol campaign and exact-main release gates remain release blockers.

- Resident memory is bounded independently of accepted archive size.
- Interpretation and payload verification cannot observe different source versions.
- A large valid fixture is inspected through checked random access without whole-archive allocation.
- Snapshot implementations agree on semantic outputs and identities.
- Protocol decoders reject malformed, oversized, truncated, and count-inconsistent frames before effect.
- Scheduled fuzzing has explicit time, memory, input, and output bounds and no unresolved reproducible crash.

## Alpha.6: reduced-authority Linux execution

Alpha.6 gives a compromised parser materially less ambient authority while preserving the same semantic result.

### Worker boundary

1. The supervisor owns the private snapshot, destination parent, stage creation, final name, publication, cleanup, and any recovery secret.
2. The same-binary worker inherits only the bounded control channel, a read-only snapshot capability, and the stage capability needed for its selected effect.
3. Close every unrelated descriptor before restriction. Pre-opened descriptors are authority and must be audited separately from pathname rules.
4. Install `no_new_privs` and Landlock before the first archive byte is interpreted.
5. Require a release-runner Landlock floor that includes cross-directory refer controls and file truncation controls, currently ABI 3. A weaker kernel reports isolation unavailable and cannot satisfy the Linux reduced-authority release gate.
6. Report available ABI, requested rights, handled rights, granted paths, inherited descriptors, and setup result separately. Do not claim complete network isolation from Landlock alone.

### Untrusted worker result

1. Bound and validate the result frame before use.
2. The supervisor consumes the same admitted manifest and never reparses ZIP.
3. Re-audit the stage for exact object count, kind, identity, size, and SHA-256 before publication.
4. Treat worker crash, malformed response, timeout, audit mismatch, cleanup failure, publication failure, and commit as distinct lifecycle states.
5. Compare every observed lifecycle receipt with an executable finite-state model.

### Native adversarial evidence

1. Keep deterministic namespace and content-substitution tests in required CI.
2. Run bounded repeated race and fault stress on native Linux, macOS, and Windows schedules.
3. Require the Linux worker to fail opening an unrelated sentinel, creating a sibling beside the stage, or publishing the final destination.
4. Keep macOS and Windows parser, identity, and materialization gates green while reporting process isolation unavailable on those platforms.

### Alpha.6 exit gate

- Isolation is installed before the first untrusted archive read.
- Only the documented descriptors survive worker startup.
- The worker cannot read the sentinel, create outside the stage, or publish.
- The supervisor rejects every missing, extra, linked, replaced, size-mismatched, or digest-mismatched staged object.
- At least 500 bounded hostile iterations per native platform complete with zero outside writes and zero destination replacement.
- Linux fails closed when the minimum handled rights are unavailable.
- Receipts distinguish enforcement, protocol, worker, audit, effect, and cleanup outcomes without changing archive admission into an effect verdict.

## Wheel laboratory, parallel and non-shipping

The [Python wheel profile draft](profiles/python-wheel-v1.md) defines this lane. Its purpose is to make the generic boundary answer a real consumer before the consumer API freezes.

The first [compatibility pilot](wheel-compatibility-pilot.md) is now reproducible from a bounded manifest and ignored local cache. Its committed report is checked offline in the existing required `CI` workflow for manifest binding, current profile and default-policy identities, internal rollups, canonical JSON, and Markdown rendering. CI does not download the corpus or claim to re-execute the measurements.

The laboratory may:

- acquire byte-addressed wheels through PyPI's documented APIs;
- inventory compatibility and proposed rules;
- build hostile wheel fixtures;
- parse verified metadata through the new member-read capability;
- compare a pure wheel plan with established tools on well-formed inputs.

It may not:

- advertise wheel support;
- add a second ZIP parser;
- silently accept unknown ZIP features;
- call an ordinary unzip after admission;
- label an archive content root as an installed-tree root;
- make a GitHub gate count as the canonical-consumer proof.

The lab becomes experimental `python-wheel.v1` admission only after the exact wheel ZIP profile, canonical UTF-8 paths, verified-member access, consumer budgets, and consumer identities pass their gates. Linux worker isolation is required for a Sealr-owned install effect, but not for a pure no-effect wheel evaluator.

## Assurance cadence

Evidence types remain distinct:

| Evidence | Initial trigger | Promotion rule |
|---|---|---|
| Unit, conformance, and generated properties | Pull request and main | Required immediately when bounded |
| Bounded model checking | Scheduled and manual | Promote named scalar harnesses after ten stable main runs |
| Coverage-guided fuzzing | Scheduled | Replay committed regressions on pull requests; add a smoke gate only after cost is stable |
| Native race and fault stress | Scheduled | Keep deterministic seams required; promote only reproducible bounded cases |
| Mutation and coverage reports | Weekly discovery | Use to find weak assertions and blind branches, not as a headline score |
| Benign compatibility measurement | Before each profile release | Publish acquisition manifest, acceptance, rejections, and investigated clusters |
| Independent review | After the semantic, worker, path, snapshot, and evidence surfaces freeze | Scope the exact claims and residual assumptions |

The existing `CI` workflow remains the only required promotion authority. Scheduled assurance discovers failures. A check moves into required CI only when its runtime is bounded, failures reproduce locally, and ten consecutive main runs establish stability.

## After Alpha.6

Two implementation lanes can proceed in parallel without inventing another meaning:

- **Semantic and consumer lane:** canonical UTF-8 paths for wheels, a separately versioned legacy CP437 profile where compatibility evidence justifies it, `WheelArtifactIR`, scheme-relative `WheelInstallPlan`, and the first external consumer bridge.
- **Systems lane:** authenticated abandoned-stage recovery, explicit durability levels, and platform-specific worker research.

Both lanes consume the same snapshot, `ArchiveIR`, identities, findings discipline, and conformance bundles. Common codecs and TAR remain behind the Phase 0.1 trust gate.

## Primary sources

- [Python wheel binary distribution format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
- [PyPI response to wheel archive confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [2026 Python wheel parser differential advisory](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
- [PyPI Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
- [PyPI public BigQuery datasets](https://docs.pypi.org/api/bigquery/)
- [Linux Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [Kani Rust Verifier](https://model-checking.github.io/kani/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [Cargo SemVer compatibility guidance](https://doc.rust-lang.org/cargo/reference/semver.html)
