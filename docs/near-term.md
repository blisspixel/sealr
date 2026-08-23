# Near-term execution plan

> Status: active plan from the Alpha.5 baseline. This page turns the long-range [roadmap](../ROADMAP.md) into release-sized work and records completed gates where they constrain the next increment.

The next work should produce thin, independently reviewable trust increments. Each increment must finish with a useful artifact, explicit evidence, and a bounded claim. Work that merely makes the codebase larger does not count as progress.

## Decisions that change the previous sequence

Three dependencies are now explicit:

1. **The private file-backed source snapshot precedes the worker.** The worker must receive an immutable, bounded archive capability. Designing IPC around a whole-archive `Vec<u8>` would make the protocol temporary and would test the wrong resource model.
2. **Assurance starts now.** Pure interval, quota, path, and lifecycle properties are prerequisites for worker, Unicode, and random-access changes. They cannot wait for a late assurance phase.
3. **Wheel research starts now, but wheel support does not.** A non-shipping laboratory will measure real wheels and pressure-test the semantic API. A supported consumer profile still waits for its exact ZIP profile, verified-member access, canonical paths, and consumer identities.

The result is one primary delivery stream and two parallel research streams:

```text
Primary       semantic contract [done] -> private snapshot [done] -> supervised Linux worker [active]
Assurance     property models [active] -> bounded fuzzing [active] -> Kani and native stress [next]
Wheel lab     corpus inventory [done]  -> profile draft [active]   -> pure admission pilot [next]
```

The assurance and wheel lanes may add test, corpus, and research tooling. They do not add a fallback parser or silently widen the shipped profile.

## Immediate Alpha.6 sequence

These are the next three mergeable trust increments. The first two can proceed in parallel. The third starts only after semantic shadow parity is clean.

1. **Close dormant semantic assurance.** **Allocation and ownership hardening landed:** input-sized path, topology, covering, extra-field, planning-canonicality, and completion-reconstruction work now uses fallible or allocation-free validation; direct completion encoding materializes no IR, invalid decode materializes none, valid decode materializes exactly one fallibly reconstructed IR, and findings move instead of cloning. A deterministic failpoint walk covers every completion-reconstruction reservation without mutating the accepted plan. A record above 64 KiB proves an exact logical reconstruction budget, one-byte-under typed failure, and one materialization at the exact budget. **Source-I/O axes fix landed:** verification-time source I/O now produces `Indeterminate + Admitted + Partial`, preventing a zero-difference matrix from canonizing the prior shared bug. Next, add a manifest-pinned shadow matrix spanning ready, terminal, complete, stopped, setup-failure, Store, Deflate, descriptor, quota, and codec outcomes. Compare exact IR, ordered findings, axes, verified frontier, and request and plan correlation. Preserve any fuzz reproducer as a deterministic regression. Clean exact-main on-demand campaign evidence is in the [assurance ledger](assurance.md#current-evidence); zero differences across the broader pinned matrix, an isolated allocator or process peak-live measurement, the first scheduled-event run, and accumulated scheduled history remain open.
2. **Close the pre-parser Linux authority gate.** Add measured no-process-creation and stage-permission-mutation controls, per-epoch stall deadlines, raw unknown-ancillary rejection, and repeated hostile fault stress. Exit evidence is denial of process creation and stage permission mutation before source transfer, bounded termination and reap for every stalled epoch, and 500 iterations with no surviving descendant, outside write, leaked descriptor, destination replacement, or cleanup before reap.
3. **Extract a crate-private inspect-only validated-plan executor.** Consume only a source-bound `ValidatedPlanningRecord`, reuse the existing IR-driven payload path, and leave destination effects, publication, retained-content transfer, and later reads out of scope. Exit evidence is instrumentation showing one structural parse during planning and none during execution, plus exact complete and stopped parity for Store, Deflate, CRC, size, ratio, total-budget, and injected source-I/O failures.

Together, the first two increments freeze what the worker may mean and what authority it may hold. The third is the narrow entry point for a later sealed, inspect-only worker bridge.

## Delivery map

| Target | Outcome | Primary exit evidence |
|---|---|---|
| Alpha.4 | Measured semantic contract | Exact profile rules, adopter-safe capability boundary, independent identity vectors, property gates, first wheel compatibility report |
| Alpha.5 | Bounded immutable input | Private file-backed snapshot, checked random access, mutation resistance, memory budget, fuzzable worker protocol |
| Alpha.6 | Reduced-authority Linux execution | Enforced worker, minimum Landlock rights, descriptor audit, supervisor re-audit, native race evidence |

Version labels are delivery targets, not permission to cut a release with a red gate. If an increment changes identity or interpretation, it receives a new profile or schema identifier and preserves prior identifiers as immutable historical contracts.

## Alpha.4: measured semantic contract

Alpha.4 closes the contract before another public surface becomes accidental API.

Current main has completed the Alpha.4 measured-contract gate. It removes public `ArchiveIR` construction and mutation, exposes read-only evidence and an opaque `VerifiedArchive`, supports independently bounded exact-path retention during the original verification pass, preserves caller-bounded fallback reads, and tests a separate consumer against the extracted packaged crate. Six finite-domain property families run in required CI. A separate workspace verifier with no Sealr dependency checks a four-case conformance bundle, validates the recorded covering without discovery or inflation, and independently reproduces two exact profile digests plus three layout and three content roots. ZIP discovery and the codec-free covering audit share checked interval construction and use separate bitmap-oracle-backed partition predicates, while declared and actual quota transitions use one atomic kernel. The reproducible 20-wheel pilot records 19 admissions plus one investigated ratio denial under the new closed strict ASCII v2 profile. The profile and identities remain preview contracts until their documented stability bar is met.

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
3. Extract pure checked kernels for ranges and partitions, quota transitions, strict-profile path topology, and outcome or materialization lifecycle transitions. **Range, partition, and quota kernels landed:** ZIP discovery and the codec-free covering audit share checked half-open interval construction. Discovery accepts unordered parts through `exact_partition`; the covering audit validates its already ordered scratch through a separate allocation-free predicate. Declared, actual, remaining, and member counters use one atomic quota transition that does not mutate state on failure.
4. Test each kernel against a deliberately simpler independent oracle. **Range, partition, and quota oracles landed:** checked offset-plus-length arithmetic and quota transitions are compared with `u128`; discovery's exact partition is compared across 1,055,758 cases with a bounded per-byte bitmap model; and the covering audit's ordered predicate is independently compared across 204,204 cases. Discovered counterexamples become committed deterministic regressions.
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

**Current main status:** complete. Magic detection, ZIP discovery, central and local metadata reads, descriptor checks, covering audit, original member verification, and later verified-member reads use checked `u64` ranges or range-limited readers. Central-directory buffering occurs only after the metadata cap passes, and compressed payloads stream in fixed buffers. A path is opened once and copied under the source cap into a random native-private directory through a fixed 64 KiB buffer while SHA-256 is computed. Sealr validates the opened source length and native change fingerprint, reopens only its own file read-only, removes its filename, and retains that unnamed capability. Windows denies write sharing during the copy. Private-file and borrowed-memory runs produce byte-identical semantic evidence. Same-length mutation, physically sparse 128 MiB, isolated peak-memory, and 3 GiB native matrix gates have passed. The bounded protocol codec, malformed-frame suite, source-controlled seed digest manifest, pinned fuzz workflow, and first clean AddressSanitizer campaign complete the increment.

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

**Status: complete on current main.** The snapshot, mutation, backend-parity, required resource, scheduled multi-gigabyte, bounded protocol, deterministic malformed-frame, and bounded AddressSanitizer fuzz gates have passed. Release promotion requires both exact-main CI and exact-commit on-demand fuzz evidence.

- Resident memory is bounded independently of accepted archive size.
- Interpretation and payload verification cannot observe different source versions.
- A large valid fixture is inspected through checked random access without whole-archive allocation.
- Snapshot implementations agree on semantic outputs and identities.
- Protocol decoders reject malformed, oversized, truncated, and count-inconsistent frames before effect.
- Scheduled fuzzing has explicit time, memory, input, and output bounds and no unresolved reproducible crash.

## Alpha.6: reduced-authority Linux execution

Alpha.6 gives a compromised parser materially less ambient authority while preserving the same public semantic and verified-capability contract. The work is split so Linux confinement can be measured before an incomplete worker result format is allowed to shape `Outcome` or `VerifiedArchive`.

### 1. Linux authority bootstrap

**Current status: authority and lifecycle conformance slices landed.** This remains a non-published tool, not a runtime path in `sealr` or `sealr-cli`.

1. A separately versioned 96-byte bootstrap exchange drives a same-binary Linux child over `SOCK_SEQPACKET`. Operation protocol v1 remains byte-compatible and non-runtime.
2. A pre-exec `close_range(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)` prevents unrelated inherited descriptors from crossing exec without interfering with the spawn error channel. At child entry, the process retains the control socket plus inert `/dev/null` output streams and repeats closure for descriptors 3 and above. A deliberate post-exec duplicate proves that the second layer closes authority independently of close-on-exec. The child then receives an optional private stage through one bounded `SCM_RIGHTS` packet. Transport validates exact counts and close-on-exec state; stage validation binds directory type, device, inode, effective owner, private mode, and read-only descriptor access, while source validation binds regular-file type, read-only access, length, device, and inode.
3. The child directly queries the running Landlock ABI, rejects a floor below ABI 3, sets and verifies `no_new_privs`, hard-requires the complete fixed ABI 3 filesystem-rights set, and grants a synthetic stage only `WRITE_FILE`, `MAKE_DIR`, and `MAKE_REG`. It sends correlated readiness before it owns any source descriptor. Deterministic ABI-2 and probe-failure modes prove the correlated fail-closed lifecycle but do not substitute for the real ABI 3 success probe.
4. The supervisor observes one thread, `NoNewPrivs: 1`, inert output streams, and the exact control-plus-optional-stage descriptor set through `/proc/<pid>`. A deliberately inheritable sentinel object must be absent. After source acceptance, a second paused observation binds exact source and stage object identities and access modes to the supervisor-retained descriptors.
5. Only after readiness does the supervisor transfer a read-only, unlinked synthetic source with exact length, device, and inode binding. The child proves the existing source capability remains readable, an unrelated or sibling path is denied, and a stage-local create succeeds when staged authority was granted.
6. The supervisor sends an explicit exit acknowledgement, waits against a bounded deadline, kills through a pidfd on timeout, reaps before fixture cleanup, and treats every response as untrusted. All post-spawn errors converge on the same bounded termination path. Native conformance covers inspect and stage success; writable, nonregular, missing, injected, and identity-drifted descriptors; operation drift; extra source authority; exact short, `MSG_TRUNC`, and `MSG_CTRUNC` source packets; deterministic restriction failures; 17 point-specific abrupt exits; and bounded timeout termination. Every abrupt-exit case checks source and outside-sentinel integrity, expected stage state, proved reap, checked cleanup, and root absence.

Remaining bootstrap closure includes bounded stalls in each authority epoch, exact unknown-ancillary handling beyond rustix's recognized control messages, and broader repeated fault stress. No-descendant and stage-permission-mutation controls also remain mandatory before semantic parsing. Current crash barriers prove deterministic unexpected self-exit handling; they do not yet prove every supervisor-initiated kill or real kernel setup failure at every phase.

### 2. Consumer-preserving semantic ownership

**Current status: dormant record, hostile decoder, source-binding hardening, input-sized allocation fallibility, single-materialization completion reconstruction, and a dedicated fuzz surface with clean exact-main on-demand evidence landed.** This establishes parity for the named deterministic record, source-binding, allocation, ownership, and codec cases plus a reproducible search boundary, not scheduled stability, broader shadow parity, complete `VerifiedArchive`, or runtime-worker parity.

1. Treat operation protocol v1 as a bounded transport foundation, not a frozen worker contract. It carries a reduced manifest but no complete `ArchiveIR`, ranges, independent public outcome axes, or authority for later `VerifiedArchive` reads.
2. Implement the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) as private split-phase planning and completion records. Keep `ArchiveIR` construction crate-private and bind each record to the exact source, request, profile, policy, resources, target, consumer, effect request, retention plan, operation, and preceding record. **Dormant codec, source-binding, and allocation slices landed:** the [private semantic-record experiment](semantic-record.md) binds those fields under independent magic, exact body consumption, a 64 MiB encoded-length ceiling checked before buffer-growth requests and copies, domain-separated request and plan IDs, and typed hostile-decode errors. Decode also binds the supervisor-owned snapshot, applies its expected-binding-validated path depth before owned component allocation, uses allocation-free ASCII-fold topology comparison with order-independent ancestor lookup and a fixed extra-ID set, reserves input-sized covering and path scratch fallibly, reproduces accepted or rejected covering evidence without cloning diagnostic labels, checks represented LFH, CDH, descriptor, name, extra-field, and structural ranges, replays signature exclusions over comments and stored descriptor payloads, checks member-kind agreement with source external attributes, and enforces the parser-equivalent metadata aggregate. The caller policy identity remains distinct from exact compiled controls; a separate compiled-controls digest stays unavailable until its preimage is specified.
3. Preserve the current destination-setup ordering: a bounded planning record exposes a phase-local ready-for-verification disposition and IR before supervisor-owned stage setup, without freezing public axes that later verification can change. Setup failure must merge into the existing admitted, setup-failed axes with incomplete verification and no `VerifiedArchive`. A successful execution phase must consume the validated plan without structurally reparsing the source and return the final semantic axes. **Representation and ownership slices landed:** planning carries complete pending IR in central-directory order; completion carries one verification state per planned member and no structural IR on wire; semantic and canonical validation borrow the accepted plan; accepted decode drops its canonical scratch before one fallible IR reconstruction and moves findings into the result. Executing that validated plan without another structural parse remains an explicit activation gate. No runtime path invokes the records.
4. Treat retained-content transfer, non-retained member reads, and helper packaging as separate capability gates. Borrowed IR and retained slices require local storage, while moving a complete IR alone would put later codec work back in the caller process. The first record experiment must not construct `VerifiedArchive`.
5. Preserve interpretation, admission, verification, view completeness, effect, and cleanup as separately owned facts. The worker cannot claim publication or final effect. The supervisor cannot claim independent archive interpretation merely because a complete record is well formed.
6. Pin record vectors for ready planning, terminal admission, terminal covering evidence, partial completion, complete completion, malformed structure, and record mutation. **Expanded deterministic slice landed:** canonical plan and completion digests, every truncation, trailing bytes, cross-kind decode, structured binding mutation, stale correlation, impossible frontiers, zero materialization for invalid completion, exactly one materialization for accepted completion, a full reconstruction-allocation failpoint walk, an exact logical allocation budget on a record above 64 KiB, source-order preservation, hostile finding labels, phase allowlists, range overflow, parser-oracle metadata-cap boundaries, represented fixed-field and descriptor source binding, interleaved exact and ASCII-folded file-ancestor conflicts, 257-component and normalization parity, expected-binding depth rejection before allocation, pre-growth encoded-length limits, and setup-failure merge are covered. A separate semantic-record libFuzzer target exercises arbitrary bytes, input-directed mutations of runtime-generated canonical frames, decode stability, exact Ready-plan IR parity with production, correlation, and every valid record kind. Four committed driver-input seeds plus a dictionary are digest-pinned. Required verification uses parsed Cargo metadata to bind each target and hidden driver, then binds the complete scheduled workflow, including its weekly trigger and both jobs. Negative fixtures reject inert TOML remapping, manual-only drift, weakening, inactive or appended commands, inert artifact evidence, and raw or quoted duplicate last-wins resource arguments. Clean exact-main on-demand evidence is recorded in the assurance ledger; the first scheduled-event run, accumulated history, an isolated peak-live allocation measurement, and broader shadow parity remain open. Worker crash belongs to supervisor lifecycle evidence, alongside verification and effect failure, writer quiescence, stage audit, cleanup, publication, clone and drop behavior, retained borrows, and bounded non-retained reads.
7. Keep the library, CLI, wheel laboratory, and packaged consumer on one semantic boundary. A CLI-only reduced manifest is not sufficient to complete this increment, and no public worker mode or protocol v2 lands before the content-authority and packaging gates close.

### 3. Supervised execution and publication

1. The supervisor owns the private snapshot, destination parent, stage creation, final name, publication, cleanup, timeout, termination, reap, and any recovery secret.
2. Run the chosen semantic operation only after the bootstrap proves restriction setup. A weaker Landlock ABI may report isolation unavailable but cannot satisfy the enforced-worker gate. Do not claim complete network isolation from Landlock alone.
3. Prevent a worker descendant from retaining writable stage authority. Use a minimal measured no-process-creation control or an equivalently proven supervisor-owned process boundary before archive interpretation; a broader syscall allowlist still waits for measured traces.
4. After a bounded result arrives, terminate and reap the worker boundary and prove writer quiescence before validating the result, auditing the stage, or publishing. A returned result alone is not a stable audit boundary.
5. Recompute every independently checkable identity, then audit the exact stage for object count, kind, link and reparse state, identity, size, and SHA-256. Do not reparse ZIP merely to create a second meaning.
6. Treat restriction failure, worker crash, malformed response, timeout, quiescence failure, audit mismatch, cleanup failure, publication failure, and commit as distinct lifecycle states and compare every observed receipt with an executable finite-state model.

### Native adversarial evidence

1. Keep deterministic namespace and content-substitution tests in required CI.
2. Run at least 500 bounded Linux worker race and fault iterations. Keep separate repeated in-process materializer stress on native Linux, macOS, and Windows schedules.
3. Require the Linux worker to fail opening an unrelated sentinel, creating a sibling beside the stage, or publishing the final destination.
4. Keep macOS and Windows parser, identity, and materialization gates green while reporting process isolation unavailable on those platforms.

### Alpha.6 exit gate

- Isolation is installed before the worker receives the source or performs its first format-dependent archive read. Supervisor-owned private snapshot copy and hashing happen earlier by design.
- Only the documented descriptors survive worker startup.
- The worker cannot read the sentinel, create outside the stage, or publish.
- No worker or descendant retains writable stage authority when audit begins.
- The supervisor rejects every missing, extra, linked, replaced, size-mismatched, or digest-mismatched staged object.
- At least 500 bounded hostile Linux worker iterations complete with zero outside writes and zero destination replacement, while the native in-process materializer stress remains green on all three platforms.
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

Stable crate and native-binary distribution remain explicit later gates. Before 1.0, every published crate must package its README and Apache-2.0 license and required CI must inspect the exact package file list. Native archives must name a minimum OS, kernel, and libc or deployment ABI and must be smoke-tested on that floor; green builds on mutable `*-latest` runners alone do not establish a support range.

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
