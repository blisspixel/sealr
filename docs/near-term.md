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

Authority closure and the remaining semantic-assurance work can proceed in parallel. The bounded shadow-parity prerequisite, shared owning planner, plan-native inspect executor, sealed transport, measured isolated plan consumption, supervisor-owned exact-byte replay, and immutable original-pass retained-content transfer are now clean. The next bridge must provide caller-bounded non-retained reads through an isolated backend with explicit clone, cancellation, crash, and last-owner behavior.

1. **Close dormant semantic assurance.** **Allocation, ownership, bounded shadow parity, shared planning, and near-limit completion measurement landed:** input-sized validation is fallible or allocation-free; invalid completion decode materializes no IR; accepted decode materializes one fallibly reconstructed IR; findings move instead of cloning; and a deterministic failpoint walk covers every reconstruction reservation. A required isolated-child probe pins a 67,041,104-byte plan and enforces that completion reconstruction adds less than 1 MiB transient requested heap above its one logical output. The frozen 12-case v1 artifact and 12 additive v2 cases pin exact bounded evidence from the production-compiled owning planner, the plan-native completion boundary, and the explicitly labeled supervisor-reproduction oracle. Their apply oracle intentionally runs a separate complete public operation for differential comparison. Clean exact-main on-demand fuzz evidence is in the [assurance ledger](assurance.md#current-evidence). Parity beyond these named fixtures, the first scheduled-event run, and accumulated scheduled history remain open.
2. **Close the pre-parser Linux authority gate.** **No-descendant, permission-mutation, raw ancillary, authority-epoch deadline, repeated-stress, sealed-blob, and isolated inspect controls landed:** the x86_64 bootstrap installs an architecture-checked `TSYNC` seccomp-BPF deny set after Landlock and before source transfer, directly probes representative denial, and exposes filter readiness for supervisor observation. Its raw `recvmsg` path validates every returned control header, accepts exactly one `SCM_RIGHTS` record, rejects kernel-generated unknown ancillary, malformed layouts, and multiple rights records, and owns installed descriptors before reporting any framing error. The nonblocking supervisor shares one absolute monotonic deadline across each send-and-response round, polls the control socket and pidfd, and proves pidfd kill and reap before cleanup for eleven stalls across four authority epochs. Canonical semantic plan and completion records cross through bounded kernel-sealed memfds with required seals, exact length, independent SHA-256 verification, binding, descriptor, and malformed-plan evidence. The restricted worker validates the plan against its exact file-backed source and executes planned Store and Deflate ranges without structural reparse. A required 500-iteration Linux campaign cycles the 44-case non-stall matrix at least 11 times per case and checks no surviving child, descriptor-count growth, source or outside-sentinel change, or cleanup before reap. Destination-replacement evidence belongs to later supervisor-owned publication because this inspect lab deliberately has no destination authority.
3. **Extract a crate-private inspect-only validated-plan executor.** **Landed:** the non-cloneable executor consumes each accepted Ready inspect plan value bound to its exact snapshot, rejects materialization, and reuses one shared Store and Deflate verifier across `apply`, later verified-member reads, and plan execution. A present bounded retention plan now captures selected bytes through that same execution pass and produces a canonical transfer bundle. The direct plan-native path performs one structural parse and no payload verification before Ready; execution adds no structural parse. The frozen differential harness separately runs public `apply()` as its oracle, so it deliberately repeats work outside the production path. Structural-range poison remains unread, and every execution read stays within a planned payload range, including ignored-extra geometry. Complete and stopped parity covers Store, Deflate, CRC with a trailing Pending member, both declared-size-lie boundaries, codec failures, and injected source I/O before and after a verified prefix. Member, ratio, and total-budget cases pass at the exact cap and remain planning-terminal one byte or one ratio unit below it; they cannot be forged as execution failures. The additive v2 artifact extends the frozen v1 projection across named strict-v2, backend, profile, topology, covering, and resource boundaries without claiming broad parity. Destination setup still precedes independently bad payload verification. Destination effects, publication, later reads, public `VerifiedArchive` construction, and activation remain out of scope.

Together, these increments freeze what the worker may mean, what authority it may hold, and the narrow plan-native entry point for a later sealed inspect-only worker bridge.

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
4. Pin fuzz tool versions and toolchains, record resource limits and seed-manifest digests, and promote every reproducible crash into a deterministic regression. **Landed for the protocol target:** required CI verifies exact tool, seed, dictionary, time, input, timeout, memory, job, and artifact-retention configuration. The bounded AddressSanitizer workflow is scheduled weekly and supports on-demand runs. Clean on-demand evidence exists; the first scheduled-event run remains pending.

### Alpha.5 exit gate

**Status: complete on current main.** The snapshot, mutation, backend-parity, required resource, scheduled multi-gigabyte, bounded protocol, deterministic malformed-frame, bounded fuzz-configuration, and exact-commit on-demand AddressSanitizer gates have passed. Release promotion requires both exact-main CI and exact-commit on-demand fuzz evidence. Scheduled-event fuzz history remains an assurance-program gate, not an Alpha.5 release claim.

- Resident memory is bounded independently of accepted archive size.
- Interpretation and payload verification cannot observe different source versions.
- A large valid fixture is inspected through checked random access without whole-archive allocation.
- Snapshot implementations agree on semantic outputs and identities.
- Protocol decoders reject malformed, oversized, truncated, and count-inconsistent frames before effect.
- The scheduled fuzz workflow has explicit time, memory, input, and output bounds, and the required on-demand campaign has no unresolved reproducible crash.

## Alpha.6: reduced-authority Linux execution

Alpha.6 builds toward giving a compromised parser materially less ambient authority without changing the public semantic and verified-capability contract. Early slices are repository-only evidence. No worker result may shape `Outcome` or `VerifiedArchive` until semantic parity, content authority, lifecycle integration, later-read behavior, and helper packaging close together.

### 1. Linux authority bootstrap

**Current status: authority and lifecycle conformance slices landed.** This remains a non-published tool, not a runtime path in `sealr` or `sealr-cli`.

1. A separately versioned 96-byte bootstrap exchange drives a same-binary Linux child over `SOCK_SEQPACKET`. Operation protocol v1 remains byte-compatible and non-runtime.
2. A pre-exec `close_range(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)` prevents unrelated inherited descriptors from crossing exec without interfering with the spawn error channel. At child entry, the process retains the control socket plus inert `/dev/null` output streams and repeats closure for descriptors 3 and above. A deliberate post-exec duplicate proves that the second layer closes authority independently of close-on-exec. The child then receives an optional private stage through one bounded `SCM_RIGHTS` packet. Transport validates exact counts and close-on-exec state; stage validation binds directory type, device, inode, effective owner, private mode, and read-only descriptor access, while source validation binds regular-file type, read-only access, length, device, and inode.
3. The child directly queries the running Landlock ABI, rejects a floor below ABI 3, sets and verifies `no_new_privs`, hard-requires the complete fixed ABI 3 filesystem-rights set, and grants a synthetic stage only `WRITE_FILE`, `MAKE_DIR`, and `MAKE_REG`. On x86_64 it then installs a `TSYNC` seccomp-BPF deny set with audit-architecture and x32 checks. Direct safe probes require `EPERM` for process creation, execution, namespace changes, permission and ownership mutation, xattrs, and `ioctl`. It sends correlated readiness before it owns any source descriptor. Deterministic ABI-2, ABI-probe, and seccomp-installation failure modes prove the correlated fail-closed lifecycle but do not substitute for real kernel success probes.
4. The supervisor observes one thread, `NoNewPrivs: 1`, seccomp filter mode, at least one installed filter, inert output streams, and the exact control-plus-optional-stage descriptor set through `/proc/<pid>`. A deliberately inheritable sentinel object must be absent. After source acceptance, a second paused observation binds exact source and stage object identities and access modes to the supervisor-retained descriptors.
5. Only after readiness does the supervisor transfer a read-only, unlinked deterministic ZIP snapshot with exact length, device, and inode binding. The child proves the existing source capability remains readable, validates the canonical semantic plan against that exact file-backed snapshot, verifies planned Store and Deflate payloads, proves an unrelated or sibling path is denied, and creates a stage-local probe when staged authority was granted.
6. The supervisor makes its control endpoint nonblocking and assigns one absolute monotonic deadline to each bootstrap-to-ready, source-transfer, probe-execution, and worker-exit round. Each readiness wait polls both the control socket and pidfd, retries only `EAGAIN`, kills through the pidfd on expiry, reaps before fixture cleanup, and treats every response as untrusted. All post-spawn errors converge on the same bounded termination path. Native conformance covers inspect and stage success; writable, nonregular, missing, injected, and identity-drifted descriptors; operation drift; extra source authority; exact short, `MSG_TRUNC`, and `MSG_CTRUNC` source packets; three deterministic restriction failures; 18 point-specific abrupt exits; nine stalls spanning pre-bootstrap receive through post-ack exit; and bounded timeout termination. Every abrupt-exit and stall case checks source and outside-sentinel integrity, expected stage state, proved reap, checked cleanup, and root absence.

The deterministic pre-parser closure now includes repeated fault stress and bounded sealed-blob mechanics. Each of 44 non-stall cases runs at least 11 times in the required 500-iteration campaign, with no surviving child PID or supervisor descriptor-count growth after any iteration. Exact source and outside-sentinel state is checked before every cleanup. Real kernel setup-failure evidence remains open because deterministic injections cannot supply it. The measured seccomp deny set closes no-descendant and stage-permission-mutation authority in the x86_64 lab, but it is not a complete syscall allowlist or a network-containment claim.

### 2. Consumer-preserving semantic ownership

**Current status: shared owning planner, dormant records, hostile decoders, source-binding hardening, input-sized allocation fallibility, single-materialization completion reconstruction, a required near-limit peak-live probe, an immutable 12-case v1 shadow baseline plus 12 additive v2 cases, a source-owning inspect executor, a sealed isolated Linux bridge, supervisor-owned exact-byte replay, immutable original-pass retained-content transfer, and a dedicated fuzz surface with clean exact-main on-demand evidence landed.** The v2 additions declare apply, backend, or supervisor-reproduction ownership for each observation and cover mixed strict-v2, same-byte profile behavior, exact memory/private-file frames, topology, covering, and quota boundaries. The repository bridge validates the full record against the exact worker source and executes planned Store and Deflate ranges without structural reparse. Selected bytes are captured in that pass and transferred in a canonical operation-, plan-, and completion-bound sealed bundle. After reap, the supervisor re-executes the accepted plan against its retained exact source and requires completion and retention bundles to match byte for byte. This establishes bounded isolated plan consumption, source-derived content authority, and retained transfer plus a reproducible search surface, not scheduled stability, broad profile or policy parity, complete `VerifiedArchive`, isolated later reads, or runtime-worker parity.

1. Treat operation protocol v1 as a bounded transport foundation, not a frozen worker contract. It carries a reduced manifest but no complete `ArchiveIR`, ranges, independent public outcome axes, or authority for later `VerifiedArchive` reads.
2. Implement the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) as private split-phase planning and completion records. Keep `ArchiveIR` construction crate-private and bind each record to the exact source, request, profile, policy, resources, target, consumer, effect request, retention plan, operation, and preceding record. **Dormant codec, source-binding, and allocation slices landed:** the [private semantic-record experiment](semantic-record.md) binds those fields under independent magic, exact body consumption, a 64 MiB encoded-length ceiling checked before buffer-growth requests and copies, domain-separated request and plan IDs, and typed hostile-decode errors. Decode also binds the supervisor-owned snapshot, applies its expected-binding-validated path depth before owned component allocation, uses allocation-free ASCII-fold topology comparison with order-independent ancestor lookup and a fixed extra-ID set, reserves input-sized covering and path scratch fallibly, reproduces accepted or rejected covering evidence without cloning diagnostic labels, checks represented LFH, CDH, descriptor, name, extra-field, and structural ranges, replays signature exclusions over comments and stored descriptor payloads, checks member-kind agreement with source external attributes, and enforces the parser-equivalent metadata aggregate. The caller policy identity remains distinct from exact compiled controls; a separate compiled-controls digest stays unavailable until its preimage is specified.
3. Preserve the current destination-setup ordering: a bounded planning record exposes a phase-local ready-for-verification disposition and IR before supervisor-owned stage setup, without freezing public axes that later verification can change. Setup failure must merge into the existing admitted, setup-failed axes with incomplete verification and no `VerifiedArchive`. A successful execution phase must consume the validated plan without structurally reparsing the source and return the final semantic axes. **Shared planning, representation, ownership, and isolated inspect slices landed:** one production-compiled, non-cloneable planning result owns the exact snapshot, pending IR, planning findings, selected profile, policy identity, and compiled controls. Ordinary `apply()` consumes it directly into retention planning, stage setup, verification, and outcome construction. The repository lab consumes a separate invocation of the same planner to author its canonical record binding; the fuzz context no longer resets a completed IR into synthetic Pending state. Planning records carry complete pending IR in central-directory order; completion carries one verification state per planned member and no structural IR on wire; semantic and canonical validation borrow the accepted plan; accepted decode drops its canonical scratch before one fallible IR reconstruction and moves findings into the result. A non-cloneable Ready inspect operation owns the exact worker source descriptor, reads only planned compressed-payload ranges, emits canonical completion bytes without invoking the structural parser, and retains the source until supervisor observation completes. No runtime path invokes the records.
4. Treat retained-content transfer, non-retained member reads, and helper packaging as separate capability gates. Borrowed IR and retained slices require local storage, while moving a complete IR alone would put later codec work back in the caller process. The first record experiment must not construct `VerifiedArchive`.
5. Preserve interpretation, admission, verification, view completeness, effect, and cleanup as separately owned facts. The worker cannot claim publication or final effect. A correlated, sealed, canonically decoded completion is still only an untrusted proposal: for files, the record can echo declared size and CRC while supplying an arbitrary content SHA-256. The regression suite proves that proposal validation accepts such a forged canonical completion. The repository lab's supervisor now rejects it by replaying the accepted plan against the retained exact source after worker reap and requiring byte-for-byte canonical agreement. This verifies the exact bytes independently of worker output, while deliberately sharing the same bounded verifier implementation. No proposal shapes public `Outcome`, `ArchiveIR`, or `VerifiedArchive`.
6. Pin record vectors for ready planning, terminal admission, terminal covering evidence, partial completion, complete completion, malformed structure, and record mutation. **Expanded deterministic and measurement slices landed:** canonical plan and completion digests, every truncation, trailing bytes, cross-kind decode, structured binding mutation, stale correlation, impossible frontiers and member-specific causes, zero materialization for invalid completion, exactly one materialization for accepted completion, a full reconstruction-allocation failpoint walk, source-order preservation, hostile finding labels, phase allowlists, range overflow, parser-oracle metadata-cap boundaries, represented fixed-field and descriptor source binding, interleaved exact and ASCII-folded file-ancestor conflicts, 257-component and normalization parity, expected-binding depth rejection before allocation, pre-growth encoded-length limits, and setup-failure merge are covered. The required isolated-child probe pins a 67,041,104-byte plan 67,760 bytes below the private cap. Its local Windows accepted Complete sample retained the 89,486,520-byte logical reconstruction with 16,752 transient bytes above it. A last-member Stopped sample with the maximum diagnostic-member label and finding detail peaked 83,367 bytes above its 89,486,480-byte logical reconstruction. Stale correlation allocated nothing, and a full-member-vector late-invalid control allocated 16,752 bytes, returned to baseline, and never materialized IR. Required release-mode CI repeats relational bounds on 64-bit Ubuntu, macOS, and Windows. The immutable `semantic-shadow-v1` manifest pins 12 exact differential cases at the shared owning plan seam and plan-native completion boundary. The additive `semantic-shadow-v2` manifest binds the exact v1 predecessor and adds 12 ordered cases for mixed strict-v2 with the allowed descriptor flag, exact memory/private-file semantic and frame equality, a same-byte strict-v1/strict-v2 ignored-extra differential with cross-profile rejection, dot-dot, exact and folded interleaved topology, exact and one-under total and ratio quotas, and a separately labeled supervisor-reproduced covering terminal. A separate semantic-record libFuzzer target exercises arbitrary bytes, input-directed mutations of runtime-generated canonical frames, decode stability, exact Ready-plan IR parity with production, correlation, and every valid record kind. Four committed driver-input seeds plus a dictionary are digest-pinned. Required verification uses parsed Cargo metadata to bind each target and hidden driver, then binds the complete scheduled workflow, including its weekly trigger and both jobs. Negative fixtures reject inert TOML remapping, manual-only drift, weakening, inactive or appended commands, inert evidence, and raw or quoted duplicate last-wins resource arguments. Clean exact-main on-demand evidence is recorded in the assurance ledger; the first scheduled-event run, accumulated history, and parity beyond the bounded projection remain open. Worker crash belongs to supervisor lifecycle evidence, alongside verification and effect failure, writer quiescence, stage audit, cleanup, publication, clone and drop behavior, retained borrows, and bounded non-retained reads.
7. Keep the library, CLI, wheel laboratory, and packaged consumer on one semantic boundary. A CLI-only reduced manifest is not sufficient to complete this increment, and no public worker mode or protocol v2 lands before retained-content, later-read, lifecycle, and packaging gates close.

The next semantic sequence is dependency-ordered. The additive v2 matrix, shared owning plan seam, x86_64 no-descendant and permission-mutation controls, raw ancillary gate, authority-epoch absolute deadlines, 500-iteration bootstrap stress, sealed handoff mechanics, Linux-only semantic inspect bridge, supervisor-owned exact-byte replay, and immutable original-pass retained-content transfer are complete without changing the frozen v1 bytes or public behavior. The worker gets no destination, later-read, receipt, or publication authority, and no proposal shapes public state. Next establish an isolated caller-bounded non-retained read backend, including clone, cancellation, crash, and last-owner behavior. Public activation still waits for the remaining lifecycle and publication gates and helper packaging.

### 3. Supervised execution and publication

1. The supervisor owns the private snapshot, destination parent, stage creation, final name, publication, cleanup, timeout, termination, reap, and any recovery secret.
2. Run the chosen semantic operation only after the bootstrap proves restriction setup. A weaker Landlock ABI may report isolation unavailable but cannot satisfy the enforced-worker gate. Do not claim complete network isolation from Landlock alone.
3. Prevent a worker descendant from retaining writable stage authority. Use a minimal measured no-process-creation control or an equivalently proven supervisor-owned process boundary before archive interpretation; a broader syscall allowlist still waits for measured traces.
4. After a bounded result arrives, terminate and reap the worker boundary and prove writer quiescence before validating the result, auditing the stage, or publishing. A returned result alone is not a stable audit boundary.
5. Recompute every independently checkable identity, then audit the exact stage for object count, kind, link and reparse state, identity, size, and SHA-256. Do not reparse ZIP merely to create a second meaning.
6. Treat restriction failure, worker crash, malformed response, timeout, quiescence failure, audit mismatch, cleanup failure, publication failure, and commit as distinct lifecycle states and compare every observed receipt with an executable finite-state model.

### Native adversarial evidence

1. Keep deterministic namespace and content-substitution tests in required CI.
2. Run at least 500 bounded Linux worker race and fault iterations. **Semantic inspect lifecycle campaign landed:** required Linux conformance cycles a closed 44-case matrix around the real sealed Store-and-Deflate bridge 500 times, with every case executed at least 11 times and per-iteration child, descriptor, retained-authority, and cleanup checks. Independently varied archive-execution races and separate repeated in-process materializer stress on native Linux, macOS, and Windows remain later gates.
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
