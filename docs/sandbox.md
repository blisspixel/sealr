# Reduced-authority execution

> Target design with repository-only conformance slices. The shipped library and CLI still have no process sandbox, worker execution path, mount command, or projected filesystem. Current receipts report `kernel_jail: unavailable`, and the parser, verifier, and materializer still run in the caller's process.

Reduced authority follows the semantic-identity work in Roadmap Step 4. Any public worker path must preserve the canonical `ArchiveIR`, the retained snapshot relationship, and the bounded `VerifiedArchive` capability; it must not create a CLI-only second meaning. Protocol v1 does not yet carry enough information to do that.

The [near-term plan](near-term.md) made the private file-backed `SourceSnapshot` a prerequisite, and that capability has landed. [Worker protocol v1](worker-protocol.md) now defines bounded control and reduced result frames. The first Alpha.6 executable slice was a separate nonsemantic authority bootstrap: pair source and optional stage roles with out-of-band descriptors, validate and close authority, install restrictions before source access, report readiness, then exit and reap without interpreting an archive. This measured the process boundary without forcing v1 into the public semantic API; the later sealed semantic bridge remains separate from protocol v1.

The executable representation slice has landed as dormant [private semantic records](semantic-record.md). It binds planning IR, completion verification state, and supervisor-selected retention without changing a shipped path. A feature-gated repository bridge carries the canonical plan through an immutable sealed memfd, binds it to the restricted worker's exact file-backed snapshot, executes only planned Store and Deflate payload ranges without invoking the structural parser, and captures selected bytes through those verifier calls. It returns the canonical completion and retained-content bundle through separately sealed memfds. The source and handoff descriptors remain live through worker observation, exit, and reap. The supervisor first treats both outputs as untrusted proposals, then replays the accepted plan against its retained exact source and requires byte-for-byte canonical agreement. This preserves the fail-closed distinction between lifecycle failure and archive semantics without activating public behavior.

Correctness cannot depend on a kernel sandbox. Path, structure, quota, codec, content, and publication invariants remain mandatory. Process confinement reduces the authority available if that logic is compromised.

## Current bootstrap evidence

`sealr-worker-bootstrap-lab` is a non-published workspace tool and is absent from native release archives. It uses a private 96-byte protocol over `SOCK_SEQPACKET` and a raw `recvmsg` path that validates every returned `cmsghdr` with Linux `CMSG_ALIGN` rules. It accepts exactly one `SCM_RIGHTS` record, rejects unknown, malformed, and multiple-rights control records, distinguishes short data, `MSG_TRUNC`, and `MSG_CTRUNC`, and receives descriptors close-on-exec. Every complete installed descriptor is owned before an ancillary or framing rejection can return. A minimal pre-exec hook marks unrelated descriptors close-on-exec. The child is bound to its expected parent, verifies the Unix sequenced-packet control peer and credential settings, duplicates a harmless control descriptor after exec, and proves that child-entry `close_range(CLOSE_RANGE_UNSHARE)` closes it. Standard input remains the control channel; standard output and error stay attached to inert `/dev/null` objects so capabilities cannot reuse those conventional descriptor numbers.

The optional stage arrives first. After validating its identity, owner, mode, and type, the child directly queries the running Landlock ABI, rejects a value below 3, sets `no_new_privs`, and handles every filesystem right in the fixed ABI 3 policy. The synthetic stage-probe route grants only `WRITE_FILE`, `MAKE_DIR`, and `MAKE_REG`; the materialize route adds `READ_DIR` so the shared component writer can traverse its own newly created directories. On the required x86_64 Linux runner the child then installs a classic seccomp-BPF filter with thread synchronization. The filter kills a wrong audit architecture or x32 syscall entry and returns `EPERM` for process and thread creation, execution, namespace changes, permission and ownership mutation, extended-attribute mutation, and `ioctl`. Safe direct probes exercise representative syscalls and stage mutations before readiness. The synthetic read-only source is transferred only after the supervisor observes correlated readiness, one thread, `NoNewPrivs: 1`, seccomp filter mode, at least one installed filter, and the exact child descriptor set through procfs.

The conformance command exercises source-only and staged success, outside and sibling denial, stage-local creation, writable and nonregular sources, wrong lengths and identities, missing or injected authority, operation mismatch, extra source descriptors, deterministic ABI-floor, ABI-probe, and seccomp-installation failure, exact source-phase short-data, `MSG_TRUNC`, and `MSG_CTRUNC` cases, and a kernel-generated timestamp header that must be rejected as unknown ancillary. Unit regressions additionally prove that descriptors installed with rejected short, truncated, unknown, malformed, and multiple-rights control data are closed. Canonical semantic planning, completion, retained-content, and member-read request records cross in bounded `SLRBLOB1` memfds with required write, grow, shrink, and seal seals. The receiver checks descriptor type and access, the caller-declared and envelope lengths, role, reserved fields, the 64 MiB payload cap, independently recomputed SHA-256, and exact operation, source, request, profile, policy, resource, target, consumer, effect, retention, and plan binding. Missing seals, declared-length drift, operation drift, and role confusion are rejected through the process boundary. The deterministic ZIP fixture includes Store and Deflate members; inspect execution invokes no structural parser and verifies exactly two planned payloads. A separate one-shot boundary reserves and reads each selected verified member through a fresh restricted worker, no stage or destination authority, and one write-only pipe. It covers exact and one-under caller limits, pre-spawn, queued, and active cancellation, post-result crash isolation, next-call recovery, 64 alternating Store and Deflate reads, and last-owner cleanup. A private writer route receives only a supervisor-created stage root, the exact source, and a sealed materialization plan. It shares the production component writer and verifier, returns a sealed completion proposal, closes through clean exit and exact reap, and only then permits retained-source replay, exact stage audit, and supervisor-only no-replace publication. Targeted writer evidence covers post-reap mutation, destination appearance, cleanup failure, four crash barriers, and two stalls. The seccomp deny set now also closes rename, link, unlink, symlink, device creation, mount, truncate, and new socket paths before source transfer. Twenty-two point-specific abrupt exits span exec entry through exit acknowledgement on the original path, including plan receive, validation, acceptance, and completion sealing. Eleven stalls add plan receive and acceptance to the earlier pre-bootstrap through post-ack sequence. The supervisor control endpoint is nonblocking; one absolute monotonic deadline covers each complete send-and-response round while `poll` observes both the socket and pidfd. Expiry kills through the pidfd. Every abrupt exit and stall proves its exact classification, bounded reap, unchanged source and outside sentinel, phase-appropriate stage state, cleanup only after reap, and an absent fixture root. One required 500-iteration campaign cycles the closed 44-case bootstrap matrix, and a separate 500-iteration campaign alternates writer publication, audit mutation, destination race, cleanup failure, pre-result crash, and post-result crash. After every iteration each campaign requires an empty supervisor child list, the baseline supervisor descriptor count, exact retained source identity and bytes, an unchanged outside sentinel, and checked cleanup. The parent observes exact stage, source, sealed-plan, and sealed-completion descriptor identity and access state while the child is paused. Required Linux CI runs this command in the existing `CI` workflow:

```text
cargo run --locked --release -p sealr-worker-bootstrap-lab -- conformance
```

This evidence is not an archive receipt and does not show that structural parsing ran confined: the trusted supervisor still authors the plan before transfer. The lab depends on `sealr` only through a feature-gated repository seam, changes no default library surface or CLI command, and does not use operation protocol v1. Deterministic restriction injections prove supervisor lifecycle behavior, not operation on a real ABI 2, disabled-Landlock, or seccomp-disabled kernel. The filter is a measured deny set, not a complete syscall allowlist. It denies creation of new network sockets and connection entry, but the lab does not claim general IPC, CPU or memory containment, or same-user interference resistance, and its seccomp filter currently fails closed outside x86_64 Linux. The bootstrap and writer campaigns repeat deterministic lifecycle schedules, not the 64 read-specific calls, every possible native race, or a near-ceiling retained-transfer or read resource measurement. Proposal validation alone does not prove content digests; retained-source replay closes that lab gate while deliberately reusing the bounded verifier implementation. Active read cancellation is proved at one deterministic probe stall, not every protocol epoch. Public capability integration, real kernel setup-failure evidence, and helper packaging remain required before the shipped product can claim reduced-authority execution.

## Target supervisor and worker

The trusted supervisor will:

1. acquire the immutable archive snapshot;
2. open and retain the destination parent;
3. create and retain the private stage;
4. start a same-binary worker with only bounded archive and stage capabilities;
5. retain the final destination name and all publication authority;
6. treat the worker result as untrusted;
7. terminate and reap the worker boundary and prove that no descendant retains writable stage authority;
8. validate the chosen complete semantic evidence and audit the staged tree;
9. publish without replacement or clean up and report failure.

The worker will:

1. validate a bounded, versioned control frame;
2. install the platform restriction before reading the first archive byte;
3. close unnecessary control and inherited handles;
4. interpret, verify, and write only through its archive and stage capabilities;
5. return the bounded private handoff required by the semantic-ownership decision;
6. never receive the destination parent, final name, recovery key, or publication authority.

Protocol v1 is only the bounded transport foundation for this split. It does not carry a complete `ArchiveIR`, snapshot ownership, later verified-read authority, or independent interpretation, admission, verification, effect, and lifecycle axes. Its request-bound validator enforces returned profile and resource claims but cannot bind source or policy fields that the result does not echo. The [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) accepts only private split-phase semantic and one-shot read experiments now. Local IR construction, public later-read integration, materializing-writer quiescence, and helper packaging have separate rules. A complete record is not automatically an independently checkable certificate, so the worker remains in the semantic trusted computing base for every source-to-record fact the supervisor does not recompute.

## Linux first

Linux is the first planned enforced worker platform. The bootstrap lab now sets `no_new_privs`, probes the running Landlock ABI, requires its fixed ABI 3 rights set, grants only the measured synthetic-stage operations, and installs its architecture-checked seccomp deny set before source transfer. The Phase 0.1 Linux release gate requires a Landlock capability floor that includes `REFER` and `TRUNCATE`, currently ABI 3. A weaker kernel may report isolation unavailable, but it cannot satisfy the enforced-worker gate.

Descriptor authority and path grants are different facts. Landlock does not revoke authority already available through inherited open descriptors, so worker startup must close everything except the bounded control channel, read-only source snapshot, and stage capabilities. The receipt lists those inherited authorities separately from handled pathname rights.

Landlock network controls vary by ABI and do not justify a blanket no-network claim. The worker does not need network access, so the measured x86_64 filter denies new socket, socketpair, connect, bind, listen, and accept paths before source transfer while preserving the already authenticated control socket. Network and syscall confinement remain recorded separately. The filter also prevents process and thread creation and denies permission mutation, rename, link, unlink, symlink, device creation, mount, and truncate operations. The private writer lab now proves clean exit and exact reap before completion validation, source replay, stage audit, cleanup, or supervisor-only publication. A complete syscall allowlist remains deferred until the public parser and writer surface is measured.

Landlock setup failure or insufficient handled rights cannot satisfy the reduced-authority release gate. A future explicit degraded mode may still rely on userspace invariants, but its receipt and exit behavior must not look equivalent to enforced isolation.

Native syscall traces must cover Store, Deflate, rejection, cleanup, worker crash, and publication handoff before an architecture-sensitive seccomp allowlist is proposed.

## macOS and Windows

Alpha.5 keeps native macOS and Windows materialization gates, but no worker containment claim exists on either platform.

A future macOS worker needs a supported packaging and restriction mechanism with native tests. A future Windows worker must evaluate AppContainer, restricted-token, job-object, handle-inheritance, and filesystem ACL behavior together. Neither platform will inherit a Linux claim by analogy.

Until those boundaries exist, receipts report process isolation unavailable while native parser, materializer, and semantic determinism tests remain mandatory.

## Projection is separate

A future read-only projection is a representation of the admitted tree, not a sandbox. It may reduce eager writes and expose a verification frontier, but it does not prevent a caller from copying observed bytes elsewhere. Projection follows the common IR, immutable snapshot, cache identity, and worker design; no platform-specific mount is on the active implementation queue.

## Evidence

The target receipt distinguishes:

- in-process and worker modes;
- restriction requested, enforced, unavailable, or setup-failed;
- platform and Landlock ABI where applicable;
- handled and granted rights;
- inherited archive and stage descriptor authority;
- worker exit and protocol status;
- staged-tree audit outcome;
- supervisor-owned publication and cleanup outcome.

These fields remain evidence about the control path. Authentication requires the later canonical evidence and signing work.

## Explicit nonclaims

- A worker does not contain root, administrators, SYSTEM, kernel or filter drivers, debug or handle-duplication privilege, or another process running under the same unrestricted principal.
- Landlock does not constrain a separate same-user process.
- Projection does not provide process confinement.
- Seccomp does not replace filesystem containment.
- A library call will not unexpectedly sandbox its caller.

See [architecture.md](architecture.md#reduced-authority-worker), [threat-model.md](threat-model.md), and [ROADMAP.md](../ROADMAP.md#4-start-parsing-and-writing-in-reduced-authority).
