# Reduced-authority execution

> Target design with repository-only conformance slices. The shipped library and CLI still have no process sandbox, worker execution path, mount command, or projected filesystem. Current receipts report `kernel_jail: unavailable`, and the parser, verifier, and materializer still run in the caller's process.

Reduced authority follows the semantic-identity work in Roadmap Step 4. Any public worker path must preserve the canonical `ArchiveIR`, the retained snapshot relationship, and the bounded `VerifiedArchive` capability; it must not create a CLI-only second meaning. Protocol v1 does not yet carry enough information to do that.

The [near-term plan](near-term.md) made the private file-backed `SourceSnapshot` a prerequisite, and that capability has landed. [Worker protocol v1](worker-protocol.md) now defines bounded control and reduced result frames. The first Alpha.6 executable slice is a separate nonsemantic authority bootstrap: pair source and optional stage roles with out-of-band descriptors, validate and close authority, install restrictions before source access, report readiness, then exit and reap without interpreting an archive. This measures the process boundary without forcing v1 into the public semantic API.

The next executable representation slice has also landed as a dormant [private semantic record](semantic-record.md). It binds planning IR and completion verification state without starting a worker or receiving a descriptor. A source-owning in-process inspect executor can now consume an accepted Ready plan and emit its canonical completion while reading only planned payload ranges and never invoking the structural parser. Transporting that plan and completion across this sandbox boundary remains future work and requires immutable sealed-blob evidence, clean worker exit and reap, and the same fail-closed distinction between lifecycle failure and archive semantics.

Correctness cannot depend on a kernel sandbox. Path, structure, quota, codec, content, and publication invariants remain mandatory. Process confinement reduces the authority available if that logic is compromised.

## Current bootstrap evidence

`sealr-worker-bootstrap-lab` is a non-published workspace tool and is absent from native release archives. It uses a private 96-byte protocol over `SOCK_SEQPACKET`, passes descriptors with `SCM_RIGHTS`, distinguishes short data, `MSG_TRUNC`, and `MSG_CTRUNC`, and receives descriptors close-on-exec. A minimal pre-exec hook marks unrelated descriptors close-on-exec. The child is bound to its expected parent, verifies the Unix sequenced-packet control peer and credential settings, duplicates a harmless control descriptor after exec, and proves that child-entry `close_range(CLOSE_RANGE_UNSHARE)` closes it. Standard input remains the control channel; standard output and error stay attached to inert `/dev/null` objects so capabilities cannot reuse those conventional descriptor numbers.

The optional synthetic stage arrives first. After validating its identity, owner, mode, and type, the child directly queries the running Landlock ABI, rejects a value below 3, sets `no_new_privs`, handles every filesystem right in the fixed ABI 3 policy, and grants only `WRITE_FILE`, `MAKE_DIR`, and `MAKE_REG` beneath that stage. It then reports correlated readiness. The synthetic read-only source is transferred only after the supervisor observes readiness, so the child cannot read source content before restriction because it does not possess the source capability. The supervisor also observes the exact child descriptor set through procfs while the child is paused.

The conformance command exercises source-only and staged success, outside and sibling denial, stage-local creation, writable and nonregular sources, wrong lengths and identities, missing or injected authority, operation mismatch, extra source descriptors, deterministic ABI-floor and ABI-probe failure, and exact source-phase short-data, `MSG_TRUNC`, and `MSG_CTRUNC` cases. Seventeen point-specific abrupt exits span exec entry through exit acknowledgement. Each proves the expected exit code, bounded reap, unchanged source and outside sentinel, phase-appropriate stage state, cleanup only after reap, and an absent fixture root. A separate deadline kills and reaps through pidfd. The parent observes source and stage descriptor identity and access state while the child is paused. Required Linux CI runs this command in the existing `CI` workflow:

```text
cargo run --locked --release -p sealr-worker-bootstrap-lab -- conformance
```

This evidence is not an archive receipt and does not show that parsing ran confined. The lab has no archive-parser dependency, changes no public API or CLI command, and does not use operation protocol v1. Deterministic restriction injections prove supervisor lifecycle behavior, not operation on a real ABI 2 or disabled-Landlock kernel. The lab does not prevent child process creation, permission or ACL mutation, networking, IPC, CPU or memory exhaustion, or same-user interference. Unknown ancillary headers are filtered by the current rustix iterator, so the lab does not claim exhaustive unknown-control rejection. The separate semantic executor is still in-process and never enters this lab. No-descendant control, permission mutation control, repeated fault stress, sealed plan transport, writer quiescence, stage audit, and supervisor-owned publication remain required before the shipped product can claim reduced-authority execution.

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

Protocol v1 is only the bounded transport foundation for this split. It does not carry a complete `ArchiveIR`, snapshot ownership, later verified-read authority, or independent interpretation, admission, verification, effect, and lifecycle axes. Its request-bound validator enforces returned profile and resource claims but cannot bind source or policy fields that the result does not echo. The [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) accepts only a private split-phase semantic-record experiment now. Local IR, retained-content transfer, isolated non-retained reads, materializing-writer quiescence, and helper packaging have separate rules. A complete record is not automatically an independently checkable certificate, so the worker remains in the semantic trusted computing base for every source-to-record fact the supervisor does not recompute.

## Linux first

Linux is the first planned enforced worker platform. The worker will set `no_new_privs`, probe the running Landlock ABI, request only rights supported by that ABI, and grant only the stage operations required by the selected effect. The Phase 0.1 Linux release gate requires a capability floor that includes `REFER` and `TRUNCATE`, currently Landlock ABI 3. A weaker kernel may report isolation unavailable, but it cannot satisfy the enforced-worker gate.

Descriptor authority and path grants are different facts. Landlock does not revoke authority already available through inherited open descriptors, so worker startup must close everything except the bounded control channel, read-only source snapshot, and stage capabilities. The receipt lists those inherited authorities separately from handled pathname rights.

Landlock network controls vary by ABI and do not justify a blanket no-network claim. The worker does not need network access, but network and syscall confinement are recorded separately. Landlock restrictions and writable descriptors are inherited by descendants, so returning a result does not make the stage stable. Alpha.6 must prevent process and thread creation before archive interpretation, or use an equivalently proven supervisor-owned process boundary, then prove writer quiescence before audit. A broader seccomp allowlist remains deferred until the real syscall surface is measured.

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
