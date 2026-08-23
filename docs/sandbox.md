# Reduced-authority execution

> Target design. Alpha.4 has no process sandbox, worker process, mount command, or projected filesystem. Current receipts report `kernel_jail: unavailable`. The current parser, verifier, and materializer run in the caller's process.

Reduced authority follows the semantic-identity work in Roadmap Step 4. The worker protocol and supervisor audit must consume the canonical `ArchiveIR`; they must not create another interpretation or manifest format.

The [near-term plan](near-term.md) made the private file-backed `SourceSnapshot` a prerequisite, and that first capability has landed. The worker must receive its retained read-only handle and a bounded control frame, never the archive as an in-memory protocol payload. This keeps source immutability, memory limits, and process authority on one design path.

Correctness cannot depend on a kernel sandbox. Path, structure, quota, codec, content, and publication invariants remain mandatory. Process confinement reduces the authority available if that logic is compromised.

## Target supervisor and worker

The trusted supervisor will:

1. acquire the immutable archive snapshot;
2. open and retain the destination parent;
3. create and retain the private stage;
4. start a same-binary worker with only bounded archive and stage capabilities;
5. retain the final destination name and all publication authority;
6. treat the worker result as untrusted;
7. audit the staged tree against the admitted IR;
8. publish without replacement or clean up and report failure.

The worker will:

1. validate a bounded, versioned control frame;
2. install the platform restriction before reading the first archive byte;
3. close unnecessary control and inherited handles;
4. interpret, verify, and write only through its archive and stage capabilities;
5. return a bounded result and member manifest;
6. never receive the destination parent, final name, recovery key, or publication authority.

## Linux first

Linux is the first planned enforced worker platform. The worker will set `no_new_privs`, probe the running Landlock ABI, request only rights supported by that ABI, and grant only the stage operations required by the selected effect. The Phase 0.1 Linux release gate requires a capability floor that includes `REFER` and `TRUNCATE`, currently Landlock ABI 3. A weaker kernel may report isolation unavailable, but it cannot satisfy the enforced-worker gate.

Descriptor authority and path grants are different facts. Landlock does not revoke authority already available through inherited open descriptors, so worker startup must close everything except the bounded control channel, read-only source snapshot, and stage capabilities. The receipt lists those inherited authorities separately from handled pathname rights.

Landlock network controls vary by ABI and do not justify a blanket no-network claim. The worker does not need network access, but network and syscall confinement are recorded separately. Seccomp remains deferred until the real syscall surface is measured.

Landlock setup failure or insufficient handled rights cannot satisfy the reduced-authority release gate. A future explicit degraded mode may still rely on userspace invariants, but its receipt and exit behavior must not look equivalent to enforced isolation.

Native syscall traces must cover Store, Deflate, rejection, cleanup, worker crash, and publication handoff before an architecture-sensitive seccomp allowlist is proposed.

## macOS and Windows

Alpha.4 keeps native macOS and Windows materialization gates, but no worker containment claim exists on either platform.

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
