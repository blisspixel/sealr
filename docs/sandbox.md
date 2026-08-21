# Sandboxing and confined views

> Target design. No kernel sandbox is implemented yet; current receipts report `kernel_jail: unavailable`. Phase 0.1 introduces a process-owned Linux worker so isolation begins before header parsing without unexpectedly sandboxing a library caller.

Landlock-first is part of [now.md](now.md) §2: drop ambient authority **before** interpreting the archive. The InspectableView (`--mount`) is a representation of the return type, not a substitute for the jail.

The engine MUST be correct **without** a kernel jail (invariants are not “hope Landlock is on”). The engine MUST also be usable **inside** a jail.

Reduced authority is **how the process starts**, not a hardening pass you remember later. On Linux, the supervisor opens the archive and destination parent, creates and retains the private stage, then passes only the archive and stage descriptors to the worker. The worker validates the bounded control frame, installs `no_new_privs` and Landlock, closes the control channel, and only then reads the first archive byte. The worker never receives the destination parent or final name and cannot publish. If Landlock is unavailable, userspace I1 still runs in explicitly reported degraded mode; that execution does not satisfy the reduced-authority release gate.

## Composition

```
host policy engine
    └─ drop ambient authority (Landlock / AppContainer / Seatbelt)
    └─ sealr inspect     (no write; enough for many agent turns)
    └─ sealr mount       (ProjFS / FUSE view; hydrate on read)
    └─ sealr materialize (into the already-jailed dest)
```

Inspect-without-write is the first agent API. Mount is the “explore without promoting files.” Materialize is the promotion step, still jailed.

## Linux

- **Landlock** is real and unprivileged. **Probe the running kernel ABI** and construct the handled-rights set from the rights that ABI actually supports. Grant the stage only the file and directory rights required for materialization. Existing archive and stage descriptors retain their descriptor authority, so the receipt must distinguish inherited descriptor access from path grants.
- **seccomp-bpf** is deferred until syscall traces cover Store, Deflate, rejection, cleanup, worker crash, and publication handoff. Seccomp is not a replacement for Landlock or userspace invariants, and an architecture-sensitive allowlist must not be guessed.
- **sandlock, landstrip, ai-jail, ferroday-cage** exist as of 2026. None is an extract engine. Do not vendor them. Implement via `landlock` crate + `seccompiler`.
- **ouch** now Landlocks and has `--no-sandbox`. We do **not** copy a boolean off switch. If Landlock is unavailable, say so on the receipt; the userspace jail still runs.
- **bubblewrap** / **Firecracker** / **gVisor**: for *callers* (CI, agent runners). Document a unit file / example; do not vendor a VMM.

## macOS

- Seatbelt / `sandbox-exec` profiles are still the lightweight knob; they are brittle and deprecated-feeling. Ship a profile example; do not require it.
- FSKit / FUSE-T for mount later.

## Windows

- Landlock does not exist. Use **AppContainer** / job objects for process confinement when we spawn; **ProjFS** for the view ([bigger.md](bigger.md)).
- MOTW (`Zone.Identifier`) on materialized files - NanaZip-class hygiene.

## Mount vs sandbox

Mount (ProjFS/FUSE) is a **destination**, not a jail. A malicious agent can still `copyfile` out of the mount. Combine: mount **and** Landlock so the agent process can only see the mount + a scratch dir.

Copy-on-write overlay (BranchFS-class, overlayfs, Windows overlay) is Phase 2: agent writes stay in the overlay until an explicit promote.

## What we will not do

- Claim Firecracker is the default.
- Make correctness depend on seccomp (fuzzing would then miss host bugs).
- Ship a custom LSM.
