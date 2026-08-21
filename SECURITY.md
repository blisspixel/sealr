# Security policy

sealr treats archive interpretation and materialization as a security boundary. The project has an alpha preview line but no stable or production-supported release. Responsible reports are welcome now.

## Report a vulnerability

Do not open a public issue for an exploitable path escape, parser differential, resource-exhaustion bypass, receipt-integrity flaw, or sandbox escape.

Use [GitHub private vulnerability reporting](https://github.com/blisspixel/sealr/security/advisories/new). If that channel is unavailable, open a public issue that contains no vulnerability details and asks for a private contact channel.

Include, when possible:

- the smallest archive fixture or a deterministic generator;
- the policy id and digest;
- the observed outcome and expected finding code;
- operating system, filesystem, and tool version;
- whether inspect and materialize disagree;
- whether any path outside the requested destination was read or written.

Do not include malware or sensitive third-party data. A synthetic proof is preferred.

## Current status

There is no production-ready or stable supported version. The current limitations are listed in [README.md](README.md). The complete pinned ZipDiff construction corpus is enforced in CI. Kernel isolation, portable Unicode paths, signed receipts, ZIP64, and non-ZIP formats are not complete.

Materialization is supported on Linux, macOS, and Windows. Other platforms reject materialization with `materialize.unsupported` rather than falling back to a weaker publication primitive.

## Materialization boundary

The destination parent must already exist. sealr opens that directory as a capability, refuses an existing destination, creates a random 128-bit same-volume stage, writes members through retained no-follow component handles, and publishes only with a native no-replace operation. A missing parent is rejected and is not created as a side effect.

On Linux and macOS, the opened parent must be owned by the effective user or root. Group-writable or other-writable parents are accepted only when the sticky bit is set. A sticky directory owned by any other user is rejected because that owner can mutate its entries. Root-owned sticky directories are trusted only because root is outside the in-process adversary boundary. The created stage must be owned by the effective user and must not grant group or other permissions.

On macOS, sealr additionally queries the opened parent and stage descriptors with `acl_get_fd_np`. Any extended ACL, or an ACL query whose result cannot be established, rejects materialization with `materialize.unsafe_parent`. This closes grants that are not represented by the BSD mode bits.

On Windows, sealr first requires the retained parent to report non-remote, writable NTFS with persistent ACLs. It creates the stage relative to that handle with `NtCreateFile`, `FILE_CREATE`, reparse-point-open semantics, and a protected DACL whose owner and sole allow principal are the effective token user. It verifies that descriptor through the returned handle before member writes, retains the handle without delete sharing, then publishes the same object relative to the parent handle with `NtSetInformationFile` and replacement disabled. This prevents inherited cross-principal mutation, a raced destination overwrite, and stage-object substitution within the documented filesystem boundary.

Receipts record the materialization backend, stage mode, stage-creation primitive, member-resolution primitive, durability choice, publication primitive, outcome, and cleanup result. On Windows they also record the storage-policy observations and whether the stage ACL was verified, without serializing a SID or volume identity. This is operational evidence, not authentication: receipts remain unsigned in the preview line.

## Platform FFI boundary

The current core's only `unsafe` blocks are isolated in the macOS descriptor-ACL module and the Windows native volume, token, security-descriptor, stage, and publication module. These small modules are the explicit platform-FFI audit boundary. Changes to them require platform tests and review of pointer lifetime, structure layout, handle ownership, share modes, no-replace semantics, and operating-system error conversion.

## Residual privilege boundary

The in-process materializer does not claim containment from root, an administrator, SYSTEM, a process running as the same security principal, Linux capabilities or Windows privileges that override filesystem access checks, filter drivers, debugging rights, or handle-duplication rights. Those actors can act with the library's authority or interfere below its namespace controls. The planned worker will constrain its own parser authority, but a distinct service identity or equivalent mandatory-access-control boundary is required to contain another process running as the same user.

## High-value security properties

A high-value report demonstrates that, under the default policy, sealr:

- publishes a member outside the requested destination;
- follows a hostile symlink or reparse point;
- accepts two inconsistent interpretations of one archive;
- exceeds a declared policy cap without rejection;
- publishes a destination after a rejected member;
- lets inspect and materialize produce different member trees;
- omits or misbinds the source, policy, view, or findings in a receipt;
- reports isolation as active when it was not enforced.

See [the threat model](docs/threat-model.md), [the invariants](docs/invariants.md), and [the finding registry](docs/findings.md).

## Non-goals

sealr does not claim malware detection, content safety, package-graph verification, or that CRC32 is authentication. A successful verdict means the archive passed the selected structural and materialization policy. It does not mean the files are trustworthy to execute.
