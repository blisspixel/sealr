# Security policy

sealr treats archive interpretation and materialization as a security boundary. The project is pre-alpha and has no supported release, but responsible reports are welcome now.

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

There is no production-ready or supported version. The current limitations are listed in [README.md](README.md). In particular, kernel isolation, the complete ZipDiff corpus, portable Unicode paths, capability-only destination I/O, signed receipts, ZIP64, and non-ZIP formats are not complete.

## Security properties under development

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
