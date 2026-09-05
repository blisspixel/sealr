# Reuse the established authority

Status: proposed experiment after Alpha.14. This document changes no supported
API, retention limit, worker protocol, or security claim.

## Start with the consumer's decision

Sealr's useful unit is an admitted tree capability. A downstream tool should
state which facts and members it needs from that capability before choosing an
integration strategy. A wheel-content acceptance check can need verified names
and a small metadata set. A complete installation needs every planned member.

The owner-maintained [downstream validation project](https://github.com/blisspixel/sealr-validation)
uses real Deepr, Primr, and Recon release wheels with immutable Alpha.14 source
and authenticated native artifacts. A local Linux Deepr inspect handoff took
217 seconds and audited 834 installed output files. That single observation is
integration feedback, not a benchmark or a claim about which stage dominates.

## The repeated work

The public copied handoff requests no retention and stages each member through
`VerifiedArchive::read_member`. For an unretained supervised member, this uses
a fresh authenticated, restricted worker and waits for verified stream
completion and reap.

There is additional repeated work in the supervisor. Request creation,
preflight validation, and final stream-result validation each bind the supplied
source and validate the plan. `bind_member_read_source` constructs a source
snapshot through `SourceSnapshot::from_worker_file`, which hashes the entire
supplied file. Decoding and validating the plan revisits member source fields.
Many small member reads can therefore multiply archive-sized and plan-sized
work, even when decompression is cheap.

Relevant implementation:

- [Copied handoff preparation](../crates/sealr/examples/pypa_installer_handoff/stage.rs)
- [Supervised member reads](../crates/sealr/src/supervised/linux.rs)
- [Member request and stream validation](../crates/sealr/src/semantic_record/worker_runtime.rs)
- [Snapshot source binding](../crates/sealr/src/snapshot.rs)
- [Plan validation](../crates/sealr/src/semantic_record.rs)
- [Public bounded retention](../crates/sealr/src/verified.rs)

These checks establish facts that the current raw-file and serialized-record
interfaces do not otherwise guarantee. A file length or claimed digest cannot
replace observing the actual bytes. Removing checks from those interfaces would
weaken the boundary.

## First experiment: an explicit working set

Use existing public `RetentionPlan` APIs in a separately labeled experimental
consumer. Keep the validation project's exact copied handoff as the baseline.
Do not edit its provenance-pinned files and still claim an unchanged copy.

Prepare exact path lists once from public verified member inventories, pin them
beside each wheel's source digest, and run three strategies on the same wheels:

| Strategy | Requested retained bytes |
|---|---|
| Baseline | None |
| Semantic working set | Exact `METADATA`, `WHEEL`, `RECORD`, and existing `entry_points.txt` members |
| Bounded working set | Semantic paths plus deterministically selected small members, at most 64 paths, 256 KiB per member, and 1 MiB total |

Start with nine complete installations across the three wheels. Record
admission, evaluation, staging, installation, and output-audit time separately.
Record requested and fulfilled retention, retained bytes, and any unsuccessful
retention status. Repeat only after the first pass establishes correctness and
identifies which comparisons justify a controlled timing run.

Independent canonical evidence verification must precede source deletion.
Delete the private source before evaluation and member consumption. Require the
same source, tree, artifact, and plan identities; exact installed paths,
content, modes, and realization identity; and the existing refusal behavior.
Preserve full-archive verification, all byte ceilings, restricted execution,
stream checks, exit checks, and reap.

Retention avoids both worker setup and repeated supervisor validation for the
selected members. This experiment alone cannot attribute the improvement to
either cost. Do not raise the 64-path limit to fit whole installations or claim
a speedup before measuring it.

## Next hypothesis: a private validated read authority

If measurements justify it, investigate retaining a source-owning, already
validated supervisor capability across member requests. Such a type would have
to carry the established source, plan, completion, and profile bindings, while
preventing raw file substitution or an unchecked construction path.

Fresh worker inputs would still need their own source and plan validation.
Every returned member would still need exact range, size, digest, request,
termination, and cleanup checks. Source lifetime, mutation detection, capability
clones, cancellation, concurrency, and failure parity are review gates before
any production change. Process pooling is a separate proposal with a separate
lifetime and authority analysis.

## Optional visual: delete the archive, keep the meaning

The clearest first visual follows a consumer through admission, deletion of
the original pathname, verified member reads, and completion. A toggle to use
a consumer that reopens the source should fail at the missing pathname. Show
the retained verified storage so the viewer does not mistake pathname deletion
for erasure of every byte.

The clean line is: "The packaging is gone. The contract still works."

An optional performance view can illustrate the absurdity of checking in every
sock separately at an airport. Connect that analogy to measured phases and
counts only. Keep proposed reuse visibly separate from observed behavior.

Ground the visual in committed conformance evidence and copyable Linux commands.
The [same-digest example](same-digest-different-tree.md) distinguishes
filename-bound artifact and plan identities; it does not demonstrate two real
parsers producing different installed trees. Keep that distinction accurate.
Use keyboard controls and a static alternative, require no uploads or server,
and put the explanation under `docs/` with only a link from the README.
