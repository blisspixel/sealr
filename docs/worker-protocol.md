# Bounded worker protocol v1

Status: implemented as a non-published, zero-dependency codec in `sealr-worker-protocol`. The protocol is preparation for the Alpha.6 supervisor-worker boundary. It does not start a worker, transfer an operating-system handle, or provide process isolation by itself.

The protocol has one narrow purpose: carry a bounded operation description and bounded semantic result while the transport transfers authority separately. Archive bytes never appear in a control frame. A transport implementation is conforming only when it associates the declared capability slots with the exact out-of-band handles received for that frame.

## Security properties

- Every integer uses little-endian encoding and every frame names protocol version `1`.
- A complete frame is at most 4 MiB. Start frames are exactly 212 bytes.
- Counts and fixed minimum encoded sizes are checked before a vector reservation.
- String byte lengths, remaining input, UTF-8, and the string language are checked before a string allocation.
- Unknown enum values, nonzero reserved fields, trailing bytes, absent-value fields with nonzero bytes, and inconsistent counts fail closed.
- Operation IDs are nonzero. A result is accepted only for the supervisor-supplied expected operation ID. The request-bound validator also requires the returned profile identity and manifest resource claims to match the accepted start request.
- Start capability declarations must exactly match the capability count reported by the transport. Result frames cannot carry capabilities.
- Manifest paths are canonical relative paths in strict bytewise order. Duplicates, order changes, and a file that is an ancestor of another object are rejected.
- The decoder is pure. It returns a bounded value or a typed error before any archive or filesystem effect.

The codec contains no `unsafe` and has no runtime dependency. Allocation uses fallible reservations. `ProtocolError` contains a fixed error kind, byte offset, and static detail instead of echoing hostile input.

## Transport contract

The byte codec cannot validate operating-system handle rights. The future supervisor must enforce the following rules at the transport boundary:

| Mode | Capability slots | Required authority |
|---|---:|---|
| Inspect | `0` source | One read-only immutable snapshot handle |
| Materialize | `0` source, `1` stage | One read-only immutable snapshot handle and one stage-directory handle |
| Result | none | Results never grant authority back to the supervisor |

The supervisor retains the destination parent, final name, publication, cleanup, staged-tree audit, and recovery authority. The worker does not receive the destination parent or an ambient archive pathname. Slot numbers are local to one received frame and do not identify a global handle table.

Protocol v1 also exposes request-bound result validation. It checks the operation ID, interpretation-profile digest, manifest member count, per-file size, aggregate file size, and canonical path depth against the accepted start request. Aggregate byte overflow fails closed. The result does not echo the source digest or policy digest, so v1 cannot provide complete request/result binding and must not be described that way.

A stream transport should read the fixed 16-byte header, reject a declared payload that would exceed 4 MiB, then read exactly the declared payload. End-of-stream before that point is truncation. Bytes after the declared payload are trailing input, not another implicit frame.

## Common header

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | Magic | ASCII `SEALRIPC` |
| 8 | 2 | Version | `1` |
| 10 | 1 | Kind | `1` start, `2` result |
| 11 | 1 | Reserved | Zero |
| 12 | 4 | Payload length | Exact bytes after the header |

The payload length excludes the header. No decoder accepts concatenated frames or trailing padding.

## Start payload

The version 1 start payload is exactly 196 bytes.

| Payload offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 16 | Operation ID | Nonzero, supervisor generated |
| 16 | 1 | Mode | `0` inspect, `1` materialize |
| 17 | 1 | Interpretation profile | `1` strict ASCII v1, `2` strict ASCII v2 |
| 18 | 1 | Member sync | Boolean `0` or `1` |
| 19 | 1 | Reserved | Zero |
| 20 | 2 | Capability count | At most 2 and equal to the transport count |
| 22 | 2 | Source slot | Available slot |
| 24 | 2 | Stage slot | Available distinct slot, or `0xffff` when absent |
| 26 | 2 | Reserved | Zero |
| 28 | 8 | Source length | At most `max_archive_bytes` |
| 36 | 32 | Source SHA-256 | Digest of the complete immutable snapshot |
| 68 | 32 | Interpretation profile SHA-256 | Exact selected profile identity |
| 100 | 32 | Policy SHA-256 | Opaque supervisor-supplied policy identity; v1 defines no compiled-policy preimage |
| 132 | 8 | Maximum archive bytes | Resource limit |
| 140 | 8 | Maximum files | Resource limit |
| 148 | 8 | Maximum member bytes | Resource limit |
| 156 | 8 | Maximum total expanded bytes | Resource limit |
| 164 | 1 | Ratio present | Boolean `0` or `1` |
| 165 | 7 | Reserved | Zero |
| 172 | 8 | Maximum ratio | Zero when absent |
| 180 | 4 | Maximum path depth | Resource limit |
| 184 | 4 | Reserved | Zero |
| 188 | 8 | Maximum metadata bytes | Resource limit |

Inspect requires exactly the source capability and no stage slot. Materialize requires exactly two distinct valid slots. The archive is referenced by source length and digest; it is not copied into the frame.

## Result payload

The result begins with a 124-byte fixed section.

| Payload offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 16 | Operation ID | Must equal the expected operation ID |
| 16 | 1 | Status | `1` complete, `2` rejected, `3` failed |
| 17 | 1 | Root flags | Bit 0 layout, bit 1 content, all other bits zero |
| 18 | 2 | Reserved | Zero |
| 20 | 4 | Manifest count | At most 10,000 |
| 24 | 4 | Finding count | At most 10,000 |
| 28 | 32 | Interpretation profile SHA-256 | Worker-observed profile identity |
| 60 | 32 | Layout root | Zero when absent |
| 92 | 32 | Content root | Zero when absent |

Each manifest entry then contains a `u16` path length, `u8` kind, zero reserved byte, `u64` size, 32-byte SHA-256, and path bytes. Kind `1` is a file and kind `2` is a directory. Directories have zero size and a zero digest. Version 1 paths are 1 through 4,096 ASCII bytes and use the current canonical jail language: relative, slash-separated, no empty, `.` or `..` component, no backslash, colon, control or portable-illegal character, no trailing dot or space, and no Windows reserved device stem.

Each finding contains `u16` code length, `u16` detail length, `u16` optional path length, `u8` severity, a zero reserved byte, then code, detail, and optional path bytes. `0xffff` means no path. Codes are 1 through 128 ASCII bytes in `[a-z][a-z0-9._]*`. Details are at most 1,024 UTF-8 bytes without control characters. A finding path follows the manifest path language.

Complete results require both roots and may not contain an error finding. Rejected and failed results have no content root or manifest and contain at least one error finding. A rejected or failed result may retain a layout root when interpretation reached a coherent layout before the later failure.

## Wire limits

| Item | Limit |
|---|---:|
| Complete frame | 4,194,304 bytes |
| Start frame | Exactly 212 bytes |
| Capabilities | 2 |
| Manifest entries | 10,000 |
| Findings | 10,000 |
| Path | 4,096 bytes |
| Finding code | 128 bytes |
| Finding detail | 1,024 bytes |

Version 1 contains no range list. If a later worker needs ranges, that protocol change receives a new version and an independently bounded encoding.

### Deliberate version 1 limits

Version 1 is a non-shipping transport foundation, not the final Alpha.6 semantic contract. Its single status is a worker-operation status. It does not preserve the public interpretation, admission, verification, effect, and lifecycle axes independently, and failed or rejected results intentionally discard the manifest and content root. It therefore cannot represent every admitted-but-effect-failed outcome.

The result carries a reduced staged-member manifest, findings, and preview roots. It does not carry a complete `ArchiveIR`, byte ranges, compressed sizes, methods, CRC32 values, extra-field dispositions, normalization actions, snapshot ownership, or an independently checkable proof that the manifest is the unique meaning of the snapshot. It therefore cannot construct the public `Outcome`, `ArchiveIR`, or `VerifiedArchive`. A supervisor can validate the frame and, after proving that all writers are quiescent, compare a stage with the returned claim. Protocol v1 alone does not let it independently verify archive semantics or preserve bounded later member reads.

The first Alpha.6 slice has landed as a separate repository-only, nonsemantic Linux authority-bootstrap lab. It tests descriptor transfer and identity, pre-exec and child-entry closure, `no_new_privs`, fixed Landlock ABI 3 ordering before source transfer, pidfd-backed termination and reap, and checked post-reap fixture cleanup without treating v1 as a runtime outcome format. The lab does not depend on or invoke protocol v1. The [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) next accepts a private split-phase semantic-record experiment while keeping retained-content transfer, isolated non-retained reads, materializing-writer quiescence, and helper packaging separate. Record tests and end-to-end merge tests must preserve IR on destination setup failure, distinguish worker and supervisor facts, and cover worker crash, malformed results, writer-quiescence failure, stage-audit failure, cleanup failure, publication failure, clone and drop behavior, retained borrows, and bounded reads before archive execution crosses the process boundary.

## Test and fuzz evidence

The deterministic protocol suite covers valid inspect and materialize round trips, complete and rejected results, every truncation of valid frames, wrong magic, version and kind, trailing input, capability and operation confusion, oversized and impossible counts, root-state confusion, malformed UTF-8, invalid paths, manifest ordering and topology, directory content claims, request-bound profile and resource drift, aggregate-size overflow, and three mutations at every byte position. A decoded value must re-encode canonically and decode to the same value.

The `protocol_decoders` libFuzzer target exercises arbitrary bytes and up to 64 input-directed mutations of known-valid start and result frames. Successful decodes must round trip to the identical canonical frame. The separate fuzz workspace pins:

| Control | Value |
|---|---:|
| Rust toolchain | `nightly-2026-08-01` |
| `cargo-fuzz` | `0.13.2` |
| `libfuzzer-sys` | `0.4.13` |
| Maximum input | 4 MiB |
| Campaign time | 600 seconds |
| Per-input timeout | 5 seconds |
| RSS limit | 1,024 MiB |
| Jobs | 1 |

The [seed manifest](../fuzz/seed-manifest.json) binds every seed and the dictionary by path, byte length, and SHA-256. Required CI verifies that manifest and the workflow bounds. The [scheduled fuzz workflow](../.github/workflows/fuzz.yml) runs the AddressSanitizer campaign weekly and on demand. A crash stops the campaign and preserves the bounded reproducer for seven days. A reproducible failure must become a deterministic regression before the fuzz gate can return to green.

The [first exact-main campaign](https://github.com/blisspixel/sealr/actions/runs/32616069888) executed 18,277,565 units in 601 seconds, averaged 30,411 executions per second, reached 503 MiB peak RSS under the 1,024 MiB limit, and produced no reproducer.

The [Alpha.5 release-gate campaign](https://github.com/blisspixel/sealr/actions/runs/32618027263) ran independently on the exact released commit. It executed 17,626,137 units in 601 seconds, averaged 29,328 executions per second, added 1,424 corpus units, reached 505 MiB peak RSS, and produced no reproducer.

Coverage-guided fuzzing is heuristic evidence. A clean bounded campaign does not prove that every frame or parser state is safe.

## Nonclaims

- This codec does not transfer, duplicate, restrict, or close operating-system handles.
- It does not prove that a worker and every descendant have released writable stage authority before audit.
- It does not authenticate its transport or protect against a malicious supervisor.
- It does not provide confidentiality for hashes, policy identities, paths, or findings.
- It does not implement Landlock, seccomp, AppContainer, a restricted token, or a worker lifecycle.
- It does not make the current in-process parser a sandbox.

The process and authority design is in [sandboxing and projection](sandbox.md). The delivery order is in the [near-term plan](near-term.md#alpha6-reduced-authority-linux-execution).
