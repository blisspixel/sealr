# Unicode and streaming wheel compatibility

Updated 2026-09-04.

This controlled producer matrix closes a specific repository evidence gap: the
[300-artifact v5 inventory](wheel-compatibility-v5.md) observed no Unicode member
paths. It does not add 24 published packages to that inventory, establish
external adoption, or estimate ecosystem compatibility.

## Exact acquisition and reproduction

The [vector bundle](../crates/sealr/tests/conformance/wheel-producers-v1.json)
contains every source byte, length, SHA-256, expected member payload, producer
version, derivation, and intended outcome. No network acquisition is needed.
CPython 3.12.10 with zlib 1.3.1 produced the originals through its real `zipfile`
writer. Fixed timestamps, Unix regular-file modes, sorted members, compression
level 6, and explicit ZIP32 output make the inputs reproducible.

```text
python scripts/generate_wheel_producers.py
cargo run --locked -p sealr-wheel-lab --bin wheel_producers -- verify \
  crates/sealr/tests/conformance/wheel-producers-v1.json \
  crates/sealr/tests/conformance/wheel-producers-report-v1.json
cargo test --locked -p sealr --test wheel_producer_compatibility
```

The generator requires the exact CPython version and compares complete committed
bytes, including the zlib version. `--write` deliberately regenerates vectors;
the Rust tool's `record` operation deliberately regenerates observations.
Both changes need review. Ordinary verification never updates expectations.

[Python documents unseekable ZIP output](https://docs.python.org/3.12/library/zipfile.html).
The streamed fixtures exercise that producer path. Signed descriptors are
unmodified producer output. Unsigned descriptors are explicit derivatives made
by removing each four-byte signature and correcting directory offsets; they
are not attributed to a different producer. Wheel metadata, RECORD hashes,
and scheme relocation follow the
[wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/).

## Matrix and measured results

| Cohort | Artifacts | Result |
|---|---:|---|
| Store and Deflate, seekable output | 2 | Admitted |
| Store and Deflate, non-seekable output with signed descriptors | 2 | Admitted |
| Store and Deflate, unsigned descriptor derivatives | 2 | Admitted |
| Descriptor CRC32, compressed-size, and expanded-size mutations | 6 | `zip.diff.a2_size` |
| Non-ASCII UTF-8 names with the flag cleared in both headers | 2 | `zip.encoding` |
| Local and central UTF-8 flag disagreement | 2 | `zip.flags` |
| Stored payload mutation | 1 | `crc.mismatch` |
| Deflate final-block bit cleared, unchanged plaintext and CRC32 | 1 | `codec.deflate.invalid_stream` |
| Incorrect Unicode member RECORD hash with correct ZIP integrity | 2 | `wheel.record-hash-mismatch` after archive admission |
| NFD name | 1 | `path.unicode` |
| Simple and full Unicode case-fold collisions | 2 | `path.case_fold` |
| Parent traversal | 1 | `path.dotdot` |

There are six admitted artifacts, sixteen archive refusals, and two wheel
semantic denials. Each admitted artifact has 14 regular-file members, including
eight non-ASCII paths. Latin, Greek, and CJK paths cover all five install schemes:
`purelib`, `platlib`, `scripts`, `headers`, and `data`. A comma-bearing member
requires correct CSV quoting in RECORD. Empty content and a Python shebang
exercise bounded member reads and script classification.

The [observation report](../crates/sealr/tests/conformance/wheel-producers-report-v1.json)
binds the vector digest, every exact finding sequence, member and descriptor
counts, the current wheel consumer digest, four source-bound identities, and
the complete install plan. All six transports produce identical plan entries;
their source-bound identities remain distinct. Interpretation, policy, and
consumer identities are unchanged.

## Boundaries exercised

The packaged Rust regression runs all 24 artifacts through inspect and native
materialization on Linux, macOS, and Windows. It deletes each path input before
wheel evaluation, compares every capability read and materialized payload with
the producer's bytes, checks bounded prefix and full reads, and requires archive
rejection to leave no destination. A wheel semantic denial remains distinct
from archive rejection: the container can be valid while its RECORD lies.

Required Linux CI also runs
[`verify_wheel_producer_handoff.py`](../scripts/verify_wheel_producer_handoff.py)
against the copied handoff built from Cargo's extracted crate and the packaged
native worker and independent verifier. Each admitted artifact completes twice,
from supervised inspect and supervised materialization. Those twelve runs verify
canonical evidence, delete the source before Python, deny post-boundary wheel
opens in the bridge, and audit exact installed output and executable modes.
Inspect and materialize runs must have identical realization identities. The
eighteen negative cases must stop at the expected boundary without creating an
installer target or consuming the source.

## Deflate completion defect exposed

The final-block mutation preserves all ten plaintext bytes, CRC32, and declared
sizes. The previous reader treated exhausted input as successful completion.
The independent zlib observation is `eof == false` despite the matching output.
The corrected reader requires the decoder's explicit `StreamEnd` status before
reporting successful EOF. Complete input consumption and matching checksums
remain separate requirements.

The shared correction covers ZIP32, ZIP64, supervised payload verification,
later capability reads, and gzip framing. Truncation, tiny input and output
buffers, empty Deflate members, trailing input, gzip trailers, and existing
source-I/O error identity have regression coverage. This enforces the existing
complete-stream contract; it adds no interpretation profile, runtime dependency,
or `unsafe` code.

The remaining compatibility gap is a measured cohort of real published wheels
with these properties and feedback from a separately maintained consumer.
