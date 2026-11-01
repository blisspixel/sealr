# Repeated-read phase observation

Status: one local diagnostic run on 2026-11-01 at 14:12:48Z. This is not a
benchmark, a latency promise, or a replacement for the Alpha.15 repeated-read
report. The Alpha.15 totals stay in
[capability reuse](capability-reuse-experiment.md#controlled-repeated-read-observation).
Do not subtract them from the numbers below.

The raw tool output is
[observations/repeated-read-phases-2026-11-01.json](observations/repeated-read-phases-2026-11-01.json).
Its SHA-256 is
`b68fc951a229e23979ab9cf25b607dad1be72e521976eb74a146fb52de1ef410`.
That file is the authoritative record of every read. Tables below summarize it.

## What ran

The supervisor was a local release build of `sealr-phase-trace` with
`__internal-phase-trace` enabled. SHA-256
`03bc2c268e09720b758985e0d23bd156106ce7d921051b33eb38c3790e36d651`.
That hash is the binary that wrote the JSON. A later change cfg-gates the
protocol constants to Linux so macOS and Windows can compile the same
sources. A rebuild after that change has a different tool hash. The protocol
and this JSON stay the same.
The helper was a local release build of `sealr-worker` from
`sealr-worker-bootstrap-lab`, without that feature. SHA-256
`631ed470950f9f814ed405e51cdb560fc46cdb4aa06388882b7b63cf2c843bb8`,
1,518,312 bytes. The helper binary does not contain the `source_hash` label.
Neither binary is the published Alpha.19 musl archive helper, and neither hash
is a release artifact. Rustc was 1.99.1 (`58cf8f9c3`, 2026-10-13).

The host was Linux 7.2.8-9-omarchy, x86_64, AMD Ryzen 7 7840U, 16 logical
CPUs. The one-minute load average was 35.74 immediately before the run and
34.40 immediately after. Unrelated release builds were active. Ranges below
include that contention. The run completed in 3.380 seconds, inside a 120
second budget. The temporary directory was removed. `complete` is true.

Both fixtures use policy `default_v8`, no destination, and eight deflated
members `m0.txt` through `m7.txt`. Each member is 45,000 bytes. Byte `i` of
member `n` is `(n + i) mod 251`. Plaintext SHA-256 values are in the raw file
and are the same for both fixtures. The `wide` fixture also stores `pad.bin`,
8,388,608 bytes of `0xA5`. That pad is admitted and verified with the archive.
It is not retained and it is not read back.

| Fixture | Archive bytes | Pad bytes | Source SHA-256 |
|---|---:|---:|---|
| small | 6,152 | 0 | `6dd40dad8a4fa54b490efdedf2b7804c338668dc3f5d81b6ac54b3781836d504` |
| wide | 8,394,850 | 8,388,608 | `3996a140161c92c7186d95d141284024578ace677fa8a8829d3f9a10c903f01d` |

The archive hashes pin the bytes this run admitted. Member plaintext is fixed
by the formula above. The container bytes also depend on the pinned `ZipWriter`.

Each fixture was admitted twice, once without retention and once retaining the
eight members. The two admissions had to agree on the source digest and both
had to be admitted with complete verification. One unretained warmup pass of
eight reads was discarded. Six measured passes then alternated order: even
passes read unretained then retained, odd passes read retained then unretained.
Every returned member was checked against its plaintext SHA-256. That is 48
unretained reads and 48 retained reads per fixture.

## What each span covers

An unretained supervised read recorded these counts on every one of the 96
unretained samples: `source_hash` 3, `plan_validation` 5, `worker_setup` 1,
`payload_verification` 1.

- `source_hash` is each supervisor `SourceSnapshot::from_worker_file` inside
  `bind_member_read_source`. The three calls are request creation, request
  preflight, and final stream-result validation.
- `plan_validation` is `decode_planning` inside those three binds, plus request
  encode and request decode. The stream-result check after the third bind is
  outside this span.
- `worker_setup` is supervisor time from the socket pair through member-read
  acceptance. It closes before the final stream-result bind. The child calls
  `validate_operation` and then `validate_member_read` before it accepts the
  read. Each of those calls constructs a source snapshot with
  `from_worker_file`. Those two child hashes sit inside this span. They are
  not included in `source_hash_count`.
- `payload_verification` is the payload pipe, the supervisor CRC32 and SHA-256,
  clean exit, and reap.

Retained reads return from `retained_member` before any of those calls. All 96
retained samples have zero phase counts.

`total_ns` is the supervisor `read_member` call. The four spans do not cover
path lookup, the operation id, descriptor clones, the read coordinator, output
reservation, or the stream-result check. Their remainder is the unspanned gap.
Sums of the four spans plus that gap equal the sum of `total_ns`. Medians of
the phases do not add up to the median total.

## Per-read medians

Each median is the mean of the 24th and 25th sorted values, in milliseconds.

| Phase | Small unretained | Wide unretained |
|---|---:|---:|
| Total | 6.171 | 49.264 |
| Source hash | 0.082 | 25.766 |
| Plan validation | 0.356 | 0.530 |
| Worker setup | 3.498 | 20.994 |
| Payload verification | 1.325 | 1.115 |

Small unretained ranges were 4.071 to 9.955 ms total, 0.070 to 0.150 ms source
hash, 0.311 to 0.511 ms plan validation, 2.438 to 7.441 ms worker setup, and
0.634 to 3.269 ms payload verification. Wide unretained ranges were 42.984 to
67.324 ms total, 23.064 to 30.478 ms source hash, 0.420 to 0.717 ms plan
validation, 17.981 to 39.724 ms worker setup, and 0.727 to 2.684 ms payload
verification. The small and wide worker-setup ranges do not overlap. The small
and wide source-hash ranges do not overlap. The payload ranges do.

Retained medians were 0.004 ms on the small archive (range 0.002 to 0.013 ms)
and 0.005 ms on the wide archive (range 0.002 to 0.018 ms).

## Where the time went

Sums below are all 48 unretained reads. Shares are of the summed `total_ns`.

| Phase | Small sum (ms) | Small share | Wide sum (ms) | Wide share |
|---|---:|---:|---:|---:|
| Source hash | 4.272 | 1.42% | 1,252.898 | 52.16% |
| Plan validation | 17.665 | 5.87% | 26.309 | 1.10% |
| Worker setup | 200.734 | 66.67% | 1,043.501 | 43.44% |
| Payload verification | 69.924 | 23.23% | 67.573 | 2.81% |
| Unspanned gap | 8.474 | 2.81% | 11.815 | 0.49% |
| Total | 301.069 | 100% | 2,402.095 | 100% |

A pass is eight reads of one strategy. Across the six measured passes, the
small unretained pass total ranged from 41.776 to 65.615 ms, median 45.992 ms.
The wide unretained pass total ranged from 377.095 to 424.901 ms, median
400.316 ms. Retained pass medians were 0.039 ms and 0.046 ms.

## What this supports

On the 6,152-byte archive, process setup is the large cost. Three supervisor
hashes of that file are a small fraction of one read. Payload verification of
the 45,000-byte member is larger than hashing and smaller than setup.

On the 8,394,850-byte archive, the same member reads are slower because the
file is hashed repeatedly. The three counted supervisor hashes are about half
of the summed time. Worker setup grows by about 17.5 ms per read. That
increase is about the cost of two more full-file hashes at the supervisor's
observed per-hash time, and the child performs exactly two snapshot
constructions before acceptance. This run did not time those two constructions
as their own spans. Payload verification did not grow with the unread pad.

A later design has to treat those as different costs. Skipping only the
supervisor re-hash leaves the child's two snapshot constructions and the
process spawn in place. Reusing a process leaves the hashes in place unless
that process also keeps a validated snapshot. No such type or pool is added
here. Admission, retention, and evidence behavior are unchanged.

The Alpha.15 observation hashed larger downstream wheels on a different host
with the released helper. These fixtures do not explain that 3.686 second
median, and they are not a speedup claim.
