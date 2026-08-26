# Codec and acceleration backends

> Deferred engineering track for acceleration. Alpha.6 has no runtime backend scheduler, GPU path, QAT path, or alternate codec selection. The current ZIP Deflate implementation uses `flate2` with the pure-Rust `zlib-rs` backend and verifies exact compressed-input consumption. Planned ZIP methods such as Zstd and XZ are codec adapters on the product path, not hardware backends; they still require exact consumption and a justified tiny dependency. See the [roadmap codec destination](../ROADMAP.md#common-compression-one-boundary).

Backends may optimize verification or realization. They may not define interpretation, paths, policy, findings, verification completeness, or tree identity.

## Workload model

Measure four costs before selecting a backend:

```text
T_structure  parse and evaluate layout
T_verify     decompress and hash required content
T_realize    create and publish filesystem objects
T_reuse      return an already verified tree
```

Many small files are usually dominated by metadata and security scanning. A large independent member may be codec-bound. Content-addressed reuse may avoid both costs. One throughput number cannot represent all three cases.

## Backend admission gate

An optional backend is eligible only when it:

1. reports exact compressed bytes consumed and uncompressed bytes produced;
2. produces byte-identical output for every admitted stream;
3. preserves codec-error, trailing-input, size, CRC32, SHA-256, and quota findings;
4. passes the hostile codec corpus and cross-backend differential tests;
5. records its identity and version in evidence;
6. remains optional and fails closed or falls back before semantic processing begins;
7. improves a named workload after initialization, transfer, filesystem, and antivirus costs are included.

## Candidate optimizations

The likely order is:

1. reuse an already verified content tree;
2. parallel verification of independent members after one sequential covering, with deterministic CD-order findings and checked quota combining, using `std::thread` rather than a task runtime;
3. parallel independent file writes after parent directories exist; never a parallel no-replace publish;
4. optimized CPU copy and DEFLATE implementations that expose exact consumption;
5. clone or link realization from a trusted content-addressed store;
6. remote range ingestion backed by an immutable private snapshot;
7. hardware offload only for a demonstrated large-buffer or device-memory consumer.

Embarrassingly parallel tools (ZipDiff classification, benign-corpus measurement) may use `std::thread` and `SEALR_JOBS` without touching the library TCB. They must still emit byte-stable aggregates.

GPU, QAT, Mojo, CubeCL, mmap, DirectStorage, and specialized codecs remain research options. None is on the active Phase 0.1 path.

## Reporting rule

Every benchmark names the source corpus, destination, verification controls, backend, cold or warm state, CPU time, wall time, peak memory, open-handle peak, and bytes avoided through reuse. Security controls remain enabled.

See [architecture.md](architecture.md#performance-architecture) and [ROADMAP.md](../ROADMAP.md#deferred-performance-track).
