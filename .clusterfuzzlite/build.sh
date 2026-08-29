#!/bin/bash -eu
# ClusterFuzzLite build: compiles every committed cargo-fuzz target and hands
# the pinned deterministic seeds and dictionaries to the runner through the
# OSS-Fuzz naming convention. The committed seed manifests remain the only
# reproducibility contract; anything this campaign grows is discovery input.
cd "$SRC/sealr"

# The base image's own nightly can lag the workspace's pinned MSRV. Pin the
# exact nightly the scheduled fuzz campaign uses so both lanes compile the
# same toolchain.
rustup toolchain install nightly-2026-08-01 --profile minimal
rustup default nightly-2026-08-01

cargo fuzz build -O --fuzz-dir fuzz

# Dictionary names follow <target>_dictionary except the two protocol-era
# names, which are mapped explicitly.
dictionary_for() {
  case "$1" in
    protocol_decoders) echo "fuzz/dictionaries/protocol_dictionary" ;;
    semantic_records) echo "fuzz/dictionaries/semantic_record_dictionary" ;;
    *) echo "fuzz/dictionaries/$1_dictionary" ;;
  esac
}

targets="
protocol_decoders
semantic_records
tar_ustar_portable_v1
tar_pax_portable_v1
tar_gnu_longname_portable_v1
gzip_rfc1952_single_member_v1
zip64_strict_ascii_v1
tar_gzip_ustar_portable_v1
tar_gzip_pax_portable_v1
tar_gzip_gnu_longname_portable_v1
tar_zstd_ustar_portable_v1
tar_xz_ustar_portable_v1
tar_bzip2_ustar_portable_v1
sevenz_copy_portable_v1
"

for target in $targets; do
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/${target}" "$OUT/${target}"
  zip -j "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/${target}"/*
  dictionary="$(dictionary_for "$target")"
  if [ ! -f "$dictionary" ]; then
    echo "missing dictionary for ${target}: ${dictionary}" >&2
    exit 1
  fi
  cp "$dictionary" "$OUT/${target}.dict"
done
