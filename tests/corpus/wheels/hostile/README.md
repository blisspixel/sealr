# Hostile wheel regression corpus

This directory contains small deterministic wheel-shaped regressions for the non-shipping research consumer. The files are test evidence, not installable releases or benign compatibility samples.

`manifest.json` binds each exact fixture to its SHA-256, byte length, outer filename, mutation, outcome, and first finding. The `hostile_fixtures` integration test reconstructs every archive from source, re-evaluates it through `sealr.profile.zip.wheel-utf8.v1`, and requires byte-for-byte equality with the committed file. Set `SEALR_UPDATE_WHEEL_FIXTURES=1` only when intentionally regenerating the corpus, then review every manifest and binary diff.

The corpus covers `RECORD` hash, size, missing, phantom, and duplicate failures; relocation and generated-target collisions; metadata and top-level root disagreements; decomposed Unicode; unknown `.data` schemes; a script-rewrite case with executable container facts; and an unmodified admitted control. Exhaustive flag and extra-field domains remain compact code-driven tests in the core crate rather than 131,072 redundant binary fixtures.
