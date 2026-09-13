# Strict ASCII ZIP64 profile v1

> Status: supported Alpha.10 in-process preview. Authenticated worker execution fails closed until semantic-record v3 can represent ZIP64-native evidence.

Profile ID: `sealr.profile.zip64.strict-ascii.v1`

Select this profile explicitly with `ZipInterpretationProfile::Zip64StrictAsciiV1` and authorize it with `Policy::default_v3()`. The CLI selection is `--format zip64`. The default `apply()` path and `--format zip` remain ZIP32; neither detects, retries, or aliases to ZIP64.

The profile accepts Store and Deflate members with strict ASCII paths and closed flag, extra-field, descriptor, disk, and record rules. It binds every legacy sentinel to one exact ZIP64 interpretation, requires single-disk structure, validates fixed ZIP64 end-record and adjacent locator geometry when present, and rejects redundant-field or local/central disagreement. A semantic ZIP64 extra is unique at each permitted site and every unrelated extra-field identifier is denied.

Accepted archives use `sealr.archive-ir.zip64.v1`, ZIP64-native member and covering evidence, an independent source-derived covering audit, and `sealrTreeV3` layout identity. The verified content identity remains the format-neutral `sealrTreeV1` encoding.

This profile is not a compatibility fallback and does not widen any ZIP32 profile. Unsupported encryption, spanning, recovery parsing, ambiguous descriptors, hidden records, path forms, methods, and resource behavior continue to fail closed.
