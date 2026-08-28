//! Independent verifier for Sealr identity conformance manifests.
//!
//! This crate deliberately does not depend on `sealr`. It reads committed
//! evidence facts, validates their semantic coherence, and independently
//! reproduces profile, layout, and content digests. It parses only the closed
//! source-bearing formats represented by a manifest and never inflates an
//! archive or performs filesystem effects.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASES: usize = 10_000;
const MAX_MEMBERS_PER_CASE: usize = 100_000;
const MANIFEST_SCHEMA: &str = "sealr.identity-conformance.v1";
const IR_SCHEMA: &str = "sealr.archive-ir.v1";
const TREE_ENCODING: &str = "sealrTreeV1";
const LAYOUT_LABEL: &str = "sealr.tree.layout.v1";
const CONTENT_LABEL: &str = "sealr.tree.content.v1";
const TAR_LAYOUT_VECTOR_SCHEMA: &str = "sealr.tar-layout-conformance.v1";
const TAR_TREE_ENCODING: &str = "sealrTreeV2";
const TAR_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-ustar.v1";
const ZIP64_MANIFEST_SCHEMA: &str = "sealr.zip64-identity-conformance.v1";
const ZIP64_IR_SCHEMA: &str = "sealr.archive-ir.zip64.v1";
const ZIP64_PROFILE_SCHEMA: &str = "sealr.profile.zip64.strict-ascii.v1";
const ZIP64_TREE_ENCODING: &str = "sealrTreeV3";
const ZIP64_LAYOUT_LABEL: &str = "sealr.tree.layout.zip64.v1";
const TAR_GZIP_MANIFEST_SCHEMA: &str = "sealr.tar-gzip-identity-conformance.v1";
const TAR_GZIP_PROFILE_SCHEMA: &str = "sealr.profile.tar-gzip.ustar-portable.v1";
const TAR_GZIP_IR_SCHEMA: &str = "sealr.archive-ir.tar-gzip-ustar.v1";
const TAR_GZIP_TREE_ENCODING: &str = "sealrTreeV4";
const TAR_GZIP_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-gzip-ustar.v1";
const TAR_PAX_MANIFEST_SCHEMA: &str = "sealr.tar-pax-identity-conformance.v1";
const TAR_PAX_PROFILE_SCHEMA: &str = "sealr.profile.tar.pax-portable.v1";
const TAR_PAX_IR_SCHEMA: &str = "sealr.archive-ir.tar-pax.v1";
const TAR_PAX_TREE_ENCODING: &str = "sealrTreeV5";
const TAR_PAX_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-pax.v1";
const TAR_GNU_LONGNAME_MANIFEST_SCHEMA: &str = "sealr.tar-gnu-longname-identity-conformance.v1";
const TAR_GNU_LONGNAME_PROFILE_SCHEMA: &str = "sealr.profile.tar.gnu-longname-portable.v1";
const TAR_GNU_LONGNAME_IR_SCHEMA: &str = "sealr.archive-ir.tar-gnu-longname.v1";
const TAR_GNU_LONGNAME_TREE_ENCODING: &str = "sealrTreeV6";
const TAR_GNU_LONGNAME_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-gnu-longname.v1";
const TAR_GZIP_PAX_MANIFEST_SCHEMA: &str = "sealr.tar-gzip-pax-identity-conformance.v1";
const TAR_GZIP_PAX_PROFILE_SCHEMA: &str = "sealr.profile.tar-gzip.pax-portable.v1";
const TAR_GZIP_PAX_IR_SCHEMA: &str = "sealr.archive-ir.tar-gzip-pax.v1";
const TAR_GZIP_PAX_TREE_ENCODING: &str = "sealrTreeV7";
const TAR_GZIP_PAX_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-gzip-pax.v1";
const TAR_GZIP_GNU_LONGNAME_MANIFEST_SCHEMA: &str =
    "sealr.tar-gzip-gnu-longname-identity-conformance.v1";
const TAR_GZIP_GNU_LONGNAME_PROFILE_SCHEMA: &str =
    "sealr.profile.tar-gzip.gnu-longname-portable.v1";
const TAR_GZIP_GNU_LONGNAME_IR_SCHEMA: &str = "sealr.archive-ir.tar-gzip-gnu-longname.v1";
const TAR_GZIP_GNU_LONGNAME_TREE_ENCODING: &str = "sealrTreeV8";
const TAR_GZIP_GNU_LONGNAME_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-gzip-gnu-longname.v1";
const TAR_PORTABLE_PROFILE_SCHEMA: &str = "sealr.profile.tar.ustar-portable.v1";
const TAR_PORTABLE_PROFILE_DIGEST: &str =
    "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700";
const GZIP_TRANSFORM_ID: &str = "sealr.transform.gzip.rfc1952-single-member.v1";
const GZIP_TRANSFORM_DEFINITION: &[u8] = b"algorithm=rfc1952-gzip;members=exactly-one;reserved-flags=zero;extra-fields=exact-subfield-framing-si2-nonzero-unique-ids;trailing-data=forbidden;header-crc=verify-when-present;data-crc32=verify;isize=verify;payload=rfc1951-deflate;output=bounded";
const GZIP_DECODER_PARAMETERS: &[u8] = b"rfc1951-window-bits=15;preset-dictionary=none";
const MAX_DERIVED_TAR_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAX_EXTENSION_BYTES: u64 = 64 * 1024;
const MAX_PAX_EXTENSIONS: usize = 1024;
const MAX_GNU_LONGNAME_CARRIERS: usize = 1024;
const MAX_GNU_LONGNAME_PAYLOAD_BYTES: u64 = 8192;

const FILE: u8 = 1;
const DIRECTORY: u8 = 2;
const SITE_LOCAL: u8 = 1;
const SITE_CENTRAL: u8 = 2;
const DISP_IGNORED: u8 = 1;
const DISP_SEMANTIC: u8 = 2;
const DISP_DENIED: u8 = 3;
const NORM_STRIP_DIR_SLASH: u8 = 1;
const NORM_DROP_DOT: u8 = 2;
const PAX_EXTENSION_GLOBAL: u8 = 1;
const PAX_EXTENSION_LOCAL: u8 = 2;
const PAX_KEYWORD_PATH: u8 = 1;
const PAX_KEYWORD_SIZE: u8 = 2;
const PAX_SOURCE_USTAR: u8 = 0;
const PAX_SOURCE_GLOBAL: u8 = 1;
const PAX_SOURCE_LOCAL: u8 = 2;
const GNU_PATH_SOURCE_HEADER: u8 = 0;
const GNU_PATH_SOURCE_CARRIER: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationSummary {
    pub profiles: usize,
    pub cases: usize,
    pub layout_roots: usize,
    pub content_roots: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TarVerificationSummary {
    pub members: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(String);

impl VerifyError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    fn context(self, context: &str) -> Self {
        Self(format!("{context}: {}", self.0))
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    tree_encoding: String,
    profiles: Vec<ProfileVector>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct ManifestEnvelope {
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Manifest {
    schema: String,
    profile: Zip64ProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    cases: Vec<Zip64Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ProfileVector {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Case {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    archive_ir: Zip64ArchiveIr,
    layout_preimage_hex: String,
    layout_root: Zip64LayoutRoot,
    content_root: Zip64ContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    format: String,
    zip64_covering: Zip64Covering,
    members: Vec<Zip64Member>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Covering {
    local_records: ByteRange,
    central_directory: ByteRange,
    zip64_eocd: Option<ByteRange>,
    zip64_locator: Option<ByteRange>,
    eocd: ByteRange,
    comment: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Member {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    method: u16,
    flags: u16,
    declared_crc: u32,
    declared_comp_size: u64,
    declared_uncomp_size: u64,
    source_ranges: MemberSourceRanges,
    extra_fields: Vec<ExtraField>,
    zip64: Zip64MemberEvidence,
    actual_uncomp_size: Option<u64>,
    actual_crc: Option<u32>,
    content_sha256: Option<String>,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64MemberEvidence {
    local_version_needed: u16,
    central_version_needed: u16,
    central_presence_mask: u8,
    central_legacy_sentinel_mask: u8,
    local_legacy_sentinel_mask: u8,
    local_value_shape: Zip64LocalValueShape,
    local_zip64_extra: Option<ByteRange>,
    central_zip64_extra: Option<ByteRange>,
    descriptor_width: Option<Zip64DescriptorWidth>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Zip64LocalValueShape {
    Absent,
    Exact,
    StreamingZeros,
    StreamingMaxima,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Zip64DescriptorWidth {
    Zip32,
    Zip64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64LayoutRoot {
    #[serde(rename = "sealrTreeV3")]
    sealr_tree_v3: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ContentRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipManifest {
    schema: String,
    archive_ir_schema: String,
    profile: TarGzipProfileVector,
    transform: TarGzipTransformVector,
    inner_profile: TarGzipProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    derived_tar: TarGzipDerivedTar,
    cases: Vec<TarGzipCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipProfileVector {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipTransformVector {
    id: String,
    definition_hex: String,
    digest: DigestHex,
    decoder_parameters_hex: String,
    decoder_parameters_digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipDerivedTar {
    bytes_hex: String,
    source: DigestHex,
    covering: TarCovering,
    members: Vec<TarGzipMember>,
    raw_layout_preimage_hex: String,
    raw_layout_root: TarLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipMember {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    declared_uncomp_size: u64,
    tar: TarGzipMemberEvidence,
    actual_uncomp_size: u64,
    actual_crc: u32,
    content_sha256: String,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipMemberEvidence {
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipCase {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    gzip: GzipWrapperVector,
    layout_preimage_hex: String,
    layout_root: TarGzipLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GzipWrapperVector {
    flags: u8,
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
    header: ByteRange,
    extra: Option<ByteRange>,
    extra_subfield_count: u32,
    original_name: Option<ByteRange>,
    comment: Option<ByteRange>,
    header_crc16: Option<ByteRange>,
    compressed_payload: ByteRange,
    trailer: ByteRange,
    declared_crc32: u32,
    declared_isize: u32,
    derived_output_len: u64,
    derived_output_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipLayoutRoot {
    #[serde(rename = "sealrTreeV4")]
    sealr_tree_v4: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxManifest {
    schema: String,
    archive_ir_schema: String,
    profile: TarPaxProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    cases: Vec<TarPaxCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxProfileVector {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxCase {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    archive_ir: TarPaxArchiveIr,
    layout_preimage_hex: String,
    layout_root: TarPaxLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    format: String,
    tar_covering: TarCovering,
    pax_extensions: Vec<TarPaxExtension>,
    members: Vec<TarPaxMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxExtension {
    raw_name_bytes: Vec<u8>,
    kind: TarPaxExtensionKind,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
    payload_sha256: String,
    records: Vec<TarPaxRecord>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum TarPaxExtensionKind {
    Global,
    Local,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxRecord {
    record: ByteRange,
    value: ByteRange,
    keyword: TarPaxKeyword,
    raw_value_bytes: Vec<u8>,
    parsed_size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum TarPaxKeyword {
    Path,
    Size,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxMember {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    declared_uncomp_size: u64,
    tar_pax: TarPaxMemberEvidence,
    actual_uncomp_size: u64,
    actual_crc: u32,
    content_sha256: String,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxMemberEvidence {
    tar: TarGzipMemberEvidence,
    base_name_bytes: Vec<u8>,
    base_size: u64,
    path_source: TarPaxValueSource,
    size_source: TarPaxValueSource,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
enum TarPaxValueSource {
    Ustar,
    Global {
        extension_index: u32,
        record_index: u32,
    },
    Local {
        extension_index: u32,
        record_index: u32,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarPaxLayoutRoot {
    #[serde(rename = "sealrTreeV5")]
    sealr_tree_v5: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameManifest {
    schema: String,
    archive_ir_schema: String,
    profile: TarGnuLongNameProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    cases: Vec<TarGnuLongNameCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameProfileVector {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameCase {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    archive_ir: TarGnuLongNameArchiveIr,
    layout_preimage_hex: String,
    layout_root: TarGnuLongNameLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    format: String,
    tar_covering: TarCovering,
    gnu_longname_carriers: Vec<TarGnuLongNameCarrier>,
    members: Vec<TarGnuLongNameMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameCarrier {
    raw_name_bytes: Vec<u8>,
    path_bytes: Vec<u8>,
    header: ByteRange,
    payload: ByteRange,
    path: ByteRange,
    padding: ByteRange,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
    payload_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameMember {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    declared_uncomp_size: u64,
    tar_gnu_longname: TarGnuLongNameMemberEvidence,
    actual_uncomp_size: u64,
    actual_crc: u32,
    content_sha256: String,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameMemberEvidence {
    tar: TarGzipMemberEvidence,
    base_name_bytes: Vec<u8>,
    path_source: TarGnuLongNamePathSource,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
enum TarGnuLongNamePathSource {
    Header,
    Carrier { carrier_index: u32 },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGnuLongNameLayoutRoot {
    #[serde(rename = "sealrTreeV6")]
    sealr_tree_v6: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipPaxManifest {
    schema: String,
    archive_ir_schema: String,
    profile: TarGzipProfileVector,
    transform: TarGzipTransformVector,
    inner_profile: TarGzipProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    derived_tar: TarGzipPaxDerivedTar,
    cases: Vec<TarGzipPaxCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipPaxDerivedTar {
    bytes_hex: String,
    source: DigestHex,
    covering: TarCovering,
    pax_extensions: Vec<TarPaxExtension>,
    members: Vec<TarPaxMember>,
    raw_layout_preimage_hex: String,
    raw_layout_root: TarPaxLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipPaxCase {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    gzip: GzipWrapperVector,
    layout_preimage_hex: String,
    layout_root: TarGzipPaxLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipPaxLayoutRoot {
    #[serde(rename = "sealrTreeV7")]
    sealr_tree_v7: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipGnuLongNameManifest {
    schema: String,
    archive_ir_schema: String,
    profile: TarGzipProfileVector,
    transform: TarGzipTransformVector,
    inner_profile: TarGzipProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    derived_tar: TarGzipGnuLongNameDerivedTar,
    cases: Vec<TarGzipGnuLongNameCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipGnuLongNameDerivedTar {
    bytes_hex: String,
    source: DigestHex,
    covering: TarCovering,
    gnu_longname_carriers: Vec<TarGnuLongNameCarrier>,
    members: Vec<TarGnuLongNameMember>,
    raw_layout_preimage_hex: String,
    raw_layout_root: TarGnuLongNameLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipGnuLongNameCase {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    gzip: GzipWrapperVector,
    layout_preimage_hex: String,
    layout_root: TarGzipGnuLongNameLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarGzipGnuLongNameLayoutRoot {
    #[serde(rename = "sealrTreeV8")]
    sealr_tree_v8: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileVector {
    id: String,
    digest: DigestHex,
    canonical_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestHex {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterpretationIdentity {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    interpretation: InterpretationIdentity,
    axes: Axes,
    findings: Vec<Finding>,
    archive_ir: Option<ArchiveIr>,
    layout_root: Root,
    content_root: Root,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Axes {
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    effect: EffectStatus,
    view_completeness: ViewCompleteness,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum InterpretationStatus {
    Interpreted,
    Malformed,
    Unsupported,
    Indeterminate,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum AdmissionStatus {
    Admitted,
    Denied,
    NotEvaluated,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum VerificationStatus {
    StructureOnly,
    Partial {
        verified_members: u64,
        pending_members: u64,
    },
    Complete,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum EffectStatus {
    NotRequested,
    Committed,
    Failed,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum ViewCompleteness {
    Complete,
    Partial { phase: StoppingPhase, cause: String },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum StoppingPhase {
    Source,
    Structure,
    Admission,
    Verification,
    Effect,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    code: String,
    severity: Severity,
    #[serde(default)]
    member: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Error,
    Deny,
    Warn,
    Info,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Root {
    Available(AvailableRoot),
    Unavailable(UnavailableRoot),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailableRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableRoot {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    covering: ArchiveCovering,
    members: Vec<Member>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ByteRange {
    offset: u64,
    len: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarLayoutVector {
    schema: String,
    tree_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    source: DigestHex,
    covering: TarCovering,
    members: Vec<TarVectorMember>,
    layout_root: TarLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarCovering {
    member_records: ByteRange,
    terminator: ByteRange,
    trailing_zeros: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarVectorMember {
    canonical_path: String,
    kind: MemberKind,
    raw_name_bytes: Vec<u8>,
    declared_uncomp_size: u64,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
    normalization_actions: Vec<NormalizationAction>,
    actual_uncomp_size: u64,
    content_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarLayoutRoot {
    #[serde(rename = "sealrTreeV2")]
    sealr_tree_v2: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarContentRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveCovering {
    local_records: ByteRange,
    central_directory: ByteRange,
    eocd: ByteRange,
    comment: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    method: u16,
    flags: u16,
    declared_crc: u32,
    declared_comp_size: u64,
    declared_uncomp_size: u64,
    source_ranges: MemberSourceRanges,
    extra_fields: Vec<ExtraField>,
    actual_uncomp_size: Option<u64>,
    actual_crc: Option<u32>,
    content_sha256: Option<String>,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MemberKind {
    File,
    Directory,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum MemberVerification {
    Pending,
    Verified,
    Failed { cause: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberSourceRanges {
    local_header: ByteRange,
    compressed_payload: ByteRange,
    data_descriptor: Option<ByteRange>,
    central_header: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraField {
    site: ExtraSite,
    id: u16,
    header_range: ByteRange,
    data_range: ByteRange,
    disposition: ExtraDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
enum ExtraSite {
    Local,
    Central,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ExtraDisposition {
    Semantic,
    Ignored,
    Denied,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum NormalizationAction {
    StripDirectoryTrailingSlash,
    DropDotComponent { component_index: u32 },
}

#[derive(Clone, Copy, Serialize)]
struct Zip64ProfileBitRule {
    bit: u8,
    mask: u16,
    disposition: &'static str,
    meaning: &'static str,
}

#[derive(Serialize)]
struct Zip64ProfileDefinition {
    schema: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [Zip64ProfileBitRule; 16],
    names: &'static str,
    extra_fields: &'static str,
    local_zip64: &'static str,
    central_zip64: &'static str,
    descriptor_width: &'static str,
    descriptors: &'static str,
    global_end_records: &'static str,
    spanning: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

#[derive(Serialize)]
struct TarGzipProfileDefinition {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    wrapper_profile: &'static str,
    wrapper_profile_sha256: String,
    decoder_parameters_sha256: String,
    gzip_members: &'static str,
    gzip_optional_fields: &'static str,
    gzip_integrity: &'static str,
    gzip_trailing_input: &'static str,
    derived_output: &'static str,
    inner_profile: &'static str,
    inner_profile_sha256: String,
}

#[derive(Serialize)]
struct TarPaxProfileDefinition {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    base_profile: &'static str,
    base_profile_sha256: String,
    extension_types: [&'static str; 2],
    extension_carrier_names: &'static str,
    underlying_member_names: &'static str,
    extension_materialization: &'static str,
    record_encoding: &'static str,
    length_encoding: &'static str,
    record_consumption: &'static str,
    keywords: [&'static str; 2],
    duplicate_keywords: &'static str,
    unknown_keywords: &'static str,
    empty_values: &'static str,
    path_values: &'static str,
    size_values: &'static str,
    precedence: &'static str,
    global_state: &'static str,
    local_state: &'static str,
    max_extension_payload_bytes: u32,
    max_extension_headers: u16,
    max_records_per_extension: u8,
    max_keyword_scan_bytes: u8,
    max_effective_path_bytes: &'static str,
    denied_features: [&'static str; 10],
}

#[derive(Serialize)]
struct TarGnuLongNameProfileDefinition {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    block_bytes: u16,
    header_magic_and_version: &'static str,
    accepted_types: [&'static str; 3],
    numeric_encoding: &'static str,
    checksum: &'static str,
    fixed_text_fields: &'static str,
    owner_names: &'static str,
    mode: &'static str,
    linkname: &'static str,
    device_numbers: &'static str,
    gnu_tail: &'static str,
    carrier_names: &'static str,
    carrier_payload: &'static str,
    carrier_state: &'static str,
    physical_name_binding: &'static str,
    min_effective_path_bytes: u8,
    max_effective_path_bytes: &'static str,
    max_carrier_payload_bytes: u16,
    max_carrier_headers: u16,
    carrier_materialization: &'static str,
    member_padding: &'static str,
    termination: &'static str,
    destination_metadata: &'static str,
    names: &'static str,
    unicode_repertoire_version: &'static str,
    unicode_repertoire: &'static str,
    unicode_repertoire_implementation: &'static str,
    character_restrictions: &'static str,
    path_grammar: &'static str,
    reserved_names: &'static str,
    normalization_unicode_version: &'static str,
    normalization_implementation: &'static str,
    case_folding_unicode_version: &'static str,
    case_folding_implementation: &'static str,
    normalization: &'static str,
    case_collision: &'static str,
    component_limit: &'static str,
    denied_features: [&'static str; 13],
}

pub fn verify_manifest_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let envelope: ManifestEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
    match envelope.schema.as_str() {
        MANIFEST_SCHEMA => {
            let manifest: Manifest = serde_json::from_slice(bytes)
                .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
            verify_manifest(&manifest)
        }
        ZIP64_MANIFEST_SCHEMA => verify_zip64_identity_vector_json(bytes),
        TAR_GZIP_MANIFEST_SCHEMA => verify_tar_gzip_identity_vector_json(bytes),
        TAR_PAX_MANIFEST_SCHEMA => verify_tar_pax_identity_vector_json(bytes),
        TAR_GNU_LONGNAME_MANIFEST_SCHEMA => verify_tar_gnu_longname_identity_vector_json(bytes),
        TAR_GZIP_PAX_MANIFEST_SCHEMA => verify_tar_gzip_pax_identity_vector_json(bytes),
        TAR_GZIP_GNU_LONGNAME_MANIFEST_SCHEMA => {
            verify_tar_gzip_gnu_longname_identity_vector_json(bytes)
        }
        schema => Err(VerifyError::new(format!("unsupported schema {schema:?}"))),
    }
}

pub fn verify_tar_gzip_pax_identity_vector_json(
    bytes: &[u8],
) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR/gzip/PAX manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: TarGzipPaxManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR/gzip/PAX JSON: {error}")))?;
    verify_tar_gzip_pax_manifest(&manifest)
}

pub fn verify_tar_gzip_gnu_longname_identity_vector_json(
    bytes: &[u8],
) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR/gzip/GNU long-name manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: TarGzipGnuLongNameManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR/gzip/GNU long-name JSON: {error}")))?;
    verify_tar_gzip_gnu_longname_manifest(&manifest)
}

pub fn verify_tar_gnu_longname_identity_vector_json(
    bytes: &[u8],
) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR/GNU long-name manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: TarGnuLongNameManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR/GNU long-name JSON: {error}")))?;
    verify_tar_gnu_longname_manifest(&manifest)
}

pub fn verify_tar_pax_identity_vector_json(
    bytes: &[u8],
) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR/PAX manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: TarPaxManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR/PAX JSON: {error}")))?;
    verify_tar_pax_manifest(&manifest)
}

pub fn verify_tar_gzip_identity_vector_json(
    bytes: &[u8],
) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR/gzip manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: TarGzipManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR/gzip JSON: {error}")))?;
    verify_tar_gzip_manifest(&manifest)
}

pub fn verify_zip64_identity_vector_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "ZIP64 manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: Zip64Manifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("ZIP64 JSON: {error}")))?;
    verify_zip64_manifest(&manifest)
}

pub fn verify_tar_layout_vector_json(bytes: &[u8]) -> Result<TarVerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR vector exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let vector: TarLayoutVector = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR vector JSON: {error}")))?;
    verify_tar_layout_vector(&vector)?;
    Ok(TarVerificationSummary {
        members: vector.members.len(),
    })
}

fn verify_tar_layout_vector(vector: &TarLayoutVector) -> Result<(), VerifyError> {
    if vector.schema != TAR_LAYOUT_VECTOR_SCHEMA
        || vector.tree_encoding != TAR_TREE_ENCODING
        || vector.layout_label != TAR_LAYOUT_LABEL
        || vector.content_encoding != TREE_ENCODING
        || vector.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported TAR vector contract"));
    }
    verify_digest(&vector.source.sha256, "TAR source digest")?;
    verify_digest(&vector.layout_root.sealr_tree_v2, "TAR layout root")?;
    verify_digest(&vector.content_root.sealr_tree_v1, "TAR content root")?;
    if vector.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("TAR vector member limit exceeded"));
    }
    validate_tar_covering(vector)?;
    let actual_layout = sha256_hex(&encode_tar_layout_vector(vector)?);
    if actual_layout != vector.layout_root.sealr_tree_v2 {
        return Err(VerifyError::new(format!(
            "TAR layout root mismatch: expected {}, calculated {actual_layout}",
            vector.layout_root.sealr_tree_v2
        )));
    }
    let actual_content = sha256_hex(&encode_tar_content_vector(vector)?);
    if actual_content != vector.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(format!(
            "TAR content root mismatch: expected {}, calculated {actual_content}",
            vector.content_root.sealr_tree_v1
        )));
    }
    Ok(())
}

fn validate_tar_covering(vector: &TarLayoutVector) -> Result<(), VerifyError> {
    let covering = &vector.covering;
    let records_end = range_end(covering.member_records, "TAR member covering")?;
    let terminator_end = range_end(covering.terminator, "TAR terminator")?;
    let source_end = range_end(covering.trailing_zeros, "TAR trailing zeros")?;
    if covering.member_records.offset != 0
        || covering.terminator.offset != records_end
        || covering.terminator.len != 1024
        || covering.trailing_zeros.offset != terminator_end
        || !source_end.is_multiple_of(512)
    {
        return Err(VerifyError::new(
            "TAR covering does not form one complete 512-byte-block source",
        ));
    }
    let mut paths = HashSet::new();
    let mut records: Vec<&TarVectorMember> = vector.members.iter().collect();
    records.sort_by_key(|member| member.header.offset);
    let mut expected_header = 0_u64;
    for member in records {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new("TAR member paths are empty or duplicate"));
        }
        if member.raw_name_bytes.is_empty() {
            return Err(VerifyError::new("TAR raw member name is empty"));
        }
        verify_digest(&member.header_sha256, "TAR header digest")?;
        verify_digest(&member.content_sha256, "TAR content digest")?;
        let header_end = range_end(member.header, "TAR member header")?;
        let payload_end = range_end(member.payload, "TAR member payload")?;
        let padding_end = range_end(member.padding, "TAR member padding")?;
        let expected_padding = (512 - (member.payload.len % 512)) % 512;
        if member.header.offset != expected_header
            || member.header.len != 512
            || member.payload.offset != header_end
            || member.payload.len != member.declared_uncomp_size
            || member.padding.offset != payload_end
            || member.padding.len != expected_padding
            || !padding_end.is_multiple_of(512)
            || member.actual_uncomp_size != member.declared_uncomp_size
        {
            return Err(VerifyError::new("TAR member record geometry is invalid"));
        }
        expected_header = padding_end;
    }
    if expected_header != records_end {
        return Err(VerifyError::new(
            "TAR member records do not fill their covering",
        ));
    }
    Ok(())
}

fn encode_tar_layout_vector(vector: &TarLayoutVector) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    encode_range(&mut body, vector.covering.member_records);
    encode_range(&mut body, vector.covering.terminator);
    encode_range(&mut body, vector.covering.trailing_zeros);
    let mut members: Vec<&TarVectorMember> = vector.members.iter().collect();
    members.sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_bytes(&mut body, &member.raw_name_bytes)?;
        push_u64(&mut body, member.declared_uncomp_size);
        encode_range(&mut body, member.header);
        encode_range(&mut body, member.payload);
        encode_range(&mut body, member.padding);
        push_u32(&mut body, member.mode);
        push_u64(&mut body, member.mtime);
        push_u32(&mut body, member.header_checksum);
        body.extend_from_slice(&decode_digest(&member.header_sha256, "TAR header digest")?);
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len())
                .map_err(|_| VerifyError::new("TAR normalization count exceeds u32"))?,
        );
        encode_normalization_actions(&mut body, &member.normalization_actions);
    }
    Ok(preimage(TAR_LAYOUT_LABEL, &body))
}

fn encode_tar_content_vector(vector: &TarLayoutVector) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    let mut members: Vec<&TarVectorMember> = vector.members.iter().collect();
    members.sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(&mut body, member.actual_uncomp_size);
        body.extend_from_slice(&decode_digest(
            &member.content_sha256,
            "TAR content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn encode_normalization_actions(output: &mut Vec<u8>, actions: &[NormalizationAction]) {
    for action in actions {
        match action {
            NormalizationAction::StripDirectoryTrailingSlash => output.push(NORM_STRIP_DIR_SLASH),
            NormalizationAction::DropDotComponent { component_index } => {
                output.push(NORM_DROP_DOT);
                push_u32(output, *component_index);
            }
        }
    }
}

fn range_end(range: ByteRange, label: &str) -> Result<u64, VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
}

fn verify_zip64_manifest(manifest: &Zip64Manifest) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != ZIP64_MANIFEST_SCHEMA
        || manifest.layout_encoding != ZIP64_TREE_ENCODING
        || manifest.layout_label != ZIP64_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported ZIP64 manifest contract"));
    }
    verify_zip64_profile(&manifest.profile)?;
    if manifest.cases.is_empty() {
        return Err(VerifyError::new("ZIP64 manifest has no cases"));
    }
    if manifest.cases.len() > MAX_CASES {
        return Err(VerifyError::new(format!(
            "ZIP64 manifest exceeds the {MAX_CASES}-case limit"
        )));
    }

    let mut case_ids = HashSet::new();
    for case in &manifest.cases {
        if case.id.is_empty() || !case_ids.insert(case.id.as_str()) {
            return Err(VerifyError::new("ZIP64 case ids are empty or duplicate"));
        }
        verify_zip64_case(case, &manifest.profile)
            .map_err(|error| error.context(&format!("ZIP64 case {}", case.id)))?;
    }

    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len(),
        content_roots: manifest.cases.len(),
    })
}

#[derive(Clone)]
struct ParsedPaxValue {
    raw: Vec<u8>,
    parsed_size: Option<u64>,
    source: TarPaxValueSource,
}

#[derive(Clone, Default)]
struct ParsedPaxOverrides {
    path: Option<ParsedPaxValue>,
    size: Option<ParsedPaxValue>,
}

struct ParsedPaxHeader {
    raw_name: Vec<u8>,
    mode: u32,
    size: u64,
    mtime: u64,
    checksum: u32,
    sha256: String,
    typeflag: u8,
}

fn verify_tar_pax_manifest(manifest: &TarPaxManifest) -> Result<VerificationSummary, VerifyError> {
    const EXPECTED_CASE_IDS: [&str; 2] = ["local-path-size", "global-local-precedence"];
    if manifest.schema != TAR_PAX_MANIFEST_SCHEMA
        || manifest.archive_ir_schema != TAR_PAX_IR_SCHEMA
        || manifest.layout_encoding != TAR_PAX_TREE_ENCODING
        || manifest.layout_label != TAR_PAX_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported TAR/PAX manifest contract"));
    }
    if manifest.cases.len() != EXPECTED_CASE_IDS.len()
        || manifest
            .cases
            .iter()
            .zip(EXPECTED_CASE_IDS)
            .any(|(case, expected)| case.id != expected)
    {
        return Err(VerifyError::new(
            "TAR/PAX v1 manifest must contain exactly the two canonical ordered cases",
        ));
    }
    verify_tar_pax_profile(&manifest.profile)?;
    let mut sources = HashSet::new();
    for case in &manifest.cases {
        if !sources.insert(case.source.sha256.as_str()) {
            return Err(VerifyError::new(
                "TAR/PAX canonical cases must bind distinct sources",
            ));
        }
        verify_tar_pax_case(case, &manifest.profile)
            .map_err(|error| error.context(&format!("case {:?}", case.id)))?;
    }
    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len(),
        content_roots: manifest.cases.len(),
    })
}

fn verify_tar_pax_profile(profile: &TarPaxProfileVector) -> Result<(), VerifyError> {
    if profile.id != TAR_PAX_PROFILE_SCHEMA {
        return Err(VerifyError::new("unsupported TAR/PAX profile identity"));
    }
    verify_digest(&profile.digest.sha256, "TAR/PAX profile digest")?;
    let canonical = tar_pax_profile_canonical_bytes()?;
    let actual = sha256_hex(&canonical);
    if actual != profile.digest.sha256 {
        return Err(VerifyError::new(format!(
            "TAR/PAX profile digest does not match its canonical definition: calculated {actual}"
        )));
    }
    Ok(())
}

fn tar_pax_profile_canonical_bytes() -> Result<Vec<u8>, VerifyError> {
    serde_json::to_vec(&TarPaxProfileDefinition {
        schema: TAR_PAX_PROFILE_SCHEMA,
        status: "supported-preview",
        format: "posix-pax",
        base_profile: TAR_PORTABLE_PROFILE_SCHEMA,
        base_profile_sha256: TAR_PORTABLE_PROFILE_DIGEST.to_owned(),
        extension_types: ["global-g", "local-x"],
        extension_carrier_names: "structurally-valid-ustar-text-not-destination-validated",
        underlying_member_names:
            "structurally-valid-ustar-text-destination-validated-only-when-effective",
        extension_materialization: "metadata-only-never-a-member",
        record_encoding: "decimal-length-space-keyword-equals-value-newline",
        length_encoding: "canonical-ascii-decimal-no-leading-zero-max-20-digits",
        record_consumption: "declared-length-exact-and-entire-payload-consumed",
        keywords: ["path", "size"],
        duplicate_keywords: "denied-within-one-extension",
        unknown_keywords: "denied",
        empty_values: "denied",
        path_values: "strict-utf8-portable-path-v1",
        size_values: "canonical-ascii-decimal-u64",
        precedence: "local-over-global-over-ustar",
        global_state: "fixed-path-and-size-fields-last-global-value-persists",
        local_state: "at-most-one-pending-header-consumed-by-exactly-one-file-or-directory",
        max_extension_payload_bytes: 64 * 1024,
        max_extension_headers: 1024,
        max_records_per_extension: 2,
        max_keyword_scan_bytes: 16,
        max_effective_path_bytes: "min-8191-and-256-times-policy-max-path-depth-minus-1",
        denied_features: [
            "gnu-long-name",
            "gnu-long-link",
            "sparse-file",
            "hard-link",
            "symbolic-link",
            "device-or-fifo",
            "base-256-numbers",
            "mixed-pax-and-gnu-state",
            "orphan-local-header",
            "concatenated-archive",
        ],
    })
    .map_err(|error| VerifyError::new(format!("TAR/PAX profile serialization: {error}")))
}

fn verify_tar_pax_case(
    case: &TarPaxCase,
    profile: &TarPaxProfileVector,
) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "TAR/PAX source bytes")?;
    if source.len() > MAX_DERIVED_TAR_BYTES as usize {
        return Err(VerifyError::new(format!(
            "TAR/PAX source exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&case.source.sha256, "TAR/PAX source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "TAR/PAX source bytes do not match their digest",
        ));
    }
    let ir = &case.archive_ir;
    if ir.schema != TAR_PAX_IR_SCHEMA
        || ir.profile != profile.id
        || ir.profile_digest != profile.digest.sha256
        || ir.source_digest.sha256 != case.source.sha256
        || ir.format != "tar-pax"
    {
        return Err(VerifyError::new(
            "TAR/PAX IR source, format, or profile identity does not match the case",
        ));
    }
    verify_tar_pax_source(&source, &ir.tar_covering, &ir.pax_extensions, &ir.members)?;

    let actual_preimage = encode_tar_pax_layout(ir)?;
    let committed_preimage = decode_hex(&case.layout_preimage_hex, "TAR/PAX layout preimage")?;
    if actual_preimage != committed_preimage {
        return Err(VerifyError::new(
            "TAR/PAX layout preimage does not match reconstructed evidence",
        ));
    }
    verify_digest(&case.layout_root.sealr_tree_v5, "TAR/PAX layout root")?;
    if sha256_hex(&actual_preimage) != case.layout_root.sealr_tree_v5 {
        return Err(VerifyError::new("TAR/PAX layout root mismatch"));
    }
    let content_preimage = encode_tar_pax_content(&ir.members)?;
    verify_digest(&case.content_root.sealr_tree_v1, "TAR/PAX content root")?;
    if sha256_hex(&content_preimage) != case.content_root.sealr_tree_v1 {
        return Err(VerifyError::new("TAR/PAX content root mismatch"));
    }
    Ok(())
}

fn verify_tar_pax_source(
    source: &[u8],
    tar_covering: &TarCovering,
    pax_extensions: &[TarPaxExtension],
    ir_members: &[TarPaxMember],
) -> Result<(), VerifyError> {
    if source.len() < 1024 || !source.len().is_multiple_of(512) {
        return Err(VerifyError::new(
            "TAR/PAX source is not a complete block-aligned archive",
        ));
    }
    if pax_extensions.len() > MAX_PAX_EXTENSIONS || ir_members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("TAR/PAX evidence exceeds verifier limits"));
    }
    let source_len = u64::try_from(source.len())
        .map_err(|_| VerifyError::new("TAR/PAX source length exceeds u64"))?;
    let mut offset = 0_u64;
    let mut extension_index = 0_usize;
    let mut member_index = 0_usize;
    let mut global = ParsedPaxOverrides::default();
    let mut local: Option<ParsedPaxOverrides> = None;
    let mut paths = HashSet::new();

    loop {
        let header_range = ByteRange { offset, len: 512 };
        let header = range_bytes(source, header_range, "TAR/PAX header")?;
        if header.iter().all(|byte| *byte == 0) {
            if local.is_some() {
                return Err(VerifyError::new("orphan local PAX extension"));
            }
            break;
        }
        let parsed = parse_tar_pax_header(header)?;
        match parsed.typeflag {
            b'g' | b'x' => {
                if local.is_some() {
                    return Err(VerifyError::new(
                        "local PAX extension is not immediately followed by a member",
                    ));
                }
                let extension = pax_extensions.get(extension_index).ok_or_else(|| {
                    VerifyError::new("source contains an undeclared PAX extension")
                })?;
                let kind = if parsed.typeflag == b'g' {
                    TarPaxExtensionKind::Global
                } else {
                    TarPaxExtensionKind::Local
                };
                if extension.kind != kind || parsed.size > MAX_PAX_EXTENSION_BYTES {
                    return Err(VerifyError::new(
                        "PAX extension kind or bounded payload size is invalid",
                    ));
                }
                let payload_offset = offset
                    .checked_add(512)
                    .ok_or_else(|| VerifyError::new("PAX payload offset overflow"))?;
                let padding_len = (512 - (parsed.size % 512)) % 512;
                let payload = ByteRange {
                    offset: payload_offset,
                    len: parsed.size,
                };
                let padding = ByteRange {
                    offset: checked_range_end(payload, "PAX extension payload")?,
                    len: padding_len,
                };
                verify_tar_pax_extension(
                    source,
                    extension,
                    extension_index,
                    header_range,
                    payload,
                    padding,
                    &parsed,
                )?;
                let update = parsed_pax_overrides(extension, extension_index)?;
                match kind {
                    TarPaxExtensionKind::Global => merge_pax_overrides(&mut global, update),
                    TarPaxExtensionKind::Local => local = Some(update),
                }
                offset = checked_range_end(padding, "PAX extension record")?;
                extension_index += 1;
            }
            0 | b'0' | b'5' => {
                let member = ir_members
                    .get(member_index)
                    .ok_or_else(|| VerifyError::new("source contains an undeclared PAX member"))?;
                let local_values = local.take();
                let (effective_name, path_source) =
                    resolve_pax_path(&parsed.raw_name, &global, local_values.as_ref())?;
                let (effective_size, size_source) =
                    resolve_pax_size(parsed.size, &global, local_values.as_ref())?;
                if !paths.insert(effective_name.clone()) {
                    return Err(VerifyError::new(
                        "TAR/PAX source resolves more than one member to the same path",
                    ));
                }
                let payload = ByteRange {
                    offset: offset
                        .checked_add(512)
                        .ok_or_else(|| VerifyError::new("PAX member payload offset overflow"))?,
                    len: effective_size,
                };
                let padding = ByteRange {
                    offset: checked_range_end(payload, "PAX member payload")?,
                    len: (512 - (effective_size % 512)) % 512,
                };
                verify_tar_pax_member(
                    source,
                    member,
                    header_range,
                    payload,
                    padding,
                    &parsed,
                    &effective_name,
                    path_source,
                    size_source,
                )?;
                offset = checked_range_end(padding, "PAX member record")?;
                member_index += 1;
            }
            typeflag => {
                return Err(VerifyError::new(format!(
                    "unsupported PAX typeflag 0x{typeflag:02x}"
                )));
            }
        }
    }

    if extension_index != pax_extensions.len() || member_index != ir_members.len() {
        return Err(VerifyError::new(
            "declared PAX extensions or members are not present in the source",
        ));
    }
    let terminator = ByteRange { offset, len: 1024 };
    let trailing = ByteRange {
        offset: checked_range_end(terminator, "PAX terminator")?,
        len: source_len
            .checked_sub(checked_range_end(terminator, "PAX terminator")?)
            .ok_or_else(|| VerifyError::new("PAX terminator extends beyond source"))?,
    };
    if tar_covering.member_records
        != (ByteRange {
            offset: 0,
            len: offset,
        })
        || tar_covering.terminator != terminator
        || tar_covering.trailing_zeros != trailing
        || range_bytes(source, terminator, "PAX terminator")?
            .iter()
            .any(|byte| *byte != 0)
        || range_bytes(source, trailing, "PAX trailing zeros")?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "TAR/PAX covering does not exactly bind the terminator and trailing blocks",
        ));
    }
    Ok(())
}

fn parse_tar_pax_header(header: &[u8]) -> Result<ParsedPaxHeader, VerifyError> {
    if header.len() != 512 || header[257..263] != *b"ustar\0" || header[263..265] != *b"00" {
        return Err(VerifyError::new(
            "PAX record header is not exact POSIX ustar",
        ));
    }
    if header[500..].iter().any(|byte| *byte != 0) || header[157..257].iter().any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "PAX record has nonzero reserved or linkname bytes",
        ));
    }
    if header[148..154]
        .iter()
        .any(|byte| !(b'0'..=b'7').contains(byte))
        || header[154] != 0
        || header[155] != b' '
    {
        return Err(VerifyError::new(
            "PAX checksum field is not six octal digits, NUL, space",
        ));
    }
    let declared = parse_tar_octal(&header[148..156], "PAX checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .try_fold(0_u32, |sum, (index, byte)| {
            sum.checked_add(u32::from(if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            }))
            .ok_or_else(|| VerifyError::new("PAX header checksum overflows u32"))
        })?;
    if declared != u64::from(actual) {
        return Err(VerifyError::new(
            "PAX header checksum does not match source bytes",
        ));
    }
    let mode = parse_tar_octal(&header[100..108], "PAX mode")?;
    let _uid = parse_tar_octal(&header[108..116], "PAX uid")?;
    let _gid = parse_tar_octal(&header[116..124], "PAX gid")?;
    let size = parse_tar_octal(&header[124..136], "PAX size")?;
    if header[156] == b'5' && size != 0 {
        return Err(VerifyError::new(
            "PAX directory has a nonzero underlying size",
        ));
    }
    let mtime = parse_tar_octal(&header[136..148], "PAX mtime")?;
    if mode > 0o7777
        || parse_tar_device_number(&header[329..337], "PAX devmajor")? != 0
        || parse_tar_device_number(&header[337..345], "PAX devminor")? != 0
    {
        return Err(VerifyError::new(
            "PAX numeric header fields are outside the profile",
        ));
    }
    verify_tar_owner_text(&header[265..297], "PAX uname")?;
    verify_tar_owner_text(&header[297..329], "PAX gname")?;
    let name = tar_text_field(&header[..100], "PAX name", false)?;
    let prefix = tar_text_field(&header[345..500], "PAX prefix", true)?;
    let mut raw_name = Vec::new();
    if !prefix.is_empty() {
        raw_name.extend_from_slice(prefix);
        raw_name.push(b'/');
    }
    raw_name.extend_from_slice(name);
    Ok(ParsedPaxHeader {
        raw_name,
        mode: u32::try_from(mode).map_err(|_| VerifyError::new("PAX mode exceeds u32"))?,
        size,
        mtime,
        checksum: actual,
        sha256: sha256_hex(header),
        typeflag: header[156],
    })
}

fn verify_tar_pax_extension(
    source: &[u8],
    extension: &TarPaxExtension,
    extension_index: usize,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    parsed: &ParsedPaxHeader,
) -> Result<(), VerifyError> {
    if extension.raw_name_bytes != parsed.raw_name
        || extension.header != header
        || extension.payload != payload
        || extension.padding != padding
        || extension.mode != parsed.mode
        || extension.mtime != parsed.mtime
        || extension.header_checksum != parsed.checksum
        || extension.header_sha256 != parsed.sha256
    {
        return Err(VerifyError::new(
            "PAX extension evidence disagrees with its source header or geometry",
        ));
    }
    verify_digest(&extension.header_sha256, "PAX extension header digest")?;
    verify_digest(&extension.payload_sha256, "PAX extension payload digest")?;
    let payload_bytes = range_bytes(source, payload, "PAX extension payload")?;
    if sha256_hex(payload_bytes) != extension.payload_sha256
        || range_bytes(source, padding, "PAX extension padding")?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "PAX extension payload digest or zero padding is invalid",
        ));
    }
    verify_tar_pax_records(payload_bytes, payload.offset, extension, extension_index)
}

fn verify_tar_pax_records(
    payload: &[u8],
    payload_offset: u64,
    extension: &TarPaxExtension,
    extension_index: usize,
) -> Result<(), VerifyError> {
    if extension.records.is_empty() || extension.records.len() > 2 {
        return Err(VerifyError::new(
            "PAX extension must contain one or two records",
        ));
    }
    let mut cursor = 0_usize;
    let mut saw_path = false;
    let mut saw_size = false;
    for (record_index, evidence) in extension.records.iter().enumerate() {
        let length_start = cursor;
        while cursor < payload.len() && payload[cursor].is_ascii_digit() {
            cursor += 1;
            if cursor - length_start > 20 {
                return Err(VerifyError::new("PAX record length exceeds 20 digits"));
            }
        }
        if cursor == length_start
            || cursor == payload.len()
            || payload[cursor] != b' '
            || (cursor - length_start > 1 && payload[length_start] == b'0')
        {
            return Err(VerifyError::new(
                "PAX record length syntax is not canonical",
            ));
        }
        let length = parse_pax_decimal(&payload[length_start..cursor], "PAX record length")?;
        let length = usize::try_from(length)
            .map_err(|_| VerifyError::new("PAX record length exceeds usize"))?;
        let record_end = length_start
            .checked_add(length)
            .ok_or_else(|| VerifyError::new("PAX record end overflows usize"))?;
        if record_end > payload.len() || length == 0 || payload[record_end - 1] != b'\n' {
            return Err(VerifyError::new(
                "PAX record does not consume its declared newline-terminated bytes",
            ));
        }
        cursor += 1;
        let keyword_start = cursor;
        while cursor < record_end && payload[cursor] != b'=' {
            cursor += 1;
            if cursor - keyword_start > 16 {
                return Err(VerifyError::new("PAX keyword exceeds scan bound"));
            }
        }
        if cursor == keyword_start || cursor >= record_end {
            return Err(VerifyError::new("PAX record has no keyword or equals sign"));
        }
        let keyword = match &payload[keyword_start..cursor] {
            b"path" if !saw_path => {
                saw_path = true;
                TarPaxKeyword::Path
            }
            b"size" if !saw_size => {
                saw_size = true;
                TarPaxKeyword::Size
            }
            b"path" | b"size" => {
                return Err(VerifyError::new("PAX extension repeats a keyword"));
            }
            _ => return Err(VerifyError::new("PAX extension uses an unknown keyword")),
        };
        cursor += 1;
        let value_start = cursor;
        let value_end = record_end - 1;
        if value_start == value_end {
            return Err(VerifyError::new("PAX record has an empty value"));
        }
        let value = &payload[value_start..value_end];
        let parsed_size = match keyword {
            TarPaxKeyword::Path => {
                verify_portable_pax_path(value)?;
                None
            }
            TarPaxKeyword::Size => Some(parse_pax_decimal(value, "PAX size value")?),
        };
        let length_start = u64::try_from(length_start)
            .map_err(|_| VerifyError::new("PAX record offset exceeds u64"))?;
        let length =
            u64::try_from(length).map_err(|_| VerifyError::new("PAX record length exceeds u64"))?;
        let value_start = u64::try_from(value_start)
            .map_err(|_| VerifyError::new("PAX value offset exceeds u64"))?;
        let value_len = u64::try_from(value.len())
            .map_err(|_| VerifyError::new("PAX value length exceeds u64"))?;
        let absolute_record = ByteRange {
            offset: payload_offset
                .checked_add(length_start)
                .ok_or_else(|| VerifyError::new("PAX record offset overflows u64"))?,
            len: length,
        };
        let absolute_value = ByteRange {
            offset: payload_offset
                .checked_add(value_start)
                .ok_or_else(|| VerifyError::new("PAX value offset overflows u64"))?,
            len: value_len,
        };
        if evidence.record != absolute_record
            || evidence.value != absolute_value
            || evidence.keyword != keyword
            || evidence.raw_value_bytes != value
            || evidence.parsed_size != parsed_size
        {
            return Err(VerifyError::new(format!(
                "PAX extension {extension_index} record {record_index} evidence disagrees with source bytes"
            )));
        }
        cursor = record_end;
    }
    if cursor != payload.len() {
        return Err(VerifyError::new(
            "PAX records do not consume the exact extension payload",
        ));
    }
    Ok(())
}

fn parse_pax_decimal(bytes: &[u8], label: &str) -> Result<u64, VerifyError> {
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(VerifyError::new(format!(
            "{label} is not canonical ASCII decimal"
        )));
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
    })
}

fn verify_portable_pax_path(bytes: &[u8]) -> Result<(), VerifyError> {
    let path =
        std::str::from_utf8(bytes).map_err(|_| VerifyError::new("PAX path is not strict UTF-8"))?;
    if path.is_empty()
        || path.len() > 8191
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || path.split('/').any(|component| {
            component.is_empty() || component == "." || component == ".." || component.len() > 255
        })
    {
        return Err(VerifyError::new(
            "PAX path is outside the portable destination grammar",
        ));
    }
    Ok(())
}

fn parsed_pax_overrides(
    extension: &TarPaxExtension,
    extension_index: usize,
) -> Result<ParsedPaxOverrides, VerifyError> {
    let mut update = ParsedPaxOverrides::default();
    for (record_index, record) in extension.records.iter().enumerate() {
        let source = match extension.kind {
            TarPaxExtensionKind::Global => TarPaxValueSource::Global {
                extension_index: u32::try_from(extension_index)
                    .map_err(|_| VerifyError::new("PAX extension index exceeds u32"))?,
                record_index: u32::try_from(record_index)
                    .map_err(|_| VerifyError::new("PAX record index exceeds u32"))?,
            },
            TarPaxExtensionKind::Local => TarPaxValueSource::Local {
                extension_index: u32::try_from(extension_index)
                    .map_err(|_| VerifyError::new("PAX extension index exceeds u32"))?,
                record_index: u32::try_from(record_index)
                    .map_err(|_| VerifyError::new("PAX record index exceeds u32"))?,
            },
        };
        let value = ParsedPaxValue {
            raw: record.raw_value_bytes.clone(),
            parsed_size: record.parsed_size,
            source,
        };
        match record.keyword {
            TarPaxKeyword::Path => update.path = Some(value),
            TarPaxKeyword::Size => update.size = Some(value),
        }
    }
    Ok(update)
}

fn merge_pax_overrides(current: &mut ParsedPaxOverrides, update: ParsedPaxOverrides) {
    if update.path.is_some() {
        current.path = update.path;
    }
    if update.size.is_some() {
        current.size = update.size;
    }
}

fn resolve_pax_path(
    base: &[u8],
    global: &ParsedPaxOverrides,
    local: Option<&ParsedPaxOverrides>,
) -> Result<(Vec<u8>, TarPaxValueSource), VerifyError> {
    let value = local
        .and_then(|values| values.path.as_ref())
        .or(global.path.as_ref());
    match value {
        Some(value) => Ok((value.raw.clone(), value.source)),
        None => {
            verify_portable_pax_path(base)?;
            Ok((base.to_vec(), TarPaxValueSource::Ustar))
        }
    }
}

fn resolve_pax_size(
    base: u64,
    global: &ParsedPaxOverrides,
    local: Option<&ParsedPaxOverrides>,
) -> Result<(u64, TarPaxValueSource), VerifyError> {
    let value = local
        .and_then(|values| values.size.as_ref())
        .or(global.size.as_ref());
    match value {
        Some(value) => Ok((
            value
                .parsed_size
                .ok_or_else(|| VerifyError::new("PAX size source does not name a size record"))?,
            value.source,
        )),
        None => Ok((base, TarPaxValueSource::Ustar)),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_tar_pax_member(
    source: &[u8],
    member: &TarPaxMember,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    parsed: &ParsedPaxHeader,
    effective_name: &[u8],
    path_source: TarPaxValueSource,
    size_source: TarPaxValueSource,
) -> Result<(), VerifyError> {
    let decoded = std::str::from_utf8(effective_name)
        .map_err(|_| VerifyError::new("effective PAX member name is not UTF-8"))?;
    verify_portable_pax_path(effective_name)?;
    let is_directory = parsed.typeflag == b'5';
    if is_directory && payload.len != 0 {
        return Err(VerifyError::new(
            "PAX directory has a nonzero effective size",
        ));
    }
    let tar = &member.tar_pax.tar;
    if member.raw_name_bytes != effective_name
        || member.decoded_name != decoded
        || member.canonical_path != decoded
        || member.components != decoded.split('/').collect::<Vec<_>>()
        || matches!(member.kind, MemberKind::Directory) != is_directory
        || member.declared_uncomp_size != payload.len
        || tar.header != header
        || tar.payload != payload
        || tar.padding != padding
        || tar.mode != parsed.mode
        || tar.mtime != parsed.mtime
        || tar.header_checksum != parsed.checksum
        || tar.header_sha256 != parsed.sha256
        || member.tar_pax.base_name_bytes != parsed.raw_name
        || member.tar_pax.base_size != parsed.size
        || member.tar_pax.path_source != path_source
        || member.tar_pax.size_source != size_source
        || member.actual_uncomp_size != payload.len
        || !matches!(member.verification, MemberVerification::Verified)
        || !member.normalization_actions.is_empty()
    {
        return Err(VerifyError::new(
            "PAX member evidence disagrees with source bytes or resolved state",
        ));
    }
    verify_digest(&tar.header_sha256, "PAX member header digest")?;
    verify_digest(&member.content_sha256, "PAX member content digest")?;
    let payload_bytes = range_bytes(source, payload, "PAX member payload")?;
    if sha256_hex(payload_bytes) != member.content_sha256
        || crc32_ieee_bytes(payload_bytes) != member.actual_crc
        || range_bytes(source, padding, "PAX member padding")?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "PAX member content digest, CRC, or padding is invalid",
        ));
    }
    Ok(())
}

fn encode_tar_pax_layout(ir: &TarPaxArchiveIr) -> Result<Vec<u8>, VerifyError> {
    Ok(preimage(
        TAR_PAX_LAYOUT_LABEL,
        &tar_pax_layout_body(&ir.tar_covering, &ir.pax_extensions, &ir.members)?,
    ))
}

fn tar_pax_layout_body(
    tar_covering: &TarCovering,
    pax_extensions: &[TarPaxExtension],
    ir_members: &[TarPaxMember],
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    encode_range(&mut body, tar_covering.member_records);
    encode_range(&mut body, tar_covering.terminator);
    encode_range(&mut body, tar_covering.trailing_zeros);
    push_u32(
        &mut body,
        u32::try_from(pax_extensions.len())
            .map_err(|_| VerifyError::new("PAX extension count exceeds u32"))?,
    );
    for extension in pax_extensions {
        body.push(match extension.kind {
            TarPaxExtensionKind::Global => PAX_EXTENSION_GLOBAL,
            TarPaxExtensionKind::Local => PAX_EXTENSION_LOCAL,
        });
        push_bytes(&mut body, &extension.raw_name_bytes)?;
        encode_range(&mut body, extension.header);
        encode_range(&mut body, extension.payload);
        encode_range(&mut body, extension.padding);
        push_u32(&mut body, extension.mode);
        push_u64(&mut body, extension.mtime);
        push_u32(&mut body, extension.header_checksum);
        body.extend_from_slice(&decode_digest(
            &extension.header_sha256,
            "PAX extension header digest",
        )?);
        body.extend_from_slice(&decode_digest(
            &extension.payload_sha256,
            "PAX extension payload digest",
        )?);
        push_u32(
            &mut body,
            u32::try_from(extension.records.len())
                .map_err(|_| VerifyError::new("PAX record count exceeds u32"))?,
        );
        for record in &extension.records {
            body.push(match record.keyword {
                TarPaxKeyword::Path => PAX_KEYWORD_PATH,
                TarPaxKeyword::Size => PAX_KEYWORD_SIZE,
            });
            encode_range(&mut body, record.record);
            encode_range(&mut body, record.value);
            push_bytes(&mut body, &record.raw_value_bytes)?;
            match record.parsed_size {
                Some(size) => {
                    body.push(1);
                    push_u64(&mut body, size);
                }
                None => body.push(0),
            }
        }
    }
    let mut members: Vec<_> = ir_members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("PAX member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_bytes(&mut body, &member.raw_name_bytes)?;
        push_bytes(&mut body, &member.tar_pax.base_name_bytes)?;
        push_u64(&mut body, member.declared_uncomp_size);
        push_u64(&mut body, member.tar_pax.base_size);
        encode_range(&mut body, member.tar_pax.tar.header);
        encode_range(&mut body, member.tar_pax.tar.payload);
        encode_range(&mut body, member.tar_pax.tar.padding);
        push_u32(&mut body, member.tar_pax.tar.mode);
        push_u64(&mut body, member.tar_pax.tar.mtime);
        push_u32(&mut body, member.tar_pax.tar.header_checksum);
        body.extend_from_slice(&decode_digest(
            &member.tar_pax.tar.header_sha256,
            "PAX member header digest",
        )?);
        encode_pax_value_source(&mut body, member.tar_pax.path_source);
        encode_pax_value_source(&mut body, member.tar_pax.size_source);
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len())
                .map_err(|_| VerifyError::new("PAX normalization count exceeds u32"))?,
        );
        encode_normalization_actions(&mut body, &member.normalization_actions);
    }
    Ok(body)
}

fn encode_pax_value_source(output: &mut Vec<u8>, source: TarPaxValueSource) {
    match source {
        TarPaxValueSource::Ustar => output.push(PAX_SOURCE_USTAR),
        TarPaxValueSource::Global {
            extension_index,
            record_index,
        } => {
            output.push(PAX_SOURCE_GLOBAL);
            push_u32(output, extension_index);
            push_u32(output, record_index);
        }
        TarPaxValueSource::Local {
            extension_index,
            record_index,
        } => {
            output.push(PAX_SOURCE_LOCAL);
            push_u32(output, extension_index);
            push_u32(output, record_index);
        }
    }
}

fn encode_tar_pax_content(ir_members: &[TarPaxMember]) -> Result<Vec<u8>, VerifyError> {
    let mut members: Vec<_> = ir_members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("PAX content member count exceeds u32"))?,
    );
    for member in members {
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "PAX content identity contains an unverified member",
            ));
        }
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(&mut body, member.actual_uncomp_size);
        body.extend_from_slice(&decode_digest(
            &member.content_sha256,
            "PAX member content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

#[derive(Clone)]
struct ParsedGnuLongNameState {
    path_bytes: Vec<u8>,
    carrier_index: u32,
}

struct ParsedGnuLongNameHeader {
    raw_name: Vec<u8>,
    mode: u32,
    size: u64,
    mtime: u64,
    checksum: u32,
    sha256: String,
    typeflag: u8,
}

fn verify_tar_gnu_longname_manifest(
    manifest: &TarGnuLongNameManifest,
) -> Result<VerificationSummary, VerifyError> {
    const EXPECTED_CASE_IDS: [&str; 2] = ["long-file", "arbitrary-carrier-directory-and-header"];
    if manifest.schema != TAR_GNU_LONGNAME_MANIFEST_SCHEMA
        || manifest.archive_ir_schema != TAR_GNU_LONGNAME_IR_SCHEMA
        || manifest.layout_encoding != TAR_GNU_LONGNAME_TREE_ENCODING
        || manifest.layout_label != TAR_GNU_LONGNAME_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new(
            "unsupported TAR/GNU long-name manifest contract",
        ));
    }
    if manifest.cases.len() != EXPECTED_CASE_IDS.len()
        || manifest
            .cases
            .iter()
            .zip(EXPECTED_CASE_IDS)
            .any(|(case, expected)| case.id != expected)
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name v1 manifest must contain exactly the two canonical ordered cases",
        ));
    }
    verify_tar_gnu_longname_profile(&manifest.profile)?;
    let mut sources = HashSet::new();
    for case in &manifest.cases {
        if !sources.insert(case.source.sha256.as_str()) {
            return Err(VerifyError::new(
                "TAR/GNU long-name canonical cases must bind distinct sources",
            ));
        }
        verify_tar_gnu_longname_case(case, &manifest.profile)
            .map_err(|error| error.context(&format!("case {:?}", case.id)))?;
    }
    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len(),
        content_roots: manifest.cases.len(),
    })
}

fn verify_tar_gnu_longname_profile(
    profile: &TarGnuLongNameProfileVector,
) -> Result<(), VerifyError> {
    if profile.id != TAR_GNU_LONGNAME_PROFILE_SCHEMA {
        return Err(VerifyError::new(
            "unsupported TAR/GNU long-name profile identity",
        ));
    }
    verify_digest(&profile.digest.sha256, "TAR/GNU long-name profile digest")?;
    let canonical = tar_gnu_longname_profile_canonical_bytes()?;
    let actual = sha256_hex(&canonical);
    if actual != profile.digest.sha256 {
        return Err(VerifyError::new(format!(
            "TAR/GNU long-name profile digest does not match its canonical definition: calculated {actual}"
        )));
    }
    Ok(())
}

fn tar_gnu_longname_profile_canonical_bytes() -> Result<Vec<u8>, VerifyError> {
    serde_json::to_vec(&TarGnuLongNameProfileDefinition {
        schema: TAR_GNU_LONGNAME_PROFILE_SCHEMA,
        status: "supported-preview",
        format: "old-gnu-tar-long-name-only",
        block_bytes: 512,
        header_magic_and_version: "7573746172202000",
        accepted_types: ["regular-0-or-nul", "directory-5-size-zero", "long-name-L"],
        numeric_encoding: "one-or-more-ascii-octal-digits;one-or-more-nul-or-space-terminators;no-leading-space;base256-denied",
        checksum: "six-octal-digits-nul-space;unsigned-byte-sum-with-spaces",
        fixed_text_fields: "name-may-fill-field;after-first-nul-all-bytes-zero",
        owner_names: "nul-terminated-printable-ascii;remaining-bytes-zero",
        mode: "ascii-octal-permission-bits<=07777",
        linkname: "all-zero",
        device_numbers: "all-zero-bytes-or-ascii-octal-zero;never-applied",
        gnu_tail: "header-345-through-511-all-zero",
        carrier_names:
            "structurally-valid-oldgnu-text-not-destination-validated-and-bound-as-evidence",
        carrier_payload:
            "strict-utf8-effective-path-followed-by-exactly-one-final-nul;no-embedded-nul",
        carrier_state:
            "at-most-one-pending-L-consumed-by-exactly-one-following-file-or-directory",
        physical_name_binding:
            "ordinary-header-name-bound-as-overridden-evidence-without-equality-rule",
        min_effective_path_bytes: 1,
        max_effective_path_bytes: "min-8191-and-256-times-policy-max-path-depth-minus-1",
        max_carrier_payload_bytes: 8192,
        max_carrier_headers: 1024,
        carrier_materialization: "metadata-only-never-a-member",
        member_padding: "zero-to-512-byte-boundary",
        termination: "two-zero-blocks;remaining-complete-blocks-zero",
        destination_metadata: "uid-gid-uname-gname-mtime-not-applied;mode-recorded-not-applied;setid-and-special-effects-never-applied",
        names: "strict-utf8-oldgnu-name-or-L-value",
        unicode_repertoire_version: "16.0.0",
        unicode_repertoire: "public-assigned-no-private-use",
        unicode_repertoire_implementation: "unicode-general-category-1.1.0-exact",
        character_restrictions: "unicode-16-general-category-cc;white-space-0085-00a0-1680-2000..200a-2028-2029-202f-205f-3000;bidi-control-061c-200e-200f-202a..202e-2066..2069",
        path_grammar: "jail-portable-v1:absolute-or-drive-denied;slash-only;empty-denied;dot-denied;dotdot-denied;colon-denied;ascii-illegal-003c-003e-0022-007c-003f-002a;trailing-dot-or-space-denied;duplicate-and-file-directory-topology-denied",
        reserved_names: "ascii-case-insensitive-stem-before-dot:CON,PRN,AUX,NUL,COM1,COM2,COM3,COM4,COM5,COM6,COM7,COM8,COM9,LPT1,LPT2,LPT3,LPT4,LPT5,LPT6,LPT7,LPT8,LPT9,COM¹,COM²,COM³,LPT¹,LPT²,LPT³",
        normalization_unicode_version: "17.0.0-stable-for-16.0.0-repertoire",
        normalization_implementation: "unicode-normalization-0.1.25-exact",
        case_folding_unicode_version: "16.0.0",
        case_folding_implementation: "caseless-0.2.2-exact",
        normalization: "unicode-17-full-nfc-over-unicode-16-repertoire-no-dot-component",
        case_collision: "unicode-16-full-default-case-fold-then-nfc",
        component_limit: "utf8-bytes<=255-and-utf16-code-units<=255",
        denied_features: [
            "pax-local-header",
            "pax-global-header",
            "gnu-long-link",
            "gnu-sparse",
            "gnu-incremental",
            "hard-link",
            "symbolic-link",
            "device-or-fifo",
            "base-256-numbers",
            "mixed-dialect-state",
            "orphan-or-chained-carrier",
            "multi-volume",
            "concatenated-archive",
        ],
    })
    .map_err(|error| {
        VerifyError::new(format!(
            "TAR/GNU long-name profile serialization: {error}"
        ))
    })
}

fn verify_tar_gnu_longname_case(
    case: &TarGnuLongNameCase,
    profile: &TarGnuLongNameProfileVector,
) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "TAR/GNU long-name source bytes")?;
    if source.len() > MAX_DERIVED_TAR_BYTES as usize {
        return Err(VerifyError::new(format!(
            "TAR/GNU long-name source exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&case.source.sha256, "TAR/GNU long-name source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "TAR/GNU long-name source bytes do not match their digest",
        ));
    }
    let ir = &case.archive_ir;
    if ir.schema != TAR_GNU_LONGNAME_IR_SCHEMA
        || ir.profile != profile.id
        || ir.profile_digest != profile.digest.sha256
        || ir.source_digest.sha256 != case.source.sha256
        || ir.format != "tar-gnu-longname"
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name IR source, format, or profile identity does not match the case",
        ));
    }
    verify_tar_gnu_longname_source(
        &source,
        &ir.tar_covering,
        &ir.gnu_longname_carriers,
        &ir.members,
    )?;

    let actual_preimage = encode_tar_gnu_longname_layout(ir)?;
    let committed_preimage = decode_hex(
        &case.layout_preimage_hex,
        "TAR/GNU long-name layout preimage",
    )?;
    if actual_preimage != committed_preimage {
        return Err(VerifyError::new(
            "TAR/GNU long-name layout preimage does not match reconstructed evidence",
        ));
    }
    verify_digest(
        &case.layout_root.sealr_tree_v6,
        "TAR/GNU long-name layout root",
    )?;
    if sha256_hex(&actual_preimage) != case.layout_root.sealr_tree_v6 {
        return Err(VerifyError::new("TAR/GNU long-name layout root mismatch"));
    }
    let content_preimage = encode_tar_gnu_longname_content(&ir.members)?;
    verify_digest(
        &case.content_root.sealr_tree_v1,
        "TAR/GNU long-name content root",
    )?;
    if sha256_hex(&content_preimage) != case.content_root.sealr_tree_v1 {
        return Err(VerifyError::new("TAR/GNU long-name content root mismatch"));
    }
    Ok(())
}

fn verify_tar_gnu_longname_source(
    source: &[u8],
    tar_covering: &TarCovering,
    gnu_longname_carriers: &[TarGnuLongNameCarrier],
    ir_members: &[TarGnuLongNameMember],
) -> Result<(), VerifyError> {
    if source.len() < 1024 || !source.len().is_multiple_of(512) {
        return Err(VerifyError::new(
            "TAR/GNU long-name source is not a complete block-aligned archive",
        ));
    }
    if gnu_longname_carriers.len() > MAX_GNU_LONGNAME_CARRIERS
        || ir_members.len() > MAX_MEMBERS_PER_CASE
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name evidence exceeds verifier limits",
        ));
    }
    let source_len = u64::try_from(source.len())
        .map_err(|_| VerifyError::new("TAR/GNU long-name source length exceeds u64"))?;
    let mut offset = 0_u64;
    let mut carrier_index = 0_usize;
    let mut member_index = 0_usize;
    let mut pending: Option<ParsedGnuLongNameState> = None;
    let mut paths = HashSet::new();

    loop {
        let header_range = ByteRange { offset, len: 512 };
        let header = range_bytes(source, header_range, "TAR/GNU long-name header")?;
        if header.iter().all(|byte| *byte == 0) {
            if pending.is_some() {
                return Err(VerifyError::new("orphan TAR/GNU long-name carrier"));
            }
            break;
        }
        let parsed = parse_tar_gnu_longname_header(header)?;
        match parsed.typeflag {
            b'L' => {
                if pending.is_some() {
                    return Err(VerifyError::new(
                        "TAR/GNU long-name carrier is chained instead of being consumed",
                    ));
                }
                if parsed.size < 2 || parsed.size > MAX_GNU_LONGNAME_PAYLOAD_BYTES {
                    return Err(VerifyError::new(
                        "TAR/GNU long-name carrier payload is outside the 2 through 8192-byte bound",
                    ));
                }
                let carrier = gnu_longname_carriers.get(carrier_index).ok_or_else(|| {
                    VerifyError::new("source contains an undeclared TAR/GNU long-name carrier")
                })?;
                let payload = ByteRange {
                    offset: offset.checked_add(512).ok_or_else(|| {
                        VerifyError::new("TAR/GNU long-name carrier payload offset overflows")
                    })?,
                    len: parsed.size,
                };
                let padding = ByteRange {
                    offset: checked_range_end(payload, "TAR/GNU long-name carrier payload")?,
                    len: (512 - (parsed.size % 512)) % 512,
                };
                let payload_bytes =
                    range_bytes(source, payload, "TAR/GNU long-name carrier payload")?;
                if payload_bytes.last() != Some(&0)
                    || payload_bytes[..payload_bytes.len() - 1].contains(&0)
                {
                    return Err(VerifyError::new(
                        "TAR/GNU long-name carrier does not contain one final NUL",
                    ));
                }
                let path_bytes = &payload_bytes[..payload_bytes.len() - 1];
                std::str::from_utf8(path_bytes).map_err(|_| {
                    VerifyError::new("TAR/GNU long-name carrier path is not strict UTF-8")
                })?;
                let path_range = ByteRange {
                    offset: payload.offset,
                    len: payload.len - 1,
                };
                if carrier.raw_name_bytes != parsed.raw_name
                    || carrier.path_bytes != path_bytes
                    || carrier.header != header_range
                    || carrier.payload != payload
                    || carrier.path != path_range
                    || carrier.padding != padding
                    || carrier.mode != parsed.mode
                    || carrier.mtime != parsed.mtime
                    || carrier.header_checksum != parsed.checksum
                    || carrier.header_sha256 != parsed.sha256
                    || carrier.payload_sha256 != sha256_hex(payload_bytes)
                    || range_bytes(source, padding, "TAR/GNU long-name carrier padding")?
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(VerifyError::new(
                        "TAR/GNU long-name carrier evidence disagrees with source bytes or geometry",
                    ));
                }
                verify_digest(
                    &carrier.header_sha256,
                    "TAR/GNU long-name carrier header digest",
                )?;
                verify_digest(
                    &carrier.payload_sha256,
                    "TAR/GNU long-name carrier payload digest",
                )?;
                pending = Some(ParsedGnuLongNameState {
                    path_bytes: path_bytes.to_vec(),
                    carrier_index: u32::try_from(carrier_index).map_err(|_| {
                        VerifyError::new("TAR/GNU long-name carrier index exceeds u32")
                    })?,
                });
                carrier_index += 1;
                offset = checked_range_end(padding, "TAR/GNU long-name carrier record")?;
            }
            0 | b'0' | b'5' => {
                let member = ir_members.get(member_index).ok_or_else(|| {
                    VerifyError::new("source contains an undeclared TAR/GNU long-name member")
                })?;
                let state = pending.take();
                let (effective_name, path_source) = match state {
                    Some(state) => (
                        state.path_bytes,
                        TarGnuLongNamePathSource::Carrier {
                            carrier_index: state.carrier_index,
                        },
                    ),
                    None => (parsed.raw_name.clone(), TarGnuLongNamePathSource::Header),
                };
                let payload = ByteRange {
                    offset: offset.checked_add(512).ok_or_else(|| {
                        VerifyError::new("TAR/GNU long-name member payload offset overflows")
                    })?,
                    len: parsed.size,
                };
                let padding = ByteRange {
                    offset: checked_range_end(payload, "TAR/GNU long-name member payload")?,
                    len: (512 - (parsed.size % 512)) % 512,
                };
                let canonical = verify_tar_gnu_longname_member(
                    source,
                    member,
                    header_range,
                    payload,
                    padding,
                    &parsed,
                    &effective_name,
                    path_source,
                )?;
                if !paths.insert(canonical) {
                    return Err(VerifyError::new(
                        "TAR/GNU long-name source resolves duplicate member paths",
                    ));
                }
                member_index += 1;
                offset = checked_range_end(padding, "TAR/GNU long-name member record")?;
            }
            typeflag => {
                return Err(VerifyError::new(format!(
                    "unsupported TAR/GNU long-name typeflag 0x{typeflag:02x}"
                )));
            }
        }
    }

    if carrier_index != gnu_longname_carriers.len() || member_index != ir_members.len() {
        return Err(VerifyError::new(
            "declared TAR/GNU long-name carriers or members are not present in the source",
        ));
    }
    let terminator = ByteRange { offset, len: 1024 };
    let terminator_end = checked_range_end(terminator, "TAR/GNU long-name terminator")?;
    let trailing = ByteRange {
        offset: terminator_end,
        len: source_len.checked_sub(terminator_end).ok_or_else(|| {
            VerifyError::new("TAR/GNU long-name terminator extends beyond source")
        })?,
    };
    if tar_covering.member_records
        != (ByteRange {
            offset: 0,
            len: offset,
        })
        || tar_covering.terminator != terminator
        || tar_covering.trailing_zeros != trailing
        || range_bytes(source, terminator, "TAR/GNU long-name terminator")?
            .iter()
            .any(|byte| *byte != 0)
        || range_bytes(source, trailing, "TAR/GNU long-name trailing zeros")?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name covering does not exactly bind the terminator and trailing blocks",
        ));
    }
    Ok(())
}

fn parse_tar_gnu_longname_header(header: &[u8]) -> Result<ParsedGnuLongNameHeader, VerifyError> {
    if header.len() != 512 || header[257..265] != *b"ustar  \0" {
        return Err(VerifyError::new(
            "TAR/GNU long-name header is not exact old-GNU magic and version",
        ));
    }
    if header[157..257].iter().any(|byte| *byte != 0) || header[345..].iter().any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name header has nonzero linkname, sparse, time, or reserved bytes",
        ));
    }
    if header[148..154]
        .iter()
        .any(|byte| !(b'0'..=b'7').contains(byte))
        || header[154] != 0
        || header[155] != b' '
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name checksum field is not six octal digits, NUL, space",
        ));
    }
    let declared = parse_tar_octal(&header[148..156], "TAR/GNU long-name checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .try_fold(0_u32, |sum, (index, byte)| {
            sum.checked_add(u32::from(if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            }))
            .ok_or_else(|| VerifyError::new("TAR/GNU long-name checksum overflows u32"))
        })?;
    if declared != u64::from(actual) {
        return Err(VerifyError::new(
            "TAR/GNU long-name header checksum does not match source bytes",
        ));
    }
    let typeflag = header[156];
    if !matches!(typeflag, 0 | b'0' | b'5' | b'L') {
        return Err(VerifyError::new(format!(
            "unsupported TAR/GNU long-name typeflag 0x{typeflag:02x}"
        )));
    }
    let mode = parse_tar_octal(&header[100..108], "TAR/GNU long-name mode")?;
    let _uid = parse_tar_octal(&header[108..116], "TAR/GNU long-name uid")?;
    let _gid = parse_tar_octal(&header[116..124], "TAR/GNU long-name gid")?;
    let size = parse_tar_octal(&header[124..136], "TAR/GNU long-name size")?;
    let mtime = parse_tar_octal(&header[136..148], "TAR/GNU long-name mtime")?;
    if typeflag == b'5' && size != 0 {
        return Err(VerifyError::new(
            "TAR/GNU long-name directory has a nonzero size",
        ));
    }
    if mode > 0o7777
        || parse_tar_device_number(&header[329..337], "TAR/GNU long-name devmajor")? != 0
        || parse_tar_device_number(&header[337..345], "TAR/GNU long-name devminor")? != 0
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name numeric fields are outside the profile",
        ));
    }
    verify_tar_owner_text(&header[265..297], "TAR/GNU long-name uname")?;
    verify_tar_owner_text(&header[297..329], "TAR/GNU long-name gname")?;
    let raw_name = tar_text_field(&header[..100], "TAR/GNU long-name name", false)?.to_vec();
    Ok(ParsedGnuLongNameHeader {
        raw_name,
        mode: u32::try_from(mode)
            .map_err(|_| VerifyError::new("TAR/GNU long-name mode exceeds u32"))?,
        size,
        mtime,
        checksum: actual,
        sha256: sha256_hex(header),
        typeflag,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_tar_gnu_longname_member(
    source: &[u8],
    member: &TarGnuLongNameMember,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    parsed: &ParsedGnuLongNameHeader,
    effective_name: &[u8],
    path_source: TarGnuLongNamePathSource,
) -> Result<String, VerifyError> {
    let decoded = std::str::from_utf8(effective_name)
        .map_err(|_| VerifyError::new("effective TAR/GNU long-name path is not strict UTF-8"))?;
    let is_directory = parsed.typeflag == b'5';
    let (canonical, components, strip_directory_slash) =
        verify_portable_gnu_longname_path(decoded, is_directory)?;
    let normalization_matches = if strip_directory_slash {
        member.normalization_actions.len() == 1
            && matches!(
                member.normalization_actions.first(),
                Some(NormalizationAction::StripDirectoryTrailingSlash)
            )
    } else {
        member.normalization_actions.is_empty()
    };
    let tar = &member.tar_gnu_longname.tar;
    if member.raw_name_bytes != effective_name
        || member.decoded_name != decoded
        || member.canonical_path != canonical
        || member.components != components
        || matches!(member.kind, MemberKind::Directory) != is_directory
        || member.declared_uncomp_size != parsed.size
        || tar.header != header
        || tar.payload != payload
        || tar.padding != padding
        || tar.mode != parsed.mode
        || tar.mtime != parsed.mtime
        || tar.header_checksum != parsed.checksum
        || tar.header_sha256 != parsed.sha256
        || member.tar_gnu_longname.base_name_bytes != parsed.raw_name
        || member.tar_gnu_longname.path_source != path_source
        || member.actual_uncomp_size != parsed.size
        || !matches!(member.verification, MemberVerification::Verified)
        || !normalization_matches
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name member evidence disagrees with source bytes or resolved state",
        ));
    }
    verify_digest(&tar.header_sha256, "TAR/GNU long-name member header digest")?;
    verify_digest(
        &member.content_sha256,
        "TAR/GNU long-name member content digest",
    )?;
    let payload_bytes = range_bytes(source, payload, "TAR/GNU long-name member payload")?;
    if sha256_hex(payload_bytes) != member.content_sha256
        || crc32_ieee_bytes(payload_bytes) != member.actual_crc
        || range_bytes(source, padding, "TAR/GNU long-name member padding")?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name member content digest, CRC, or padding is invalid",
        ));
    }
    Ok(canonical)
}

fn verify_portable_gnu_longname_path(
    decoded: &str,
    is_directory: bool,
) -> Result<(String, Vec<String>, bool), VerifyError> {
    if decoded.is_empty()
        || decoded.len() > 8191
        || decoded.starts_with('/')
        || decoded.contains('\\')
        || decoded
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(VerifyError::new(
            "TAR/GNU long-name path is outside the portable destination grammar",
        ));
    }
    let strip_directory_slash = is_directory && decoded.ends_with('/');
    if !is_directory && decoded.ends_with('/') {
        return Err(VerifyError::new(
            "TAR/GNU long-name file path has a trailing slash",
        ));
    }
    let canonical = if strip_directory_slash {
        &decoded[..decoded.len() - 1]
    } else {
        decoded
    };
    if canonical.is_empty() {
        return Err(VerifyError::new(
            "TAR/GNU long-name path becomes empty after directory normalization",
        ));
    }
    let components: Vec<String> = canonical.split('/').map(str::to_owned).collect();
    if components.iter().any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.encode_utf16().count() > 255
            || component.contains(':')
            || component
                .bytes()
                .any(|byte| matches!(byte, b'<' | b'>' | b'"' | b'|' | b'?' | b'*'))
            || component.ends_with('.')
            || component.ends_with(' ')
    }) {
        return Err(VerifyError::new(
            "TAR/GNU long-name path component is outside the portable destination grammar",
        ));
    }
    Ok((canonical.to_owned(), components, strip_directory_slash))
}

fn encode_tar_gnu_longname_layout(ir: &TarGnuLongNameArchiveIr) -> Result<Vec<u8>, VerifyError> {
    Ok(preimage(
        TAR_GNU_LONGNAME_LAYOUT_LABEL,
        &tar_gnu_longname_layout_body(&ir.tar_covering, &ir.gnu_longname_carriers, &ir.members)?,
    ))
}

fn tar_gnu_longname_layout_body(
    tar_covering: &TarCovering,
    gnu_longname_carriers: &[TarGnuLongNameCarrier],
    ir_members: &[TarGnuLongNameMember],
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    encode_range(&mut body, tar_covering.member_records);
    encode_range(&mut body, tar_covering.terminator);
    encode_range(&mut body, tar_covering.trailing_zeros);
    push_u32(
        &mut body,
        u32::try_from(gnu_longname_carriers.len())
            .map_err(|_| VerifyError::new("TAR/GNU long-name carrier count exceeds u32"))?,
    );
    for carrier in gnu_longname_carriers {
        push_bytes(&mut body, &carrier.raw_name_bytes)?;
        push_bytes(&mut body, &carrier.path_bytes)?;
        encode_range(&mut body, carrier.header);
        encode_range(&mut body, carrier.payload);
        encode_range(&mut body, carrier.path);
        encode_range(&mut body, carrier.padding);
        push_u32(&mut body, carrier.mode);
        push_u64(&mut body, carrier.mtime);
        push_u32(&mut body, carrier.header_checksum);
        body.extend_from_slice(&decode_digest(
            &carrier.header_sha256,
            "TAR/GNU long-name carrier header digest",
        )?);
        body.extend_from_slice(&decode_digest(
            &carrier.payload_sha256,
            "TAR/GNU long-name carrier payload digest",
        )?);
    }
    let mut members: Vec<_> = ir_members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR/GNU long-name member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_bytes(&mut body, &member.raw_name_bytes)?;
        push_bytes(&mut body, &member.tar_gnu_longname.base_name_bytes)?;
        push_u64(&mut body, member.declared_uncomp_size);
        encode_range(&mut body, member.tar_gnu_longname.tar.header);
        encode_range(&mut body, member.tar_gnu_longname.tar.payload);
        encode_range(&mut body, member.tar_gnu_longname.tar.padding);
        push_u32(&mut body, member.tar_gnu_longname.tar.mode);
        push_u64(&mut body, member.tar_gnu_longname.tar.mtime);
        push_u32(&mut body, member.tar_gnu_longname.tar.header_checksum);
        body.extend_from_slice(&decode_digest(
            &member.tar_gnu_longname.tar.header_sha256,
            "TAR/GNU long-name member header digest",
        )?);
        match member.tar_gnu_longname.path_source {
            TarGnuLongNamePathSource::Header => body.push(GNU_PATH_SOURCE_HEADER),
            TarGnuLongNamePathSource::Carrier { carrier_index } => {
                body.push(GNU_PATH_SOURCE_CARRIER);
                push_u32(&mut body, carrier_index);
            }
        }
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len()).map_err(|_| {
                VerifyError::new("TAR/GNU long-name normalization count exceeds u32")
            })?,
        );
        encode_normalization_actions(&mut body, &member.normalization_actions);
    }
    Ok(body)
}

fn encode_tar_gnu_longname_content(
    ir_members: &[TarGnuLongNameMember],
) -> Result<Vec<u8>, VerifyError> {
    let mut members: Vec<_> = ir_members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR/GNU long-name content member count exceeds u32"))?,
    );
    for member in members {
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "TAR/GNU long-name content identity contains an unverified member",
            ));
        }
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(&mut body, member.actual_uncomp_size);
        body.extend_from_slice(&decode_digest(
            &member.content_sha256,
            "TAR/GNU long-name member content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn verify_zip64_profile(profile: &Zip64ProfileVector) -> Result<(), VerifyError> {
    if profile.id != ZIP64_PROFILE_SCHEMA {
        return Err(VerifyError::new("unsupported ZIP64 profile id"));
    }
    verify_digest(&profile.digest.sha256, "ZIP64 profile digest")?;
    let canonical = zip64_profile_canonical_bytes()?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "ZIP64 profile digest does not match the independently reconstructed profile",
        ));
    }
    Ok(())
}

fn zip64_profile_canonical_bytes() -> Result<Vec<u8>, VerifyError> {
    const fn rule(
        bit: u8,
        disposition: &'static str,
        meaning: &'static str,
    ) -> Zip64ProfileBitRule {
        Zip64ProfileBitRule {
            bit,
            mask: 1_u16 << bit,
            disposition,
            meaning,
        }
    }
    let definition = Zip64ProfileDefinition {
        schema: ZIP64_PROFILE_SCHEMA,
        format: "zip64",
        methods: [0, 8],
        general_purpose_bits: [
            rule(0, "denied", "traditional-encryption"),
            rule(1, "denied", "method-dependent-option-1"),
            rule(2, "denied", "method-dependent-option-2"),
            rule(3, "semantic", "data-descriptor"),
            rule(4, "denied", "enhanced-deflating"),
            rule(5, "denied", "compressed-patched-data"),
            rule(6, "denied", "strong-encryption"),
            rule(7, "denied", "unused"),
            rule(8, "denied", "unused"),
            rule(9, "denied", "unused"),
            rule(10, "denied", "unused"),
            rule(11, "denied", "utf8-name"),
            rule(12, "denied", "reserved-enhanced-compression"),
            rule(13, "denied", "masked-local-header"),
            rule(14, "denied", "alternate-streams"),
            rule(15, "denied", "reserved"),
        ],
        names: "strict-ascii",
        extra_fields: "exactly-one-semantic-zip64-per-site-or-none-all-other-ids-denied",
        local_zip64: "exact-u-c-or-cpython-zero-pair-or-zip-rs-max-pair",
        central_zip64: "unique-fixed-order-u-c-o-mask-with-exact-redundancy",
        descriptor_width: "zip64-iff-local-zip64-or-resolved-size-at-least-u32-max",
        descriptors: "signed-only-exact-crc-compressed-uncompressed",
        global_end_records: "optional-fixed-56-byte-eocd-plus-adjacent-20-byte-locator",
        spanning: "denied-single-disk-only",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-producer-compatible-lfh-cdh-descriptor-and-end-records",
    };
    serde_json::to_vec(&definition)
        .map_err(|error| VerifyError::new(format!("ZIP64 profile serialization: {error}")))
}

fn verify_zip64_case(case: &Zip64Case, profile: &Zip64ProfileVector) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "ZIP64 source_bytes_hex")?;
    verify_digest(&case.source.sha256, "ZIP64 source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "ZIP64 source bytes do not match source digest",
        ));
    }
    let ir = &case.archive_ir;
    if ir.schema != ZIP64_IR_SCHEMA
        || ir.profile != profile.id
        || ir.profile_digest != profile.digest.sha256
        || ir.source_digest.sha256 != case.source.sha256
        || ir.format != "zip64"
    {
        return Err(VerifyError::new(
            "ZIP64 IR source, format, or profile identity does not match the case",
        ));
    }
    validate_zip64_ir(ir)?;
    verify_zip64_covering(&source, ir)?;

    verify_digest(&case.layout_root.sealr_tree_v3, "ZIP64 layout root")?;
    let expected_preimage = decode_hex(&case.layout_preimage_hex, "ZIP64 layout preimage")?;
    let actual_preimage = encode_zip64_layout(ir)?;
    if actual_preimage != expected_preimage {
        return Err(VerifyError::new(
            "ZIP64 layout preimage does not match reconstructed evidence",
        ));
    }
    let actual_layout = sha256_hex(&actual_preimage);
    if actual_layout != case.layout_root.sealr_tree_v3 {
        return Err(VerifyError::new(format!(
            "ZIP64 layout root mismatch: expected {}, calculated {actual_layout}",
            case.layout_root.sealr_tree_v3
        )));
    }

    verify_digest(&case.content_root.sealr_tree_v1, "ZIP64 content root")?;
    let actual_content = sha256_hex(&encode_zip64_content(ir)?);
    if actual_content != case.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(format!(
            "ZIP64 content root mismatch: expected {}, calculated {actual_content}",
            case.content_root.sealr_tree_v1
        )));
    }
    Ok(())
}

fn validate_zip64_ir(ir: &Zip64ArchiveIr) -> Result<(), VerifyError> {
    if ir.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("ZIP64 IR member limit exceeded"));
    }
    u32::try_from(ir.members.len())
        .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?;
    let mut paths = HashSet::new();
    for member in &ir.members {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new(
                "ZIP64 canonical paths are empty or duplicate",
            ));
        }
        if member.raw_name_bytes.is_empty()
            || !member.raw_name_bytes.is_ascii()
            || member.decoded_name.as_bytes() != member.raw_name_bytes
            || member.components.join("/") != member.canonical_path
        {
            return Err(VerifyError::new("ZIP64 member name evidence is invalid"));
        }
        if !matches!(member.method, 0 | 8) || !matches!(member.flags, 0 | 0x0008) {
            return Err(VerifyError::new("ZIP64 member method or flags are denied"));
        }
        for (range, label) in [
            (member.source_ranges.local_header, "ZIP64 local header"),
            (
                member.source_ranges.compressed_payload,
                "ZIP64 compressed payload",
            ),
            (member.source_ranges.central_header, "ZIP64 central header"),
        ] {
            validate_range(range, label)?;
        }
        if let Some(range) = member.source_ranges.data_descriptor {
            validate_range(range, "ZIP64 data descriptor")?;
        }
        let mut sites = HashSet::new();
        for extra in &member.extra_fields {
            validate_range(extra.header_range, "ZIP64 extra header")?;
            validate_range(extra.data_range, "ZIP64 extra data")?;
            if extra.id != 1
                || !matches!(extra.disposition, ExtraDisposition::Semantic)
                || extra.header_range.len != 4
                || checked_range_end(extra.header_range, "ZIP64 extra header")?
                    != extra.data_range.offset
                || !sites.insert(extra.site)
            {
                return Err(VerifyError::new(
                    "ZIP64 extra evidence is outside the closed semantic language",
                ));
            }
        }
        if member.zip64.central_presence_mask > 0b111
            || member.zip64.central_legacy_sentinel_mask > 0b111
            || member.zip64.local_legacy_sentinel_mask > 0b11
        {
            return Err(VerifyError::new("ZIP64 evidence mask is invalid"));
        }
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "ZIP64 conformance content requires verified members",
            ));
        }
        let actual_size = member
            .actual_uncomp_size
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual size"))?;
        let actual_crc = member
            .actual_crc
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual CRC"))?;
        let content_digest = member
            .content_sha256
            .as_deref()
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no content digest"))?;
        verify_digest(content_digest, "ZIP64 member content digest")?;
        if actual_size != member.declared_uncomp_size || actual_crc != member.declared_crc {
            return Err(VerifyError::new(
                "ZIP64 verified member facts differ from their declarations",
            ));
        }
    }
    Ok(())
}

fn verify_tar_gzip_manifest(
    manifest: &TarGzipManifest,
) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != TAR_GZIP_MANIFEST_SCHEMA
        || manifest.archive_ir_schema != TAR_GZIP_IR_SCHEMA
        || manifest.layout_encoding != TAR_GZIP_TREE_ENCODING
        || manifest.layout_label != TAR_GZIP_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported TAR/gzip manifest contract"));
    }
    const EXPECTED_CASE_IDS: [&str; 2] = ["optional-default", "minimal-stored-deflate"];
    if manifest.cases.len() != EXPECTED_CASE_IDS.len()
        || manifest
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .ne(EXPECTED_CASE_IDS)
    {
        return Err(VerifyError::new(
            "TAR/gzip v1 manifest must contain exactly the two canonical ordered cases",
        ));
    }
    verify_tar_gzip_transform(&manifest.transform)?;
    verify_tar_gzip_profile(
        &manifest.profile,
        &manifest.inner_profile,
        &manifest.transform,
    )?;
    let derived = verify_tar_gzip_derived_tar(&manifest.derived_tar)?;
    let raw_layout = encode_tar_gzip_inner_layout(&manifest.derived_tar)?;
    let committed_raw_preimage = decode_hex(
        &manifest.derived_tar.raw_layout_preimage_hex,
        "raw TAR layout preimage",
    )?;
    if raw_layout != committed_raw_preimage {
        return Err(VerifyError::new(
            "raw TAR layout preimage does not match derived evidence",
        ));
    }
    verify_digest(
        &manifest.derived_tar.raw_layout_root.sealr_tree_v2,
        "raw TAR layout root",
    )?;
    if sha256_hex(&raw_layout) != manifest.derived_tar.raw_layout_root.sealr_tree_v2 {
        return Err(VerifyError::new("raw TAR layout root mismatch"));
    }
    let content_preimage = encode_tar_gzip_content(&manifest.derived_tar)?;
    verify_digest(
        &manifest.derived_tar.content_root.sealr_tree_v1,
        "derived TAR content root",
    )?;
    if sha256_hex(&content_preimage) != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new("derived TAR content root mismatch"));
    }

    let mut source_digests = HashSet::new();
    let mut layout_roots = HashSet::new();
    let mut compressed_payload_digests = HashSet::new();
    for case in &manifest.cases {
        verify_tar_gzip_case(case, manifest, &derived)
            .map_err(|error| error.context(&format!("TAR/gzip case {}", case.id)))?;
        source_digests.insert(case.source.sha256.as_str());
        layout_roots.insert(case.layout_root.sealr_tree_v4.as_str());
        let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
        compressed_payload_digests.insert(sha256_hex(range_bytes(
            &source,
            case.gzip.compressed_payload,
            "gzip compressed payload",
        )?));
    }
    if source_digests.len() < 2 || layout_roots.len() < 2 || compressed_payload_digests.len() < 2 {
        return Err(VerifyError::new(
            "TAR/gzip cases do not prove distinct encodings and source/layout separation",
        ));
    }
    if manifest.derived_tar.raw_layout_root.sealr_tree_v2
        == manifest.cases[0].layout_root.sealr_tree_v4
    {
        return Err(VerifyError::new(
            "raw TAR and wrapped TAR layouts are not separated",
        ));
    }

    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len() + 1,
        content_roots: manifest.cases.len() + 1,
    })
}

fn verify_tar_gzip_transform(transform: &TarGzipTransformVector) -> Result<(), VerifyError> {
    if transform.id != GZIP_TRANSFORM_ID {
        return Err(VerifyError::new("unsupported gzip transform id"));
    }
    let definition = decode_hex(&transform.definition_hex, "gzip transform definition")?;
    let decoder_parameters =
        decode_hex(&transform.decoder_parameters_hex, "gzip decoder parameters")?;
    if definition != GZIP_TRANSFORM_DEFINITION || decoder_parameters != GZIP_DECODER_PARAMETERS {
        return Err(VerifyError::new(
            "gzip transform constants differ from the closed verifier registry",
        ));
    }
    verify_digest(&transform.digest.sha256, "gzip transform digest")?;
    verify_digest(
        &transform.decoder_parameters_digest.sha256,
        "gzip decoder-parameter digest",
    )?;
    let id_len = u64::try_from(transform.id.len())
        .map_err(|_| VerifyError::new("gzip transform id length exceeds u64"))?;
    let definition_len = u64::try_from(definition.len())
        .map_err(|_| VerifyError::new("gzip transform definition length exceeds u64"))?;
    let mut profile_preimage = Vec::new();
    profile_preimage.extend_from_slice(b"sealr.transform-profile.v1\0");
    profile_preimage.extend_from_slice(&id_len.to_be_bytes());
    profile_preimage.extend_from_slice(transform.id.as_bytes());
    profile_preimage.extend_from_slice(&definition_len.to_be_bytes());
    profile_preimage.extend_from_slice(&definition);
    if sha256_hex(&profile_preimage) != transform.digest.sha256
        || sha256_hex(&decoder_parameters) != transform.decoder_parameters_digest.sha256
    {
        return Err(VerifyError::new(
            "gzip transform or decoder parameters do not match their digest",
        ));
    }
    Ok(())
}

fn verify_tar_gzip_profile(
    profile: &TarGzipProfileVector,
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<(), VerifyError> {
    if profile.id != TAR_GZIP_PROFILE_SCHEMA
        || inner.id != TAR_PORTABLE_PROFILE_SCHEMA
        || inner.digest.sha256 != TAR_PORTABLE_PROFILE_DIGEST
    {
        return Err(VerifyError::new(
            "unsupported TAR/gzip or inner TAR profile identity",
        ));
    }
    verify_digest(&profile.digest.sha256, "TAR/gzip profile digest")?;
    verify_digest(&inner.digest.sha256, "inner TAR profile digest")?;
    let canonical = tar_gzip_profile_canonical_bytes(inner, transform)?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "TAR/gzip profile digest does not match reconstructed canonical bytes",
        ));
    }
    Ok(())
}

fn tar_gzip_profile_canonical_bytes(
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<Vec<u8>, VerifyError> {
    tar_gzip_composed_profile_canonical_bytes(
        TAR_GZIP_PROFILE_SCHEMA,
        "tar-gzip-ustar",
        TAR_PORTABLE_PROFILE_SCHEMA,
        inner,
        transform,
    )
}

fn tar_gzip_pax_profile_canonical_bytes(
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<Vec<u8>, VerifyError> {
    tar_gzip_composed_profile_canonical_bytes(
        TAR_GZIP_PAX_PROFILE_SCHEMA,
        "tar-gzip-pax",
        TAR_PAX_PROFILE_SCHEMA,
        inner,
        transform,
    )
}

fn tar_gzip_gnu_longname_profile_canonical_bytes(
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<Vec<u8>, VerifyError> {
    tar_gzip_composed_profile_canonical_bytes(
        TAR_GZIP_GNU_LONGNAME_PROFILE_SCHEMA,
        "tar-gzip-gnu-longname",
        TAR_GNU_LONGNAME_PROFILE_SCHEMA,
        inner,
        transform,
    )
}

fn tar_gzip_composed_profile_canonical_bytes(
    schema: &'static str,
    format: &'static str,
    inner_profile: &'static str,
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<Vec<u8>, VerifyError> {
    let definition = TarGzipProfileDefinition {
        schema,
        status: "supported-preview",
        format,
        wrapper_profile: GZIP_TRANSFORM_ID,
        wrapper_profile_sha256: transform.digest.sha256.clone(),
        decoder_parameters_sha256: transform.decoder_parameters_digest.sha256.clone(),
        gzip_members: "exactly-one",
        gzip_optional_fields: "bounded-exact-rfc1952-framing-si2-nonzero-unique-ids",
        gzip_integrity: "fhcrc-when-present-and-crc32-and-isize",
        gzip_trailing_input: "denied-including-zero-padding-and-concatenation",
        derived_output: "private-immutable-bounded-and-sha256-bound",
        inner_profile,
        inner_profile_sha256: inner.digest.sha256.clone(),
    };
    serde_json::to_vec(&definition)
        .map_err(|error| VerifyError::new(format!("{format} profile serialization: {error}")))
}

fn verify_tar_gzip_derived_tar(derived: &TarGzipDerivedTar) -> Result<Vec<u8>, VerifyError> {
    let bytes = decode_hex(&derived.bytes_hex, "derived TAR bytes")?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| VerifyError::new("derived TAR length exceeds u64"))?;
    if len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "derived TAR exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&derived.source.sha256, "derived TAR digest")?;
    if sha256_hex(&bytes) != derived.source.sha256 {
        return Err(VerifyError::new(
            "committed derived TAR bytes do not match their digest",
        ));
    }
    if derived.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("derived TAR member limit exceeded"));
    }
    let records_end = checked_range_end(derived.covering.member_records, "TAR member records")?;
    let terminator_end = checked_range_end(derived.covering.terminator, "TAR terminator")?;
    let trailing_end = checked_range_end(derived.covering.trailing_zeros, "TAR trailing zeros")?;
    if derived.covering.member_records.offset != 0
        || derived.covering.terminator.offset != records_end
        || derived.covering.terminator.len != 1024
        || derived.covering.trailing_zeros.offset != terminator_end
        || trailing_end != len
        || !trailing_end.is_multiple_of(512)
    {
        return Err(VerifyError::new(
            "derived TAR covering does not exactly partition complete blocks",
        ));
    }

    let mut members: Vec<_> = derived.members.iter().collect();
    members.sort_by_key(|member| member.tar.header.offset);
    let mut expected_header = 0_u64;
    let mut paths = HashSet::new();
    for member in members {
        if member.canonical_path.is_empty()
            || !paths.insert(member.canonical_path.as_str())
            || member.components.join("/") != member.canonical_path
            || member.raw_name_bytes.is_empty()
            || member.decoded_name.as_bytes() != member.raw_name_bytes
        {
            return Err(VerifyError::new(
                "derived TAR member name evidence is invalid",
            ));
        }
        let evidence = &member.tar;
        let header_end = checked_range_end(evidence.header, "TAR member header")?;
        let payload_end = checked_range_end(evidence.payload, "TAR member payload")?;
        let padding_end = checked_range_end(evidence.padding, "TAR member padding")?;
        let expected_padding = (512 - (evidence.payload.len % 512)) % 512;
        if evidence.header.offset != expected_header
            || evidence.header.len != 512
            || evidence.payload.offset != header_end
            || evidence.payload.len != member.declared_uncomp_size
            || evidence.padding.offset != payload_end
            || evidence.padding.len != expected_padding
            || !padding_end.is_multiple_of(512)
            || padding_end > records_end
            || member.actual_uncomp_size != member.declared_uncomp_size
            || !matches!(member.verification, MemberVerification::Verified)
        {
            return Err(VerifyError::new("derived TAR member geometry is invalid"));
        }
        let header = range_bytes(&bytes, evidence.header, "derived TAR header")?;
        verify_tar_gzip_header(member, header)?;
        verify_digest(&evidence.header_sha256, "derived TAR header digest")?;
        if sha256_hex(header) != evidence.header_sha256 {
            return Err(VerifyError::new(
                "derived TAR header digest disagrees with committed bytes",
            ));
        }
        let payload = range_bytes(&bytes, evidence.payload, "derived TAR payload")?;
        verify_digest(&member.content_sha256, "derived TAR member content digest")?;
        if sha256_hex(payload) != member.content_sha256
            || crc32_ieee_bytes(payload) != member.actual_crc
        {
            return Err(VerifyError::new(
                "derived TAR payload digest or CRC disagrees with evidence",
            ));
        }
        if range_bytes(&bytes, evidence.padding, "derived TAR padding")?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(VerifyError::new("derived TAR member padding is nonzero"));
        }
        expected_header = padding_end;
    }
    if expected_header != records_end {
        return Err(VerifyError::new(
            "derived TAR members do not fill their covering",
        ));
    }
    for (range, label) in [
        (derived.covering.terminator, "derived TAR terminator"),
        (
            derived.covering.trailing_zeros,
            "derived TAR trailing zeros",
        ),
    ] {
        if range_bytes(&bytes, range, label)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(VerifyError::new(format!("{label} contains nonzero bytes")));
        }
    }
    Ok(bytes)
}

fn verify_tar_gzip_header(member: &TarGzipMember, header: &[u8]) -> Result<(), VerifyError> {
    if header.len() != 512 || header[257..263] != *b"ustar\0" || header[263..265] != *b"00" {
        return Err(VerifyError::new("derived TAR header is not portable ustar"));
    }
    if header[500..512].iter().any(|byte| *byte != 0) {
        return Err(VerifyError::new(
            "derived TAR reserved ustar header bytes are nonzero",
        ));
    }
    if header[157..257].iter().any(|byte| *byte != 0) {
        return Err(VerifyError::new(
            "derived TAR linkname is not empty for the portable subset",
        ));
    }
    if header[148..154]
        .iter()
        .any(|byte| !(b'0'..=b'7').contains(byte))
        || header[154] != 0
        || header[155] != b' '
    {
        return Err(VerifyError::new(
            "derived TAR checksum field is not six octal digits, NUL, space",
        ));
    }
    let declared_checksum = parse_tar_octal(&header[148..156], "TAR checksum")?;
    let mut checksum_header = header.to_vec();
    checksum_header[148..156].fill(b' ');
    let actual_checksum = checksum_header.iter().try_fold(0_u32, |sum, byte| {
        sum.checked_add(u32::from(*byte))
            .ok_or_else(|| VerifyError::new("TAR checksum overflows u32"))
    })?;
    if declared_checksum != u64::from(actual_checksum)
        || member.tar.header_checksum != actual_checksum
    {
        return Err(VerifyError::new(
            "derived TAR checksum evidence disagrees with header bytes",
        ));
    }
    let mode = parse_tar_octal(&header[100..108], "TAR mode")?;
    let _uid = parse_tar_octal(&header[108..116], "TAR uid")?;
    let _gid = parse_tar_octal(&header[116..124], "TAR gid")?;
    let size = parse_tar_octal(&header[124..136], "TAR size")?;
    let mtime = parse_tar_octal(&header[136..148], "TAR mtime")?;
    let device_major = parse_tar_device_number(&header[329..337], "TAR devmajor")?;
    let device_minor = parse_tar_device_number(&header[337..345], "TAR devminor")?;
    if mode > 0o7777
        || u32::try_from(mode).ok() != Some(member.tar.mode)
        || size != member.declared_uncomp_size
        || mtime != member.tar.mtime
    {
        return Err(VerifyError::new(
            "derived TAR numeric evidence disagrees with header bytes",
        ));
    }
    if device_major != 0 || device_minor != 0 {
        return Err(VerifyError::new(
            "derived TAR device numbers must be zero in the portable subset",
        ));
    }
    verify_tar_owner_text(&header[265..297], "TAR uname")?;
    verify_tar_owner_text(&header[297..329], "TAR gname")?;
    let name = tar_text_field(&header[..100], "TAR name", false)?;
    let prefix = tar_text_field(&header[345..500], "TAR prefix", true)?;
    let mut raw_path = Vec::new();
    if !prefix.is_empty() {
        raw_path.extend_from_slice(prefix);
        raw_path.push(b'/');
    }
    raw_path.extend_from_slice(name);
    if raw_path != member.raw_name_bytes {
        return Err(VerifyError::new(
            "derived TAR path evidence disagrees with header bytes",
        ));
    }
    let typeflag = header[156];
    let source_is_directory = typeflag == b'5';
    if !matches!(typeflag, 0 | b'0' | b'5')
        || source_is_directory != matches!(member.kind, MemberKind::Directory)
        || (source_is_directory && member.declared_uncomp_size != 0)
    {
        return Err(VerifyError::new(
            "derived TAR member kind disagrees with typeflag",
        ));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8], label: &str) -> Result<u64, VerifyError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(VerifyError::new(format!(
            "{label} uses denied base-256 encoding"
        )));
    }
    let digit_end = field
        .iter()
        .position(|byte| matches!(*byte, 0 | b' '))
        .unwrap_or(field.len());
    if digit_end == 0
        || digit_end == field.len()
        || field[..digit_end]
            .iter()
            .any(|byte| !(b'0'..=b'7').contains(byte))
        || field[digit_end..]
            .iter()
            .any(|byte| !matches!(*byte, 0 | b' '))
    {
        return Err(VerifyError::new(format!(
            "{label} is not canonical ASCII octal"
        )));
    }
    field[..digit_end].iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
    })
}

fn parse_tar_device_number(field: &[u8], label: &str) -> Result<u64, VerifyError> {
    if field.iter().all(|byte| *byte == 0) {
        Ok(0)
    } else {
        parse_tar_octal(field, label)
    }
}

fn tar_text_field<'a>(
    field: &'a [u8],
    label: &str,
    empty_allowed: bool,
) -> Result<&'a [u8], VerifyError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(VerifyError::new(format!(
            "{label} has nonzero bytes after its first NUL"
        )));
    }
    if !empty_allowed && end == 0 {
        return Err(VerifyError::new(format!("{label} is empty")));
    }
    Ok(&field[..end])
}

fn verify_tar_owner_text(field: &[u8], label: &str) -> Result<(), VerifyError> {
    let Some(end) = field.iter().position(|byte| *byte == 0) else {
        return Err(VerifyError::new(format!("{label} is not NUL-terminated")));
    };
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(VerifyError::new(format!(
            "{label} has nonzero bytes after its first NUL"
        )));
    }
    if field[..end]
        .iter()
        .any(|byte| !matches!(*byte, b' '..=b'~'))
    {
        return Err(VerifyError::new(format!("{label} is not printable ASCII")));
    }
    Ok(())
}

fn verify_tar_gzip_case(
    case: &TarGzipCase,
    manifest: &TarGzipManifest,
    derived: &[u8],
) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
    let source_len = u64::try_from(source.len())
        .map_err(|_| VerifyError::new("gzip source length exceeds u64"))?;
    if source_len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "gzip source exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&case.source.sha256, "gzip source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "gzip source bytes do not match their digest",
        ));
    }
    verify_gzip_wrapper(
        &source,
        &case.gzip,
        derived,
        &manifest.derived_tar.source.sha256,
    )?;

    let actual_preimage = encode_tar_gzip_layout(case, manifest)?;
    let committed_preimage = decode_hex(&case.layout_preimage_hex, "TAR/gzip layout preimage")?;
    if actual_preimage != committed_preimage {
        return Err(VerifyError::new(
            "TAR/gzip layout preimage does not match reconstructed evidence",
        ));
    }
    verify_digest(&case.layout_root.sealr_tree_v4, "TAR/gzip layout root")?;
    if sha256_hex(&actual_preimage) != case.layout_root.sealr_tree_v4 {
        return Err(VerifyError::new("TAR/gzip layout root mismatch"));
    }
    verify_digest(&case.content_root.sealr_tree_v1, "TAR/gzip content root")?;
    if case.content_root.sealr_tree_v1 != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new("wrapped and raw TAR content roots differ"));
    }
    Ok(())
}

fn verify_tar_gzip_pax_manifest(
    manifest: &TarGzipPaxManifest,
) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != TAR_GZIP_PAX_MANIFEST_SCHEMA
        || manifest.archive_ir_schema != TAR_GZIP_PAX_IR_SCHEMA
        || manifest.layout_encoding != TAR_GZIP_PAX_TREE_ENCODING
        || manifest.layout_label != TAR_GZIP_PAX_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new(
            "unsupported TAR/gzip/PAX manifest contract",
        ));
    }
    const EXPECTED_CASE_IDS: [&str; 2] = ["optional-default", "minimal-stored-deflate"];
    if manifest.cases.len() != EXPECTED_CASE_IDS.len()
        || manifest
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .ne(EXPECTED_CASE_IDS)
    {
        return Err(VerifyError::new(
            "TAR/gzip/PAX v1 manifest must contain exactly the two canonical ordered cases",
        ));
    }
    verify_tar_gzip_transform(&manifest.transform)?;
    verify_tar_gzip_pax_profile(
        &manifest.profile,
        &manifest.inner_profile,
        &manifest.transform,
    )?;
    let derived = verify_tar_gzip_pax_derived_tar(&manifest.derived_tar)?;
    let raw_layout = preimage(
        TAR_PAX_LAYOUT_LABEL,
        &tar_pax_layout_body(
            &manifest.derived_tar.covering,
            &manifest.derived_tar.pax_extensions,
            &manifest.derived_tar.members,
        )?,
    );
    let committed_raw_preimage = decode_hex(
        &manifest.derived_tar.raw_layout_preimage_hex,
        "raw TAR/PAX layout preimage",
    )?;
    if raw_layout != committed_raw_preimage {
        return Err(VerifyError::new(
            "raw TAR/PAX layout preimage does not match derived evidence",
        ));
    }
    verify_digest(
        &manifest.derived_tar.raw_layout_root.sealr_tree_v5,
        "raw TAR/PAX layout root",
    )?;
    if sha256_hex(&raw_layout) != manifest.derived_tar.raw_layout_root.sealr_tree_v5 {
        return Err(VerifyError::new("raw TAR/PAX layout root mismatch"));
    }
    let content_preimage = encode_tar_pax_content(&manifest.derived_tar.members)?;
    verify_digest(
        &manifest.derived_tar.content_root.sealr_tree_v1,
        "derived TAR/PAX content root",
    )?;
    if sha256_hex(&content_preimage) != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new("derived TAR/PAX content root mismatch"));
    }

    let mut source_digests = HashSet::new();
    let mut layout_roots = HashSet::new();
    let mut compressed_payload_digests = HashSet::new();
    for case in &manifest.cases {
        verify_tar_gzip_pax_case(case, manifest, &derived)
            .map_err(|error| error.context(&format!("TAR/gzip/PAX case {}", case.id)))?;
        source_digests.insert(case.source.sha256.as_str());
        layout_roots.insert(case.layout_root.sealr_tree_v7.as_str());
        let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
        compressed_payload_digests.insert(sha256_hex(range_bytes(
            &source,
            case.gzip.compressed_payload,
            "gzip compressed payload",
        )?));
    }
    if source_digests.len() < 2 || layout_roots.len() < 2 || compressed_payload_digests.len() < 2 {
        return Err(VerifyError::new(
            "TAR/gzip/PAX cases do not prove distinct encodings and source/layout separation",
        ));
    }
    if manifest.derived_tar.raw_layout_root.sealr_tree_v5
        == manifest.cases[0].layout_root.sealr_tree_v7
    {
        return Err(VerifyError::new(
            "raw TAR/PAX and wrapped TAR/PAX layouts are not separated",
        ));
    }

    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len() + 1,
        content_roots: manifest.cases.len() + 1,
    })
}

fn verify_tar_gzip_pax_profile(
    profile: &TarGzipProfileVector,
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<(), VerifyError> {
    if profile.id != TAR_GZIP_PAX_PROFILE_SCHEMA || inner.id != TAR_PAX_PROFILE_SCHEMA {
        return Err(VerifyError::new(
            "unsupported TAR/gzip/PAX or inner TAR/PAX profile identity",
        ));
    }
    verify_digest(&profile.digest.sha256, "TAR/gzip/PAX profile digest")?;
    verify_digest(&inner.digest.sha256, "inner TAR/PAX profile digest")?;
    if sha256_hex(&tar_pax_profile_canonical_bytes()?) != inner.digest.sha256 {
        return Err(VerifyError::new(
            "inner TAR/PAX profile digest does not match its canonical definition",
        ));
    }
    let canonical = tar_gzip_pax_profile_canonical_bytes(inner, transform)?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "TAR/gzip/PAX profile digest does not match reconstructed canonical bytes",
        ));
    }
    Ok(())
}

fn verify_tar_gzip_pax_derived_tar(derived: &TarGzipPaxDerivedTar) -> Result<Vec<u8>, VerifyError> {
    let bytes = decode_hex(&derived.bytes_hex, "derived TAR/PAX bytes")?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| VerifyError::new("derived TAR/PAX length exceeds u64"))?;
    if len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "derived TAR/PAX exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&derived.source.sha256, "derived TAR/PAX digest")?;
    if sha256_hex(&bytes) != derived.source.sha256 {
        return Err(VerifyError::new(
            "committed derived TAR/PAX bytes do not match their digest",
        ));
    }
    verify_tar_pax_source(
        &bytes,
        &derived.covering,
        &derived.pax_extensions,
        &derived.members,
    )?;
    Ok(bytes)
}

fn verify_tar_gzip_pax_case(
    case: &TarGzipPaxCase,
    manifest: &TarGzipPaxManifest,
    derived: &[u8],
) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
    let source_len = u64::try_from(source.len())
        .map_err(|_| VerifyError::new("gzip source length exceeds u64"))?;
    if source_len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "gzip source exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&case.source.sha256, "gzip source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "gzip source bytes do not match their digest",
        ));
    }
    verify_gzip_wrapper(
        &source,
        &case.gzip,
        derived,
        &manifest.derived_tar.source.sha256,
    )?;

    let actual_preimage = encode_tar_gzip_pax_layout(case, manifest)?;
    let committed_preimage = decode_hex(&case.layout_preimage_hex, "TAR/gzip/PAX layout preimage")?;
    if actual_preimage != committed_preimage {
        return Err(VerifyError::new(
            "TAR/gzip/PAX layout preimage does not match reconstructed evidence",
        ));
    }
    verify_digest(&case.layout_root.sealr_tree_v7, "TAR/gzip/PAX layout root")?;
    if sha256_hex(&actual_preimage) != case.layout_root.sealr_tree_v7 {
        return Err(VerifyError::new("TAR/gzip/PAX layout root mismatch"));
    }
    verify_digest(
        &case.content_root.sealr_tree_v1,
        "TAR/gzip/PAX content root",
    )?;
    if case.content_root.sealr_tree_v1 != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(
            "wrapped and raw TAR/PAX content roots differ",
        ));
    }
    Ok(())
}

fn verify_tar_gzip_gnu_longname_manifest(
    manifest: &TarGzipGnuLongNameManifest,
) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != TAR_GZIP_GNU_LONGNAME_MANIFEST_SCHEMA
        || manifest.archive_ir_schema != TAR_GZIP_GNU_LONGNAME_IR_SCHEMA
        || manifest.layout_encoding != TAR_GZIP_GNU_LONGNAME_TREE_ENCODING
        || manifest.layout_label != TAR_GZIP_GNU_LONGNAME_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new(
            "unsupported TAR/gzip/GNU long-name manifest contract",
        ));
    }
    const EXPECTED_CASE_IDS: [&str; 2] = ["optional-default", "minimal-stored-deflate"];
    if manifest.cases.len() != EXPECTED_CASE_IDS.len()
        || manifest
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .ne(EXPECTED_CASE_IDS)
    {
        return Err(VerifyError::new(
            "TAR/gzip/GNU long-name v1 manifest must contain exactly the two canonical ordered cases",
        ));
    }
    verify_tar_gzip_transform(&manifest.transform)?;
    verify_tar_gzip_gnu_longname_profile(
        &manifest.profile,
        &manifest.inner_profile,
        &manifest.transform,
    )?;
    let derived = verify_tar_gzip_gnu_longname_derived_tar(&manifest.derived_tar)?;
    let raw_layout = preimage(
        TAR_GNU_LONGNAME_LAYOUT_LABEL,
        &tar_gnu_longname_layout_body(
            &manifest.derived_tar.covering,
            &manifest.derived_tar.gnu_longname_carriers,
            &manifest.derived_tar.members,
        )?,
    );
    let committed_raw_preimage = decode_hex(
        &manifest.derived_tar.raw_layout_preimage_hex,
        "raw TAR/GNU long-name layout preimage",
    )?;
    if raw_layout != committed_raw_preimage {
        return Err(VerifyError::new(
            "raw TAR/GNU long-name layout preimage does not match derived evidence",
        ));
    }
    verify_digest(
        &manifest.derived_tar.raw_layout_root.sealr_tree_v6,
        "raw TAR/GNU long-name layout root",
    )?;
    if sha256_hex(&raw_layout) != manifest.derived_tar.raw_layout_root.sealr_tree_v6 {
        return Err(VerifyError::new(
            "raw TAR/GNU long-name layout root mismatch",
        ));
    }
    let content_preimage = encode_tar_gnu_longname_content(&manifest.derived_tar.members)?;
    verify_digest(
        &manifest.derived_tar.content_root.sealr_tree_v1,
        "derived TAR/GNU long-name content root",
    )?;
    if sha256_hex(&content_preimage) != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(
            "derived TAR/GNU long-name content root mismatch",
        ));
    }

    let mut source_digests = HashSet::new();
    let mut layout_roots = HashSet::new();
    let mut compressed_payload_digests = HashSet::new();
    for case in &manifest.cases {
        verify_tar_gzip_gnu_longname_case(case, manifest, &derived)
            .map_err(|error| error.context(&format!("TAR/gzip/GNU long-name case {}", case.id)))?;
        source_digests.insert(case.source.sha256.as_str());
        layout_roots.insert(case.layout_root.sealr_tree_v8.as_str());
        let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
        compressed_payload_digests.insert(sha256_hex(range_bytes(
            &source,
            case.gzip.compressed_payload,
            "gzip compressed payload",
        )?));
    }
    if source_digests.len() < 2 || layout_roots.len() < 2 || compressed_payload_digests.len() < 2 {
        return Err(VerifyError::new(
            "TAR/gzip/GNU long-name cases do not prove distinct encodings and source/layout separation",
        ));
    }
    if manifest.derived_tar.raw_layout_root.sealr_tree_v6
        == manifest.cases[0].layout_root.sealr_tree_v8
    {
        return Err(VerifyError::new(
            "raw TAR/GNU long-name and wrapped TAR/GNU long-name layouts are not separated",
        ));
    }

    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len() + 1,
        content_roots: manifest.cases.len() + 1,
    })
}

fn verify_tar_gzip_gnu_longname_profile(
    profile: &TarGzipProfileVector,
    inner: &TarGzipProfileVector,
    transform: &TarGzipTransformVector,
) -> Result<(), VerifyError> {
    if profile.id != TAR_GZIP_GNU_LONGNAME_PROFILE_SCHEMA
        || inner.id != TAR_GNU_LONGNAME_PROFILE_SCHEMA
    {
        return Err(VerifyError::new(
            "unsupported TAR/gzip/GNU long-name or inner TAR/GNU long-name profile identity",
        ));
    }
    verify_digest(
        &profile.digest.sha256,
        "TAR/gzip/GNU long-name profile digest",
    )?;
    verify_digest(
        &inner.digest.sha256,
        "inner TAR/GNU long-name profile digest",
    )?;
    if sha256_hex(&tar_gnu_longname_profile_canonical_bytes()?) != inner.digest.sha256 {
        return Err(VerifyError::new(
            "inner TAR/GNU long-name profile digest does not match its canonical definition",
        ));
    }
    let canonical = tar_gzip_gnu_longname_profile_canonical_bytes(inner, transform)?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "TAR/gzip/GNU long-name profile digest does not match reconstructed canonical bytes",
        ));
    }
    Ok(())
}

fn verify_tar_gzip_gnu_longname_derived_tar(
    derived: &TarGzipGnuLongNameDerivedTar,
) -> Result<Vec<u8>, VerifyError> {
    let bytes = decode_hex(&derived.bytes_hex, "derived TAR/GNU long-name bytes")?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| VerifyError::new("derived TAR/GNU long-name length exceeds u64"))?;
    if len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "derived TAR/GNU long-name exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&derived.source.sha256, "derived TAR/GNU long-name digest")?;
    if sha256_hex(&bytes) != derived.source.sha256 {
        return Err(VerifyError::new(
            "committed derived TAR/GNU long-name bytes do not match their digest",
        ));
    }
    verify_tar_gnu_longname_source(
        &bytes,
        &derived.covering,
        &derived.gnu_longname_carriers,
        &derived.members,
    )?;
    Ok(bytes)
}

fn verify_tar_gzip_gnu_longname_case(
    case: &TarGzipGnuLongNameCase,
    manifest: &TarGzipGnuLongNameManifest,
    derived: &[u8],
) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "gzip source bytes")?;
    let source_len = u64::try_from(source.len())
        .map_err(|_| VerifyError::new("gzip source length exceeds u64"))?;
    if source_len > MAX_DERIVED_TAR_BYTES {
        return Err(VerifyError::new(format!(
            "gzip source exceeds the {MAX_DERIVED_TAR_BYTES}-byte verifier cap"
        )));
    }
    verify_digest(&case.source.sha256, "gzip source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "gzip source bytes do not match their digest",
        ));
    }
    verify_gzip_wrapper(
        &source,
        &case.gzip,
        derived,
        &manifest.derived_tar.source.sha256,
    )?;

    let actual_preimage = encode_tar_gzip_gnu_longname_layout(case, manifest)?;
    let committed_preimage = decode_hex(
        &case.layout_preimage_hex,
        "TAR/gzip/GNU long-name layout preimage",
    )?;
    if actual_preimage != committed_preimage {
        return Err(VerifyError::new(
            "TAR/gzip/GNU long-name layout preimage does not match reconstructed evidence",
        ));
    }
    verify_digest(
        &case.layout_root.sealr_tree_v8,
        "TAR/gzip/GNU long-name layout root",
    )?;
    if sha256_hex(&actual_preimage) != case.layout_root.sealr_tree_v8 {
        return Err(VerifyError::new(
            "TAR/gzip/GNU long-name layout root mismatch",
        ));
    }
    verify_digest(
        &case.content_root.sealr_tree_v1,
        "TAR/gzip/GNU long-name content root",
    )?;
    if case.content_root.sealr_tree_v1 != manifest.derived_tar.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(
            "wrapped and raw TAR/GNU long-name content roots differ",
        ));
    }
    Ok(())
}

fn verify_gzip_wrapper(
    source: &[u8],
    evidence: &GzipWrapperVector,
    derived: &[u8],
    derived_source_sha256: &str,
) -> Result<(), VerifyError> {
    const FLAG_HEADER_CRC: u8 = 1 << 1;
    const FLAG_EXTRA: u8 = 1 << 2;
    const FLAG_NAME: u8 = 1 << 3;
    const FLAG_COMMENT: u8 = 1 << 4;
    const FLAG_RESERVED: u8 = 0b1110_0000;

    let source_len =
        u64::try_from(source.len()).map_err(|_| VerifyError::new("gzip source exceeds u64"))?;
    let header_end = checked_range_end(evidence.header, "gzip header")?;
    let payload_end = checked_range_end(evidence.compressed_payload, "gzip compressed payload")?;
    let trailer_end = checked_range_end(evidence.trailer, "gzip trailer")?;
    if evidence.header.offset != 0
        || evidence.header.len < 10
        || evidence.compressed_payload.offset != header_end
        || evidence.trailer.offset != payload_end
        || evidence.trailer.len != 8
        || trailer_end != source_len
    {
        return Err(VerifyError::new(
            "gzip ranges do not exactly partition one source member",
        ));
    }
    let fixed = source
        .get(..10)
        .ok_or_else(|| VerifyError::new("gzip fixed header is truncated"))?;
    if fixed[..3] != [0x1f, 0x8b, 8]
        || fixed[3] & FLAG_RESERVED != 0
        || fixed[3] != evidence.flags
        || le_u32(fixed, 4) != evidence.modification_time
        || fixed[8] != evidence.extra_flags
        || fixed[9] != evidence.operating_system
    {
        return Err(VerifyError::new(
            "gzip fixed structural signature or fields disagree with evidence",
        ));
    }

    let mut cursor = 10_u64;
    if evidence.flags & FLAG_EXTRA != 0 {
        let extra = evidence
            .extra
            .ok_or_else(|| VerifyError::new("gzip FEXTRA flag has no range"))?;
        if extra.offset != cursor || extra.len < 2 {
            return Err(VerifyError::new("gzip FEXTRA range is not canonical"));
        }
        let extra_bytes = range_bytes(source, extra, "gzip FEXTRA")?;
        if u64::from(le_u16(extra_bytes, 0)) + 2 != extra.len {
            return Err(VerifyError::new("gzip XLEN disagrees with FEXTRA range"));
        }
        let mut position = 2_usize;
        let mut count = 0_u32;
        let mut ids = HashSet::new();
        while position < extra_bytes.len() {
            let header_end = position
                .checked_add(4)
                .ok_or_else(|| VerifyError::new("gzip FEXTRA position overflows"))?;
            let subfield = extra_bytes
                .get(position..header_end)
                .ok_or_else(|| VerifyError::new("gzip FEXTRA has an incomplete subfield header"))?;
            if subfield[1] == 0 {
                return Err(VerifyError::new(
                    "gzip FEXTRA subfield uses reserved SI2 zero",
                ));
            }
            let id = le_u16(subfield, 0);
            if !ids.insert(id) {
                return Err(VerifyError::new("gzip FEXTRA repeats a subfield id"));
            }
            let end = header_end
                .checked_add(usize::from(le_u16(subfield, 2)))
                .ok_or_else(|| VerifyError::new("gzip FEXTRA subfield overflows"))?;
            if end > extra_bytes.len() {
                return Err(VerifyError::new("gzip FEXTRA subfield exceeds XLEN"));
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| VerifyError::new("gzip FEXTRA count overflows"))?;
            position = end;
        }
        if count != evidence.extra_subfield_count {
            return Err(VerifyError::new(
                "gzip FEXTRA subfield count disagrees with evidence",
            ));
        }
        cursor = checked_range_end(extra, "gzip FEXTRA")?;
    } else if evidence.extra.is_some() || evidence.extra_subfield_count != 0 {
        return Err(VerifyError::new(
            "gzip FEXTRA evidence is present without its flag",
        ));
    }

    cursor = verify_gzip_c_string(
        source,
        cursor,
        header_end,
        evidence.flags & FLAG_NAME != 0,
        evidence.original_name,
        "gzip FNAME",
    )?;
    cursor = verify_gzip_c_string(
        source,
        cursor,
        header_end,
        evidence.flags & FLAG_COMMENT != 0,
        evidence.comment,
        "gzip FCOMMENT",
    )?;
    if evidence.flags & FLAG_HEADER_CRC != 0 {
        let range = evidence
            .header_crc16
            .ok_or_else(|| VerifyError::new("gzip FHCRC flag has no range"))?;
        if range.offset != cursor || range.len != 2 {
            return Err(VerifyError::new("gzip FHCRC range is not canonical"));
        }
        let prefix = source
            .get(
                ..usize::try_from(cursor)
                    .map_err(|_| VerifyError::new("gzip FHCRC prefix length exceeds usize"))?,
            )
            .ok_or_else(|| VerifyError::new("gzip FHCRC prefix is outside source"))?;
        let declared = range_bytes(source, range, "gzip FHCRC")?;
        if le_u16(declared, 0) != crc32_ieee_bytes(prefix) as u16 {
            return Err(VerifyError::new("gzip FHCRC disagrees with header bytes"));
        }
        cursor = checked_range_end(range, "gzip FHCRC")?;
    } else if evidence.header_crc16.is_some() {
        return Err(VerifyError::new(
            "gzip FHCRC evidence is present without its flag",
        ));
    }
    if cursor != header_end {
        return Err(VerifyError::new(
            "gzip optional fields do not exactly fill the header",
        ));
    }

    let trailer = range_bytes(source, evidence.trailer, "gzip trailer")?;
    let derived_len = u64::try_from(derived.len())
        .map_err(|_| VerifyError::new("derived TAR length exceeds u64"))?;
    let derived_isize = u32::try_from(derived_len % (u64::from(u32::MAX) + 1))
        .map_err(|_| VerifyError::new("gzip ISIZE modulo does not fit u32"))?;
    let derived_crc = crc32_ieee_bytes(derived);
    let derived_sha = sha256_hex(derived);
    if le_u32(trailer, 0) != evidence.declared_crc32
        || le_u32(trailer, 4) != evidence.declared_isize
        || evidence.declared_crc32 != derived_crc
        || evidence.declared_isize != derived_isize
        || evidence.derived_output_len != derived_len
        || evidence.derived_output_sha256 != derived_sha
        || evidence.derived_output_sha256 != derived_source_sha256
    {
        return Err(VerifyError::new(
            "gzip trailer and derived TAR CRC32, ISIZE, length, or SHA-256 disagree",
        ));
    }
    Ok(())
}

fn verify_gzip_c_string(
    source: &[u8],
    cursor: u64,
    header_end: u64,
    flagged: bool,
    range: Option<ByteRange>,
    label: &str,
) -> Result<u64, VerifyError> {
    if !flagged {
        return if range.is_none() {
            Ok(cursor)
        } else {
            Err(VerifyError::new(format!(
                "{label} evidence is present without its flag"
            )))
        };
    }
    let range = range.ok_or_else(|| VerifyError::new(format!("{label} flag has no range")))?;
    let end = checked_range_end(range, label)?;
    if range.offset != cursor || range.len == 0 || end > header_end {
        return Err(VerifyError::new(format!("{label} range is not canonical")));
    }
    let bytes = range_bytes(source, range, label)?;
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(VerifyError::new(format!(
            "{label} is not exactly one NUL-terminated byte string"
        )));
    }
    Ok(end)
}

fn encode_tar_gzip_layout(
    case: &TarGzipCase,
    manifest: &TarGzipManifest,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = gzip_wrapper_layout_body(&case.gzip, &case.source.sha256, &manifest.transform)?;
    push_bytes(
        &mut body,
        &tar_gzip_inner_layout_body(&manifest.derived_tar)?,
    )?;
    Ok(preimage(TAR_GZIP_LAYOUT_LABEL, &body))
}

fn encode_tar_gzip_pax_layout(
    case: &TarGzipPaxCase,
    manifest: &TarGzipPaxManifest,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = gzip_wrapper_layout_body(&case.gzip, &case.source.sha256, &manifest.transform)?;
    push_bytes(
        &mut body,
        &tar_pax_layout_body(
            &manifest.derived_tar.covering,
            &manifest.derived_tar.pax_extensions,
            &manifest.derived_tar.members,
        )?,
    )?;
    Ok(preimage(TAR_GZIP_PAX_LAYOUT_LABEL, &body))
}

fn encode_tar_gzip_gnu_longname_layout(
    case: &TarGzipGnuLongNameCase,
    manifest: &TarGzipGnuLongNameManifest,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = gzip_wrapper_layout_body(&case.gzip, &case.source.sha256, &manifest.transform)?;
    push_bytes(
        &mut body,
        &tar_gnu_longname_layout_body(
            &manifest.derived_tar.covering,
            &manifest.derived_tar.gnu_longname_carriers,
            &manifest.derived_tar.members,
        )?,
    )?;
    Ok(preimage(TAR_GZIP_GNU_LONGNAME_LAYOUT_LABEL, &body))
}

fn gzip_wrapper_layout_body(
    gzip: &GzipWrapperVector,
    source_sha256: &str,
    transform: &TarGzipTransformVector,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    push_bytes(&mut body, transform.id.as_bytes())?;
    body.extend_from_slice(&decode_digest(
        &transform.digest.sha256,
        "gzip transform digest",
    )?);
    body.extend_from_slice(&decode_digest(
        &transform.decoder_parameters_digest.sha256,
        "gzip decoder-parameter digest",
    )?);
    push_u16(&mut body, 0);
    encode_range(
        &mut body,
        ByteRange {
            offset: 0,
            len: checked_range_end(gzip.trailer, "gzip source range")?,
        },
    );
    body.extend_from_slice(&decode_digest(source_sha256, "gzip source digest")?);
    push_u16(&mut body, 1);
    push_u64(&mut body, gzip.derived_output_len);
    body.extend_from_slice(&decode_digest(
        &gzip.derived_output_sha256,
        "gzip derived output digest",
    )?);
    body.push(gzip.flags);
    push_u32(&mut body, gzip.modification_time);
    body.push(gzip.extra_flags);
    body.push(gzip.operating_system);
    encode_range(&mut body, gzip.header);
    encode_optional_range(&mut body, gzip.extra);
    push_u32(&mut body, gzip.extra_subfield_count);
    encode_optional_range(&mut body, gzip.original_name);
    encode_optional_range(&mut body, gzip.comment);
    encode_optional_range(&mut body, gzip.header_crc16);
    encode_range(&mut body, gzip.compressed_payload);
    encode_range(&mut body, gzip.trailer);
    push_u32(&mut body, gzip.declared_crc32);
    push_u32(&mut body, gzip.declared_isize);
    push_u64(&mut body, gzip.derived_output_len);
    body.extend_from_slice(&decode_digest(
        &gzip.derived_output_sha256,
        "gzip derived output digest",
    )?);
    Ok(body)
}

fn encode_tar_gzip_inner_layout(derived: &TarGzipDerivedTar) -> Result<Vec<u8>, VerifyError> {
    Ok(preimage(
        TAR_LAYOUT_LABEL,
        &tar_gzip_inner_layout_body(derived)?,
    ))
}

fn tar_gzip_inner_layout_body(derived: &TarGzipDerivedTar) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    encode_range(&mut body, derived.covering.member_records);
    encode_range(&mut body, derived.covering.terminator);
    encode_range(&mut body, derived.covering.trailing_zeros);
    let mut members: Vec<_> = derived.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("derived TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_bytes(&mut body, &member.raw_name_bytes)?;
        push_u64(&mut body, member.declared_uncomp_size);
        encode_range(&mut body, member.tar.header);
        encode_range(&mut body, member.tar.payload);
        encode_range(&mut body, member.tar.padding);
        push_u32(&mut body, member.tar.mode);
        push_u64(&mut body, member.tar.mtime);
        push_u32(&mut body, member.tar.header_checksum);
        body.extend_from_slice(&decode_digest(
            &member.tar.header_sha256,
            "derived TAR header digest",
        )?);
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len())
                .map_err(|_| VerifyError::new("TAR normalization count exceeds u32"))?,
        );
        encode_normalization_actions(&mut body, &member.normalization_actions);
    }
    Ok(body)
}

fn encode_tar_gzip_content(derived: &TarGzipDerivedTar) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    let mut members: Vec<_> = derived.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("derived TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(&mut body, member.actual_uncomp_size);
        body.extend_from_slice(&decode_digest(
            &member.content_sha256,
            "derived TAR member content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn crc32_ieee_bytes(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn verify_zip64_covering(source: &[u8], ir: &Zip64ArchiveIr) -> Result<(), VerifyError> {
    const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const CDH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const ZIP64_EOCD: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const ZIP64_LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

    let covering = &ir.zip64_covering;
    let source_len =
        u64::try_from(source.len()).map_err(|_| VerifyError::new("source exceeds u64"))?;
    for (range, label) in [
        (covering.local_records, "ZIP64 local covering"),
        (covering.central_directory, "ZIP64 central covering"),
        (covering.eocd, "ZIP64 EOCD covering"),
        (covering.comment, "ZIP64 comment covering"),
    ] {
        validate_range(range, label)?;
    }
    let pair = match (covering.zip64_eocd, covering.zip64_locator) {
        (None, None) => None,
        (Some(record), Some(locator)) => {
            validate_range(record, "ZIP64 EOCD record")?;
            validate_range(locator, "ZIP64 locator")?;
            Some((record, locator))
        }
        _ => {
            return Err(VerifyError::new(
                "ZIP64 end-record evidence is only partially present",
            ));
        }
    };
    if pair.is_none()
        && !ir.members.iter().any(|member| {
            member.zip64.local_zip64_extra.is_some()
                || member.zip64.central_zip64_extra.is_some()
                || matches!(
                    member.zip64.descriptor_width,
                    Some(Zip64DescriptorWidth::Zip64)
                )
        })
    {
        return Err(VerifyError::new(
            "ZIP64 profile evidence contains no ZIP64 construct",
        ));
    }
    let after_central = pair.map_or(covering.eocd.offset, |(record, _)| record.offset);
    if covering.local_records.offset != 0
        || checked_range_end(covering.local_records, "ZIP64 local covering")?
            != covering.central_directory.offset
        || checked_range_end(covering.central_directory, "ZIP64 central covering")? != after_central
        || covering.eocd.len != 22
        || checked_range_end(covering.eocd, "ZIP64 EOCD covering")? != covering.comment.offset
        || checked_range_end(covering.comment, "ZIP64 comment covering")? != source_len
    {
        return Err(VerifyError::new(
            "ZIP64 top-level covering does not exactly partition the source",
        ));
    }

    let eocd = range_bytes(source, covering.eocd, "ZIP64 classic EOCD")?;
    if eocd[0..4] != EOCD || le_u16(eocd, 4) != 0 || le_u16(eocd, 6) != 0 {
        return Err(VerifyError::new(
            "ZIP64 classic EOCD is absent, invalid, or spanned",
        ));
    }
    if u64::from(le_u16(eocd, 20)) != covering.comment.len {
        return Err(VerifyError::new(
            "ZIP64 classic EOCD comment length disagrees with covering",
        ));
    }
    reject_zip64_structural_metadata(
        range_bytes(source, covering.comment, "ZIP64 global EOCD comment")?,
        "global EOCD comment",
    )?;
    let classic_count_disk = le_u16(eocd, 8);
    let classic_count_total = le_u16(eocd, 10);
    let classic_cd_size = le_u32(eocd, 12);
    let classic_cd_offset = le_u32(eocd, 16);
    let member_count = u64::try_from(ir.members.len())
        .map_err(|_| VerifyError::new("ZIP64 member count exceeds u64"))?;
    let mut end_version_needed = None;

    if let Some((record_range, locator_range)) = pair {
        if record_range.len != 56
            || locator_range.len != 20
            || checked_range_end(record_range, "ZIP64 EOCD record")? != locator_range.offset
            || checked_range_end(locator_range, "ZIP64 locator")? != covering.eocd.offset
        {
            return Err(VerifyError::new(
                "ZIP64 end pair does not have fixed adjacent geometry",
            ));
        }
        let record = range_bytes(source, record_range, "ZIP64 EOCD record")?;
        let locator = range_bytes(source, locator_range, "ZIP64 locator")?;
        if record[0..4] != ZIP64_EOCD
            || le_u64(record, 4) != 44
            || le_u32(record, 16) != 0
            || le_u32(record, 20) != 0
            || le_u64(record, 24) != member_count
            || le_u64(record, 32) != member_count
            || le_u64(record, 40) != covering.central_directory.len
            || le_u64(record, 48) != covering.central_directory.offset
        {
            return Err(VerifyError::new(
                "ZIP64 EOCD disagrees with represented archive geometry",
            ));
        }
        end_version_needed = Some(le_u16(record, 14));
        if locator[0..4] != ZIP64_LOCATOR
            || le_u32(locator, 4) != 0
            || le_u64(locator, 8) != record_range.offset
            || le_u32(locator, 16) != 1
        {
            return Err(VerifyError::new(
                "ZIP64 locator disagrees with represented archive geometry",
            ));
        }
        let has_sentinel = classic_count_disk == u16::MAX
            || classic_count_total == u16::MAX
            || classic_cd_size == u32::MAX
            || classic_cd_offset == u32::MAX;
        if !has_sentinel
            || !canonical_zip64_end_u16(classic_count_disk, member_count)
            || !canonical_zip64_end_u16(classic_count_total, member_count)
            || !canonical_zip64_end_u32(classic_cd_size, covering.central_directory.len)
            || !canonical_zip64_end_u32(classic_cd_offset, covering.central_directory.offset)
        {
            return Err(VerifyError::new(
                "classic EOCD is not canonical for the ZIP64 end record",
            ));
        }
    } else if u64::from(classic_count_disk) != member_count
        || u64::from(classic_count_total) != member_count
        || u64::from(classic_cd_size) != covering.central_directory.len
        || u64::from(classic_cd_offset) != covering.central_directory.offset
    {
        return Err(VerifyError::new(
            "classic EOCD disagrees with member-only ZIP64 evidence",
        ));
    }

    let mut local_ranges = Vec::with_capacity(ir.members.len());
    let mut central_ranges = Vec::with_capacity(ir.members.len());
    for member in &ir.members {
        let ranges = &member.source_ranges;
        if ranges.local_header.len < 30 || ranges.central_header.len < 46 {
            return Err(VerifyError::new("ZIP64 member header is too short"));
        }
        let local = range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset,
                len: 30,
            },
            "ZIP64 local fixed header",
        )?;
        let central = range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset,
                len: 46,
            },
            "ZIP64 central fixed header",
        )?;
        if local[0..4] != LFH || central[0..4] != CDH {
            return Err(VerifyError::new("ZIP64 member signature is invalid"));
        }
        let local_name_len = u64::from(le_u16(local, 26));
        let local_extra_len = u64::from(le_u16(local, 28));
        let central_name_len = u64::from(le_u16(central, 28));
        let central_extra_len = u64::from(le_u16(central, 30));
        let central_comment_len = u64::from(le_u16(central, 32));
        if ranges.local_header.len != 30 + local_name_len + local_extra_len
            || ranges.central_header.len
                != 46 + central_name_len + central_extra_len + central_comment_len
            || checked_range_end(ranges.local_header, "ZIP64 local header")?
                != ranges.compressed_payload.offset
            || ranges.compressed_payload.len != member.declared_comp_size
            || !contains_range(covering.local_records, ranges.local_header)?
            || !contains_range(covering.central_directory, ranges.central_header)?
        {
            return Err(VerifyError::new(
                "ZIP64 member ranges disagree with encoded header lengths",
            ));
        }
        let central_comment_offset = ranges
            .central_header
            .offset
            .checked_add(46 + central_name_len + central_extra_len)
            .ok_or_else(|| VerifyError::new("ZIP64 central comment offset overflows"))?;
        reject_zip64_structural_metadata(
            range_bytes(
                source,
                ByteRange {
                    offset: central_comment_offset,
                    len: central_comment_len,
                },
                "ZIP64 central member comment",
            )?,
            "central member comment",
        )?;
        let local_name = range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset + 30,
                len: local_name_len,
            },
            "ZIP64 local name",
        )?;
        let central_name = range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset + 46,
                len: central_name_len,
            },
            "ZIP64 central name",
        )?;
        if local_name != member.raw_name_bytes || central_name != member.raw_name_bytes {
            return Err(VerifyError::new(
                "ZIP64 member names disagree with source bytes",
            ));
        }
        verify_zip64_common_member(member, local, central, pair.is_some())?;
        verify_zip64_extras(source, member, local, central)?;
        if member.method == 0 && member.flags & 0x0008 != 0 {
            reject_zip64_stream_signatures(
                range_bytes(
                    source,
                    ranges.compressed_payload,
                    "ZIP64 stored descriptor payload",
                )?,
                "stored descriptor payload",
            )?;
        }
        verify_zip64_descriptor(source, member)?;

        let payload_end = checked_range_end(ranges.compressed_payload, "ZIP64 payload")?;
        let local_end = if let Some(descriptor) = ranges.data_descriptor {
            if payload_end != descriptor.offset {
                return Err(VerifyError::new(
                    "ZIP64 payload does not abut its descriptor",
                ));
            }
            checked_range_end(descriptor, "ZIP64 descriptor")?
        } else {
            payload_end
        };
        local_ranges.push((ranges.local_header.offset, local_end));
        central_ranges.push((
            ranges.central_header.offset,
            checked_range_end(ranges.central_header, "ZIP64 central header")?,
        ));
    }

    if let Some(version_needed) = end_version_needed {
        let maximum_member_version = ir
            .members
            .iter()
            .map(|member| member.zip64.central_version_needed)
            .max()
            .unwrap_or(0);
        if version_needed != 45
            && (maximum_member_version == 0 || version_needed != maximum_member_version)
        {
            return Err(VerifyError::new(
                "ZIP64 EOCD extraction version is not canonical",
            ));
        }
    }

    local_ranges.sort_unstable_by_key(|range| range.0);
    central_ranges.sort_unstable_by_key(|range| range.0);
    verify_partition(
        &local_ranges,
        covering.local_records,
        "ZIP64 local record partition",
    )?;
    verify_partition(
        &central_ranges,
        covering.central_directory,
        "ZIP64 central header partition",
    )?;
    Ok(())
}

fn reject_zip64_structural_metadata(data: &[u8], context: &str) -> Result<(), VerifyError> {
    const SIGNATURES: [[u8; 4]; 6] = [
        [0x50, 0x4b, 0x06, 0x06],
        [0x50, 0x4b, 0x06, 0x07],
        [0x50, 0x4b, 0x05, 0x06],
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];
    if SIGNATURES
        .iter()
        .any(|signature| data.windows(4).any(|window| window == signature))
    {
        return Err(VerifyError::new(format!(
            "ZIP64 structural signature is denied in {context}"
        )));
    }
    Ok(())
}

fn reject_zip64_stream_signatures(data: &[u8], context: &str) -> Result<(), VerifyError> {
    const SIGNATURES: [[u8; 4]; 3] = [
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];
    if SIGNATURES
        .iter()
        .any(|signature| data.windows(4).any(|window| window == signature))
    {
        return Err(VerifyError::new(format!(
            "ZIP64 stream signature is denied in {context}"
        )));
    }
    Ok(())
}

fn verify_zip64_common_member(
    member: &Zip64Member,
    local: &[u8],
    central: &[u8],
    has_global_end_pair: bool,
) -> Result<(), VerifyError> {
    if le_u16(local, 4) != member.zip64.local_version_needed
        || le_u16(central, 6) != member.zip64.central_version_needed
        || le_u16(local, 6) != member.flags
        || le_u16(central, 8) != member.flags
        || le_u16(local, 8) != member.method
        || le_u16(central, 10) != member.method
        || le_u32(central, 16) != member.declared_crc
        || le_u16(central, 34) != 0
    {
        return Err(VerifyError::new(
            "ZIP64 common member evidence disagrees with source bytes",
        ));
    }
    let source_is_directory = member.raw_name_bytes.ends_with(b"/");
    if source_is_directory != matches!(member.kind, MemberKind::Directory) {
        return Err(VerifyError::new(
            "ZIP64 member kind disagrees with source name",
        ));
    }
    let attributes = le_u32(central, 38);
    let dos_directory = attributes & 0x10 != 0;
    let unix_kind = (attributes >> 16) & 0xf000;
    let attribute_is_directory = dos_directory || unix_kind == 0x4000;
    let attribute_is_regular = unix_kind == 0x8000;
    let attribute_is_special = unix_kind != 0 && unix_kind != 0x4000 && unix_kind != 0x8000;
    if attribute_is_special
        || (attribute_is_directory && attribute_is_regular)
        || (attribute_is_directory != source_is_directory
            && (attribute_is_directory || attribute_is_regular))
        || (source_is_directory
            && (member.declared_comp_size != 0
                || member.declared_uncomp_size != 0
                || member.method != 0
                || member.declared_crc != 0))
    {
        return Err(VerifyError::new("ZIP64 member attributes are invalid"));
    }

    let central_legacy_mask = u8::from(le_u32(central, 24) == u32::MAX)
        | (u8::from(le_u32(central, 20) == u32::MAX) << 1)
        | (u8::from(le_u32(central, 42) == u32::MAX) << 2);
    let local_legacy_mask =
        u8::from(le_u32(local, 22) == u32::MAX) | (u8::from(le_u32(local, 18) == u32::MAX) << 1);
    if central_legacy_mask != member.zip64.central_legacy_sentinel_mask
        || local_legacy_mask != member.zip64.local_legacy_sentinel_mask
    {
        return Err(VerifyError::new(
            "ZIP64 legacy sentinel evidence disagrees with source bytes",
        ));
    }

    let local_crc = le_u32(local, 14);
    let local_comp = le_u32(local, 18);
    let local_uncomp = le_u32(local, 22);
    let uses_descriptor = member.flags & 0x0008 != 0;
    if (!uses_descriptor && local_crc != member.declared_crc)
        || (uses_descriptor && local_crc != 0 && local_crc != member.declared_crc)
    {
        return Err(VerifyError::new("ZIP64 local CRC disagrees with evidence"));
    }
    match member.zip64.local_value_shape {
        Zip64LocalValueShape::Absent => {
            let sizes_match = if uses_descriptor {
                (local_comp == 0 || u64::from(local_comp) == member.declared_comp_size)
                    && (local_uncomp == 0 || u64::from(local_uncomp) == member.declared_uncomp_size)
            } else {
                u64::from(local_comp) == member.declared_comp_size
                    && u64::from(local_uncomp) == member.declared_uncomp_size
            };
            if member.zip64.local_zip64_extra.is_some() || !sizes_match {
                return Err(VerifyError::new(
                    "ZIP64 absent local value shape is invalid",
                ));
            }
        }
        Zip64LocalValueShape::Exact => {
            let forced = local_uncomp == u32::MAX && local_comp == u32::MAX;
            let canonical = canonical_zip64_member_u32(local_uncomp, member.declared_uncomp_size)
                && canonical_zip64_member_u32(local_comp, member.declared_comp_size);
            if member.zip64.local_zip64_extra.is_none() || (!forced && !canonical) {
                return Err(VerifyError::new("ZIP64 exact local value shape is invalid"));
            }
        }
        Zip64LocalValueShape::StreamingZeros => {
            if !uses_descriptor
                || member.zip64.local_zip64_extra.is_none()
                || local_uncomp != u32::MAX
                || local_comp != u32::MAX
            {
                return Err(VerifyError::new(
                    "ZIP64 zero-streaming local value shape is invalid",
                ));
            }
        }
        Zip64LocalValueShape::StreamingMaxima => {
            if !uses_descriptor
                || member.zip64.local_zip64_extra.is_none()
                || local_uncomp != 0
                || local_comp != 0
            {
                return Err(VerifyError::new(
                    "ZIP64 maximum-streaming local value shape is invalid",
                ));
            }
        }
    }
    if member.zip64.local_zip64_extra.is_some() && member.zip64.local_version_needed < 45 {
        return Err(VerifyError::new(
            "ZIP64 local extra requires extraction version 4.5",
        ));
    }
    let standard_offset_only = member.zip64.central_presence_mask == 0b100
        && u64::from(le_u32(central, 24)) == member.declared_uncomp_size
        && u64::from(le_u32(central, 20)) == member.declared_comp_size
        && matches!(
            (member.method, member.zip64.central_version_needed),
            (0, 10) | (8, 20)
        );
    let go_offset_only = member.zip64.central_presence_mask == 0b111
        && le_u32(central, 24) == u32::MAX
        && le_u32(central, 20) == u32::MAX
        && member.zip64.central_version_needed == 20
        && matches!(member.method, 0 | 8);
    let offset_only = has_global_end_pair
        && (standard_offset_only || go_offset_only)
        && le_u32(central, 42) == u32::MAX
        && member.declared_uncomp_size < u64::from(u32::MAX)
        && member.declared_comp_size < u64::from(u32::MAX)
        && member.source_ranges.local_header.offset >= u64::from(u32::MAX);
    if member.zip64.central_zip64_extra.is_some()
        && member.zip64.central_version_needed < 45
        && !offset_only
    {
        return Err(VerifyError::new(
            "ZIP64 central extra has an invalid extraction version",
        ));
    }
    let expected_width = uses_descriptor.then_some(
        if member.zip64.local_zip64_extra.is_some()
            || member.declared_comp_size >= u64::from(u32::MAX)
            || member.declared_uncomp_size >= u64::from(u32::MAX)
        {
            Zip64DescriptorWidth::Zip64
        } else {
            Zip64DescriptorWidth::Zip32
        },
    );
    if member.zip64.descriptor_width != expected_width {
        return Err(VerifyError::new(
            "ZIP64 descriptor width evidence is not canonical",
        ));
    }
    Ok(())
}

fn verify_zip64_extras(
    source: &[u8],
    member: &Zip64Member,
    local: &[u8],
    central: &[u8],
) -> Result<(), VerifyError> {
    for (site, expected) in [
        (ExtraSite::Local, member.zip64.local_zip64_extra),
        (ExtraSite::Central, member.zip64.central_zip64_extra),
    ] {
        let mut matching = member
            .extra_fields
            .iter()
            .filter(|field| field.site == site);
        let actual = matching.next().map(|field| field.data_range);
        if matching.next().is_some() || actual != expected {
            return Err(VerifyError::new(
                "ZIP64 site-specific extra evidence is inconsistent",
            ));
        }
        if let Some(data_range) = expected {
            let header_offset = data_range
                .offset
                .checked_sub(4)
                .ok_or_else(|| VerifyError::new("ZIP64 extra header underflows"))?;
            let header = range_bytes(
                source,
                ByteRange {
                    offset: header_offset,
                    len: 4,
                },
                "ZIP64 extra header",
            )?;
            if le_u16(header, 0) != 1 || u64::from(le_u16(header, 2)) != data_range.len {
                return Err(VerifyError::new(
                    "ZIP64 extra header disagrees with evidence",
                ));
            }
        }
    }

    let local_extra_start = member
        .source_ranges
        .local_header
        .offset
        .checked_add(30 + u64::from(le_u16(local, 26)))
        .ok_or_else(|| VerifyError::new("ZIP64 local extra offset overflows"))?;
    let local_extra_end = local_extra_start
        .checked_add(u64::from(le_u16(local, 28)))
        .ok_or_else(|| VerifyError::new("ZIP64 local extra range overflows"))?;
    let central_extra_start = member
        .source_ranges
        .central_header
        .offset
        .checked_add(46 + u64::from(le_u16(central, 28)))
        .ok_or_else(|| VerifyError::new("ZIP64 central extra offset overflows"))?;
    let central_extra_end = central_extra_start
        .checked_add(u64::from(le_u16(central, 30)))
        .ok_or_else(|| VerifyError::new("ZIP64 central extra range overflows"))?;
    for (range, start, end) in [
        (
            member.zip64.local_zip64_extra,
            local_extra_start,
            local_extra_end,
        ),
        (
            member.zip64.central_zip64_extra,
            central_extra_start,
            central_extra_end,
        ),
    ] {
        if let Some(range) = range {
            let header_start = range
                .offset
                .checked_sub(4)
                .ok_or_else(|| VerifyError::new("ZIP64 extra range underflows"))?;
            if header_start != start || checked_range_end(range, "ZIP64 extra data")? != end {
                return Err(VerifyError::new(
                    "ZIP64 extra does not exactly fill its header extra area",
                ));
            }
        } else if start != end {
            return Err(VerifyError::new(
                "unrepresented ZIP64 header extra bytes remain",
            ));
        }
    }

    match member.zip64.local_zip64_extra {
        None => {
            if member.zip64.local_value_shape != Zip64LocalValueShape::Absent {
                return Err(VerifyError::new(
                    "absent ZIP64 local extra has a non-absent shape",
                ));
            }
        }
        Some(range) => {
            if range.len != 16 || member.zip64.local_value_shape == Zip64LocalValueShape::Absent {
                return Err(VerifyError::new(
                    "ZIP64 local extra has an invalid semantic shape",
                ));
            }
            let data = range_bytes(source, range, "ZIP64 local extra data")?;
            let values = [le_u64(data, 0), le_u64(data, 8)];
            let valid = match member.zip64.local_value_shape {
                Zip64LocalValueShape::Absent => false,
                Zip64LocalValueShape::Exact => {
                    values == [member.declared_uncomp_size, member.declared_comp_size]
                }
                Zip64LocalValueShape::StreamingZeros => values == [0, 0],
                Zip64LocalValueShape::StreamingMaxima => values == [u64::MAX, u64::MAX],
            };
            if !valid {
                return Err(VerifyError::new(
                    "ZIP64 local value shape disagrees with source bytes",
                ));
            }
        }
    }

    match member.zip64.central_zip64_extra {
        None => {
            if member.zip64.central_presence_mask != 0
                || member.zip64.central_legacy_sentinel_mask != 0
                || u64::from(le_u32(central, 24)) != member.declared_uncomp_size
                || u64::from(le_u32(central, 20)) != member.declared_comp_size
                || u64::from(le_u32(central, 42)) != member.source_ranges.local_header.offset
            {
                return Err(VerifyError::new(
                    "absent ZIP64 central extra disagrees with legacy fields",
                ));
            }
        }
        Some(range) => {
            let mask = member.zip64.central_presence_mask;
            if mask == 0
                || mask > 0b111
                || range.len != u64::from(mask.count_ones()) * 8
                || mask & member.zip64.central_legacy_sentinel_mask
                    != member.zip64.central_legacy_sentinel_mask
            {
                return Err(VerifyError::new("ZIP64 central presence mask is invalid"));
            }
            let data = range_bytes(source, range, "ZIP64 central extra data")?;
            let legacy = [
                le_u32(central, 24),
                le_u32(central, 20),
                le_u32(central, 42),
            ];
            let resolved = [
                member.declared_uncomp_size,
                member.declared_comp_size,
                member.source_ranges.local_header.offset,
            ];
            let required_mask = legacy
                .iter()
                .enumerate()
                .fold(0_u8, |required, (index, value)| {
                    required | (u8::from(*value == u32::MAX) << index)
                });
            let mut matching_masks = 0_u8;
            let mut unique_mask = 0_u8;
            for candidate in 1_u8..8 {
                if candidate.count_ones() != mask.count_ones()
                    || candidate & required_mask != required_mask
                {
                    continue;
                }
                let mut candidate_values = legacy.map(u64::from);
                let mut cursor = 0_usize;
                let mut valid = true;
                for (index, value) in candidate_values.iter_mut().enumerate() {
                    if candidate & (1 << index) == 0 {
                        continue;
                    }
                    let encoded = le_u64(data, cursor);
                    cursor += 8;
                    if legacy[index] == u32::MAX {
                        *value = encoded;
                    } else if encoded != u64::from(legacy[index]) {
                        valid = false;
                        break;
                    }
                }
                if valid && candidate_values == resolved {
                    matching_masks = matching_masks.saturating_add(1);
                    unique_mask = candidate;
                }
            }
            if matching_masks != 1 || unique_mask != mask {
                return Err(VerifyError::new(
                    "ZIP64 central values lack one evidence-selected interpretation",
                ));
            }
        }
    }
    Ok(())
}

fn verify_zip64_descriptor(source: &[u8], member: &Zip64Member) -> Result<(), VerifyError> {
    const DESCRIPTOR: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
    match (
        member.zip64.descriptor_width,
        member.source_ranges.data_descriptor,
    ) {
        (None, None) if member.flags & 0x0008 == 0 => Ok(()),
        (Some(width), Some(range)) if member.flags & 0x0008 != 0 => {
            let expected_len = match width {
                Zip64DescriptorWidth::Zip32 => 16,
                Zip64DescriptorWidth::Zip64 => 24,
            };
            if range.len != expected_len {
                return Err(VerifyError::new(
                    "ZIP64 descriptor range has the wrong width",
                ));
            }
            let data = range_bytes(source, range, "ZIP64 data descriptor")?;
            if data[0..4] != DESCRIPTOR || le_u32(data, 4) != member.declared_crc {
                return Err(VerifyError::new(
                    "ZIP64 descriptor signature or CRC disagrees with evidence",
                ));
            }
            let (compressed, uncompressed) = match width {
                Zip64DescriptorWidth::Zip32 => {
                    (u64::from(le_u32(data, 8)), u64::from(le_u32(data, 12)))
                }
                Zip64DescriptorWidth::Zip64 => (le_u64(data, 8), le_u64(data, 16)),
            };
            if compressed != member.declared_comp_size
                || uncompressed != member.declared_uncomp_size
            {
                return Err(VerifyError::new(
                    "ZIP64 descriptor sizes disagree with evidence",
                ));
            }
            Ok(())
        }
        _ => Err(VerifyError::new(
            "ZIP64 descriptor evidence disagrees with flag bit 3",
        )),
    }
}

fn canonical_zip64_member_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved
    } else {
        legacy == u32::MAX
    }
}

fn canonical_zip64_end_u16(legacy: u16, resolved: u64) -> bool {
    if resolved < u64::from(u16::MAX) {
        u64::from(legacy) == resolved || legacy == u16::MAX
    } else {
        legacy == u16::MAX
    }
}

fn canonical_zip64_end_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved || legacy == u32::MAX
    } else {
        legacy == u32::MAX
    }
}

fn encode_zip64_layout(ir: &Zip64ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let covering = &ir.zip64_covering;
    let members = sorted_zip64_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, covering.local_records);
    encode_range(&mut body, covering.central_directory);
    encode_optional_range(&mut body, covering.zip64_eocd);
    encode_optional_range(&mut body, covering.zip64_locator);
    encode_range(&mut body, covering.eocd);
    encode_range(&mut body, covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?,
    );
    for member in members {
        encode_zip64_layout_member(&mut body, member)?;
        push_u16(&mut body, member.zip64.local_version_needed);
        push_u16(&mut body, member.zip64.central_version_needed);
        body.push(member.zip64.central_presence_mask);
        body.push(member.zip64.central_legacy_sentinel_mask);
        body.push(member.zip64.local_legacy_sentinel_mask);
        body.push(match member.zip64.local_value_shape {
            Zip64LocalValueShape::Absent => 0,
            Zip64LocalValueShape::Exact => 1,
            Zip64LocalValueShape::StreamingZeros => 2,
            Zip64LocalValueShape::StreamingMaxima => 3,
        });
        encode_optional_range(&mut body, member.zip64.local_zip64_extra);
        encode_optional_range(&mut body, member.zip64.central_zip64_extra);
        body.push(match member.zip64.descriptor_width {
            None => 0,
            Some(Zip64DescriptorWidth::Zip32) => 1,
            Some(Zip64DescriptorWidth::Zip64) => 2,
        });
    }
    Ok(preimage(ZIP64_LAYOUT_LABEL, &body))
}

fn encode_zip64_layout_member(
    output: &mut Vec<u8>,
    member: &Zip64Member,
) -> Result<(), VerifyError> {
    push_bytes(output, member.canonical_path.as_bytes())?;
    output.push(kind_tag(&member.kind));
    push_bytes(output, &member.raw_name_bytes)?;
    push_u16(output, member.method);
    push_u16(output, member.flags);
    push_u64(output, member.declared_comp_size);
    push_u64(output, member.declared_uncomp_size);
    push_u32(output, member.declared_crc);
    encode_range(output, member.source_ranges.local_header);
    encode_range(output, member.source_ranges.compressed_payload);
    if let Some(descriptor) = member.source_ranges.data_descriptor {
        output.push(1);
        encode_range(output, descriptor);
    } else {
        output.push(0);
    }
    encode_range(output, member.source_ranges.central_header);
    let mut extras: Vec<_> = member.extra_fields.iter().collect();
    extras.sort_by_key(|extra| (site_tag(extra.site), extra.id, extra.data_range.offset));
    push_u32(
        output,
        u32::try_from(extras.len())
            .map_err(|_| VerifyError::new("ZIP64 extra-field count exceeds u32"))?,
    );
    for extra in extras {
        output.push(site_tag(extra.site));
        push_u16(output, extra.id);
        output.push(match extra.disposition {
            ExtraDisposition::Ignored => DISP_IGNORED,
            ExtraDisposition::Semantic => DISP_SEMANTIC,
            ExtraDisposition::Denied => DISP_DENIED,
        });
        push_u64(output, extra.data_range.offset);
        push_u16(
            output,
            u16::try_from(extra.data_range.len)
                .map_err(|_| VerifyError::new("ZIP64 extra data length exceeds u16"))?,
        );
    }
    push_u32(
        output,
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("ZIP64 normalization count exceeds u32"))?,
    );
    encode_normalization_actions(output, &member.normalization_actions);
    Ok(())
}

fn encode_zip64_content(ir: &Zip64ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_zip64_members(ir);
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(
            &mut body,
            member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual size"))?,
        );
        body.extend_from_slice(&decode_digest(
            member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("ZIP64 verified member has no content digest"))?,
            "ZIP64 member content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn sorted_zip64_members(ir: &Zip64ArchiveIr) -> Vec<&Zip64Member> {
    let mut members: Vec<_> = ir.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    members
}

fn encode_optional_range(output: &mut Vec<u8>, range: Option<ByteRange>) {
    if let Some(range) = range {
        output.push(1);
        encode_range(output, range);
    } else {
        output.push(0);
    }
}

fn verify_manifest(manifest: &Manifest) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(VerifyError::new(format!(
            "unsupported schema {:?}",
            manifest.schema
        )));
    }
    if manifest.tree_encoding != TREE_ENCODING {
        return Err(VerifyError::new(format!(
            "unsupported tree encoding {:?}",
            manifest.tree_encoding
        )));
    }
    if manifest.profiles.is_empty() {
        return Err(VerifyError::new("manifest has no profile vectors"));
    }
    if manifest.cases.is_empty() {
        return Err(VerifyError::new("manifest has no cases"));
    }
    if manifest.cases.len() > MAX_CASES {
        return Err(VerifyError::new(format!(
            "manifest exceeds the {MAX_CASES}-case limit"
        )));
    }

    let mut profiles = HashMap::new();
    for profile in &manifest.profiles {
        verify_profile(profile)
            .map_err(|error| error.context(&format!("profile {}", profile.id)))?;
        if profiles.insert(profile.id.as_str(), profile).is_some() {
            return Err(VerifyError::new(format!(
                "duplicate profile id {:?}",
                profile.id
            )));
        }
    }

    let mut case_ids = HashSet::new();
    let mut layout_roots = 0;
    let mut content_roots = 0;
    for case in &manifest.cases {
        if case.id.is_empty() {
            return Err(VerifyError::new("case id is empty"));
        }
        if !case_ids.insert(case.id.as_str()) {
            return Err(VerifyError::new(format!("duplicate case id {:?}", case.id)));
        }
        let (has_layout, has_content) = verify_case(case, &profiles)
            .map_err(|error| error.context(&format!("case {}", case.id)))?;
        layout_roots += usize::from(has_layout);
        content_roots += usize::from(has_content);
    }

    Ok(VerificationSummary {
        profiles: manifest.profiles.len(),
        cases: manifest.cases.len(),
        layout_roots,
        content_roots,
    })
}

fn verify_profile(profile: &ProfileVector) -> Result<(), VerifyError> {
    if profile.id.is_empty() {
        return Err(VerifyError::new("profile id is empty"));
    }
    let canonical = decode_hex(&profile.canonical_bytes_hex, "canonical_bytes_hex")?;
    if canonical.is_empty() {
        return Err(VerifyError::new("canonical profile bytes are empty"));
    }
    verify_digest(&profile.digest.sha256, "profile digest")?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "canonical profile bytes do not match digest",
        ));
    }
    let definition: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|error| VerifyError::new(format!("canonical profile JSON: {error}")))?;
    if definition.get("schema").and_then(serde_json::Value::as_str) != Some(&profile.id) {
        return Err(VerifyError::new(
            "canonical profile schema does not match profile id",
        ));
    }
    Ok(())
}

fn verify_case(
    case: &Case,
    profiles: &HashMap<&str, &ProfileVector>,
) -> Result<(bool, bool), VerifyError> {
    let source_bytes = decode_hex(&case.source_bytes_hex, "source_bytes_hex")?;
    verify_digest(&case.source.sha256, "source digest")?;
    if sha256_hex(&source_bytes) != case.source.sha256 {
        return Err(VerifyError::new("source bytes do not match source digest"));
    }

    let profile = profiles
        .get(case.interpretation.id.as_str())
        .ok_or_else(|| VerifyError::new("case references an unknown profile"))?;
    verify_digest(&case.interpretation.digest.sha256, "interpretation digest")?;
    if case.interpretation.digest.sha256 != profile.digest.sha256 {
        return Err(VerifyError::new(
            "case interpretation digest does not match profile vector",
        ));
    }
    verify_axes(&case.axes, &case.findings)?;

    for finding in &case.findings {
        if finding.code.is_empty() || finding.detail.is_empty() {
            return Err(VerifyError::new("finding code and detail must be nonempty"));
        }
        let _ = (&finding.severity, &finding.member);
    }

    match &case.archive_ir {
        Some(ir) => {
            if ir.schema != IR_SCHEMA {
                return Err(VerifyError::new(format!(
                    "unsupported IR schema {:?}",
                    ir.schema
                )));
            }
            if ir.profile != case.interpretation.id
                || ir.profile_digest != case.interpretation.digest.sha256
                || ir.source_digest.sha256 != case.source.sha256
            {
                return Err(VerifyError::new(
                    "IR source or interpretation identity does not match case",
                ));
            }
            validate_ir(ir)?;
            verify_covering(&source_bytes, ir)?;

            let expected_layout = available_root(&case.layout_root, "layout root")?
                .ok_or_else(|| VerifyError::new("IR case has no layout root"))?;
            let actual_layout = sha256_hex(&encode_layout(ir)?);
            if actual_layout != expected_layout {
                return Err(VerifyError::new(format!(
                    "layout root mismatch: expected {expected_layout}, calculated {actual_layout}"
                )));
            }

            let verification_complete =
                matches!(case.axes.verification, VerificationStatus::Complete);
            if verification_complete {
                let expected_content = available_root(&case.content_root, "content root")?
                    .ok_or_else(|| VerifyError::new("complete case has no content root"))?;
                let actual_content = sha256_hex(&encode_content(ir)?);
                if actual_content != expected_content {
                    return Err(VerifyError::new(format!(
                        "content root mismatch: expected {expected_content}, calculated {actual_content}"
                    )));
                }
                Ok((true, true))
            } else {
                if available_root(&case.content_root, "content root")?.is_some() {
                    return Err(VerifyError::new(
                        "incomplete verification carries a content root",
                    ));
                }
                Ok((true, false))
            }
        }
        None => {
            if available_root(&case.layout_root, "layout root")?.is_some()
                || available_root(&case.content_root, "content root")?.is_some()
            {
                return Err(VerifyError::new("case without IR carries a tree root"));
            }
            if matches!(case.axes.verification, VerificationStatus::Complete) {
                return Err(VerifyError::new("complete case has no IR"));
            }
            Ok((false, false))
        }
    }
}

fn verify_axes(axes: &Axes, findings: &[Finding]) -> Result<(), VerifyError> {
    if matches!(axes.verification, VerificationStatus::Complete)
        && (!matches!(axes.interpretation, InterpretationStatus::Interpreted)
            || !matches!(axes.admission, AdmissionStatus::Admitted)
            || !matches!(axes.view_completeness, ViewCompleteness::Complete))
    {
        return Err(VerifyError::new(
            "complete verification requires interpreted, admitted, complete evidence",
        ));
    }
    if matches!(axes.effect, EffectStatus::Committed)
        && (!matches!(axes.admission, AdmissionStatus::Admitted)
            || !matches!(axes.verification, VerificationStatus::Complete))
    {
        return Err(VerifyError::new(
            "committed effect requires admission and complete verification",
        ));
    }
    if matches!(axes.admission, AdmissionStatus::Denied)
        && !matches!(axes.effect, EffectStatus::NotRequested)
    {
        return Err(VerifyError::new("denied case carries an effect outcome"));
    }
    if let VerificationStatus::Partial {
        verified_members,
        pending_members,
    } = axes.verification
    {
        if verified_members.checked_add(pending_members).is_none() || pending_members == 0 {
            return Err(VerifyError::new("invalid partial verification counts"));
        }
    }
    if let ViewCompleteness::Partial { phase, cause } = &axes.view_completeness {
        if cause.is_empty() || !findings.iter().any(|finding| finding.code == *cause) {
            return Err(VerifyError::new(
                "partial evidence cause is not present in findings",
            ));
        }
        let _ = phase;
    }
    Ok(())
}

fn validate_ir(ir: &ArchiveIr) -> Result<(), VerifyError> {
    if ir.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new(format!(
            "IR exceeds the {MAX_MEMBERS_PER_CASE}-member limit"
        )));
    }
    u32::try_from(ir.members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?;
    validate_range(ir.covering.local_records, "covering.local_records")?;
    validate_range(ir.covering.central_directory, "covering.central_directory")?;
    validate_range(ir.covering.eocd, "covering.eocd")?;
    validate_range(ir.covering.comment, "covering.comment")?;

    let mut paths = HashSet::new();
    for member in &ir.members {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new(format!(
                "empty or duplicate canonical path {:?}",
                member.canonical_path
            )));
        }
        if member.components.join("/") != member.canonical_path {
            return Err(VerifyError::new(format!(
                "components do not reproduce canonical path {:?}",
                member.canonical_path
            )));
        }
        u32::try_from(member.canonical_path.len())
            .map_err(|_| VerifyError::new("canonical path exceeds u32"))?;
        u32::try_from(member.raw_name_bytes.len())
            .map_err(|_| VerifyError::new("raw name exceeds u32"))?;
        u32::try_from(member.extra_fields.len())
            .map_err(|_| VerifyError::new("extra-field count exceeds u32"))?;
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("normalization count exceeds u32"))?;

        validate_range(member.source_ranges.local_header, "member.local_header")?;
        validate_range(
            member.source_ranges.compressed_payload,
            "member.compressed_payload",
        )?;
        if let Some(descriptor) = member.source_ranges.data_descriptor {
            validate_range(descriptor, "member.data_descriptor")?;
        }
        validate_range(member.source_ranges.central_header, "member.central_header")?;
        let mut extra_ids = HashSet::new();
        for extra in &member.extra_fields {
            validate_range(extra.header_range, "extra.header_range")?;
            validate_range(extra.data_range, "extra.data_range")?;
            u16::try_from(extra.data_range.len)
                .map_err(|_| VerifyError::new("extra data length exceeds u16"))?;
            if !extra_ids.insert((extra.site, extra.id)) {
                return Err(VerifyError::new("duplicate extra-field id at one site"));
            }
            if extra.header_range.len != 4
                || checked_range_end(extra.header_range, "extra header")? != extra.data_range.offset
            {
                return Err(VerifyError::new(
                    "extra header does not exactly precede its data",
                ));
            }
            let enclosing_header = match extra.site {
                ExtraSite::Local => member.source_ranges.local_header,
                ExtraSite::Central => member.source_ranges.central_header,
            };
            if !contains_range(enclosing_header, extra.header_range)?
                || !contains_range(enclosing_header, extra.data_range)?
            {
                return Err(VerifyError::new(
                    "extra field is outside its claimed ZIP header",
                ));
            }
        }

        if let MemberVerification::Failed { cause } = &member.verification {
            if cause.is_empty() {
                return Err(VerifyError::new("failed member has an empty cause"));
            }
        }
        if matches!(member.verification, MemberVerification::Verified) {
            let actual_size = member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("verified member has no actual size"))?;
            let actual_crc = member
                .actual_crc
                .ok_or_else(|| VerifyError::new("verified member has no actual CRC"))?;
            let content_digest = member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("verified member has no content digest"))?;
            verify_digest(content_digest, "member content digest")?;
            if actual_size != member.declared_uncomp_size || actual_crc != member.declared_crc {
                return Err(VerifyError::new(
                    "verified member actual size or CRC differs from declaration",
                ));
            }
        }
        let _ = (
            &member.decoded_name,
            member.declared_comp_size,
            member.method,
            member.flags,
        );
    }
    Ok(())
}

fn validate_range(range: ByteRange, label: &str) -> Result<(), VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))?;
    Ok(())
}

fn verify_covering(source: &[u8], ir: &ArchiveIr) -> Result<(), VerifyError> {
    const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const CDH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const DESCRIPTOR: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];

    let covering = &ir.covering;
    let source_len =
        u64::try_from(source.len()).map_err(|_| VerifyError::new("source length exceeds u64"))?;
    if covering.local_records.offset != 0
        || checked_range_end(covering.local_records, "local covering")?
            != covering.central_directory.offset
        || checked_range_end(covering.central_directory, "central covering")?
            != covering.eocd.offset
        || checked_range_end(covering.eocd, "EOCD covering")? != covering.comment.offset
        || checked_range_end(covering.comment, "comment covering")? != source_len
    {
        return Err(VerifyError::new(
            "covering ranges do not form an exact source partition",
        ));
    }
    if covering.eocd.len != 22 {
        return Err(VerifyError::new("EOCD covering length is not 22"));
    }
    let eocd = range_bytes(source, covering.eocd, "EOCD")?;
    if eocd[0..4] != EOCD {
        return Err(VerifyError::new(
            "EOCD signature is absent at claimed offset",
        ));
    }
    if le_u16(eocd, 4) != 0 || le_u16(eocd, 6) != 0 {
        return Err(VerifyError::new("EOCD claims a spanned archive"));
    }
    if le_u16(eocd, 8) != le_u16(eocd, 10)
        || usize::from(le_u16(eocd, 10)) != ir.members.len()
        || u64::from(le_u32(eocd, 12)) != covering.central_directory.len
        || u64::from(le_u32(eocd, 16)) != covering.central_directory.offset
        || u64::from(le_u16(eocd, 20)) != covering.comment.len
    {
        return Err(VerifyError::new(
            "EOCD fields do not match the covering certificate",
        ));
    }

    let mut local_ranges = Vec::with_capacity(ir.members.len());
    let mut central_ranges = Vec::with_capacity(ir.members.len());
    for member in &ir.members {
        let ranges = &member.source_ranges;
        if ranges.local_header.len < 30 || ranges.central_header.len < 46 {
            return Err(VerifyError::new(
                "member header range is shorter than its fixed ZIP32 header",
            ));
        }
        if range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset,
                len: 4,
            },
            "local-header signature",
        )? != LFH
        {
            return Err(VerifyError::new(
                "local-header signature is absent at claimed offset",
            ));
        }
        if range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset,
                len: 4,
            },
            "central-header signature",
        )? != CDH
        {
            return Err(VerifyError::new(
                "central-header signature is absent at claimed offset",
            ));
        }
        if checked_range_end(ranges.local_header, "local header")?
            != ranges.compressed_payload.offset
        {
            return Err(VerifyError::new("local header does not abut its payload"));
        }
        let payload_end = checked_range_end(ranges.compressed_payload, "payload")?;
        let local_end = if let Some(descriptor) = ranges.data_descriptor {
            if payload_end != descriptor.offset {
                return Err(VerifyError::new(
                    "payload does not abut its data descriptor",
                ));
            }
            let descriptor_bytes = range_bytes(source, descriptor, "data descriptor")?;
            match descriptor_bytes.len() {
                12 if descriptor_bytes[0..4] != DESCRIPTOR => {}
                16 if descriptor_bytes[0..4] == DESCRIPTOR => {}
                _ => {
                    return Err(VerifyError::new(
                        "data descriptor is neither the 12-byte nor signed 16-byte form",
                    ));
                }
            }
            checked_range_end(descriptor, "data descriptor")?
        } else {
            payload_end
        };
        let local_record = ByteRange {
            offset: ranges.local_header.offset,
            len: local_end
                .checked_sub(ranges.local_header.offset)
                .ok_or_else(|| VerifyError::new("local record range underflows"))?,
        };
        if local_record.len == 0
            || !contains_range(covering.local_records, local_record)?
            || !contains_range(local_record, ranges.compressed_payload)?
        {
            return Err(VerifyError::new(
                "member local record is outside the local covering",
            ));
        }
        if !contains_range(covering.central_directory, ranges.central_header)? {
            return Err(VerifyError::new(
                "member central header is outside the central covering",
            ));
        }
        local_ranges.push((local_record.offset, local_end));
        central_ranges.push((
            ranges.central_header.offset,
            checked_range_end(ranges.central_header, "central header")?,
        ));
    }

    local_ranges.sort_unstable_by_key(|range| range.0);
    central_ranges.sort_unstable_by_key(|range| range.0);
    verify_partition(
        &local_ranges,
        covering.local_records,
        "local record partition",
    )?;
    verify_partition(
        &central_ranges,
        covering.central_directory,
        "central header partition",
    )?;
    Ok(())
}

fn verify_partition(
    ranges: &[(u64, u64)],
    covering: ByteRange,
    label: &str,
) -> Result<(), VerifyError> {
    if ranges.is_empty() {
        if covering.len == 0 {
            return Ok(());
        }
        return Err(VerifyError::new(format!(
            "empty {label} has a nonempty covering"
        )));
    }
    if ranges[0].0 != covering.offset
        || ranges.windows(2).any(|window| window[0].1 != window[1].0)
        || ranges.last().map(|range| range.1) != Some(checked_range_end(covering, label)?)
    {
        return Err(VerifyError::new(format!(
            "{label} does not exactly fill its covering"
        )));
    }
    Ok(())
}

fn contains_range(outer: ByteRange, inner: ByteRange) -> Result<bool, VerifyError> {
    Ok(inner.offset >= outer.offset
        && checked_range_end(inner, "inner range")? <= checked_range_end(outer, "outer range")?)
}

fn range_bytes<'a>(
    source: &'a [u8],
    range: ByteRange,
    label: &str,
) -> Result<&'a [u8], VerifyError> {
    let start = usize::try_from(range.offset)
        .map_err(|_| VerifyError::new(format!("{label} offset exceeds usize")))?;
    let end = usize::try_from(checked_range_end(range, label)?)
        .map_err(|_| VerifyError::new(format!("{label} end exceeds usize")))?;
    source
        .get(start..end)
        .ok_or_else(|| VerifyError::new(format!("{label} is outside source bytes")))
}

fn checked_range_end(range: ByteRange, label: &str) -> Result<u64, VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn available_root<'a>(root: &'a Root, label: &str) -> Result<Option<&'a str>, VerifyError> {
    match root {
        Root::Available(root) => {
            verify_digest(&root.sealr_tree_v1, label)?;
            Ok(Some(&root.sealr_tree_v1))
        }
        Root::Unavailable(root) if root.status == "unavailable" => Ok(None),
        Root::Unavailable(root) => Err(VerifyError::new(format!(
            "{label} has unsupported status {:?}",
            root.status
        ))),
    }
}

fn encode_layout(ir: &ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, ir.covering.local_records);
    encode_range(&mut body, ir.covering.central_directory);
    encode_range(&mut body, ir.covering.eocd);
    encode_range(&mut body, ir.covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?,
    );
    for member in members {
        encode_layout_member(&mut body, member)?;
    }
    Ok(preimage(LAYOUT_LABEL, &body))
}

fn encode_content(ir: &ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?,
    );
    for member in members {
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "complete content case contains an unverified member",
            ));
        }
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(
            &mut body,
            member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("verified member has no actual size"))?,
        );
        let digest = decode_digest(
            member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("verified member has no content digest"))?,
            "member content digest",
        )?;
        body.extend_from_slice(&digest);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn sorted_members(ir: &ArchiveIr) -> Vec<&Member> {
    let mut members: Vec<_> = ir.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    members
}

fn encode_layout_member(output: &mut Vec<u8>, member: &Member) -> Result<(), VerifyError> {
    push_bytes(output, member.canonical_path.as_bytes())?;
    output.push(kind_tag(&member.kind));
    push_bytes(output, &member.raw_name_bytes)?;
    push_u16(output, member.method);
    push_u16(output, member.flags);
    push_u64(output, member.declared_comp_size);
    push_u64(output, member.declared_uncomp_size);
    push_u32(output, member.declared_crc);
    encode_range(output, member.source_ranges.local_header);
    encode_range(output, member.source_ranges.compressed_payload);
    if let Some(descriptor) = member.source_ranges.data_descriptor {
        output.push(1);
        encode_range(output, descriptor);
    } else {
        output.push(0);
    }
    encode_range(output, member.source_ranges.central_header);

    let mut extras: Vec<_> = member.extra_fields.iter().collect();
    extras.sort_by_key(|extra| (site_tag(extra.site), extra.id, extra.data_range.offset));
    push_u32(
        output,
        u32::try_from(extras.len())
            .map_err(|_| VerifyError::new("extra-field count exceeds u32"))?,
    );
    for extra in extras {
        output.push(site_tag(extra.site));
        push_u16(output, extra.id);
        output.push(match extra.disposition {
            ExtraDisposition::Ignored => DISP_IGNORED,
            ExtraDisposition::Semantic => DISP_SEMANTIC,
            ExtraDisposition::Denied => DISP_DENIED,
        });
        push_u64(output, extra.data_range.offset);
        push_u16(
            output,
            u16::try_from(extra.data_range.len)
                .map_err(|_| VerifyError::new("extra data length exceeds u16"))?,
        );
    }

    push_u32(
        output,
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("normalization count exceeds u32"))?,
    );
    for action in &member.normalization_actions {
        match action {
            NormalizationAction::StripDirectoryTrailingSlash => {
                output.push(NORM_STRIP_DIR_SLASH);
            }
            NormalizationAction::DropDotComponent { component_index } => {
                output.push(NORM_DROP_DOT);
                push_u32(output, *component_index);
            }
        }
    }
    Ok(())
}

fn kind_tag(kind: &MemberKind) -> u8 {
    match kind {
        MemberKind::File => FILE,
        MemberKind::Directory => DIRECTORY,
    }
}

fn site_tag(site: ExtraSite) -> u8 {
    match site {
        ExtraSite::Local => SITE_LOCAL,
        ExtraSite::Central => SITE_CENTRAL,
    }
}

fn encode_range(output: &mut Vec<u8>, range: ByteRange) {
    push_u64(output, range.offset);
    push_u64(output, range.len);
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VerifyError> {
    push_u32(
        output,
        u32::try_from(bytes.len()).map_err(|_| VerifyError::new("byte string exceeds u32"))?,
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn preimage(label: &str, body: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(label.as_bytes());
    output.push(b' ');
    output.extend_from_slice(body.len().to_string().as_bytes());
    output.push(0);
    output.extend_from_slice(body);
    output
}

fn verify_digest(value: &str, label: &str) -> Result<(), VerifyError> {
    decode_digest(value, label).map(|_| ())
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; 32], VerifyError> {
    if value.len() != 64 {
        return Err(VerifyError::new(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        )));
    }
    let decoded = decode_hex(value, label)?;
    decoded
        .try_into()
        .map_err(|_| VerifyError::new(format!("{label} is not 32 bytes")))
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, VerifyError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifyError::new(format!(
            "{label} must be lowercase, even-length hexadecimal"
        )));
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(VerifyError::new(format!(
            "{label} must have even hexadecimal length"
        )));
    }
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| VerifyError::new(format!("{label} is not UTF-8")))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| VerifyError::new(format!("{label} contains invalid hexadecimal")))
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
        }
        output
    }

    fn tar_gzip_vector_with_header_mutation(mutate: impl FnOnce(&mut [u8])) -> serde_json::Value {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut derived = decode_hex(
            vector["derived_tar"]["bytes_hex"].as_str().unwrap(),
            "test derived TAR",
        )
        .unwrap();
        mutate(&mut derived[..512]);
        derived[148..156].fill(b' ');
        let checksum = derived[..512]
            .iter()
            .fold(0_u32, |sum, byte| sum + u32::from(*byte));
        let checksum_text = format!("{checksum:06o}");
        assert_eq!(checksum_text.len(), 6);
        derived[148..154].copy_from_slice(checksum_text.as_bytes());
        derived[154] = 0;
        derived[155] = b' ';

        let header_sha = sha256_hex(&derived[..512]);
        let derived_sha = sha256_hex(&derived);
        let derived_crc = crc32_ieee_bytes(&derived);
        vector["derived_tar"]["bytes_hex"] = serde_json::json!(hex_bytes(&derived));
        vector["derived_tar"]["source"]["sha256"] = serde_json::json!(derived_sha.clone());
        vector["derived_tar"]["members"][0]["tar"]["header_checksum"] = serde_json::json!(checksum);
        vector["derived_tar"]["members"][0]["tar"]["header_sha256"] = serde_json::json!(header_sha);

        for case_index in 0..2 {
            let mut source = decode_hex(
                vector["cases"][case_index]["source_bytes_hex"]
                    .as_str()
                    .unwrap(),
                "test gzip source",
            )
            .unwrap();
            let trailer_offset = vector["cases"][case_index]["gzip"]["trailer"]["offset"]
                .as_u64()
                .and_then(|offset| usize::try_from(offset).ok())
                .unwrap();
            source[trailer_offset..trailer_offset + 4].copy_from_slice(&derived_crc.to_le_bytes());
            vector["cases"][case_index]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
            vector["cases"][case_index]["source"]["sha256"] =
                serde_json::json!(sha256_hex(&source));
            vector["cases"][case_index]["gzip"]["declared_crc32"] = serde_json::json!(derived_crc);
            vector["cases"][case_index]["gzip"]["derived_output_sha256"] =
                serde_json::json!(derived_sha.clone());
        }

        let manifest: TarGzipManifest = serde_json::from_value(vector.clone()).unwrap();
        let raw_preimage = encode_tar_gzip_inner_layout(&manifest.derived_tar).unwrap();
        vector["derived_tar"]["raw_layout_preimage_hex"] =
            serde_json::json!(hex_bytes(&raw_preimage));
        vector["derived_tar"]["raw_layout_root"]["sealrTreeV2"] =
            serde_json::json!(sha256_hex(&raw_preimage));
        for case_index in 0..2 {
            let preimage = encode_tar_gzip_layout(&manifest.cases[case_index], &manifest).unwrap();
            vector["cases"][case_index]["layout_preimage_hex"] =
                serde_json::json!(hex_bytes(&preimage));
            vector["cases"][case_index]["layout_root"]["sealrTreeV4"] =
                serde_json::json!(sha256_hex(&preimage));
        }
        vector
    }

    fn tar_gzip_case_with_extra_payload(
        payload: &[u8],
        subfield_count: u32,
    ) -> (Vec<u8>, TarGzipManifest) {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source = decode_hex(
            vector["cases"][0]["source_bytes_hex"].as_str().unwrap(),
            "test gzip source",
        )
        .unwrap();
        let payload_len = u16::try_from(payload.len()).unwrap();
        let mut replacement = payload_len.to_le_bytes().to_vec();
        replacement.extend_from_slice(payload);
        source.splice(10..19, replacement.iter().copied());
        let extra_len = u64::try_from(replacement.len()).unwrap();
        let header_len = 28 + extra_len;
        let payload_offset = header_len;
        let trailer_offset = payload_offset + 116;
        vector["cases"][0]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
        vector["cases"][0]["source"]["sha256"] = serde_json::json!(sha256_hex(&source));
        vector["cases"][0]["gzip"]["header"]["len"] = serde_json::json!(header_len);
        vector["cases"][0]["gzip"]["extra"]["len"] = serde_json::json!(extra_len);
        vector["cases"][0]["gzip"]["extra_subfield_count"] = serde_json::json!(subfield_count);
        vector["cases"][0]["gzip"]["original_name"]["offset"] = serde_json::json!(10 + extra_len);
        vector["cases"][0]["gzip"]["comment"]["offset"] = serde_json::json!(22 + extra_len);
        vector["cases"][0]["gzip"]["compressed_payload"]["offset"] =
            serde_json::json!(payload_offset);
        vector["cases"][0]["gzip"]["trailer"]["offset"] = serde_json::json!(trailer_offset);
        let manifest: TarGzipManifest = serde_json::from_value(vector).unwrap();
        (source, manifest)
    }

    #[test]
    fn portable_ustar_profile_vector_verifies_without_sealr() {
        let vector =
            include_bytes!("../../../crates/sealr/tests/conformance/tar-ustar-portable-v1.json");
        let canonical = &vector[..vector.len() - 1];
        assert_eq!(
            sha256_hex(canonical),
            "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700"
        );
        let value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        assert_eq!(value["schema"], "sealr.profile.tar.ustar-portable.v1");
    }

    const VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/identity-v1.json");
    const ZIP64_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/zip64-identity-v1.json");
    const TAR_GZIP_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-gzip-identity-v1.json");
    const TAR_PAX_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-pax-identity-v1.json");
    const TAR_GNU_LONGNAME_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-gnu-longname-identity-v1.json");
    const TAR_GZIP_PAX_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-gzip-pax-identity-v1.json");
    const TAR_GZIP_GNU_LONGNAME_VECTORS: &[u8] = include_bytes!(
        "../../../crates/sealr/tests/conformance/tar-gzip-gnu-longname-identity-v1.json"
    );
    const TAR_LAYOUT_VECTOR: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-layout-v2.json");

    #[test]
    fn zip64_profile_digest_is_reconstructed_without_sealr() {
        assert_eq!(
            sha256_hex(&zip64_profile_canonical_bytes().unwrap()),
            "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2"
        );
    }

    #[test]
    fn committed_zip64_vectors_verify_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 2,
            content_roots: 2,
        };
        assert_eq!(
            verify_zip64_identity_vector_json(ZIP64_VECTORS).unwrap(),
            expected
        );
        assert_eq!(verify_manifest_json(ZIP64_VECTORS).unwrap(), expected);
    }

    #[test]
    fn committed_tar_gzip_vectors_verify_both_domains_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 3,
            content_roots: 3,
        };
        assert_eq!(
            verify_tar_gzip_identity_vector_json(TAR_GZIP_VECTORS).unwrap(),
            expected
        );
        assert_eq!(verify_manifest_json(TAR_GZIP_VECTORS).unwrap(), expected);

        let manifest: TarGzipManifest = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        assert_ne!(
            manifest.cases[0].source.sha256,
            manifest.cases[1].source.sha256
        );
        assert_ne!(
            manifest.cases[0].layout_root.sealr_tree_v4,
            manifest.cases[1].layout_root.sealr_tree_v4
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.cases[1].content_root.sealr_tree_v1
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.derived_tar.content_root.sealr_tree_v1
        );
    }

    #[test]
    fn committed_tar_pax_vectors_verify_source_state_and_both_roots_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 2,
            content_roots: 2,
        };
        assert_eq!(
            verify_tar_pax_identity_vector_json(TAR_PAX_VECTORS).unwrap(),
            expected
        );
        assert_eq!(verify_manifest_json(TAR_PAX_VECTORS).unwrap(), expected);

        let manifest: TarPaxManifest = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        assert_eq!(
            manifest.profile.digest.sha256,
            "db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445"
        );
        assert_eq!(
            manifest.cases[0].layout_root.sealr_tree_v5,
            "df37178d11acabacd11f384ebf8b77fef80bef65ba6a923d94d7b32d53c03442"
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            "82e62b2a1eeea4f2e70a0a7fdc9a869a68ad8d4b552940759a74ddc352596789"
        );
        assert_eq!(
            manifest.cases[1].layout_root.sealr_tree_v5,
            "8361957ae88f826d3d9b11604057a08f2b027ecfa498f8c37ac6a593818472a8"
        );
        assert_eq!(
            manifest.cases[1].content_root.sealr_tree_v1,
            "a2e2aa8b8b14dc562e94a4e09533c456e206ccb1f5bcea9c2d8be7ff1fa5ba94"
        );
    }

    #[test]
    fn tar_pax_profile_digest_is_reconstructed_without_sealr() {
        let manifest: TarPaxManifest = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        verify_tar_pax_profile(&manifest.profile).unwrap();
    }

    #[test]
    fn tar_pax_tampered_source_and_state_references_are_rejected() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        let mut source = decode_hex(
            vector["cases"][0]["source_bytes_hex"].as_str().unwrap(),
            "test PAX source",
        )
        .unwrap();
        source[0] ^= 1;
        let source_sha = sha256_hex(&source);
        vector["cases"][0]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
        vector["cases"][0]["source"]["sha256"] = serde_json::json!(source_sha.clone());
        vector["cases"][0]["archive_ir"]["source_digest"]["sha256"] = serde_json::json!(source_sha);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("checksum"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        vector["cases"][1]["archive_ir"]["members"][0]["tar_pax"]["path_source"]
            ["extension_index"] = serde_json::json!(0);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("resolved state"));
    }

    #[test]
    fn tar_pax_record_geometry_profile_and_layout_mutations_are_rejected() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        vector["cases"][0]["archive_ir"]["pax_extensions"][0]["records"][0]["value"]["offset"] =
            serde_json::json!(521);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("record 0 evidence"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        vector["profile"]["digest"]["sha256"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile digest"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_PAX_VECTORS).unwrap();
        vector["cases"][0]["layout_root"]["sealrTreeV5"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));
    }

    #[test]
    fn tar_pax_header_enforces_underlying_directory_size() {
        fn header(size: u64, typeflag: u8) -> [u8; 512] {
            fn octal(field: &mut [u8], value: u64) {
                field.fill(b'0');
                let value = format!("{value:o}");
                let end = field.len() - 1;
                field[end - value.len()..end].copy_from_slice(value.as_bytes());
                field[end] = 0;
            }

            let mut header = [0_u8; 512];
            header[..3].copy_from_slice(b"dir");
            octal(&mut header[100..108], 0o755);
            octal(&mut header[108..116], 0);
            octal(&mut header[116..124], 0);
            octal(&mut header[124..136], size);
            octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = typeflag;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            octal(&mut header[329..337], 0);
            octal(&mut header[337..345], 0);
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
            header[154] = 0;
            header[155] = b' ';
            header
        }

        let Err(error) = parse_tar_pax_header(&header(1, b'5')) else {
            panic!("nonzero underlying directory size must be rejected");
        };
        assert!(error
            .to_string()
            .contains("PAX directory has a nonzero underlying size"));
        parse_tar_pax_header(&header(0, b'5')).expect("zero-size directory remains canonical");
        parse_tar_pax_header(&header(1, b'0')).expect("nonzero regular file remains canonical");
    }

    #[test]
    fn committed_tar_gnu_longname_vectors_verify_state_and_both_roots_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 2,
            content_roots: 2,
        };
        assert_eq!(
            verify_tar_gnu_longname_identity_vector_json(TAR_GNU_LONGNAME_VECTORS).unwrap(),
            expected
        );
        assert_eq!(
            verify_manifest_json(TAR_GNU_LONGNAME_VECTORS).unwrap(),
            expected
        );

        let manifest: TarGnuLongNameManifest =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        assert_eq!(
            manifest.profile.digest.sha256,
            "08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4"
        );
        assert_eq!(
            manifest.cases[0].layout_root.sealr_tree_v6,
            "40eca4cb8b52bcb3f52d7706620b643125c2b9134ac0b26ecf43f13e254d9a1a"
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            "7d0746a82186263db1ab62a81d7ce54812778c05fe4df090359738cb634f4fee"
        );
        assert_eq!(
            manifest.cases[1].layout_root.sealr_tree_v6,
            "062c3182f1be41752f697f693123d064ea93d52b4c73a3ace6948dab54a2f23b"
        );
        assert_eq!(
            manifest.cases[1].content_root.sealr_tree_v1,
            "d85889f682cd54562a3896540403a8d04d3b15f5f9ff15a80c4fb8abe08e4dc6"
        );
    }

    #[test]
    fn tar_gnu_longname_profile_digest_is_reconstructed_without_sealr() {
        let manifest: TarGnuLongNameManifest =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        verify_tar_gnu_longname_profile(&manifest.profile).unwrap();
    }

    #[test]
    fn tar_gnu_longname_magic_payload_and_state_mutations_are_rejected() {
        fn mutate_source(
            vector: &mut serde_json::Value,
            case_index: usize,
            mutate: impl FnOnce(&mut [u8], &serde_json::Value),
        ) {
            let mut source = decode_hex(
                vector["cases"][case_index]["source_bytes_hex"]
                    .as_str()
                    .unwrap(),
                "test TAR/GNU long-name source",
            )
            .unwrap();
            mutate(&mut source, &vector["cases"][case_index]);
            let digest = sha256_hex(&source);
            vector["cases"][case_index]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
            vector["cases"][case_index]["source"]["sha256"] = serde_json::json!(digest.clone());
            vector["cases"][case_index]["archive_ir"]["source_digest"]["sha256"] =
                serde_json::json!(digest);
        }

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        mutate_source(&mut vector, 0, |source, _| source[263] = b'0');
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("exact old-GNU magic"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        mutate_source(&mut vector, 0, |source, case| {
            let payload = &case["archive_ir"]["gnu_longname_carriers"][0]["payload"];
            let end = payload["offset"].as_u64().unwrap() + payload["len"].as_u64().unwrap();
            source[usize::try_from(end - 1).unwrap()] = 1;
        });
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("one final NUL"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        vector["cases"][0]["archive_ir"]["members"][0]["tar_gnu_longname"]["path_source"]
            ["carrier_index"] = serde_json::json!(1);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("resolved state"));
    }

    #[test]
    fn tar_gnu_longname_carrier_evidence_profile_and_layout_mutations_are_rejected() {
        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        vector["cases"][1]["archive_ir"]["gnu_longname_carriers"][0]["raw_name_bytes"][0] =
            serde_json::json!(0);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("carrier evidence"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        vector["profile"]["digest"]["sha256"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile digest"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GNU_LONGNAME_VECTORS).unwrap();
        vector["cases"][0]["layout_root"]["sealrTreeV6"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));
    }

    #[test]
    fn committed_tar_gzip_pax_vectors_verify_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 3,
            content_roots: 3,
        };
        assert_eq!(
            verify_tar_gzip_pax_identity_vector_json(TAR_GZIP_PAX_VECTORS).unwrap(),
            expected
        );
        assert_eq!(
            verify_manifest_json(TAR_GZIP_PAX_VECTORS).unwrap(),
            expected
        );

        let manifest: TarGzipPaxManifest = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        assert_ne!(
            manifest.cases[0].source.sha256,
            manifest.cases[1].source.sha256
        );
        assert_ne!(
            manifest.cases[0].layout_root.sealr_tree_v7,
            manifest.cases[1].layout_root.sealr_tree_v7
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.cases[1].content_root.sealr_tree_v1
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.derived_tar.content_root.sealr_tree_v1
        );
    }

    #[test]
    fn committed_tar_gzip_gnu_longname_vectors_verify_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 3,
            content_roots: 3,
        };
        assert_eq!(
            verify_tar_gzip_gnu_longname_identity_vector_json(TAR_GZIP_GNU_LONGNAME_VECTORS)
                .unwrap(),
            expected
        );
        assert_eq!(
            verify_manifest_json(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap(),
            expected
        );

        let manifest: TarGzipGnuLongNameManifest =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        assert_ne!(
            manifest.cases[0].source.sha256,
            manifest.cases[1].source.sha256
        );
        assert_ne!(
            manifest.cases[0].layout_root.sealr_tree_v8,
            manifest.cases[1].layout_root.sealr_tree_v8
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.cases[1].content_root.sealr_tree_v1
        );
        assert_eq!(
            manifest.cases[0].content_root.sealr_tree_v1,
            manifest.derived_tar.content_root.sealr_tree_v1
        );
    }

    #[test]
    fn tar_gzip_pax_profile_digest_is_reconstructed_without_sealr() {
        let manifest: TarGzipPaxManifest = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        verify_tar_gzip_pax_profile(
            &manifest.profile,
            &manifest.inner_profile,
            &manifest.transform,
        )
        .unwrap();
        assert_eq!(
            sha256_hex(&tar_pax_profile_canonical_bytes().unwrap()),
            "db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445"
        );
        assert_eq!(
            sha256_hex(
                &tar_gzip_pax_profile_canonical_bytes(&manifest.inner_profile, &manifest.transform)
                    .unwrap()
            ),
            "6cc91b2b8563b5b070b44bf357a5c62e5d9dda0aedc374d7a08cd80da9c5434f"
        );
    }

    #[test]
    fn tar_gzip_gnu_longname_profile_digest_is_reconstructed_without_sealr() {
        let manifest: TarGzipGnuLongNameManifest =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        verify_tar_gzip_gnu_longname_profile(
            &manifest.profile,
            &manifest.inner_profile,
            &manifest.transform,
        )
        .unwrap();
        assert_eq!(
            sha256_hex(&tar_gnu_longname_profile_canonical_bytes().unwrap()),
            "08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4"
        );
        assert_eq!(
            sha256_hex(
                &tar_gzip_gnu_longname_profile_canonical_bytes(
                    &manifest.inner_profile,
                    &manifest.transform
                )
                .unwrap()
            ),
            "622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a"
        );
    }

    #[test]
    fn tar_gzip_pax_tampered_roots_and_wrapper_fields_are_rejected() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["cases"][0]["layout_root"]["sealrTreeV7"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["derived_tar"]["raw_layout_root"]["sealrTreeV5"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("raw TAR/PAX layout root mismatch"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["cases"][0]["gzip"]["declared_isize"] = serde_json::json!(1);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("CRC32, ISIZE, length, or SHA-256 disagree"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["profile"]["digest"]["sha256"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile digest"));
    }

    #[test]
    fn tar_gzip_pax_tampered_derived_bytes_and_provenance_are_rejected() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        let mut derived = decode_hex(
            vector["derived_tar"]["bytes_hex"].as_str().unwrap(),
            "test derived TAR/PAX",
        )
        .unwrap();
        derived[0] ^= 1;
        vector["derived_tar"]["bytes_hex"] = serde_json::json!(hex_bytes(&derived));
        vector["derived_tar"]["source"]["sha256"] = serde_json::json!(sha256_hex(&derived));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("checksum"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["derived_tar"]["members"][0]["tar_pax"]["path_source"]["extension_index"] =
            serde_json::json!(7);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("resolved state"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_PAX_VECTORS).unwrap();
        vector["derived_tar"]["pax_extensions"][0]["records"][0]["value"]["offset"] =
            serde_json::json!(521);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("record 0 evidence"));
    }

    #[test]
    fn tar_gzip_gnu_longname_tampered_roots_and_wrapper_fields_are_rejected() {
        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["cases"][0]["layout_root"]["sealrTreeV8"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["derived_tar"]["raw_layout_root"]["sealrTreeV6"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("raw TAR/GNU long-name layout root mismatch"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["cases"][1]["gzip"]["declared_crc32"] = serde_json::json!(1);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("CRC32, ISIZE, length, or SHA-256 disagree"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["profile"]["digest"]["sha256"] = serde_json::json!("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile digest"));
    }

    #[test]
    fn tar_gzip_gnu_longname_tampered_derived_bytes_and_state_are_rejected() {
        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        let mut derived = decode_hex(
            vector["derived_tar"]["bytes_hex"].as_str().unwrap(),
            "test derived TAR/GNU long-name",
        )
        .unwrap();
        derived[263] = b'0';
        vector["derived_tar"]["bytes_hex"] = serde_json::json!(hex_bytes(&derived));
        vector["derived_tar"]["source"]["sha256"] = serde_json::json!(sha256_hex(&derived));
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("exact old-GNU magic"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["derived_tar"]["gnu_longname_carriers"][0]["raw_name_bytes"][0] =
            serde_json::json!(0);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("carrier evidence"));

        let mut vector: serde_json::Value =
            serde_json::from_slice(TAR_GZIP_GNU_LONGNAME_VECTORS).unwrap();
        vector["derived_tar"]["members"][0]["tar_gnu_longname"]["path_source"]["carrier_index"] =
            serde_json::json!(3);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error.to_string().contains("resolved state"));
    }

    #[test]
    fn tar_gzip_profile_and_transform_constants_are_reconstructed() {
        let manifest: TarGzipManifest = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        verify_tar_gzip_transform(&manifest.transform).unwrap();
        verify_tar_gzip_profile(
            &manifest.profile,
            &manifest.inner_profile,
            &manifest.transform,
        )
        .unwrap();
        assert_eq!(
            sha256_hex(
                &tar_gzip_profile_canonical_bytes(&manifest.inner_profile, &manifest.transform)
                    .unwrap()
            ),
            "914acdc0eab541483309a6838716fe837488ca80a1b7758383f28e47470925e1"
        );
    }

    #[test]
    fn tar_gzip_structural_magic_trailing_member_and_inner_records_are_denied() {
        let mut manifest: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source = decode_hex(
            manifest["cases"][0]["source_bytes_hex"].as_str().unwrap(),
            "test gzip source",
        )
        .unwrap();
        source[0..4].copy_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        manifest["cases"][0]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
        manifest["cases"][0]["source"]["sha256"] = serde_json::json!(sha256_hex(&source));
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("fixed structural signature"));

        let mut manifest: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source = decode_hex(
            manifest["cases"][0]["source_bytes_hex"].as_str().unwrap(),
            "test gzip source",
        )
        .unwrap();
        source.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]);
        manifest["cases"][0]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
        manifest["cases"][0]["source"]["sha256"] = serde_json::json!(sha256_hex(&source));
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("exactly partition one source member"));

        let mut manifest: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut derived = decode_hex(
            manifest["derived_tar"]["bytes_hex"].as_str().unwrap(),
            "test derived TAR",
        )
        .unwrap();
        derived[1024..1029].copy_from_slice(b"ustar");
        manifest["derived_tar"]["bytes_hex"] = serde_json::json!(hex_bytes(&derived));
        manifest["derived_tar"]["source"]["sha256"] = serde_json::json!(sha256_hex(&derived));
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("terminator contains nonzero bytes"));
    }

    #[test]
    fn tar_gzip_valid_and_corrupt_fhcrc_are_distinguished_without_decompression() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source = decode_hex(
            vector["cases"][0]["source_bytes_hex"].as_str().unwrap(),
            "test gzip source",
        )
        .unwrap();
        source[3] |= 0x02;
        let fhcrc = (crc32_ieee_bytes(&source[..37]) as u16).to_le_bytes();
        source.splice(37..37, fhcrc);
        vector["cases"][0]["source_bytes_hex"] = serde_json::json!(hex_bytes(&source));
        vector["cases"][0]["source"]["sha256"] = serde_json::json!(sha256_hex(&source));
        vector["cases"][0]["gzip"]["flags"] = serde_json::json!(30);
        vector["cases"][0]["gzip"]["header"]["len"] = serde_json::json!(39);
        vector["cases"][0]["gzip"]["header_crc16"] = serde_json::json!({ "offset": 37, "len": 2 });
        vector["cases"][0]["gzip"]["compressed_payload"]["offset"] = serde_json::json!(39);
        vector["cases"][0]["gzip"]["trailer"]["offset"] = serde_json::json!(155);
        let manifest: TarGzipManifest = serde_json::from_value(vector.clone()).unwrap();
        let derived = decode_hex(&manifest.derived_tar.bytes_hex, "test derived TAR").unwrap();
        verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .expect("valid FHCRC");

        source[37] ^= 1;
        let manifest: TarGzipManifest = serde_json::from_value(vector).unwrap();
        let error = verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("FHCRC disagrees"));
    }

    #[test]
    fn tar_gzip_inner_ustar_rejects_targeted_self_consistent_mutations() {
        type HeaderMutation = (&'static str, fn(&mut [u8]), &'static str);
        let mutations: [HeaderMutation; 9] = [
            (
                "linkname",
                (|header: &mut [u8]| header[157] = b'x') as fn(&mut [u8]),
                "linkname",
            ),
            (
                "reserved byte",
                |header: &mut [u8]| header[500] = 1,
                "reserved ustar header bytes",
            ),
            (
                "uid grammar",
                |header: &mut [u8]| header[108] = b' ',
                "TAR uid is not canonical ASCII octal",
            ),
            (
                "gid base-256",
                |header: &mut [u8]| header[116] = 0x80,
                "TAR gid uses denied base-256 encoding",
            ),
            (
                "device number",
                |header: &mut [u8]| header[329..337].copy_from_slice(b"0000001\0"),
                "device numbers must be zero",
            ),
            (
                "uname printable ASCII",
                |header: &mut [u8]| header[265] = 1,
                "TAR uname is not printable ASCII",
            ),
            (
                "gname zero remainder",
                |header: &mut [u8]| {
                    header[297] = b'g';
                    header[298] = 0;
                    header[299] = b'x';
                },
                "TAR gname has nonzero bytes after its first NUL",
            ),
            (
                "empty name with prefix",
                |header: &mut [u8]| {
                    header[..100].fill(0);
                    header[345..500].fill(0);
                    header[345..353].copy_from_slice(b"mission\0");
                },
                "TAR name is empty",
            ),
            (
                "unterminated octal",
                |header: &mut [u8]| header[136..148].fill(b'0'),
                "TAR mtime is not canonical ASCII octal",
            ),
        ];
        for (label, mutate, expected) in mutations {
            let vector = tar_gzip_vector_with_header_mutation(mutate);
            let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{label} reached unexpected rejection: {error}"
            );
        }
    }

    #[test]
    fn tar_gzip_fextra_subfield_grammar_is_closed_and_multi_field_capable() {
        let manifest: TarGzipManifest = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let derived = decode_hex(&manifest.derived_tar.bytes_hex, "test derived TAR").unwrap();

        let (source, manifest) = tar_gzip_case_with_extra_payload(&[0], 0);
        let error = verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("incomplete subfield header"));

        let manifest: TarGzipManifest = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source =
            decode_hex(&manifest.cases[0].source_bytes_hex, "test gzip source").unwrap();
        source[13] = 0;
        let error = verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("reserved SI2 zero"));

        let duplicate = [b'A', b'B', 0, 0, b'A', b'B', 0, 0];
        let (source, manifest) = tar_gzip_case_with_extra_payload(&duplicate, 2);
        let error = verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("repeats a subfield id"));

        let manifest: TarGzipManifest = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let mut source =
            decode_hex(&manifest.cases[0].source_bytes_hex, "test gzip source").unwrap();
        source[14..16].copy_from_slice(&4_u16.to_le_bytes());
        let error = verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("subfield exceeds XLEN"));

        let valid = [b'A', b'B', 0, 0, b'C', b'D', 0, 0];
        let (source, manifest) = tar_gzip_case_with_extra_payload(&valid, 2);
        verify_gzip_wrapper(
            &source,
            &manifest.cases[0].gzip,
            &derived,
            &manifest.derived_tar.source.sha256,
        )
        .expect("two unique canonical FEXTRA subfields must verify");
    }

    #[test]
    fn tar_gzip_v1_case_set_is_exact_ordered_and_checked_early() {
        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        let cloned_case = vector["cases"][0].clone();
        vector["cases"].as_array_mut().unwrap().push(cloned_case);
        vector["transform"]["definition_hex"] = serde_json::json!("00");
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("exactly the two canonical ordered cases"));

        let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
        vector["cases"].as_array_mut().unwrap().swap(0, 1);
        let error = verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("exactly the two canonical ordered cases"));
    }

    #[test]
    fn tar_gzip_mutations_across_wrapper_derived_inner_and_roots_are_rejected() {
        let mutations = [
            ("/schema", serde_json::json!("sealr.unknown")),
            (
                "/archive_ir_schema",
                serde_json::json!("sealr.archive-ir.v1"),
            ),
            ("/profile/id", serde_json::json!("sealr.profile.unknown")),
            ("/profile/digest/sha256", serde_json::json!("0".repeat(64))),
            (
                "/transform/id",
                serde_json::json!("sealr.transform.unknown"),
            ),
            ("/transform/definition_hex", serde_json::json!("00")),
            (
                "/transform/digest/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/transform/decoder_parameters_hex", serde_json::json!("00")),
            (
                "/transform/decoder_parameters_digest/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/inner_profile/id",
                serde_json::json!("sealr.profile.tar.unknown"),
            ),
            (
                "/inner_profile/digest/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/layout_encoding", serde_json::json!("sealrTreeV2")),
            (
                "/layout_label",
                serde_json::json!("sealr.tree.layout.tar-ustar.v1"),
            ),
            ("/content_encoding", serde_json::json!("sealrTreeV4")),
            ("/content_label", serde_json::json!("sealr.tree.content.v2")),
            ("/derived_tar/bytes_hex", serde_json::json!("00")),
            (
                "/derived_tar/source/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/derived_tar/covering/member_records/len",
                serde_json::json!(1023),
            ),
            (
                "/derived_tar/covering/terminator/offset",
                serde_json::json!(1023),
            ),
            (
                "/derived_tar/covering/trailing_zeros/len",
                serde_json::json!(1),
            ),
            (
                "/derived_tar/members/0/raw_name_bytes",
                serde_json::json!([120]),
            ),
            (
                "/derived_tar/members/0/decoded_name",
                serde_json::json!("x"),
            ),
            (
                "/derived_tar/members/0/canonical_path",
                serde_json::json!("x"),
            ),
            (
                "/derived_tar/members/0/components",
                serde_json::json!(["x"]),
            ),
            (
                "/derived_tar/members/0/kind",
                serde_json::json!("directory"),
            ),
            (
                "/derived_tar/members/0/declared_uncomp_size",
                serde_json::json!(24),
            ),
            (
                "/derived_tar/members/0/tar/header/offset",
                serde_json::json!(1),
            ),
            (
                "/derived_tar/members/0/tar/header/len",
                serde_json::json!(511),
            ),
            (
                "/derived_tar/members/0/tar/payload/offset",
                serde_json::json!(511),
            ),
            (
                "/derived_tar/members/0/tar/payload/len",
                serde_json::json!(24),
            ),
            (
                "/derived_tar/members/0/tar/padding/offset",
                serde_json::json!(536),
            ),
            (
                "/derived_tar/members/0/tar/padding/len",
                serde_json::json!(486),
            ),
            ("/derived_tar/members/0/tar/mode", serde_json::json!(384)),
            (
                "/derived_tar/members/0/tar/mtime",
                serde_json::json!(1788000001_u64),
            ),
            (
                "/derived_tar/members/0/tar/header_checksum",
                serde_json::json!(0),
            ),
            (
                "/derived_tar/members/0/tar/header_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/derived_tar/members/0/actual_uncomp_size",
                serde_json::json!(24),
            ),
            ("/derived_tar/members/0/actual_crc", serde_json::json!(0)),
            (
                "/derived_tar/members/0/content_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/derived_tar/members/0/verification/status",
                serde_json::json!("pending"),
            ),
            (
                "/derived_tar/members/0/normalization_actions",
                serde_json::json!([{ "action": "strip-directory-trailing-slash" }]),
            ),
            (
                "/derived_tar/raw_layout_preimage_hex",
                serde_json::json!("00"),
            ),
            (
                "/derived_tar/raw_layout_root/sealrTreeV2",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/derived_tar/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
            ("/cases/1/id", serde_json::json!("optional-default")),
            ("/cases/0/source_bytes_hex", serde_json::json!("00")),
            ("/cases/0/source/sha256", serde_json::json!("0".repeat(64))),
            ("/cases/0/gzip/flags", serde_json::json!(0)),
            ("/cases/0/gzip/modification_time", serde_json::json!(1)),
            ("/cases/0/gzip/extra_flags", serde_json::json!(1)),
            ("/cases/0/gzip/operating_system", serde_json::json!(3)),
            ("/cases/0/gzip/header/len", serde_json::json!(36)),
            ("/cases/0/gzip/extra/offset", serde_json::json!(11)),
            ("/cases/0/gzip/extra/len", serde_json::json!(8)),
            ("/cases/0/gzip/extra_subfield_count", serde_json::json!(2)),
            ("/cases/0/gzip/original_name/offset", serde_json::json!(20)),
            ("/cases/0/gzip/comment/len", serde_json::json!(5)),
            (
                "/cases/0/gzip/header_crc16",
                serde_json::json!({ "offset": 37, "len": 2 }),
            ),
            (
                "/cases/0/gzip/compressed_payload/offset",
                serde_json::json!(36),
            ),
            (
                "/cases/0/gzip/compressed_payload/len",
                serde_json::json!(115),
            ),
            ("/cases/0/gzip/trailer/offset", serde_json::json!(152)),
            ("/cases/0/gzip/trailer/len", serde_json::json!(7)),
            ("/cases/0/gzip/declared_crc32", serde_json::json!(0)),
            ("/cases/0/gzip/declared_isize", serde_json::json!(2047)),
            ("/cases/0/gzip/derived_output_len", serde_json::json!(2047)),
            (
                "/cases/0/gzip/derived_output_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/cases/0/layout_preimage_hex", serde_json::json!("00")),
            (
                "/cases/0/layout_root/sealrTreeV4",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut vector: serde_json::Value = serde_json::from_slice(TAR_GZIP_VECTORS).unwrap();
            *vector
                .pointer_mut(pointer)
                .expect("known TAR/gzip vector pointer") = replacement;
            assert!(
                verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).is_err(),
                "TAR/gzip mutation {pointer} must fail"
            );
        }
    }

    #[test]
    fn zip64_covering_is_bound_to_source_records_and_semantic_extra_values() {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();

        let case = &manifest.cases[0];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[0] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("signature"));

        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[35] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("value shape"));

        let case = &manifest.cases[1];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[0] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("EOCD"));
    }

    const ZIP64_STRUCTURAL_SIGNATURES: [[u8; 4]; 6] = [
        [0x50, 0x4b, 0x06, 0x06],
        [0x50, 0x4b, 0x06, 0x07],
        [0x50, 0x4b, 0x05, 0x06],
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];

    const ZIP64_STREAM_SIGNATURES: [[u8; 4]; 3] = [
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];

    fn zip64_case_with_global_comment(comment: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();
        let case = &manifest.cases[1];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        let eocd = usize::try_from(case.archive_ir.zip64_covering.eocd.offset).unwrap();
        source[eocd + 20..eocd + 22].copy_from_slice(&4_u16.to_le_bytes());
        source.extend_from_slice(&comment);
        let ir_value = serde_json::to_value(
            serde_json::from_slice::<serde_json::Value>(ZIP64_VECTORS).unwrap()["cases"][1]
                ["archive_ir"]
                .clone(),
        )
        .unwrap();
        let mut ir: Zip64ArchiveIr = serde_json::from_value(ir_value).unwrap();
        ir.zip64_covering.comment.len = 4;
        ir.source_digest.sha256 = sha256_hex(&source);
        (source, ir)
    }

    fn zip64_case_with_central_comment(comment: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();
        let case = &manifest.cases[0];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        let central =
            usize::try_from(case.archive_ir.zip64_covering.central_directory.offset).unwrap();
        source[central + 32..central + 34].copy_from_slice(&4_u16.to_le_bytes());
        let old_eocd = usize::try_from(case.archive_ir.zip64_covering.eocd.offset).unwrap();
        source.splice(old_eocd..old_eocd, comment);
        let new_eocd = old_eocd + 4;
        source[new_eocd + 12..new_eocd + 16].copy_from_slice(&51_u32.to_le_bytes());
        let ir_value = serde_json::from_slice::<serde_json::Value>(ZIP64_VECTORS).unwrap()["cases"]
            [0]["archive_ir"]
            .clone();
        let mut ir: Zip64ArchiveIr = serde_json::from_value(ir_value).unwrap();
        ir.zip64_covering.central_directory.len = 51;
        ir.zip64_covering.eocd.offset += 4;
        ir.zip64_covering.comment.offset += 4;
        ir.members[0].source_ranges.central_header.len += 4;
        ir.source_digest.sha256 = sha256_hex(&source);
        (source, ir)
    }

    fn crc32_ieee(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    fn zip64_store_descriptor_case(payload: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        const LOCAL_HEADER_LEN: u64 = 51;
        const DESCRIPTOR_OFFSET: u64 = 55;
        const CENTRAL_OFFSET: u64 = 79;
        const EOCD_OFFSET: u64 = 126;
        const SOURCE_LEN: u64 = 148;

        let crc = crc32_ieee(&payload);
        let content_digest = sha256_hex(&payload);
        let mut source = Vec::new();
        source.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        push_u16(&mut source, 45);
        push_u16(&mut source, 0x0008);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, 0);
        push_u32(&mut source, u32::MAX);
        push_u32(&mut source, u32::MAX);
        push_u16(&mut source, 1);
        push_u16(&mut source, 20);
        source.push(b'a');
        push_u16(&mut source, 1);
        push_u16(&mut source, 16);
        push_u64(&mut source, 4);
        push_u64(&mut source, 4);
        assert_eq!(source.len(), usize::try_from(LOCAL_HEADER_LEN).unwrap());
        source.extend_from_slice(&payload);
        source.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        push_u32(&mut source, crc);
        push_u64(&mut source, 4);
        push_u64(&mut source, 4);
        assert_eq!(source.len(), usize::try_from(CENTRAL_OFFSET).unwrap());
        source.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        push_u16(&mut source, 45);
        push_u16(&mut source, 45);
        push_u16(&mut source, 0x0008);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, crc);
        push_u32(&mut source, 4);
        push_u32(&mut source, 4);
        push_u16(&mut source, 1);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, 0);
        push_u32(&mut source, 0);
        source.push(b'a');
        assert_eq!(source.len(), usize::try_from(EOCD_OFFSET).unwrap());
        source.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 1);
        push_u16(&mut source, 1);
        push_u32(&mut source, 47);
        push_u32(&mut source, u32::try_from(CENTRAL_OFFSET).unwrap());
        push_u16(&mut source, 0);
        assert_eq!(source.len(), usize::try_from(SOURCE_LEN).unwrap());

        let ir: Zip64ArchiveIr = serde_json::from_value(serde_json::json!({
            "schema": ZIP64_IR_SCHEMA,
            "profile": ZIP64_PROFILE_SCHEMA,
            "profile_digest": "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2",
            "source_digest": { "sha256": sha256_hex(&source) },
            "format": "zip64",
            "zip64_covering": {
                "local_records": { "offset": 0, "len": CENTRAL_OFFSET },
                "central_directory": { "offset": CENTRAL_OFFSET, "len": 47 },
                "zip64_eocd": null,
                "zip64_locator": null,
                "eocd": { "offset": EOCD_OFFSET, "len": 22 },
                "comment": { "offset": SOURCE_LEN, "len": 0 }
            },
            "members": [{
                "raw_name_bytes": [97],
                "decoded_name": "a",
                "canonical_path": "a",
                "components": ["a"],
                "kind": "file",
                "method": 0,
                "flags": 8,
                "declared_crc": crc,
                "declared_comp_size": 4,
                "declared_uncomp_size": 4,
                "source_ranges": {
                    "local_header": { "offset": 0, "len": LOCAL_HEADER_LEN },
                    "compressed_payload": { "offset": LOCAL_HEADER_LEN, "len": 4 },
                    "data_descriptor": { "offset": DESCRIPTOR_OFFSET, "len": 24 },
                    "central_header": { "offset": CENTRAL_OFFSET, "len": 47 }
                },
                "extra_fields": [{
                    "site": "local",
                    "id": 1,
                    "header_range": { "offset": 31, "len": 4 },
                    "data_range": { "offset": 35, "len": 16 },
                    "disposition": "semantic"
                }],
                "zip64": {
                    "local_version_needed": 45,
                    "central_version_needed": 45,
                    "central_presence_mask": 0,
                    "central_legacy_sentinel_mask": 0,
                    "local_legacy_sentinel_mask": 3,
                    "local_value_shape": "exact",
                    "local_zip64_extra": { "offset": 35, "len": 16 },
                    "central_zip64_extra": null,
                    "descriptor_width": "zip64"
                },
                "actual_uncomp_size": 4,
                "actual_crc": crc,
                "content_sha256": content_digest,
                "verification": { "status": "verified" },
                "normalization_actions": []
            }]
        }))
        .unwrap();
        (source, ir)
    }

    #[test]
    fn zip64_global_comment_rejects_every_production_structural_signature() {
        let (source, ir) = zip64_case_with_global_comment(*b"safe");
        verify_zip64_covering(&source, &ir).expect("safe global comment");
        for signature in ZIP64_STRUCTURAL_SIGNATURES {
            let (source, ir) = zip64_case_with_global_comment(signature);
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("global EOCD comment"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_central_comment_rejects_every_production_structural_signature() {
        let (source, ir) = zip64_case_with_central_comment(*b"safe");
        verify_zip64_covering(&source, &ir).expect("safe central comment");
        for signature in ZIP64_STRUCTURAL_SIGNATURES {
            let (source, ir) = zip64_case_with_central_comment(signature);
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("central member comment"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_store_descriptor_payload_rejects_every_stream_signature() {
        let (source, ir) = zip64_store_descriptor_case(*b"safe");
        validate_zip64_ir(&ir).expect("self-consistent stored member IR");
        verify_zip64_covering(&source, &ir).expect("safe stored descriptor payload");
        for signature in ZIP64_STREAM_SIGNATURES {
            let (source, ir) = zip64_store_descriptor_case(signature);
            validate_zip64_ir(&ir).expect("self-consistent stored member IR");
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("stored descriptor payload"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_mutations_across_each_identity_family_are_rejected() {
        let mutations = [
            ("/schema", serde_json::json!("sealr.unknown")),
            ("/profile/id", serde_json::json!("sealr.profile.unknown")),
            ("/profile/digest/sha256", serde_json::json!("0".repeat(64))),
            ("/layout_encoding", serde_json::json!("sealrTreeV1")),
            ("/layout_label", serde_json::json!("sealr.tree.layout.v1")),
            ("/content_encoding", serde_json::json!("sealrTreeV3")),
            ("/content_label", serde_json::json!("sealr.tree.content.v2")),
            ("/cases/0/source_bytes_hex", serde_json::json!("00")),
            ("/cases/0/source/sha256", serde_json::json!("0".repeat(64))),
            (
                "/cases/0/archive_ir/schema",
                serde_json::json!("sealr.archive-ir.v1"),
            ),
            (
                "/cases/0/archive_ir/profile",
                serde_json::json!("sealr.profile.unknown"),
            ),
            (
                "/cases/0/archive_ir/profile_digest",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/archive_ir/source_digest/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/cases/0/archive_ir/format", serde_json::json!("zip32")),
            (
                "/cases/0/archive_ir/zip64_covering/local_records/len",
                serde_json::json!(55),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/central_directory/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/zip64_eocd",
                serde_json::json!({ "offset": 103, "len": 56 }),
            ),
            (
                "/cases/1/archive_ir/zip64_covering/zip64_locator/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/eocd/len",
                serde_json::json!(23),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/comment/len",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/raw_name_bytes",
                serde_json::json!([98]),
            ),
            (
                "/cases/0/archive_ir/members/0/decoded_name",
                serde_json::json!("b"),
            ),
            (
                "/cases/0/archive_ir/members/0/canonical_path",
                serde_json::json!("b"),
            ),
            (
                "/cases/0/archive_ir/members/0/components",
                serde_json::json!(["b"]),
            ),
            (
                "/cases/0/archive_ir/members/0/kind",
                serde_json::json!("directory"),
            ),
            ("/cases/0/archive_ir/members/0/method", serde_json::json!(0)),
            ("/cases/0/archive_ir/members/0/flags", serde_json::json!(8)),
            (
                "/cases/0/archive_ir/members/0/declared_crc",
                serde_json::json!(3137623818_u32),
            ),
            (
                "/cases/0/archive_ir/members/0/declared_comp_size",
                serde_json::json!(6),
            ),
            (
                "/cases/0/archive_ir/members/0/declared_uncomp_size",
                serde_json::json!(17),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/local_header/len",
                serde_json::json!(50),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/compressed_payload/offset",
                serde_json::json!(50),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/data_descriptor",
                serde_json::json!({ "offset": 56, "len": 24 }),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/central_header/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/id",
                serde_json::json!(2),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/header_range/offset",
                serde_json::json!(30),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/data_range/len",
                serde_json::json!(15),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/disposition",
                serde_json::json!("ignored"),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_version_needed",
                serde_json::json!(44),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_version_needed",
                serde_json::json!(44),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_presence_mask",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_legacy_sentinel_mask",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_legacy_sentinel_mask",
                serde_json::json!(2),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_value_shape",
                serde_json::json!("absent"),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_zip64_extra/offset",
                serde_json::json!(36),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_zip64_extra",
                serde_json::json!({ "offset": 103, "len": 8 }),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/descriptor_width",
                serde_json::json!("zip64"),
            ),
            (
                "/cases/0/archive_ir/members/0/actual_uncomp_size",
                serde_json::json!(17),
            ),
            (
                "/cases/0/archive_ir/members/0/actual_crc",
                serde_json::json!(3137623818_u32),
            ),
            (
                "/cases/0/archive_ir/members/0/content_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/archive_ir/members/0/verification/status",
                serde_json::json!("pending"),
            ),
            (
                "/cases/0/archive_ir/members/0/normalization_actions",
                serde_json::json!([{ "action": "strip-directory-trailing-slash" }]),
            ),
            ("/cases/0/layout_preimage_hex", serde_json::json!("00")),
            (
                "/cases/0/layout_root/sealrTreeV3",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut vector: serde_json::Value = serde_json::from_slice(ZIP64_VECTORS).unwrap();
            *vector
                .pointer_mut(pointer)
                .expect("known ZIP64 vector pointer") = replacement;
            assert!(
                verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).is_err(),
                "ZIP64 mutation {pointer} must fail"
            );
        }
    }

    #[test]
    fn tar_layout_and_content_roots_verify_independently() {
        assert_eq!(
            verify_tar_layout_vector_json(TAR_LAYOUT_VECTOR).unwrap(),
            TarVerificationSummary { members: 3 }
        );
    }

    #[test]
    fn tar_covering_rejects_partial_trailing_record_padding() {
        let mut vector: TarLayoutVector = serde_json::from_slice(TAR_LAYOUT_VECTOR).unwrap();
        vector.covering.trailing_zeros.len = 1;
        let error = validate_tar_covering(&vector).unwrap_err();
        assert!(error.to_string().contains("complete 512-byte-block source"));
    }

    #[test]
    fn every_tar_layout_field_family_is_bound_or_structurally_checked() {
        let mutations = [
            ("/covering/member_records/len", serde_json::json!(2559)),
            ("/covering/terminator/offset", serde_json::json!(2559)),
            ("/covering/trailing_zeros/offset", serde_json::json!(3583)),
            ("/members/0/canonical_path", serde_json::json!("mission-x")),
            ("/members/0/kind", serde_json::json!("file")),
            ("/members/0/raw_name_bytes", serde_json::json!([109, 47])),
            ("/members/1/declared_uncomp_size", serde_json::json!(27)),
            ("/members/1/header/offset", serde_json::json!(511)),
            ("/members/1/header/len", serde_json::json!(511)),
            ("/members/1/payload/offset", serde_json::json!(1023)),
            ("/members/1/payload/len", serde_json::json!(27)),
            ("/members/1/padding/offset", serde_json::json!(1051)),
            ("/members/1/padding/len", serde_json::json!(483)),
            ("/members/1/mode", serde_json::json!(384)),
            ("/members/1/mtime", serde_json::json!(1788000001_u64)),
            ("/members/1/header_checksum", serde_json::json!(6294)),
            (
                "/members/1/header_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/members/1/normalization_actions",
                serde_json::json!([{ "action": "strip-directory-trailing-slash" }]),
            ),
            ("/members/1/actual_uncomp_size", serde_json::json!(27)),
            (
                "/members/1/content_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/layout_root/sealrTreeV2",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut vector: serde_json::Value = serde_json::from_slice(TAR_LAYOUT_VECTOR).unwrap();
            *vector.pointer_mut(pointer).expect("known vector pointer") = replacement;
            assert!(
                verify_tar_layout_vector_json(&serde_json::to_vec(&vector).unwrap()).is_err(),
                "mutation {pointer} must fail"
            );
        }
    }

    #[test]
    fn committed_vectors_verify_independently() {
        let summary = verify_manifest_json(VECTORS).expect("committed vectors");
        assert_eq!(summary.profiles, 4);
        assert_eq!(summary.cases, 4);
        assert_eq!(summary.layout_roots, 3);
        assert_eq!(summary.content_roots, 3);
    }

    #[test]
    fn tampered_layout_root_is_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["layout_root"][TREE_ENCODING] =
            serde_json::Value::String("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));
    }

    #[test]
    fn tampered_source_is_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][0]["source_bytes_hex"] = serde_json::Value::String(String::new());
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("source bytes do not match"));
    }

    #[test]
    fn tampered_profile_bytes_are_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["profiles"][0]["canonical_bytes_hex"] = serde_json::Value::String(String::new());
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile bytes are empty"));
    }

    #[test]
    fn tampered_covering_is_rejected_before_root_comparison() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["archive_ir"]["covering"]["local_records"]["len"] =
            serde_json::json!(126);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("covering ranges"));
    }

    #[test]
    fn tampered_extra_range_is_rejected_before_root_comparison() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][2]["archive_ir"]["members"][0]["extra_fields"][0]["header_range"]
            ["len"] = serde_json::json!(3);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("extra header does not exactly precede"));
    }

    #[test]
    fn root_objects_reject_unknown_fields() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][0]["layout_root"]["unexpected"] = serde_json::json!(true);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("JSON"));
    }

    #[test]
    fn unavailable_ir_cannot_carry_a_root() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][3]["layout_root"] = serde_json::json!({
            TREE_ENCODING: "0".repeat(64)
        });
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("without IR carries a tree root"));
    }

    #[test]
    fn duplicate_case_ids_are_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["id"] = manifest["cases"][0]["id"].clone();
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("duplicate case id"));
    }
}
