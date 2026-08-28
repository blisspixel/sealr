use serde::Serialize;

/// Agent-switchable codes. Strings are stable; renaming is breaking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FindingCode {
    PathAbsolute,
    PathDotDot,
    PathEmpty,
    PathAds,
    PathReserved,
    PathTrailing,
    PathEscape,
    PathDepth,
    PathNul,
    PathInvalidChar,
    PathUnicode,
    PathCaseFold,
    PathConflict,
    MaterializeExists,
    MaterializeIo,
    MaterializeCommit,
    MaterializeUnsafeParent,
    MaterializeUnsafeComponent,
    MaterializeCleanup,
    MaterializeUnsupported,
    MaterializeUnsupportedFilesystem,
    MaterializeUnsafeStage,
    MaterializeAudit,
    SourceIo,
    QuotaArchive,
    QuotaMetadata,
    QuotaFiles,
    QuotaMember,
    QuotaTotal,
    QuotaRatio,
    QuotaOverflow,
    QuotaDeclaredLie,
    PolicyUnsupported,
    ZipDiffA1Method,
    ZipDiffA2Size,
    ZipDiffA3Name,
    ZipDiffA4Dir,
    ZipDiffA5Crypt,
    ZipDiffB1Dup,
    ZipDiffB2Chars,
    ZipDiffC1Stream,
    ZipDiffC2Eocd,
    ZipDiffC3Count,
    ZipDiffC4Offset,
    ZipDiffC5Zip64,
    ZipOverlap,
    CoveringInconsistent,
    ZipEncrypted,
    ZipEncoding,
    ZipExtra,
    ZipFlags,
    TarChecksum,
    TarDialect,
    TarNumeric,
    TarPadding,
    TarTerminator,
    TarTruncated,
    TarType,
    TarFeatureUnsupported,
    FormatUnsupported,
    FormatMagic,
    GzipExtra,
    CodecDeflateInvalidStream,
    CodecDeflateTrailingInput,
    CrcMismatch,
    MethodUnsupported,
}

impl FindingCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PathAbsolute => "path.absolute",
            Self::PathDotDot => "path.dotdot",
            Self::PathEmpty => "path.empty",
            Self::PathAds => "path.ads",
            Self::PathReserved => "path.reserved",
            Self::PathTrailing => "path.trailing",
            Self::PathEscape => "path.escape",
            Self::PathDepth => "path.depth",
            Self::PathNul => "path.nul",
            Self::PathInvalidChar => "path.invalid_char",
            Self::PathUnicode => "path.unicode",
            Self::PathCaseFold => "path.case_fold",
            Self::PathConflict => "path.conflict",
            Self::MaterializeExists => "materialize.exists",
            Self::MaterializeIo => "materialize.io",
            Self::MaterializeCommit => "materialize.commit",
            Self::MaterializeUnsafeParent => "materialize.unsafe_parent",
            Self::MaterializeUnsafeComponent => "materialize.unsafe_component",
            Self::MaterializeCleanup => "materialize.cleanup",
            Self::MaterializeUnsupported => "materialize.unsupported",
            Self::MaterializeUnsupportedFilesystem => "materialize.unsupported_filesystem",
            Self::MaterializeUnsafeStage => "materialize.unsafe_stage",
            Self::MaterializeAudit => "materialize.audit",
            Self::SourceIo => "source.io",
            Self::QuotaArchive => "quota.archive",
            Self::QuotaMetadata => "quota.metadata",
            Self::QuotaFiles => "quota.files",
            Self::QuotaMember => "quota.member",
            Self::QuotaTotal => "quota.total",
            Self::QuotaRatio => "quota.ratio",
            Self::QuotaOverflow => "quota.overflow",
            Self::QuotaDeclaredLie => "quota.declared_lie",
            Self::PolicyUnsupported => "policy.unsupported",
            Self::ZipDiffA1Method => "zip.diff.a1_method",
            Self::ZipDiffA2Size => "zip.diff.a2_size",
            Self::ZipDiffA3Name => "zip.diff.a3_name",
            Self::ZipDiffA4Dir => "zip.diff.a4_dir",
            Self::ZipDiffA5Crypt => "zip.diff.a5_crypt",
            Self::ZipDiffB1Dup => "zip.diff.b1_dup",
            Self::ZipDiffB2Chars => "zip.diff.b2_chars",
            Self::ZipDiffC1Stream => "zip.diff.c1_stream",
            Self::ZipDiffC2Eocd => "zip.diff.c2_eocd",
            Self::ZipDiffC3Count => "zip.diff.c3_count",
            Self::ZipDiffC4Offset => "zip.diff.c4_offset",
            Self::ZipDiffC5Zip64 => "zip.diff.c5_zip64",
            Self::ZipOverlap => "zip.overlap",
            Self::CoveringInconsistent => "covering.inconsistent",
            Self::ZipEncrypted => "zip.encrypted",
            Self::ZipEncoding => "zip.encoding",
            Self::ZipExtra => "zip.extra",
            Self::ZipFlags => "zip.flags",
            Self::TarChecksum => "tar.checksum",
            Self::TarDialect => "tar.dialect",
            Self::TarNumeric => "tar.numeric",
            Self::TarPadding => "tar.padding",
            Self::TarTerminator => "tar.terminator",
            Self::TarTruncated => "tar.truncated",
            Self::TarType => "tar.type",
            Self::TarFeatureUnsupported => "tar.feature_unsupported",
            Self::FormatUnsupported => "format.unsupported",
            Self::FormatMagic => "format.magic",
            Self::GzipExtra => "gzip.extra",
            Self::CodecDeflateInvalidStream => "codec.deflate.invalid_stream",
            Self::CodecDeflateTrailingInput => "codec.deflate.trailing_input",
            Self::CrcMismatch => "crc.mismatch",
            Self::MethodUnsupported => "method.unsupported",
        }
    }
}

impl Serialize for FindingCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    Error,
    Deny,
    Warn,
    Info,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    pub detail: String,
}

impl Finding {
    pub fn error(code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            member: None,
            detail: detail.into(),
        }
    }

    pub fn on(mut self, member: impl Into<String>) -> Self {
        self.member = Some(member.into());
        self
    }
}
