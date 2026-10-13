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
    QuotaDerived,
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
    ZipSymlink,
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
    TarPaxRecord,
    TarPaxState,
    FormatUnsupported,
    FormatMagic,
    GzipExtra,
    CodecDeflateInvalidStream,
    CodecDeflateTrailingInput,
    CrcMismatch,
    MethodUnsupported,
    TarGnuLongName,
    TarGnuState,
    CodecZstdInvalidFrame,
    CodecZstdTrailingInput,
    CodecXzInvalidStream,
    CodecXzTrailingInput,
    CodecBzip2InvalidStream,
    CodecBzip2TrailingInput,
    SevenZInvalidStructure,
    EvidenceCanonicalization,
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
            Self::QuotaDerived => "quota.derived",
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
            Self::ZipSymlink => "zip.symlink",
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
            Self::TarPaxRecord => "tar.pax.record",
            Self::TarPaxState => "tar.pax.state",
            Self::TarGnuLongName => "tar.gnu.long_name",
            Self::TarGnuState => "tar.gnu.state",
            Self::FormatUnsupported => "format.unsupported",
            Self::FormatMagic => "format.magic",
            Self::GzipExtra => "gzip.extra",
            Self::CodecDeflateInvalidStream => "codec.deflate.invalid_stream",
            Self::CodecDeflateTrailingInput => "codec.deflate.trailing_input",
            Self::CodecZstdInvalidFrame => "codec.zstd.invalid_frame",
            Self::CodecZstdTrailingInput => "codec.zstd.trailing_input",
            Self::CodecXzInvalidStream => "codec.xz.invalid_stream",
            Self::CodecXzTrailingInput => "codec.xz.trailing_input",
            Self::CodecBzip2InvalidStream => "codec.bzip2.invalid_stream",
            Self::CodecBzip2TrailingInput => "codec.bzip2.trailing_input",
            Self::SevenZInvalidStructure => "sevenz.invalid_structure",
            Self::EvidenceCanonicalization => "evidence.canonicalization",
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

/// Next step attached to `format.unsupported` and `tar.dialect`.
///
/// `observed` and `formats` come from fixed signature bytes. The hint is not
/// an interpretation and is never used to select a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FindingHint {
    pub observed: String,
    pub formats: Vec<String>,
}

impl FindingHint {
    pub fn new(
        observed: impl Into<String>,
        formats: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            observed: observed.into(),
            formats: formats.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<FindingHint>,
}

impl Finding {
    pub fn error(code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            member: None,
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn on(mut self, member: impl Into<String>) -> Self {
        self.member = Some(member.into());
        self
    }

    pub fn with_hint(mut self, hint: FindingHint) -> Self {
        self.hint = Some(hint);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::FindingCode;

    #[test]
    fn tar_extension_finding_codes_are_stable() {
        assert_eq!(FindingCode::TarPaxRecord.as_str(), "tar.pax.record");
        assert_eq!(FindingCode::TarPaxState.as_str(), "tar.pax.state");
        assert_eq!(FindingCode::TarGnuLongName.as_str(), "tar.gnu.long_name");
        assert_eq!(FindingCode::TarGnuState.as_str(), "tar.gnu.state");
        assert_eq!(FindingCode::ZipSymlink.as_str(), "zip.symlink");
    }

    #[test]
    fn absent_hint_does_not_change_finding_json() {
        let finding = super::Finding::error(FindingCode::FormatUnsupported, "magic unknown");
        let json = serde_json::to_string(&finding).unwrap();
        assert_eq!(
            json,
            r#"{"code":"format.unsupported","severity":"error","detail":"magic unknown"}"#
        );
        let hinted = finding.with_hint(super::FindingHint {
            observed: "gzip member".to_owned(),
            formats: vec!["tar-gzip-ustar".to_owned()],
        });
        let hinted_json = serde_json::to_value(&hinted).unwrap();
        assert_eq!(hinted_json["detail"], "magic unknown");
        assert_eq!(hinted_json["hint"]["observed"], "gzip member");
        assert_eq!(hinted_json["hint"]["formats"][0], "tar-gzip-ustar");
    }
}
