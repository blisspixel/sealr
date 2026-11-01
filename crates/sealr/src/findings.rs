use serde::Serialize;

/// Agent-switchable codes. Strings are stable; renaming is breaking.
///
/// Discriminants are an explicit append-only contract for `as isize` casts.
/// They match the source-baseline-20260913 values. `ZipSymlink` is 79, the
/// first free value after that baseline, which is also its semantic-record
/// tag. Those two number spaces are separate; do not assume they stay equal.
/// Add a variant at the end with the next unused discriminant. Do not insert
/// or renumber one. The semantic-record tag is chosen in its own match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FindingCode {
    PathAbsolute = 0,
    PathDotDot = 1,
    PathEmpty = 2,
    PathAds = 3,
    PathReserved = 4,
    PathTrailing = 5,
    PathEscape = 6,
    PathDepth = 7,
    PathNul = 8,
    PathInvalidChar = 9,
    PathUnicode = 10,
    PathCaseFold = 11,
    PathConflict = 12,
    MaterializeExists = 13,
    MaterializeIo = 14,
    MaterializeCommit = 15,
    MaterializeUnsafeParent = 16,
    MaterializeUnsafeComponent = 17,
    MaterializeCleanup = 18,
    MaterializeUnsupported = 19,
    MaterializeUnsupportedFilesystem = 20,
    MaterializeUnsafeStage = 21,
    MaterializeAudit = 22,
    SourceIo = 23,
    QuotaArchive = 24,
    QuotaDerived = 25,
    QuotaMetadata = 26,
    QuotaFiles = 27,
    QuotaMember = 28,
    QuotaTotal = 29,
    QuotaRatio = 30,
    QuotaOverflow = 31,
    QuotaDeclaredLie = 32,
    PolicyUnsupported = 33,
    ZipDiffA1Method = 34,
    ZipDiffA2Size = 35,
    ZipDiffA3Name = 36,
    ZipDiffA4Dir = 37,
    ZipDiffA5Crypt = 38,
    ZipDiffB1Dup = 39,
    ZipDiffB2Chars = 40,
    ZipDiffC1Stream = 41,
    ZipDiffC2Eocd = 42,
    ZipDiffC3Count = 43,
    ZipDiffC4Offset = 44,
    ZipDiffC5Zip64 = 45,
    ZipOverlap = 46,
    CoveringInconsistent = 47,
    ZipEncrypted = 48,
    ZipEncoding = 49,
    ZipExtra = 50,
    ZipFlags = 51,
    TarChecksum = 52,
    TarDialect = 53,
    TarNumeric = 54,
    TarPadding = 55,
    TarTerminator = 56,
    TarTruncated = 57,
    TarType = 58,
    TarFeatureUnsupported = 59,
    TarPaxRecord = 60,
    TarPaxState = 61,
    FormatUnsupported = 62,
    FormatMagic = 63,
    GzipExtra = 64,
    CodecDeflateInvalidStream = 65,
    CodecDeflateTrailingInput = 66,
    CrcMismatch = 67,
    MethodUnsupported = 68,
    TarGnuLongName = 69,
    TarGnuState = 70,
    CodecZstdInvalidFrame = 71,
    CodecZstdTrailingInput = 72,
    CodecXzInvalidStream = 73,
    CodecXzTrailingInput = 74,
    CodecBzip2InvalidStream = 75,
    CodecBzip2TrailingInput = 76,
    SevenZInvalidStructure = 77,
    EvidenceCanonicalization = 78,
    ZipSymlink = 79,
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

/// Attach the ustar name field when this finding does not already name a member.
///
/// The label is diagnostic. It is not a path decision and is not used to select
/// an interpretation. Control bytes and non-UTF-8 names are omitted.
pub(crate) fn label_header_member(finding: Finding, header: &[u8]) -> Finding {
    if finding.member.is_some() {
        return finding;
    }
    let Some(name) = header_name_label(header) else {
        return finding;
    };
    finding.on(name)
}

fn header_name_label(header: &[u8]) -> Option<String> {
    let field = header.get(..100)?;
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let raw = &field[..end];
    if raw.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_owned())
}

pub(crate) fn checksum_field_detail(field: &[u8]) -> &'static str {
    if field.len() == 8
        && field[..7].iter().all(|byte| matches!(byte, b'0'..=b'7'))
        && field[7] == 0
    {
        "checksum field must be six octal digits followed by NUL and space (observed 7-digit checksum, as written by git archive and npm)"
    } else {
        "checksum field must be six octal digits followed by NUL and space"
    }
}

/// Name the common refused typeflags. `x` and `g` carry an empty format list
/// so the caller can add the sibling `--format` for the wrapper already selected.
pub(crate) fn unsupported_typeflag_finding(header: &[u8], typeflag: u8) -> Finding {
    let (words, observed) = match typeflag {
        b'1' => ("hard link", None),
        b'2' => ("symlink", None),
        b'x' => ("PAX extended header", Some("PAX extended header")),
        b'g' => ("PAX global header", Some("PAX global header")),
        _ => ("", None),
    };
    let detail = if words.is_empty() {
        format!("unsupported ustar typeflag 0x{typeflag:02x}")
    } else {
        format!("{words} (ustar typeflag 0x{typeflag:02x})")
    };
    let mut finding = Finding::error(FindingCode::TarFeatureUnsupported, detail);
    finding = label_header_member(finding, header);
    if let Some(observed) = observed {
        finding = finding.with_hint(FindingHint::new(observed, std::iter::empty::<String>()));
    }
    finding
}

pub(crate) fn pax_keyword_refusal(keyword: &[u8]) -> Finding {
    let shown = std::str::from_utf8(keyword).ok().filter(|text| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'=')
    });
    let detail = match shown {
        Some(keyword) => {
            format!("pax keyword {keyword} is outside the closed path/size profile")
        }
        None => "pax keyword is outside the closed path/size profile".to_owned(),
    };
    Finding::error(FindingCode::TarFeatureUnsupported, detail)
}

#[cfg(test)]
mod tests {
    use super::FindingCode;

    #[test]
    fn finding_code_discriminants_stay_append_only() {
        let pinned = [
            (FindingCode::PathAbsolute, 0),
            (FindingCode::ZipDiffA4Dir, 37),
            (FindingCode::ZipDiffA5Crypt, 38),
            (FindingCode::ZipDiffB1Dup, 39),
            (FindingCode::EvidenceCanonicalization, 78),
            (FindingCode::ZipSymlink, 79),
        ];
        for (code, discriminant) in pinned {
            assert_eq!(code as isize, discriminant);
        }
        let all = [
            FindingCode::PathAbsolute,
            FindingCode::PathDotDot,
            FindingCode::PathEmpty,
            FindingCode::PathAds,
            FindingCode::PathReserved,
            FindingCode::PathTrailing,
            FindingCode::PathEscape,
            FindingCode::PathDepth,
            FindingCode::PathNul,
            FindingCode::PathInvalidChar,
            FindingCode::PathUnicode,
            FindingCode::PathCaseFold,
            FindingCode::PathConflict,
            FindingCode::MaterializeExists,
            FindingCode::MaterializeIo,
            FindingCode::MaterializeCommit,
            FindingCode::MaterializeUnsafeParent,
            FindingCode::MaterializeUnsafeComponent,
            FindingCode::MaterializeCleanup,
            FindingCode::MaterializeUnsupported,
            FindingCode::MaterializeUnsupportedFilesystem,
            FindingCode::MaterializeUnsafeStage,
            FindingCode::MaterializeAudit,
            FindingCode::SourceIo,
            FindingCode::QuotaArchive,
            FindingCode::QuotaDerived,
            FindingCode::QuotaMetadata,
            FindingCode::QuotaFiles,
            FindingCode::QuotaMember,
            FindingCode::QuotaTotal,
            FindingCode::QuotaRatio,
            FindingCode::QuotaOverflow,
            FindingCode::QuotaDeclaredLie,
            FindingCode::PolicyUnsupported,
            FindingCode::ZipDiffA1Method,
            FindingCode::ZipDiffA2Size,
            FindingCode::ZipDiffA3Name,
            FindingCode::ZipDiffA4Dir,
            FindingCode::ZipDiffA5Crypt,
            FindingCode::ZipDiffB1Dup,
            FindingCode::ZipDiffB2Chars,
            FindingCode::ZipDiffC1Stream,
            FindingCode::ZipDiffC2Eocd,
            FindingCode::ZipDiffC3Count,
            FindingCode::ZipDiffC4Offset,
            FindingCode::ZipDiffC5Zip64,
            FindingCode::ZipOverlap,
            FindingCode::CoveringInconsistent,
            FindingCode::ZipEncrypted,
            FindingCode::ZipEncoding,
            FindingCode::ZipExtra,
            FindingCode::ZipFlags,
            FindingCode::TarChecksum,
            FindingCode::TarDialect,
            FindingCode::TarNumeric,
            FindingCode::TarPadding,
            FindingCode::TarTerminator,
            FindingCode::TarTruncated,
            FindingCode::TarType,
            FindingCode::TarFeatureUnsupported,
            FindingCode::TarPaxRecord,
            FindingCode::TarPaxState,
            FindingCode::FormatUnsupported,
            FindingCode::FormatMagic,
            FindingCode::GzipExtra,
            FindingCode::CodecDeflateInvalidStream,
            FindingCode::CodecDeflateTrailingInput,
            FindingCode::CrcMismatch,
            FindingCode::MethodUnsupported,
            FindingCode::TarGnuLongName,
            FindingCode::TarGnuState,
            FindingCode::CodecZstdInvalidFrame,
            FindingCode::CodecZstdTrailingInput,
            FindingCode::CodecXzInvalidStream,
            FindingCode::CodecXzTrailingInput,
            FindingCode::CodecBzip2InvalidStream,
            FindingCode::CodecBzip2TrailingInput,
            FindingCode::SevenZInvalidStructure,
            FindingCode::EvidenceCanonicalization,
            FindingCode::ZipSymlink,
        ];
        let mut unique = [false; 80];
        for code in all {
            let discriminant = code as isize;
            assert!((0..80).contains(&discriminant));
            assert!(
                !unique[discriminant as usize],
                "duplicate discriminant {discriminant}"
            );
            unique[discriminant as usize] = true;
            if discriminant != 79 {
                assert!(discriminant <= 78);
            }
        }
        assert!(unique.iter().all(|present| *present));
    }

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
