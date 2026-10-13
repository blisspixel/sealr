//! Signature hints for `format.unsupported` and `tar.dialect`.
//!
//! Every label below is a fixed byte pattern. Callers must not pass a file
//! name, and nothing in this module selects an interpretation.

use crate::findings::FindingHint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TarWrapperClass {
    Raw,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
}

pub(crate) fn hint_from_prefix(bytes: &[u8]) -> Option<FindingHint> {
    if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return Some(formats("xz stream", &["tar-xz-ustar"]));
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(formats("zstd frame", &["tar-zstd-ustar"]));
    }
    if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(formats("7z signature", &["7z-copy"]));
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(formats(
            "gzip member",
            &["tar-gzip-ustar", "tar-gzip-pax", "tar-gzip-gnu-longname"],
        ));
    }
    if bytes.len() >= 4
        && bytes[0] == b'B'
        && bytes[1] == b'Z'
        && bytes[2] == b'h'
        && matches!(bytes[3], b'1'..=b'9')
    {
        return Some(formats("bzip2 stream", &["tar-bzip2-ustar"]));
    }
    if is_zip_signature(bytes) {
        return Some(formats("zip member", &["zip", "zip64"]));
    }
    if bytes.len() >= 265 {
        return hint_for_tar_magic(TarWrapperClass::Raw, &bytes[257..265]);
    }
    None
}

pub(crate) fn hint_for_tar_dialect(class: TarWrapperClass, magic: &[u8]) -> Option<FindingHint> {
    if magic.len() < 8 {
        return None;
    }
    hint_for_tar_magic(class, &magic[..8])
}

fn hint_for_tar_magic(class: TarWrapperClass, magic: &[u8]) -> Option<FindingHint> {
    let (observed, ustar) = if magic == b"ustar\x0000" {
        ("ustar magic \"ustar\\0\" \"00\"", true)
    } else if magic == b"ustar  \0" {
        ("GNU magic \"ustar  \\0\"", false)
    } else {
        return None;
    };
    let formats = match (class, ustar) {
        (TarWrapperClass::Raw, true) => &["tar-ustar", "tar-pax"][..],
        (TarWrapperClass::Raw, false) => &["tar-gnu-longname"][..],
        (TarWrapperClass::Gzip, true) => &["tar-gzip-ustar", "tar-gzip-pax"][..],
        (TarWrapperClass::Gzip, false) => &["tar-gzip-gnu-longname"][..],
        (TarWrapperClass::Zstd, true) => &["tar-zstd-ustar"][..],
        (TarWrapperClass::Xz, true) => &["tar-xz-ustar"][..],
        (TarWrapperClass::Bzip2, true) => &["tar-bzip2-ustar"][..],
        (TarWrapperClass::Zstd | TarWrapperClass::Xz | TarWrapperClass::Bzip2, false) => &[][..],
    };
    Some(self_formats(observed, formats))
}

fn formats(observed: &str, values: &[&str]) -> FindingHint {
    self_formats(observed, values)
}

fn self_formats(observed: &str, values: &[&str]) -> FindingHint {
    FindingHint {
        observed: observed.to_owned(),
        formats: values.iter().map(|value| (*value).to_owned()).collect(),
    }
}

fn is_zip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && matches!(
            (bytes[2], bytes[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08) | (0x06, 0x06)
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_hints_ignore_any_name_and_use_only_fixed_bytes() {
        let gzip = hint_from_prefix(&[0x1f, 0x8b, 0x08, 0x00]).unwrap();
        assert_eq!(gzip.observed, "gzip member");
        assert_eq!(
            gzip.formats,
            vec!["tar-gzip-ustar", "tar-gzip-pax", "tar-gzip-gnu-longname"]
        );
        assert_eq!(
            hint_from_prefix(&[0x1f, 0x8b]).unwrap().formats,
            gzip.formats
        );
        let mut ustar = vec![0_u8; 265];
        ustar[257..265].copy_from_slice(b"ustar\x0000");
        let hinted = hint_from_prefix(&ustar).unwrap();
        assert_eq!(hinted.observed, "ustar magic \"ustar\\0\" \"00\"");
        assert_eq!(hinted.formats, vec!["tar-ustar", "tar-pax"]);
        let mut gnu = vec![0_u8; 265];
        gnu[257..265].copy_from_slice(b"ustar  \0");
        assert_eq!(
            hint_from_prefix(&gnu).unwrap().formats,
            vec!["tar-gnu-longname"]
        );
        assert!(hint_from_prefix(b"not an archive").is_none());
        assert!(hint_from_prefix(&[0x1f]).is_none());
    }

    #[test]
    fn dialect_hint_keeps_the_outer_wrapper() {
        let gnu = hint_for_tar_dialect(TarWrapperClass::Gzip, b"ustar  \0").unwrap();
        assert_eq!(gnu.observed, "GNU magic \"ustar  \\0\"");
        assert_eq!(gnu.formats, vec!["tar-gzip-gnu-longname"]);
        let ustar = hint_for_tar_dialect(TarWrapperClass::Gzip, b"ustar\x0000").unwrap();
        assert_eq!(ustar.formats, vec!["tar-gzip-ustar", "tar-gzip-pax"]);
        assert!(hint_for_tar_dialect(TarWrapperClass::Zstd, b"ustar  \0")
            .unwrap()
            .formats
            .is_empty());
        assert!(hint_for_tar_dialect(TarWrapperClass::Raw, b"no magic").is_none());
    }
}
