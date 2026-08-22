use std::path::{Path, PathBuf};

use crate::findings::{Finding, FindingCode};
use crate::ir::NormalizationAction;

/// Jailed relative components plus the recorded normalization actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailedName {
    pub components: Vec<String>,
    pub actions: Vec<NormalizationAction>,
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Jail a member name to a relative component list. Pure: no filesystem.
pub fn jail_relative(raw: &str, max_depth: u32) -> Result<Vec<String>, Finding> {
    Ok(jail_name(raw, max_depth)?.components)
}

/// Jail a member name and record silent normalizations for the IR.
pub fn jail_name(raw: &str, max_depth: u32) -> Result<JailedName, Finding> {
    if raw.contains('\0') {
        return Err(Finding::error(FindingCode::PathNul, "NUL in member name").on(raw));
    }
    if !raw.is_ascii() {
        return Err(Finding::error(
            FindingCode::PathUnicode,
            "Unicode path normalization is not implemented",
        )
        .on(raw));
    }
    if raw.contains('\\') {
        return Err(Finding::error(
            FindingCode::PathInvalidChar,
            "backslash is not a portable ZIP path separator",
        )
        .on(raw));
    }
    if raw.starts_with('/') || raw.starts_with("//") || looks_like_drive(raw) {
        return Err(Finding::error(FindingCode::PathAbsolute, "absolute or drive path").on(raw));
    }

    let mut out = Vec::new();
    let mut actions = Vec::new();
    for (component_index, part) in raw.split('/').enumerate() {
        if part.is_empty() {
            return Err(Finding::error(FindingCode::PathEmpty, "empty path component").on(raw));
        }
        if part == "." {
            actions.push(NormalizationAction::DropDotComponent {
                component_index: component_index as u32,
            });
            continue;
        }
        if part == ".." {
            return Err(Finding::error(FindingCode::PathDotDot, "parent component").on(raw));
        }
        if part.contains(':') {
            return Err(Finding::error(FindingCode::PathAds, "colon in component").on(raw));
        }
        if part
            .chars()
            .any(|c| c.is_ascii_control() || "<>\"|?*".contains(c))
        {
            return Err(Finding::error(FindingCode::PathInvalidChar, "illegal character").on(raw));
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(Finding::error(FindingCode::PathTrailing, "trailing dot or space").on(raw));
        }
        if is_reserved(part) {
            return Err(Finding::error(FindingCode::PathReserved, "Windows reserved name").on(raw));
        }
        out.push(part.to_string());
    }
    if out.is_empty() {
        return Err(Finding::error(FindingCode::PathEmpty, "name empty after normalize").on(raw));
    }
    if out.len() as u32 > max_depth {
        return Err(Finding::error(FindingCode::PathDepth, "path too deep").on(raw));
    }
    Ok(JailedName {
        components: out,
        actions,
    })
}

/// Join jailed components under dest. Dest must already be absolute.
pub fn join_under_dest(dest: &Path, parts: &[String], raw: &str) -> Result<PathBuf, Finding> {
    let dest = dest.to_path_buf();
    let mut target = dest.clone();
    for p in parts {
        target.push(p);
    }
    let dest_abs = dest;
    let tgt = target;
    if !is_strict_child_or_eq(&dest_abs, &tgt) {
        return Err(Finding::error(FindingCode::PathEscape, "path escapes destination").on(raw));
    }
    Ok(tgt)
}

fn looks_like_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn is_reserved(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part);
    RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

fn is_strict_child_or_eq(root: &Path, target: &Path) -> bool {
    let root_c: Vec<_> = root.components().collect();
    let tgt_c: Vec<_> = target.components().collect();
    tgt_c.starts_with(&root_c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dest() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\out")
        } else {
            PathBuf::from("/out")
        }
    }

    #[test]
    fn rejects_dotdot() {
        let e = jail_relative("../outside.txt", 32).unwrap_err();
        assert_eq!(e.code, FindingCode::PathDotDot);
    }

    #[test]
    fn rejects_colon_ads() {
        let e = jail_relative("safe.txt:hidden", 32).unwrap_err();
        assert_eq!(e.code, FindingCode::PathAds);
    }

    #[test]
    fn rejects_absolute() {
        assert_eq!(
            jail_relative("/etc/passwd", 32).unwrap_err().code,
            FindingCode::PathAbsolute
        );
    }

    #[test]
    fn rejects_reserved_nul() {
        assert_eq!(
            jail_relative("NUL.txt", 32).unwrap_err().code,
            FindingCode::PathReserved
        );
    }

    #[test]
    fn accepts_nested() {
        let p = jail_relative("nested/hello.txt", 32).unwrap();
        assert_eq!(p, ["nested", "hello.txt"]);
        let joined = join_under_dest(&dest(), &p, "nested/hello.txt").unwrap();
        assert!(joined.ends_with("hello.txt"));
    }

    #[test]
    fn rejects_backslash_instead_of_rewriting_it() {
        let e = jail_relative(r"nested\hello.txt", 32).unwrap_err();
        assert_eq!(e.code, FindingCode::PathInvalidChar);
    }

    #[test]
    fn rejects_ascii_delete() {
        let e = jail_relative("bad\u{7f}name", 32).unwrap_err();
        assert_eq!(e.code, FindingCode::PathInvalidChar);
    }

    #[test]
    fn drops_dot_components() {
        let p = jail_relative("a/./b.txt", 32).unwrap();
        assert_eq!(p, ["a", "b.txt"]);
        let jailed = jail_name("a/./b.txt", 32).unwrap();
        assert_eq!(
            jailed.actions,
            [NormalizationAction::DropDotComponent { component_index: 1 }]
        );
    }
}
