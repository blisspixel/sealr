use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

use crate::findings::{Finding, FindingCode};
use crate::ir::NormalizationAction;
use unicode_normalization::UnicodeNormalization;

/// Jailed relative components plus the recorded normalization actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailedName {
    pub components: Vec<String>,
    pub actions: Vec<NormalizationAction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JailNameError {
    Invalid {
        code: FindingCode,
        detail: &'static str,
    },
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentDisposition {
    DropDot,
    Keep,
}

#[cfg(test)]
thread_local! {
    static CONTAINER_RESERVATION_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
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
    match jail_name_fallible(raw, max_depth) {
        Ok(jailed) => Ok(jailed),
        Err(JailNameError::Invalid { code, detail }) => Err(Finding::error(code, detail).on(raw)),
        Err(JailNameError::AllocationFailed) => {
            panic!("bounded path normalization allocation failed")
        }
    }
}

pub(crate) fn jail_name_fallible(raw: &str, max_depth: u32) -> Result<JailedName, JailNameError> {
    let (component_count, action_count) = validate_name(raw, max_depth)?;

    let mut out = Vec::new();
    reserve_exact(&mut out, component_count)?;
    let mut actions = Vec::new();
    reserve_exact(&mut actions, action_count)?;
    for (component_index, part) in raw.split('/').enumerate() {
        match validate_component(part).expect("first path-validation pass accepted the component") {
            ComponentDisposition::DropDot => {
                actions.push(NormalizationAction::DropDotComponent {
                    component_index: u32::try_from(component_index)
                        .expect("first path-validation pass bounded the component index"),
                });
            }
            ComponentDisposition::Keep => {
                let mut component = String::new();
                component
                    .try_reserve_exact(part.len())
                    .map_err(|_| JailNameError::AllocationFailed)?;
                component.push_str(part);
                out.push(component);
            }
        }
    }
    Ok(JailedName {
        components: out,
        actions,
    })
}

fn validate_name(raw: &str, max_depth: u32) -> Result<(usize, usize), JailNameError> {
    if raw.contains('\0') {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathNul,
            detail: "NUL in member name",
        });
    }
    if !raw.nfc().eq(raw.chars()) {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathUnicode,
            detail: "member name is not NFC-normalized",
        });
    }
    if raw.contains('\\') {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathInvalidChar,
            detail: "backslash is not a portable ZIP path separator",
        });
    }
    if raw.starts_with('/') || raw.starts_with("//") || looks_like_drive(raw) {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathAbsolute,
            detail: "absolute or drive path",
        });
    }

    let mut component_count = 0_usize;
    let mut action_count = 0_usize;
    for (component_index, part) in raw.split('/').enumerate() {
        match validate_component(part)? {
            ComponentDisposition::DropDot => {
                u32::try_from(component_index).map_err(|_| JailNameError::Invalid {
                    code: FindingCode::PathDepth,
                    detail: "path too deep",
                })?;
                action_count += 1;
            }
            ComponentDisposition::Keep => component_count += 1,
        }
    }
    if component_count == 0 {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathEmpty,
            detail: "name empty after normalize",
        });
    }
    if u32::try_from(component_count).map_or(true, |count| count > max_depth) {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathDepth,
            detail: "path too deep",
        });
    }
    Ok((component_count, action_count))
}

fn validate_component(part: &str) -> Result<ComponentDisposition, JailNameError> {
    if part.is_empty() {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathEmpty,
            detail: "empty path component",
        });
    }
    if part == "." {
        return Ok(ComponentDisposition::DropDot);
    }
    if part == ".." {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathDotDot,
            detail: "parent component",
        });
    }
    if part.contains(':') {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathAds,
            detail: "colon in component",
        });
    }
    if part
        .chars()
        .any(|c| {
            c.is_control()
                || (!c.is_ascii() && c.is_whitespace())
                || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                || "<>\"|?*".contains(c)
        })
    {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathInvalidChar,
            detail: "illegal character",
        });
    }
    if part.ends_with('.') || part.ends_with(' ') {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathTrailing,
            detail: "trailing dot or space",
        });
    }
    if is_reserved(part) {
        return Err(JailNameError::Invalid {
            code: FindingCode::PathReserved,
            detail: "Windows reserved name",
        });
    }
    Ok(ComponentDisposition::Keep)
}

/// Deterministic portable collision key for admitted NFC paths.
pub(crate) fn portable_case_fold(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).nfc().collect()
}

fn reserve_exact<T>(items: &mut Vec<T>, count: usize) -> Result<(), JailNameError> {
    #[cfg(test)]
    CONTAINER_RESERVATION_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    items
        .try_reserve_exact(count)
        .map_err(|_| JailNameError::AllocationFailed)
}

#[cfg(test)]
fn reset_container_reservation_attempts() {
    CONTAINER_RESERVATION_ATTEMPTS.with(|attempts| attempts.set(0));
}

#[cfg(test)]
fn container_reservation_attempts() -> usize {
    CONTAINER_RESERVATION_ATTEMPTS.with(Cell::get)
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

    #[test]
    fn rejects_before_reserving_for_untrusted_component_counts() {
        let slash_dense = format!("../{}", "a/".repeat(32_768));
        reset_container_reservation_attempts();
        assert_eq!(
            jail_name_fallible(&slash_dense, u32::MAX),
            Err(JailNameError::Invalid {
                code: FindingCode::PathDotDot,
                detail: "parent component",
            })
        );
        assert_eq!(container_reservation_attempts(), 0);

        reset_container_reservation_attempts();
        assert_eq!(
            jail_name_fallible("a/b/c", 2),
            Err(JailNameError::Invalid {
                code: FindingCode::PathDepth,
                detail: "path too deep",
            })
        );
        assert_eq!(container_reservation_attempts(), 0);

        reset_container_reservation_attempts();
        jail_name_fallible("a/./b", 2).expect("valid name should materialize after validation");
        assert_eq!(container_reservation_attempts(), 2);
    }
}
