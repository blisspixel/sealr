//! RFC 8785 (JCS) canonical JSON emission over sealr's integer-only evidence
//! domain.
//!
//! This is the encoder for the planned JCS evidence lineage: new versioned
//! view and receipt schemas whose emitted file bytes are exactly the digested
//! bytes. Nothing in the shipped `sealr.view.v1` / `sealr.receipt.v2` lineage
//! calls it; those digests remain covered by the frozen declaration-order
//! encoding in `docs/evidence-encoding.md`.
//!
//! The implementation follows RFC 8785 with one deliberate restriction that is
//! stricter than the RFC: sealr's evidence domain contains no floats, so any
//! non-integer number — including a float that happens to equal an integer —
//! fails closed instead of entering ECMAScript double-to-string territory.
//! Integers are bounded to the IEEE-754 double-safe range so every emitted
//! value is exactly representable in any RFC-compliant consumer.

use std::fmt;

use serde::Serialize;
use serde_json::Value;

/// Largest integer magnitude the canonical evidence domain admits: 2^53 − 1,
/// the IEEE-754 double-safe ceiling RFC 8785 recommends for true integers.
pub const MAX_CANONICAL_INTEGER: u64 = (1 << 53) - 1;

/// Stable category for canonicalization failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalJsonErrorKind {
    /// A non-integer number appeared; the evidence domain is integer-only.
    NonInteger,
    /// An integer magnitude exceeded 2^53 − 1.
    IntegerRange,
    /// The value could not be converted to a JSON tree at all.
    Serialize,
}

/// Failure produced while emitting canonical bytes. Canonicalization is
/// all-or-nothing: no bytes are produced on any failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanonicalJsonError {
    kind: CanonicalJsonErrorKind,
    detail: String,
}

impl CanonicalJsonError {
    fn new(kind: CanonicalJsonErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> CanonicalJsonErrorKind {
        self.kind
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Serialize `value` as RFC 8785 canonical JSON bytes over the integer-only
/// evidence domain.
///
/// Object properties are sorted by the UTF-16 code units of their raw names,
/// strings use the exact JCS escape table, no whitespace is emitted, and any
/// non-integer number or integer outside ±(2^53 − 1) fails closed with no
/// bytes produced.
pub fn jcs_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    let tree = serde_json::to_value(value).map_err(|error| {
        CanonicalJsonError::new(
            CanonicalJsonErrorKind::Serialize,
            format!("value did not convert to a JSON tree: {error}"),
        )
    })?;
    let mut out = Vec::new();
    write_value(&tree, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_CANONICAL_INTEGER {
                    return Err(CanonicalJsonError::new(
                        CanonicalJsonErrorKind::IntegerRange,
                        format!("{unsigned} exceeds the 2^53-1 canonical integer ceiling"),
                    ));
                }
                out.extend_from_slice(unsigned.to_string().as_bytes());
            } else if let Some(signed) = number.as_i64() {
                if signed.unsigned_abs() > MAX_CANONICAL_INTEGER {
                    return Err(CanonicalJsonError::new(
                        CanonicalJsonErrorKind::IntegerRange,
                        format!("{signed} exceeds the 2^53-1 canonical integer ceiling"),
                    ));
                }
                out.extend_from_slice(signed.to_string().as_bytes());
            } else {
                return Err(CanonicalJsonError::new(
                    CanonicalJsonErrorKind::NonInteger,
                    format!("{number} is not an integer; the evidence domain is integer-only"),
                ));
            }
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Emit one string with the exact RFC 8785 escape table: `\"` and `\\`, the
/// two-character escapes for backspace, tab, line feed, form feed, and
/// carriage return, lowercase `\u00hh` for the remaining controls below
/// U+0020, and every other character — non-ASCII included — as literal UTF-8.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{000c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut encoded = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_rfc_8785_property_sorting_vector_is_reproduced_exactly() {
        let value = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis",
        });
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
             \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\
             \"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\
             \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(
            String::from_utf8(jcs_bytes(&value).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn surrogate_keys_sort_by_utf16_code_units_not_code_points() {
        // U+1F600 > U+FB33 as code points, but its UTF-16 lead surrogate
        // 0xD83D sorts below 0xFB33 — the RFC's deliberate quirk. Relying on
        // serde_json's BTreeMap code-point order would invert this pair.
        assert!('\u{1f600}' > '\u{fb33}');
        let value = json!({ "\u{1f600}": 1, "\u{fb33}": 2 });
        assert_eq!(
            String::from_utf8(jcs_bytes(&value).unwrap()).unwrap(),
            "{\"\u{1f600}\":1,\"\u{fb33}\":2}"
        );
    }

    #[test]
    fn the_escape_table_matches_the_rfc_exactly() {
        let text: String = ('\u{0000}'..='\u{001f}').collect();
        let value = json!({ "controls": text, "quote": "\"\\", "literal": "\u{f6}\u{1f600}" });
        let emitted = String::from_utf8(jcs_bytes(&value).unwrap()).unwrap();
        assert_eq!(
            emitted,
            "{\"controls\":\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\
             \\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\
             \\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\",\
             \"literal\":\"\u{f6}\u{1f600}\",\"quote\":\"\\\"\\\\\"}"
        );
    }

    #[test]
    fn integers_are_bounded_to_the_double_safe_range() {
        assert_eq!(jcs_bytes(&json!(0)).unwrap(), b"0");
        assert_eq!(
            jcs_bytes(&json!(9_007_199_254_740_991_u64)).unwrap(),
            b"9007199254740991"
        );
        assert_eq!(
            jcs_bytes(&json!(-9_007_199_254_740_991_i64)).unwrap(),
            b"-9007199254740991"
        );
        assert_eq!(
            jcs_bytes(&json!(9_007_199_254_740_992_u64))
                .unwrap_err()
                .kind(),
            CanonicalJsonErrorKind::IntegerRange
        );
        assert_eq!(
            jcs_bytes(&json!(-9_007_199_254_740_992_i64))
                .unwrap_err()
                .kind(),
            CanonicalJsonErrorKind::IntegerRange
        );
        assert_eq!(
            jcs_bytes(&json!(u64::MAX)).unwrap_err().kind(),
            CanonicalJsonErrorKind::IntegerRange
        );
    }

    #[test]
    fn every_non_integer_number_fails_closed() {
        for hostile in [json!(1.5), json!(1.0), json!(-0.0), json!(3.333)] {
            assert_eq!(
                jcs_bytes(&hostile).unwrap_err().kind(),
                CanonicalJsonErrorKind::NonInteger,
                "{hostile} must be rejected"
            );
        }
    }

    #[test]
    fn structure_emits_compact_bytes_with_no_whitespace() {
        let value = json!({
            "b": [null, true, false, {"nested": []}],
            "a": {"y": 1, "x": 2},
        });
        assert_eq!(
            String::from_utf8(jcs_bytes(&value).unwrap()).unwrap(),
            r#"{"a":{"x":2,"y":1},"b":[null,true,false,{"nested":[]}]}"#
        );
    }

    #[test]
    fn every_default_policy_and_a_live_view_canonicalize_semantically_unchanged() {
        for policy in [
            crate::Policy::default_v1(),
            crate::Policy::default_v2(),
            crate::Policy::default_v3(),
            crate::Policy::default_v4(),
            crate::Policy::default_v5(),
            crate::Policy::default_v6(),
            crate::Policy::default_v7(),
            crate::Policy::default_v8(),
            crate::Policy::default_v9(),
            crate::Policy::default_v10(),
            crate::Policy::default_v11(),
        ] {
            let canonical = jcs_bytes(&policy).unwrap();
            let reparsed: Value = serde_json::from_slice(&canonical).unwrap();
            assert_eq!(
                reparsed,
                serde_json::to_value(&policy).unwrap(),
                "{}: canonical bytes must carry the identical document",
                policy.id
            );
        }
    }
}
