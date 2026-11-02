//! Identity of one retained materialization stage.
//!
//! `sealr.stage-witness.v1` names the directory object on Linux and macOS.
//! `sealr.windows-file-id.v1` names it on Windows. Neither value is a stage
//! name, a parent listing, or a field of `sealr.materialization.v2` or
//! `sealr.receipt.v3`. `sealr.stage-retention.v1` is the separate record a
//! caller keeps when cleanup fails, and the record
//! `ApplyOptions::with_stage_retention_path` writes after the stage exists.
//! A match does not by itself remove a directory: removal is
//! `recover_abandoned_stage`, and only after the parent, exact component, and
//! witness all check. A process killed before that write still has nothing a
//! later process can present.

pub const STAGE_WITNESS_SCHEMA: &str = "sealr.stage-witness.v1";
pub const WINDOWS_FILE_ID_SCHEMA: &str = "sealr.windows-file-id.v1";
pub const STAGE_RETENTION_SCHEMA: &str = "sealr.stage-retention.v1";

/// Device and inode, or a Windows file identifier, of one retained stage.
///
/// Absence of a witness is not proof, and this value is not a search key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageWitness {
    Unix {
        device: u64,
        inode: u64,
    },
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

impl StageWitness {
    pub(crate) fn unix(device: u64, inode: u64) -> Self {
        Self::Unix { device, inode }
    }

    /// A volume serial of zero is a real volume. An all-zero file identifier
    /// is not an identity and is rejected.
    pub(crate) fn windows(volume_serial: u64, file_id: [u8; 16]) -> Option<Self> {
        if file_id == [0_u8; 16] {
            None
        } else {
            Some(Self::Windows {
                volume_serial,
                file_id,
            })
        }
    }

    #[cfg(test)]
    pub(crate) fn schema(self) -> &'static str {
        match self {
            Self::Unix { .. } => STAGE_WITNESS_SCHEMA,
            Self::Windows { .. } => WINDOWS_FILE_ID_SCHEMA,
        }
    }

    pub(crate) fn to_record(self) -> StageWitnessRecord {
        match self {
            Self::Unix { device, inode } => StageWitnessRecord::Unix { device, inode },
            Self::Windows {
                volume_serial,
                file_id,
            } => StageWitnessRecord::Windows {
                volume_serial,
                file_id: encode_file_id(file_id),
            },
        }
    }

    pub(crate) fn from_record(record: &StageWitnessRecord) -> Option<Self> {
        match record {
            StageWitnessRecord::Unix { device, inode } => Some(Self::unix(*device, *inode)),
            StageWitnessRecord::Windows {
                volume_serial,
                file_id,
            } => Self::windows(*volume_serial, parse_windows_file_id(file_id)?),
        }
    }
}

/// Result of comparing a witness the caller presents with one just observed.
///
/// [`WitnessComparison::SameObject`] means the two values name one object. It
/// does not open a directory, list a parent, or authorize deletion. A Unix
/// witness and a Windows witness are different objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessComparison {
    SameObject,
    NotRecorded,
    DifferentObject,
}

pub(crate) fn compare_witnesses(
    presented: Option<&StageWitness>,
    observed: Option<&StageWitness>,
) -> WitnessComparison {
    match (presented, observed) {
        (Some(presented), Some(observed)) if presented == observed => WitnessComparison::SameObject,
        (Some(_), Some(_)) => WitnessComparison::DifferentObject,
        _ => WitnessComparison::NotRecorded,
    }
}

/// Serializable witness for one retained stage directory.
///
/// `Unix` keeps the historical `sealr.stage-witness.v1` JSON object: `schema`,
/// `device`, and `inode`. `Windows` is `sealr.windows-file-id.v1`: `schema`,
/// `volume_serial`, and `file_id`. `file_id` is exactly 32 lowercase
/// hexadecimal digits. This value does not contain a stage name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
#[non_exhaustive]
pub enum StageWitnessRecord {
    /// Linux and macOS device and inode.
    #[non_exhaustive]
    #[serde(rename = "sealr.stage-witness.v1")]
    Unix { device: u64, inode: u64 },
    /// Windows volume serial and 128-bit file identifier.
    ///
    /// Volume serial zero is accepted. An all-zero, uppercase, or
    /// wrong-length `file_id` is not a witness.
    #[non_exhaustive]
    #[serde(rename = "sealr.windows-file-id.v1")]
    Windows { volume_serial: u64, file_id: String },
}

impl StageWitnessRecord {
    pub(crate) fn is_well_formed(&self) -> bool {
        match self {
            Self::Unix { .. } => true,
            Self::Windows { file_id, .. } => parse_windows_file_id(file_id).is_some(),
        }
    }

    /// True only for the witness kind this process can check.
    ///
    /// A foreign witness fails closed before any directory is opened.
    pub(crate) fn is_for_this_platform(&self) -> bool {
        match self {
            Self::Unix { .. } => cfg!(any(target_os = "linux", target_os = "macos")),
            Self::Windows { .. } => cfg!(windows) && self.is_well_formed(),
        }
    }
}

/// Caller-held record for one stage whose cleanup failed.
///
/// This is not a receipt and not authority to scan a parent directory.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StageRetention {
    pub schema: String,
    pub stage_component: String,
    pub witness: StageWitnessRecord,
}

impl StageRetention {
    pub(crate) fn from_live(stage_component: &str, witness: StageWitness) -> Option<Self> {
        if !is_exact_stage_component(stage_component) {
            return None;
        }
        Some(Self {
            schema: STAGE_RETENTION_SCHEMA.to_owned(),
            stage_component: stage_component.to_owned(),
            witness: witness.to_record(),
        })
    }

    pub(crate) fn validate(&self) -> bool {
        self.schema == STAGE_RETENTION_SCHEMA
            && is_exact_stage_component(&self.stage_component)
            && self.witness.is_well_formed()
    }
}

pub(crate) fn is_exact_stage_component(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".sealr-stage-") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn encode_file_id(file_id: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in file_id {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Exactly 32 lowercase hex digits, and not 16 zero bytes.
pub(crate) fn parse_windows_file_id(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for index in 0..16 {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (high << 4) | low;
    }
    if out == [0_u8; 16] { None } else { Some(out) }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component() -> String {
        format!(".sealr-stage-{}", "ab".repeat(16))
    }

    fn sample_file_id() -> [u8; 16] {
        let mut file_id = [0_u8; 16];
        file_id[0] = 0xab;
        file_id[15] = 0x11;
        file_id
    }

    #[test]
    fn schema_is_not_a_receipt_schema() {
        let unix = StageWitness::unix(1, 2);
        assert_eq!(unix.schema(), "sealr.stage-witness.v1");
        assert!(!unix.schema().contains("receipt"));
        assert!(!unix.schema().contains("materialization"));
        let windows = StageWitness::windows(0, sample_file_id()).unwrap();
        assert_eq!(windows.schema(), "sealr.windows-file-id.v1");
        assert!(!windows.schema().contains("receipt"));
        assert!(!windows.schema().contains("materialization"));
    }

    #[test]
    fn missing_witness_is_not_a_match() {
        let observed = StageWitness::unix(7, 11);
        assert_eq!(
            compare_witnesses(None, Some(&observed)),
            WitnessComparison::NotRecorded
        );
        assert_eq!(
            compare_witnesses(Some(&observed), None),
            WitnessComparison::NotRecorded
        );
        assert_eq!(
            compare_witnesses(None, None),
            WitnessComparison::NotRecorded
        );
    }

    #[test]
    fn equal_device_and_inode_match_and_a_difference_does_not() {
        let retained = StageWitness::unix(7, 11);
        assert_eq!(
            compare_witnesses(Some(&retained), Some(&StageWitness::unix(7, 11))),
            WitnessComparison::SameObject
        );
        assert_eq!(
            compare_witnesses(Some(&retained), Some(&StageWitness::unix(7, 12))),
            WitnessComparison::DifferentObject
        );
        assert_eq!(
            compare_witnesses(Some(&retained), Some(&StageWitness::unix(8, 11))),
            WitnessComparison::DifferentObject
        );
    }

    #[test]
    fn unix_and_windows_witnesses_are_different_objects() {
        let unix = StageWitness::unix(1, 2);
        let windows = StageWitness::windows(1, sample_file_id()).unwrap();
        assert_eq!(
            compare_witnesses(Some(&unix), Some(&windows)),
            WitnessComparison::DifferentObject
        );
        assert!(StageWitness::windows(9, [0_u8; 16]).is_none());
    }

    #[test]
    fn retention_accepts_only_the_exact_lowercase_component() {
        let witness = StageWitness::unix(7, 11);
        let retention = StageRetention::from_live(&component(), witness).unwrap();
        assert!(retention.validate());
        assert!(StageRetention::from_live(".sealr-stage-AB", witness).is_none());
        assert!(
            StageRetention::from_live("../.sealr-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", witness)
                .is_none()
        );
        assert!(StageRetention::from_live(&format!("{}/child", component()), witness).is_none());
        let mut wrong_schema = retention.clone();
        wrong_schema.schema = "sealr.receipt.v3".to_owned();
        assert!(!wrong_schema.validate());
        assert!(
            serde_json::from_str::<StageWitnessRecord>(
                r#"{"schema":"sealr.receipt.v3","device":1,"inode":2}"#
            )
            .is_err()
        );
    }

    #[test]
    fn unix_retention_json_keeps_the_historical_witness_object() {
        let retention = StageRetention::from_live(&component(), StageWitness::unix(7, 11)).unwrap();
        let json = serde_json::to_string(&retention).unwrap();
        let expected = format!(
            r#"{{"schema":"sealr.stage-retention.v1","stage_component":"{}","witness":{{"schema":"sealr.stage-witness.v1","device":7,"inode":11}}}}"#,
            component()
        );
        assert_eq!(json, expected);
        let parsed: StageRetention = serde_json::from_str(&json).unwrap();
        assert!(parsed.validate());
        assert_eq!(parsed, retention);
        assert!(
            serde_json::from_str::<StageRetention>(&format!(
                r#"{{"schema":"sealr.stage-retention.v1","stage_component":"{}","witness":{{"schema":"sealr.stage-witness.v1","device":7,"inode":11,"extra":true}}}}"#,
                component()
            ))
            .is_err()
        );
    }

    #[test]
    fn windows_file_id_accepts_volume_serial_zero_and_rejects_a_bad_identifier() {
        let witness = StageWitness::windows(0, sample_file_id()).unwrap();
        let retention = StageRetention::from_live(&component(), witness).unwrap();
        let json = serde_json::to_string(&retention).unwrap();
        let expected = format!(
            r#"{{"schema":"sealr.stage-retention.v1","stage_component":"{}","witness":{{"schema":"sealr.windows-file-id.v1","volume_serial":0,"file_id":"ab000000000000000000000000000011"}}}}"#,
            component()
        );
        assert_eq!(json, expected);
        assert!(retention.validate());
        assert!(retention.witness.is_well_formed());

        let mut uppercase = retention.clone();
        let StageWitnessRecord::Windows { file_id, .. } = &mut uppercase.witness else {
            panic!("windows witness");
        };
        file_id.make_ascii_uppercase();
        assert!(!uppercase.validate());
        assert!(StageWitness::from_record(&uppercase.witness).is_none());

        for file_id in [
            "00000000000000000000000000000000",
            "ab",
            "ab00000000000000000000000000001",
            "gb000000000000000000000000000011",
        ] {
            let bad = format!(
                r#"{{"schema":"sealr.stage-retention.v1","stage_component":"{}","witness":{{"schema":"sealr.windows-file-id.v1","volume_serial":1,"file_id":"{file_id}"}}}}"#,
                component()
            );
            let parsed: StageRetention = serde_json::from_str(&bad).unwrap();
            assert!(!parsed.validate(), "{file_id}");
        }
    }
}
