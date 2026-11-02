//! Identity of one retained materialization stage.
//!
//! `sealr.stage-witness.v1` names the directory object the creating operation
//! holds. It is not a stage name, not a parent listing, and not a field of
//! `sealr.materialization.v2` or `sealr.receipt.v3`.
//! `sealr.stage-retention.v1` is the separate record a caller keeps when
//! cleanup fails. A match does not by itself remove a directory: removal is
//! `recover_abandoned_stage`, and only after the parent, exact component, and
//! witness all check. A killed process that never returned the record still
//! has nothing a later process can present.

pub const STAGE_WITNESS_SCHEMA: &str = "sealr.stage-witness.v1";
pub const STAGE_RETENTION_SCHEMA: &str = "sealr.stage-retention.v1";

pub(crate) const SCHEMA: &str = STAGE_WITNESS_SCHEMA;

/// Device and inode of the retained stage directory on Linux and macOS.
///
/// Windows file identifiers are not recorded yet. Absence of a witness is not
/// proof, and this value is not a search key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StageWitness {
    schema: &'static str,
    device: u64,
    inode: u64,
}

impl StageWitness {
    pub(crate) fn unix(device: u64, inode: u64) -> Self {
        Self {
            schema: SCHEMA,
            device,
            inode,
        }
    }
}

/// Result of comparing a witness the caller presents with one just observed.
///
/// [`WitnessComparison::SameObject`] means the two values name one object. It
/// does not open a directory, list a parent, or authorize deletion.
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

/// Serializable device and inode witness. It does not contain a stage name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StageWitnessRecord {
    pub schema: String,
    pub device: u64,
    pub inode: u64,
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
            witness: StageWitnessRecord {
                schema: STAGE_WITNESS_SCHEMA.to_owned(),
                device: witness.device,
                inode: witness.inode,
            },
        })
    }

    pub(crate) fn validate(&self) -> bool {
        self.schema == STAGE_RETENTION_SCHEMA
            && is_exact_stage_component(&self.stage_component)
            && self.witness.schema == STAGE_WITNESS_SCHEMA
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_not_a_receipt_schema() {
        let witness = StageWitness::unix(1, 2);
        assert_eq!(witness.schema, "sealr.stage-witness.v1");
        assert!(!witness.schema.contains("receipt"));
        assert!(!witness.schema.contains("materialization"));
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
    fn retention_accepts_only_the_exact_lowercase_component() {
        let witness = StageWitness::unix(7, 11);
        let component = format!(".sealr-stage-{}", "ab".repeat(16));
        let retention = StageRetention::from_live(&component, witness).unwrap();
        assert!(retention.validate());
        assert!(StageRetention::from_live(".sealr-stage-AB", witness).is_none());
        assert!(
            StageRetention::from_live("../.sealr-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", witness)
                .is_none()
        );
        assert!(StageRetention::from_live(&format!("{component}/child"), witness).is_none());
        let mut wrong_schema = retention.clone();
        wrong_schema.schema = "sealr.receipt.v3".to_owned();
        assert!(!wrong_schema.validate());
        let mut wrong_witness = retention.clone();
        wrong_witness.witness.schema = "sealr.receipt.v3".to_owned();
        assert!(!wrong_witness.validate());
    }
}
