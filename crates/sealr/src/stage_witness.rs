//! Live identity of one retained materialization stage.
//!
//! `sealr.stage-witness.v1` names the directory object the creating operation
//! holds. It is not a stage name, not a parent listing, and not a field of
//! `sealr.materialization.v2` or `sealr.receipt.v3`. A match does not permit
//! removal. Recovery after the creating process is gone is not implemented.

pub(crate) const SCHEMA: &str = "sealr.stage-witness.v1";

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
}
