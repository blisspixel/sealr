use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

use crate::findings::Finding;

/// SHA-256 of the archive bytes, or an explicit gap when those bytes were never held.
///
/// Available sources serialize as `{ "sha256": "..." }` so the alpha.2 inspect and
/// materialize JSON shape stays byte-compatible. Unavailable sources serialize as
/// `{ "status": "unavailable" }` and never emit the former all-zero sentinel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceDigest {
    Available { sha256: String },
    Unavailable,
}

impl SourceDigest {
    pub fn available(sha256: impl Into<String>) -> Self {
        Self::Available {
            sha256: sha256.into(),
        }
    }

    pub fn unavailable() -> Self {
        Self::Unavailable
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Available { sha256 } => Some(sha256),
            Self::Unavailable => None,
        }
    }
}

impl Serialize for SourceDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Available { sha256 } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("sha256", sha256)?;
                map.end()
            }
            Self::Unavailable => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("status", "unavailable")?;
                map.end()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum InterpretationStatus {
    Interpreted,
    Malformed,
    Unsupported,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum AdmissionStatus {
    Admitted,
    Denied,
    NotEvaluated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum VerificationStatus {
    StructureOnly,
    Partial {
        verified_members: u64,
        pending_members: u64,
    },
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum EffectStatus {
    NotRequested,
    Committed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoppingPhase {
    Source,
    Structure,
    Admission,
    Verification,
    Effect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ViewCompleteness {
    Complete,
    Partial { phase: StoppingPhase, cause: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SemanticAxes {
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
}

impl SemanticAxes {
    pub fn inspect_complete() -> Self {
        Self {
            interpretation: InterpretationStatus::Interpreted,
            admission: AdmissionStatus::Admitted,
            verification: VerificationStatus::Complete,
            effect: EffectStatus::NotRequested,
            view_completeness: ViewCompleteness::Complete,
        }
    }

    pub fn materialize_committed() -> Self {
        Self {
            interpretation: InterpretationStatus::Interpreted,
            admission: AdmissionStatus::Admitted,
            verification: VerificationStatus::Complete,
            effect: EffectStatus::Committed,
            view_completeness: ViewCompleteness::Complete,
        }
    }

    pub fn source_failure(finding: &Finding, admission: AdmissionStatus) -> Self {
        Self {
            interpretation: InterpretationStatus::Indeterminate,
            admission,
            verification: VerificationStatus::StructureOnly,
            effect: EffectStatus::NotRequested,
            view_completeness: partial(StoppingPhase::Source, finding),
        }
    }

    pub fn structure_stop(
        interpretation: InterpretationStatus,
        admission: AdmissionStatus,
        finding: &Finding,
    ) -> Self {
        let completeness = if matches!(
            interpretation,
            InterpretationStatus::Unsupported | InterpretationStatus::Malformed
        ) {
            ViewCompleteness::Complete
        } else {
            partial(StoppingPhase::Structure, finding)
        };
        Self {
            interpretation,
            admission,
            verification: VerificationStatus::StructureOnly,
            effect: EffectStatus::NotRequested,
            view_completeness: completeness,
        }
    }

    pub fn denied_at_admission(finding: &Finding) -> Self {
        Self {
            interpretation: InterpretationStatus::Interpreted,
            admission: AdmissionStatus::Denied,
            verification: VerificationStatus::StructureOnly,
            effect: EffectStatus::NotRequested,
            view_completeness: partial(StoppingPhase::Admission, finding),
        }
    }

    pub fn admitted_setup_failed(finding: &Finding) -> Self {
        Self {
            interpretation: InterpretationStatus::Interpreted,
            admission: AdmissionStatus::Admitted,
            verification: VerificationStatus::StructureOnly,
            effect: EffectStatus::Failed,
            view_completeness: partial(StoppingPhase::Effect, finding),
        }
    }

    pub fn admitted_verification_stop(
        verified_members: u64,
        pending_members: u64,
        finding: &Finding,
        dest_requested: bool,
    ) -> Self {
        let (interpretation, admission) = match finding.code {
            crate::findings::FindingCode::CodecDeflateInvalidStream
            | crate::findings::FindingCode::CodecDeflateTrailingInput
            | crate::findings::FindingCode::ZipDiffC4Offset => (
                InterpretationStatus::Malformed,
                AdmissionStatus::NotEvaluated,
            ),
            crate::findings::FindingCode::MaterializeIo
            | crate::findings::FindingCode::MaterializeUnsafeComponent
            | crate::findings::FindingCode::MaterializeCommit
            | crate::findings::FindingCode::MaterializeExists => {
                (InterpretationStatus::Interpreted, AdmissionStatus::Admitted)
            }
            _ => (InterpretationStatus::Interpreted, AdmissionStatus::Denied),
        };
        Self {
            interpretation,
            admission,
            verification: VerificationStatus::Partial {
                verified_members,
                pending_members,
            },
            effect: if dest_requested {
                EffectStatus::Failed
            } else {
                EffectStatus::NotRequested
            },
            view_completeness: partial(StoppingPhase::Verification, finding),
        }
    }

    pub fn admitted_publication_failed(_finding: &Finding) -> Self {
        Self {
            interpretation: InterpretationStatus::Interpreted,
            admission: AdmissionStatus::Admitted,
            verification: VerificationStatus::Complete,
            effect: EffectStatus::Failed,
            view_completeness: ViewCompleteness::Complete,
        }
    }
}

fn partial(phase: StoppingPhase, finding: &Finding) -> ViewCompleteness {
    ViewCompleteness::Partial {
        phase,
        cause: finding.code.as_str().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, FindingCode};

    #[test]
    fn available_source_digest_keeps_alpha2_json_shape() {
        let json = serde_json::to_value(SourceDigest::available("abc")).unwrap();
        assert_eq!(json, serde_json::json!({"sha256": "abc"}));
        assert!(json.get("status").is_none());
    }

    #[test]
    fn unavailable_source_digest_omits_sha256() {
        let json = serde_json::to_value(SourceDigest::unavailable()).unwrap();
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));
        assert!(json.get("sha256").is_none());
    }

    #[test]
    fn source_failure_is_indeterminate_not_a_policy_denial_for_io() {
        let finding = Finding::error(FindingCode::SourceIo, "open");
        let axes = SemanticAxes::source_failure(&finding, AdmissionStatus::NotEvaluated);
        assert_eq!(axes.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(axes.admission, AdmissionStatus::NotEvaluated);
        assert_eq!(axes.effect, EffectStatus::NotRequested);
    }
}
