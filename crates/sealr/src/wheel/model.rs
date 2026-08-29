use serde::{Deserialize, Serialize};

pub const CONSUMER_PROFILE_ID: &str = "sealr.consumer.python-wheel.v1";
pub const CONSUMER_PROFILE_SCHEMA: &str = "sealr.wheel-consumer-profile.v1";
pub const SPEC_SNAPSHOT_ID: &str = "pypa-wheel-core-metadata-2026-08-28";
pub const ARTIFACT_ENCODING_ID: &str = "sealrWheelArtifactV1";
pub const PLAN_ENCODING_ID: &str = "sealrWheelInstallPlanV1";
pub const REALIZATION_ENCODING_ID: &str = "sealrWheelRealizationV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelLimits {
    pub max_filename_bytes: u64,
    pub max_wheel_bytes: u64,
    pub max_metadata_bytes: u64,
    pub max_record_bytes: u64,
    pub max_entry_points_bytes: u64,
    pub max_semantic_bytes: u64,
    pub max_script_bytes: u64,
    pub max_plan_inspection_bytes: u64,
    pub max_header_lines: u64,
    pub max_header_line_bytes: u64,
    pub max_record_rows: u64,
    pub max_record_row_bytes: u64,
    pub max_expanded_tags: u64,
}

impl Default for WheelLimits {
    fn default() -> Self {
        Self {
            max_filename_bytes: 1_024,
            max_wheel_bytes: 64 * 1024,
            max_metadata_bytes: 4 * 1024 * 1024,
            max_record_bytes: 16 * 1024 * 1024,
            max_entry_points_bytes: 1024 * 1024,
            max_semantic_bytes: 22 * 1024 * 1024,
            max_script_bytes: 1024 * 1024,
            max_plan_inspection_bytes: 16 * 1024 * 1024,
            max_header_lines: 4_096,
            max_header_line_bytes: 8 * 1024,
            max_record_rows: 65_536,
            max_record_row_bytes: 16 * 1024,
            max_expanded_tags: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EvaluationStage {
    Container,
    Filename,
    Selection,
    WheelMetadata,
    CoreMetadata,
    Record,
    EntryPoints,
    Plan,
    Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelFinding {
    pub stage: EvaluationStage,
    pub code: String,
    pub detail: String,
    pub path: Option<String>,
}

impl WheelFinding {
    pub(crate) fn new(
        stage: EvaluationStage,
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            code: code.into(),
            detail: detail.into(),
            path: None,
        }
    }

    pub(crate) fn on(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelFilename {
    pub raw: String,
    pub distribution: String,
    pub version: String,
    pub build: Option<String>,
    pub python_tag: String,
    pub abi_tag: String,
    pub platform_tag: String,
    pub normalized_distribution: String,
    pub normalized_version: String,
    pub expanded_tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelHeaders {
    pub wheel_version: String,
    pub generator: Option<String>,
    pub root_is_purelib: bool,
    pub build: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CoreMetadata {
    pub metadata_version: String,
    pub name: String,
    pub version: String,
    pub normalized_name: String,
    pub normalized_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RecordBinding {
    pub path: String,
    pub member_index: usize,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub is_record: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EntryPoint {
    pub group: String,
    pub name: String,
    pub object: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExecutableDisposition {
    NotExecutable,
    SourceExecutable,
    GeneratedWrapper,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelMemberFacts {
    pub member_index: usize,
    pub path: String,
    pub creator_system: u8,
    pub external_attributes: u32,
    pub source_executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelArtifactIR {
    pub schema: String,
    pub consumer_profile: String,
    pub consumer_profile_digest: String,
    pub spec_snapshot: String,
    pub source_sha256: String,
    pub archive_tree_sha256: String,
    pub interpretation_profile: String,
    pub interpretation_profile_sha256: String,
    pub filename: WheelFilename,
    pub dist_info_root: String,
    pub data_root: Option<String>,
    pub wheel: WheelHeaders,
    pub metadata: CoreMetadata,
    pub record: Vec<RecordBinding>,
    pub entry_points: Vec<EntryPoint>,
    pub member_facts: Vec<WheelMemberFacts>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum InstallScheme {
    Purelib,
    Platlib,
    Scripts,
    Headers,
    Data,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum InstallTransform {
    Copy,
    RewritePythonShebang,
    GenerateConsoleWrapper,
    GenerateGuiWrapper,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct InstallEntry {
    pub source_member_index: Option<usize>,
    pub source_path: Option<String>,
    pub scheme: InstallScheme,
    pub relative_path: String,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub executable: ExecutableDisposition,
    pub transform: InstallTransform,
    pub entry_point: Option<EntryPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelInstallPlan {
    pub(crate) schema: String,
    pub(crate) model: String,
    pub(crate) artifact_sha256: String,
    pub(crate) entries: Vec<InstallEntry>,
}

impl WheelInstallPlan {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub fn entries(&self) -> &[InstallEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WheelIdentities {
    pub source_sha256: String,
    pub archive_tree_sha256: String,
    pub artifact_sha256: String,
    pub install_plan_sha256: String,
    pub realization_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RealizedOutput {
    pub scheme: InstallScheme,
    pub relative_path: String,
    pub sha256: String,
    pub size: u64,
}

impl RealizedOutput {
    /// The only way an external consumer can report one realized file, since
    /// the struct is non-exhaustive.
    pub fn new(
        scheme: InstallScheme,
        relative_path: impl Into<String>,
        sha256: impl Into<String>,
        size: u64,
    ) -> Self {
        Self {
            scheme,
            relative_path: relative_path.into(),
            sha256: sha256.into(),
            size,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {detail}")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RealizationIdentityError {
    pub code: String,
    pub detail: String,
    pub path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
#[non_exhaustive]
#[must_use = "wheel evaluation outcomes must be classified"]
pub enum WheelEvaluation {
    Admitted {
        artifact: Box<WheelArtifactIR>,
        plan: Box<WheelInstallPlan>,
        identities: WheelIdentities,
        findings: Vec<WheelFinding>,
    },
    Denied {
        findings: Vec<WheelFinding>,
    },
    Unsupported {
        findings: Vec<WheelFinding>,
    },
    InfrastructureFailure {
        kind: WheelInfrastructureErrorKind,
        detail: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum WheelInfrastructureErrorKind {
    NotFound,
    NotFile,
    LimitExceeded,
    PlatformLimit,
    AllocationFailed,
    SourceIo,
    IntegrityMismatch,
    IsolationUnavailable,
    WorkerFailed,
    TimedOut,
    Internal,
}
