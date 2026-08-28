use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
pub use crate::ratio::ratio_exceeds;

pub const POLICY_FORMAT_ZIP: &str = "zip";
pub const POLICY_FORMAT_TAR_USTAR: &str = "tar-ustar";

/// Pre-release Sealr policy, hashed in this struct's deterministic serialized field order.
///
/// This is the caller constructor and receipt-hashed object. Runtime enforcement
/// uses [`Policy::compile`] output, not these fields directly.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Policy {
    pub schema: &'static str,
    pub id: String,
    pub formats: Vec<String>,
    pub max_archive_bytes: u64,
    pub max_files: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: Option<u64>,
    pub max_path_depth: u32,
    pub max_metadata_bytes: u64,
    pub max_dict_bytes: u64,
    pub symlinks: &'static str,
    pub hardlinks: &'static str,
    pub overwrite: &'static str,
    pub setuid: &'static str,
    pub nested_depth: u32,
    pub ambiguity: &'static str,
    pub case_fold_collision: &'static str,
    pub magic_vs_extension: &'static str,
    pub encrypted: &'static str,
    pub atomic: bool,
}

/// Typed resource caps copied from a compiled policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceBudget {
    pub max_archive_bytes: u64,
    pub max_files: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: Option<u64>,
    pub max_path_depth: u32,
    pub max_metadata_bytes: u64,
}

/// The only implemented target filesystem model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetModel {
    PortableV1,
}

/// The only implemented consumer. Package profiles come later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerProfile {
    GenericArchive,
}

/// Effect controls that currently compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectPolicy {
    pub member_sync: bool,
}

/// Supported controls compiled from a [`Policy`] before source ingestion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledControls {
    pub budget: ResourceBudget,
    pub target: TargetModel,
    pub consumer: ConsumerProfile,
    pub effect: EffectPolicy,
}

impl Policy {
    /// Construct the Alpha.8 compatibility policy, which authorizes ZIP only.
    pub fn default_v1() -> Self {
        Self {
            schema: "sealr.policy.v1",
            id: "sealr:policy/default/v1".into(),
            formats: vec![POLICY_FORMAT_ZIP.into()],
            max_archive_bytes: 512 * 1024 * 1024,
            max_files: 10_000,
            max_member_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 5 * 1024 * 1024 * 1024,
            max_ratio: Some(100),
            max_path_depth: 32,
            max_metadata_bytes: 4 * 1024 * 1024,
            max_dict_bytes: 64 * 1024 * 1024,
            symlinks: "deny",
            hardlinks: "deny",
            overwrite: "refuse",
            setuid: "strip",
            nested_depth: 1,
            ambiguity: "deny",
            case_fold_collision: "deny",
            magic_vs_extension: "deny",
            encrypted: "deny",
            atomic: false,
        }
    }

    /// Construct the multi-format v2 policy, which authorizes ZIP and portable ustar.
    ///
    /// Format selection remains a separate explicit operation input. This policy
    /// only defines which selected formats the operation is allowed to interpret.
    pub fn default_v2() -> Self {
        Self {
            schema: "sealr.policy.v2",
            id: "sealr:policy/default/v2".into(),
            formats: vec![POLICY_FORMAT_ZIP.into(), POLICY_FORMAT_TAR_USTAR.into()],
            ..Self::default_v1()
        }
    }

    pub fn digest_hex(&self) -> String {
        let json = serde_json::to_vec(self).expect("policy serializes");
        hex_sha256(&json)
    }

    pub fn allows_format(&self, magic: &str) -> bool {
        self.formats.iter().any(|f| f == magic)
    }

    /// Compile into typed supported controls, or fail closed before source ingestion.
    ///
    /// Reserved constructor fields must still equal the default values. Mutating
    /// them does not enable behavior; it is an unsupported policy.
    pub fn compile(&self) -> Result<CompiledControls, Finding> {
        match self.schema {
            "sealr.policy.v1" if self.formats.as_slice() == [POLICY_FORMAT_ZIP] => {}
            "sealr.policy.v1" => {
                return Err(unsupported(format!(
                    "formats {:?} are unsupported by sealr.policy.v1; only [\"zip\"] is implemented",
                    self.formats
                )));
            }
            "sealr.policy.v2" if valid_v2_formats(&self.formats) => {}
            "sealr.policy.v2" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"tar-ustar\"]",
                    self.formats
                )));
            }
            _ => {
                return Err(unsupported(format!(
                    "policy schema {} is unsupported",
                    self.schema
                )));
            }
        }
        let defaults = Self::default_v1();
        check_reserved("symlinks", self.symlinks, defaults.symlinks)?;
        check_reserved("hardlinks", self.hardlinks, defaults.hardlinks)?;
        check_reserved("overwrite", self.overwrite, defaults.overwrite)?;
        check_reserved("setuid", self.setuid, defaults.setuid)?;
        check_reserved("ambiguity", self.ambiguity, defaults.ambiguity)?;
        check_reserved(
            "case_fold_collision",
            self.case_fold_collision,
            defaults.case_fold_collision,
        )?;
        check_reserved(
            "magic_vs_extension",
            self.magic_vs_extension,
            defaults.magic_vs_extension,
        )?;
        check_reserved("encrypted", self.encrypted, defaults.encrypted)?;
        if self.nested_depth != defaults.nested_depth {
            return Err(unsupported(format!(
                "nested_depth={} is unsupported; only {} is implemented",
                self.nested_depth, defaults.nested_depth
            )));
        }
        if self.max_dict_bytes != defaults.max_dict_bytes {
            return Err(unsupported(format!(
                "max_dict_bytes={} is unsupported; only {} is implemented",
                self.max_dict_bytes, defaults.max_dict_bytes
            )));
        }
        if self.schema == "sealr.policy.v2" && self.max_files > u64::from(u32::MAX) {
            return Err(unsupported(format!(
                "max_files={} exceeds the u32 identity-encoding limit",
                self.max_files
            )));
        }

        Ok(CompiledControls {
            budget: ResourceBudget {
                max_archive_bytes: self.max_archive_bytes,
                max_files: self.max_files,
                max_member_bytes: self.max_member_bytes,
                max_total_bytes: self.max_total_bytes,
                max_ratio: self.max_ratio,
                max_path_depth: self.max_path_depth,
                max_metadata_bytes: self.max_metadata_bytes,
            },
            target: TargetModel::PortableV1,
            consumer: ConsumerProfile::GenericArchive,
            effect: EffectPolicy {
                member_sync: self.atomic,
            },
        })
    }

    /// Compile the policy and require it to authorize the explicitly selected format.
    pub fn compile_for_format(&self, format: &str) -> Result<CompiledControls, Finding> {
        let controls = self.compile()?;
        if self.allows_format(format) {
            Ok(controls)
        } else {
            Err(unsupported(format!(
                "selected format {format:?} is not authorized by policy formats {:?}",
                self.formats
            )))
        }
    }
}

fn valid_v2_formats(formats: &[String]) -> bool {
    match formats {
        [only] => only == POLICY_FORMAT_ZIP || only == POLICY_FORMAT_TAR_USTAR,
        [first, second] => first == POLICY_FORMAT_ZIP && second == POLICY_FORMAT_TAR_USTAR,
        _ => false,
    }
}

fn check_reserved(name: &str, actual: &str, supported: &str) -> Result<(), Finding> {
    if actual == supported {
        Ok(())
    } else {
        Err(unsupported(format!(
            "{name}={actual:?} is unsupported; only {supported:?} is implemented"
        )))
    }
}

fn unsupported(detail: String) -> Finding {
    Finding::error(FindingCode::PolicyUnsupported, detail)
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v1().digest_hex(),
            "8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340"
        );
    }

    #[test]
    fn multi_format_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v2().digest_hex(),
            "a02984fd88cb3fed1d60a339485eb0742da418681427dadcf699b4303f17d14a"
        );
    }

    #[test]
    fn default_policy_compiles() {
        let compiled = Policy::default_v1().compile().expect("default compiles");
        assert_eq!(compiled.budget.max_ratio, Some(100));
        assert!(!compiled.effect.member_sync);
        assert_eq!(compiled.target, TargetModel::PortableV1);
    }

    #[test]
    fn reserved_field_mutation_fails_closed() {
        let mut policy = Policy::default_v1();
        policy.encrypted = "allow";
        let finding = policy.compile().unwrap_err();
        assert_eq!(finding.code, FindingCode::PolicyUnsupported);
        assert!(finding.detail.contains("encrypted"));
    }

    #[test]
    fn unsupported_overwrite_fails_closed() {
        let mut policy = Policy::default_v1();
        policy.overwrite = "replace";
        assert_eq!(
            policy.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn unknown_format_fails_closed() {
        let mut policy = Policy::default_v1();
        policy.formats = vec!["zip".into(), "tar".into()];
        assert_eq!(
            policy.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn selected_format_must_be_authorized() {
        assert_eq!(
            Policy::default_v1()
                .compile_for_format(POLICY_FORMAT_TAR_USTAR)
                .unwrap_err()
                .code,
            FindingCode::PolicyUnsupported
        );
        assert!(Policy::default_v2()
            .compile_for_format(POLICY_FORMAT_ZIP)
            .is_ok());
        assert!(Policy::default_v2()
            .compile_for_format(POLICY_FORMAT_TAR_USTAR)
            .is_ok());
    }

    #[test]
    fn multi_format_policy_requires_a_canonical_known_subset() {
        for formats in [
            Vec::new(),
            vec![POLICY_FORMAT_TAR_USTAR.into(), POLICY_FORMAT_ZIP.into()],
            vec![POLICY_FORMAT_ZIP.into(), POLICY_FORMAT_ZIP.into()],
            vec![POLICY_FORMAT_ZIP.into(), "7z".into()],
        ] {
            let mut policy = Policy::default_v2();
            policy.formats = formats;
            assert_eq!(
                policy.compile().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }
    }

    #[test]
    fn atomic_true_compiles_to_member_sync() {
        let mut policy = Policy::default_v1();
        policy.atomic = true;
        let compiled = policy.compile().unwrap();
        assert!(compiled.effect.member_sync);
    }

    #[test]
    fn member_cap_cannot_exceed_the_identity_encoding() {
        let mut policy = Policy::default_v2();
        policy.max_files = u64::from(u32::MAX) + 1;
        assert_eq!(
            policy.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn compatibility_policy_preserves_its_pre_alpha9_member_cap_language() {
        let mut policy = Policy::default_v1();
        policy.max_files = u64::from(u32::MAX) + 1;
        assert_eq!(
            policy.compile().unwrap().budget.max_files,
            u64::from(u32::MAX) + 1
        );
    }
}
