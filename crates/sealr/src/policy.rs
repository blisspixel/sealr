use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};

/// Pre-release `sealr.policy.v1`, hashed in this struct's deterministic serialized field order.
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
    pub fn default_v1() -> Self {
        Self {
            schema: "sealr.policy.v1",
            id: "sealr:policy/default/v1".into(),
            formats: vec!["zip".into()],
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
        if self.schema != "sealr.policy.v1" {
            return Err(unsupported(format!(
                "policy schema {} is unsupported",
                self.schema
            )));
        }
        if self.formats.as_slice() != ["zip"] {
            return Err(unsupported(format!(
                "formats {:?} are unsupported; only [\"zip\"] is implemented",
                self.formats
            )));
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

/// Strict greater-than comparison of uncompressed/compressed against `max_ratio`.
///
/// `uncomp == max_ratio * comp` passes. `comp == 0` is infinite when `uncomp > 0`
/// and passes only when both sides are zero. `max_ratio == 0` is not “off”;
/// disable the check with `None`.
pub fn ratio_exceeds(uncomp: u64, comp: u64, max_ratio: u64) -> bool {
    if comp == 0 {
        return uncomp > 0;
    }
    // The product of two u64 values always fits in u128 exactly.
    let product = u128::from(max_ratio) * u128::from(comp);
    u128::from(uncomp) > product
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
    fn atomic_true_compiles_to_member_sync() {
        let mut policy = Policy::default_v1();
        policy.atomic = true;
        let compiled = policy.compile().unwrap();
        assert!(compiled.effect.member_sync);
    }

    #[test]
    fn ratio_exceeds_table() {
        assert!(!ratio_exceeds(1000, 10, 100));
        assert!(ratio_exceeds(1001, 10, 100));
        assert!(!ratio_exceeds(100, 1, 100));
        assert!(ratio_exceeds(101, 1, 100));
        assert!(!ratio_exceeds(50, 50, 100));
        assert!(ratio_exceeds(51, 50, 1));
        assert!(!ratio_exceeds(0, 0, 100));
        assert!(!ratio_exceeds(0, 1, 100));
        assert!(ratio_exceeds(1, 0, 100));
        assert!(!ratio_exceeds(1, 1, 1));
        assert!(ratio_exceeds(2, 1, 1));
        assert!(!ratio_exceeds(u64::MAX, u64::MAX, 100));
        assert!(ratio_exceeds(u64::MAX, 1, 100));
        let exact_comp = u64::MAX / 100;
        assert!(!ratio_exceeds(
            exact_comp.saturating_mul(100),
            exact_comp,
            100
        ));
        assert!(ratio_exceeds(
            exact_comp.saturating_mul(100).saturating_add(1),
            exact_comp,
            100
        ));
        let mantissa = (1_u64 << 53) + 1;
        assert!(ratio_exceeds(mantissa, 1, 1_u64 << 53));
    }

    #[test]
    fn ratio_exceeds_matches_an_independent_small_domain_oracle() {
        fn oracle(uncomp: u64, comp: u64, max_ratio: u64) -> bool {
            if comp == 0 {
                return uncomp > 0;
            }
            let quotient = uncomp / comp;
            let remainder = uncomp % comp;
            quotient > max_ratio || (quotient == max_ratio && remainder > 0)
        }

        for uncomp in 0..=255 {
            for comp in 0..=64 {
                for max_ratio in 0..=64 {
                    assert_eq!(
                        ratio_exceeds(uncomp, comp, max_ratio),
                        oracle(uncomp, comp, max_ratio),
                        "uncomp={uncomp}, comp={comp}, max_ratio={max_ratio}"
                    );
                }
            }
        }
    }
}
