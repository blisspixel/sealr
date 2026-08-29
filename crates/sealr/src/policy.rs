use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
pub use crate::ratio::ratio_exceeds;

pub const POLICY_FORMAT_ZIP: &str = "zip";
pub const POLICY_FORMAT_ZIP64: &str = "zip64";
pub const POLICY_FORMAT_TAR_USTAR: &str = "tar-ustar";
pub const POLICY_FORMAT_TAR_GZIP_USTAR: &str = "tar-gzip-ustar";
pub const POLICY_FORMAT_TAR_PAX: &str = "tar-pax";
pub const POLICY_FORMAT_TAR_GNU_LONGNAME: &str = "tar-gnu-longname";
pub const POLICY_FORMAT_TAR_GZIP_PAX: &str = "tar-gzip-pax";
pub const POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME: &str = "tar-gzip-gnu-longname";
pub const POLICY_FORMAT_TAR_ZSTD_USTAR: &str = "tar-zstd-ustar";
pub const POLICY_FORMAT_TAR_XZ_USTAR: &str = "tar-xz-ustar";
pub const POLICY_FORMAT_TAR_BZIP2_USTAR: &str = "tar-bzip2-ustar";
pub const POLICY_FORMAT_SEVENZ_COPY: &str = "7z-copy";

/// Pre-release Sealr policy, hashed in this struct's deterministic serialized field order.
///
/// This is the caller constructor and receipt-hashed object. Runtime enforcement
/// uses [`Policy::compile`] output, not these fields directly.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Policy {
    pub schema: &'static str,
    pub id: String,
    pub formats: Vec<String>,
    pub max_archive_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_derived_archive_bytes: Option<u64>,
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
    pub max_derived_archive_bytes: u64,
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
            max_derived_archive_bytes: None,
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

    /// Construct the v3 policy, which additionally authorizes strict ZIP64.
    ///
    /// Format selection remains explicit. The policy authorizes interpretation
    /// but does not infer a format from names, extensions, or overlapping magic.
    pub fn default_v3() -> Self {
        Self {
            schema: "sealr.policy.v3",
            id: "sealr:policy/default/v3".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
            ],
            ..Self::default_v1()
        }
    }

    /// Construct the v4 policy, which additionally authorizes strict
    /// single-member gzip-wrapped portable ustar.
    pub fn default_v4() -> Self {
        let max_derived_archive_bytes = 512 * 1024 * 1024;
        Self {
            schema: "sealr.policy.v4",
            id: "sealr:policy/default/v4".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
            ],
            max_derived_archive_bytes: Some(max_derived_archive_bytes),
            ..Self::default_v1()
        }
    }

    /// Construct the v5 policy, which additionally authorizes portable POSIX PAX.
    pub fn default_v5() -> Self {
        Self {
            schema: "sealr.policy.v5",
            id: "sealr:policy/default/v5".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
            ],
            ..Self::default_v4()
        }
    }

    /// Construct the v6 policy, which additionally authorizes the restricted
    /// raw old-GNU long-name profile.
    pub fn default_v6() -> Self {
        Self {
            schema: "sealr.policy.v6",
            id: "sealr:policy/default/v6".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
            ],
            ..Self::default_v5()
        }
    }

    /// Construct the v7 policy, which additionally authorizes gzip-wrapped
    /// restricted PAX and old-GNU long-name TAR archives.
    pub fn default_v7() -> Self {
        Self {
            schema: "sealr.policy.v7",
            id: "sealr:policy/default/v7".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_GZIP_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME.into(),
            ],
            ..Self::default_v6()
        }
    }

    /// Construct the v8 policy, which additionally authorizes zstd-wrapped
    /// portable ustar archives.
    pub fn default_v8() -> Self {
        Self {
            schema: "sealr.policy.v8",
            id: "sealr:policy/default/v8".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_GZIP_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_ZSTD_USTAR.into(),
            ],
            ..Self::default_v7()
        }
    }

    /// Construct the v9 policy, which additionally authorizes xz-wrapped
    /// portable ustar archives.
    pub fn default_v9() -> Self {
        Self {
            schema: "sealr.policy.v9",
            id: "sealr:policy/default/v9".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_GZIP_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_ZSTD_USTAR.into(),
                POLICY_FORMAT_TAR_XZ_USTAR.into(),
            ],
            ..Self::default_v8()
        }
    }

    /// Construct the v10 policy, which additionally authorizes bzip2-wrapped
    /// portable ustar archives.
    pub fn default_v10() -> Self {
        Self {
            schema: "sealr.policy.v10",
            id: "sealr:policy/default/v10".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_GZIP_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_ZSTD_USTAR.into(),
                POLICY_FORMAT_TAR_XZ_USTAR.into(),
                POLICY_FORMAT_TAR_BZIP2_USTAR.into(),
            ],
            ..Self::default_v9()
        }
    }

    /// Construct the v11 policy, which additionally authorizes the restricted
    /// Copy-only 7z container.
    pub fn default_v11() -> Self {
        Self {
            schema: "sealr.policy.v11",
            id: "sealr:policy/default/v11".into(),
            formats: vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_GZIP_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME.into(),
                POLICY_FORMAT_TAR_ZSTD_USTAR.into(),
                POLICY_FORMAT_TAR_XZ_USTAR.into(),
                POLICY_FORMAT_TAR_BZIP2_USTAR.into(),
                POLICY_FORMAT_SEVENZ_COPY.into(),
            ],
            ..Self::default_v10()
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
            "sealr.policy.v3" if valid_v3_formats(&self.formats) => {}
            "sealr.policy.v3" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\"]",
                    self.formats
                )));
            }
            "sealr.policy.v4" if valid_v4_formats(&self.formats) => {}
            "sealr.policy.v4" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\"]",
                    self.formats
                )));
            }
            "sealr.policy.v5" if valid_v5_formats(&self.formats) => {}
            "sealr.policy.v5" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\"]",
                    self.formats
                )));
            }
            "sealr.policy.v6" if valid_v6_formats(&self.formats) => {}
            "sealr.policy.v6" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\"]",
                    self.formats
                )));
            }
            "sealr.policy.v7" if valid_v7_formats(&self.formats) => {}
            "sealr.policy.v7" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\", \"tar-gzip-pax\", \"tar-gzip-gnu-longname\"]",
                    self.formats
                )));
            }
            "sealr.policy.v8" if valid_v8_formats(&self.formats) => {}
            "sealr.policy.v8" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\", \"tar-gzip-pax\", \"tar-gzip-gnu-longname\", \"tar-zstd-ustar\"]",
                    self.formats
                )));
            }
            "sealr.policy.v9" if valid_v9_formats(&self.formats) => {}
            "sealr.policy.v9" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\", \"tar-gzip-pax\", \"tar-gzip-gnu-longname\", \"tar-zstd-ustar\", \"tar-xz-ustar\"]",
                    self.formats
                )));
            }
            "sealr.policy.v11" if valid_v11_formats(&self.formats) => {}
            "sealr.policy.v11" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\", \"tar-gzip-pax\", \"tar-gzip-gnu-longname\", \"tar-zstd-ustar\", \"tar-xz-ustar\", \"tar-bzip2-ustar\", \"7z-copy\"]",
                    self.formats
                )));
            }
            "sealr.policy.v10" if valid_v10_formats(&self.formats) => {}
            "sealr.policy.v10" => {
                return Err(unsupported(format!(
                    "formats {:?} are not a canonical nonempty subset of [\"zip\", \"zip64\", \"tar-ustar\", \"tar-gzip-ustar\", \"tar-pax\", \"tar-gnu-longname\", \"tar-gzip-pax\", \"tar-gzip-gnu-longname\", \"tar-zstd-ustar\", \"tar-xz-ustar\", \"tar-bzip2-ustar\"]",
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
        if matches!(
            self.schema,
            "sealr.policy.v2"
                | "sealr.policy.v3"
                | "sealr.policy.v4"
                | "sealr.policy.v5"
                | "sealr.policy.v6"
                | "sealr.policy.v7"
                | "sealr.policy.v8"
                | "sealr.policy.v9"
                | "sealr.policy.v10"
                | "sealr.policy.v11"
        ) && self.max_files > u64::from(u32::MAX)
        {
            return Err(unsupported(format!(
                "max_files={} exceeds the u32 identity-encoding limit",
                self.max_files
            )));
        }
        match (self.schema, self.max_derived_archive_bytes) {
            (
                "sealr.policy.v4" | "sealr.policy.v5" | "sealr.policy.v6" | "sealr.policy.v7"
                | "sealr.policy.v8" | "sealr.policy.v9" | "sealr.policy.v10" | "sealr.policy.v11",
                Some(_),
            ) => {}
            (
                "sealr.policy.v4" | "sealr.policy.v5" | "sealr.policy.v6" | "sealr.policy.v7"
                | "sealr.policy.v8" | "sealr.policy.v9" | "sealr.policy.v10" | "sealr.policy.v11",
                None,
            ) => {
                return Err(unsupported(format!(
                    "{} requires an explicit max_derived_archive_bytes cap",
                    self.schema
                )));
            }
            (_, None) => {}
            (_, Some(value)) => {
                return Err(unsupported(format!(
                    "max_derived_archive_bytes={value} is only supported by sealr.policy.v4 through sealr.policy.v11"
                )));
            }
        }

        Ok(CompiledControls {
            budget: ResourceBudget {
                max_archive_bytes: self.max_archive_bytes,
                max_derived_archive_bytes: self.max_derived_archive_bytes.unwrap_or(0),
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
    valid_canonical_subset(formats, &[POLICY_FORMAT_ZIP, POLICY_FORMAT_TAR_USTAR])
}

fn valid_v3_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
        ],
    )
}

fn valid_v4_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
        ],
    )
}

fn valid_v5_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
        ],
    )
}

fn valid_v6_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
        ],
    )
}

fn valid_v7_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
        ],
    )
}

fn valid_v8_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
        ],
    )
}

fn valid_v9_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
        ],
    )
}

fn valid_v10_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
            POLICY_FORMAT_TAR_BZIP2_USTAR,
        ],
    )
}

fn valid_v11_formats(formats: &[String]) -> bool {
    valid_canonical_subset(
        formats,
        &[
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
            POLICY_FORMAT_TAR_BZIP2_USTAR,
            POLICY_FORMAT_SEVENZ_COPY,
        ],
    )
}

fn valid_canonical_subset(formats: &[String], canonical: &[&str]) -> bool {
    if formats.is_empty() {
        return false;
    }

    let mut next = 0;
    for format in formats {
        let Some(relative_index) = canonical[next..]
            .iter()
            .position(|candidate| *candidate == format)
        else {
            return false;
        };
        next += relative_index + 1;
    }
    true
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

/// Largest integer magnitude the canonical evidence domain admits: 2^53 - 1.
///
/// This mirrors the bound in the evidence encoding contract so every validated
/// policy value is exactly representable as an IEEE-754 double in any future
/// canonical-JSON lineage.
const MAX_DOUBLE_SAFE_INTEGER: u64 = (1 << 53) - 1;

const KNOWN_POLICY_SCHEMAS: [&str; 11] = [
    "sealr.policy.v1",
    "sealr.policy.v2",
    "sealr.policy.v3",
    "sealr.policy.v4",
    "sealr.policy.v5",
    "sealr.policy.v6",
    "sealr.policy.v7",
    "sealr.policy.v8",
    "sealr.policy.v9",
    "sealr.policy.v10",
    "sealr.policy.v11",
];

fn static_schema(schema: &str) -> Result<&'static str, Finding> {
    KNOWN_POLICY_SCHEMAS
        .iter()
        .find(|known| **known == schema)
        .copied()
        .ok_or_else(|| unsupported(format!("policy schema {schema:?} is not a known version")))
}

fn static_vocabulary(field: &'static str, value: &str) -> Result<&'static str, Finding> {
    let token = match (field, value) {
        ("symlinks", "deny")
        | ("hardlinks", "deny")
        | ("ambiguity", "deny")
        | ("case_fold_collision", "deny")
        | ("magic_vs_extension", "deny")
        | ("encrypted", "deny") => Some("deny"),
        ("overwrite", "refuse") => Some("refuse"),
        ("setuid", "strip") => Some("strip"),
        _ => None,
    };
    token.ok_or_else(|| {
        unsupported(format!(
            "policy {field} value {value:?} is outside the supported vocabulary"
        ))
    })
}

/// Caller-authored policy data exactly as parsed from JSON, before any
/// validation. This is the only deserializable policy shape: unknown fields
/// are rejected, every field is required except the one field the canonical
/// encoding makes conditional, and nothing here is usable for admission until
/// [`PolicyDocument::validate`] proves it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema: String,
    pub id: String,
    pub formats: Vec<String>,
    pub max_archive_bytes: u64,
    #[serde(default)]
    pub max_derived_archive_bytes: Option<u64>,
    pub max_files: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: Option<u64>,
    pub max_path_depth: u32,
    pub max_metadata_bytes: u64,
    pub max_dict_bytes: u64,
    pub symlinks: String,
    pub hardlinks: String,
    pub overwrite: String,
    pub setuid: String,
    pub nested_depth: u32,
    pub ambiguity: String,
    pub case_fold_collision: String,
    pub magic_vs_extension: String,
    pub encrypted: String,
    pub atomic: bool,
}

impl PolicyDocument {
    /// Validate the document into a policy whose validity and digest are
    /// proven, or fail closed with a typed finding.
    ///
    /// Validation maps every string field onto the exact supported vocabulary,
    /// reconstructs the canonical [`Policy`], proves it compiles, and bounds
    /// every cap to the double-safe integer ceiling. The resulting digest is
    /// the canonical policy digest: a document that used non-canonical JSON
    /// spelling (for example an explicit `null` for the conditional field)
    /// still validates to the same canonical policy and digest.
    pub fn validate(self) -> Result<ValidatedPolicy, Finding> {
        let policy = Policy {
            schema: static_schema(&self.schema)?,
            id: self.id,
            formats: self.formats,
            max_archive_bytes: self.max_archive_bytes,
            max_derived_archive_bytes: self.max_derived_archive_bytes,
            max_files: self.max_files,
            max_member_bytes: self.max_member_bytes,
            max_total_bytes: self.max_total_bytes,
            max_ratio: self.max_ratio,
            max_path_depth: self.max_path_depth,
            max_metadata_bytes: self.max_metadata_bytes,
            max_dict_bytes: self.max_dict_bytes,
            symlinks: static_vocabulary("symlinks", &self.symlinks)?,
            hardlinks: static_vocabulary("hardlinks", &self.hardlinks)?,
            overwrite: static_vocabulary("overwrite", &self.overwrite)?,
            setuid: static_vocabulary("setuid", &self.setuid)?,
            nested_depth: self.nested_depth,
            ambiguity: static_vocabulary("ambiguity", &self.ambiguity)?,
            case_fold_collision: static_vocabulary(
                "case_fold_collision",
                &self.case_fold_collision,
            )?,
            magic_vs_extension: static_vocabulary("magic_vs_extension", &self.magic_vs_extension)?,
            encrypted: static_vocabulary("encrypted", &self.encrypted)?,
            atomic: self.atomic,
        };
        ValidatedPolicy::new(policy)
    }
}

/// A policy whose compilability and digest are proven at construction.
///
/// Nothing prevents digesting an arbitrary [`Policy`]; this type does. A
/// `ValidatedPolicy` exists only if the wrapped policy compiles and every cap
/// is within the double-safe integer ceiling, and its memoized digest is the
/// canonical policy digest.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedPolicy {
    policy: Policy,
    digest: String,
}

impl ValidatedPolicy {
    /// Prove `policy` compiles and is canonically representable, or fail
    /// closed with a typed finding.
    pub fn new(policy: Policy) -> Result<Self, Finding> {
        policy.compile()?;
        for (field, value) in [
            ("max_archive_bytes", Some(policy.max_archive_bytes)),
            (
                "max_derived_archive_bytes",
                policy.max_derived_archive_bytes,
            ),
            ("max_files", Some(policy.max_files)),
            ("max_member_bytes", Some(policy.max_member_bytes)),
            ("max_total_bytes", Some(policy.max_total_bytes)),
            ("max_ratio", policy.max_ratio),
            ("max_metadata_bytes", Some(policy.max_metadata_bytes)),
            ("max_dict_bytes", Some(policy.max_dict_bytes)),
        ] {
            if let Some(value) = value {
                if value > MAX_DOUBLE_SAFE_INTEGER {
                    return Err(unsupported(format!(
                        "policy {field} value {value} exceeds the 2^53-1 double-safe ceiling"
                    )));
                }
            }
        }
        let digest = policy.digest_hex();
        Ok(Self { policy, digest })
    }

    /// The proven policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The memoized canonical policy digest.
    pub fn digest_hex(&self) -> &str {
        &self.digest
    }

    /// Unwrap the proven policy.
    pub fn into_policy(self) -> Policy {
        self.policy
    }
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_V1_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v1","id":"sealr:policy/default/v1","formats":["zip"],"#,
        r#""max_archive_bytes":536870912,"max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V2_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v2","id":"sealr:policy/default/v2","#,
        r#""formats":["zip","tar-ustar"],"max_archive_bytes":536870912,"max_files":10000,"#,
        r#""max_member_bytes":1073741824,"max_total_bytes":5368709120,"max_ratio":100,"#,
        r#""max_path_depth":32,"max_metadata_bytes":4194304,"max_dict_bytes":67108864,"#,
        r#""symlinks":"deny","hardlinks":"deny","overwrite":"refuse","setuid":"strip","#,
        r#""nested_depth":1,"ambiguity":"deny","case_fold_collision":"deny","#,
        r#""magic_vs_extension":"deny","encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V3_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v3","id":"sealr:policy/default/v3","#,
        r#""formats":["zip","zip64","tar-ustar"],"max_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"max_total_bytes":5368709120,"#,
        r#""max_ratio":100,"max_path_depth":32,"max_metadata_bytes":4194304,"#,
        r#""max_dict_bytes":67108864,"symlinks":"deny","hardlinks":"deny","#,
        r#""overwrite":"refuse","setuid":"strip","nested_depth":1,"ambiguity":"deny","#,
        r#""case_fold_collision":"deny","magic_vs_extension":"deny","encrypted":"deny","#,
        r#""atomic":false}"#,
    );

    const DEFAULT_V4_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v4","id":"sealr:policy/default/v4","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V5_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v5","id":"sealr:policy/default/v5","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V6_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v6","id":"sealr:policy/default/v6","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","tar-gnu-longname"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V7_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v7","id":"sealr:policy/default/v7","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","#,
        r#""tar-gnu-longname","tar-gzip-pax","tar-gzip-gnu-longname"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V9_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v9","id":"sealr:policy/default/v9","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","#,
        r#""tar-gnu-longname","tar-gzip-pax","tar-gzip-gnu-longname","tar-zstd-ustar","#,
        r#""tar-xz-ustar"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V10_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v10","id":"sealr:policy/default/v10","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","#,
        r#""tar-gnu-longname","tar-gzip-pax","tar-gzip-gnu-longname","tar-zstd-ustar","#,
        r#""tar-xz-ustar","tar-bzip2-ustar"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V11_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v11","id":"sealr:policy/default/v11","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","#,
        r#""tar-gnu-longname","tar-gzip-pax","tar-gzip-gnu-longname","tar-zstd-ustar","#,
        r#""tar-xz-ustar","tar-bzip2-ustar","7z-copy"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

    const DEFAULT_V8_JSON: &str = concat!(
        r#"{"schema":"sealr.policy.v8","id":"sealr:policy/default/v8","#,
        r#""formats":["zip","zip64","tar-ustar","tar-gzip-ustar","tar-pax","#,
        r#""tar-gnu-longname","tar-gzip-pax","tar-gzip-gnu-longname","tar-zstd-ustar"],"#,
        r#""max_archive_bytes":536870912,"max_derived_archive_bytes":536870912,"#,
        r#""max_files":10000,"max_member_bytes":1073741824,"#,
        r#""max_total_bytes":5368709120,"max_ratio":100,"max_path_depth":32,"#,
        r#""max_metadata_bytes":4194304,"max_dict_bytes":67108864,"symlinks":"deny","#,
        r#""hardlinks":"deny","overwrite":"refuse","setuid":"strip","nested_depth":1,"#,
        r#""ambiguity":"deny","case_fold_collision":"deny","magic_vs_extension":"deny","#,
        r#""encrypted":"deny","atomic":false}"#,
    );

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
    fn zip64_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v3().digest_hex(),
            "2cc96c7a2dd83617b3c80df7ec5ae7e4b92f74b0b391d70aa73f54f3f82068bd"
        );
    }

    #[test]
    fn tar_gzip_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v4().digest_hex(),
            "ecfca685a8f05c63fd12b7fd1c183a90a3fa705f801493fa4cb003cd57f1d601"
        );
    }

    #[test]
    fn tar_pax_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v5().digest_hex(),
            "d1268c72f284f8f1b7ce5e06ada17ef7cbbbc5768a876ee93d103ad21e77d019"
        );
    }

    #[test]
    fn tar_gnu_longname_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v6().digest_hex(),
            "aefc8a1baa113d7face30857ef64fe8f47c647fae863a72810b80380f8fd4178"
        );
    }

    #[test]
    fn tar_gzip_compositions_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v7().digest_hex(),
            "92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef"
        );
    }

    #[test]
    fn tar_zstd_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v8().digest_hex(),
            "d0cfdf4d40e3a88c8e80170494b23e91761802304265e41ce19cb616fa8a1c42"
        );
    }

    #[test]
    fn tar_xz_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v9().digest_hex(),
            "c512895c09453f16c07ebeae94712099191b197ba9edaae384dba0fe7bb8b39e"
        );
    }

    #[test]
    fn tar_bzip2_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v10().digest_hex(),
            "eada8150e14c0f05dcb25b6c9a90b87d3821fbb5f754192aceaea6d942e9f374"
        );
    }

    #[test]
    fn sevenz_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v11().digest_hex(),
            "afa0aeb04ceca00706b31dfd250216a87f2af0ada6e98d3815873de0d15172fc"
        );
    }

    #[test]
    fn every_default_policy_round_trips_through_the_document_to_the_same_bytes() {
        for policy in [
            Policy::default_v1(),
            Policy::default_v2(),
            Policy::default_v3(),
            Policy::default_v4(),
            Policy::default_v5(),
            Policy::default_v6(),
            Policy::default_v7(),
            Policy::default_v8(),
            Policy::default_v9(),
            Policy::default_v10(),
            Policy::default_v11(),
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let document: PolicyDocument = serde_json::from_str(&json).unwrap();
            let validated = document.validate().unwrap();
            assert_eq!(
                validated.digest_hex(),
                policy.digest_hex(),
                "{}: validated digest must equal the pinned digest",
                policy.id
            );
            assert_eq!(
                serde_json::to_string(validated.policy()).unwrap(),
                json,
                "{}: reconstruction must be byte-identical",
                policy.id
            );
        }
    }

    #[test]
    fn documents_with_unknown_fields_do_not_deserialize() {
        let mut value = serde_json::to_value(Policy::default_v1()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("insecure".into(), serde_json::json!(true));
        let error = serde_json::from_value::<PolicyDocument>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn unknown_schemas_and_vocabulary_fail_closed_as_unsupported() {
        let json = serde_json::to_string(&Policy::default_v1()).unwrap();

        let mut document: PolicyDocument = serde_json::from_str(&json).unwrap();
        document.schema = "sealr.policy.v99".into();
        assert_eq!(
            document.validate().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );

        let mut document: PolicyDocument = serde_json::from_str(&json).unwrap();
        document.symlinks = "allow".into();
        let finding = document.validate().unwrap_err();
        assert_eq!(finding.code, FindingCode::PolicyUnsupported);
        assert!(finding.detail.contains("symlinks"), "{}", finding.detail);
    }

    #[test]
    fn caps_above_the_double_safe_ceiling_fail_closed() {
        let json = serde_json::to_string(&Policy::default_v1()).unwrap();
        let mut document: PolicyDocument = serde_json::from_str(&json).unwrap();
        document.max_total_bytes = 1 << 53;
        let finding = document.validate().unwrap_err();
        assert_eq!(finding.code, FindingCode::PolicyUnsupported);
        assert!(finding.detail.contains("double-safe"), "{}", finding.detail);
    }

    #[test]
    fn an_explicit_null_conditional_field_validates_to_the_canonical_policy() {
        let mut value = serde_json::to_value(Policy::default_v1()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("max_derived_archive_bytes".into(), serde_json::Value::Null);
        let document: PolicyDocument = serde_json::from_value(value).unwrap();
        let validated = document.validate().unwrap();
        assert_eq!(validated.digest_hex(), Policy::default_v1().digest_hex());
    }

    #[test]
    fn an_uncompilable_policy_cannot_become_validated() {
        let mut policy = Policy::default_v1();
        policy.max_dict_bytes = 1;
        assert_eq!(
            ValidatedPolicy::new(policy).unwrap_err().code,
            FindingCode::PolicyUnsupported
        );

        let mut policy = Policy::default_v1();
        policy.formats = vec!["7z-copy".into()];
        assert_eq!(
            ValidatedPolicy::new(policy).unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn default_policy_serializations_are_stable() {
        assert_eq!(
            serde_json::to_string(&Policy::default_v1()).unwrap(),
            DEFAULT_V1_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v2()).unwrap(),
            DEFAULT_V2_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v3()).unwrap(),
            DEFAULT_V3_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v4()).unwrap(),
            DEFAULT_V4_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v5()).unwrap(),
            DEFAULT_V5_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v6()).unwrap(),
            DEFAULT_V6_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v7()).unwrap(),
            DEFAULT_V7_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v8()).unwrap(),
            DEFAULT_V8_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v9()).unwrap(),
            DEFAULT_V9_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v10()).unwrap(),
            DEFAULT_V10_JSON
        );
        assert_eq!(
            serde_json::to_string(&Policy::default_v11()).unwrap(),
            DEFAULT_V11_JSON
        );
    }

    #[test]
    fn default_policy_compiles() {
        let v1 = Policy::default_v1().compile().expect("default compiles");
        assert_eq!(v1.budget.max_ratio, Some(100));
        assert!(!v1.effect.member_sync);
        assert_eq!(v1.target, TargetModel::PortableV1);

        let v3 = Policy::default_v3().compile().expect("v3 default compiles");
        assert_eq!(v3, v1, "v3 preserves all compiled controls and limits");

        let v4 = Policy::default_v4().compile().expect("v4 default compiles");
        assert_eq!(v4.budget.max_derived_archive_bytes, 512 * 1024 * 1024);

        let v5 = Policy::default_v5().compile().expect("v5 default compiles");
        assert_eq!(v5, v4, "v5 preserves all compiled controls and limits");

        let v6 = Policy::default_v6().compile().expect("v6 default compiles");
        assert_eq!(v6, v5, "v6 preserves all compiled controls and limits");
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
        assert!(Policy::default_v3()
            .compile_for_format(POLICY_FORMAT_ZIP64)
            .is_ok());
        assert_eq!(
            Policy::default_v2()
                .compile_for_format(POLICY_FORMAT_ZIP64)
                .unwrap_err()
                .code,
            FindingCode::PolicyUnsupported
        );
        assert!(Policy::default_v5()
            .compile_for_format(POLICY_FORMAT_TAR_PAX)
            .is_ok());
        assert!(Policy::default_v6()
            .compile_for_format(POLICY_FORMAT_TAR_GNU_LONGNAME)
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
    fn zip64_policy_accepts_every_canonical_nonempty_subset() {
        for formats in [
            vec![POLICY_FORMAT_ZIP.into()],
            vec![POLICY_FORMAT_ZIP64.into()],
            vec![POLICY_FORMAT_TAR_USTAR.into()],
            vec![POLICY_FORMAT_ZIP.into(), POLICY_FORMAT_ZIP64.into()],
            vec![POLICY_FORMAT_ZIP.into(), POLICY_FORMAT_TAR_USTAR.into()],
            vec![POLICY_FORMAT_ZIP64.into(), POLICY_FORMAT_TAR_USTAR.into()],
            vec![
                POLICY_FORMAT_ZIP.into(),
                POLICY_FORMAT_ZIP64.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
            ],
        ] {
            let mut policy = Policy::default_v3();
            policy.formats = formats;
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn zip64_policy_rejects_empty_reordered_duplicate_and_unknown_formats() {
        for formats in [
            Vec::new(),
            vec![POLICY_FORMAT_ZIP64.into(), POLICY_FORMAT_ZIP.into()],
            vec![POLICY_FORMAT_TAR_USTAR.into(), POLICY_FORMAT_ZIP64.into()],
            vec![POLICY_FORMAT_ZIP64.into(), POLICY_FORMAT_ZIP64.into()],
            vec![POLICY_FORMAT_ZIP.into(), "7z".into()],
        ] {
            let mut policy = Policy::default_v3();
            policy.formats = formats;
            assert_eq!(
                policy.compile().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }
    }

    #[test]
    fn tar_gzip_policy_requires_canonical_formats_and_an_explicit_derived_cap() {
        for formats in [
            Vec::new(),
            vec![
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_USTAR.into(),
            ],
            vec![
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
            ],
            vec![POLICY_FORMAT_ZIP.into(), "7z".into()],
        ] {
            let mut policy = Policy::default_v4();
            policy.formats = formats;
            assert_eq!(
                policy.compile().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }

        let mut missing = Policy::default_v4();
        missing.max_derived_archive_bytes = None;
        assert_eq!(
            missing.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );

        let mut old_schema = Policy::default_v3();
        old_schema.max_derived_archive_bytes = Some(1);
        assert_eq!(
            old_schema.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn tar_pax_policy_requires_canonical_formats_and_an_explicit_derived_cap() {
        for formats in [
            Vec::new(),
            vec![
                POLICY_FORMAT_TAR_PAX.into(),
                POLICY_FORMAT_TAR_GZIP_USTAR.into(),
            ],
            vec![POLICY_FORMAT_TAR_PAX.into(), POLICY_FORMAT_TAR_PAX.into()],
            vec![POLICY_FORMAT_ZIP.into(), "7z".into()],
        ] {
            let mut policy = Policy::default_v5();
            policy.formats = formats;
            assert_eq!(
                policy.compile().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }

        let mut missing = Policy::default_v5();
        missing.max_derived_archive_bytes = None;
        assert_eq!(
            missing.compile().unwrap_err().code,
            FindingCode::PolicyUnsupported
        );
    }

    #[test]
    fn tar_pax_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
        ];
        for mask in 1_u8..(1_u8 << canonical.len()) {
            let mut policy = Policy::default_v5();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u8 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn tar_gnu_longname_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
        ];
        for mask in 1_u8..(1_u8 << canonical.len()) {
            let mut policy = Policy::default_v6();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u8 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn tar_gzip_compositions_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
        ];
        for mask in 1_u16..(1_u16 << canonical.len()) {
            let mut policy = Policy::default_v7();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u16 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn tar_xz_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
        ];
        for mask in 1_u16..(1_u16 << canonical.len()) {
            let mut policy = Policy::default_v9();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u16 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn sevenz_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
            POLICY_FORMAT_TAR_BZIP2_USTAR,
            POLICY_FORMAT_SEVENZ_COPY,
        ];
        for mask in 1_u16..(1_u16 << canonical.len()) {
            let mut policy = Policy::default_v11();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u16 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn tar_bzip2_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
            POLICY_FORMAT_TAR_XZ_USTAR,
            POLICY_FORMAT_TAR_BZIP2_USTAR,
        ];
        for mask in 1_u16..(1_u16 << canonical.len()) {
            let mut policy = Policy::default_v10();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u16 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
        }
    }

    #[test]
    fn tar_zstd_policy_accepts_every_canonical_nonempty_subset() {
        let canonical = [
            POLICY_FORMAT_ZIP,
            POLICY_FORMAT_ZIP64,
            POLICY_FORMAT_TAR_USTAR,
            POLICY_FORMAT_TAR_GZIP_USTAR,
            POLICY_FORMAT_TAR_PAX,
            POLICY_FORMAT_TAR_GNU_LONGNAME,
            POLICY_FORMAT_TAR_GZIP_PAX,
            POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME,
            POLICY_FORMAT_TAR_ZSTD_USTAR,
        ];
        for mask in 1_u16..(1_u16 << canonical.len()) {
            let mut policy = Policy::default_v8();
            policy.formats = canonical
                .iter()
                .enumerate()
                .filter_map(|(index, format)| {
                    (mask & (1_u16 << index) != 0).then_some((*format).to_owned())
                })
                .collect();
            policy.compile().expect("canonical subset compiles");
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
        for mut policy in [
            Policy::default_v2(),
            Policy::default_v3(),
            Policy::default_v4(),
            Policy::default_v5(),
            Policy::default_v6(),
            Policy::default_v7(),
            Policy::default_v8(),
            Policy::default_v9(),
            Policy::default_v10(),
            Policy::default_v11(),
        ] {
            policy.max_files = u64::from(u32::MAX) + 1;
            assert_eq!(
                policy.compile().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }
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
