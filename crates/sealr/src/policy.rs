use serde::Serialize;
use sha2::{Digest, Sha256};

/// Pre-release `sealr.policy.v1`, hashed in this struct's deterministic serialized field order.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Policy {
    pub schema: &'static str,
    pub id: String,
    pub formats: Vec<String>,
    pub max_archive_bytes: u64,
    pub max_files: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: Option<f64>,
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
            max_ratio: Some(100.0),
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
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::Policy;

    #[test]
    fn default_policy_digest_is_stable() {
        assert_eq!(
            Policy::default_v1().digest_hex(),
            "371ad96417cf53ec84d6265759c30199f9c72437e49a960d5d2e07128d14aae7"
        );
    }
}
