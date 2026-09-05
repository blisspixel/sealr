//! Exact producer evidence must survive source deletion and native publication.

#[path = "support/wheel_producers.rs"]
mod support;

use serde_json::Value;
use std::{fs, path::PathBuf};

const VECTORS: &[u8] = include_bytes!("conformance/wheel-producers-v1.json");
const REPORT: &[u8] = include_bytes!("conformance/wheel-producers-report-v1.json");

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "sealr-wheel-producers-{}",
            support::digest(&random)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn producer_results_survive_source_deletion_and_native_materialization() {
    let vectors = support::load(VECTORS);
    let report: Value = serde_json::from_slice(REPORT).unwrap();
    assert_eq!(report["schema"], "sealr.wheel-producer-report.v1");
    assert_eq!(report["vectors_sha256"], support::digest(VECTORS));
    let expected = report["fixtures"].as_array().unwrap();
    assert_eq!(expected.len(), vectors.fixtures.len());
    let temp = TestDir::new();
    let mut admitted = 0;
    let mut plan = None;
    for (fixture, pinned) in vectors.fixtures.iter().zip(expected) {
        let source = temp.0.join(&fixture.filename);
        let inspect = support::measure(fixture, Some(&source), None);
        assert_eq!(&inspect, pinned, "{} inspect changed", fixture.id);
        let dest = temp.0.join(&fixture.id);
        let materialized = support::measure(fixture, Some(&source), Some(&dest));
        assert_eq!(
            &materialized, pinned,
            "{} materialization changed",
            fixture.id
        );
        if fixture.expected_outcome == "admitted" {
            admitted += 1;
            assert_eq!(inspect["unicode_members"], 8);
            assert_eq!(inspect["member_count"], 14);
            assert_eq!(
                inspect["descriptor_members"],
                if fixture.id.ends_with("seekable") {
                    0
                } else {
                    14
                }
            );
            if let Some(plan) = &plan {
                assert_eq!(
                    &inspect["plan"], plan,
                    "transport changed the semantic install plan"
                );
            } else {
                plan = Some(inspect["plan"].clone());
            }
        }
    }
    assert_eq!(admitted, 6);
}
