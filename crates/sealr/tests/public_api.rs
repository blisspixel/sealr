//! Downstream-facing compile and behavior fixture for the intended public API.

use sealr::{
    apply, EnvMeta, MaterializationMeta, Outcome, OutcomeIdentities, Policy, PolicyMeta, Receipt,
    Request, SnapshotKind, Source, SourceMeta, ToolMeta, View,
};

const EMPTY_ZIP: &[u8] = &[
    0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn assert_public_output_types(outcome: &Outcome) {
    let _: &View = &outcome.view;
    let _: &Receipt = &outcome.receipt;
    let _: &SourceMeta = &outcome.view.source;
    let _: &PolicyMeta = &outcome.view.policy;
    let _: &ToolMeta = &outcome.receipt.tool;
    let _: &EnvMeta = &outcome.receipt.environment;
    let _: &MaterializationMeta = &outcome.receipt.materialization;
    let _: &OutcomeIdentities = &outcome.receipt.identities;
    let _: SnapshotKind = outcome.receipt.source_snapshot;
}

#[test]
fn intended_receipt_and_view_types_are_nameable_downstream() {
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("empty.zip"),
            data: EMPTY_ZIP,
        },
        policy: &policy,
        dest: None,
    });

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_public_output_types(&outcome);
}
