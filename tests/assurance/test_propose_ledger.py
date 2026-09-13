"""Offline fixtures for local, nonpromoting assurance ledger proposals."""

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_collect_history import HistoryFixture, MODULE as HISTORY


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("propose_ledger", ROOT / "scripts/propose_assurance_ledger.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def report_for(fixture):
    report = fixture.finish().collect()
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    report["observed_at"] = start.isoformat()
    for check in report["checks"]:
        for index, observation in enumerate(check["observations"], 1):
            observation["observed_at"] = (start + timedelta(seconds=index)).isoformat()
    return report


class ProposeLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealr-ledger-proposal-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True, capture_output=True)
        self.fixture = HistoryFixture()
        self.fixture.add_run(1)
        self.report = report_for(self.fixture)
        for name, content in self.fixture.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def ledger(self):
        return json.loads((self.root / HISTORY.LEDGER).read_text(encoding="utf-8"))

    def save_ledger(self, ledger):
        (self.root / HISTORY.LEDGER).write_text(json.dumps(ledger), encoding="utf-8")

    def test_valid_report_proposes_history_without_changing_active_ledger(self):
        before = (self.root / HISTORY.LEDGER).read_bytes()
        proposal = MODULE.propose(self.root, self.report)
        self.assertEqual(proposal["checks"][0]["stable_main_runs"][0]["run_id"], 1)
        self.assertEqual((self.root / HISTORY.LEDGER).read_bytes(), before)
        self.assertTrue(all(not check["promoted"] for check in proposal["checks"]))

    def test_all_governance_fields_are_preserved(self):
        ledger = self.ledger()
        ledger["additional_governance"] = {"preserve": [1, 2, 3]}
        self.save_ledger(ledger)
        proposal = MODULE.propose(self.root, self.report)
        self.assertEqual(proposal["additional_governance"], ledger["additional_governance"])
        for old, new in zip(ledger["checks"], proposal["checks"]):
            for key, value in old.items():
                if key not in ("stable_main_runs", "eligible"):
                    self.assertEqual(new[key], value)

    def test_ready_history_does_not_promote_but_existing_promotion_is_preserved(self):
        fixture = HistoryFixture()
        for index in range(1, 11):
            fixture.add_run(index)
        report = report_for(fixture)
        proposal = MODULE.propose(self.root, report)
        self.assertTrue(proposal["checks"][0]["eligible"])
        self.assertFalse(proposal["checks"][0]["promoted"])
        ledger = self.ledger()
        ledger["checks"][0]["promoted"] = True
        self.save_ledger(ledger)
        self.assertTrue(MODULE.propose(self.root, report)["checks"][0]["promoted"])

    def test_ineligible_existing_promotion_requires_separate_demotion(self):
        ledger = self.ledger()
        ledger["checks"][0]["promoted"] = True
        self.save_ledger(ledger)
        with self.assertRaisesRegex(MODULE.Incomplete, "separate CI demotion"):
            MODULE.propose(self.root, self.report)

    def test_stale_report_fingerprint_and_modified_actual_source_are_rejected(self):
        bad = copy.deepcopy(self.report)
        bad["checks"][0]["current_domain_fingerprint"] = "f" * 64
        with self.assertRaisesRegex(MODULE.Incomplete, "stale evidence domain"):
            MODULE.propose(self.root, bad)
        path = self.root / "verification/kani/src/lib.rs"
        path.write_bytes(b"a changed proof domain\n")
        with self.assertRaisesRegex(MODULE.Incomplete, "stale evidence domain"):
            MODULE.propose(self.root, self.report)

    def test_untracked_evidence_files_are_included(self):
        path = self.root / "fuzz/fuzz_targets/new_domain.rs"
        path.write_bytes(b"untracked source must affect the domain\n")
        with self.assertRaisesRegex(MODULE.Incomplete, "stale evidence domain"):
            MODULE.propose(self.root, self.report)

    def test_ignored_build_outputs_do_not_change_the_evidence_domain(self):
        (self.root / ".gitignore").write_text("/fuzz/target\n", encoding="utf-8")
        target = self.root / "fuzz/target/build.out"
        target.parent.mkdir()
        target.write_bytes(b"generated output")
        MODULE.propose(self.root, self.report)

    def test_incomplete_and_nonobject_reports_are_rejected(self):
        for report in (None, [], {**self.report, "status": "incomplete"}):
            with self.assertRaises(MODULE.Incomplete):
                MODULE.propose(self.root, report)

    def test_closed_category_identity_and_promotability_are_checked(self):
        changes = ({"category": "mutation-discovery"}, {"check_id": "other.v1"},
                   {"promotable": False}, {"promoted": True}, {"status": "incomplete"})
        for change in changes:
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                report["checks"][0].update(change)
                with self.assertRaises(MODULE.Incomplete):
                    MODULE.propose(self.root, report)

    def test_summary_cannot_claim_unobserved_runs(self):
        report = copy.deepcopy(self.report)
        report["checks"][0]["consecutive_successful_distinct_commits"] = 10
        report["checks"][0]["qualifying_run_ids"] = list(range(1, 11))
        with self.assertRaisesRegex(MODULE.Incomplete, "summary mismatch"):
            MODULE.propose(self.root, report)

    def test_failed_or_retried_attempt_cannot_remain_counted(self):
        for change in ({"latest_attempt": 2}, {"checked_attempt": 2},
                       {"original_conclusion": "failure"}, {"latest_conclusion": "failure"}):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                report["checks"][0]["observations"][0].update(change)
                with self.assertRaises(MODULE.Incomplete):
                    MODULE.propose(self.root, report)

    def test_duplicate_ids_and_duplicate_counted_commits_are_rejected(self):
        for same_id in (True, False):
            with self.subTest(same_id=same_id):
                report = copy.deepcopy(self.report)
                record = report["checks"][0]
                later = copy.deepcopy(record["observations"][0])
                if not same_id:
                    later["run_id"] = 2
                    later["url"] = "https://github.com/blisspixel/sealr/actions/runs/2"
                    later["created_at"] = "2026-09-02T09:00:00Z"
                    later["observed_at"] = (HISTORY.timestamp(later["observed_at"]) + timedelta(microseconds=1)).isoformat()
                record["observations"].append(later)
                with self.assertRaises(MODULE.Incomplete):
                    MODULE.propose(self.root, report)

    def test_success_requires_the_exact_successful_job_set(self):
        for change in ({"name": "wrong job"}, {"conclusion": "failure"}, {"status": "in_progress"}):
            report = copy.deepcopy(self.report)
            report["checks"][0]["observations"][0]["jobs"][0].update(change)
            with self.assertRaises(MODULE.Incomplete):
                MODULE.propose(self.root, report)

    def test_observation_bindings_and_times_are_checked(self):
        changes = ({"branch": "topic"}, {"event": "workflow_dispatch"}, {"url": "https://example.com/run"},
                   {"observed_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()})
        for change in changes:
            report = copy.deepcopy(self.report)
            report["checks"][0]["observations"][0].update(change)
            with self.assertRaises(MODULE.Incomplete):
                MODULE.propose(self.root, report)

    def test_legacy_same_second_observations_cannot_produce_an_invalid_ledger(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        fixture.add_run(2)
        report = report_for(fixture)
        observations = report["checks"][0]["observations"]
        first = HISTORY.timestamp(observations[0]["observed_at"])
        observations[1]["observed_at"] = first.replace(microsecond=999999).isoformat()
        with self.assertRaisesRegex(MODULE.Incomplete, "distinct increasing seconds"):
            MODULE.propose(self.root, report)

    def test_documented_failure_reset_can_clear_unpromoted_history(self):
        report = copy.deepcopy(self.report)
        record = report["checks"][0]
        record["observations"][0].update(original_conclusion="failure", latest_conclusion="failure", decision="unsuccessful_run")
        record["consecutive_successful_distinct_commits"] = 0
        record["qualifying_run_ids"] = []
        self.assertEqual(MODULE.propose(self.root, report)["checks"][0]["stable_main_runs"], [])

    def test_precontract_and_changed_domain_boundaries_reset_history(self):
        for missing_contract in (True, False):
            fixture = HistoryFixture()
            old = fixture.add_run(1)
            overrides = {HISTORY.LEDGER: None} if missing_contract else {"verification/kani/src/lib.rs": b"older domain"}
            fixture.add_revision(old["head_sha"], overrides)
            fixture.add_run(2)
            proposal = MODULE.propose(self.root, report_for(fixture))
            self.assertEqual([row["run_id"] for row in proposal["checks"][0]["stable_main_runs"]], [2])

    def test_output_cannot_overwrite_the_active_ledger_or_input_report(self):
        report_path = self.root / "report.json"
        report_path.write_text(json.dumps(self.report), encoding="utf-8")
        for path in (self.root / HISTORY.LEDGER, report_path):
            before = path.read_bytes()
            with self.assertRaisesRegex(MODULE.Incomplete, "cannot overwrite"):
                MODULE.write_proposal(self.root, report_path, path)
            self.assertEqual(path.read_bytes(), before)
        output = self.root / "target/proposed-ledger.json"
        MODULE.write_proposal(self.root, report_path, output)
        self.assertEqual(json.loads(output.read_text())["schema"], "sealr.assurance-promotion-ledger.v1")
        self.assertNotIn(b"\r\n", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
