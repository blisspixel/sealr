"""Offline behavioral fixtures for read-only assurance history collection."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("collect_history", ROOT / "scripts/collect_assurance_history.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CATEGORY = "bounded-model-checking"
WORKFLOW = MODULE.WORKFLOWS[CATEGORY]
REPO = "blisspixel/sealr"
CURRENT = "c" * 40


class FakeGitHub:
    def __init__(self):
        self.responses = {}
        self.calls = []

    def get(self, endpoint):
        self.calls.append(endpoint)
        if endpoint not in self.responses:
            raise MODULE.Incomplete("source_missing or fixture API evidence unavailable: " + endpoint)
        return copy.deepcopy(self.responses[endpoint])


class HistoryFixture:
    def __init__(self):
        self.api = FakeGitHub()
        self.prefix = "repos/" + REPO
        self.files = {
            "scripts/verify_assurance.ps1": b"verify the bounded domains\n",
            MODULE.MANIFEST: b'{"schema":"fixture.assurance.v1"}',
            "verification/kani/Cargo.toml": b"bounded proof manifest\n",
            "verification/kani/src/lib.rs": b"proof-only modules\n",
            "tests/assurance/semver-source-baseline-20260913-known-warnings.txt": b"",
            "fuzz/Cargo.toml": b"fuzz manifest\n",
            "fuzz/Cargo.lock": b"fuzz lock\n",
            "fuzz/fuzz_targets/example.rs": b"bounded fuzz domain\n",
            "scripts/verify_fuzz_seeds.ps1": b"verify seeds\n",
            "crates/sealr/tests/bounded_path_memory.rs": b"resource fixture\n",
            "Cargo.toml": b"workspace manifest\n",
            "Cargo.lock": b"workspace lock\n",
            **{f"crates/sealr/src/{name}.rs": name.encode() for name in ("interval", "quota", "ratio")},
        }
        checks = []
        for index, (category, workflow) in enumerate(MODULE.WORKFLOWS.items()):
            checks.append({"id": category + ".v1", "category": category, "scheduled_workflow": workflow,
                           "promotable": category not in ("mutation-discovery", "coverage-discovery"),
                           "domain": category + " exact fixture", "stable_main_runs": [], "eligible": False,
                           "promoted": False})
            filename = workflow.rsplit("/", 1)[1]
            self.api.responses[f"{self.prefix}/actions/workflows/{filename}"] = {"id": 50, "path": workflow}
        self.files[MODULE.LEDGER] = json.dumps({"schema": "sealr.assurance-promotion-ledger.v1",
                                              "minimum_consecutive_successful_main_runs": 10, "checks": checks}).encode()
        self.files[WORKFLOW] = ("jobs:\n" + "".join(f"  job{index}:\n    name: {name}\n"
                                                  for index, name in enumerate(MODULE.SINGLE_JOBS.values()))).encode()
        self.files[MODULE.WORKFLOWS["coverage-guided-fuzzing"]] = b"jobs:\n  fuzz:\n    name: Bounded fixture fuzz\n"
        self.files[MODULE.WORKFLOWS["native-resource-evidence"]] = (
            b"jobs:\n  resource:\n    name: 3 GiB sparse gate on ${{ matrix.os }}\n"
            b"        os: [ubuntu-24.04, macos-15, windows-2022]\n")
        self.add_revision(CURRENT)
        self.api.responses[f"{self.prefix}/branches/main"] = {"name": "main", "commit": {"sha": CURRENT}}
        self.runs = []

    def add_revision(self, sha, overrides=None):
        files = {**self.files, **(overrides or {})}
        entries = []
        for path, raw in files.items():
            if raw is None:
                continue
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            entries.append({"type": "blob", "path": path, "sha": blob})
            self.api.responses[f"{self.prefix}/contents/{path}?ref={sha}"] = {
                "type": "file", "path": path, "encoding": "base64", "size": len(raw),
                "sha": blob, "content": base64.b64encode(raw).decode(),
            }
        tree_sha = hashlib.sha1(json.dumps(entries, sort_keys=True).encode()).hexdigest()
        self.api.responses[f"{self.prefix}/git/commits/{sha}"] = {"sha": sha, "tree": {"sha": tree_sha}}
        self.api.responses[f"{self.prefix}/git/trees/{tree_sha}?recursive=1"] = {
            "sha": tree_sha, "truncated": False, "tree": entries,
        }

    def add_run(self, index, sha=None, conclusion="success", attempt=1, category=CATEGORY, original=None):
        sha = sha or f"{index:040x}"
        self.add_revision(sha)
        workflow = MODULE.WORKFLOWS[category]
        run = {"id": index, "workflow_id": 50, "path": workflow, "head_sha": sha, "head_branch": "main",
               "event": "schedule", "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
               "html_url": f"https://github.com/{REPO}/actions/runs/{index}", "run_attempt": attempt,
               "created_at": f"2026-09-{index:02d}T09:00:00Z", "status": "completed", "conclusion": conclusion}
        self.runs.append(run)
        self.api.responses[f"{self.prefix}/actions/runs/{index}/attempts/1"] = {
            **copy.deepcopy(run), "run_attempt": 1, "conclusion": original or conclusion,
        }
        if category in MODULE.SINGLE_JOBS:
            names = list(MODULE.SINGLE_JOBS.values())
        elif category == "native-resource-evidence":
            names = ["3 GiB sparse gate on " + os for os in ("ubuntu-24.04", "macos-15", "windows-2022")]
        else:
            names = ["Bounded fixture fuzz"]
        jobs = [{"id": index * 10 + offset, "run_id": index, "run_attempt": 1, "head_sha": sha,
                 "name": name, "status": "completed", "conclusion": "success"}
                for offset, name in enumerate(names, 1)]
        self.api.responses[f"{self.prefix}/actions/runs/{index}/attempts/1/jobs?per_page=100&page=1"] = {
            "total_count": len(jobs), "jobs": jobs,
        }
        return run

    def finish(self):
        for workflow in set(MODULE.WORKFLOWS.values()):
            filename = workflow.rsplit("/", 1)[1]
            runs = [run for run in self.runs if run["path"] == workflow]
            self.api.responses[f"{self.prefix}/actions/workflows/{filename}/runs?branch=main&event=schedule&per_page=100&page=1"] = {
                "total_count": len(runs), "workflow_runs": list(reversed(runs)),
            }
        def fixture_observer(previous, deadline=None):
            return datetime.now(timezone.utc) if previous is None else previous + timedelta(seconds=1)

        return MODULE.Collector(self.api, observer=fixture_observer)

    def jobs(self, index):
        return self.api.responses[f"{self.prefix}/actions/runs/{index}/attempts/1/jobs?per_page=100&page=1"]


class CollectHistoryTests(unittest.TestCase):
    def test_same_second_clock_values_wait_and_preserve_real_later_fractions(self):
        start = datetime(2026, 9, 13, tzinfo=timezone.utc)
        later = start + timedelta(seconds=1, milliseconds=7)
        readings = iter([start, start + timedelta(milliseconds=1), later])
        pauses = []
        self.assertEqual(MODULE.observe_after(start, lambda: next(readings), pauses.append), later)
        self.assertEqual(len(pauses), 2)
        self.assertTrue(all(pause <= 0.01 for pause in pauses))

    def test_clock_exhaustion_reports_incomplete_without_synthetic_time(self):
        start = datetime(2026, 9, 13, tzinfo=timezone.utc)
        with self.assertRaisesRegex(MODULE.Incomplete, "UTC clock did not advance"):
            MODULE.observe_after(start, lambda: start, lambda _: None)
        fixture = HistoryFixture()
        fixture.add_run(1)
        collector = fixture.finish()
        with patch.object(collector, "observer", side_effect=MODULE.Incomplete("UTC clock did not advance")):
            report = collector.check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["eligible"])

    def test_global_deadline_applies_to_observer_and_cached_collection(self):
        start = datetime(2026, 9, 13, tzinfo=timezone.utc)
        with self.assertRaisesRegex(MODULE.Incomplete, "collection deadline"):
            MODULE.observe_after(start, lambda: start, lambda _: None, deadline=100, monotonic=lambda: 100)
        fixture = HistoryFixture()
        fixture.add_run(1)
        collector = fixture.finish()
        self.assertEqual(collector.collect()["status"], "complete")
        calls = len(fixture.api.calls)
        collector.deadline = 0
        self.assertEqual(collector.collect()["status"], "incomplete")
        self.assertEqual(collector.check(CURRENT, CATEGORY)["status"], "incomplete")
        self.assertEqual(len(fixture.api.calls), calls)

    def test_ten_distinct_successes_are_ready_but_never_promoted(self):
        fixture = HistoryFixture()
        for index in range(1, 11):
            fixture.add_run(index)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "eligible")
        self.assertEqual(report["qualifying_run_ids"], list(range(1, 11)))
        self.assertFalse(report["promoted"])
        for observation in report["observations"]:
            self.assertEqual(observation["original_conclusion"], "success")
            self.assertEqual(observation["domain_fingerprint"], report["current_domain_fingerprint"])
            self.assertIsNotNone(MODULE.timestamp(observation["observed_at"]))
            self.assertNotEqual(observation["observed_at"], observation["created_at"])

    def test_nine_is_ineligible_not_incomplete(self):
        fixture = HistoryFixture()
        for index in range(1, 10):
            fixture.add_run(index)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "ineligible")
        self.assertEqual(report["consecutive_successful_distinct_commits"], 9)

    def test_duplicate_commits_do_not_inflate_sequence(self):
        fixture = HistoryFixture()
        for index in range(1, 11):
            fixture.add_run(index, sha="a" * 40)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["consecutive_successful_distinct_commits"], 1)
        self.assertEqual(report["observations"][-1]["decision"], "duplicate_commit")

    def test_failed_run_resets_then_new_success_starts_sequence(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        fixture.add_run(2, conclusion="failure")
        fixture.add_run(3)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["qualifying_run_ids"], [3])

    def test_successful_rerun_never_masks_failed_original(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        fixture.add_run(2, attempt=2, original="failure")
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["consecutive_successful_distinct_commits"], 0)
        self.assertEqual(report["observations"][-1]["original_conclusion"], "failure")
        self.assertEqual(report["observations"][-1]["decision"], "rerun_excluded")

    def test_rerun_even_with_green_original_is_conservatively_excluded(self):
        fixture = HistoryFixture()
        fixture.add_run(1, attempt=3)
        self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["qualifying_run_ids"], [])

    def test_missing_duplicate_and_failed_jobs_are_not_counted(self):
        for mutation in ("missing", "duplicate", "failed"):
            with self.subTest(mutation=mutation):
                fixture = HistoryFixture()
                fixture.add_run(1)
                evidence = fixture.jobs(1)
                if mutation == "missing":
                    evidence["jobs"].pop(0)
                elif mutation == "duplicate":
                    evidence["jobs"].append({**evidence["jobs"][0], "id": 100})
                else:
                    evidence["jobs"][0]["conclusion"] = "failure"
                evidence["total_count"] = len(evidence["jobs"])
                report = fixture.finish().check(CURRENT, CATEGORY)
                self.assertEqual(report["status"], "ineligible")
                self.assertEqual(report["qualifying_run_ids"], [])

    def test_wrong_run_bindings_fail_incomplete(self):
        changes = ({"head_branch": "topic"}, {"event": "workflow_dispatch"},
                   {"repository": {"full_name": "attacker/sealr"}},
                   {"head_repository": {"full_name": "attacker/sealr"}},
                   {"workflow_id": 51}, {"path": ".github/workflows/other.yml"},
                   {"html_url": "https://example.com/unrelated"})
        for change in changes:
            with self.subTest(change=change):
                fixture = HistoryFixture()
                run = fixture.add_run(1)
                collector = fixture.finish()
                # Mutate the already built API page, including the workflow mismatch case.
                endpoint = f"{fixture.prefix}/actions/workflows/assurance.yml/runs?branch=main&event=schedule&per_page=100&page=1"
                fixture.api.responses[endpoint]["workflow_runs"][0] = {**run, **change}
                self.assertEqual(collector.check(CURRENT, CATEGORY)["status"], "incomplete")

    def test_job_wrong_attempt_or_source_fails_incomplete(self):
        for change in ({"run_attempt": 2}, {"head_sha": "f" * 40}, {"run_id": 2}):
            fixture = HistoryFixture()
            fixture.add_run(1)
            fixture.jobs(1)["jobs"][0].update(change)
            self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["status"], "incomplete")

    def test_changed_historical_domain_resets(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        run = fixture.add_run(2)
        fixture.add_revision(run["head_sha"], {"verification/kani/src/lib.rs": b"different proof domain\n"})
        fixture.add_run(3)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["qualifying_run_ids"], [3])
        self.assertEqual(report["observations"][1]["decision"], "different_evidence_domain")

    def test_unrelated_readme_change_preserves_domain(self):
        fixture = HistoryFixture()
        run = fixture.add_run(1)
        fixture.add_revision(run["head_sha"], {"README.md": b"unrelated prose\n"})
        self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["qualifying_run_ids"], [1])

    def test_missing_historical_source_never_uses_current_source(self):
        fixture = HistoryFixture()
        run = fixture.add_run(1)
        del fixture.api.responses[f"{fixture.prefix}/contents/{WORKFLOW}?ref={run['head_sha']}"]
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["eligible"])
        self.assertIn("source_unavailable at " + run["head_sha"], report["error"])

    def test_authenticated_pre_contract_boundary_allows_new_history(self):
        fixture = HistoryFixture()
        old = fixture.add_run(1)
        fixture.add_revision(old["head_sha"], {MODULE.LEDGER: None})
        for index in range(2, 12):
            fixture.add_run(index)
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "eligible")
        self.assertEqual(report["qualifying_run_ids"], list(range(2, 12)))
        boundary = report["observations"][0]
        self.assertEqual(boundary["decision"], "contract_not_present")
        self.assertEqual(boundary["missing_contract_path"], MODULE.LEDGER)
        self.assertEqual(len(boundary["commit_tree"]), 40)
        self.assertNotIn(f"{fixture.prefix}/contents/{MODULE.LEDGER}?ref={old['head_sha']}", fixture.api.calls)

    def test_declared_historical_contract_acquisition_failure_is_incomplete(self):
        fixture = HistoryFixture()
        run = fixture.add_run(1)
        del fixture.api.responses[f"{fixture.prefix}/contents/{MODULE.LEDGER}?ref={run['head_sha']}"]
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "incomplete")
        self.assertNotIn("contract_not_present", report["error"])

    def test_missing_expected_source_is_detected_before_content_request(self):
        fixture = HistoryFixture()
        run = fixture.add_run(1)
        path = "crates/sealr/src/interval.rs"
        fixture.add_revision(run["head_sha"], {path: None})
        report = fixture.finish().check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("source_missing in authenticated tree", report["error"])
        self.assertNotIn(f"{fixture.prefix}/contents/{path}?ref={run['head_sha']}", fixture.api.calls)

    def test_successful_second_page_is_collected_and_page_drift_rejected(self):
        for drift in (False, True):
            with self.subTest(drift=drift):
                fixture = HistoryFixture()
                fixture.add_run(1)
                fixture.add_run(2)
                collector = fixture.finish()
                endpoint = f"{fixture.prefix}/actions/workflows/assurance.yml/runs?branch=main&event=schedule&per_page=100&page="
                first = fixture.api.responses[endpoint + "1"]
                earlier = first["workflow_runs"].pop()
                fixture.api.responses[endpoint + "2"] = {
                    "total_count": 3 if drift else 2, "workflow_runs": [earlier],
                }
                report = collector.check(CURRENT, CATEGORY)
                self.assertEqual(report["status"], "incomplete" if drift else "ineligible")
                if not drift:
                    self.assertEqual(report["qualifying_run_ids"], [1, 2])

    def test_unnamed_workflow_job_cannot_silently_disappear(self):
        fixture = HistoryFixture()
        workflow = MODULE.WORKFLOWS["coverage-guided-fuzzing"]
        fixture.add_revision(CURRENT, {workflow: fixture.files[workflow] + b"  hidden:\n    runs-on: ubuntu-latest\n"})
        report = fixture.finish().check(CURRENT, "coverage-guided-fuzzing")
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("explicit display name", report["error"])

    def test_source_digest_and_tree_bindings_are_checked(self):
        for change in ({"content": base64.b64encode(b"untrusted").decode()}, {"sha": "d" * 40}):
            fixture = HistoryFixture()
            fixture.api.responses[f"{fixture.prefix}/contents/{WORKFLOW}?ref={CURRENT}"].update(change)
            self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["status"], "incomplete")

    def test_truncated_history_is_incomplete(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        collector = fixture.finish()
        collector.max_pages = 1
        endpoint = f"{fixture.prefix}/actions/workflows/assurance.yml/runs?branch=main&event=schedule&per_page=100&page=1"
        fixture.api.responses[endpoint]["total_count"] = 101
        report = collector.check(CURRENT, CATEGORY)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("pagination bound", report["error"])

    def test_paginated_jobs_and_truncated_tree_fail_incomplete(self):
        fixture = HistoryFixture()
        fixture.add_run(1)
        fixture.jobs(1)["total_count"] = 101
        self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["status"], "incomplete")
        fixture = HistoryFixture()
        for endpoint, response in fixture.api.responses.items():
            if "/git/trees/" in endpoint:
                response["truncated"] = True
        self.assertEqual(fixture.finish().collect()["status"], "incomplete")

    def test_resource_history_requires_all_three_platform_jobs(self):
        fixture = HistoryFixture()
        fixture.add_run(1, category="native-resource-evidence")
        evidence = fixture.jobs(1)
        evidence["jobs"].pop()
        evidence["total_count"] -= 1
        report = fixture.finish().check(CURRENT, "native-resource-evidence")
        self.assertEqual(report["qualifying_run_ids"], [])
        self.assertEqual(len(report["required_jobs"]), 3)

    def test_mutation_and_coverage_are_never_promotable(self):
        for category in ("mutation-discovery", "coverage-discovery"):
            fixture = HistoryFixture()
            for index in range(1, 11):
                fixture.add_run(index, category=category)
            report = fixture.finish().check(CURRENT, category)
            self.assertEqual(report["consecutive_successful_distinct_commits"], 10)
            self.assertFalse(report["eligible"])
            self.assertFalse(report["promotable"])

    def test_pending_run_is_incomplete(self):
        fixture = HistoryFixture()
        fixture.add_run(1)["status"] = "in_progress"
        self.assertEqual(fixture.finish().check(CURRENT, CATEGORY)["status"], "incomplete")

    def test_empty_history_is_complete_and_ineligible(self):
        report = HistoryFixture().finish().collect()
        self.assertEqual(report["schema"], MODULE.SCHEMA)
        self.assertEqual(report["status"], "complete")
        self.assertTrue(all(check["status"] == "ineligible" for check in report["checks"]))

    def test_malformed_ledger_shapes_emit_versioned_incomplete_report(self):
        for raw in (b"null", b"[]", b'{"schema":"sealr.assurance-promotion-ledger.v1",'
                                            b'"minimum_consecutive_successful_main_runs":10,'
                                            b'"checks":["bad",null,[],0,true,{}]}'):
            with self.subTest(raw=raw):
                fixture = HistoryFixture()
                fixture.add_revision(CURRENT, {MODULE.LEDGER: raw})
                report = fixture.finish().collect()
                self.assertEqual(report["schema"], MODULE.SCHEMA)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("JSON object", report["error"])

    def test_malformed_api_rows_are_incomplete_without_tracebacks(self):
        for shape in ("workflow", "tree_entry", "job", "run", "repository", "source", "commit"):
            with self.subTest(shape=shape):
                fixture = HistoryFixture()
                fixture.add_run(1)
                collector = fixture.finish()
                if shape == "workflow":
                    fixture.api.responses[f"{fixture.prefix}/actions/workflows/assurance.yml"] = []
                elif shape == "tree_entry":
                    for endpoint, response in fixture.api.responses.items():
                        if "/git/trees/" in endpoint:
                            response["tree"][0] = None
                elif shape == "job":
                    fixture.jobs(1)["jobs"][0] = []
                elif shape in ("run", "repository"):
                    endpoint = f"{fixture.prefix}/actions/workflows/assurance.yml/runs?branch=main&event=schedule&per_page=100&page=1"
                    if shape == "run":
                        fixture.api.responses[endpoint]["workflow_runs"][0] = None
                    else:
                        fixture.api.responses[endpoint]["workflow_runs"][0]["repository"] = []
                elif shape == "source":
                    fixture.api.responses[f"{fixture.prefix}/contents/{MODULE.LEDGER}?ref={CURRENT}"] = []
                else:
                    fixture.api.responses[f"{fixture.prefix}/git/commits/{CURRENT}"] = None
                report = collector.collect()
                self.assertEqual(report["schema"], MODULE.SCHEMA)
                self.assertEqual(report["status"], "incomplete")
                for check in report["checks"]:
                    self.assertFalse(check["eligible"])


if __name__ == "__main__":
    unittest.main()
