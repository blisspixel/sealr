"""Propose local assurance history bookkeeping from a complete saved report.

A saved report is an unauthenticated proposal input, not permission or evidence
for promotion. This command makes no network requests and never changes the
active ledger, CI, or promotion flags. Only the explicit output file is written.
"""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from collect_assurance_history import (
    Collector, Incomplete, LEDGER, MAX_RESPONSE_BYTES, MAX_SOURCE_BYTES,
    SCHEMA, WORKFLOWS, mapping, positive_int, require, timestamp,
)


REPOSITORY = "blisspixel/sealr"
PREFIXES = ("fuzz/", "verification/kani/")


def read_json(path):
    require(path.stat().st_size <= MAX_RESPONSE_BYTES, "JSON input exceeds byte limit")
    return json.loads(path.read_text(encoding="utf-8"))


class LocalSource(Collector):
    """Read actual working files, including untracked nonignored evidence files."""

    def __init__(self, root):
        super().__init__(None, REPOSITORY)
        self.root = root.resolve()
        self.local_tree = None

    def local_file(self, path):
        candidate = self.root / path
        require(not candidate.is_symlink(), "evidence source must not be a symlink: " + path)
        resolved = candidate.resolve()
        require(resolved.is_relative_to(self.root) and resolved.is_file(), "missing or escaped local source: " + path)
        return resolved

    def source(self, sha, path):
        candidate = self.local_file(path)
        before = candidate.stat()
        require(before.st_size <= MAX_SOURCE_BYTES, "local source exceeds byte limit: " + path)
        raw = candidate.read_bytes()
        after = candidate.stat()
        require(len(raw) == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns,
                "local source changed during observation: " + path)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        return raw, blob

    def tree(self, sha):
        if self.local_tree is None:
            names = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                check=True, capture_output=True, timeout=10,
            ).stdout
            require(len(names) <= MAX_RESPONSE_BYTES, "local source inventory exceeds byte limit")
            paths = {path.decode("utf-8") for path in names.split(b"\0") if path}
            require(len(paths) <= 20000, "local source inventory exceeds file limit")
            # Exact nonprefix source files are read directly by Collector.domain.
            # The tree inventory supplies every prefix file, including new files.
            self.local_tree = {path: self.source(sha, path)[1]
                               for path in paths if path == LEDGER or path.startswith(PREFIXES)}
        return self.local_tree


def hexadecimal(value, length, context):
    require(isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value), "invalid " + context)


def replay(check, domain, started, now):
    observations = check.get("observations")
    require(isinstance(observations, list) and len(observations) <= 1000, "invalid observations")
    sequence, active_commits, ids = [], set(), set()
    previous_created, previous_observed = None, None
    for row in observations:
        mapping(row, "observation")
        run_id = row.get("run_id")
        require(positive_int(run_id) and run_id not in ids, "duplicate or invalid run id")
        ids.add(run_id)
        hexadecimal(row.get("commit"), 40, "observation revision")
        hexadecimal(row.get("commit_tree"), 40, "observation tree")
        require(row.get("branch") == "main" and row.get("event") == "schedule", "observation branch or event mismatch")
        require(row.get("url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}", "observation URL mismatch")
        require(positive_int(row.get("latest_attempt")), "invalid latest attempt")
        created = (timestamp(row.get("created_at")), run_id)
        observed = timestamp(row.get("observed_at"))
        require(started <= observed <= now and created[0] <= observed, "invalid observation time")
        require(previous_created is None or created > previous_created, "observations are not chronological")
        require(previous_observed is None or observed.replace(microsecond=0) > previous_observed.replace(microsecond=0),
                "observation times must occupy distinct increasing seconds")
        previous_created, previous_observed = created, observed
        jobs = row.get("jobs")
        require(isinstance(jobs, list) and len(jobs) <= 100, "invalid observed jobs")
        job_ids = set()
        for job in jobs:
            mapping(job, "observed job")
            require(positive_int(job.get("id")) and job["id"] not in job_ids, "duplicate or invalid job id")
            job_ids.add(job["id"])
            require(isinstance(job.get("name"), str), "invalid job name")
        if row.get("decision") == "contract_not_present":
            require(row.get("missing_contract_path") == LEDGER and row.get("checked_attempt") is None
                    and "domain_fingerprint" not in row and not jobs, "invalid precontract boundary")
            expected = "contract_not_present"
        else:
            hexadecimal(row.get("domain_fingerprint"), 64, "historical domain fingerprint")
            require(row.get("checked_attempt") == 1 and type(row.get("checked_attempt")) is int,
                    "original attempt must be observed")
            if row["domain_fingerprint"] != domain["fingerprint"]:
                expected = "different_evidence_domain"
            elif row["latest_attempt"] != 1:
                expected = "rerun_excluded"
            elif row.get("original_conclusion") != "success" or row.get("latest_conclusion") != "success":
                expected = "unsuccessful_run"
            elif sorted(job["name"] for job in jobs) != domain["jobs"]:
                expected = "missing_or_duplicate_required_jobs"
            elif any(job.get("status") != "completed" or job.get("conclusion") != "success" for job in jobs):
                expected = "unsuccessful_required_job"
            elif row["commit"] in active_commits:
                expected = "duplicate_commit"
            else:
                expected = "counted"
        require(row.get("decision") == expected, "observation decision disagrees with its evidence")
        if expected == "counted":
            sequence.append(row)
            active_commits.add(row["commit"])
        elif expected != "duplicate_commit":
            sequence, active_commits = [], set()
    return sequence


def propose(root, report, now=None):
    mapping(report, "history report")
    require(report.get("schema") == SCHEMA and report.get("status") == "complete", "a complete supported history report is required")
    require(report.get("repository") == REPOSITORY and report.get("minimum_distinct_commits") == 10,
            "report repository or threshold mismatch")
    hexadecimal(report.get("subject_revision"), 40, "report subject revision")
    started = timestamp(report.get("observed_at"))
    now = now or datetime.now(timezone.utc)
    require(started <= now, "report observation starts in the future")
    records = report.get("checks")
    require(isinstance(records, list) and len(records) == len(WORKFLOWS), "all six report categories are required")
    for record in records:
        mapping(record, "report check")
    require({record.get("category") for record in records} == set(WORKFLOWS), "report categories are incomplete or duplicated")
    local = LocalSource(root)
    ledger = local.ledger(report["subject_revision"])
    proposed = copy.deepcopy(ledger)
    for check in proposed["checks"]:
        category = check["category"]
        record = next(item for item in records if item["category"] == category)
        domain = local.domain(report["subject_revision"], category)
        require(set(domain["source_prefixes"]).issubset(PREFIXES), "unsupported local evidence prefix")
        require(record.get("current_domain_fingerprint") == domain["fingerprint"], "stale evidence domain: " + category)
        require(record.get("check_id") == check["id"] and record.get("workflow") == WORKFLOWS[category]
                and positive_int(record.get("workflow_id")), "check or workflow identity mismatch")
        require(record.get("required_jobs") == domain["jobs"], "current job set mismatch")
        promotable = check.get("promotable") is True and category not in ("mutation-discovery", "coverage-discovery")
        require(type(record.get("promotable")) is bool and record["promotable"] == promotable,
                "report promotability mismatch")
        require(record.get("promoted") is False, "collector reports cannot grant promotion")
        sequence = replay(record, domain, started, now)
        eligible = promotable and len(sequence) >= 10
        require(type(record.get("eligible")) is bool and record["eligible"] == eligible
                and record.get("status") == ("eligible" if eligible else "ineligible"), "readiness summary mismatch")
        require(type(record.get("consecutive_successful_distinct_commits")) is int
                and record["consecutive_successful_distinct_commits"] == len(sequence)
                and record.get("qualifying_run_ids") == [row["run_id"] for row in sequence], "qualifying history summary mismatch")
        require(type(check.get("promoted")) is bool, "invalid existing promotion flag")
        require(not check["promoted"] or eligible, "an existing promoted check needs separate CI demotion")
        history = [{"sequence": index, "run_id": row["run_id"], "commit": row["commit"],
                    "branch": row["branch"], "event": row["event"], "conclusion": row["original_conclusion"],
                    "url": row["url"], "observed_at": row["observed_at"]}
                   for index, row in enumerate(sequence, 1)]
        existing = check.get("stable_main_runs")
        require(isinstance(existing, list), "invalid existing stable history")
        if existing and existing != history:
            newest = max(timestamp(mapping(row, "existing history row").get("observed_at")) for row in existing)
            require(started >= newest, "saved report predates the existing ledger observation")
        check["stable_main_runs"], check["eligible"] = history, eligible
    return proposed


def write_proposal(root, report_path, output):
    root, report_path, output = root.resolve(), report_path.resolve(), output.resolve()
    require(output not in (root / LEDGER, report_path), "output cannot overwrite the active ledger or report")
    proposal = propose(root, read_json(report_path))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8", newline="\n")
    return proposal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        proposal = write_proposal(args.repository_root, args.report, args.output)
    except (Incomplete, OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "proposed", "output": str(args.output),
                      "recorded_runs": sum(len(check["stable_main_runs"]) for check in proposal["checks"]),
                      "nonclaim": "Local bookkeeping proposal only; saved reports are not authenticated promotion evidence."}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
