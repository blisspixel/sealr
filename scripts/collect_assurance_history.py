"""Collect bounded, read-only GitHub assurance readiness evidence.

This report never changes the promotion ledger, required CI, or GitHub state.
Historical configuration is fetched at each observed source revision. Conservative
domain fingerprints include supporting source identities, so even a harmless
change to those files starts a new history. All reruns reset the sequence.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.parse import quote


SCHEMA = "sealr.assurance-history.v1"
LEDGER = "tests/assurance/promotion-ledger.json"
MANIFEST = "tests/assurance/manifest.json"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
SINGLE_JOBS = {
    "bounded-model-checking": "Bounded scalar model checking",
    "mutation-discovery": "Targeted mutation discovery",
    "coverage-discovery": "Source coverage discovery",
    "public-api-compatibility": "Public API compatibility discovery",
}
WORKFLOWS = {
    **{category: ".github/workflows/assurance.yml" for category in SINGLE_JOBS},
    "coverage-guided-fuzzing": ".github/workflows/fuzz.yml",
    "native-resource-evidence": ".github/workflows/resource-evidence.yml",
}


class Incomplete(RuntimeError):
    """The bounded observation cannot establish readiness."""


class ContractAbsent(Incomplete):
    """An authenticated historical tree predates the declared contract."""


def require(condition, message):
    if not condition:
        raise Incomplete(message)


def positive_int(value):
    return type(value) is int and value > 0


def mapping(value, context):
    require(isinstance(value, dict), context + " must be a JSON object")
    return value


def timestamp(value):
    require(isinstance(value, str), "missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise Incomplete("invalid timestamp") from error
    require(parsed.tzinfo is not None, "timestamp has no timezone")
    return parsed


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def observe_after(previous, clock=None, pause=None, deadline=None, monotonic=None):
    """Obtain a real timestamp in a later whole second for ledger compatibility."""
    clock = clock or (lambda: datetime.now(timezone.utc))
    pause = pause or time.sleep
    monotonic = monotonic or time.monotonic
    stop = monotonic() + 1.25
    if deadline is not None:
        stop = min(stop, deadline)
    for _ in range(126):
        if deadline is not None and monotonic() >= deadline:
            raise Incomplete("collection deadline exhausted while recording observation time")
        if monotonic() >= stop:
            break
        observed = clock()
        if previous is None or observed.replace(microsecond=0) > previous.replace(microsecond=0):
            return observed
        remaining = stop - monotonic()
        if remaining <= 0:
            break
        pause(min(0.01, remaining))
    raise Incomplete("UTC clock did not advance to a later second within the observation timestamp bound")


class GitHub:
    """Only GET requests, with hard subprocess, response, call, and time bounds."""

    def __init__(self, seconds=300, max_calls=200):
        self.deadline = time.monotonic() + seconds
        self.max_calls = max_calls
        self.calls = 0

    def get(self, endpoint):
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        require(self.calls <= self.max_calls and remaining > 0, "API observation budget exhausted")
        output = bytearray()
        overflow = []
        try:
            process = subprocess.Popen(
                ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except OSError as error:
            raise Incomplete("GitHub CLI could not start") from error

        def read_output():
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                if len(output) + len(chunk) > MAX_RESPONSE_BYTES:
                    overflow.append(True)
                    process.kill()
                    break
                output.extend(chunk)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            process.wait(timeout=min(30, remaining))
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=5)
            reader.join(timeout=5)
            raise Incomplete("GitHub API request timed out") from error
        reader.join(timeout=5)
        require(not reader.is_alive(), "GitHub API output reader did not finish")
        require(not overflow, "GitHub API response exceeded byte limit")
        require(process.returncode == 0, "GitHub API request failed: " + endpoint.split("?")[0])
        try:
            result = json.loads(output)
        except (ValueError, UnicodeError) as error:
            raise Incomplete("GitHub API returned invalid JSON") from error
        require(isinstance(result, dict), "GitHub API returned a non-object response")
        return result


class Collector:
    def __init__(self, api, repository="blisspixel/sealr", max_pages=2, observer=None):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository")
        require(type(max_pages) is int and 1 <= max_pages <= 10, "invalid pagination bound")
        self.api = api
        self.deadline = getattr(api, "deadline", time.monotonic() + 300)
        self.observer = observer or observe_after
        self.repository = repository
        self.prefix = "repos/" + repository
        self.max_pages = max_pages
        self.sources = {}
        self.trees = {}
        self.tree_shas = {}
        self.histories = {}
        self.attempts = {}

    def within_deadline(self):
        require(time.monotonic() < self.deadline, "collection deadline exhausted")

    def source(self, sha, path):
        key = (sha, path)
        if key not in self.sources:
            tree = self.tree(sha)
            require(path in tree, f"source_missing in authenticated tree at {sha}:{path}")
            try:
                obj = self.api.get(f"{self.prefix}/contents/{quote(path, safe='/')}?ref={sha}")
            except Incomplete as error:
                raise Incomplete(f"source_unavailable at {sha}:{path}: {error}") from error
            mapping(obj, "source response")
            require(obj.get("type") == "file" and obj.get("path") == path, "source path binding failed")
            require(obj.get("encoding") == "base64", "source content is unavailable")
            size = obj.get("size")
            require(type(size) is int and 0 <= size <= MAX_SOURCE_BYTES, "source exceeds byte limit")
            try:
                raw = base64.b64decode("".join(obj["content"].split()), validate=True)
            except (KeyError, ValueError, TypeError) as error:
                raise Incomplete("invalid source encoding") from error
            require(len(raw) == size, "source size mismatch")
            blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + raw).hexdigest()
            require(blob == obj.get("sha"), "source Git blob digest mismatch")
            require(tree[path] == blob, "source is not bound to the requested commit tree")
            self.sources[key] = (raw, blob)
        return self.sources[key]

    def tree(self, sha):
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha), "invalid source revision")
        if sha not in self.trees:
            commit = self.api.get(f"{self.prefix}/git/commits/{sha}")
            mapping(commit, "commit response")
            require(commit.get("sha") == sha, "commit identity mismatch")
            tree_sha = mapping(commit.get("tree"), "commit tree reference").get("sha")
            require(isinstance(tree_sha, str) and re.fullmatch(r"[0-9a-f]{40}", tree_sha), "invalid commit tree")
            result = self.api.get(f"{self.prefix}/git/trees/{tree_sha}?recursive=1")
            mapping(result, "tree response")
            require(result.get("sha") == tree_sha and result.get("truncated") is False, "commit tree is incomplete")
            entries = result.get("tree")
            require(isinstance(entries, list), "missing commit tree entries")
            files = {}
            for entry in entries:
                mapping(entry, "tree entry")
                if entry.get("type") != "blob":
                    continue
                path, blob = entry.get("path"), entry.get("sha")
                require(isinstance(path, str) and path not in files, "duplicate or invalid tree path")
                require(isinstance(blob, str) and re.fullmatch(r"[0-9a-f]{40}", blob), "invalid tree blob")
                files[path] = blob
            self.trees[sha] = files
            self.tree_shas[sha] = tree_sha
        return self.trees[sha]

    def ledger(self, sha):
        try:
            ledger = json.loads(self.source(sha, LEDGER)[0])
        except (ValueError, UnicodeError) as error:
            raise Incomplete("invalid historical ledger JSON") from error
        mapping(ledger, "ledger")
        require(ledger.get("schema") == "sealr.assurance-promotion-ledger.v1", "unsupported ledger schema")
        require(ledger.get("minimum_consecutive_successful_main_runs") == 10, "unsupported promotion threshold")
        checks = ledger.get("checks")
        require(isinstance(checks, list) and len(checks) == 6, "incomplete evidence categories")
        for item in checks:
            mapping(item, "ledger check")
        require({item.get("category") for item in checks} == set(WORKFLOWS), "unsupported evidence categories")
        require(len({item.get("id") for item in checks}) == 6, "duplicate check identity")
        return ledger

    def domain(self, sha, category):
        if LEDGER not in self.tree(sha):
            raise ContractAbsent(f"contract_not_present in authenticated tree at {sha}:{LEDGER}")
        ledger = self.ledger(sha)
        check = next(item for item in ledger["checks"] if item["category"] == category)
        workflow = WORKFLOWS[category]
        require(check.get("scheduled_workflow") == workflow, "ledger workflow binding mismatch")
        text, workflow_blob = self.source(sha, workflow)
        try:
            text = text.decode("utf-8")
        except UnicodeError as error:
            raise Incomplete("workflow is not UTF-8") from error
        blocks = re.split(r"^jobs:\s*$", text, flags=re.MULTILINE)
        require(len(blocks) == 2, "unsupported workflow jobs declaration")
        job_ids = re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", blocks[1], flags=re.MULTILINE)
        names = re.findall(r"^    name: (.+)$", blocks[1], flags=re.MULTILINE)
        require(len(job_ids) == len(names), "every workflow job must have an explicit display name")
        require(names and len(names) == len(set(names)), "workflow job names are missing or ambiguous")
        if category in SINGLE_JOBS:
            jobs = [SINGLE_JOBS[category]]
            require(jobs[0] in names, "historical required job is missing")
        elif category == "native-resource-evidence":
            require(names == ["3 GiB sparse gate on ${{ matrix.os }}"], "unsupported resource job expansion")
            require("os: [ubuntu-24.04, macos-15, windows-2022]" in text, "unsupported resource matrix")
            jobs = ["3 GiB sparse gate on " + os for os in ("ubuntu-24.04", "macos-15", "windows-2022")]
        else:
            require(all(re.fullmatch(r"[A-Za-z0-9 ._-]+", name) for name in names), "unsupported dynamic workflow job names")
            jobs = names
        files = {workflow: workflow_blob}
        tree = self.tree(sha)
        if category == "coverage-guided-fuzzing":
            prefixes = ("fuzz/",)
            required = ["fuzz/Cargo.toml", "fuzz/Cargo.lock", "scripts/verify_fuzz_seeds.ps1"]
        elif category == "native-resource-evidence":
            prefixes = ()
            required = ["crates/sealr/tests/bounded_path_memory.rs", "Cargo.toml", "Cargo.lock"]
        else:
            prefixes = ("verification/kani/",) if category == "bounded-model-checking" else ()
            required = [MANIFEST, "scripts/verify_assurance.ps1"]
            if category in ("bounded-model-checking", "mutation-discovery"):
                required += [f"crates/sealr/src/{name}.rs" for name in ("interval", "quota", "ratio")]
            if category == "public-api-compatibility":
                required += ["tests/assurance/semver-alpha12-known-warnings.txt"]
        for path in required:
            files[path] = self.source(sha, path)[1]
        files.update({path: blob for path, blob in tree.items() if path.startswith(prefixes)})
        contract = {key: value for key, value in check.items() if key not in ("stable_main_runs", "eligible", "promoted")}
        fingerprint = digest({"contract": contract, "files": files, "jobs": sorted(jobs)})
        return {"fingerprint": fingerprint, "check": check, "jobs": sorted(jobs), "source_blob_count": len(files),
                "source_files": sorted({workflow, *required}), "source_prefixes": list(prefixes)}

    def history(self, workflow):
        if workflow in self.histories:
            return self.histories[workflow]
        filename = workflow.rsplit("/", 1)[1]
        obj = self.api.get(f"{self.prefix}/actions/workflows/{filename}")
        mapping(obj, "workflow response")
        require(obj.get("path") == workflow and positive_int(obj.get("id")), "workflow identity mismatch")
        runs, ids, total = [], set(), None
        for page in range(1, self.max_pages + 1):
            result = self.api.get(f"{self.prefix}/actions/workflows/{filename}/runs?branch=main&event=schedule&per_page=100&page={page}")
            mapping(result, "history page")
            count = result.get("total_count")
            require(type(count) is int and count >= 0, "invalid history total")
            require(total is None or total == count, "history changed during pagination")
            total = count
            batch = result.get("workflow_runs")
            require(isinstance(batch, list) and len(batch) <= 100, "invalid history page")
            for run in batch:
                self.validate_run(run, workflow, obj["id"])
                require(run["id"] not in ids, "duplicate run across history pages")
                ids.add(run["id"])
                runs.append(run)
            require(len(runs) <= total, "history exceeded declared total")
            if len(runs) == total:
                runs.sort(key=lambda run: (timestamp(run["created_at"]), run["id"]))
                self.histories[workflow] = (obj["id"], runs)
                return self.histories[workflow]
            require(batch, "history ended before declared total")
        raise Incomplete("history pagination bound reached before all runs were observed")

    def validate_run(self, run, workflow, workflow_id):
        mapping(run, "run")
        require(positive_int(run.get("id")) and positive_int(run.get("run_attempt")), "invalid run identity")
        require(run.get("workflow_id") == workflow_id and run.get("path") == workflow, "run workflow mismatch")
        require(run.get("head_branch") == "main" and run.get("event") == "schedule", "run branch or event mismatch")
        require(mapping(run.get("repository"), "run repository").get("full_name") == self.repository, "run repository mismatch")
        require(mapping(run.get("head_repository"), "run source repository").get("full_name") == self.repository, "run source repository mismatch")
        require(run.get("html_url") == f"https://github.com/{self.repository}/actions/runs/{run['id']}", "run URL mismatch")
        require(isinstance(run.get("head_sha"), str) and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]), "invalid run revision")
        timestamp(run.get("created_at"))

    def original_attempt(self, run, workflow, workflow_id):
        run_id = run["id"]
        if run_id not in self.attempts:
            attempt = self.api.get(f"{self.prefix}/actions/runs/{run_id}/attempts/1")
            self.validate_run(attempt, workflow, workflow_id)
            require(attempt["id"] == run_id and attempt["run_attempt"] == 1, "original attempt identity mismatch")
            require(all(attempt.get(key) == run.get(key) for key in ("head_sha", "created_at")), "original attempt source mismatch")
            result = self.api.get(f"{self.prefix}/actions/runs/{run_id}/attempts/1/jobs?per_page=100&page=1")
            mapping(result, "attempt jobs response")
            jobs = result.get("jobs")
            require(isinstance(jobs, list) and type(result.get("total_count")) is int, "invalid attempt jobs")
            require(len(jobs) == result["total_count"] and len(jobs) <= 100, "attempt job pagination is incomplete")
            ids = set()
            for job in jobs:
                mapping(job, "job")
                require(positive_int(job.get("id")) and job["id"] not in ids, "invalid or duplicate job identity")
                ids.add(job["id"])
                require(job.get("run_id") == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == run["head_sha"], "job attempt or source mismatch")
            self.attempts[run_id] = (attempt, jobs)
        return self.attempts[run_id]

    def check(self, revision, category):
        result = {"category": category, "status": "incomplete", "eligible": False, "promoted": False,
                  "consecutive_successful_distinct_commits": 0, "observations": []}
        try:
            self.within_deadline()
            current = self.domain(revision, category)
            promotable = current["check"].get("promotable") is True and category not in ("mutation-discovery", "coverage-discovery")
            result.update(check_id=current["check"]["id"], promotable=promotable,
                          current_domain_fingerprint=current["fingerprint"], required_jobs=current["jobs"],
                          domain_source_blob_count=current["source_blob_count"],
                          domain_inputs={"files": current["source_files"], "prefixes": current["source_prefixes"],
                                         "contract": LEDGER + " category record excluding history, eligibility, and promotion flags"})
            workflow = WORKFLOWS[category]
            workflow_id, runs = self.history(workflow)
            result.update(workflow=workflow, workflow_id=workflow_id)
            sequence, commits = [], set()
            previous_observed = None
            for run in runs:
                try:
                    historical = self.domain(run["head_sha"], category)
                except ContractAbsent:
                    previous_observed = self.observer(previous_observed, deadline=self.deadline)
                    result["observations"].append({
                        "run_id": run["id"], "commit": run["head_sha"], "event": run["event"],
                        "branch": run["head_branch"], "url": run["html_url"], "created_at": run["created_at"],
                        "observed_at": previous_observed.isoformat(),
                        "latest_attempt": run["run_attempt"], "checked_attempt": None,
                        "commit_tree": self.tree_shas[run["head_sha"]], "missing_contract_path": LEDGER,
                        "decision": "contract_not_present", "jobs": [],
                    })
                    sequence, commits = [], set()
                    continue
                attempt, jobs = self.original_attempt(run, workflow, workflow_id)
                previous_observed = self.observer(previous_observed, deadline=self.deadline)
                observed = {"run_id": run["id"], "commit": run["head_sha"], "event": run["event"],
                            "branch": run["head_branch"], "url": run["html_url"], "created_at": run["created_at"],
                            "observed_at": previous_observed.isoformat(),
                            "latest_attempt": run["run_attempt"], "checked_attempt": 1,
                            "commit_tree": self.tree_shas[run["head_sha"]],
                            "original_conclusion": attempt.get("conclusion"),
                            "latest_conclusion": run.get("conclusion"),
                            "domain_fingerprint": historical["fingerprint"]}
                selected = [job for job in jobs if job.get("name") in historical["jobs"]]
                observed["jobs"] = [{key: job.get(key) for key in ("id", "name", "status", "conclusion")} for job in selected]
                names = [job.get("name") for job in selected]
                if historical["fingerprint"] != current["fingerprint"]:
                    reason = "different_evidence_domain"
                elif run["run_attempt"] != 1:
                    reason = "rerun_excluded"
                elif run.get("status") != "completed" or attempt.get("status") != "completed":
                    raise Incomplete("a scheduled run is still pending")
                elif run.get("conclusion") != "success" or attempt.get("conclusion") != "success":
                    reason = "unsuccessful_run"
                elif sorted(names) != historical["jobs"]:
                    reason = "missing_or_duplicate_required_jobs"
                elif any(job.get("status") != "completed" or job.get("conclusion") != "success" for job in selected):
                    reason = "unsuccessful_required_job"
                elif run["head_sha"] in commits:
                    reason = "duplicate_commit"
                else:
                    reason = "counted"
                observed["decision"] = reason
                result["observations"].append(observed)
                if reason == "counted":
                    sequence.append(run["id"])
                    commits.add(run["head_sha"])
                elif reason != "duplicate_commit":
                    sequence, commits = [], set()
            self.within_deadline()
            eligible = promotable and len(sequence) >= 10
            result.update(status="eligible" if eligible else "ineligible", eligible=eligible,
                          consecutive_successful_distinct_commits=len(sequence), qualifying_run_ids=sequence)
        except (Incomplete, KeyError, TypeError, ValueError, AttributeError) as error:
            result["error"] = str(error)
        return result

    def collect(self, revision=None):
        report = {"schema": SCHEMA, "repository": self.repository, "observed_at": datetime.now(timezone.utc).isoformat(),
                  "status": "incomplete", "checks": [], "minimum_distinct_commits": 10,
                  "bounds": {"history_pages_per_workflow": self.max_pages, "runs_per_page": 100,
                             "jobs_per_attempt": 100, "api_response_bytes": MAX_RESPONSE_BYTES,
                             "source_file_bytes": MAX_SOURCE_BYTES, "api_calls": 200,
                             "observation_seconds": 300, "request_seconds": 30,
                             "observation_timestamp_wait_seconds": 1.25},
                  "nonclaim": "Read-only readiness observation. No ledger mutation, promotion, independent human review, artifact verification, or claim of correctness. All reruns reset history; conservative source fingerprints may reset after harmless changes."}
        try:
            self.within_deadline()
            if revision is None:
                branch = self.api.get(f"{self.prefix}/branches/main")
                mapping(branch, "branch response")
                require(branch.get("name") == "main", "main branch identity mismatch")
                revision = mapping(branch.get("commit"), "branch commit").get("sha")
            self.tree(revision)
            report["subject_revision"] = revision
            self.ledger(revision)
            report["checks"] = [self.check(revision, category) for category in WORKFLOWS]
            self.within_deadline()
            if all(check["status"] != "incomplete" for check in report["checks"]):
                report["status"] = "complete"
        except (Incomplete, KeyError, TypeError, ValueError, AttributeError) as error:
            report["error"] = str(error)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="blisspixel/sealr")
    parser.add_argument("--revision", help="Exact 40-character source revision; defaults to observed remote main")
    parser.add_argument("--max-pages", type=int, choices=range(1, 11), default=2)
    parser.add_argument("--report", type=Path, help="Optional local JSON output path")
    args = parser.parse_args()
    try:
        collector = Collector(GitHub(), args.repository, args.max_pages)
        report = collector.collect(args.revision)
    except Incomplete as error:
        report = {"schema": SCHEMA, "status": "incomplete", "error": str(error)}
    rendered = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8", newline="\n")
    sys.stdout.write(rendered)
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main())
