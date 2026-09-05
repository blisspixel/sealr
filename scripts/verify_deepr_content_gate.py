"""Verify the public Linux content gate against an exact released Deepr wheel."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


FILENAME = "deepr_research-2.50.11-py3-none-any.whl"
SOURCE_BYTES = 4_126_292
SOURCE_URL = f"https://github.com/blisspixel/deepr/releases/download/v2.50.11/{FILENAME}"
IDENTITIES = {
    "source_sha256": "149377d4db9fa2a074dd213d155afd5cb1c0e145cbed2c80beff6f25a692f0a1",
    "archive_tree_sha256": "7c201d810c3144d53e9fca7b92c145810ef3f4dd159872569ef22053aad4bc6d",
    "artifact_sha256": "1b7e4dab651e034f53653d09ff3180ce26c13683dfc93c9582f40e91c2a6dc80",
    "install_plan_sha256": "545f556f42408b5497fb9c626231660fea925faa6ab236d858bb1c2743eed671",
}
SEMANTIC_PATHS = sorted(
    f"deepr_research-2.50.11.dist-info/{name}"
    for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt")
)
PHASES = (
    "admission_seconds",
    "evidence_seconds",
    "evaluation_seconds",
    "content_gate_seconds",
)
DEADLINE_SECONDS = 60


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def bounded_read(path, limit):
    require(path.is_file() and not path.is_symlink(), f"Expected regular file: {path}")
    with path.open("rb") as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, f"File exceeds its {limit}-byte bound: {path}")
    return content


def check_wheel_bytes(content):
    require(len(content) == SOURCE_BYTES, "Released wheel byte length changed")
    require(
        hashlib.sha256(content).hexdigest() == IDENTITIES["source_sha256"],
        "Released wheel SHA-256 changed",
    )


def acquire(cache):
    if cache is not None:
        content = bounded_read(cache, SOURCE_BYTES)
    else:
        request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "sealr-content-gate-ci"})
        with urllib.request.urlopen(request, timeout=30) as response:
            resolved = urllib.parse.urlsplit(response.url)
            require(
                resolved.scheme == "https"
                and resolved.hostname in {
                    "github.com",
                    "release-assets.githubusercontent.com",
                    "objects.githubusercontent.com",
                },
                "Wheel download redirected outside the allowed HTTPS release hosts",
            )
            content = response.read(SOURCE_BYTES + 1)
    check_wheel_bytes(content)
    return content


def kill_session_groups(session):
    # The example gives its verifier a separate process group in this same session.
    # Include that group when the outer deadline aborts the example.
    groups = {session}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="utf-8", errors="replace").rsplit(")", 1)[1].split()
            if int(fields[3]) == session:
                groups.add(int(fields[2]))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run(command, case):
    with subprocess.Popen(
        command,
        cwd=case,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=DEADLINE_SECONDS)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            kill_session_groups(child.pid)
            child.kill()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("Content-gate deadline cleanup did not complete within five seconds") from error
            raise
    require(len(stdout) + len(stderr) <= 1024 * 1024, "Content-gate output exceeded one MiB")
    return child.returncode, stdout, stderr


def verifier_wrapper(case, verifier, fail=False):
    wrapper = case / "verify-evidence"
    marker = case / "evidence-verified"
    if fail:
        script = "#!/bin/sh\nexit 23\n"
    else:
        script = (
            "#!/bin/sh\nset -eu\n"
            f"{shlex.quote(str(verifier))} \"$@\"\n"
            f"printf 'verified\\n' >> {shlex.quote(str(marker))}\n"
        )
    wrapper.write_text(script, encoding="utf-8", newline="\n")
    wrapper.chmod(0o500)
    return wrapper, marker


def command(example, source, manifest, verifier, retention=()):
    result = [
        str(example), "--wheel", str(source),
        "--worker-manifest", str(manifest), "--verifier", str(verifier),
    ]
    for path in retention:
        result += ["--retain-member", path]
    return result


def check_report(report, retained):
    fields = {
        "schema", "accepted", "private_source_deleted_before_evaluation", "installed_files",
        "canonical_view_sha256", "canonical_receipt_sha256", "content", "retention",
        "retained_bytes", *IDENTITIES, *PHASES,
    }
    require(isinstance(report, dict) and set(report) == fields, "Content-gate report fields changed")
    require(report["schema"] == "sealr.deepr-content-gate.v1", "Content-gate report schema changed")
    require(report["accepted"] is True, "Content decision was not accepted")
    require(
        report["private_source_deleted_before_evaluation"] is True,
        "Private source was not deleted before evaluation",
    )
    require(type(report["installed_files"]) is int and report["installed_files"] == 0,
            "The content gate reported installed files")
    for field, expected in IDENTITIES.items():
        require(report[field] == expected, f"Released wheel identity changed: {field}")
    require(report["content"] == {
        "required_files": 5, "javascript_files": 51, "css_files": 1,
    }, "Released Deepr content decision changed")
    expected_retention = [{"path": path, "status": "Retained"} for path in SEMANTIC_PATHS] if retained else []
    require(report["retention"] == expected_retention, "Requested retention was not fulfilled exactly")
    require(type(report["retained_bytes"]) is int and report["retained_bytes"] == (91_892 if retained else 0),
            "Retained byte count changed")
    for field in ("canonical_view_sha256", "canonical_receipt_sha256"):
        require(isinstance(report[field], str) and re.fullmatch(r"[0-9a-f]{64}", report[field]),
                f"Invalid canonical evidence digest: {field}")
    for field in PHASES:
        value = report[field]
        require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                f"Expected positive finite phase timing: {field}")


def accepted_case(root, label, example, manifest, verifier, content, retained):
    case = root / label
    case.mkdir()
    source = case / FILENAME
    source.write_bytes(content)
    wrapper, marker = verifier_wrapper(case, verifier)
    code, stdout, stderr = run(
        command(example, source, manifest, wrapper, SEMANTIC_PATHS if retained else ()), case,
    )
    require(code == 0, f"{label} failed ({code}):\n{stdout}\n{stderr}")
    report = json.loads(stdout)
    check_report(report, retained)
    require(bounded_read(marker, 32) == b"verified\n", "Independent verifier did not succeed exactly once")
    check_wheel_bytes(bounded_read(source, SOURCE_BYTES))
    require(set(case.iterdir()) == {source, wrapper, marker}, f"{label} wrote unexpected caller-visible files")
    print(f"Verified {label}: 5 required files, 51 JavaScript, 1 CSS, no installation", flush=True)
    return {
        "example_report": report,
        "independent_verifier_successes": 1,
        "caller_source_preserved": True,
    }


def refused_case(root, label, example, manifest, verifier, content, expected, failure_verifier=False):
    case = root / label
    case.mkdir()
    source = case / FILENAME
    source.write_bytes(content)
    wrapper, marker = verifier_wrapper(case, verifier, fail=failure_verifier)
    code, stdout, stderr = run(command(example, source, manifest, wrapper), case)
    require(code != 0 and expected in stderr, f"Expected {label} refusal {expected!r}:\n{stdout}\n{stderr}")
    require(not stdout.strip(), f"{label} emitted an acceptance report")
    require(not marker.exists(), f"{label} unexpectedly verified evidence")
    check_wheel_bytes(bounded_read(source, SOURCE_BYTES))
    require(set(case.iterdir()) == {source, wrapper}, f"{label} wrote unexpected caller-visible files")
    print(f"Verified {label}: refusal, caller source preserved, no installation", flush=True)
    return {"case": label, "refusal": expected, "caller_source_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", required=True, type=Path)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--wheel-cache", type=Path, help="Existing exact wheel file; never modified")
    parser.add_argument("--report", type=Path, help="Write the verified smoke report as JSON")
    args = parser.parse_args()
    require(sys.platform == "linux", "This smoke test requires the supported Linux worker environment")
    example = args.example.resolve(strict=True)
    native = args.native.resolve(strict=True)
    manifest = native / "libexec/sealr/sealr-worker.manifest"
    verifier = native / "sealr-identity-verifier"
    manifest_bytes = bounded_read(manifest, 16 * 1024)
    native_manifest = json.loads(manifest_bytes)
    require(native_manifest["schema"] == "sealr.worker-artifact.v1", "Unexpected native manifest schema")
    worker_bytes = bounded_read(manifest.parent / "sealr-worker", 32 * 1024 * 1024)
    require(len(worker_bytes) == native_manifest["byte_len"], "Packaged worker byte length changed")
    require(hashlib.sha256(worker_bytes).hexdigest() == native_manifest["sha256"],
            "Packaged worker SHA-256 changed")
    content = acquire(args.wheel_cache)
    with tempfile.TemporaryDirectory(prefix="sealr-deepr-content-gate-") as temporary:
        root = Path(temporary)
        accepted = {
            "baseline": accepted_case(root, "baseline", example, manifest, verifier, content, False),
            "semantic-retention": accepted_case(root, "semantic-retention", example, manifest, verifier, content, True),
        }
        # Canonical evidence includes distinct private paths. Each pair is independently
        # verified above; equality is required only for the four semantic identities.
        for field in IDENTITIES:
            require(accepted["baseline"]["example_report"][field]
                    == accepted["semantic-retention"]["example_report"][field],
                    f"Retention changed {field}")
        refused = []
        for label, field, value, expected in [
            ("worker-version", "release_version", "0.0.0-mismatch",
             "worker manifest release version does not match"),
            ("worker-target", "target", "aarch64-unknown-linux-musl",
             "worker manifest does not select the supported x86_64 Linux helper target"),
            ("worker-abi", "bootstrap_abi", 0, "worker manifest bootstrap ABI is unsupported"),
        ]:
            worker_root = root / f"{label}-native"
            worker_root.mkdir()
            copied_worker = worker_root / "sealr-worker"
            copied_worker.write_bytes(worker_bytes)
            copied_worker.chmod(0o500)
            mutated = dict(native_manifest)
            mutated[field] = value
            mutated_manifest = worker_root / "sealr-worker.manifest"
            mutated_manifest.write_text(json.dumps(mutated) + "\n", encoding="utf-8")
            refused.append(refused_case(root, label, example, mutated_manifest, verifier, content, expected))
        refused.append(refused_case(
            root, "verifier-failure", example, manifest, verifier, content,
            "independent evidence verification failed", failure_verifier=True,
        ))
    require(bounded_read(manifest, 16 * 1024) == manifest_bytes, "Native package manifest was modified")
    if args.wheel_cache is not None:
        check_wheel_bytes(bounded_read(args.wheel_cache, SOURCE_BYTES))
    report = {
        "schema": "sealr.deepr-content-gate-smoke.v1",
        "source": {"filename": FILENAME, "url": SOURCE_URL, "bytes": SOURCE_BYTES, **IDENTITIES},
        "native_release_version": native_manifest["release_version"],
        "accepted": accepted,
        "refused": refused,
        "timing_claim": "Observed phase timings only; no performance threshold or speedup claim.",
    }
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Verified two capability-only acceptance runs and four fail-closed refusals", flush=True)


if __name__ == "__main__":
    main()
