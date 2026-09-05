"""Run the pinned producer matrix through the copied public-API Linux handoff."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE = ROOT / "crates/sealr/tests/conformance"


def run(command):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        return child.returncode, stdout, stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--installer-root", required=True, type=Path)
    parser.add_argument("--python", default="/usr/bin/python3")
    args = parser.parse_args()
    vectors_bytes = (CONFORMANCE / "wheel-producers-v1.json").read_bytes()
    vectors = json.loads(vectors_bytes)
    report = json.loads((CONFORMANCE / "wheel-producers-report-v1.json").read_bytes())
    assert hashlib.sha256(vectors_bytes).hexdigest() == report["vectors_sha256"]
    observations = {f["id"]: f for f in report["fixtures"]}
    admissions = denials = 0
    with tempfile.TemporaryDirectory(prefix="sealr-producer-handoff-") as temporary:
        root = Path(temporary)
        for fixture in vectors["fixtures"]:
            expected = observations[fixture["id"]]
            admitted = fixture["expected_outcome"] == "admitted"
            inspect = None
            for mode in (["inspect", "materialize"] if admitted else ["inspect"]):
                case = root / f"{fixture['id']}-{mode}"
                case.mkdir()
                source = case / fixture["filename"]
                data = bytes.fromhex(fixture["source_hex"])
                assert hashlib.sha256(data).hexdigest() == fixture["source_sha256"]
                source.write_bytes(data)
                destination = case / "installed"
                command = [str(args.handoff), "--consume-wheel", str(source),
                           "--worker-manifest", str(args.native / "libexec/sealr/sealr-worker.manifest"),
                           "--verifier", str(args.native / "sealr-identity-verifier"),
                           "--python", args.python, "--installer-root", str(args.installer_root),
                           "--output-root", str(destination)]
                if mode == "materialize":
                    command += ["--materialize-raw", str(case / "raw")]
                code, stdout, stderr = run(command)
                if not admitted:
                    assert code != 0, (fixture["id"], "unexpected admission")
                    assert not destination.exists(), (fixture["id"], "denial wrote target")
                    assert source.read_bytes() == data, (fixture["id"], "denial consumed source")
                    boundary = "wheel admission failed" if expected["outcome"] == "archive-rejected" else "wheel evaluation did not admit"
                    assert boundary in stderr, (fixture["id"], stderr)
                    denials += 1
                    continue
                assert code == 0, (fixture["id"], stdout, stderr)
                observed = json.loads(stdout.splitlines()[-1])
                assert observed["schema"] == "sealr.pypa-wheel-source-example.v1"
                assert observed["source_deleted_before_python"] is True
                assert not source.exists()
                assert observed["installed_files"] == 14
                assert observed["raw_materialized"] == (mode == "materialize")
                for field in ["source_sha256", "archive_tree_sha256", "artifact_sha256", "install_plan_sha256"]:
                    assert observed[field] == expected["identities"][field], (fixture["id"], field)
                if inspect is None:
                    inspect = observed
                else:
                    for field in ["source_sha256", "archive_tree_sha256", "artifact_sha256", "install_plan_sha256", "realization_sha256"]:
                        assert inspect[field] == observed[field], (fixture["id"], field)
                admissions += 1
                print(f"Verified {fixture['id']} through supervised {mode}, evidence, source deletion, installer, and output audit", flush=True)
    assert (admissions, denials) == (12, 18)
    print(f"Verified {admissions} complete installations and {denials} fail-closed refusals")


if __name__ == "__main__":
    main()
