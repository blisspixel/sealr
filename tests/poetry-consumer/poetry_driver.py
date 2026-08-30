#!/usr/bin/env python3
"""Exercise the packaged WheelSource handoff through exact Poetry 2.4.2."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import http.server
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable
import zipfile


WHEEL_FILENAME = "demo-1.0-py3-none-any.whl"
WHEEL_SHA256 = "078364afdeda960f1e0df0959d9cafcdb067b2c3c8c2999c0cea7cd521c466ec"
ARCHIVE_TREE_SHA256 = "7336763b06639d2cc5a1ee004adf6c42a0a15e6ace846e0457299f3010011f82"
ARTIFACT_SHA256 = "986f82074b5ac802253ba317579bf1500a28947e022b0c27581180ea05004c55"
INSTALL_PLAN_SHA256 = "54b263d0c136a522fa08e0b5d582a5bdfb5203af970e5a84c786ef549a19dac8"
POETRY_WHEEL_SHA256 = "a506d6ff7fcc54a3472b2618145b8e4a1ef8d76d52836d41b813fa1b36083a08"
EXECUTOR_SOURCE_SHA256 = "b6f3b05fe2451ddb02057a353cfa2ffff18f185766c1bb3655fd411c14b3df13"
WHEEL_INSTALLER_SOURCE_SHA256 = "5502c48146e830116a0154130f97695f450720c9a445098a4877eff917d19734"
PREPARED_SCHEMA = "sealr.pypa-wheel-source-prepared.v1"
SUCCESS_SCHEMA = "sealr.pypa-wheel-source-example.v1"
TARGET_MODEL = "poetry-2.4.2-installer-1.0.1-linux-posix"
INSTALLER_POLICY = "poetry-2.4.2-cpython-3.12-venv-no-bytecode-no-overwrite-v1"
EXPECTED_REALIZATION_SHA256 = "76a81ee48ebc43ff7d6f60440dce5edd047f13f3ac9a6663fbe3f52322566142"
RUNTIME_ROOT = Path("/tmp/sealr-poetry-2.4.2-fixture")
PREPARED_KEYS = {
    "schema",
    "context_sha256",
    "source_deleted",
    "target_model",
    "installer_policy",
    "canonical_receipt_sha256",
    "source_sha256",
    "archive_tree_sha256",
    "artifact_sha256",
    "install_plan_sha256",
}
SUCCESS_KEYS = {
    "schema",
    "source_deleted_before_python",
    "target_model",
    "installer_policy",
    "canonical_view_sha256",
    "canonical_receipt_sha256",
    "source_sha256",
    "archive_tree_sha256",
    "artifact_sha256",
    "install_plan_sha256",
    "realization_sha256",
    "installed_files",
    "raw_materialized",
    "context_sha256",
}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
REQUIREMENT = re.compile(
    r"([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})"
)
PROCESS_TIMEOUT = 300.0
MAX_PROTOCOL_LINE = 64 * 1024
MAX_STDERR = 128 * 1024


class FixtureError(RuntimeError):
    pass


class WheelOpenDenied(PermissionError):
    pass


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise FixtureError(detail)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_bytes().decode("utf-8"),
            object_pairs_hook=duplicate_safe_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                FixtureError(f"JSON contains forbidden number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"invalid strict JSON in {path}: {error}") from error


def requirement_set(paths: list[Path]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = REQUIREMENT.fullmatch(line)
            require(match is not None, f"non-exact requirement in {path}: {line}")
            name, version, digest = match.groups()
            key = normalized_name(name)
            require(key not in result, f"duplicate requirement: {name}")
            result[key] = (version, digest)
    return result


def verify_wheelhouse(
    wheelhouse: Path,
    manifest_path: Path,
    requirements: list[Path],
) -> dict[str, Path]:
    manifest = load_json(manifest_path)
    require(type(manifest) is dict, "wheelhouse manifest must be an object")
    require(
        set(manifest) == {"schema", "platform", "resolved_at", "resolver", "artifacts"},
        "wheelhouse manifest schema is not closed",
    )
    require(
        manifest["schema"] == "sealr.poetry-2.4.2-wheelhouse.v1",
        "wheelhouse manifest schema changed",
    )
    require(
        manifest["platform"] == "ubuntu-24.04-x86_64-cpython-3.12",
        "wheelhouse platform changed",
    )
    require(manifest["resolved_at"] == "2026-08-30", "resolution date changed")
    require(manifest["resolver"] == "uv 0.11.33", "resolver identity changed")
    artifacts = manifest["artifacts"]
    require(type(artifacts) is list and len(artifacts) == 47, "wheelhouse must bind 47 wheels")
    bound: dict[str, Path] = {}
    role_counts = {"poetry-runtime": 0, "target-bootstrap": 0}
    previous = ""
    for offset, artifact in enumerate(artifacts):
        require(type(artifact) is dict, f"artifact {offset} must be an object")
        require(
            set(artifact) == {"filename", "bytes", "sha256", "role"},
            f"artifact {offset} schema is not closed",
        )
        filename = artifact["filename"]
        require(
            type(filename) is str
            and filename.endswith(".whl")
            and Path(filename).name == filename,
            f"artifact {offset} filename is invalid",
        )
        require(filename.casefold() > previous.casefold(), "artifacts must be sorted by filename")
        previous = filename
        size = artifact["bytes"]
        digest = artifact["sha256"]
        role = artifact["role"]
        require(type(size) is int and size > 0, f"artifact {filename} size is invalid")
        require(type(digest) is str and HEX_SHA256.fullmatch(digest) is not None, f"artifact {filename} digest is invalid")
        require(role in role_counts, f"artifact {filename} role is invalid")
        role_counts[role] += 1
        path = wheelhouse / filename
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, f"artifact {filename} must be a single-link regular file")
        require(info.st_size == size, f"artifact {filename} size changed")
        require(sha256_file(path) == digest, f"artifact {filename} digest changed")
        require(filename not in bound, f"duplicate wheelhouse filename: {filename}")
        bound[filename] = path
    require(role_counts == {"poetry-runtime": 46, "target-bootstrap": 1}, "wheelhouse roles changed")
    observed = {entry.name for entry in wheelhouse.iterdir()}
    require(observed == set(bound), "wheelhouse file set differs from its manifest")

    pinned = requirement_set(requirements)
    require(len(pinned) == 47, "requirements must pin 47 distributions")
    installed: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = normalized_name(distribution.metadata["Name"])
        require(name not in installed, f"controller contains duplicate distribution {name}")
        installed[name] = distribution.version
    require(
        installed == {name: value[0] for name, value in pinned.items()},
        f"controller distribution set changed: {installed}",
    )
    poetry_wheel = bound.get("poetry-2.4.2-py3-none-any.whl")
    require(poetry_wheel is not None and sha256_file(poetry_wheel) == POETRY_WHEEL_SHA256, "Poetry wheel changed")
    return bound


def verify_platform() -> None:
    require(sys.implementation.name == "cpython", "fixture requires CPython")
    require(sys.version_info[:2] == (3, 12), "fixture requires CPython 3.12")
    require(platform.machine() == "x86_64", "fixture requires x86_64")
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04", "fixture requires Ubuntu 24.04")


def run_checked(argv: list[str], *, timeout: float = PROCESS_TIMEOUT) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "NO_PROXY": "127.0.0.1,localhost",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
    )
    if result.returncode != 0:
        raise FixtureError(
            f"command failed ({result.returncode}): {argv!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def record_hash(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=")
    return f"sha256={encoded.decode('ascii')}"


def build_old_wheel(path: Path) -> None:
    require(not path.exists(), "old fixture wheel path must be new")
    members = {
        "demo/__init__.py": b'__version__ = "0.9"\n',
        "demo-0.9.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: demo\nVersion: 0.9\nSummary: Sealr Poetry update fixture\n\n"
        ),
        "demo-0.9.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
        ),
    }
    rows = [
        (name, record_hash(value), str(len(value))) for name, value in members.items()
    ]
    rows.append(("demo-0.9.dist-info/RECORD", "", ""))
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    members["demo-0.9.dist-info/RECORD"] = buffer.getvalue().encode("utf-8")
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, value in members.items():
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, value, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def create_target(target: Path, pip_wheel: Path, old_wheel: Path) -> None:
    require(not target.exists(), f"target already exists: {target}")
    run_checked(["/usr/bin/python3", "-m", "venv", "--without-pip", "--copies", str(target)])
    python = target / "bin/python"
    run_checked(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--python",
            str(python),
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            str(pip_wheel),
        ]
    )
    install_old(target, old_wheel)


def install_old(target: Path, old_wheel: Path) -> None:
    run_checked(
        [
            str(target / "bin/python"),
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--force-reinstall",
            str(old_wheel),
        ]
    )
    require_demo(target, "0.9")


def uninstall_demo(target: Path) -> None:
    run_checked([str(target / "bin/python"), "-I", "-m", "pip", "uninstall", "demo", "-y"])


def demo_version(target: Path) -> str | None:
    script = (
        "import importlib.metadata, json\n"
        "try:\n"
        " print(json.dumps(importlib.metadata.version('demo')))\n"
        "except importlib.metadata.PackageNotFoundError:\n"
        " print('null')\n"
    )
    result = run_checked([str(target / "bin/python"), "-I", "-B", "-c", script])
    return json.loads(result.stdout)


def require_demo(target: Path, version: str | None) -> None:
    require(demo_version(target) == version, f"target demo version must be {version!r}")


def verify_bridge_physical_antichain(bridge_path: Path, target: Path) -> None:
    script = r'''
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("sealr_wheel_source_antichain", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not load exact WheelSource bridge")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
root = Path(sys.argv[2])
purelib = root / "lib/python3.12/site-packages"
schemes = {
    "purelib": str(purelib),
    "platlib": str(purelib),
    "scripts": str(root / "bin"),
    "headers": str(root / "include/site/python3.12/demo"),
    "data": str(root),
}

def require_denied(first_scheme, first_path, second_scheme, second_path):
    physical = set()
    bridge._validate_poetry_output_target(
        root, schemes, first_scheme, first_path, physical
    )
    try:
        bridge._validate_poetry_output_target(
            root, schemes, second_scheme, second_path, physical
        )
    except bridge.HandoffError as error:
        if "physical file-ancestor conflict" not in str(error):
            raise
    else:
        raise SystemExit("physical file-ancestor collision was accepted")

require_denied(
    "purelib", "sealr-antichain", "data",
    "lib/python3.12/site-packages/sealr-antichain/child",
)
require_denied(
    "data", "lib/python3.12/site-packages/sealr-antichain/child",
    "purelib", "sealr-antichain",
)
print("physical-antichain-denied")
'''
    result = run_checked(
        [sys.executable, "-I", "-B", "-c", script, str(bridge_path), str(target)]
    )
    require(result.stdout.strip() == "physical-antichain-denied", "bridge antichain oracle changed")


def tree_snapshot(root: Path) -> tuple[str, list[dict[str, Any]]]:
    require(root.is_absolute(), "snapshot root must be absolute")
    records: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if entry.name == "__pycache__" or entry.name.endswith((".pyc", ".pyo")):
                continue
            info = os.lstat(path)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                records.append({"path": relative, "type": "link", "mode": mode, "target": os.readlink(path)})
            elif stat.S_ISDIR(info.st_mode):
                records.append({"path": relative, "type": "directory", "mode": mode})
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                records.append(
                    {
                        "path": relative,
                        "type": "file",
                        "mode": mode,
                        "bytes": info.st_size,
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise FixtureError(f"target contains unsupported filesystem object: {relative}")
    records.sort(key=lambda item: item["path"])
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded), records


class WheelServer:
    def __init__(self, wheel: bytes) -> None:
        self.wheel = wheel
        self.requests: list[str] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:
                return

            def do_HEAD(self) -> None:
                self._respond(head_only=True)

            def do_GET(self) -> None:
                self._respond(head_only=False)

            def _respond(self, *, head_only: bool) -> None:
                owner.requests.append(self.path)
                if self.path in {"/simple/demo", "/simple/demo/"}:
                    body = (
                        f'<a href="/packages/{WHEEL_FILENAME}" data-requires-python=">=3.12">'
                        f"{WHEEL_FILENAME}</a>\n"
                    ).encode("utf-8")
                    content_type = "text/html; charset=utf-8"
                elif self.path == f"/packages/{WHEEL_FILENAME}":
                    body = owner.wheel
                    content_type = "application/octet-stream"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}/simple"

    def __enter__(self) -> WheelServer:
        self.thread.start()
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), "loopback repository did not stop")


class HandoffSession:
    def __init__(self, process: subprocess.Popen[bytes], stderr: Any, context: str) -> None:
        self.process = process
        self.stderr = stderr
        self.context = context

    def read_report(self) -> dict[str, Any]:
        stdout = self.process.stdout
        require(stdout is not None, "handoff stdout is unavailable")
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + PROCESS_TIMEOUT
        encoded = bytearray()
        try:
            while b"\n" not in encoded:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "handoff protocol exceeded its deadline")
                events = selector.select(remaining)
                require(bool(events), "handoff protocol exceeded its deadline")
                chunk = os.read(stdout.fileno(), 4096)
                require(chunk, "handoff closed stdout before a report")
                encoded.extend(chunk)
                require(len(encoded) <= MAX_PROTOCOL_LINE, "handoff protocol line exceeded its cap")
        finally:
            selector.close()
        line, separator, trailing = bytes(encoded).partition(b"\n")
        require(separator == b"\n" and not trailing, "handoff emitted trailing protocol bytes")
        try:
            report = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=duplicate_safe_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    FixtureError(f"protocol contains forbidden number {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FixtureError(f"handoff report is not strict JSON: {error}") from error
        require(type(report) is dict, "handoff report must be an object")
        return report

    def stderr_text(self) -> str:
        self.stderr.flush()
        self.stderr.seek(0)
        data = self.stderr.read(MAX_STDERR + 1)
        require(len(data) <= MAX_STDERR, "handoff stderr exceeded its cap")
        return data.decode("utf-8", errors="replace")

    def wait(self) -> int:
        try:
            return self.process.wait(timeout=PROCESS_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            self.terminate()
            raise FixtureError("handoff process exceeded its deadline") from error

    def require_stdout_eof(self) -> None:
        require(self.process.poll() is not None, "stdout EOF check requires an exited handoff")
        stdout = self.process.stdout
        require(stdout is not None, "handoff stdout is unavailable")
        require(stdout.read(MAX_PROTOCOL_LINE + 1) == b"", "handoff emitted trailing protocol bytes")

    def terminate(self) -> None:
        if self.process.poll() is None:
            descendants = self._descendants(self.process.pid)
            for process_id in reversed(descendants):
                try:
                    os.kill(process_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=10)

    @staticmethod
    def _descendants(process_id: int) -> list[int]:
        result: list[int] = []
        pending = [process_id]
        seen = {process_id}
        while pending:
            parent = pending.pop()
            children_path = Path(f"/proc/{parent}/task/{parent}/children")
            try:
                children = children_path.read_text(encoding="ascii").split()
            except (FileNotFoundError, ProcessLookupError):
                continue
            for child_text in children:
                child = int(child_text)
                if child in seen:
                    continue
                seen.add(child)
                result.append(child)
                pending.append(child)
        return result

    def close(self) -> None:
        self.terminate()
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()
        self.stderr.close()


class Harness:
    def __init__(
        self,
        *,
        mode: str,
        target: Path,
        handoff: Path,
        worker_manifest: Path,
        verifier: Path,
        installer_root: Path,
        decoy: Path,
    ) -> None:
        self.mode = mode
        self.target = target
        self.handoff = handoff
        self.worker_manifest = worker_manifest
        self.verifier = verifier
        self.installer_root = installer_root
        self.decoy = decoy
        self.before = tree_snapshot(target)
        self.events: list[str] = []
        self.archive: Path | None = None
        self.shared_archive: Path | None = None
        self.session: HandoffSession | None = None
        self.prepared: dict[str, Any] | None = None
        self.success: dict[str, Any] | None = None
        self.wheel_installer_calls = 0
        self.uninstall_calls = 0
        self.failure: str | None = None
        self._wheel_guard_installed = False
        self._deny_wheel_opens = False

    def context(self) -> str:
        material = f"sealr-poetry-2.4.2:{self.mode}:{WHEEL_SHA256}:{self.before[0]}"
        return sha256_bytes(material.encode("ascii"))

    def private_source(self, shared_archive: Path) -> Path:
        info = shared_archive.lstat()
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), "Poetry cache artifact is not a regular file")
        require(sha256_file(shared_archive) == WHEEL_SHA256, "Poetry cache artifact changed after lock validation")
        directory = self.decoy.parent / f"{self.mode}-consumed-source"
        directory.mkdir(mode=0o700)
        path = directory / WHEEL_FILENAME
        with shared_archive.open("rb") as source, path.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        path.chmod(0o600)
        require(sha256_file(path) == WHEEL_SHA256, "private consumed copy changed")
        self.shared_archive = shared_archive
        return path

    def start(self, archive: Path) -> None:
        context = self.context()
        self._install_wheel_open_guard()
        stderr = tempfile.TemporaryFile(mode="w+b")
        process = subprocess.Popen(
            [
                str(self.handoff),
                "--consume-wheel",
                str(archive),
                "--worker-manifest",
                str(self.worker_manifest),
                "--verifier",
                str(self.verifier),
                "--python",
                "/usr/bin/python3",
                "--installer-root",
                str(self.installer_root),
                "--output-root",
                str(self.target),
                "--poetry-2-4-2-update",
                context,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            start_new_session=True,
        )
        self.session = HandoffSession(process, stderr, context)
        report = self.session.read_report()
        self._deny_wheel_opens = True
        require(set(report) == PREPARED_KEYS, "prepared report schema is not closed")
        require(report["schema"] == PREPARED_SCHEMA, "prepared report schema changed")
        require(report["context_sha256"] == context, "prepared context changed")
        require(report["source_deleted"] is True, "prepared report did not confirm source deletion")
        require(report["target_model"] == TARGET_MODEL, "prepared target model changed")
        require(report["installer_policy"] == INSTALLER_POLICY, "prepared installer policy changed")
        require(report["source_sha256"] == WHEEL_SHA256, "prepared source identity changed")
        require(report["archive_tree_sha256"] == ARCHIVE_TREE_SHA256, "prepared archive-tree identity changed")
        require(report["artifact_sha256"] == ARTIFACT_SHA256, "prepared artifact identity changed")
        require(report["install_plan_sha256"] == INSTALL_PLAN_SHA256, "prepared plan identity changed")
        require(HEX_SHA256.fullmatch(report["canonical_receipt_sha256"]) is not None, "prepared receipt digest is invalid")
        require(not archive.exists() and not archive.is_symlink(), "prepared source still exists")
        require(
            self.shared_archive is not None
            and self.shared_archive.exists()
            and stat.S_ISREG(self.shared_archive.lstat().st_mode)
            and not self.shared_archive.is_symlink(),
            "handoff consumed Poetry's shared cache artifact",
        )
        require(tree_snapshot(self.target) == self.before, "prepared handoff changed the target")
        require_demo(self.target, "0.9")
        self.prepared = report
        self.events.append("prepared")

    def abort_after_prepared(self) -> None:
        require(self.session is not None, "abort requires a handoff session")
        stdin = self.session.process.stdin
        require(stdin is not None, "handoff stdin is unavailable")
        stdin.close()
        status = self.session.wait()
        error = self.session.stderr_text()
        require(status != 0, "handoff accepted EOF as an install permit")
        require("input closed before authorization" in error, "handoff EOF failure changed")
        require(tree_snapshot(self.target) == self.before, "aborted handoff changed the target")
        require_demo(self.target, "0.9")
        self.events.append("protocol-eof-denied")

    def _install_wheel_open_guard(self) -> None:
        require(not self._wheel_guard_installed, "wheel-open guard was installed twice")

        def audit(event: str, arguments: tuple[Any, ...]) -> None:
            if not self._deny_wheel_opens or event != "open" or not arguments:
                return
            value = arguments[0]
            if isinstance(value, bytes):
                value = os.fsdecode(value)
            if isinstance(value, str) and value.casefold().endswith(".whl"):
                raise WheelOpenDenied("wheel opens are forbidden after PREPARED")

        sys.addaudithook(audit)
        self._wheel_guard_installed = True

    def probe_wheel_open_guard(self) -> None:
        require(self._wheel_guard_installed and self._deny_wheel_opens, "wheel-open guard is inactive")
        try:
            with self.decoy.open("rb"):
                pass
        except WheelOpenDenied:
            self.events.append("wheel-open-probe-denied")
        else:
            raise FixtureError("post-PREPARED wheel-open probe was accepted")

    def audit_pip(
        self,
        args: tuple[str, ...],
        kwargs: dict[str, Any],
        delegate: Callable[..., str],
    ) -> str:
        require(self.mode == "adapted", "abort case reached Poetry uninstall")
        require(args == ("uninstall", "demo", "-y") and not kwargs, "Poetry pip uninstall command changed")
        require(self.prepared is not None, "Poetry uninstall began before PREPARED")
        require(self.archive is not None and not self.archive.exists(), "Poetry uninstall began before source deletion")
        require(tree_snapshot(self.target) == self.before, "target changed before real Poetry uninstall")
        require_demo(self.target, "0.9")
        self.uninstall_calls += 1
        self.events.append("real-uninstall-entered")
        result = delegate(*args, **kwargs)
        require_demo(self.target, None)
        self.events.append("real-uninstall-returned")
        return result

    def authorize_install(self, archive: Path) -> None:
        require(self.mode == "adapted", "abort case reached the install proxy")
        require(self.session is not None and self.prepared is not None, "install proxy lacks prepared authority")
        require(self.archive == archive and not archive.exists(), "install proxy received the wrong live archive")
        require(self.uninstall_calls == 1, "install proxy ran before one real uninstall")
        require_demo(self.target, None)
        self.wheel_installer_calls += 1
        stdin = self.session.process.stdin
        require(stdin is not None, "handoff stdin is unavailable")
        self.events.append("permit-written")
        stdin.write(f"install {self.session.context}\n".encode("ascii"))
        stdin.flush()
        stdin.close()
        report = self.session.read_report()
        status = self.session.wait()
        self.session.require_stdout_eof()
        error = self.session.stderr_text()
        require(status == 0, f"handoff failed after permit: {error}")
        require(set(report) == SUCCESS_KEYS, "success report schema is not closed")
        require(report["schema"] == SUCCESS_SCHEMA, "success report schema changed")
        require(report["context_sha256"] == self.session.context, "success context changed")
        require(report["source_deleted_before_python"] is True, "success report lost source ordering")
        require(report["target_model"] == TARGET_MODEL, "success target model changed")
        require(report["installer_policy"] == INSTALLER_POLICY, "success installer policy changed")
        require(report["source_sha256"] == WHEEL_SHA256, "success source identity changed")
        require(report["archive_tree_sha256"] == ARCHIVE_TREE_SHA256, "success archive-tree identity changed")
        require(report["artifact_sha256"] == ARTIFACT_SHA256, "success artifact identity changed")
        require(report["install_plan_sha256"] == INSTALL_PLAN_SHA256, "success plan identity changed")
        require(report["raw_materialized"] is False, "Poetry fixture unexpectedly materialized a raw tree")
        require(type(report["installed_files"]) is int and report["installed_files"] > 0, "success file count is invalid")
        for key in ("canonical_view_sha256", "canonical_receipt_sha256", "realization_sha256"):
            require(type(report[key]) is str and HEX_SHA256.fullmatch(report[key]) is not None, f"success {key} is invalid")
        require(
            report["canonical_receipt_sha256"] == self.prepared["canonical_receipt_sha256"],
            "prepared and success receipts differ",
        )
        require(report["realization_sha256"] == EXPECTED_REALIZATION_SHA256, "realization identity changed")
        self.success = report
        self.events.append("handoff-completed")

    def close(self) -> None:
        self._deny_wheel_opens = False
        if self.session is not None:
            self.session.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--worker-manifest", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--installer-root", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--wheelhouse-manifest", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--pip-requirement", type=Path, required=True)
    parser.add_argument("--controlled-wheel", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    return parser.parse_args()


def exact_path(path: Path, *, kind: str) -> Path:
    require(path.is_absolute(), f"{kind} path must be absolute")
    info = path.lstat()
    if kind == "directory":
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), f"{path} must be a real directory")
    else:
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), f"{path} must be a regular file")
    return path


def main() -> int:
    args = parse_args()
    verify_platform()
    for path in (
        args.handoff,
        args.bridge,
        args.worker_manifest,
        args.verifier,
        args.wheelhouse_manifest,
        args.requirements,
        args.pip_requirement,
        args.controlled_wheel,
    ):
        exact_path(path, kind="file")
    for path in (args.installer_root, args.wheelhouse, args.project, args.runtime):
        exact_path(path, kind="directory")
    require(args.runtime == RUNTIME_ROOT, f"runtime must be exactly {RUNTIME_ROOT}")
    require(sha256_file(args.controlled_wheel) == WHEEL_SHA256, "controlled wheel digest changed")
    wheels = verify_wheelhouse(
        args.wheelhouse,
        args.wheelhouse_manifest,
        [args.requirements, args.pip_requirement],
    )

    from cleo.io.null_io import NullIO
    from poetry.__version__ import __version__ as poetry_version
    from poetry.config.config import Config
    from poetry.factory import Factory
    from poetry.installation.executor import Executor
    from poetry.installation.operations import Update
    import poetry.installation.executor as executor_module
    import poetry.installation.wheel_installer as wheel_installer_module
    from poetry.repositories import RepositoryPool
    from poetry.repositories.installed_repository import InstalledRepository
    from poetry.repositories.legacy_repository import LegacyRepository
    from poetry.utils.env import VirtualEnv

    require(poetry_version == "2.4.2", "Poetry version changed")
    require(importlib.metadata.version("poetry-core") == "2.4.0", "poetry-core version changed")
    require(importlib.metadata.version("installer") == "1.0.1", "installer version changed")
    require(sha256_file(Path(executor_module.__file__)) == EXECUTOR_SOURCE_SHA256, "Poetry executor source changed")
    require(
        sha256_file(Path(wheel_installer_module.__file__)) == WHEEL_INSTALLER_SOURCE_SHA256,
        "Poetry wheel installer source changed",
    )

    poetry = Factory().create_poetry(args.project, disable_plugins=True, disable_cache=True)
    require(poetry.locker.is_locked() and poetry.locker.is_fresh(), "committed Poetry lock is missing or stale")
    locked = poetry.locker.locked_repository().packages
    require(len(locked) == 1, "Poetry lock must contain one package")
    target_package = locked[0]
    require(target_package.name == "demo" and str(target_package.version) == "1.0", "locked package changed")
    require(
        target_package.files == [{"file": WHEEL_FILENAME, "hash": f"sha256:{WHEEL_SHA256}"}],
        "locked wheel file set changed",
    )
    lock_before = (args.project / "poetry.lock").read_bytes()

    old_wheel = args.runtime / "demo-0.9-py3-none-any.whl"
    decoy = args.runtime / "post-prepared-probe.whl"
    build_old_wheel(old_wheel)
    decoy.write_bytes(b"post-PREPARED wheel-open probe\n")
    pip_wheel = wheels["pip-26.2.1-py3-none-any.whl"]
    controlled_bytes = args.controlled_wheel.read_bytes()

    class ObservedVirtualEnv(VirtualEnv):
        observer: Callable[[tuple[str, ...], dict[str, Any], Callable[..., str]], str] | None = None

        def run_pip(self, *pip_args: str, **kwargs: Any) -> str:
            delegate = super().run_pip
            if self.observer is None:
                return delegate(*pip_args, **kwargs)
            return self.observer(pip_args, kwargs, delegate)

    class SealrExecutor(Executor):
        harness: Harness

        def _download(self, operation: Any) -> Path:
            archive = super()._download(operation)
            self.harness.events.append("poetry-download-returned")
            require(operation.job_type == "update", "fixture expected one Poetry update")
            require(operation.initial_package.name == "demo" and str(operation.initial_package.version) == "0.9", "initial package changed")
            require(operation.target_package is target_package, "executor did not receive the committed lock package")
            require(archive.name == WHEEL_FILENAME, "Poetry selected an unlisted filename")
            require(sha256_file(archive) == WHEEL_SHA256, "Poetry returned unexpected wheel bytes")
            require(self._hashes.get("demo") == f"sha256:{WHEEL_SHA256}", "Poetry lock hash was not accepted")
            self.harness.events.append("poetry-lock-hash-confirmed")
            archive = self.harness.private_source(archive)
            self.harness.archive = archive
            try:
                self.harness.start(archive)
            except Exception as error:
                detail = str(error)
                if self.harness.session is not None:
                    status = self.harness.session.wait()
                    detail += f"; handoff status {status}: {self.harness.session.stderr_text()}"
                self.harness.failure = detail
                raise
            if self.harness.mode == "abort":
                self.harness.abort_after_prepared()
                raise FixtureError("fixture abort after PREPARED")
            self.harness.probe_wheel_open_guard()
            return archive

    require(SealrExecutor._install is Executor._install, "fixture replaced Poetry _install")
    require(SealrExecutor._remove is Executor._remove, "fixture replaced Poetry _remove")

    class PermitProxy:
        invalid_wheels: dict[Path, list[str]] = {}

        def __init__(self, harness: Harness) -> None:
            self.harness = harness

        def install(self, archive: Path) -> None:
            self.harness.authorize_install(archive)

        def enable_bytecode_compilation(self, enable: bool = True) -> None:
            require(not enable, "Poetry fixture must keep bytecode disabled")

    def config_for(cache: Path) -> Config:
        config = Config(use_environment=False)
        config.merge(
            {
                "cache-dir": str(cache),
                "installer": {
                    "parallel": False,
                    "re-resolve": False,
                    "only-binary": [":all:"],
                },
                "keyring": {"enabled": False},
                "requests": {"max-retries": 0},
            }
        )
        return config

    def operation_for(env: VirtualEnv) -> Update:
        installed = [package for package in InstalledRepository.load(env).packages if package.name == "demo"]
        require(len(installed) == 1 and str(installed[0].version) == "0.9", "target must contain exactly demo 0.9")
        return Update(installed[0], target_package)

    def pool_for(config: Config, repository_url: str) -> RepositoryPool:
        repository = LegacyRepository(
            "sealr-fixture",
            repository_url,
            config=config,
            disable_cache=True,
            pool_size=1,
        )
        return RepositoryPool([repository], config=config)

    primary = args.runtime / "stable-target"
    abort_target = args.runtime / "abort-target"
    symlink_target = args.runtime / "symlink-target"
    symlink_outside = args.runtime / "symlink-outside"
    create_target(primary, pip_wheel, old_wheel)
    create_target(abort_target, pip_wheel, old_wheel)
    create_target(symlink_target, pip_wheel, old_wheel)
    symlink_outside.mkdir(mode=0o700)
    symlink_sentinel = symlink_outside / "sentinel"
    symlink_sentinel.write_bytes(b"outside target namespace\n")
    symlink_path = symlink_target / "include/site"
    require(not symlink_path.exists() and not symlink_path.is_symlink(), "symlink gate path already exists")
    symlink_path.symlink_to(symlink_outside, target_is_directory=True)
    initial_snapshot = tree_snapshot(primary)
    abort_snapshot = tree_snapshot(abort_target)
    symlink_snapshot = tree_snapshot(symlink_target)
    symlink_sentinel_before = tree_snapshot(symlink_outside)
    verify_bridge_physical_antichain(args.bridge, symlink_target)

    with WheelServer(controlled_bytes) as server:
        stock_config = config_for(args.runtime / "stock-cache")
        stock_env = ObservedVirtualEnv(primary)
        stock_uninstall_events: list[str] = []

        def observe_stock(
            pip_args: tuple[str, ...],
            kwargs: dict[str, Any],
            delegate: Callable[..., str],
        ) -> str:
            require(pip_args == ("uninstall", "demo", "-y") and not kwargs, "stock uninstall changed")
            require(tree_snapshot(primary) == initial_snapshot, "stock target changed before uninstall")
            stock_uninstall_events.append("entered")
            result = delegate(*pip_args, **kwargs)
            require_demo(primary, None)
            stock_uninstall_events.append("returned")
            return result

        stock_env.observer = observe_stock
        stock_pool = pool_for(stock_config, server.url)
        stock_executor = Executor(
            stock_env,
            stock_pool,
            stock_config,
            NullIO(),
            parallel=False,
            disable_cache=True,
        )
        require(type(stock_executor) is Executor, "stock control must use exact Poetry Executor")
        require(type(stock_executor._wheel_installer) is wheel_installer_module.WheelInstaller, "stock control installer changed")
        require(stock_executor.execute([operation_for(stock_env)]) == 0, "stock Poetry update failed")
        stock_executor._executor.shutdown(wait=True)
        require(stock_executor.updates_count == 1 and stock_executor.installations_count == 0 and stock_executor.removals_count == 0, "stock operation counts changed")
        require(stock_uninstall_events == ["entered", "returned"], "stock uninstall ordering changed")
        require_demo(primary, "1.0")
        stock_snapshot = tree_snapshot(primary)
        installer_file = primary / "lib/python3.12/site-packages/demo-1.0.dist-info/INSTALLER"
        require(installer_file.read_bytes() == b"Poetry 2.4.2", "stock INSTALLER metadata changed")

        uninstall_demo(primary)
        require_demo(primary, None)
        for empty in (
            primary / "include/site/python3.12",
            primary / "include/site",
        ):
            if empty.exists():
                require(not any(empty.iterdir()), f"stock uninstall left populated directory {empty}")
                empty.rmdir()
        install_old(primary, old_wheel)
        restored_snapshot = tree_snapshot(primary)
        if restored_snapshot != initial_snapshot:
            initial_by_path = {item["path"]: item for item in initial_snapshot[1]}
            restored_by_path = {item["path"]: item for item in restored_snapshot[1]}
            changed = [
                path
                for path in sorted(set(initial_by_path) | set(restored_by_path))
                if initial_by_path.get(path) != restored_by_path.get(path)
            ]
            raise FixtureError(f"stable target did not restore exactly: {changed[:20]}")

        abort_harness = Harness(
            mode="abort",
            target=abort_target,
            handoff=args.handoff,
            worker_manifest=args.worker_manifest,
            verifier=args.verifier,
            installer_root=args.installer_root,
            decoy=decoy,
        )
        try:
            abort_config = config_for(args.runtime / "abort-cache")
            abort_env = ObservedVirtualEnv(abort_target)

            def reject_abort_uninstall(
                _pip_args: tuple[str, ...],
                _kwargs: dict[str, Any],
                _delegate: Callable[..., str],
            ) -> str:
                raise FixtureError("abort case reached Poetry uninstall")

            abort_env.observer = reject_abort_uninstall
            abort_executor = SealrExecutor(
                abort_env,
                pool_for(abort_config, server.url),
                abort_config,
                NullIO(),
                parallel=False,
                disable_cache=True,
            )
            abort_executor.harness = abort_harness
            abort_executor._wheel_installer = PermitProxy(abort_harness)
            require(abort_executor.execute([operation_for(abort_env)]) == 1, "abort case did not fail closed")
            require(abort_executor.updates_count == 0, "abort case counted an update")
            expected_abort_events = [
                "poetry-download-returned",
                "poetry-lock-hash-confirmed",
                "prepared",
                "protocol-eof-denied",
            ]
            require(
                abort_harness.events == expected_abort_events,
                f"abort event order changed: {abort_harness.events}; {abort_harness.failure}",
            )
            require(tree_snapshot(abort_target) == abort_snapshot, "abort target changed")
            require_demo(abort_target, "0.9")
            require(abort_harness.wheel_installer_calls == 0 and abort_harness.uninstall_calls == 0, "abort crossed the uninstall boundary")
        finally:
            abort_harness.close()

        symlink_harness = Harness(
            mode="symlink",
            target=symlink_target,
            handoff=args.handoff,
            worker_manifest=args.worker_manifest,
            verifier=args.verifier,
            installer_root=args.installer_root,
            decoy=decoy,
        )
        try:
            symlink_config = config_for(args.runtime / "symlink-cache")
            symlink_env = ObservedVirtualEnv(symlink_target)

            def reject_symlink_uninstall(
                _pip_args: tuple[str, ...],
                _kwargs: dict[str, Any],
                _delegate: Callable[..., str],
            ) -> str:
                raise FixtureError("symlink case reached Poetry uninstall")

            symlink_env.observer = reject_symlink_uninstall
            symlink_executor = SealrExecutor(
                symlink_env,
                pool_for(symlink_config, server.url),
                symlink_config,
                NullIO(),
                parallel=False,
                disable_cache=True,
            )
            symlink_executor.harness = symlink_harness
            symlink_executor._wheel_installer = PermitProxy(symlink_harness)
            require(symlink_executor.execute([operation_for(symlink_env)]) == 1, "symlink case did not fail closed")
            require(symlink_executor.updates_count == 0, "symlink case counted an update")
            require(
                symlink_harness.events == ["poetry-download-returned", "poetry-lock-hash-confirmed"],
                f"symlink event order changed: {symlink_harness.events}",
            )
            require(
                symlink_harness.failure is not None and "symbolic link" in symlink_harness.failure,
                f"symlink preflight failure changed: {symlink_harness.failure}",
            )
            require(symlink_harness.prepared is None, "symlink case reached PREPARED")
            require(tree_snapshot(symlink_target) == symlink_snapshot, "symlink target changed")
            require(tree_snapshot(symlink_outside) == symlink_sentinel_before, "symlink preflight changed outside data")
            require_demo(symlink_target, "0.9")
            require(
                symlink_harness.wheel_installer_calls == 0 and symlink_harness.uninstall_calls == 0,
                "symlink case crossed the uninstall boundary",
            )
        finally:
            symlink_harness.close()

        adapted_harness = Harness(
            mode="adapted",
            target=primary,
            handoff=args.handoff,
            worker_manifest=args.worker_manifest,
            verifier=args.verifier,
            installer_root=args.installer_root,
            decoy=decoy,
        )
        try:
            adapted_config = config_for(args.runtime / "adapted-cache")
            adapted_env = ObservedVirtualEnv(primary)
            adapted_env.observer = adapted_harness.audit_pip
            adapted_executor = SealrExecutor(
                adapted_env,
                pool_for(adapted_config, server.url),
                adapted_config,
                NullIO(),
                parallel=False,
                disable_cache=True,
            )
            adapted_executor.harness = adapted_harness
            adapted_executor._wheel_installer = PermitProxy(adapted_harness)
            require(adapted_executor.execute([operation_for(adapted_env)]) == 0, "adapted Poetry update failed")
            adapted_executor._executor.shutdown(wait=True)
            require(adapted_executor.updates_count == 1 and adapted_executor.installations_count == 0 and adapted_executor.removals_count == 0, "adapted operation counts changed")
            require(adapted_harness.uninstall_calls == 1 and adapted_harness.wheel_installer_calls == 1, "adapted seam counts changed")
            require(adapted_harness.events == [
                "poetry-download-returned",
                "poetry-lock-hash-confirmed",
                "prepared",
                "wheel-open-probe-denied",
                "real-uninstall-entered",
                "real-uninstall-returned",
                "permit-written",
                "handoff-completed",
            ], "adapted event order changed")
            require_demo(primary, "1.0")
            adapted_snapshot = tree_snapshot(primary)
            require(adapted_snapshot == stock_snapshot, "adapted target differs from stock Poetry")
            require(adapted_harness.success is not None, "adapted handoff lacks a success report")
            require(installer_file.read_bytes() == b"Poetry 2.4.2", "adapted INSTALLER metadata changed")
            require(
                not (primary / "lib/python3.12/site-packages/demo/__pycache__").exists(),
                "adapted install generated bytecode",
            )
        finally:
            adapted_harness.close()

    require((args.project / "poetry.lock").read_bytes() == lock_before, "fixture changed poetry.lock")
    require(any(path == f"/packages/{WHEEL_FILENAME}" for path in server.requests), "loopback repository never served the controlled wheel")
    success = adapted_harness.success
    require(success is not None, "missing adapted success report")
    report = {
        "schema": "sealr.poetry-2.4.2-conformance.v1",
        "platform": "ubuntu-24.04-x86_64-cpython-3.12",
        "poetry": "2.4.2",
        "poetry_core": "2.4.0",
        "installer": "1.0.1",
        "wheelhouse_artifacts": 47,
        "runtime_distributions": 46,
        "source_sha256": success["source_sha256"],
        "archive_tree_sha256": success["archive_tree_sha256"],
        "artifact_sha256": success["artifact_sha256"],
        "install_plan_sha256": success["install_plan_sha256"],
        "realization_sha256": success["realization_sha256"],
        "installed_files": success["installed_files"],
        "stock_target_sha256": stock_snapshot[0],
        "adapted_target_sha256": tree_snapshot(primary)[0],
        "event_order": adapted_harness.events,
        "abort_gate": "old-install-preserved-after-prepared-eof",
        "symlink_gate": "preflight-denied-before-prepared-or-uninstall",
        "physical_collision_gate": "dry-preflight-antichain-denied-both-orders",
        "post_prepared_wheel_open": "denied",
        "lock_unchanged": True,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Poetry 2.4.2 conformance: {error}", file=sys.stderr)
        raise SystemExit(1)
