#!/usr/bin/env python3
"""PyPA installer 0.7.0 proof over Sealr-staged verified members."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator


MAX_DESCRIPTOR_BYTES = 16 * 1024 * 1024
EXPECTED_SCHEMA = "sealr.installer-bridge.v1"
EXPECTED_BRIDGE = "pypa-installer-0.7.0-wheel-source"
EXPECTED_INSTALLER_VERSION = "0.7.0"
EXPECTED_INSTALLER_WHEEL_SHA256 = (
    "05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53"
)


def _audit(event: str, arguments: tuple[object, ...]) -> None:
    if event != "open" or not arguments:
        return
    try:
        path = os.fspath(arguments[0])  # type: ignore[arg-type]
    except TypeError:
        return
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    if path.casefold().endswith(".whl"):
        raise RuntimeError(f"bridge attempted to open a wheel archive: {path}")


sys.addaudithook(_audit)

if len(sys.argv) != 3:
    raise SystemExit("usage: installer_bridge.py <descriptor.json> <installer-import-root>")
_installer_import_root = Path(sys.argv[2]).resolve(strict=True)
if _installer_import_root.suffix.casefold() == ".whl":
    raise ValueError("installer must be imported from the pinned extracted distribution")
sys.path.insert(0, str(_installer_import_root))

from importlib.metadata import version as distribution_version  # noqa: E402

from installer import install  # noqa: E402
from installer.destinations import WheelDestination  # noqa: E402
from installer.records import Hash, RecordEntry, parse_record_file  # noqa: E402
from installer.scripts import Script  # noqa: E402
from installer.sources import WheelSource  # noqa: E402
from installer.utils import construct_record_file, fix_shebang  # noqa: E402


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{label} keys disagree: missing={sorted(expected - actual)!r} "
            f"unknown={sorted(actual - expected)!r}"
        )


def _read_descriptor(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if size > MAX_DESCRIPTOR_BYTES:
        raise ValueError(f"descriptor exceeds {MAX_DESCRIPTOR_BYTES} bytes")
    with path.open("rb") as stream:
        raw = stream.read(MAX_DESCRIPTOR_BYTES + 1)
    if len(raw) != size:
        raise ValueError("descriptor size changed while reading")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("descriptor root must be an object")
    _exact_keys(
        value,
        {
            "schema",
            "bridge",
            "installer_version",
            "installer_wheel_sha256",
            "interpreter",
            "artifact",
            "plan",
            "members",
        },
        "descriptor",
    )
    if value["schema"] != EXPECTED_SCHEMA or value["bridge"] != EXPECTED_BRIDGE:
        raise ValueError("descriptor selects an unknown bridge schema")
    if value["installer_version"] != EXPECTED_INSTALLER_VERSION:
        raise ValueError("descriptor selects an unexpected installer version")
    if value["installer_wheel_sha256"] != EXPECTED_INSTALLER_WHEEL_SHA256:
        raise ValueError("descriptor selects unexpected installer bytes")
    if distribution_version("installer") != EXPECTED_INSTALLER_VERSION:
        raise ValueError("imported installer distribution is not exactly 0.7.0")
    if not isinstance(value["artifact"], dict) or not isinstance(value["plan"], dict):
        raise ValueError("artifact and plan must be objects")
    if not isinstance(value["members"], list):
        raise ValueError("members must be a list")
    return value


class _MemberStream(io.BytesIO):
    def __init__(self, data: bytes, member_index: int, source_path: str) -> None:
        super().__init__(data)
        self.member_index = member_index
        self.source_path = source_path


class SealrWheelSource(WheelSource):
    validation_error = ValueError

    def __init__(self, descriptor_path: Path, descriptor: dict[str, object]) -> None:
        self._root = descriptor_path.parent.resolve(strict=True)
        self._members_root = (self._root / "members").resolve(strict=True)
        self._artifact = descriptor["artifact"]
        self._members = descriptor["members"]
        assert isinstance(self._artifact, dict)
        assert isinstance(self._members, list)
        filename = self._artifact["filename"]
        if not isinstance(filename, dict):
            raise ValueError("artifact filename must be an object")
        distribution = filename.get("distribution")
        version = filename.get("version")
        if not isinstance(distribution, str) or not isinstance(version, str):
            raise ValueError("artifact filename fields are unavailable")
        super().__init__(distribution=distribution, version=version)

        self._by_path: dict[str, dict[str, object]] = {}
        previous_index = -1
        for raw_member in self._members:
            if not isinstance(raw_member, dict):
                raise ValueError("bridge member must be an object")
            _exact_keys(
                raw_member,
                {
                    "member_index",
                    "path",
                    "blob",
                    "sha256",
                    "size",
                    "record_hash",
                    "record_size",
                    "executable",
                },
                "member",
            )
            path = raw_member["path"]
            if (
                not isinstance(path, str)
                or not path
                or path.startswith("/")
                or "\\" in path
                or any(part in ("", ".", "..") for part in path.split("/"))
            ):
                raise ValueError("bridge member path is not canonical")
            member_index = raw_member["member_index"]
            if not isinstance(member_index, int) or member_index <= previous_index:
                raise ValueError("bridge member indices are not strictly source ordered")
            previous_index = member_index
            if path in self._by_path:
                raise ValueError("bridge member path is duplicated")
            self._by_path[path] = raw_member

    @property
    def dist_info_dir(self) -> str:
        value = self._artifact["dist_info_root"]
        if not isinstance(value, str):
            raise ValueError("dist-info root is unavailable")
        return value

    @property
    def data_dir(self) -> str:
        value = self._artifact["data_root"]
        if value is None:
            filename = self._artifact["filename"]
            assert isinstance(filename, dict)
            return f"{filename['normalized_distribution'].replace('-', '_')}-{filename['normalized_version']}.data"
        if not isinstance(value, str):
            raise ValueError("data root is invalid")
        return value

    @property
    def dist_info_filenames(self) -> list[str]:
        prefix = self.dist_info_dir + "/"
        return sorted(
            path[len(prefix) :]
            for path in self._by_path
            if path.startswith(prefix) and "/" not in path[len(prefix) :]
        )

    def _member_bytes(self, member: dict[str, object]) -> bytes:
        blob = member["blob"]
        size = member["size"]
        digest = member["sha256"]
        if (
            not isinstance(blob, str)
            or Path(blob).name != blob
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
        ):
            raise ValueError("bridge member evidence is invalid")
        path = (self._members_root / blob).resolve(strict=True)
        if path.parent != self._members_root:
            raise ValueError("bridge blob escapes its member directory")
        if path.stat().st_size != size:
            raise ValueError("bridge blob size disagrees with its descriptor")
        with path.open("rb") as stream:
            data = stream.read(size + 1)
        if len(data) != size:
            raise ValueError("bridge blob changed while reading")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("bridge blob digest disagrees with verified evidence")
        return data

    def read_dist_info(self, filename: str) -> str:
        if Path(filename).name != filename:
            raise ValueError("dist-info filename must be one component")
        member = self._by_path.get(f"{self.dist_info_dir}/{filename}")
        if member is None:
            raise ValueError("dist-info member does not exist")
        return self._member_bytes(member).decode("utf-8")

    def validate_record(self) -> None:
        rows = list(parse_record_file(self.read_dist_info("RECORD").splitlines()))
        mapping: dict[str, tuple[str, str, str]] = {}
        for row in rows:
            if row[0] in mapping:
                raise ValueError("installer bridge observed a duplicate RECORD row")
            mapping[row[0]] = row
        for path, member in self._by_path.items():
            row = mapping.pop(path, None)
            signature = path in {
                f"{self.dist_info_dir}/RECORD.jws",
                f"{self.dist_info_dir}/RECORD.p7s",
            }
            if signature:
                if row is not None:
                    raise ValueError("legacy signature file appears in RECORD")
                continue
            if row is None:
                raise ValueError(f"bridge member {path} is absent from RECORD")
            expected = (path, member["record_hash"], member["record_size"])
            if row != expected:
                raise ValueError(f"bridge RECORD tuple disagrees for {path}")
            entry = RecordEntry.from_elements(*row)
            if path == f"{self.dist_info_dir}/RECORD":
                if entry.hash_ is not None or entry.size is not None:
                    raise ValueError("RECORD self row contains hash or size")
            elif not entry.validate(self._member_bytes(member)):
                raise ValueError(f"installer rejected bridge evidence for {path}")
        if mapping:
            raise ValueError(f"RECORD contains phantom rows: {sorted(mapping)!r}")

    def get_contents(
        self,
    ) -> Iterator[tuple[tuple[str, str, str], BinaryIO, bool]]:
        for path, member in self._by_path.items():
            yield (
                (path, str(member["record_hash"]), str(member["record_size"])),
                _MemberStream(
                    self._member_bytes(member), int(member["member_index"]), path
                ),
                bool(member["executable"]),
            )


class RecordingDestination(WheelDestination):
    def __init__(self, interpreter: str) -> None:
        self.interpreter = interpreter
        self.actions: list[dict[str, object]] = []
        self.final_record: dict[str, object] | None = None

    @staticmethod
    def _record(path: str, data: bytes) -> RecordEntry:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode(
            "ascii"
        ).rstrip("=")
        return RecordEntry(path, Hash("sha256", digest), len(data))

    def write_file(
        self, scheme: str, path: str | os.PathLike[str], stream: BinaryIO, is_executable: bool
    ) -> RecordEntry:
        source_path = getattr(stream, "source_path", None)
        member_index = getattr(stream, "member_index", None)
        destination_path = os.fspath(path)
        transform = "copy"
        if scheme == "scripts":
            with fix_shebang(stream, self.interpreter) as rewritten:
                data = rewritten.read()
            if source_path is None:
                raise ValueError("source script stream lost its member binding")
            source_data = stream.getvalue() if isinstance(stream, io.BytesIO) else None
            if source_data is not None and data != source_data:
                transform = "rewrite-python-shebang"
        else:
            data = stream.read()
        self.actions.append(
            {
                "source_member_index": member_index,
                "source_path": source_path,
                "scheme": str(scheme),
                "relative_path": destination_path,
                "executable": bool(is_executable),
                "transform": transform,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
        return self._record(destination_path, data)

    def write_script(self, name: str, module: str, attr: str, section: str) -> RecordEntry:
        generated_name, data = Script(name, module, attr, section).generate(
            self.interpreter, "posix"
        )
        self.actions.append(
            {
                "source_member_index": None,
                "source_path": None,
                "scheme": "scripts",
                "relative_path": generated_name,
                "executable": True,
                "transform": (
                    "generate-console-wrapper"
                    if section == "console"
                    else "generate-gui-wrapper"
                ),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
        return self._record(generated_name, data)

    def finalize_installation(
        self,
        scheme: str,
        record_file_path: str,
        records: Iterable[tuple[str, RecordEntry]],
    ) -> None:
        record_list = list(records)
        with construct_record_file(record_list, lambda other: None if other == scheme else f"../{other}/") as stream:
            data = stream.read()
        self.final_record = {
            "scheme": str(scheme),
            "relative_path": record_file_path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }


def _repeatability(source: SealrWheelSource) -> list[tuple[object, ...]]:
    observed: list[tuple[object, ...]] = []
    for record, stream, executable in source.get_contents():
        with stream:
            data = stream.read()
        observed.append((record, hashlib.sha256(data).hexdigest(), len(data), executable))
    return observed


def _expected_actions(plan: dict[str, object]) -> list[dict[str, object]]:
    entries = plan.get("entries")
    if not isinstance(entries, list):
        raise ValueError("plan entries are unavailable")
    expected: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("plan entry must be an object")
        expected.append(
            {
                "source_member_index": entry["source_member_index"],
                "source_path": entry["source_path"],
                "scheme": entry["scheme"],
                "relative_path": entry["relative_path"],
                "executable": entry["executable"] != "not-executable",
                "transform": entry["transform"],
            }
        )
    return sorted(expected, key=lambda action: json.dumps(action, sort_keys=True))


def _observed_actions(actions: list[dict[str, object]]) -> list[dict[str, object]]:
    projected = [
        {key: action[key] for key in (
            "source_member_index",
            "source_path",
            "scheme",
            "relative_path",
            "executable",
            "transform",
        )}
        for action in actions
    ]
    return sorted(projected, key=lambda action: json.dumps(action, sort_keys=True))


def main() -> None:
    descriptor_path = Path(sys.argv[1]).resolve(strict=True)
    descriptor = _read_descriptor(descriptor_path)
    source = SealrWheelSource(descriptor_path, descriptor)
    source.validate_record()
    first = _repeatability(source)
    second = _repeatability(source)
    if first != second:
        raise ValueError("WheelSource get_contents is not repeatable")
    destination = RecordingDestination(str(descriptor["interpreter"]))
    install(source, destination, additional_metadata={})
    if _observed_actions(destination.actions) != _expected_actions(descriptor["plan"]):
        raise ValueError(
            "installer actions disagree with the Sealr plan\n"
            f"expected={_expected_actions(descriptor['plan'])!r}\n"
            f"observed={_observed_actions(destination.actions)!r}"
        )
    artifact = descriptor["artifact"]
    assert isinstance(artifact, dict)
    expected_scheme = "purelib" if artifact["wheel"]["root_is_purelib"] else "platlib"
    expected_record = f"{artifact['dist_info_root']}/RECORD"
    if destination.final_record is None:
        raise ValueError("installer did not finalize RECORD")
    if (
        destination.final_record["scheme"] != expected_scheme
        or destination.final_record["relative_path"] != expected_record
    ):
        raise ValueError("installer finalized RECORD at an unexpected target")
    report = {
        "schema": "sealr.installer-bridge-report.v1",
        "installer_version": EXPECTED_INSTALLER_VERSION,
        "repeatable_member_reads": len(first),
        "actions": destination.actions,
        "final_record": destination.final_record,
        "wheel_open_audit": "enforced",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
