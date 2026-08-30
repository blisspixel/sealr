#!/usr/bin/env python3
"""Install a staged, already verified wheel through PyPA installer 1.0.1."""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterable


SCHEMA = "sealr.pypa-adopter.v1"
BRIDGE = "pypa-installer-1.0.1-wheel-source"
INSTALLER_VERSION = "1.0.1"
INSTALLER_WHEEL_SHA256 = (
    "011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b"
)
REPORT_SCHEMA = "sealr.pypa-adopter-report.v1"
TARGET_MODEL = "pypa-installer-1.0.1-linux-posix"
INSTALLER_POLICY = "separate-roots-no-bytecode-no-overwrite-v1"
MAX_DESCRIPTOR_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 65_536
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 64 * 1024 * 1024
MAX_DIST_INFO_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_FILES = 131_072
MAX_OUTPUT_BYTES = 8 * 1024 * 1024 * 1024
SCHEMES = ("purelib", "platlib", "scripts", "headers", "data")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_SHA256 = re.compile(r"sha256=([A-Za-z0-9_-]{43})")
DECIMAL = re.compile(r"0|[1-9][0-9]*")


class BridgeError(ValueError):
    """A closed-contract or installation failure."""


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if event != "open" or not args:
        return
    value = args[0]
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if isinstance(value, str) and value.casefold().endswith(".whl"):
        raise BridgeError("opening wheel archives is forbidden in the adopter bridge")


sys.addaudithook(_audit_hook)


def _fail(detail: str) -> None:
    raise BridgeError(detail)


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"descriptor contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail(f"descriptor contains forbidden JSON number {value}")


def _exact_object(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{where} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unexpected = sorted(actual - keys)
        _fail(f"{where} keys disagree: missing={missing}, unexpected={unexpected}")
    return value


def _list(value: Any, where: str, maximum: int = MAX_MEMBERS) -> list[Any]:
    if type(value) is not list:
        _fail(f"{where} must be an array")
    if len(value) > maximum:
        _fail(f"{where} exceeds the {maximum}-item cap")
    return value


def _string(value: Any, where: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        _fail(f"{where} must be a nonempty string of at most {maximum} UTF-8 bytes")
    if "\x00" in value:
        _fail(f"{where} contains NUL")
    return value


def _optional_string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _string(value, where)


def _integer(value: Any, where: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"{where} must be an unsigned integer no greater than {maximum}")
    return value


def _boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        _fail(f"{where} must be a boolean")
    return value


def _hex_sha256(value: Any, where: str) -> str:
    text = _string(value, where, 64)
    if HEX_SHA256.fullmatch(text) is None:
        _fail(f"{where} must be a lowercase hexadecimal SHA-256 digest")
    return text


def _optional_sha256(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _hex_sha256(value, where)


def _canonical_path(value: Any, where: str) -> str:
    text = _string(value, where)
    if text.startswith("/") or "\\" in text:
        _fail(f"{where} is not a relative POSIX path")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail(f"{where} contains a forbidden path component")
    return text


def _one_component(value: Any, suffix: str, where: str) -> str:
    text = _canonical_path(value, where)
    if "/" in text or not text.endswith(suffix):
        _fail(f"{where} must be one path component ending in {suffix}")
    return text


def _enum(value: Any, choices: set[str], where: str) -> str:
    text = _string(value, where, 128)
    if text not in choices:
        _fail(f"{where} is not one of {sorted(choices)}")
    return text


def _load_descriptor(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        _fail("descriptor must not be a symbolic link")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        _fail("descriptor must be a regular file")
    if info.st_size > MAX_DESCRIPTOR_BYTES + 1:
        _fail(f"descriptor exceeds the {MAX_DESCRIPTOR_BYTES}-byte cap")
    encoded = path.read_bytes()
    if len(encoded) != info.st_size:
        _fail("descriptor changed while it was read")
    if len(encoded) > MAX_DESCRIPTOR_BYTES and not (
        len(encoded) == MAX_DESCRIPTOR_BYTES + 1 and encoded.endswith(b"\n")
    ):
        _fail(f"descriptor exceeds the {MAX_DESCRIPTOR_BYTES}-byte cap")
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"descriptor is not strict UTF-8 JSON: {error}")
    return _exact_object(
        value,
        {
            "schema",
            "bridge",
            "installer_version",
            "installer_wheel_sha256",
            "interpreter",
            "target_model",
            "installer_policy",
            "artifact",
            "plan",
            "identities",
            "members",
        },
        "descriptor",
    )


def _validate_entry_point(value: Any, where: str) -> None:
    point = _exact_object(value, {"group", "name", "object"}, where)
    for key in ("group", "name", "object"):
        _string(point[key], f"{where}.{key}")


def _validate_artifact(value: Any) -> dict[str, Any]:
    artifact = _exact_object(
        value,
        {
            "schema",
            "consumer_profile",
            "consumer_profile_digest",
            "spec_snapshot",
            "source_sha256",
            "archive_tree_sha256",
            "interpretation_profile",
            "interpretation_profile_sha256",
            "filename",
            "dist_info_root",
            "data_root",
            "wheel",
            "metadata",
            "record",
            "entry_points",
            "member_facts",
        },
        "descriptor.artifact",
    )
    for key in (
        "schema",
        "consumer_profile",
        "consumer_profile_digest",
        "spec_snapshot",
        "interpretation_profile",
        "interpretation_profile_sha256",
    ):
        _string(artifact[key], f"descriptor.artifact.{key}")
    if artifact["schema"] != "sealrWheelArtifactV1":
        _fail("descriptor.artifact.schema is not sealrWheelArtifactV1")
    _hex_sha256(artifact["source_sha256"], "descriptor.artifact.source_sha256")
    _hex_sha256(
        artifact["archive_tree_sha256"], "descriptor.artifact.archive_tree_sha256"
    )
    filename = _exact_object(
        artifact["filename"],
        {
            "raw",
            "distribution",
            "version",
            "build",
            "python_tag",
            "abi_tag",
            "platform_tag",
            "normalized_distribution",
            "normalized_version",
            "expanded_tags",
        },
        "descriptor.artifact.filename",
    )
    for key in (
        "raw",
        "distribution",
        "version",
        "python_tag",
        "abi_tag",
        "platform_tag",
        "normalized_distribution",
        "normalized_version",
    ):
        _string(filename[key], f"descriptor.artifact.filename.{key}")
    _optional_string(filename["build"], "descriptor.artifact.filename.build")
    for index, tag in enumerate(_list(filename["expanded_tags"], "expanded_tags", 4096)):
        _string(tag, f"descriptor.artifact.filename.expanded_tags[{index}]")
    artifact["dist_info_root"] = _one_component(
        artifact["dist_info_root"], ".dist-info", "descriptor.artifact.dist_info_root"
    )
    if artifact["data_root"] is not None:
        artifact["data_root"] = _one_component(
            artifact["data_root"], ".data", "descriptor.artifact.data_root"
        )
    wheel = _exact_object(
        artifact["wheel"],
        {"wheel_version", "generator", "root_is_purelib", "build", "tags"},
        "descriptor.artifact.wheel",
    )
    _string(wheel["wheel_version"], "descriptor.artifact.wheel.wheel_version")
    _optional_string(wheel["generator"], "descriptor.artifact.wheel.generator")
    _boolean(wheel["root_is_purelib"], "descriptor.artifact.wheel.root_is_purelib")
    _optional_string(wheel["build"], "descriptor.artifact.wheel.build")
    for index, tag in enumerate(_list(wheel["tags"], "descriptor.artifact.wheel.tags", 4096)):
        _string(tag, f"descriptor.artifact.wheel.tags[{index}]")
    metadata = _exact_object(
        artifact["metadata"],
        {"metadata_version", "name", "version", "normalized_name", "normalized_version"},
        "descriptor.artifact.metadata",
    )
    for key in metadata:
        _string(metadata[key], f"descriptor.artifact.metadata.{key}")
    record_paths: set[str] = set()
    record_indices: set[int] = set()
    for index, value in enumerate(_list(artifact["record"], "descriptor.artifact.record")):
        row = _exact_object(
            value,
            {"path", "member_index", "sha256", "size", "is_record"},
            f"descriptor.artifact.record[{index}]",
        )
        row_path = _canonical_path(row["path"], f"descriptor.artifact.record[{index}].path")
        row_index = _integer(row["member_index"], f"descriptor.artifact.record[{index}].member_index")
        if row_path in record_paths or row_index in record_indices:
            _fail("descriptor.artifact.record duplicates a path or member index")
        record_paths.add(row_path)
        record_indices.add(row_index)
        _optional_sha256(row["sha256"], f"descriptor.artifact.record[{index}].sha256")
        if row["size"] is not None:
            _integer(row["size"], f"descriptor.artifact.record[{index}].size")
        _boolean(row["is_record"], f"descriptor.artifact.record[{index}].is_record")
    for index, point in enumerate(_list(artifact["entry_points"], "descriptor.artifact.entry_points")):
        _validate_entry_point(point, f"descriptor.artifact.entry_points[{index}]")
    fact_paths: set[str] = set()
    fact_indices: set[int] = set()
    for index, value in enumerate(_list(artifact["member_facts"], "descriptor.artifact.member_facts")):
        facts = _exact_object(
            value,
            {"member_index", "path", "creator_system", "external_attributes", "source_executable"},
            f"descriptor.artifact.member_facts[{index}]",
        )
        fact_index = _integer(facts["member_index"], f"descriptor.artifact.member_facts[{index}].member_index")
        fact_path = _canonical_path(facts["path"], f"descriptor.artifact.member_facts[{index}].path")
        if fact_index in fact_indices or fact_path in fact_paths:
            _fail("descriptor.artifact.member_facts duplicates a path or member index")
        fact_indices.add(fact_index)
        fact_paths.add(fact_path)
        _integer(facts["creator_system"], f"descriptor.artifact.member_facts[{index}].creator_system", 255)
        _integer(
            facts["external_attributes"],
            f"descriptor.artifact.member_facts[{index}].external_attributes",
            (1 << 32) - 1,
        )
        _boolean(
            facts["source_executable"],
            f"descriptor.artifact.member_facts[{index}].source_executable",
        )
    return artifact


def _validate_plan(value: Any) -> dict[str, Any]:
    plan = _exact_object(
        value,
        {"schema", "model", "artifact_sha256", "entries"},
        "descriptor.plan",
    )
    if plan["schema"] != "sealrWheelInstallPlanV1":
        _fail("descriptor.plan.schema is not sealrWheelInstallPlanV1")
    if plan["model"] != "scheme-relative-v1":
        _fail("descriptor.plan.model is not scheme-relative-v1")
    _hex_sha256(plan["artifact_sha256"], "descriptor.plan.artifact_sha256")
    for index, value in enumerate(_list(plan["entries"], "descriptor.plan.entries", 131_072)):
        entry = _exact_object(
            value,
            {
                "source_member_index",
                "source_path",
                "scheme",
                "relative_path",
                "sha256",
                "size",
                "executable",
                "transform",
                "entry_point",
            },
            f"descriptor.plan.entries[{index}]",
        )
        if entry["source_member_index"] is not None:
            _integer(entry["source_member_index"], f"descriptor.plan.entries[{index}].source_member_index")
        if entry["source_path"] is not None:
            _canonical_path(entry["source_path"], f"descriptor.plan.entries[{index}].source_path")
        _enum(entry["scheme"], set(SCHEMES), f"descriptor.plan.entries[{index}].scheme")
        _canonical_path(entry["relative_path"], f"descriptor.plan.entries[{index}].relative_path")
        _optional_sha256(entry["sha256"], f"descriptor.plan.entries[{index}].sha256")
        if entry["size"] is not None:
            _integer(entry["size"], f"descriptor.plan.entries[{index}].size")
        _enum(
            entry["executable"],
            {"not-executable", "source-executable", "generated-wrapper"},
            f"descriptor.plan.entries[{index}].executable",
        )
        _enum(
            entry["transform"],
            {"copy", "rewrite-python-shebang", "generate-console-wrapper", "generate-gui-wrapper"},
            f"descriptor.plan.entries[{index}].transform",
        )
        if entry["entry_point"] is not None:
            _validate_entry_point(entry["entry_point"], f"descriptor.plan.entries[{index}].entry_point")
    return plan


def _validate_identities(value: Any) -> dict[str, Any]:
    identities = _exact_object(
        value,
        {
            "source_sha256",
            "archive_tree_sha256",
            "artifact_sha256",
            "install_plan_sha256",
            "realization_sha256",
        },
        "descriptor.identities",
    )
    for key in ("source_sha256", "archive_tree_sha256", "artifact_sha256", "install_plan_sha256"):
        _hex_sha256(identities[key], f"descriptor.identities.{key}")
    if identities["realization_sha256"] is not None:
        _hex_sha256(identities["realization_sha256"], "descriptor.identities.realization_sha256")
    return identities


def _validate_members(value: Any, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    members = _list(value, "descriptor.members")
    paths: set[str] = set()
    blobs: set[str] = set()
    indices: set[int] = set()
    total = 0
    facts_by_index = {facts["member_index"]: facts for facts in artifact["member_facts"]}
    records_by_index = {record["member_index"]: record for record in artifact["record"]}
    record_path = f"{artifact['dist_info_root']}/RECORD"
    signature_paths = {f"{record_path}.jws", f"{record_path}.p7s"}
    for offset, value in enumerate(members):
        where = f"descriptor.members[{offset}]"
        member = _exact_object(
            value,
            {"member_index", "path", "blob", "sha256", "size", "record_hash", "record_size", "executable"},
            where,
        )
        member_index = _integer(member["member_index"], f"{where}.member_index")
        path = _canonical_path(member["path"], f"{where}.path")
        blob = _one_component(member["blob"], ".bin", f"{where}.blob")
        digest = _hex_sha256(member["sha256"], f"{where}.sha256")
        size = _integer(member["size"], f"{where}.size", MAX_MEMBER_BYTES)
        record_hash = member["record_hash"]
        record_size = member["record_size"]
        if type(record_hash) is not str or type(record_size) is not str:
            _fail(f"{where} RECORD fields must be strings")
        executable = _boolean(member["executable"], f"{where}.executable")
        if member_index in indices or path in paths or blob in blobs:
            _fail(f"{where} duplicates a member index, path, or blob")
        indices.add(member_index)
        paths.add(path)
        blobs.add(blob)
        total += size
        if total > MAX_TOTAL_MEMBER_BYTES:
            _fail(f"descriptor members exceed the {MAX_TOTAL_MEMBER_BYTES}-byte aggregate cap")
        facts = facts_by_index.get(member_index)
        if facts is None or facts["path"] != path:
            _fail(f"{where} disagrees with descriptor.artifact.member_facts")
        record = records_by_index.get(member_index)
        if path in signature_paths:
            if record is not None or record_hash or record_size:
                _fail(f"{where} legacy RECORD signature binding is invalid")
        else:
            if record is None or record["path"] != path:
                _fail(f"{where} is absent from descriptor.artifact.record")
            if path == record_path:
                if not record["is_record"] or record["sha256"] is not None or record["size"] is not None:
                    _fail(f"{where} RECORD self binding is invalid")
                if record_hash or record_size:
                    _fail(f"{where} RECORD self fields must be empty")
            else:
                match = RECORD_SHA256.fullmatch(record_hash)
                if match is None or DECIMAL.fullmatch(record_size) is None:
                    _fail(f"{where} has invalid RECORD hash or size text")
                expected_hash = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=").decode("ascii")
                if match.group(1) != expected_hash or record_size != str(size):
                    _fail(f"{where} RECORD fields disagree with staged evidence")
                if record["sha256"] != digest or record["size"] != size or record["is_record"]:
                    _fail(f"{where} disagrees with descriptor.artifact.record")
        if executable != facts["source_executable"]:
            _fail(f"{where}.executable disagrees with the Sealr plan evidence")
    expected_indices = set(records_by_index)
    expected_indices.update(
        index
        for index, facts in facts_by_index.items()
        if facts["path"] in signature_paths
    )
    if indices != expected_indices:
        _fail("descriptor.members do not exactly cover RECORD-bound files and legacy signatures")
    return members


def _validate_descriptor(descriptor: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    expected = {
        "schema": SCHEMA,
        "bridge": BRIDGE,
        "installer_version": INSTALLER_VERSION,
        "installer_wheel_sha256": INSTALLER_WHEEL_SHA256,
    }
    for key, value in expected.items():
        if descriptor[key] != value:
            _fail(f"descriptor.{key} must equal {value!r}")
    interpreter = _string(descriptor["interpreter"], "descriptor.interpreter")
    if "\r" in interpreter or "\n" in interpreter:
        _fail("descriptor.interpreter contains a line break")
    if descriptor["target_model"] != TARGET_MODEL:
        _fail(f"descriptor.target_model must equal {TARGET_MODEL!r}")
    if descriptor["installer_policy"] != INSTALLER_POLICY:
        _fail(f"descriptor.installer_policy must equal {INSTALLER_POLICY!r}")
    artifact = _validate_artifact(descriptor["artifact"])
    plan = _validate_plan(descriptor["plan"])
    identities = _validate_identities(descriptor["identities"])
    members = _validate_members(descriptor["members"], artifact)
    if artifact["source_sha256"] != identities["source_sha256"]:
        _fail("artifact and identities source SHA-256 values disagree")
    if artifact["archive_tree_sha256"] != identities["archive_tree_sha256"]:
        _fail("artifact and identities archive tree SHA-256 values disagree")
    if plan["artifact_sha256"] != identities["artifact_sha256"]:
        _fail("plan and identities artifact SHA-256 values disagree")
    return artifact, plan, identities, members


def _hash_file(path: Path, expected_size: int | None = None) -> tuple[str, int]:
    if path.is_symlink():
        _fail(f"symbolic link is forbidden: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        _fail(f"regular file required: {path}")
    if expected_size is not None and info.st_size != expected_size:
        _fail(f"staged member size mismatch: {path.name}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    if expected_size is not None and size != expected_size:
        _fail(f"staged member changed while it was read: {path.name}")
    return digest.hexdigest(), size


def _load_installer(import_root: Path) -> tuple[Any, Any, Any, Any, Any]:
    if import_root.is_symlink() or not import_root.is_dir():
        _fail("installer import root must be a real directory")
    if import_root.name.casefold().endswith(".whl"):
        _fail("installer import root must be extracted, not a wheel archive")
    sys.path.insert(0, str(import_root))
    package = importlib.import_module("installer")
    package_file = Path(package.__file__).resolve(strict=True)
    try:
        package_file.relative_to(import_root)
    except ValueError:
        _fail("installer was not imported from the supplied import root")
    distributions = [
        item
        for item in importlib.metadata.distributions(path=[str(import_root)])
        if item.metadata.get("Name", "").casefold() == "installer"
    ]
    if len(distributions) != 1 or distributions[0].version != INSTALLER_VERSION:
        _fail(f"installer import root must contain exactly installer {INSTALLER_VERSION}")
    destinations = importlib.import_module("installer.destinations")
    records = importlib.import_module("installer.records")
    sources = importlib.import_module("installer.sources")
    return package.install, destinations.SchemeDictionaryDestination, records.RecordEntry, records.parse_record_file, sources.WheelSource


def _source_type(wheel_source_base: type, record_entry_type: type, parse_record_file: Callable[..., Iterable[Any]]) -> type:
    class StagedWheelSource(wheel_source_base):
        validation_error = BridgeError

        def __init__(self, descriptor_path: Path, artifact: dict[str, Any], members: list[dict[str, Any]]) -> None:
            filename = artifact["filename"]
            super().__init__(filename["distribution"], filename["version"])
            self._descriptor_path = descriptor_path
            self._members = tuple(members)
            self._by_path = {member["path"]: member for member in members}
            self._members_root = descriptor_path.parent / "members"
            if self._members_root.is_symlink() or not self._members_root.is_dir():
                _fail("staged members directory must be a real directory")
            self._dist_info_dir = artifact["dist_info_root"]
            data_root = artifact["data_root"]
            self._data_dir = data_root or f"{filename['normalized_distribution']}-{filename['normalized_version']}.data"

        @property
        def dist_info_dir(self) -> str:
            return self._dist_info_dir

        @property
        def data_dir(self) -> str:
            return self._data_dir

        @property
        def dist_info_filenames(self) -> list[str]:
            prefix = f"{self.dist_info_dir}/"
            return sorted(
                path[len(prefix) :]
                for path in self._by_path
                if path.startswith(prefix) and "/" not in path[len(prefix) :]
            )

        def _read_blob(self, member: dict[str, Any]) -> bytes:
            path = self._members_root / member["blob"]
            if path.parent != self._members_root:
                _fail("staged member blob escaped the members directory")
            if path.is_symlink():
                _fail(f"staged member blob is a symbolic link: {member['blob']}")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != member["size"]:
                _fail(f"staged member size mismatch: {member['path']}")
            with path.open("rb") as stream:
                data = stream.read(member["size"] + 1)
            if len(data) != member["size"] or hashlib.sha256(data).hexdigest() != member["sha256"]:
                _fail(f"staged member evidence mismatch: {member['path']}")
            return data

        def read_dist_info(self, filename: str) -> str:
            if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
                _fail("invalid dist-info filename request")
            member = self._by_path.get(f"{self.dist_info_dir}/{filename}")
            if member is None:
                _fail(f"missing dist-info member: {filename}")
            if member["size"] > MAX_DIST_INFO_BYTES:
                _fail(f"dist-info member exceeds the {MAX_DIST_INFO_BYTES}-byte cap")
            return self._read_blob(member).decode("utf-8")

        def validate_record(self) -> None:
            record_path = f"{self.dist_info_dir}/RECORD"
            record_member = self._by_path.get(record_path)
            if record_member is None:
                _fail("staged wheel is missing RECORD")
            rows = list(parse_record_file(self.read_dist_info("RECORD").splitlines()))
            by_path: dict[str, tuple[str, str]] = {}
            for row in rows:
                if row[0] in by_path:
                    _fail(f"RECORD contains duplicate path: {row[0]}")
                by_path[row[0]] = (row[1], row[2])
            signature_paths = {f"{record_path}.jws", f"{record_path}.p7s"}
            for member in self._members:
                expected = (member["record_hash"], member["record_size"])
                if member["path"] in signature_paths:
                    if member["path"] in by_path:
                        _fail("legacy RECORD signature must remain outside RECORD")
                    self._read_blob(member)
                    continue
                actual = by_path.pop(member["path"], None)
                if actual != expected:
                    _fail(f"RECORD binding mismatch: {member['path']}")
                entry = record_entry_type.from_elements(member["path"], *expected)
                with io.BytesIO(self._read_blob(member)) as stream:
                    if not entry.validate_stream(stream):
                        _fail(f"RECORD content validation failed: {member['path']}")
            if by_path:
                _fail(f"RECORD references unstaged paths: {sorted(by_path)}")

        def get_contents(self) -> Iterable[tuple[Any, Any, bool]]:
            for member in self._members:
                record = (
                    member["path"], member["record_hash"], member["record_size"]
                )
                with io.BytesIO(self._read_blob(member)) as stream:
                    yield record, stream, member["executable"]

    return StagedWheelSource


def _consume_source(source: Any) -> list[tuple[tuple[str, str, str], str, int, bool]]:
    result: list[tuple[tuple[str, str, str], str, int, bool]] = []
    for record, stream, executable in source.get_contents():
        if (
            type(record) is not tuple
            or len(record) != 3
            or any(type(element) is not str for element in record)
            or type(executable) is not bool
        ):
            _fail("WheelSource returned an invalid content element")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        result.append((record, digest.hexdigest(), size, executable))
    return result


def _prepare_destination(root: Path) -> dict[str, str]:
    if root.exists() or root.is_symlink():
        _fail("install root already exists; exclusive installation is required")
    root.mkdir(mode=0o700)
    result: dict[str, str] = {}
    resolved: set[Path] = set()
    for scheme in SCHEMES:
        path = root / scheme
        path.mkdir(mode=0o700)
        resolved_path = path.resolve(strict=True)
        if resolved_path in resolved:
            _fail("scheme roots must be distinct")
        resolved.add(resolved_path)
        result[scheme] = str(resolved_path)
    return result


def _enumerate_outputs(root: Path) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []
    total = 0
    for scheme in SCHEMES:
        scheme_root = root / scheme
        stack: list[tuple[Path, str]] = [(scheme_root, "")]
        while stack:
            directory, prefix = stack.pop()
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda item: item.name)
            for entry in ordered:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                canonical = _canonical_path(relative.replace(os.sep, "/"), "installed output path")
                path = Path(entry.path)
                if entry.is_symlink():
                    _fail(f"installed output is a symbolic link: {scheme}/{canonical}")
                if entry.is_dir(follow_symlinks=False):
                    stack.append((path, canonical))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    _fail(f"installed output is not a regular file: {scheme}/{canonical}")
                digest, size = _hash_file(path)
                total += size
                if len(outputs) >= MAX_OUTPUT_FILES or total > MAX_OUTPUT_BYTES:
                    _fail("installed outputs exceed the bridge reporting cap")
                mode = entry.stat(follow_symlinks=False).st_mode
                outputs.append(
                    {
                        "scheme": scheme,
                        "relative_path": canonical,
                        "sha256": digest,
                        "size": size,
                        "executable": bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
                    }
                )
    outputs.sort(key=lambda item: (SCHEMES.index(item["scheme"]), item["relative_path"]))
    return outputs


def _run(argv: list[str]) -> dict[str, Any]:
    if len(argv) != 3:
        _fail("usage: bridge.py <descriptor.json> <installer-import-root>")
    descriptor_path = Path(argv[1]).resolve(strict=True)
    import_root = Path(argv[2]).resolve(strict=True)
    descriptor = _load_descriptor(descriptor_path)
    artifact, _plan, _identities, members = _validate_descriptor(descriptor)
    install, destination_type, record_entry_type, parse_record_file, wheel_source_base = _load_installer(import_root)
    source_class = _source_type(wheel_source_base, record_entry_type, parse_record_file)
    source = source_class(descriptor_path, artifact, members)
    source.validate_record()
    first_read = _consume_source(source)
    second_read = _consume_source(source)
    if first_read != second_read or len(first_read) != len(members):
        _fail("WheelSource member reads are not repeatable")
    install_root = descriptor_path.parent / "install"
    scheme_dict = _prepare_destination(install_root)
    destination = destination_type(
        scheme_dict=scheme_dict,
        interpreter=descriptor["interpreter"],
        script_kind="posix",
        hash_algorithm="sha256",
        bytecode_optimization_levels=(),
        destdir=None,
        overwrite_existing=False,
    )
    install(source, destination, {})
    outputs = _enumerate_outputs(install_root)
    return {
        "schema": REPORT_SCHEMA,
        "installer_version": INSTALLER_VERSION,
        "wheel_open_audit": "enforced",
        "repeatable_member_reads": len(first_read),
        "installed_files": outputs,
    }


def main() -> int:
    try:
        report = _run(sys.argv)
    except (BridgeError, OSError, ValueError, UnicodeError) as error:
        print(f"pypa installer consumer bridge: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
