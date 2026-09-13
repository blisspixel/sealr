"""Reproduce the targeted wheel corpus with CPython's actual ZIP writer.

Default mode checks committed bytes. --write deliberately replaces the vectors.
These are controlled producer fixtures, not a sample of published packages.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import platform
import struct
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "crates/sealr/tests/conformance/wheel-producers-v1.json"
FILENAME = "demo-1.0-py3-none-any.whl"


class Stream(io.BytesIO):
    def seekable(self):
        return False

    def seek(self, *args):
        raise io.UnsupportedOperation("non-seekable producer")


def members(extra=None, lying_record=False):
    files = {
        "demo/__init__.py": b"VALUE = 1\n",
        "demo/caf\u00e9.py": b"LATIN = 1\n",
        "demo/\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae.txt": b"Greek member\n",
        "demo/\u65e5\u672c\u8a9e.txt": b"CJK member\n",
        "demo/data,one.txt": b"CSV quoted path\n",
        "demo/empty.txt": b"",
        "demo-1.0.data/purelib/extra/caf\u00e9.txt": b"purelib\n",
        "demo-1.0.data/platlib/extra/\u03bb.txt": b"platlib\n",
        "demo-1.0.data/headers/caf\u00e9.h": b"#define DEMO 1\n",
        "demo-1.0.data/data/share/\u65e5\u672c\u8a9e.txt": b"data\n",
        "demo-1.0.data/scripts/caf\u00e9": b"#!python\nprint('demo')\n",
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: sealr-producer-fixture\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n\n"
        ),
        "demo-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n",
    }
    files.update(extra or {})
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, content in sorted(files.items()):
        digest = hashlib.sha256(content).digest()
        if lying_record and path == "demo/caf\u00e9.py":
            digest = bytes(32)
        writer.writerow([path, "sha256=" + base64.urlsafe_b64encode(digest).decode().rstrip("="), len(content)])
    writer.writerow(["demo-1.0.dist-info/RECORD", "", ""])
    files["demo-1.0.dist-info/RECORD"] = record.getvalue().encode()
    return files


def produce(files, method, streamed):
    output = Stream() if streamed else io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(path, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100755 if ".data/scripts/" in path else 0o100644) << 16
            info.compress_type = method
            archive.writestr(info, content, compresslevel=6)
    return output.getvalue()


def records(source):
    """Locate exact producer records via the central directory, never magic scans."""
    with zipfile.ZipFile(io.BytesIO(source)) as archive:
        central = archive.start_dir
        for info in archive.infolist():
            local = info.header_offset
            name_len, extra_len = struct.unpack_from("<HH", source, local + 26)
            payload = local + 30 + name_len + extra_len
            yield info, local, central, payload, payload + info.compress_size
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", source, central + 28)
            central += 46 + name_len + extra_len + comment_len


def unsigned_descriptors(source):
    rows = list(records(source))
    cuts = [end for _, _, _, _, end in rows]
    result = bytearray(source)
    eocd = len(source) - 22
    central_start = struct.unpack_from("<I", source, eocd + 16)[0]
    for _, local, central, _, end in rows:
        assert source[end:end + 4] == b"PK\x07\x08"
        struct.pack_into("<I", result, central + 42, local - 4 * sum(cut < local for cut in cuts))
    struct.pack_into("<I", result, eocd + 16, central_start - 4 * len(cuts))
    for cut in reversed(cuts):
        del result[cut:cut + 4]
    return bytes(result)


def fixture(identifier, source, files, outcome, derivation):
    return {
        "id": identifier,
        "filename": FILENAME,
        "derivation": derivation,
        "expected_outcome": outcome,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "source_bytes": len(source),
        "source_hex": source.hex(),
        "members": [{"path": path, "content_hex": content.hex()} for path, content in sorted(files.items())],
    }


def generate():
    cases = []
    files = members()
    for label, method in [("stored", zipfile.ZIP_STORED), ("deflate", zipfile.ZIP_DEFLATED)]:
        for streamed in [False, True]:
            mode = "streamed" if streamed else "seekable"
            source = produce(files, method, streamed)
            cases.append(fixture(f"{label}-{mode}", source, files, "admitted", "unmodified CPython zipfile output"))
            if not streamed:
                continue
            cases.append(fixture(f"{label}-unsigned", unsigned_descriptors(source), files, "admitted", "remove descriptor signatures and adjust central offsets"))
            row = next(row for row in records(source) if row[0].filename == "demo/caf\u00e9.py")
            _, local, central, payload, descriptor = row
            for field, offset in [("crc", 4), ("compressed-size", 8), ("expanded-size", 12)]:
                mutation = bytearray(source)
                mutation[descriptor + offset] ^= 1
                cases.append(fixture(f"{label}-descriptor-{field}", bytes(mutation), files, "archive-rejected", f"flip low bit of first {field} byte in Unicode member descriptor"))
            for label2, offsets in [("unflagged-utf8", [local + 6, central + 8]), ("flag-disagreement", [local + 6])]:
                mutation = bytearray(source)
                for offset in offsets:
                    flags = struct.unpack_from("<H", mutation, offset)[0]
                    struct.pack_into("<H", mutation, offset, flags & ~0x800)
                cases.append(fixture(f"{label}-{label2}", bytes(mutation), files, "archive-rejected", label2))
            mutation = bytearray(source)
            mutation[payload] ^= 1
            mutation_id = "stored-payload-tamper" if method == zipfile.ZIP_STORED else "deflate-missing-stream-end"
            derivation = "flip first stored payload byte" if method == zipfile.ZIP_STORED else "clear BFINAL; complete plaintext and matching CRC32 remain, but the stream never ends"
            cases.append(fixture(mutation_id, bytes(mutation), files, "archive-rejected", derivation))
            lying = members(lying_record=True)
            cases.append(fixture(f"{label}-record-tamper", produce(lying, method, True), lying, "wheel-denied", "correct ZIP integrity with an incorrect Unicode member RECORD hash"))
    for label, extra in [
        ("nfd", {"demo/cafe\u0301.py": b"NFD\n"}),
        ("casefold-collision", {"demo/CAF\u00c9.py": b"collision\n"}),
        ("full-casefold-collision", {"demo/stra\u00dfe.txt": b"one\n", "demo/strasse.txt": b"two\n"}),
        ("path-traversal", {"demo/../escape.txt": b"escape\n"}),
    ]:
        bad = members(extra)
        cases.append(fixture(label, produce(bad, zipfile.ZIP_DEFLATED, True), bad, "archive-rejected", "unmodified producer output with deliberately inadmissible member names"))
    return {
        "schema": "sealr.wheel-producer-vectors.v1",
        "producer": {"python": platform.python_version(), "implementation": platform.python_implementation(), "zlib": zlib.ZLIB_RUNTIME_VERSION},
        "selection": "controlled Unicode and data-descriptor boundary matrix; not external adoption or a published-package sample",
        "fixtures": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.10":
        raise SystemExit("reproduction requires exact CPython 3.12.10")
    vectors = generate()
    generated = (json.dumps(vectors, ensure_ascii=True, indent=2) + "\n").encode()
    if args.write:
        OUTPUT.write_bytes(generated)
    elif OUTPUT.read_bytes() != generated:
        raise SystemExit("producer vectors drifted; inspect the producer and zlib versions before updating")
    print(f"Verified {len(vectors['fixtures'])} producer vectors; SHA-256 {hashlib.sha256(generated).hexdigest()}")


if __name__ == "__main__":
    main()
