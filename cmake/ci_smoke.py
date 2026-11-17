#!/usr/bin/env python3
# CXAPKiD - C port of APKiD. SPDX-License-Identifier: MIT
"""Check a packaged executable with its adjacent rules, then optionally ZIP it."""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile
import zipfile
import zlib


def minimal_dex():
    """DEX 035 with a valid header, checksums and an empty class table."""
    header = bytearray(0x70)
    mapping = struct.pack("<IHHIIHHII", 2, 0, 0, 1, 0, 0x1000, 0, 1, 0x70)
    header[:8] = b"dex\n035\0"
    struct.pack_into("<III", header, 0x20, len(header) + len(mapping), 0x70, 0x12345678)
    struct.pack_into("<I", header, 0x34, 0x70)
    struct.pack_into("<II", header, 0x68, len(mapping), 0x70)
    data = header + mapping
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return bytes(data)


def smoke(package):
    executable = package / ("cxapkid.exe" if (package / "cxapkid.exe").is_file() else "cxapkid")
    if not executable.is_file() or not (package / "rules" / "LICENSE").is_file():
        raise ValueError("Package must contain the executable and rules/LICENSE")
    if not any((package / "rules").rglob("*.yara")):
        raise ValueError("Package contains no YARA rules")
    with tempfile.TemporaryDirectory(prefix="cxapkid-ci-") as directory:
        work = pathlib.Path(directory)
        dex = work / "sample.dex"
        dex.write_bytes(minimal_dex())
        apk = work / "sample.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"<manifest/>")
            archive.writestr("classes.dex", dex.read_bytes())
            archive.writestr("lib/armeabi-v7a/libjiagu.so", b"\x7fELF" + bytes(60))
        # No --rules-dir: this must use the packaged rules from a different cwd.
        result = subprocess.run(
            [str(executable), "-j", "-st", "--include-types", "--threads", "2", str(dex), str(apk)],
            cwd=work, capture_output=True, text=True, encoding="utf-8", timeout=120)
        if result.returncode or result.stderr:
            raise ValueError(f"Packaged scan failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")
        documents = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if len(documents) != 2:
            raise ValueError(f"Expected two scan results, got: {result.stdout}")
        found = {}
        for document in documents:
            digest = document.get("rules_sha256", "")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Scan result has no valid rules hash")
            for entry in document["files"]:
                name = entry["filename"].replace("\\", "/").rsplit("/", 1)[-1]
                found[name] = entry["matches"]
        expected = {"sample.dex": ("file_type", "DEX"),
                    "sample.apk": ("packer", "Jiagu"),
                    "sample.apk!classes.dex": ("file_type", "DEX")}
        for name, (category, match) in expected.items():
            if match not in found.get(name, {}).get(category, []):
                raise ValueError(f"Missing {category}={match} for {name}: {result.stdout}")
    print("Packaged rules smoke test passed: DEX, APK/Jiagu and nested DEX")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("--archive", type=pathlib.Path)
    args = parser.parse_args()
    package = args.package.resolve()
    smoke(package)
    if args.archive:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(package.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(package).as_posix())
        print(f"Created {args.archive}")


if __name__ == "__main__":
    main()
