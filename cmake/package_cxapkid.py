#!/usr/bin/env python3
# CXAPKiD - C port of APKiD. SPDX-License-Identifier: MIT
"""Assemble an executable and adapted APKiD rules; never build or download."""
import argparse
import pathlib
import shutil
import sys
import tempfile

# Packaging must not add Python bytecode to the exported cmake/ sources.
sys.dont_write_bytecode = True
from import_apkid_rules import load_rules, write_rules


def dependency_notices(root):
    """Use the same dep/ then local-sibling lookup as the CMake defaults."""
    notices = {}
    for library, names in (("xxyara", ("LICENSE", "LICENSE.YARA-X")), ("xxfclib", ("LICENSE",))):
        source = root / "dep" / library
        if not (source / "CMakeLists.txt").is_file():
            source = root.parent / "_mylibs" / library
        if not (source / "CMakeLists.txt").is_file():
            raise ValueError(f"{library}: dependency checkout not found under dep/ or ../_mylibs/")
        for name in names:
            path = source / name
            if not path.is_file():
                raise ValueError(f"{path}: required dependency license is missing")
            notices[pathlib.Path("licenses") / library / name] = path.read_bytes()
    return notices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux", "windows"), required=True)
    parser.add_argument("executable", nargs="?", help="built executable (default: build/bin[/Release]/cxapkid[.exe])")
    parser.add_argument("destination", nargs="?", help="new package directory (default: release/<platform>)")
    parser.add_argument("apkid", nargs="?", help="APKiD checkout (default: dep/APKiD)")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    name = "cxapkid.exe" if args.platform == "windows" else "cxapkid"
    candidates = [root / "build" / "bin" / name, root / "build" / "bin" / "Release" / name]
    if args.platform == "windows":
        candidates.reverse()
    executable = pathlib.Path(args.executable) if args.executable else next(
        (path for path in candidates if path.is_file()), candidates[0])
    destination = pathlib.Path(args.destination) if args.destination else root / "release" / args.platform
    checkout = pathlib.Path(args.apkid) if args.apkid else root / "dep" / "APKiD"

    try:
        if not executable.is_file():
            raise ValueError(f"{executable}: built executable not found; build CXAPKiD first or pass its path")
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"{destination}: destination already exists; choose a new package directory")
        license_path = root / "LICENSE"
        if not license_path.is_file():
            raise ValueError(f"{license_path}: scanner license is missing")
        # Validate all upstream inputs before creating a package directory.
        rules = load_rules(checkout)
        notices = dependency_notices(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".cxapkid-package-", dir=destination.parent) as temporary:
            package = pathlib.Path(temporary) / "package"
            package.mkdir()
            shutil.copy2(executable, package / name)
            if args.platform == "linux":
                (package / name).chmod((package / name).stat().st_mode | 0o111)
            shutil.copy2(license_path, package / "LICENSE")
            write_rules(rules, package / "rules")
            for notice_name, contents in notices.items():
                path = package / notice_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            # Only this script's temporary directory is cleaned up on failure.
            if destination.exists() or destination.is_symlink():
                raise ValueError(f"{destination}: destination appeared while packaging; refusing to replace it")
            package.rename(destination)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f"cxapkid package: {error}")
    print(f"Packaged {destination.resolve()} ({name}, {len(rules) - 1} adapted rule files, licenses)")


if __name__ == "__main__":
    main()
