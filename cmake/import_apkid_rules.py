#!/usr/bin/env python3
# CXAPKiD - C port of APKiD. SPDX-License-Identifier: MIT
"""Import APKiD's YARA rules into CXAPKiD.

  python import_apkid_rules.py <APKiD checkout> <CXAPKiD rules directory>

Copies apkid/rules/<type>/*.yara with LF line ends (the bytes upstream
stores) and rewrites the few conditions that use parts of YARA 3.11's dex
module which YARA-X does not have. Each rewrite must match exactly as often
as expected, so a changed upstream rule stops the import instead of being
skipped. Also copies LICENSE.GPL as rules/LICENSE. The destination must be
new or empty; existing rules are never removed. Each rewrite below includes
a comment explaining the compatibility adjustment.
"""
import pathlib
import sys

LEGACY_NOTE = "    // CXAPKiD: "

EDITS = {
    "dex/abnormal.yara": [
        ("    dex.header.link_offset != 0x0\n",
         LEGACY_NOTE + "YARA-X names legacy header.link_offset `link_off`.\n"
         "    dex.header.link_off != 0x0\n", 1),
        ("    dex.header.file_size < dex.header.map_offset + (dex.map_list.size * 12) + 4\n",
         LEGACY_NOTE + "YARA-X does not export header.map_offset; read it at 0x34.\n"
         "    dex.header.file_size < uint32(0x34) + (dex.map_list.size * 12) + 4\n", 1),
    ],
    "dex/compilers.yara": [
        ("    for any i in (0..dex.header.string_ids_size - 1) : (dex.string_ids[i + 1].offset < dex.string_ids[i].offset)\n",
         LEGACY_NOTE + "YARA-X has no string_ids[].offset; CXAPKiD evaluates this\n"
         "    // loop over YARA 3.11's string_ids[] (cx_dex.c) and passes the result.\n"
         "    cxapkid_dex_unsorted_string_pool\n", 1),
        ("dex.map_list.map_item[", "dex.map_list.items[", 74),
        ("    for any i in (0..dex.header.class_defs_size) : (dex.class_defs[i].interfaces_offset > 0 and uint32(dex.class_defs[i].interfaces_offset) == 0)\n",
         LEGACY_NOTE + "YARA 3.11 declares class_defs[].interfaces_offset but stores the\n"
         "    // value as interfaces_off, so the field is never defined and APKiD never\n"
         "    // matches this rule. Kept that way for identical results.\n"
         "    false\n", 1),
    ],
    "dex/obfuscators.yara": [
        ("    $a_inner_unicode = /Lo\\/([\\u0000-\\u007F]{1,4}|[^\\u0000-\\u007F]{1,4})\\$[^\\u0000-\\u007F]{1,4};\\x00/\n",
         LEGACY_NOTE + "YARA 3.11 has no \\u escape: it reads [\\u0000-\\u007F] as the bytes\n"
         "    // 0x30-0x75 ('u', '0', the range '0'-'u', '0', '0', '7', 'F'). YARA-X would read\n"
         "    // the ASCII range, so the classes are spelled as YARA 3.11 matches them.\n"
         "    $a_inner_unicode = /Lo\\/([\\x30-\\x75]{1,4}|[^\\x30-\\x75]{1,4})\\$[^\\x30-\\x75]{1,4};\\x00/\n", 1),
        ("    for 3 i in (0..dex.header.field_ids_size) : (dex.field[i].name matches /[^\\x00-\\x7F]{1,4}/)\n",
         LEGACY_NOTE + "dex.field[] (fields defined in class data) has no YARA-X\n"
         "    // counterpart; CXAPKiD counts these names as YARA 3.11 sees them (cx_dex.c).\n"
         "    cxapkid_dex_unicode_field_names >= 3\n", 1),
        ("    for 3 i in (0..dex.header.method_ids_size) : (dex.method[i].name matches /[^\\x00-\\x7F]{1,4}/)\n",
         LEGACY_NOTE + "dex.method[] (methods defined in class data) has no YARA-X\n"
         "    // counterpart; CXAPKiD counts these names as YARA 3.11 sees them (cx_dex.c).\n"
         "    cxapkid_dex_unicode_method_names >= 3\n", 1),
        ("    uint32(dex.header.data_offset + dex.header.data_size - 4) == 0\n",
         LEGACY_NOTE + "YARA-X leaves header.data_size/data_off undefined; read 0x68/0x6C.\n"
         "    dex.is_dex and uint32(uint32(0x6C) + uint32(0x68) - 4) == 0\n", 1),
    ],
    "dex/packers.yara": [
        ("    is_dex and all of them and (dex.header.data_size + dex.header.data_offset) < dex.header.file_size\n",
         LEGACY_NOTE + "YARA-X leaves header.data_size/data_off undefined; read 0x68/0x6C.\n"
         "    is_dex and all of them and (uint32(0x68) + uint32(0x6C)) < dex.header.file_size\n", 1),
    ],
}


def load_rules(checkout):
    """Validate every upstream rewrite before creating any output files."""
    checkout = pathlib.Path(checkout)
    source = checkout / "apkid" / "rules"
    if not source.is_dir():
        raise ValueError(f"{source}: not an APKiD rules directory; initialize dep/APKiD first")
    license_path = checkout / "LICENSE.GPL"
    if not license_path.is_file():
        raise ValueError(f"{license_path}: APKiD's GPL license is missing")
    files = sorted(p.relative_to(source) for p in source.rglob("*.yara"))
    if not files:
        raise ValueError(f"{source}: no .yara files")

    texts = {}
    for name in files:
        data = (source / name).read_bytes().replace(b"\r\n", b"\n")
        texts[name.as_posix()] = data.decode("utf-8")
    for name, edits in EDITS.items():
        if name not in texts:
            raise ValueError(f"{name}: missing from the APKiD rules")
        text = texts[name]
        for old, new, count in edits:
            found = text.count(old)
            if found != count:
                raise ValueError(f"{name}: expected {count} x {old!r}, found {found}; use the pinned APKiD revision")
            text = text.replace(old, new)
        texts[name] = text

    output = {name: text.encode("utf-8") for name, text in texts.items()}
    output["LICENSE"] = license_path.read_bytes()
    return output


def write_rules(files, target):
    target = pathlib.Path(target)
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ValueError(f"{target}: destination must be new or empty")
    for name, data in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        files = load_rules(sys.argv[1])
        write_rules(files, sys.argv[2])
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f"import_apkid_rules: {error}")
    print(f"imported {len(files) - 1} rule files, {sum(len(e) for e in EDITS.values())} rewrites, and LICENSE")


if __name__ == "__main__":
    main()
