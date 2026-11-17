# CXAPKiD

A C port of [APKiD 3.2.0](https://github.com/rednaga/APKiD) by RedNaga.
Detects compilers, packers, obfuscators, protectors and trackers in Android
files using APKiD's rules and [xxyara](https://github.com/horsicq/xxyara).

## Build

Requires CMake 3.21 or newer and a C11 compiler. Dependencies are Git submodules.

```sh
git clone --recurse-submodules https://github.com/horsicq/CXAPKiD.git
cd CXAPKiD
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Existing checkouts can use `git submodule update --init --recursive`.
Override `CXAPKID_XXYARA_DIR` and `CXAPKID_XXFCLIB_DIR` to use other library trees.
The executable is in `build/bin/` or `build/bin/Release/`.

## Package

Packaging requires Python 3 to adapt APKiD's rules; running CXAPKiD does not.
After building, run `bash packaging/linux.sh` on Linux or
`packaging\windows.bat` on Windows. The scripts create `release/linux/` or
`release/windows/` with the executable, notices and a separate `rules/` folder.
Optional arguments are the executable path, a new destination directory and
the APKiD checkout (default: `dep/APKiD`).

## Usage

```sh
cxapkid app.apk          # Scan one file
cxapkid -j app.apk       # JSON output
cxapkid -st app.apk      # Include tracker rules
cxapkid -r apps/         # Scan a directory recursively
cxapkid -h              # All options
```

Keep `rules/` beside the executable. Rules are loaded from that folder, never
embedded in the binary. Use `--rules-dir DIR` to select another rule directory.

## License

The scanner source is [MIT licensed](LICENSE). APKiD's rules are Copyright (C)
RedNaga and GPL-3.0 licensed; their notice is packaged as `rules/LICENSE`.
CXAPKiD is an independent port and is not affiliated with RedNaga.
