#!/usr/bin/env bash
# Usage: packaging/linux.sh [executable [destination [APKiD-checkout]]]
# Defaults: build/bin/cxapkid (or build/bin/Release/cxapkid), release/linux,
# dep/APKiD. The destination must not exist. Requires Python 3 for packaging
# only; no build, submodule download, or Python runtime is performed/needed.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python_command=${PYTHON:-python3}
if ! command -v "$python_command" >/dev/null 2>&1; then
    echo "cxapkid package: Python 3 is required; set PYTHON to its executable path" >&2
    exit 1
fi
exec "$python_command" "$script_dir/../cmake/package_cxapkid.py" --platform linux "$@"
