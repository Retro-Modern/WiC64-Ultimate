#!/usr/bin/env bash
set -euo pipefail
native_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$native_dir/build_native.py" "$@"
