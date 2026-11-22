#!/bin/sh
set -eu
WIC64_SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$WIC64_SOURCE_ROOT/tools/build.py" "$@"
