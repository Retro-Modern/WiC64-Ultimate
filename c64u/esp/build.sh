#!/usr/bin/env bash
set -euo pipefail
ESP_BUILD_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$ESP_BUILD_ROOT/build.py" "$@"
