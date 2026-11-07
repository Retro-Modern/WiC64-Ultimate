#!/usr/bin/env bash
set -euo pipefail
ESP_SETUP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$ESP_SETUP_ROOT/setup.py" "$@"
