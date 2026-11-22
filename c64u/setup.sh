#!/bin/sh
set -eu
WIC64_SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "${1:-all}" in
    native)
        bash "$WIC64_SOURCE_ROOT/native/setup.sh"
        ;;
    esp)
        bash "$WIC64_SOURCE_ROOT/esp/setup.sh"
        ;;
    all)
        bash "$WIC64_SOURCE_ROOT/native/setup.sh"
        bash "$WIC64_SOURCE_ROOT/esp/setup.sh"
        ;;
    -h|--help)
        printf '%s\n' 'Usage: ./setup.sh [all|native|esp]' 'Download and prepare the selected pinned build dependencies (default: all).'
        ;;
    *)
        printf '%s\n' 'Usage: ./setup.sh [all|native|esp]' >&2
        exit 2
        ;;
esac
