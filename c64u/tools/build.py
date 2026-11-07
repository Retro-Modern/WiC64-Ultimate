#!/usr/bin/env python3
"""Build the C64U application and ESP controller applications."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = 'WiC64_C64U_Beta2.ue2'
RESTORE_NAME = 'C64U_ESP_STOCK_1.11.ESP'


def jobs(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 16:
        raise argparse.ArgumentTypeError('choose 1 to 16 parallel jobs')
    return result


def component(name: str, arguments: list[str], *, env=None) -> None:
    subprocess.run(['bash', str(ROOT / name / 'build.sh'), *arguments],
                   cwd=ROOT, env=env, check=True)


def package(application: Path, restore: Path) -> None:
    inputs = {
        APP_NAME: application,
        RESTORE_NAME: restore,
        'README.TXT': ROOT / 'README.TXT',
        'WiC64/WIC64CC.PRG': ROOT / 'WiC64/WIC64CC.PRG',
        'THIRD_PARTY_NOTICES.txt': ROOT / 'THIRD_PARTY_NOTICES.txt',
    }
    for name, source in inputs.items():
        if not source.is_file():
            raise SystemExit(f'Missing runtime input for {name}: {source}')
    licenses = ROOT / 'LICENSES'
    if not licenses.is_dir() or not any(path.is_file() for path in licenses.rglob('*')):
        raise SystemExit('Missing LICENSES/ notice files')
    destination = ROOT / 'dist'
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir()
    for name, source in inputs.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    shutil.copytree(licenses, destination / 'LICENSES')
    print('Runtime files are ready in dist/.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', choices=('all', 'native', 'esp'), default='all')
    parser.add_argument('--clean', action='store_true', help='Clean selected component build outputs first.')
    parser.add_argument('--jobs', type=jobs, default=2, metavar='N', help='Native parallel jobs, 1..16 (default: 2).')
    args = parser.parse_args()
    options = ['--clean'] if args.clean else []
    environment = dict(os.environ)
    fresh_app = ROOT / 'esp/build/custom_app.bin'
    fresh_stock = ROOT / 'esp/build/stock_app.bin'
    fresh_restore = ROOT / ('esp/build/' + RESTORE_NAME)
    if args.target in ('esp', 'all') or not all(output.is_file() for output in (fresh_app, fresh_stock, fresh_restore)):
        component('esp', options)
    for output in (fresh_app, fresh_stock, fresh_restore):
        if not output.is_file():
            raise SystemExit(f'ESP build did not produce {output.relative_to(ROOT)}')
    if args.target == 'esp':
        print('ESP application and restore files are ready in esp/build/.')
        return
    environment['C64U_ESP_APP'] = str(fresh_app)
    environment['C64U_ESP_STOCK_APP'] = str(fresh_stock)
    component('native', options + ['--jobs', str(args.jobs)], env=environment)
    package(ROOT / ('native/build/' + APP_NAME), fresh_restore)


if __name__ == '__main__':
    main()
