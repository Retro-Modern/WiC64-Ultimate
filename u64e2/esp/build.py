#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Current distribution, modified 2026-11-07.
"""Build the WiC64 or restore ESP app with an externally installed ESP-IDF."""
from pathlib import Path
import argparse
import os
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('variant', choices=['wic64', 'restore'])
    p.add_argument('--work-dir', type=Path)
    a = p.parse_args()
    idf = os.environ.get('IDF_PATH')
    if not idf or not (Path(idf) / 'tools/idf.py').is_file():
        p.error('First activate the external ESP-IDF v5.3.1 environment.')
    actual = subprocess.check_output(['git', '-C', idf, 'rev-parse', 'HEAD'], text=True).strip()
    if actual != 'c8fc5f643b7a7b0d3b182d3df610844e3dc9bd74':
        p.error('Use the ESP-IDF commit specified in README.md')
    work = (a.work_dir or ROOT.parent / ('esp-build-' + a.variant)).resolve()
    if work.exists():
        p.error('Choose a new --work-dir')
    work.mkdir(parents=True)
    project = ROOT / a.variant / 'software/u64ctrl'
    config = work / 'sdkconfig'
    shutil.copyfile(project / 'sdkconfig', config)
    subprocess.run([sys.executable, str(Path(idf) / 'tools/idf.py'), '-C', str(project),
                    '-B', str(work), '-DSDKCONFIG=' + str(config), 'build'], check=True)
    data = (work / 'u64ctrl.bin').read_bytes()
    if len(data) < 24 or data[0] != 0xe9 or data[12:14] != b'\x09\x00':
        raise ValueError('Expected ESP32-S3 application')
    name = 'WiC64_ESP.ESP' if a.variant == 'wic64' else 'U64E2_ESP_RESTORE.ESP'
    (work / name).write_bytes(struct.pack('<4sII', b'SEGM', len(data), 0x10000) + data)
    print('Output:', work / name)


if __name__ == '__main__':
    main()
