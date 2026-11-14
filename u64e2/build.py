#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Current source distribution, modified 2026-11-07.
"""Build WiC64 U64E2 B5RM3 (Beta 5 + Retro-Modern changes). No network or device operations."""
from pathlib import Path
import argparse
import datetime
import json
import os
import hashlib
import platform
import shutil
import struct
import subprocess
import sys

from build_support import cfw, crypto, esp_image

ROOT = Path(__file__).resolve().parent
FEATURES = ('P08_SERVICE=1', 'P05_RAM_DIAGNOSTIC=1', 'P14_TLS=1', 'P18_TLS=1',
            'P18_LOG=1', 'P18M_ESP_BUNDLE=1', 'U64E2_CIA_VISIBLE_SAMPLE=1',
            'P18M_INITIALIZED_ESP_HEAP=1', 'P18M_HEAP_BYTES=0x4e4000',
            'P17F_CACHED_MATH=1', 'P17I_WD_DMA=1')


def run(args, cwd, log):
    print('Running:', ' '.join(map(str, args)), flush=True)
    with log.open('a') as stream:
        result = subprocess.run(list(map(str, args)), cwd=cwd, stdout=stream,
                                stderr=subprocess.STDOUT)
    if result.returncode:
        print('\n'.join(log.read_text(errors='replace').splitlines()[-25:]), file=sys.stderr)
        raise SystemExit('Build failed; see ' + str(log))


def canonical_app(elf, sparse):
    """Check every allocated ELF byte against the native HEX2BIN records."""
    info, payload = cfw.inspect_elf(elf)
    present = bytearray(len(payload))
    represented = bytearray(len(payload))
    position, previous = 0, cfw.RAM_START
    records = []
    while position < len(sparse):
        if len(sparse) - position < 12:
            raise ValueError('Truncated APP record')
        address, size, entry = struct.unpack_from('<III', sparse, position)
        position += 12
        start = address - cfw.RAM_START
        if not size or address < previous or start < 0 or start + size > len(payload) or position + size > len(sparse):
            raise ValueError('Invalid APP record bounds')
        present[start:start + size] = b'\1' * size
        represented[start:start + size] = sparse[position:position + size]
        records.append((address, size, entry))
        position += size
        previous = address + size
    if not records or records[0][0] != cfw.RAM_START or records[-1][2] != cfw.RAM_START or any(r[2] for r in records[:-1]):
        raise ValueError('Invalid APP entry')
    for section in info['allocated_sections']:
        if section['type'] == 8:
            continue
        start = section['address'] - cfw.RAM_START
        end = start + section['size']
        if not all(present[start:end]) or represented[start:end] != payload[start:end]:
            raise ValueError('APP differs from allocated ELF source bytes')
    return struct.pack('<III', cfw.RAM_START, len(payload), cfw.RAM_START) + payload


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--toolchain', type=Path, required=True,
                   help='Installed xPack GCC 11.3.0-1 root directory')
    p.add_argument('--tass', default='64tass', help='External 64tass executable')
    p.add_argument('--work-dir', type=Path, default=ROOT / 'build-work')
    p.add_argument('--jobs', type=int, default=4)
    p.add_argument('--esp-app', type=Path, help='Explicit ESP32-S3 .bin or .ESP to embed')
    a = p.parse_args()
    work, toolchain = a.work_dir.resolve(), a.toolchain.resolve()
    if (platform.system(), platform.machine()) not in (('Linux', 'x86_64'), ('Linux', 'amd64'), ('Darwin', 'arm64')):
        p.error('Use Linux x86_64, WSL2 or macOS arm64.')
    if any(c.isspace() for c in str(ROOT) + str(work) + str(toolchain)):
        p.error('Use paths without spaces.')
    if work.exists():
        p.error('Choose a new --work-dir; existing directories are not removed.')
    if not 1 <= a.jobs <= 32:
        p.error('--jobs must be 1..32')
    for cmd in ['make', 'gcc', 'g++']:
        if not shutil.which(cmd):
            p.error('Missing host tool: ' + cmd)
    tass = shutil.which(a.tass)
    if tass is None:
        p.error('External 64tass missing; see README.md.')
    tass = str(Path(tass).resolve())
    if any(c.isspace() for c in tass):
        p.error('Use an assembler path without spaces.')
    prefix = str(toolchain / 'bin/riscv-none-elf-')
    compiler = prefix + 'gcc'
    if not Path(compiler).is_file():
        p.error('Toolchain must contain bin/riscv-none-elf-gcc')
    version = subprocess.check_output([compiler, '--version'], text=True)
    if '11.3.0' not in version:
        p.error('Use xPack GCC 11.3.0-1')
    try:
        seed = a.esp_app or ROOT / 'assets/wic64_esp.bin'
        esp_app = esp_image.application(seed.read_bytes())
        if not a.esp_app and (len(esp_app) != esp_image.RESOURCE_BYTES or
                hashlib.sha256(esp_app).hexdigest() != esp_image.RESOURCE_SHA256):
            p.error('Bundled ESP image does not match its source identity')
    except (OSError, ValueError) as error:
        p.error(str(error))
    esp_digest = esp_image.configure(esp_app)
    work.mkdir(parents=True)
    log = work / 'build.log'
    source = work / 'native'
    shutil.copytree(ROOT / 'native', source)
    (source / 'software/system/p18m_esp_app.bin').write_bytes(esp_app)
    (source / 'software/system/p18m_esp_image.h').write_text(esp_image.header(esp_app))
    print('Building wolfSSL...', flush=True)
    library, identity, header = crypto.build(ROOT, work / 'crypto', prefix, a.jobs)
    helpers = work / 'helpers'
    helpers.mkdir()
    for name in ('hex2bin', 'make_mem'):
        run(['gcc', '-std=c99', source / 'tools' / (name + '.c'), '-o', helpers / name], ROOT, log)
    target = source / 'target/u64ii/riscv/ultimate'
    (target / 'output').mkdir()
    (target / 'result').mkdir()
    # Fixed defaults make this source release reproducible across build hosts.
    # SOURCE_DATE_EPOCH is optional and must be an integer Unix timestamp.
    stamp = '2026-11-07 00:00'
    if 'SOURCE_DATE_EPOCH' in os.environ:
        try:
            stamp = datetime.datetime.fromtimestamp(int(os.environ['SOURCE_DATE_EPOCH']),
                        datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')
        except (ValueError, OverflowError, OSError) as error:
            p.error('Invalid SOURCE_DATE_EPOCH: ' + str(error))
    fields = {'APP_VERSION_TAG': 'WiC64 U64E2 Beta5',
              'APP_VERSION_BRANCH': 'WiC64-U64E2', 'APP_VERSION_DATE': '2026-11-07',
              'APP_VERSION_HASH': 'u64e2b5', 'APP_BUILD_DATE': stamp,
              'APP_BUILD_MACHINE': 'reproducible'}
    text = '/* Generated current build information. */\n' + ''.join(
        '#define ' + key + ' ' + json.dumps(value, ensure_ascii=True) + '\n'
        for key, value in fields.items())
    (target / 'output/gitinfo.h').write_text(text)
    (source / 'target/libs/riscv/lwip/output').mkdir(parents=True)
    (source / 'target/libs/riscv/lwip/result').mkdir()
    common = ['CROSS=' + prefix, 'AR=' + prefix + 'ar', 'TASS=' + tass, 'PYTHON=' + sys.executable,
              'HEX2BIN=' + str(helpers / 'hex2bin'), 'MAKEMEM=' + str(helpers / 'make_mem')]
    run(['make', '-C', 'target/libs/riscv/lwip', '-j' + str(a.jobs), *common], source, log)
    run(['make', '-C', 'target/u64ii/riscv/ultimate', '-j' + str(a.jobs), *common,
         'OUTPUT=output', 'RESULT=result',
         'EFFORT=' + ' '.join('-D' + f for f in FEATURES) + ' -fstack-usage',
         'P14_TLS_LIBRARY=' + str(library), 'P14_WOLFSSL_DIR=' + str(ROOT / 'crypto/wolfssl'),
         'P14_TLS_CONFIG=' + str(ROOT / 'crypto'), 'P14_TLS_INPUT_SHA256=' + identity,
         'P14_TLS_IDENTITY_HEADER=' + str(header), 'LINK=wic64_linker.x'], source, log)
    elf = (target / 'result/ultimate.elf').read_bytes()
    app = canonical_app(elf, (target / 'result/ultimate.app').read_bytes())
    image, check = cfw.build_cfw(elf, app)
    out = work / 'out'
    (out / 'WiC64').mkdir(parents=True)
    (out / 'WiC64_U64E2_B5RM3.cfw').write_bytes(image)
    (out / 'WiC64_U64E2_B5RM3.elf').write_bytes(elf)
    shutil.copyfile(ROOT / 'assets/U64E2_ESP_RESTORE.ESP', out / 'U64E2_ESP_RESTORE.ESP')
    shutil.copyfile(ROOT / 'assets/WIC64CC.PRG', out / 'WiC64/WIC64CC.PRG')
    shutil.copyfile(ROOT / 'assets/README.TXT', out / 'README.TXT')
    if a.esp_app:
        (out / 'U64E2_ESP_WIC64.ESP').write_bytes(struct.pack('<4sII', b'SEGM', len(esp_app), 0x10000) + esp_app)
    (work / 'build_report.json').write_text(json.dumps(check, indent=2) + '\n')
    print('ESP SHA256:', esp_digest)
    print('Build PASS; startup reserve:', check['static_to_stack_gap'], 'bytes')
    print('CFW SHA256:', hashlib.sha256(image).hexdigest())
    print('Output:', out)


if __name__ == '__main__':
    main()
