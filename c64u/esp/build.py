#!/usr/bin/env python3
"""Build the C64U ESP application and APP-only stock restore.

No device is opened and no flash tool is executed. setup.py downloads pinned
dependencies into .deps on the first run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / '.deps'
OUTPUT = ROOT / 'build'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(command, env, log):
    print('  ' + log.name, flush=True)
    with log.open('w') as stream:
        result = subprocess.run([str(x) for x in command], env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text(errors='replace')[-10000:], file=sys.stderr)
        raise RuntimeError(f'Command failed ({result.returncode}); see {log}')


def prepare():
    subprocess.run([sys.executable, str(ROOT / 'setup.py')], check=True)
    OUTPUT.mkdir(exist_ok=True)
    tools = CACHE / 'espressif'
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    env.update(IDF_PATH=str(CACHE / 'esp-idf'),
               IDF_TOOLS_PATH=str(tools),
               IDF_PYTHON_ENV_PATH=str(CACHE / 'python'),
               IDF_COMPONENT_MANAGER='0',
               ESP_ROM_ELF_DIR=str(CACHE / 'esp-rom-elfs'),
               PYTHONDONTWRITEBYTECODE='1', PIP_NO_INDEX='1',
               PIP_DISABLE_PIP_VERSION_CHECK='1')
    paths = [CACHE / 'python/bin',
             CACHE / 'cmake/cmake-3.24.0-linux-x86_64/bin',
             CACHE / 'ninja',
             CACHE / 'xtensa-esp-elf/xtensa-esp-elf/bin',
             CACHE / 'esp32ulp-elf/esp32ulp-elf/bin']
    env['PATH'] = os.pathsep.join(str(x) for x in paths) + os.pathsep + env.get('PATH', '')
    return env


def image_info(path):
    data = path.read_bytes()
    if len(data) > 0x300000 or len(data) < 32 or data[0] != 0xe9:
        raise RuntimeError('ESP application does not fit the existing factory partition')
    if int.from_bytes(data[12:14], 'little') != 9:
        raise RuntimeError('ESP image is not for ESP32-S3')
    return {'file': path.name, 'bytes': len(data), 'sha256': sha(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clean', action='store_true', help='Remove only previous ESP build outputs')
    args = parser.parse_args()
    if args.clean:
        for name in ('build-complete', 'build-stock_1_11'):
            path = CACHE / name
            if path.exists():
                shutil.rmtree(path)
        if OUTPUT.exists():
            shutil.rmtree(OUTPUT)
    env = prepare()
    python = CACHE / 'python/bin/python'
    idf = CACHE / 'esp-idf/tools/idf.py'
    records = {}
    for variant, output in (('complete', 'custom_app.bin'), ('stock_1_11', 'stock_app.bin')):
        print('Building ESP ' + variant + '...', flush=True)
        build = CACHE / ('build-' + variant)
        build.mkdir(exist_ok=True)
        config = build / 'sdkconfig'
        if not config.exists():
            shutil.copyfile(ROOT / variant / 'software/u64ctrl/sdkconfig', config)
        command = [python, idf, '-C', ROOT / variant / 'software/u64ctrl', '-B', build,
                   '-DSDKCONFIG=' + str(config),
                   '-DCMAKE_JOB_POOLS=c64u_compile=4;c64u_link=1',
                   '-DCMAKE_JOB_POOL_COMPILE=c64u_compile',
                   '-DCMAKE_JOB_POOL_LINK=c64u_link', 'build']
        run(command, env, OUTPUT / (variant + '.log'))
        raw = OUTPUT / output
        shutil.copyfile(build / 'u64ctrl.bin', raw)
        info = image_info(raw)
        # A single APP record. No bootloader, partition table or NVS records.
        wrapper = OUTPUT / ('C64U_ESP_COMPLETE_APP.ESP' if variant == 'complete'
                            else 'C64U_ESP_STOCK_1.11.ESP')
        wrapper.write_bytes(struct.pack('<III', 0x4d474553, raw.stat().st_size, 0x10000)
                            + raw.read_bytes())
        run([python, '-m', 'esptool', '--chip', 'esp32s3', 'image_info', raw],
            env, OUTPUT / (variant + '-image-info.log'))
        info['wrapper'] = {'file': wrapper.name, 'bytes': wrapper.stat().st_size,
                           'sha256': sha(wrapper), 'app_offset': 0x10000,
                           'record_count': 1}
        records[variant] = info
    partition_a = CACHE / 'build-complete/partition_table/partition-table.bin'
    partition_b = CACHE / 'build-stock_1_11/partition_table/partition-table.bin'
    if partition_a.read_bytes() != partition_b.read_bytes():
        raise RuntimeError('Custom and stock ESP partition tables differ')
    summary = {'status': 'PASS', 'hardware_execution': 'NOT_RUN',
               'network_required_for_setup': True,
               'sdk': 'ESP-IDF v5.3.1', 'compiler': 'esp-13.2.0_20240530',
               'build_timestamp_and_elf_hash': 'Regenerated by ESP-IDF; rebuilt bytes may differ from release.',
               'partition_table_sha256': sha(partition_a), 'artifacts': records}
    (OUTPUT / 'validation.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
