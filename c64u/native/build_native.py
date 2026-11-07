#!/usr/bin/env python3
"""Build the current C64U native application from source."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
TREE = ROOT / 'src'
SUPPORT = ROOT
BUILD = ROOT / 'build'
TOOLS = ROOT / 'checks'
HOST_TOOLS = ROOT / '.deps/host-tools'
COMPILER = ROOT / '.deps/toolchain/xpack-riscv-none-elf-gcc-11.3.0-1'
PREFIX = str(COMPILER / 'bin/riscv-none-elf-')
SETTINGS = ROOT / 'crypto/user_settings.h'
BUILDER = ROOT / 'dependencies/build_wolfssl.py'
BUILDER_SHA = '46055ca766c488bca98af5dadb40a5ec2e2e95208f517185f16984e4eb1b0147'
APP = TREE / 'target/u64ii/riscv/ultimate'
APP_OUTPUT = 'output'
APP_RESULT = 'result'
FLAGS = '-DC64U_CORE49_FENCELESS=1 -DC64U_BOOT_TRACE=1 -DC64U_BOOT_TRACE_DISPLAY=0 -DC64U_API22_ALPHA=1 -DC64U_CIA_VISIBLE_SAMPLE=1 -DP08_SERVICE=1 -DP05_RAM_DIAGNOSTIC=1 -DP05_MAILBOX_DIAGNOSTIC=1 -DP14_TLS=1 -DP18_TLS=1 -DP18_LOG=1 -DP18M_ESP_BUNDLE=1 -DP18M_INITIALIZED_ESP_HEAP=1 -DP18M_HEAP_BYTES=0x480000 -DC64U_ESP_TLS=1 -DC64U_ESP_TLS_INSTALL=1 -DC64U_ESP_PERSIST=1 -DC64U_ESP_WIFI_CONFIG=1 -DP17F_CACHED_MATH=0 -DP17I_WD_DMA=1 -fstack-usage'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv, cwd, name, environment):
    log = BUILD / 'logs' / (name + '.log')
    print(name, flush=True)
    with log.open('w') as stream:
        result = subprocess.run([str(x) for x in argv], cwd=cwd, env=environment,
                                stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        print(''.join(log.read_text(errors='replace').splitlines(True)[-70:]), flush=True)
        raise RuntimeError('%s failed (%d); see %s' % (name, result.returncode, log))


def manifest():
    result = {}
    for path in sorted(TREE.rglob('*')):
        relative = path.relative_to(TREE)
        if not path.is_file() or any(part == '.git' or part.startswith(('output', 'result')) for part in relative.parts):
            continue
        if path.suffix in ('.o', '.d', '.lst', '.su') or path.name.startswith('python_out_'):
            continue
        result[relative.as_posix()] = sha(path)
    return result


def prepare_esp():
    asset = TREE / 'software/system/p18m_esp_app.bin'
    lengths = TREE / 'software/io/wifi/c64u_esp_image_profile.h'
    approvals = TREE / 'software/io/wifi/c64u_esp_install_profile.h'
    originals = {path: path.read_bytes() if path.is_file() else None for path in (asset, lengths, approvals)}
    requested = os.environ.get('C64U_ESP_APP')
    requested = requested or str(ROOT.parent / 'esp/build/custom_app.bin')
    image_path = Path(requested).expanduser().resolve()
    if not image_path.is_file():
        raise RuntimeError('Build the ESP application first with ../build.sh all, or set C64U_ESP_APP to its raw app .bin')
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if len(image) < 256 or len(image) > 0x300000 or image[0] != 0xe9 or image[12:14] != b'\x09\x00':
        raise ValueError('Expected a raw ESP32-S3 app, without SEGM wrapper/bootloader/partition image')
    if len(image) + 32 >= 0x480000:
        raise ValueError('ESP resource exceeds the reserved native initialized heap')
    stock_path = Path(os.environ.get('C64U_ESP_STOCK_APP') or ROOT.parent / 'esp/build/stock_app.bin').expanduser().resolve()
    if not stock_path.is_file():
        raise RuntimeError('Build the ESP return application first with ../build.sh all, or set C64U_ESP_STOCK_APP to its raw app .bin')
    stock = stock_path.read_bytes()
    stock_digest = hashlib.sha256(stock).hexdigest()
    if len(stock) < 256 or len(stock) > 0x300000 or stock[0] != 0xe9 or stock[12:14] != b'\x09\x00':
        raise ValueError('Expected a raw ESP32-S3 return app without a container')
    if len(stock) == len(image):
        raise ValueError('TLS and return app lengths must differ for the installer role selector')
    if requested:
        profile, count = re.subn(r'(#define C64U_ESP_TLS_APP_BYTES )\d+', r'\g<1>' + str(len(image)), originals[lengths].decode())
        if count != 1:
            raise ValueError('Cannot bind ESP TLS byte length unambiguously')
        profile, count = re.subn(r'(#define C64U_ESP_RETURN_APP_BYTES )\d+', r'\g<1>' + str(len(stock)), profile)
        if count != 1:
            raise ValueError('Cannot bind ESP return byte length unambiguously')
        digest_bytes = ','.join('0x' + digest[index:index+2] for index in range(0, 64, 2))
        installer, count = re.subn(r'(static const uint8_t tls_sha256\[32\]=\{).*?(\n    \};)',
                                  r'\g<1>\n        ' + digest_bytes + r'\g<2>',
                                  originals[approvals].decode(), count=1, flags=re.S)
        if count != 1:
            raise ValueError('Cannot bind ESP TLS installer digest unambiguously')
        stock_digest_bytes = ','.join('0x' + stock_digest[index:index+2] for index in range(0, 64, 2))
        installer, count = re.subn(r'(static const uint8_t return_sha256\[32\]=\{).*?(\n    \};)',
                                  r'\g<1>\n        ' + stock_digest_bytes + r'\g<2>',
                                  installer, count=1, flags=re.S)
        if count != 1:
            raise ValueError('Cannot bind ESP return installer digest unambiguously')
        asset.write_bytes(image)
        lengths.write_text(profile)
        approvals.write_text(installer)
    (BUILD / 'embedded_esp.bin').write_bytes(image)
    return originals, {'selection': 'C64U_ESP_APP' if requested else 'fresh ESP source build',
                       'bytes': len(image), 'sha256': digest,
                       'stock_return': {'bytes': len(stock), 'sha256': stock_digest},
                       'native_bindings': ['raw incbin resource', 'TLS and return app byte lengths', 'runtime TLS and return SHA256 allowlists']}


def verify_installer_binding(image, environment):
    """Compile and execute the actual installer selector with both fresh inputs."""
    tls = ','.join('0x' + image['sha256'][n:n+2] for n in range(0, 64, 2))
    stock = ','.join('0x' + image['stock_return']['sha256'][n:n+2] for n in range(0, 64, 2))
    source = BUILD / 'installer_binding.c'
    source.write_text('''#include "c64u_esp_install_profile.h"
int main(void) {
    unsigned char tls[32]={%s}, stock[32]={%s};
    if(c64u_esp_app_approval(tls,%d)!=1) return 1;
    if(c64u_esp_app_approval(stock,%d)!=2) return 2;
    if(c64u_esp_app_approval(tls,%d)!=0) return 3;
    if(c64u_esp_app_approval(stock,%d)!=0) return 4;
    for(unsigned i=0;i<32;++i) {
        tls[i]^=1; stock[i]^=1;
        if(c64u_esp_app_approval(tls,%d)!=0 || c64u_esp_app_approval(stock,%d)!=0) return 5;
        tls[i]^=1; stock[i]^=1;
    }
    if(c64u_esp_app_approval(0,%d)!=0) return 6;
    return 0;
}
''' % (tls, stock, image['bytes'], image['stock_return']['bytes'],
       image['stock_return']['bytes'], image['bytes'], image['bytes'],
       image['stock_return']['bytes'], image['bytes']))
    binary = BUILD / 'installer_binding'
    defines = [flag for flag in FLAGS.split() if flag.startswith('-D')]
    command = ['gcc', '-std=c99', '-O2', '-DRISCV=1', '-DU64=2', '-DFLASH_EXTRA_PROTECTION=1',
               *defines, '-I' + str(TREE / 'software/io/wifi'), source, '-o', binary]
    run(command, ROOT, 'installer-binding-compile', environment)
    run([binary], ROOT, 'installer-binding-check', environment)


def validate(elf_path, app_path, image):
    sys.path.insert(0, str(TOOLS))
    gate = load('current_native_validation', TOOLS / 'validate_native.py')
    report = gate.validate(elf_path, app_path, PREFIX, image)
    (BUILD / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument('--clean', action='store_true', help='Rebuild all owned native/crypto/host outputs')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error('--jobs must be 1..16')
    esp_input = Path(os.environ.get('C64U_ESP_APP') or ROOT.parent / 'esp/build/custom_app.bin')
    if not esp_input.is_file():
        raise RuntimeError('Build the ESP application first with ../build.sh all, or set C64U_ESP_APP to its raw app .bin')
    stock_input = Path(os.environ.get('C64U_ESP_STOCK_APP') or ROOT.parent / 'esp/build/stock_app.bin')
    if not stock_input.is_file():
        raise RuntimeError('Build the ESP return application first with ../build.sh all, or set C64U_ESP_STOCK_APP to its raw app .bin')
    if not (HOST_TOOLS / 'Makefile').is_file():
        raise RuntimeError('Native dependencies missing. Run ../setup.sh or ./setup.sh first.')
    if args.clean:
        shutil.rmtree(BUILD, ignore_errors=True)
        for relative in (APP_OUTPUT, APP_RESULT):
            shutil.rmtree(APP / relative, ignore_errors=True)
        for relative in ('output', 'result'):
            shutil.rmtree(TREE / 'target/libs/riscv/lwip' / relative, ignore_errors=True)
        shutil.rmtree(TREE / 'software/6502/sidcrt/target', ignore_errors=True)
        for name in ('bin2hex', 'hex2bin', 'make_mem', 'checksum', '64tass/64tass'):
            (HOST_TOOLS / name).unlink(missing_ok=True)
        for path in (HOST_TOOLS / '64tass').glob('*.o'):
            path.unlink()
    (BUILD / 'logs').mkdir(parents=True, exist_ok=True)
    for name in ('make', 'gcc', 'g++'):
        if not shutil.which(name):
            raise RuntimeError('Required host tool missing: ' + name)
    if not Path(PREFIX + 'gcc').is_file():
        raise RuntimeError('RISC-V compiler missing. Run ../setup.sh or native/setup.sh first.')
    multi = subprocess.check_output([PREFIX + 'gcc', '-march=rv32i', '-mabi=ilp32', '-print-multi-directory'], text=True).strip()
    if multi != 'rv32i/ilp32':
        raise RuntimeError('Unexpected target compiler multilib: ' + multi)
    environment = os.environ.copy()
    host_bin = BUILD / 'host-bin'
    host_bin.mkdir(exist_ok=True)
    python_alias = host_bin / 'python'
    python_alias.unlink(missing_ok=True)
    python_alias.symlink_to(sys.executable)
    environment['PATH'] = str(host_bin) + os.pathsep + environment.get('PATH', '')
    common = ['make', '-j' + str(args.jobs), 'CROSS=' + PREFIX, 'MARCH=rv32i', 'MABI=ilp32',
              'C64U_SNAPSHOT_GITINFO=' + str(ROOT / 'scripts/write_gitinfo.py'), 'TOOLS=' + str(HOST_TOOLS)]
    run(['make', '-j' + str(args.jobs), 'bin2hex', 'hex2bin', 'make_mem', 'checksum'], HOST_TOOLS, 'host-tools', environment)
    run(['make', '-j' + str(args.jobs)], HOST_TOOLS / '64tass', '64tass', environment)
    run(['make', '-j' + str(args.jobs), 'TOOLS=' + str(HOST_TOOLS)], TREE / 'software/6502/sidcrt', 'sid-inputs', environment)
    if sha(BUILDER) != BUILDER_SHA:
        raise RuntimeError('Current crypto source-bound builder changed')
    crypto = load('beta1_wolfssl_builder', BUILDER)
    crypto.SETTINGS = SETTINGS
    wolf = crypto.ensure_sources()
    print('wolfSSL-RV32I', flush=True)
    crypto_path = BUILD / 'crypto'
    crypto_report = crypto.build_library(crypto_path, PREFIX, args.jobs, fresh=args.clean,
                                        extra_flags=('-march=rv32i', '-DC64U_CORE49_FENCELESS=1'))
    audit = load('beta1_crypto_audit', TOOLS / 'crypto_validation.py')
    audit.PREFIX, audit.SETTINGS, audit.OUTPUT = PREFIX, SETTINGS, crypto_path
    audit.AUDIT = crypto_path / 'logs/core49_audit'
    audit.AUDIT.mkdir(parents=True, exist_ok=True)
    scan = audit.scan_archive(crypto_path / 'libwolfssl.a')
    if scan['misc_mem_fence_count'] or scan['amo_count']:
        raise RuntimeError('Crypto archive contains forbidden Core49 instructions')
    wipe = audit.forcezero_proof(wolf, crypto_report)
    (BUILD / 'crypto_validation.json').write_text(json.dumps({'status': 'PASS', 'scan': scan, 'secure_wipe_proof': wipe}, indent=2) + '\n')
    lwip = TREE / 'target/libs/riscv/lwip'
    run(common + ['AR=' + PREFIX + 'ar'], lwip, 'lwip', environment)
    # The upstream assembly rules do not track every .incbin/header dependency.
    # Recompile the application on every invocation so selecting a rebuilt ESP
    # app, changing its size, or returning to the shipped app cannot reuse stale
    # image/allowlist objects. --clean additionally rebuilds crypto/lwIP/host tools.
    for directory in (APP / APP_OUTPUT, APP / APP_RESULT):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir()
    originals, image = prepare_esp()
    try:
        verify_installer_binding(image, environment)
        before = manifest()
        command = common + ['OUTPUT=' + APP_OUTPUT, 'RESULT=' + APP_RESULT, 'LINK=ram.x', 'EFFORT=' + FLAGS,
                            'P14_TLS_LIBRARY=' + str(crypto_path / 'libwolfssl.a'),
                            'P14_WOLFSSL_DIR=' + str(wolf), 'P14_TLS_CONFIG=' + str(SETTINGS.parent),
                            'P14_TLS_INPUT_SHA256=' + crypto_report['build_input_sha256'],
                            'P14_TLS_IDENTITY_HEADER=' + str(crypto_path / 'build_identity.h')]
        run(command, APP, 'native-application', environment)
        after = manifest()
        if before != after:
            changed = [key for key in before.keys() | after.keys() if before.get(key) != after.get(key)]
            raise RuntimeError('Application source inputs changed during build: ' + repr(changed))
        elf = APP / APP_RESULT / 'ultimate.elf'
        upstream_app = APP / APP_RESULT / 'ultimate.app'
        shutil.copy2(upstream_app, BUILD / 'ultimate.upstream.app')
        payload_file = BUILD / 'ultimate.payload.bin'
        run([PREFIX + 'objcopy', '-O', 'binary', '--gap-fill', '0xff', elf, payload_file], ROOT, 'canonical-payload', environment)
        data = elf.read_bytes()
        if data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 243:
            raise RuntimeError('Expected ELF32LE RISC-V application')
        entry = struct.unpack_from('<I', data, 24)[0]
        payload = payload_file.read_bytes()
        if entry != 0x03000000 or not 0 < len(payload) <= 0x00c00000:
            raise RuntimeError('Application exceeds reviewed C64U RAM window')
        output = BUILD / 'WiC64_C64U_Beta2.ue2'
        output.write_bytes(struct.pack('<III', 0x03000000, len(payload), entry) + payload)
        validation = validate(elf, output, image)
        shutil.copy2(elf, BUILD / 'WiC64_C64U_Beta2.elf')
        shutil.copy2(APP / APP_OUTPUT / 'ultimate.map', BUILD / 'WiC64_C64U_Beta2.map')
        (BUILD / 'source_manifest.json').write_text(json.dumps(after, indent=2) + '\n')
        report = {'status': 'PASS', 'source_revision': json.loads((ROOT / 'source_revision.json').read_text()),
                  'native_flags': FLAGS, 'native_command': command, 'selected_esp_input': image,
                  'compiler_multilib': multi, 'crypto_input_sha256': crypto_report['build_input_sha256'],
                  'elf_sha256': sha(elf), 'ue2_sha256': sha(output), 'ue2_bytes': output.stat().st_size,
                  'source_manifest_sha256': sha(BUILD / 'source_manifest.json'),
                  'D81_REU_memory_windows': validation['D81_REU_memory_windows'],
                  'hardware_execution': 'NOT_RUN',
                  'build_identity_note': 'Absolute paths and build metadata contribute to the generated binary identity.'}
        (BUILD / 'build_report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': 'PASS', 'output': str(output), 'sha256': sha(output), 'bytes': output.stat().st_size}), flush=True)
    finally:
        for path, original in originals.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)


if __name__ == '__main__':
    main()
