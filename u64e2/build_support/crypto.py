# SPDX-License-Identifier: GPL-3.0-or-later
# Current distribution, modified 2026-11-05.
"""Compile the included wolfSSL sources with the firmware's fixed ABI."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import subprocess


def build(root, output, prefix, jobs):
    root, output = Path(root), Path(output)
    output.mkdir(parents=True)
    source = root / 'crypto/wolfssl'
    settings = root / 'crypto'
    units = (settings / 'sources.txt').read_text().splitlines()
    identity = {str(p.relative_to(settings)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in settings.rglob('*') if p.is_file()}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    header = output / 'build_identity.h'
    header.write_text('''/* Generated crypto ABI identity. */
#ifndef P14_WOLFSSL_BUILD_IDENTITY_H
#define P14_WOLFSSL_BUILD_IDENTITY_H
#ifndef P14_WOLFSSL_BUILD_INPUT_SHA256
#error Missing crypto build identity
#endif
#define P14_WOLFSSL_STRINGIFY_(x) #x
#define P14_WOLFSSL_STRINGIFY(x) P14_WOLFSSL_STRINGIFY_(x)
static const char p14_wolfssl_build_input_identity[] __attribute__((used)) =
    P14_WOLFSSL_STRINGIFY(P14_WOLFSSL_BUILD_INPUT_SHA256);
#endif
''')
    flags = ['-std=gnu99', '-Os', '-fwrapv', '-ffunction-sections', '-fdata-sections',
             '-fno-common', '-fstack-usage', '-gdwarf-2', '-DWOLFSSL_USER_SETTINGS',
             '-I' + str(settings), '-I' + str(source), '-Wno-unused-function',
             '-Wno-unused-parameter', '-march=rv32im', '-mabi=ilp32', '-mno-div',
             '-nostartfiles', '-DP14_WOLFSSL_BUILD_INPUT_SHA256=' + digest,
             '-include', str(header)]

    def one(name):
        obj = output / (name.replace('/', '__')[:-2] + '.o')
        result = subprocess.run([str(prefix) + 'gcc', *flags, '-c', str(source / name),
                                 '-o', str(obj)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('wolfSSL: ' + name + '\n' + result.stderr)
        if digest.encode() + b'\0' not in obj.read_bytes():
            raise RuntimeError('Missing crypto ABI identity: ' + name)
        return obj

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        objects = list(pool.map(one, units))
    library = output / 'libwolfssl.a'
    subprocess.run([str(prefix) + 'ar', 'rcsD', str(library), *map(str, objects)], check=True)
    return library, digest, header
