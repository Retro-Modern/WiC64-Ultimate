#!/usr/bin/env python3
"""wolfSSL aus Wanderers Quellen (u64e2/crypto) fuer den Nios II des ersten U64 bauen.

Wie build_support/crypto.py, nur mit Nios-II-Flags statt rv32im.
Aufruf: python3 wolfssl_nios2.py <ausgabeordner> <u64e2-ordner> <toolchain-ordner>
"""
import hashlib, json, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

out = Path(sys.argv[1]).resolve()
ROOT = Path(sys.argv[2]).resolve()
PREFIX = str(Path(sys.argv[3]).resolve() / 'bin/nios2-elf-')
out.mkdir(parents=True, exist_ok=True)
source, settings = ROOT / 'crypto/wolfssl', ROOT / 'crypto'
units = [u for u in (settings / 'sources.txt').read_text().splitlines() if u.strip()]
identity = {str(p.relative_to(settings)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in settings.rglob('*') if p.is_file()}
digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
header = out / 'build_identity.h'
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
''')  # wie u64e2/build_support/crypto.py
flags = ['-std=gnu99', '-Os', '-fwrapv', '-ffunction-sections', '-fdata-sections',
         '-fno-common', '-gdwarf-2', '-DWOLFSSL_USER_SETTINGS',
         '-I' + str(settings), '-I' + str(source), '-Wno-unused-function',
         '-Wno-unused-parameter', '-mno-hw-div', '-mno-hw-mul', '-mno-hw-mulx',
         '-DP14_WOLFSSL_BUILD_INPUT_SHA256=' + digest, '-include', str(header)]


def one(name):
    obj = out / (name.replace('/', '__')[:-2] + '.o')
    r = subprocess.run([PREFIX + 'gcc', *flags, '-c', str(source / name), '-o', str(obj)],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError('wolfSSL: ' + name + '\n' + r.stderr[-3000:])
    return obj


with ThreadPoolExecutor(max_workers=16) as pool:
    objects = list(pool.map(one, units))
lib = out / 'libwolfssl.a'
lib.unlink(missing_ok=True)
subprocess.run([PREFIX + 'ar', 'rcsD', str(lib), *map(str, objects)], check=True)
print(lib)
print(digest)
print(header)
