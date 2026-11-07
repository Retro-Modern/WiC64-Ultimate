#!/usr/bin/env python3
"""Install the exact current native build dependencies into the local .deps cache."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import platform
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
DEPS = ROOT / '.deps'
COMPILER_ARCHIVE = 'xpack-riscv-none-elf-gcc-11.3.0-1-linux-x64.tar.gz'
COMPILER_URL = 'https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v11.3.0-1/' + COMPILER_ARCHIVE
COMPILER_SHA256 = '1c99fb1573ff2ed5deffce64cb96bb9272f351f054684c49dfd5ad41c6dd804d'
COMPILER_NAME = 'xpack-riscv-none-elf-gcc-11.3.0-1'


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def fetch(url, destination, digest=None):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and (digest is None or sha(destination) == digest):
        return destination
    print('Downloading ' + destination.name, flush=True)
    temporary = destination.with_name(destination.name + '.partial')
    request = urllib.request.Request(url, headers={'User-Agent': 'WiC64-C64U-source-setup'})
    try:
        with urllib.request.urlopen(request, timeout=120) as source, temporary.open('wb') as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        if digest and sha(temporary) != digest:
            raise ValueError('SHA256 mismatch: ' + destination.name)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def verified(path, digest, size=None):
    path = Path(path)
    if not path.is_file() or (size is not None and path.stat().st_size != size) or sha(path) != digest:
        raise ValueError('Dependency identity mismatch: ' + str(path))
    return path


def compiler_member(relative, is_directory):
    if is_directory:
        return True
    name = relative.as_posix()
    bins = {'gcc', 'gcc-11.3.0', 'g++', 'c++', 'cpp', 'ar', 'as', 'ld', 'ld.bfd', 'nm',
            'ranlib', 'objcopy', 'objdump', 'readelf', 'size', 'strings', 'strip', 'addr2line', 'c++filt'}
    if name == 'README.md' or (relative.parent.as_posix() == 'bin' and relative.name.removeprefix('riscv-none-elf-') in bins):
        return True
    prefixes = ('distro-info/', 'include/', 'lib64/', 'libexec/', 'riscv-none-elf/include/',
                'riscv-none-elf/bin/', 'riscv-none-elf/lib/rv32i/ilp32/', 'riscv-none-elf/lib/ldscripts/',
                'lib/gcc/riscv-none-elf/11.3.0/include/', 'lib/gcc/riscv-none-elf/11.3.0/include-fixed/',
                'lib/gcc/riscv-none-elf/11.3.0/rv32i/ilp32/')
    return name.startswith(prefixes) or (name.startswith('lib/gcc/riscv-none-elf/11.3.0/') and len(relative.parts) == 5) or (name.startswith('share/') and any(value in name.lower() for value in ('license', 'copying', '/doc/')))


def install_compiler(archive):
    verified(archive, COMPILER_SHA256)
    destination = DEPS / 'toolchain'
    ready = destination / 'compiler.sha256'
    if ready.is_file() and ready.read_text().strip() == COMPILER_SHA256 and (destination / COMPILER_NAME / 'bin/riscv-none-elf-gcc').is_file():
        return
    destination.mkdir(parents=True, exist_ok=True)
    print('Installing RV32I/ILP32 compiler', flush=True)
    with tarfile.open(archive, 'r:gz') as packed:
        for entry in packed:
            parts = PurePosixPath(entry.name).parts
            if not parts or parts[0] != COMPILER_NAME or '..' in parts or entry.name.startswith('/'):
                raise ValueError('Unexpected compiler archive path')
            relative = PurePosixPath(*parts[1:])
            if compiler_member(relative, entry.isdir()):
                packed.extract(entry, destination, filter='tar')
    ready.write_text(COMPILER_SHA256 + '\n')


def install_host_tools(cache, source_directory):
    metadata = json.loads((ROOT / 'dependencies/host_tools.json').read_text())
    destination = DEPS / 'host-tools'
    files = metadata['files']
    if all((destination / name).is_file() and sha(destination / name) == item['sha256'] for name, item in files.items()):
        return
    print('Preparing pinned native host-tool sources', flush=True)
    packed = None
    members = {}
    if source_directory is None:
        archive = fetch(metadata['url'], cache / metadata['archive'])
        packed = tarfile.open(archive, 'r:gz')
        for member in packed:
            parts = PurePosixPath(member.name).parts
            if member.isfile() and len(parts) > 1:
                members['/'.join(parts[1:])] = member
    try:
        for name, item in files.items():
            upstream = item.get('upstream', 'tools/' + name)
            if source_directory:
                source = source_directory / name
                if upstream == 'LICENSE.txt':
                    source = source_directory.parent / 'LICENSE.txt'
                data = verified(source, item['sha256'], item['bytes']).read_bytes()
            else:
                if upstream not in members:
                    raise ValueError('Missing upstream host-tool source: ' + upstream)
                data = packed.extractfile(members[upstream]).read()
                if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('Upstream host-tool identity mismatch: ' + upstream)
            output = destination / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
    finally:
        if packed is not None:
            packed.close()


def install_assets(cache, source_directory):
    metadata = json.loads((ROOT / 'dependencies/assets.json').read_text())
    for name, item in metadata.items():
        output = ROOT / 'src' / name
        if output.is_file() and output.stat().st_size == item['bytes'] and sha(output) == item['sha256']:
            continue
        if source_directory:
            source = verified(source_directory / name, item['sha256'], item['bytes'])
        else:
            source = fetch(item['url'], cache / ('asset-' + item['sha256'] + '.bin'), item['sha256'])
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-dir', type=Path, default=DEPS / 'downloads')
    parser.add_argument('--compiler-archive', type=Path)
    parser.add_argument('--wolfssl-archive', type=Path)
    parser.add_argument('--host-tools-source', type=Path)
    parser.add_argument('--asset-source', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine().lower() not in {'x86_64', 'amd64'}:
        raise SystemExit('Use Linux x86_64 or WSL2 with a Linux x86_64 distribution.')
    compiler_ready = DEPS / 'toolchain/compiler.sha256'
    compiler_binary = DEPS / 'toolchain' / COMPILER_NAME / 'bin/riscv-none-elf-gcc'
    if not (compiler_ready.is_file() and compiler_ready.read_text().strip() == COMPILER_SHA256 and compiler_binary.is_file()):
        compiler = args.compiler_archive or fetch(COMPILER_URL, args.cache_dir / COMPILER_ARCHIVE, COMPILER_SHA256)
        install_compiler(compiler)
    install_host_tools(args.cache_dir, args.host_tools_source)
    wolf = json.loads((ROOT / 'dependencies/wolfssl.json').read_text())
    wolf_destination = DEPS / 'wolfssl' / wolf['archive']
    if not (wolf_destination.is_file() and wolf_destination.stat().st_size == wolf['archive_bytes'] and sha(wolf_destination) == wolf['archive_sha256']):
        archive = args.wolfssl_archive or fetch(wolf['url'], args.cache_dir / wolf['archive'], wolf['archive_sha256'])
        verified(archive, wolf['archive_sha256'], wolf['archive_bytes'])
        wolf_destination.parent.mkdir(parents=True, exist_ok=True)
        if Path(archive).resolve() != wolf_destination.resolve():
            shutil.copy2(archive, wolf_destination)
    install_assets(args.cache_dir, args.asset_source)
    print('Native dependencies ready', flush=True)


if __name__ == '__main__':
    main()
