#!/usr/bin/env python3
"""Build the source-bound wolfSSL client library for P14, without device I/O.

The full unmodified upstream source is delivered as its official ZIP. Extracted
sources are a disposable cache; no configure-generated files are used. Native
and owned-host tests use the same explicit user_settings.h and C source list.
"""
from pathlib import Path, PurePosixPath
from concurrent.futures import ThreadPoolExecutor
import argparse
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / '.deps/wolfssl'
SETTINGS = ROOT / 'crypto/user_settings.h'
VERSION = '5.9.4'
TLS_SOURCES = ('src/ssl.c', 'src/internal.c', 'src/tls.c', 'src/tls13.c',
               'src/keys.c', 'src/wolfio.c')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def archive_files():
    metadata = json.loads((ROOT / 'dependencies/wolfssl.json').read_text())
    archive = VENDOR / metadata['archive']
    need(metadata['version'] == VERSION, 'Unexpected wolfSSL release')
    need(archive.stat().st_size == metadata['archive_bytes'] and
         sha(archive) == metadata['archive_sha256'] == metadata['expected_official_download_sha256'],
         'Official wolfSSL archive identity mismatch')
    prefix = 'wolfssl-' + VERSION
    expected = {}
    with zipfile.ZipFile(archive) as packed:
        need(packed.testzip() is None, 'wolfSSL archive CRC failure')
        for entry in packed.infolist():
            relative = PurePosixPath(entry.filename)
            need(not relative.is_absolute() and '..' not in relative.parts and
                 relative.parts and relative.parts[0] == prefix and
                 not stat.S_ISLNK(entry.external_attr >> 16), 'Unsafe wolfSSL archive path')
            if entry.is_dir():
                continue
            path = Path(*relative.parts[1:]).as_posix()
            need(path and path not in expected, 'Duplicate wolfSSL archive member')
            expected[path] = hashlib.sha256(packed.read(entry)).hexdigest()
    return metadata, archive, expected


def ensure_sources():
    """Extract when absent and verify every installed upstream file unchanged."""
    metadata, archive, expected = archive_files()
    directory = VENDOR / ('wolfssl-' + VERSION)
    if not directory.exists():
        VENDOR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='extract_wolfssl_', dir=VENDOR) as temporary:
            destination = Path(temporary)
            with zipfile.ZipFile(archive) as packed:
                for entry in packed.infolist():
                    if entry.is_dir():
                        continue
                    relative = PurePosixPath(entry.filename)
                    target = destination.joinpath(*relative.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(packed.read(entry))
            shutil.move(str(destination / directory.name), directory)
    actual = {}
    for path in directory.rglob('*'):
        need(not path.is_symlink(), 'Extracted wolfSSL sources contain a symlink')
        if path.is_file():
            actual[path.relative_to(directory).as_posix()] = sha(path)
    need(actual == expected, 'Installed wolfSSL tree differs from the official archive')
    return directory


def source_files(directory=None):
    directory = Path(directory) if directory is not None else ensure_sources()
    # Optional algorithms compile to empty objects when disabled by the pinned
    # settings. Keeping upstream's top-level crypto units avoids a hidden
    # dependency on configure output or a host feature-discovery result.
    result = sorted(path.relative_to(directory).as_posix()
                    for path in (directory / 'wolfcrypt/src').glob('*.c'))
    result.extend(TLS_SOURCES)
    need(len(result) == len(set(result)), 'Duplicate wolfSSL translation unit')
    return tuple(result)


def inputs_match(values):
    return all((ROOT / name).is_file() and sha(ROOT / name) == digest
               for name, digest in values.items())


def object_identity_matches(path, digest):
    """The forced, used marker must survive in every individual object."""
    return Path(path).is_file() and digest.encode('ascii') + b'\0' in Path(path).read_bytes()


def identity_header(digest):
    return ("/* Generated content identity: every crypto ABI consumer includes this. */\n"
            "#ifndef P14_WOLFSSL_BUILD_IDENTITY_H\n#define P14_WOLFSSL_BUILD_IDENTITY_H\n"
            "#ifndef P14_WOLFSSL_BUILD_INPUT_SHA256\n#error Missing P14 crypto build identity\n#endif\n"
            "#define P14_WOLFSSL_STRINGIFY_(x) #x\n"
            "#define P14_WOLFSSL_STRINGIFY(x) P14_WOLFSSL_STRINGIFY_(x)\n"
            "static const char p14_wolfssl_build_input_identity[] __attribute__((used)) =\n"
            "    P14_WOLFSSL_STRINGIFY(P14_WOLFSSL_BUILD_INPUT_SHA256);\n"
            "#endif\n").encode('ascii')


def cache_matches(output, report, identity):
    """Never trust timestamps, a library alone, or a matching report alone."""
    try:
        digest = report['build_input_sha256']
        expected_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        objects = report['object_names']
        return (report.get('identity') == identity and digest == expected_digest and
                bool(objects) and len(objects) == len(identity['translation_units']) and
                (output / 'build_identity.h').read_bytes() == identity_header(digest) and
                sha(output / 'libwolfssl.a') == report['library_sha256'] and
                inputs_match(report['source_inputs_sha256']) and
                all((output / name).is_file() and sha(output / name) == value
                    for name, value in report['artifacts_sha256'].items()) and
                all(object_identity_matches(output / name, digest) for name in objects))
    except (KeyError, OSError, ValueError, TypeError):
        return False


def check_owned_output(output):
    if output.exists():
        owned = {'objects', 'logs', 'libwolfssl.a', 'wolfssl_build_report.json', 'build_identity.h'}
        need(output.is_dir() and not output.is_symlink() and
             not (set(p.name for p in output.iterdir()) - owned),
             'Refusing to clear an output directory with unrelated files')


def build_library(output, cross_prefix=None, jobs=4, *, fresh=False, extra_flags=()):
    """Build a complete library privately, then publish under an exclusive lock.

    Configuration, all upstream files (including every public header), compiler
    and flags form a content key in every compiler invocation and object. A
    header-only settings change therefore cannot reuse an object of another ABI.
    Native callers supply the reviewed riscv-none-elf- prefix; host builds only
    support owned tests. The existing complete result remains intact on failure.
    """
    output = Path(output).resolve()
    need(1 <= jobs <= 32, 'jobs must be 1..32')
    output.parent.mkdir(parents=True, exist_ok=True)
    # The lock lives outside the directory that is replaced under this lock.
    with (output.parent / ('.' + output.name + '.wolfssl.lock')).open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _build_locked(output, cross_prefix, jobs, fresh, tuple(extra_flags))


def _build_locked(output, cross_prefix, jobs, fresh, extra_flags):
    check_owned_output(output)
    directory = ensure_sources()
    need(SETTINGS.is_file(), 'P14 wolfSSL user settings missing')
    compiler = str(cross_prefix) + 'gcc' if cross_prefix else 'gcc'
    archiver = str(cross_prefix) + 'ar' if cross_prefix else 'ar'
    version = subprocess.check_output([compiler, '--version'], text=True).splitlines()[0]
    if cross_prefix:
        need('11.3.0' in version, 'Use the reviewed xPack GCC 11.3.0 target compiler')
    # Upstream's compiler hardening profile also enables -fwrapv. Full SP
    # math uses signed redundant limbs whose add/subtract wrap is intentional;
    # define that arithmetic on both host and RV32 rather than relying on UB.
    flags = ['-std=gnu99', '-Os', '-fwrapv', '-ffunction-sections', '-fdata-sections', '-fno-common',
             '-fstack-usage', '-gdwarf-2', '-DWOLFSSL_USER_SETTINGS',
             '-I' + str(SETTINGS.parent), '-I' + str(directory),
             '-Wno-unused-function', '-Wno-unused-parameter']
    if cross_prefix:
        flags += ['-march=rv32im', '-mabi=ilp32', '-mno-div', '-nostartfiles']
    flags += list(extra_flags)
    files = source_files(directory)
    meta, archive, official = archive_files()
    upstream_digest = hashlib.sha256(json.dumps(official, sort_keys=True).encode()).hexdigest()
    identity = {'compiler': version, 'compiler_binary_sha256': sha(Path(shutil.which(compiler)).resolve()),
                'archiver_binary_sha256': sha(Path(shutil.which(archiver)).resolve()),
                'flags': flags, 'translation_units': list(files),
                'native_rv32': bool(cross_prefix), 'archive_sha256': sha(archive),
                'upstream_all_files_sha256': upstream_digest,
                'upstream_file_count': len(official),
                'settings_sha256': sha(SETTINGS), 'builder_sha256': sha(Path(__file__))}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    report_path = output / 'wolfssl_build_report.json'
    if not fresh and report_path.is_file():
        try:
            prior = json.loads(report_path.read_text())
            if cache_matches(output, prior, identity):
                return prior
        except (ValueError, OSError):
            pass
    # A unique path also defeats caches keyed by stale source/argv paths. Every
    # single unit is built here; no object is copied from a previous result.
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '.stage-', dir=output.parent) as temporary:
        stage = Path(temporary)
        objects_dir = stage / 'objects'; objects_dir.mkdir()
        logs_dir = stage / 'logs'; logs_dir.mkdir()
        generated = stage / 'build_identity.h'
        generated.write_bytes(identity_header(digest))
        bound_flags = [*flags, '-DP14_WOLFSSL_BUILD_INPUT_SHA256=' + digest,
                       '-include', str(generated)]
        selected_before = {str((directory / name).relative_to(ROOT)): sha(directory / name) for name in files}
        selected_before[str(SETTINGS.relative_to(ROOT))] = sha(SETTINGS)

        def compile_one(relative):
            stem = relative.replace('/', '__')[:-2]
            obj = objects_dir / (stem + '.o')
            dependency = objects_dir / (stem + '.d')
            command = [compiler, *bound_flags, '-MMD', '-MF', str(dependency), '-c',
                       str(directory / relative), '-o', str(obj)]
            process = subprocess.run(command, capture_output=True, text=True)
            (logs_dir / (stem + '.log')).write_text(json.dumps(command) + '\n' + process.stdout + process.stderr)
            need(process.returncode == 0, 'wolfSSL compilation failed: ' + relative + '\n' + process.stderr[-6000:])
            need(object_identity_matches(obj, digest), 'Stale or unbound crypto object: ' + relative)
            return obj, dependency

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            compiled = list(pool.map(compile_one, files))
        objects = [item[0] for item in compiled]
        archive_path = stage / 'libwolfssl.a'
        subprocess.run([archiver, 'rcsD', str(archive_path), *map(str, objects)], check=True,
                       capture_output=True, text=True)
        inputs = dict(selected_before)
        for _, dependency in compiled:
            content = dependency.read_text().replace('\\\n', ' ')
            for name in shlex.split(content.split(':', 1)[1]):
                path = Path(name).resolve()
                if path == generated:
                    continue
                need(path.is_relative_to(ROOT), 'Unbound external crypto include: ' + str(path))
                inputs[path.relative_to(ROOT).as_posix()] = sha(path)
        # Revalidate the complete official tree, not merely files noticed by MMD.
        need(ensure_sources() == directory and sha(archive) == identity['archive_sha256'] and
             hashlib.sha256(json.dumps(archive_files()[2], sort_keys=True).encode()).hexdigest() ==
             identity['upstream_all_files_sha256'] and inputs_match(inputs) and
             sha(SETTINGS) == identity['settings_sha256'] and
             sha(Path(__file__)) == identity['builder_sha256'],
             'Crypto source/header/settings/builder changed during compilation')
        for name, value in inputs.items():
            path = ROOT / name
            if path.is_relative_to(directory):
                need(official.get(path.relative_to(directory).as_posix()) == value,
                     'Compiled upstream crypto dependency is modified: ' + name)
        artifacts = {p.relative_to(stage).as_posix(): sha(p) for p in stage.rglob('*') if p.is_file()}
        report = {'status': 'EXECUTED_PASS', 'product': 'P14_WOLFSSL', 'version': VERSION,
                  'identity': identity, 'build_input_sha256': digest,
                  'identity_compiler_argument': '-DP14_WOLFSSL_BUILD_INPUT_SHA256=' + digest,
                  'identity_header_sha256': sha(generated),
                  'object_names': [p.relative_to(stage).as_posix() for p in objects],
                  'build_isolation': 'Exclusive flock; unique complete staging build; per-object embedded key; serialized complete-directory publication.',
                  'source_archive': {'path': archive.relative_to(ROOT).as_posix(),
                      'bytes': archive.stat().st_size, 'sha256': identity['archive_sha256'],
                      'url': meta['url'], 'license': meta['license'],
                      'provenance_sha256': sha(ROOT / 'dependencies/wolfssl.json')},
                  'source_directory': directory.relative_to(ROOT).as_posix(),
                  'settings_path': SETTINGS.relative_to(ROOT).as_posix(),
                  'source_inputs_sha256': inputs, 'library_sha256': sha(archive_path),
                  'library_bytes': archive_path.stat().st_size, 'artifacts_sha256': artifacts,
                  'hardware_execution': 'NOT_RUN',
                  'limits': ['Compile/archive proof; TLS/entropy/certificate behavior has separate owned-server tests.',
                             'The unmodified upstream archive contains public upstream test fixtures; none are production trust anchors.']}
        (stage / 'wolfssl_build_report.json').write_text(json.dumps(report, indent=2) + '\n')
        need(cache_matches(stage, report, identity), 'Complete staged crypto result failed self-validation')
        # Retain the old complete tree until the new result is entirely verified.
        previous = None
        if output.exists():
            previous = Path(tempfile.mkdtemp(prefix='.' + output.name + '.previous-', dir=output.parent))
            previous.rmdir()
            output.rename(previous)
        try:
            stage.rename(output)
        except BaseException:
            if previous is not None:
                previous.rename(output)
            raise
        if previous is not None:
            shutil.rmtree(previous)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cross-prefix')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--extra-flag', action='append', default=[])
    args = parser.parse_args()
    report = build_library(args.output, args.cross_prefix, args.jobs,
                           fresh=args.fresh, extra_flags=args.extra_flag)
    print(json.dumps({key: report[key] for key in
                     ('status', 'version', 'library_bytes', 'library_sha256')}, indent=2))


if __name__ == '__main__':
    main()
