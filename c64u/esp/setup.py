#!/usr/bin/env python3
"""Install pinned ESP build dependencies locally in .deps."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import venv
import zipfile

ROOT = Path(__file__).resolve().parent
DEPS = ROOT / '.deps'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(command, log):
    with log.open('a') as stream:
        p = subprocess.run([str(x) for x in command], stdout=stream,
                           stderr=subprocess.STDOUT)
    if p.returncode:
        raise RuntimeError(f'Dependency setup failed; see {log}')


def sdk_digest(directory):
    digest = hashlib.sha256()
    count = 0
    for path in sorted(directory.rglob('*'), key=lambda p: p.relative_to(directory).as_posix()):
        if path.is_symlink():
            data = os.readlink(path).encode()
            mode = '120000'
        elif path.is_file():
            data = path.read_bytes()
            mode = '100755' if path.stat().st_mode & stat.S_IXUSR else '100644'
        else:
            continue
        relative = path.relative_to(directory).as_posix()
        row = relative + '\0' + mode + '\0' + str(len(data)) + '\0' + hashlib.sha256(data).hexdigest() + '\n'
        digest.update(row.encode())
        count += 1
    return count, digest.hexdigest()


def install_sdk(pin, log):
    sdk = DEPS / 'esp-idf'
    marker = DEPS / 'sdk.json'
    wanted = (pin['file_count'], pin['export_digest_sha256'])
    if marker.exists() and sdk.is_dir() and not (sdk / '.git').exists():
        if sdk_digest(sdk) == wanted:
            return
        raise RuntimeError('The installed ESP-IDF source differs from its pinned revision.')
    checkout = DEPS / 'sdk-checkout'
    # Continue an interrupted checkout, but never use an unrelated repository.
    if (sdk / '.git').exists() and not checkout.exists():
        sdk.rename(checkout)
    if not (checkout / '.git').exists():
        checkout.mkdir(exist_ok=True)
        run(['git', 'init', checkout], log)
        run(['git', '-C', checkout, 'remote', 'add', 'origin', pin['url']], log)
    remote = subprocess.check_output(['git', '-C', checkout, 'remote', 'get-url', 'origin'], text=True).strip()
    if remote != pin['url']:
        raise RuntimeError('Unexpected ESP-IDF checkout remote.')
    print('Fetching ESP-IDF ' + pin['version'] + ' and pinned submodules...', flush=True)
    run(['git', '-C', checkout, '-c', 'http.version=HTTP/1.1', 'fetch', '--depth', '1',
         'origin', pin['commit']], log)
    run(['git', '-C', checkout, 'checkout', '--detach', 'FETCH_HEAD'], log)
    run(['git', '-C', checkout, '-c', 'http.version=HTTP/1.1', 'submodule', 'update',
         '--init', '--recursive', '--depth', '1', '--jobs', '4'], log)
    actual = subprocess.check_output(['git', '-C', checkout, 'rev-parse', 'HEAD'], text=True).strip()
    if actual != pin['commit']:
        raise RuntimeError('Unexpected ESP-IDF revision.')
    lines = subprocess.check_output(['git', '-C', checkout, 'submodule', 'status', '--recursive'], text=True)
    observed = {}
    for line in lines.splitlines():
        if not line.startswith(' '):
            raise RuntimeError('An ESP-IDF submodule is not at its pinned commit.')
        commit, path, *_ = line.split()
        observed[path] = commit
    if observed != pin['submodules']:
        raise RuntimeError('ESP-IDF submodule inventory differs.')
    files = subprocess.check_output(['git', '-C', checkout, 'ls-files', '--recurse-submodules', '-z']).split(b'\0')
    exported = DEPS / 'sdk-export'
    if exported.exists():
        shutil.rmtree(exported)
    exported.mkdir()
    for raw in files:
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        source = checkout / relative
        target = exported / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target)
    if sdk_digest(exported) != wanted:
        raise RuntimeError('Exported ESP-IDF sources failed SHA256 verification.')
    if sdk.exists():
        raise RuntimeError('Refuse to overwrite an unexpected ESP-IDF directory.')
    exported.rename(sdk)
    marker.write_text(json.dumps({'commit': pin['commit'], 'export_digest_sha256': wanted[1]}, indent=2) + '\n')
    shutil.rmtree(checkout)


def fetch_tool(row):
    downloads = DEPS / 'downloads'
    downloads.mkdir(exist_ok=True)
    path = downloads / row['filename']
    if path.is_file() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']:
        return path
    temporary = path.with_suffix(path.suffix + '.partial')
    print('Downloading ' + row['name'] + ' ' + row['version'] + '...', flush=True)
    with urllib.request.urlopen(row['url'], timeout=180) as source, temporary.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    if temporary.stat().st_size != row['bytes'] or sha(temporary) != row['sha256']:
        temporary.unlink(missing_ok=True)
        raise RuntimeError('Tool archive SHA256 mismatch: ' + row['filename'])
    temporary.replace(path)
    return path


def main():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise RuntimeError('Use x86-64 Linux or WSL2 Ubuntu 24.04.')
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('Use Python 3.12, as supplied by Ubuntu 24.04.')
    if shutil.which('git') is None:
        raise RuntimeError('Install git before running setup.')
    pins = json.loads((ROOT / 'toolchain.json').read_text())
    constraints = ROOT / 'espidf.constraints.v5.3.txt'
    if sha(constraints) != pins['python_constraints_sha256']:
        raise RuntimeError('ESP-IDF Python constraint file changed.')
    DEPS.mkdir(exist_ok=True)
    log = DEPS / 'setup.log'
    install_sdk(pins['sdk'], log)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        archives = list(pool.map(fetch_tool, pins['tools']))
    for row, archive in zip(pins['tools'], archives):
        destination = DEPS / row['destination']
        marker = DEPS / (row['destination'] + '.json')
        if marker.exists() and json.loads(marker.read_text()).get('archive_sha256') == row['sha256']:
            continue
        destination.mkdir(exist_ok=True)
        if archive.suffix == '.zip':
            with zipfile.ZipFile(archive) as stream:
                for name in stream.namelist():
                    if not (destination / name).resolve().is_relative_to(destination.resolve()):
                        raise RuntimeError('Unsafe ZIP member.')
                stream.extractall(destination)
            if row['name'] == 'ninja':
                (destination / 'ninja').chmod(0o755)
        else:
            with tarfile.open(archive) as stream:
                stream.extractall(destination, filter='data')
        marker.write_text(json.dumps({'archive_sha256': row['sha256']}, indent=2) + '\n')
    python = DEPS / 'python/bin/python'
    requirements = ROOT / 'requirements-lock.txt'
    marker = DEPS / 'python.json'
    wanted = sha(requirements)
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(DEPS / 'python')
    if not marker.exists() or json.loads(marker.read_text()).get('requirements_sha256') != wanted:
        print('Installing pinned Python dependencies...', flush=True)
        run([python, '-m', 'pip', 'install', '--disable-pip-version-check', '-r', requirements,
             '-c', constraints], log)
        marker.write_text(json.dumps({'requirements_sha256': wanted}, indent=2) + '\n')
    tools = DEPS / 'espressif'
    tools.mkdir(exist_ok=True)
    shutil.copyfile(constraints, tools / constraints.name)
    print('ESP build dependencies are ready.', flush=True)


if __name__ == '__main__':
    main()
