"""Build the checked-in observation-only patch against a verified source archive."""
import hashlib
import io
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

recipe = Path(__file__).parent
provenance = json.loads((recipe / 'provenance.json').read_text())
def download(url, expected):
    data = urllib.request.urlopen(url, timeout=120).read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('SHA256 mismatch: ' + url)
    return data

patch = recipe / 'delete.patch'
assert hashlib.sha256(patch.read_bytes()).hexdigest() == provenance['patch_sha256']
source = download(provenance['source_url'], provenance['source_sha256'])
work = Path('/gvisor-source')
work.mkdir(exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(source), mode='r:gz') as archive:
    archive.extractall(work, filter='data')
root = work / ('gvisor-' + provenance['upstream_commit'])
subprocess.run(['patch', '-p1', '--batch', '--fuzz=0', '-i', str(patch)], cwd=root, check=True)
arch = 'arm64' if platform.machine() == 'aarch64' else 'x86_64'
version = (root / '.bazelversion').read_text().strip()
url = f'https://releases.bazel.build/{version}/release/bazel-{version}-linux-{arch}'
sha = urllib.request.urlopen(url + '.sha256', timeout=60).read().decode().split()[0]
bazel = Path('/usr/local/bin/bazel')
bazel.write_bytes(download(url, sha)); bazel.chmod(0o755)
(root / 'tools/workspace_status.sh').write_text('#!/bin/sh\necho STABLE_VERSION release-20260928.0-traceward-delete1\n')
subprocess.run([str(bazel), '--batch', 'build', '--jobs=4', '--local_resources=memory=4096',
                '//:release', '--config=' + ('aarch64' if arch == 'arm64' else 'x86_64')], cwd=root, check=True)
Path('/out').mkdir(exist_ok=True)
shutil.copytree(root / 'bazel-bin/release', '/out/bin', dirs_exist_ok=True)
shutil.copy2(recipe / 'provenance.json', '/out/gvisor-provenance.json')
