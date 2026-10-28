"""Install the pinned native Windows LLVM recovery backend locally.

Uses upstream RetDec v5.0 and conda-forge's OpenSSL 1.1 runtime. No PATH,
registry or OS changes are made. Existing differing files are never replaced.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

from cpp_recovery import ROOT, sha, atomic_json

RETDEC_URL = 'https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Windows-Release.7z'
RETDEC_SHA = '496a2d86420115eaa21ac8ff9b202282525f0a46a28a78c983f2cca0643ab101'
CRYPTO_URL = 'https://conda.anaconda.org/conda-forge/win-64/openssl-1.1.1w-hcfcfb64_0.conda'
CRYPTO_SHA = '6d46986fab161cb1b62f019c06dfc27f2e15caccd3943b3282d9e59872fa4ad2'


def download(url, target, digest):
    if not target.exists():
        pending = target.with_suffix('.part')
        try:
            with urllib.request.urlopen(url, timeout=60) as response, pending.open('wb') as output:
                shutil.copyfileobj(response, output)
            if sha(pending) != digest:
                raise ValueError('Downloaded archive hash differs: ' + url)
            pending.replace(target)
        finally:
            pending.unlink(missing_ok=True)
    if sha(target) != digest:
        raise ValueError('Existing archive differs: ' + str(target))


def install():
    if os.name != 'nt':
        raise ValueError('Install and use this backend on Windows')
    seven = shutil.which('7z') or r'C:\Program Files\7-Zip\7z.exe'
    if not Path(seven).is_file():
        raise ValueError('7-Zip is required to unpack the upstream Windows distribution')
    destination = ROOT / '.toolchains/retdec-v5.0'
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / 'RetDec-v5.0-Windows-Release.7z'
    crypto = destination / 'openssl-1.1.1w.conda'
    download(RETDEC_URL, archive, RETDEC_SHA)
    download(CRYPTO_URL, crypto, CRYPTO_SHA)
    with tempfile.TemporaryDirectory(prefix='recovery-install-',dir=destination) as folder:
        staging = Path(folder)
        subprocess.run([seven,'x','-y','-bso0','-bsp0',str(archive),'-o'+str(staging),
                        'bin/retdec-decompiler.exe','share/retdec/decompiler-config.json',
                        'share/retdec/support/ordinals/*','share/retdec/support/generic/types/*',
                        'share/retdec/support/generic/yara_patterns/signsrch/*','LICENSE*'],check=True)
        with zipfile.ZipFile(crypto) as package:
            for name in package.namelist():
                if not name.endswith('.tar.zst'):
                    continue
                compressed = staging / 'runtime.tar.zst'
                compressed.write_bytes(package.read(name))
                tar_path = staging / 'runtime.tar'
                with tar_path.open('wb') as stream:
                    subprocess.run([seven,'e','-so',str(compressed)],stdout=stream,stderr=subprocess.PIPE,check=True)
                with tarfile.open(tar_path) as files:
                    for member in files:
                        if member.name.endswith('/libcrypto-1_1-x64.dll'):
                            (staging/'bin/libcrypto-1_1-x64.dll').write_bytes(files.extractfile(member).read())
                        elif member.isfile() and member.name.startswith('info/licenses/'):
                            target = staging/'licenses/openssl'/Path(member.name).name
                            target.parent.mkdir(parents=True,exist_ok=True)
                            target.write_bytes(files.extractfile(member).read())
                compressed.unlink(); tar_path.unlink()
        files = [p for p in staging.rglob('*') if p.is_file()]
        for source in files:
            target = destination/source.relative_to(staging)
            if target.exists() and sha(target) != sha(source):
                raise ValueError('Existing tool file differs; installation stopped: ' + str(target))
        for source in files:
            target = destination/source.relative_to(staging)
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(source,target)
        executable = destination/'bin/retdec-decompiler.exe'
        subprocess.run([str(executable),'--help'],capture_output=True,check=True,timeout=30)
        receipt = dict(schema=1,version='5.0',host='windows-x64',
                       archives=[dict(url=RETDEC_URL,sha256=RETDEC_SHA),dict(url=CRYPTO_URL,sha256=CRYPTO_SHA)],
                       files={p.relative_to(staging).as_posix():sha(p) for p in files})
        atomic_json(destination/'installation.json',receipt)
    print(json.dumps(dict(installed=str(destination),tool_sha256=sha(executable)),indent=2))


if __name__ == '__main__':
    install()
