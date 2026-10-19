"""Install the pinned MIT-licensed Monaco editor from the npm registry."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.57.0'
URL = f'https://registry.npmjs.org/monaco-editor/-/monaco-editor-{VERSION}.tgz'
INTEGRITY = '5BkI9KGoqrNvBGUe15/QlZq3OooZ8WLg1AxTpaqHRCP3HNpzPPZKE2EDz8M7c+VRmCeUw1Brp4cx/PWm3kI/5A=='


def install():
    destination = ROOT / 'workstation/web/vendor/monaco'
    receipt_path = destination / 'receipt.json'
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text())
        if receipt.get('version') == VERSION and all((destination / name).is_file() and
                hashlib.sha256((destination / name).read_bytes()).hexdigest() == sha
                for name, sha in receipt.get('files', {}).items()) and receipt.get('files'):
            return receipt
    with urllib.request.urlopen(URL, timeout=120) as response:
        package = response.read(64 << 20)
    if base64.b64encode(hashlib.sha512(package).digest()).decode() != INTEGRITY:
        raise ValueError('Monaco package integrity differs from the pinned npm release')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if member.name.startswith('package/min/vs/'):
                relative = member.name.removeprefix('package/min/')
            elif member.name in ('package/LICENSE', 'package/ThirdPartyNotices.txt'):
                relative = member.name.removeprefix('package/')
            else:
                continue
            path = (destination / relative).resolve()
            if not path.is_relative_to(destination.resolve()):
                raise ValueError('Invalid editor package member path')
            data = archive.extractfile(member).read()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            files[relative] = hashlib.sha256(data).hexdigest()
    if 'vs/loader.js' not in files:
        raise ValueError('Pinned editor package has no AMD loader')
    receipt = {'version': VERSION, 'source': URL, 'license': 'MIT', 'package_sha256': hashlib.sha256(package).hexdigest(),
               'package_sha512_base64': INTEGRITY, 'files': files}
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    result = install()
    print(json.dumps({key: value for key, value in result.items() if key != 'files'}))
