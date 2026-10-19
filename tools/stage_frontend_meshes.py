"""Stage hash-verified converted mesh dependencies in a fresh isolated run folder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct


def checked_files(manifest_path):
    manifest_path=Path(manifest_path).resolve()
    document=json.loads(manifest_path.read_text())
    if document.get('schema')!=2 or document.get('source_version')!=4289:
        raise ValueError('Unsupported mesh cache contract')
    if not re.fullmatch(r'[0-9a-f]{64}',document.get('source_sha256','')):
        raise ValueError('Mesh cache lacks source identity')
    names=set(); files=set(); result=[]
    for item in document['files']:
        name=item['name']; filename=item['file']
        if not name or name in names or filename in files or not re.fullmatch(r'[0-9a-f]{16}\.rmesh',filename):
            raise ValueError('Duplicate or unsafe mesh identity')
        value=0xcbf29ce484222325
        for byte in name.encode():value=((value^byte)*0x100000001b3)&0xffffffffffffffff
        if filename!=f'{value:016x}.rmesh':raise ValueError('Mesh name/file identity mismatch')
        source=manifest_path.parent/filename
        data=source.read_bytes()
        if len(data)!=item['bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise ValueError(f'Mesh dependency changed: {filename}')
        if len(data)<40:raise ValueError('Truncated mesh header')
        magic,version,count,source_size,resident_size,_,_=struct.unpack_from('<QIIIIQQ',data)
        if magic!=0x3248534d594c5052 or version!=document['source_version'] or not 0<count<=65535 or source_size>resident_size or len(data)!=40+count*4+resident_size:
            raise ValueError('Mesh dependency header mismatch')
        result.append((source,item));names.add(name);files.add(filename)
    if not result:raise ValueError('Empty mesh manifest')
    return document,result


def stage(manifest_path,run_folder,hardlink=False):
    paths=[manifest_path] if isinstance(manifest_path,(str,Path)) else list(manifest_path)
    if not paths:raise ValueError('At least one mesh manifest is required')
    files_by_name={}; manifests=[]; version=None
    for path in paths:
        document,entries=checked_files(path)
        if version is not None and document['source_version']!=version:
            raise ValueError('Mesh manifests must share a serialized version')
        version=document['source_version']
        manifests.append(dict(source_sha256=document['source_sha256'],
                              manifest_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                              files=[item['file'] for _,item in entries]))
        for source,item in entries:
            previous=files_by_name.get(item['file'])
            if previous and any(previous[1][key]!=item[key] for key in ('name','bytes','sha256')):
                raise ValueError(f'Conflicting mesh dependency: {item["name"]}')
            files_by_name.setdefault(item['file'],(source,item))
    files=list(files_by_name.values())
    run_folder=Path(run_folder).resolve(strict=True)
    if not run_folder.name.startswith('replay-compiler-frontend-'):
        raise ValueError('Mesh dependencies require an isolated frontend run folder')
    zone=(run_folder/'zone').resolve(strict=True)
    if zone.parent!=run_folder:
        raise ValueError('Mesh dependencies require an isolated, local zone directory')
    destination=zone/f'replay_mesh_{version}'
    if destination.exists():raise ValueError('Mesh dependency destination must be fresh')
    destination.mkdir()
    for source,item in files:
        target=destination/item['file']
        if hardlink:
            # Frozen converted meshes are opened read-only by the game. Share
            # their verified storage between isolated runs on the same volume.
            # Fail rather than silently copying when linking is unavailable.
            os.link(source,target)
            if not source.samefile(target):
                raise ValueError('Mesh dependency hardlink identity mismatch')
        else:
            shutil.copyfile(source,target)
        if hashlib.sha256(target.read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError('Mesh dependency copy verification failed')
    receipt=dict(schema=3,source_version=version,manifests=manifests,
                 storage='verified-hardlinks' if hardlink else 'verified-copies',
                 files=[item for _,item in files],status='staged; runtime admission remains controlled by the compiled profile')
    (destination/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return dict(destination=str(destination),files=len(files),bytes=sum(item['bytes'] for _,item in files),
                source_sha256s=[item['source_sha256'] for item in manifests])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,nargs='+',required=True)
    parser.add_argument('--run-folder',type=Path,required=True)
    parser.add_argument('--hardlink',action='store_true',
                        help='Share immutable, hash-verified mesh files on the same volume')
    args=parser.parse_args()
    print(json.dumps(stage(args.manifest,args.run_folder,args.hardlink),indent=2))
