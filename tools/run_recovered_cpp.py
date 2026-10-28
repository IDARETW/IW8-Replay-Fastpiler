"""Stage and launch a verified Windows Replay build in its own runtime folder."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from cpp_recovery import ROOT, Recovery, sha, atomic_json, windows_compiler


def validated_proxy(root, executable):
    folder=Path(root)/'.toolchains/cpp-runtime-proxy'
    receipt=folder/'receipt.json'
    if not receipt.is_file():
        raise ValueError('Replay startup requires its owner proxy; run tools/prepare_cpp_runtime_proxy.py first')
    data=json.loads(receipt.read_text())
    for name,digest in data['files'].items():
        if Path(name).name!=name or sha(folder/name)!=digest:
            raise ValueError('Prepared runtime proxy or validator changed')
    result=subprocess.run([str(folder/'replay-compiler-target-tests.exe'),str(executable)],capture_output=True,text=True,timeout=30)
    if result.returncode:
        raise ValueError('Prepared proxy rejects this executable: '+result.stdout+result.stderr)
    return folder/'XInput9_1_0.dll'


def stage(root=ROOT, output='build-cpp-recovery'):
    windows_compiler()
    recovery=Recovery(root)
    build=(recovery.root/output).resolve()
    if not build.is_relative_to(recovery.root) or not build.name.startswith('build-'):
        raise ValueError('Select an isolated project-local build-* directory')
    report=json.loads((build/'build-report.json').read_text())
    verification=json.loads((build/'verification-report.json').read_text())
    quality=json.loads((build/'quality-checks.json').read_text())
    executable=build/'game_dx12_ship_replay_recompiled.exe'
    if sha(executable)!=report['sha256'] or verification.get('sha256')!=report['sha256'] or not verification.get('windows_sec_image_mapping'):
        raise ValueError('Executable has no matching Windows image verification')
    if quality.get('sha256')!=report['sha256'] or quality.get('passed') is not True:
        raise ValueError('Executable has no matching passing post-link quality checks')
    import source_provenance
    source_provenance.validate_report(report)
    proxy=validated_proxy(recovery.root,executable)
    game=recovery.paths['game']
    folder=game/('replay-compiler-cpp-'+report['sha256'][:16]+'-'+sha(proxy)[:8])
    if folder.exists():
        receipt=json.loads((folder/'cpp-runtime.json').read_text())
        if receipt['sha256']!=report['sha256'] or sha(folder/'game_dx12_ship_replay.exe')!=receipt['sha256']:
            raise ValueError('Existing isolated runtime differs from its receipt')
        for name,digest in receipt.get('runtime_dlls',{}).items():
            if Path(name).name!=name or sha(folder/name)!=digest:
                raise ValueError('Isolated runtime DLL changed: '+name)
        return receipt
    folder.mkdir()
    receipt=dict(schema=1,source_build=str(build),sha256=report['sha256'],folder=str(folder),
                 executable=str(folder/'game_dx12_ship_replay.exe'),root_game_unchanged=True,runtime_dlls={})
    import _winapi
    for path in game.iterdir():
        name=path.name.lower()
        if path==folder or name.startswith('replay-compiler-'):
            continue
        target=folder/path.name
        if path.is_dir():
            if name=='.proxy':
                continue
            if name=='players':
                shutil.copytree(path,target)
            else:
                _winapi.CreateJunction(str(path),str(target))
        elif path.suffix.lower()=='.dll' or path.suffix.lower()=='.ini':
            # Independent DLL/INI entries keep runtime caches/config changes
            # from replacing original files through hard links.
            shutil.copy2(path,target)
            if path.suffix.lower()=='.dll':
                receipt['runtime_dlls'][path.name]=sha(target)
    (folder/'.proxy').mkdir(exist_ok=True)
    shutil.copy2(proxy,folder/'XInput9_1_0.dll')
    receipt['runtime_dlls']['XInput9_1_0.dll']=sha(proxy)
    shutil.copy2(executable,folder/'game_dx12_ship_replay.exe')
    if sha(folder/'game_dx12_ship_replay.exe')!=report['sha256']:
        raise ValueError('Runtime executable copy differs')
    atomic_json(folder/'cpp-runtime.json',receipt)
    atomic_json(build/'isolated-runtime.json',receipt)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',default='build-cpp-recovery')
    parser.add_argument('--stage-only',action='store_true')
    args=parser.parse_args()
    try:
        result=stage(output=args.build)
        if not args.stage_only:
            process=subprocess.Popen([result['executable']],cwd=result['folder'])
            result=dict(result,pid=process.pid,runtime='launched; acceptance remains separate')
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,KeyError) as error:
        print(str(error),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
