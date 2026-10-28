"""Build and freeze the owner's Windows Replay startup proxy and validators."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from cpp_recovery import ROOT, Recovery, atomic_json, sha, windows_compiler


def prepare():
    windows_compiler()
    recovery=Recovery()
    source=recovery.paths['proxy_source']
    if source is None or not (source/'xmake.lua').is_file():
        raise ValueError('Configure the owner-supplied Replay proxy source before preparing its runtime')
    xmake=shutil.which('xmake')
    if not xmake:
        raise ValueError('Windows XMake is required to build the Replay startup proxy')
    build=ROOT/'build-cpp-recovery'
    executable=build/'game_dx12_ship_replay_recompiled.exe'
    expected=json.loads((build/'build-report.json').read_text())['sha256']
    if sha(executable)!=expected:
        raise ValueError('Baseline executable changed before proxy validation')
    env=os.environ.copy();env['_LINK_']='/DEBUG:NONE /INCREMENTAL:NO'
    commands=[[xmake,'f','-P',str(source),'-m','debug','-a','x64','--replay_compiler_keep_crash_markers=n','-y']]
    commands += [[xmake,'build','-P',str(source),name] for name in ('mw120rproxy','replay-pattern-tests','replay-compiler-target-tests')]
    commands += [[xmake,'run','-P',str(source),'replay-pattern-tests'],
                 [xmake,'run','-P',str(source),'replay-compiler-target-tests',str(executable)]]
    log=ROOT/'analysis/cpp-recovery/proxy-build.log';log.parent.mkdir(parents=True,exist_ok=True)
    with log.open('w',encoding='utf-8') as stream:
        for command in commands:
            subprocess.run(command,cwd=source,env=env,stdout=stream,stderr=subprocess.STDOUT,check=True)
    folder=ROOT/'.toolchains/cpp-runtime-proxy';folder.mkdir(parents=True,exist_ok=True)
    files={}
    for path in [source/'xmake-out/x64/Debug/XInput9_1_0.dll',
                 source/'build/windows/x64/debug/replay-pattern-tests.exe',
                 source/'build/windows/x64/debug/replay-compiler-target-tests.exe']:
        # XMake uses its own default output layout for the test targets.
        if not path.is_file():
            matches=list((source/'build').glob('**/'+path.name))
            if len(matches)!=1:
                raise ValueError('Cannot uniquely locate proxy validator: '+path.name)
            path=matches[0]
        target=folder/path.name
        shutil.copy2(path,target)
        files[target.name]=sha(target)
    receipt=dict(schema=1,source_project=str(source),files=files,
                 baseline_executable_sha256=sha(executable),startup_compatibility='native GDI bootstrap attach-time repair',
                 validation_log=str(log))
    if sha(executable)!=expected:
        raise ValueError('Baseline executable changed during proxy validation')
    atomic_json(folder/'receipt.json',receipt)
    print(json.dumps(receipt,indent=2))
    return receipt


if __name__=='__main__':
    prepare()
