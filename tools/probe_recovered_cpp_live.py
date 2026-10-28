"""Observe a compiled diagnostic counter in an isolated Windows game process.

The selected build must define the requested counter. Only the process started
by this command is stopped, and the result distinguishes execution from a full
menu/gameplay acceptance test.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import time

from cpp_recovery import ROOT, atomic_json
from run_recovered_cpp import stage


def probe(build='build-cpp-recovery-probe',symbol='ReplayCppRecoveryCalls',seconds=30):
    receipt=stage(output=build)
    report=json.loads((ROOT/build/'build-report.json').read_text())
    rva=report['symbols'].get(symbol)
    if not isinstance(rva,int):
        raise ValueError('Build does not define the selected diagnostic counter')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.K32EnumProcessModules.argtypes=[wintypes.HANDLE,ctypes.POINTER(ctypes.c_void_p),wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    kernel.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    process=subprocess.Popen([receipt['executable']],cwd=receipt['folder'])
    result=dict(schema=1,build_sha256=report['sha256'],pid=process.pid,symbol=symbol,rva=rva,
                execution_observed=False,menu_acceptance=False,gameplay_acceptance=False,samples=[])
    deadline=time.monotonic()+seconds
    try:
        while time.monotonic()<deadline and process.poll() is None:
            modules=(ctypes.c_void_p*256)();needed=wintypes.DWORD()
            if kernel.K32EnumProcessModules(int(process._handle),modules,ctypes.sizeof(modules),ctypes.byref(needed)) and modules[0]:
                value=ctypes.c_uint64();got=ctypes.c_size_t()
                address=modules[0]+rva
                if kernel.ReadProcessMemory(int(process._handle),address,ctypes.byref(value),8,ctypes.byref(got)) and got.value==8:
                    result['samples'].append(value.value)
                    result['image_base']=modules[0]
                    if value.value:
                        result['execution_observed']=True
                        break
            time.sleep(0.25)
        result['exit_code_before_cleanup']=process.poll()
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        result['own_process_stopped']=process.poll() is not None
        atomic_json(ROOT/'analysis/cpp-recovery/live-counter.json',result)
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',default='build-cpp-recovery-probe')
    parser.add_argument('--seconds',type=int,default=30)
    args=parser.parse_args()
    raise SystemExit(0 if probe(args.build,seconds=args.seconds)['execution_observed'] else 1)
