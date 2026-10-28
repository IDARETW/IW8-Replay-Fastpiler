"""Differential tests of native Replay instructions and Windows COFF objects.

The locale conversion dependency is replaced on both sides by the same modeled
callback; its argument trace is compared. This is not a live-game test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import struct
import sys
import tempfile

from cpp_recovery import Recovery, ROOT, FLAGS, atomic_json, sha, run, windows_compiler


class Machine:
    ARENA = 0x300000000
    OBJECT = 0x200000000
    CALLBACK = 0x210000000

    def __init__(self, pe, object_file=None):
        import capstone
        import unicorn
        import unicorn.x86_const as x
        import coff
        self.x = x
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.trace = []
        self.mode = 'ascii'
        self.base = pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            if section.Name.rstrip(b'\0') in (b'.text', b'.rdata'):
                size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & -4096
                self.uc.mem_map(self.base+section.VirtualAddress, size)
                self.uc.mem_write(self.base+section.VirtualAddress, section.get_data())
        self.uc.mem_map(self.ARENA, 0x40000)
        self.uc.mem_map(self.CALLBACK, 0x1000)
        self.uc.mem_write(self.CALLBACK, b'\xc3')
        self.callbacks = {self.CALLBACK}
        # Resolve the dependency from this build's actual CALL operands.
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        for ins in decoder.disasm(pe.get_data(33779248, 141), self.base+33779248):
            if ins.mnemonic == 'call':
                self.callbacks.add(ins.operands[0].imm)
        self.symbols = {}
        if object_file:
            obj = coff.read(object_file)
            addresses = {}
            for i, section in enumerate(obj['sections'], 1):
                if not section['data']:
                    continue
                address = self.OBJECT+i*0x10000
                addresses[i] = address
                self.uc.mem_map(address, (len(section['data'])+4095)&-4096)
                self.uc.mem_write(address, bytes(section['data']))
            for sym in obj['symbols'].values():
                if sym['section'] in addresses:
                    self.symbols[sym['name']] = addresses[sym['section']] + sym['value']
            self.symbols['tolower'] = self.CALLBACK
            for i, section in enumerate(obj['sections'], 1):
                if i not in addresses:
                    continue
                for offset, index, kind in section['relocations']:
                    symbol = obj['symbols'][index]
                    target = self.symbols.get(symbol['name'])
                    if target is None:
                        raise ValueError('Unresolved object dependency: ' + symbol['name'])
                    site = addresses[i] + offset
                    if 4 <= kind <= 9:
                        addend = struct.unpack('<i', bytes(self.uc.mem_read(site,4)))[0]
                        value = target + addend - (site+4+(kind-4))
                        self.uc.mem_write(site, struct.pack('<i', value))
                    elif kind == 1:
                        addend = struct.unpack('<Q', bytes(self.uc.mem_read(site,8)))[0]
                        self.uc.mem_write(site,struct.pack('<Q',target+addend))
                    elif section['name'] in ('.pdata', '.debug$S', '.debug$T'):
                        continue  # Unwind/debug sections are not executed here.
                    else:
                        raise ValueError(f'Unsupported test relocation {kind} in {section["name"]}')
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, user):
        if address not in self.callbacks:
            return
        x = self.x
        value = uc.reg_read(x.UC_X86_REG_ECX)
        value = value if value < 0x80000000 else value-0x100000000
        self.trace.append(value)
        result = value
        if self.mode != 'identity' and 65 <= value <= 90:
            result += 32
        if self.mode == 'latin' and 192 <= value <= 214:
            result += 32
        uc.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(uc.mem_read(stack,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,stack+8)
        uc.reg_write(x.UC_X86_REG_RIP,ret)

    def execute(self, entry, left, right=b'', vector=False, mode='ascii'):
        x, uc = self.x, self.uc
        self.mode = mode
        self.trace = []
        for reg in (x.UC_X86_REG_RAX,x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9,x.UC_X86_REG_R10,x.UC_X86_REG_R11):
            uc.reg_write(reg,0)
        nonvolatile = [x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15]
        saved = {reg:0x1234567800000000+reg for reg in nonvolatile}
        for reg,value in saved.items(): uc.reg_write(reg,value)
        for i in range(16): uc.reg_write(getattr(x,f'UC_X86_REG_XMM{i}'),0x123456789abcdef)
        uc.reg_write(x.UC_X86_REG_MXCSR,0x1f80)
        first, second, sentinel, stack = self.ARENA+0x1000,self.ARENA+0x5000,self.ARENA+0x100,self.ARENA+0x30000-8
        uc.mem_write(first,b'\xa5'*0x1000)
        uc.mem_write(second,b'\x5a'*0x1000)
        uc.mem_write(first,left if vector else left+b'\0')
        uc.mem_write(second,right+b'\0')
        uc.mem_write(stack,struct.pack('<Q',sentinel))
        uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.reg_write(x.UC_X86_REG_RCX,first)
        uc.reg_write(x.UC_X86_REG_RDX,second)
        uc.emu_start(entry,sentinel,count=200000)
        if uc.reg_read(x.UC_X86_REG_RIP) != sentinel:
            raise ValueError('Function did not return within instruction budget')
        if uc.reg_read(x.UC_X86_REG_RSP) != stack+8:
            raise ValueError('Function changed caller stack')
        if any(uc.reg_read(reg)!=value for reg,value in saved.items()):
            raise ValueError('Function clobbered a nonvolatile register')
        if any(uc.reg_read(getattr(x,f'UC_X86_REG_XMM{i}'))!=0x123456789abcdef for i in range(6,16)):
            raise ValueError('Function clobbered a nonvolatile SIMD register')
        result = dict(memory=bytes(uc.mem_read(first, max(len(left)+1,32))).hex(),
                      right_memory=bytes(uc.mem_read(second,max(len(right)+1,32))).hex(),
                      trace=list(self.trace))
        if vector:
            result.update(xmm0=uc.reg_read(x.UC_X86_REG_XMM0),mxcsr=uc.reg_read(x.UC_X86_REG_MXCSR))
        else:
            result['rax'] = uc.reg_read(x.UC_X86_REG_RAX)
        return result


def cases():
    randomizer = random.Random(0x120)
    strings = [(b'',b''),(b'A',b'a'),(b'Z',b'['),(b'abc',b'ab'),(b'',b'needle'),
               (b'hello WORLD',b'world'),(b'world',b''),(b'xxAAAa',b'aa'),(b'\xffA',b'\xffa')]
    for value in range(1,256): strings.append((bytes([value]),bytes([value^32])))
    for _ in range(384):
        left = bytes(randomizer.randrange(1,256) for _ in range(randomizer.randrange(0,70)))
        right = bytes(randomizer.randrange(1,256) for _ in range(randomizer.randrange(0,25)))
        if randomizer.randrange(3)==0: right=left[randomizer.randrange(len(left)+1):]
        strings.append((left,right))
    vectors = [(0,0,0),(1,2,3),(-1,-2,-3),(3,4,0),(-0.0,0.0,-0.0),
               (float('inf'),1,0),(float('-inf'),0,1),(float('nan'),1,2),
               (1e-40,1e-40,1e-40),(3e38,3e38,1)]
    vectors += [tuple(randomizer.uniform(-10000,10000) for _ in range(3)) for _ in range(384)]
    return strings, vectors


def test_pilot(root=ROOT):
    import pefile
    recovery = Recovery(root)
    recovery.verify_image()
    compiler = windows_compiler()
    pe = pefile.PE(str(recovery.image),fast_load=True)
    directory = recovery.directory/'pilot-tests'
    directory.mkdir(parents=True,exist_ok=True)
    strings, vectors = cases()
    identities = [('I_stricmp','fn_2a385ed3a736c866','I_stricmp.cpp'),
                  ('I_stristr','fn_98e4a70bc4c66c13','I_stristr.cpp'),
                  ('Vec3Normalize','fn_62b1f5ea433e8291','Vec3Normalize.cpp')]
    results = []
    for symbol,identity,filename in identities:
        source = recovery.root/'src/recovered'/filename
        obj = directory/(source.stem+'.obj')
        compiled = run([compiler,*FLAGS,'-I',str(recovery.root/'src'),'-c',source,'-o',obj],recovery.root,60)
        if compiled['returncode']!=0:
            raise ValueError(compiled['stderr'])
        row = recovery.resolve(identity)
        native = Machine(pe)
        candidate = Machine(pe,obj)
        total = 0
        if filename == 'Vec3Normalize.cpp':
            inputs = [(struct.pack('<fff',*v),b'',True,'ascii') for v in vectors]
        else:
            modes = ['ascii','latin','identity'] if filename == 'I_stristr.cpp' else ['ascii']
            inputs = [(a,b,False,mode) for mode in modes for a,b in strings]
        for a,b,vector,mode in inputs:
            expected = native.execute(pe.OPTIONAL_HEADER.ImageBase+row['rva'],a,b,vector,mode)
            actual = candidate.execute(candidate.symbols[symbol],a,b,vector,mode)
            if expected != actual:
                raise ValueError(f'{symbol} case {total} differs: input={a.hex()}, {b.hex()}, mode={mode}; native={expected}; candidate={actual}')
            total += 1
        validation=recovery.validate(source,symbol)
        if not validation['compiled']:
            raise ValueError(validation['diagnostics'])
        evidence = dict(schema=1,function_id=identity,symbol=symbol,image_sha256=recovery.catalog['image_sha256'],
                        source_sha256=sha(source),abi_review=dict(basis='native instruction review and Windows x64 differential register/stack checks',
                        return_contract='XMM0 four lanes' if filename=='Vec3Normalize.cpp' else 'RAX; integer result is zero-extended from EAX' if filename=='I_stricmp.cpp' else 'pointer in RAX'),
                        differential=dict(passed=True,cases=total,method='Unicorn native instructions versus Windows COFF',
                        tolower='same modeled callback and ordered signed argument trace' if filename=='I_stristr.cpp' else None),
                        compiler=dict(path=str(compiler),sha256=sha(compiler)),object_sha256=sha(obj),
                        compilation_dependencies=validation['dependencies'],
                        dependencies={'src/recovered/ReplayUtilityLayouts.h':sha(recovery.root/'src/recovered/ReplayUtilityLayouts.h')} if filename=='Vec3Normalize.cpp' else {},
                        linking=False,runtime=False)
        atomic_json(directory/(source.stem+'.json'),evidence)
        results.append(evidence)
        print(f'{symbol}: {total} differential cases passed',flush=True)
    atomic_json(directory/'report.json',dict(schema=1,passed=True,functions=results))
    return results


def compare_retdec(root=ROOT):
    """Reject backend C when it fails an actual native behavior comparison."""
    import pefile
    recovery=Recovery(root)
    recovery.verify_image()
    identity='fn_2a385ed3a736c866'
    records=sorted((recovery.directory/identity/'retdec').glob('*/record.json'),key=lambda p:p.stat().st_mtime_ns,reverse=True)
    if not records:
        raise ValueError('Recover the comparison function with RetDec first')
    record=next(p for p in records if json.loads(p.read_text())['status']=='recovered-reference')
    source=record.parent/'candidate.c'
    obj=recovery.directory/'pilot-tests/retdec-comparison.obj'
    flags=[f for f in FLAGS if f not in ('-std=c++20','-fno-exceptions','-fno-rtti')]
    result=run([windows_compiler(),*flags,'-std=c17','-c',source,'-o',obj],recovery.root,60)
    report=dict(image_sha256=recovery.catalog['image_sha256'],backend='retdec',function_id=identity,
                record=str(record),source_sha256=sha(source),compiled=result['returncode']==0,accepted=False)
    if result['returncode'] != 0:
        report['strict_compiler_diagnostics']=result['stderr']
        # This comparison is diagnostic only. Suppress a sign-warning error so
        # the backend's unedited behavior can still be exercised and rejected.
        result=run([windows_compiler(),*flags,'-Wno-error=sign-compare','-std=c17','-c',source,'-o',obj],recovery.root,60)
        report['diagnostic_object_compiled']=result['returncode']==0
    if result['returncode']==0:
        pe=pefile.PE(str(recovery.image),fast_load=True)
        native,candidate=Machine(pe),Machine(pe,obj)
        symbol='function_140e60c20'
        tested=0
        for a,b in cases()[0]:
            expected=native.execute(pe.OPTIONAL_HEADER.ImageBase+recovery.resolve(identity)['rva'],a,b)
            actual=candidate.execute(candidate.symbols[symbol],a,b)
            tested+=1
            if expected!=actual:
                report.update(cases_before_mismatch=tested,counterexample=dict(left=a.hex(),right=b.hex(),native=expected,candidate=actual),
                              reason='Backend C differs from native instructions; keep as reference')
                break
        else:
            report.update(accepted=True,cases=tested)
    else:
        report['diagnostics']=result['stderr']
    atomic_json(recovery.directory/'pilot-tests/retdec-comparison.json',report)
    print(json.dumps(report,indent=2))
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--compare-retdec',action='store_true')
    args=parser.parse_args()
    if args.compare_retdec:
        compare_retdec(args.root)
    else:
        test_pilot(args.root)
