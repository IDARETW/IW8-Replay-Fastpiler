"""Exercise native font outline callbacks to diagnose shifted SIMD data flow."""
import json
from pathlib import Path
import struct

import pefile
import unicorn
import unicorn.x86_const as x
from layout import from_report


def callbacks(pe, report=None):
    base = pe.OPTIONAL_HEADER.ImageBase
    moved = lambda rva: from_report(rva, report) if report else rva
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for section in pe.sections[:2]:
        machine.mem_map(base+section.VirtualAddress, (max(section.Misc_VirtualSize, section.SizeOfRawData)+4095)&-4096)
        machine.mem_write(base+section.VirtualAddress, section.get_data())
    cookie = moved(0x5A543F8)
    machine.mem_map(base+(cookie&-4096),4096)
    arena = 0x100000000
    machine.mem_map(arena,0x40000)
    context, points, pixels = arena+0x2000,arena+0x3000,arena+0x10000
    state = struct.pack('<ff8IQ',25.890625,15.5,56,67,29,5,35,0,56,0,pixels)
    machine.mem_write(context,state)
    for i,point in enumerate([(835,2069),(636,1992),(349,1984)]):
        machine.mem_write(points+i*16,struct.pack('<ii',*point))
    sentinel,rsp = arena+0x100,arena+0xF000-8
    results = []
    for original in (0x1936220,0x1936140,0x1935640,0x1935760):
        machine.mem_write(context,state)
        machine.mem_write(pixels,struct.pack('<f',float('inf'))*8192)
        machine.mem_write(rsp,struct.pack('<Q',sentinel))
        machine.reg_write(x.UC_X86_REG_RSP,rsp)
        machine.reg_write(x.UC_X86_REG_RCX,points)
        if original in (0x1936220,0x1936140):
            machine.reg_write(x.UC_X86_REG_RDX,context)
        elif original == 0x1935640:
            machine.reg_write(x.UC_X86_REG_RDX,points+16)
            machine.reg_write(x.UC_X86_REG_R8,context)
        else:
            machine.reg_write(x.UC_X86_REG_RDX,points+16)
            machine.reg_write(x.UC_X86_REG_R8,points+32)
            machine.reg_write(x.UC_X86_REG_R9,context)
        try:
            machine.emu_start(base+moved(original),sentinel,count=100000)
        except unicorn.UcError:
            print('FAULT',hex(original),'RIP',hex(machine.reg_read(x.UC_X86_REG_RIP)-base))
            raise
        if machine.reg_read(x.UC_X86_REG_RIP)!=sentinel:raise ValueError('Font callback did not return')
        result = (bytes(machine.mem_read(context,len(state))),bytes(machine.mem_read(pixels,32768)))
        results.append(result)
        print(hex(original),struct.unpack('<ff',result[0][:8]))
    return results


if __name__ == '__main__':
    original = pefile.PE(r'E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe',fast_load=True)
    before = callbacks(original)
    report = json.loads(Path('build-shift/build-report.json').read_text())
    rebuilt = pefile.PE(report['executable'],fast_load=True)
    if callbacks(rebuilt,report)!=before:raise ValueError('Shifted font callback data flow changed')
    print('Four native font callbacks agree')
