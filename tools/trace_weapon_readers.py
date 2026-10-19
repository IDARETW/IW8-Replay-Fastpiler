"""Record native weapon reader calls and transfer-global field bindings.

The analysis-only 1.31 image is executed only in Unicorn with deterministic
service stubs. No reference-image code is used as a compilation input.
"""
from pathlib import Path
import json
import struct

import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP

from analyze_frontend_loaders import bounded_body, ORIGINAL, REFERENCE, ROOT

SOURCE, EXTRA, STACK, DONE = 0x70001000, 0x70010000, 0x60000000, 0x71000000
ROOTS = {'WeaponDef': (0x5d404a8, 0x997dab8), 'WeaponCompleteDef': (0x5d404b8, 0x997dad8)}
ENTRIES = {'WeaponDef': (0xd9a580, 0x1d3d390), 'WeaponCompleteDef': (0xd99d00, 0x1d3cab0)}
SIZES = {'WeaponDef': (5296, 5336), 'WeaponCompleteDef': (624, 632)}
COMMON = {'stream': (0x11b2a20, 0x23c8750), 'align': (0xd8d480, 0x1d30210),
          'push': (0x11b2570, 0x23c8340), 'pop': (0x11b24c0, 0x23c8290),
          'shared': (0xd8e5b0, 0x1d310a0), 'unshared': (0xd8e2e0, 0x1d30dd0),
          'resolve': (0xd90530, 0x1d332e0), 'asset_push': (0xd8da80, 0x1d30810),
          'asset_pop': (0xd8d850, 0x1d305e0)}


def trace(pe, name, newer, overrides=()):
    which = int(newer)
    instructions, end = bounded_body(pe, ENTRIES[name][which])
    globals_ = sorted({ins.address + ins.size + op.mem.disp for ins in instructions
        for op in ins.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP})
    calls = {ins.operands[0].imm for ins in instructions if ins.mnemonic == 'call' and ins.operands[0].type == X86_OP_IMM}
    calls.update(ins.operands[0].imm for ins in instructions if ins.mnemonic == 'jmp' and ins.operands[0].type == X86_OP_IMM and
                 not ENTRIES[name][which] <= ins.operands[0].imm < end)
    machine = Uc(UC_ARCH_X86, UC_MODE_64); pages = set()
    def map_(at, size):
        for page in range(at & ~4095, (at + size + 4095) & ~4095, 4096):
            if page not in pages: machine.mem_map(page, 4096); pages.add(page)
    def put(at, raw): map_(at, len(raw)); machine.mem_write(at, bytes(raw))
    def qput(at, value): put(at, struct.pack('<Q', value))
    def qget(at): return struct.unpack('<Q', machine.mem_read(at, 8))[0]
    map_(SOURCE, 0x50000); map_(STACK, 0x10000); map_(DONE, 4096)
    entry = ENTRIES[name][which]; put(entry, pe.get_data(entry, end - entry))
    for index, at in enumerate(globals_): qput(at, 0xabc000 + index * 16)
    qput(ROOTS[name][which], SOURCE)
    other_name = next(key for key in ROOTS if key != name)
    qput(ROOTS[other_name][which], SOURCE + 0x6000)
    pos = (0xd120c00, 0x140bd9d0)[which]; qput(pos, EXTRA)
    for offset, value, width in overrides: put(SOURCE + offset, value.to_bytes(width, 'little'))
    for at in calls: put(at, b'\xc3')
    sp = STACK + 0x8008; qput(sp, DONE)
    machine.reg_write(UC_X86_REG_RSP, sp); machine.reg_write(UC_X86_REG_RCX, 1)
    services = {rvas[which]: label for label, rvas in COMMON.items()}
    events = []; stream_stack = []; streams = {4: EXTRA + 0x20000, 5: EXTRA + 0x10000}; stream = 0
    def hook(_, at, size, opaque):
        nonlocal stream
        if at == DONE: machine.emu_stop(); return
        if at not in calls: return
        cx = machine.reg_read(UC_X86_REG_RCX); dx = machine.reg_read(UC_X86_REG_RDX); r8 = machine.reg_read(UC_X86_REG_R8)
        bindings = {f'{g:x}': qget(g) - SOURCE for g in globals_ if SOURCE <= qget(g) < SOURCE + SIZES[name][which]}
        allocated = {f'{g:x}': qget(g) - EXTRA for g in globals_ if EXTRA <= qget(g) < EXTRA + 0x30000}
        event = dict(call=f'{at:x}', name=services.get(at), cx=cx, dx=dx, r8=r8, bindings=bindings, allocated=allocated, pos=qget(pos)-EXTRA)
        events.append(event)
        label = services.get(at)
        if label == 'stream' and cx & 0xffffffff == 0: qput(pos, qget(pos) + r8)
        elif label == 'align': qput(pos, (qget(pos) + cx) & ~cx)
        elif label == 'resolve': qput(cx, EXTRA + 0x30000)
        elif label == 'push':
            streams[stream] = qget(pos); stream_stack.append(stream); stream = cx; qput(pos, streams[cx])
        elif label == 'pop':
            streams[stream] = qget(pos); stream = stream_stack.pop(); qput(pos, streams[stream])
        # AllocLoad helpers return the current stream position. Other helpers'
        # return values are unused; nested reads are intentionally not executed.
        machine.reg_write(UC_X86_REG_RAX, qget(pos))
        sp = machine.reg_read(UC_X86_REG_RSP); target = qget(sp)
        machine.reg_write(UC_X86_REG_RSP, sp + 8); machine.reg_write(UC_X86_REG_RIP, target)
    machine.hook_add(UC_HOOK_CODE, hook)
    try:
        machine.emu_start(entry, DONE + 1, count=100000)
    except Exception as exc:
        raise RuntimeError((name, newer, hex(machine.reg_read(UC_X86_REG_RIP)), events[-3:])) from exc
    assert machine.reg_read(UC_X86_REG_RIP) == DONE and not stream_stack
    return events


def main():
    images = [pefile.PE(str(path), fast_load=True) for path in (ORIGINAL, REFERENCE)]
    result = {}
    for name in ENTRIES:
        traces = [trace(image, name, bool(index)) for index, image in enumerate(images)]
        result[name] = dict(replay=traces[0], mw131=traces[1])
        for label, events in zip(('replay', 'mw131'), traces):
            print(name, label)
            for event in events:
                if event['name'] is None:
                    print(event['call'], {g: hex(offset) for g, offset in event['bindings'].items()}, hex(event['cx']), hex(event['dx']))
    (ROOT / 'evidence/weapon-reader-native-traces.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__': main()
