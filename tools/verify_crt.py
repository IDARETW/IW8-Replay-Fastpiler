"""Execute native CRT registration and destructor paths across shifted layouts."""
import struct

import unicorn
from unicorn import x86_const as x86

from layout import from_report


def verify(pe, report=None):
    rows = []
    mapped = lambda rva: from_report(rva, report) if report else rva
    for delta in (0, 0x200000):
        for populated in (False, True):
            base = pe.OPTIONAL_HEADER.ImageBase + delta
            machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
            text = pe.sections[0]
            machine.mem_map(base+text.VirtualAddress, (max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
            machine.mem_write(base+text.VirtualAddress, text.get_data())
            # This real static constructor initializes the fixed node pool and
            # registers the adjacent unpadded destructor through native atexit.
            obj = base+mapped(0xF326920)
            page = (obj & -4096)-4096
            machine.mem_map(page, 0xE000)
            stack, stop, heap = 0x60000000, 0x6000F000, 0x61000000
            machine.mem_map(stack, 0x10000)
            machine.mem_map(heap, 0x1000)
            rsp = stack+0x8008
            registration = base+mapped(0x21CCE40)
            machine.mem_write(registration, b'\xc3')
            callbacks = []
            def capture(uc, at, size, user):
                if at == registration: callbacks.append(uc.reg_read(x86.UC_X86_REG_RCX))
            machine.hook_add(unicorn.UC_HOOK_CODE, capture)
            def execute(at):
                machine.mem_write(rsp, struct.pack('<Q',stop))
                machine.reg_write(x86.UC_X86_REG_RSP,rsp)
                machine.emu_start(at,stop,count=10000)
                if machine.reg_read(x86.UC_X86_REG_RSP) != rsp+8:
                    raise ValueError('Native CRT callback changed its stack ABI')
            execute(base+mapped(0x34BC20))
            callback = base+mapped(0x234D8E0)
            if callbacks != [callback]: raise ValueError('Native constructor registered a stale destructor address')
            head = obj+0xB008
            read = lambda at: struct.unpack('<Q',machine.mem_read(at,8))[0]
            if read(head) != head or read(head+8) != head or read(obj+0xB000) != obj:
                raise ValueError('Native static constructor initialized the wrong shifted global')
            if populated:
                machine.mem_write(heap,struct.pack('<QQ',head,heap+0x40))
                machine.mem_write(heap+0x40,struct.pack('<QQ',heap,head))
                machine.mem_write(head,struct.pack('<QQ',heap+0x40,heap))
            execute(callback)
            if read(head) != head or read(head+8) != head:
                raise ValueError('Native CRT destructor did not clear the relocated list')
            if populated and (read(obj+0xB000) != heap+0x40 or read(heap+0x40) != heap or read(heap) != obj):
                raise ValueError('Native CRT destructor changed its free-list results')
            rows.append(dict(aslr_delta=delta,populated=populated,registered_rva=mapped(0x234D8E0),head_rva=head-base,passed=True))
    return rows
