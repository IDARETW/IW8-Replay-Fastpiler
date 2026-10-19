"""Execute native spatial initialization and check its relocated pointer fields."""
import struct

import unicorn
import unicorn.x86_const as x
from layout import from_report


def verify(pe, report=None):
    base = pe.OPTIONAL_HEADER.ImageBase
    moved = lambda rva: base + (from_report(rva, report) if report else rva)
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+text.VirtualAddress, (text.SizeOfRawData+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress, text.get_data())
    for begin, size in ((0xD652000, 0x9000), (0xD5D7000, 0x1000), (0xD591000, 0x1000)):
        first = min(base+begin,moved(begin))&-4096
        end = (max(base+begin,moved(begin))+size+4095)&-4096
        machine.mem_map(first, end-first)
    arena = 0x100000000
    machine.mem_map(arena, 0x10000)
    allocated = []

    def allocator(uc, address, size, _):
        if address != moved(0x1036AB0):
            return
        pointer = arena + 0x1000 + len(allocated)*0x100
        allocated.append(pointer)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, pointer)
        uc.reg_write(x.UC_X86_REG_RIP, struct.unpack("<Q",uc.mem_read(rsp,8))[0])
        uc.reg_write(x.UC_X86_REG_RSP, rsp+8)

    machine.hook_add(unicorn.UC_HOOK_CODE, allocator)
    # Two array entries exercise both the RVA displacement and indexed offset.
    for client in range(2):
        allocated.clear()
        for register, value in ((x.UC_X86_REG_RSP,arena+0xf000),
                                (x.UC_X86_REG_R12,client*0x3040),
                                (x.UC_X86_REG_RBP,client),
                                (x.UC_X86_REG_RSI,4), (x.UC_X86_REG_RDI,4)):
            machine.reg_write(register,value)
        machine.emu_start(moved(0x12EC72A),moved(0x12EC7C5),count=1000)
        assert machine.reg_read(x.UC_X86_REG_RIP) == moved(0x12EC7C5)
        actual = [struct.unpack("<Q",machine.mem_read(moved(rva)+client*0x3040,8))[0]
                  for rva in (0xD655190,0xD6551A0,0xD6551A8)]
        if actual != allocated or len(allocated) != 3:
            raise ValueError(f"Spatial initializer writes disagree with relocated fields: {actual} != {allocated}")
    return dict(clients=2, pointer_fields=3, native_initializer_executed=True)
