"""Verify recovered instructions, PE structure, native behavior and relocation metadata."""

import ctypes
import argparse
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct

import capstone
import pefile
import unicorn
import unicorn.x86_const as x86
from verify_spatial import verify as verify_spatial
from verify_crt import verify as verify_crt
from font_probe import callbacks as native_font_callbacks
import compiler_identity
import source_provenance
import proxy_signature_registry
import native_unproven
from coff import read as read_coff
from types import SimpleNamespace
from layout import from_report
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_RSP

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path(os.environ.get('REPLAY_GAME_ROOT', r'E:\IW8\Builds\1.20-replay')) / 'game_dx12_ship_replay.exe'


def remap(rva, report):
    if report.get("rva_map"):
        return from_report(rva, report)
    for item in report["replacements"]:
        if rva == item["begin"]:
            return report["symbols"][item["symbol"]]
    return rva


def instruction_key(instruction, report=None):
    address, size, mnemonic, operands = instruction
    mnemonic = {"movabs": "mov", "sal": "shl"}.get(mnemonic, mnemonic)
    if report:
        if "_operand_rows" not in report:
            report["_operand_rows"] = {}
            for item in report.get("metadata", {}).get("image_relative_operands", []):
                report["_operand_rows"].setdefault(item["rva"],[]).append(item)
        for item in report["_operand_rows"].get(address,[]):
            operands = re.sub(rf"\b0x{item['target']:x}\b", hex(remap(item["target"],report)), operands)
    match = re.search(r"rip(?:\s*([+-])\s*(0x[0-9a-f]+))?", operands)
    if match:
        displacement = int(match[2], 16) * (-1 if match[1] == "-" else 1) if match[2] else 0
        target = address+size+displacement
        if report:
            target = remap(target, report)
        operands = operands[:match.start()]+f"absolute_rva_{target:x}"+operands[match.end():]
    if report and (mnemonic.split()[-1].startswith(("j", "loop")) or mnemonic.split()[-1] == "call") and re.fullmatch(r"0x[0-9a-f]+", operands):
        operands = hex(remap(int(operands, 16), report))
    if mnemonic == "xchg" and re.fullmatch(r"\w+, \w+", operands):
        operands = ", ".join(sorted(operands.split(", ")))
    if mnemonic == "cmp":
        match = re.fullmatch(r"(ax|bx|cx|dx|si|di|bp|sp), (-?0x[0-9a-f]+|-?\d+)", operands)
        if match:
            operands = f"{match[1]}, {int(match[2], 0) & 0xffff:#x}"
    return mnemonic, operands


def verify_protected_callbacks(original, rebuilt, report):
    """Reprove certified callback operands before normalizing text comparison.

    The instruction inventory deliberately leaves encoded/unowned regions as
    data. An independently certified callback in such a region still has two
    relocated RIP operands; every other protected byte remains exact.
    """
    if not report.get('protected_callback_thunks'):
        return []
    manifest = json.loads((ROOT / 'generated/manifest.json').read_text())
    text = manifest['sections'][0]
    spans = native_unproven.load(ROOT / 'generated', report['input_sha256'],
        manifest.get('input_md5', ''), text['rva'], text['rva'] + text['raw_size'], original.get_data)
    records = {Path(record['source']).name: record for record in report['assembly']}
    objects = {}
    for chunk in manifest['chunks']:
        record = records[chunk['file']]
        path = Path(record['object'])
        path = path if path.is_absolute() else ROOT / path
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['object_sha256']:
            raise ValueError('Callback proof assembly object changed')
        obj = read_coff(path)
        code = next(section for section in obj['sections'] if section['name'] == '.text')
        code['original_rva'] = chunk['rva']
        objects[chunk['file']] = obj, code
    rows = spans.prove_callback_thunks(manifest, objects,
        (ROOT / 'generated/instruction-lengths.bin').read_bytes(),
        (ROOT / 'generated/instruction-confidence.bin').read_bytes(), original.get_data)
    claimed = [{key: value for key, value in row.items() if key != 'compilation'}
               for row in report['protected_callback_thunks']]
    if rows != claimed:
        raise ValueError('Protected callback proof differs from compiled receipts')
    layout = SimpleNamespace(replacements=report['replacements'],
        points=[row['rva'] for row in report['rva_map']['insertions']],
        map=lambda rva: remap(rva, report), resolve=lambda rva: remap(rva, report))
    spans.verify_layout(layout)
    linked = next(section for section in rebuilt.sections if section.Name.rstrip(b'\0') == b'.text')
    spans.verify_bytes(linked.get_data(), linked.VirtualAddress, layout)
    return rows


def check_text(original, rebuilt, report, output):
    old = next(s for s in original.sections if s.Name.rstrip(b"\0") == b".text")
    new = next(s for s in rebuilt.sections if s.Name.rstrip(b"\0") == b".text")
    before, after = bytearray(old.get_data()), new.get_data()
    callbacks = verify_protected_callbacks(original, rebuilt, report)
    for thunk in callbacks:
        for reference in thunk['references']:
            at = thunk['rva'] + reference['offset']
            value = remap(reference['target'], report) - (remap(at, report) + 4)
            struct.pack_into('<i', before, at - old.VirtualAddress, value)
    for at, target, width in struct.iter_unpack("<III", (ROOT / "generated" / "data-fixups.bin").read_bytes()):
        if old.VirtualAddress <= at < old.VirtualAddress+len(before):
            struct.pack_into("<Q" if width == 8 else "<I", before, at-old.VirtualAddress,
                             remap(target, report)+(original.OPTIONAL_HEADER.ImageBase if width == 8 else 0))
    for at,target,width in struct.iter_unpack("<III", (ROOT / "generated" / "metadata-fixups.bin").read_bytes()):
        if old.VirtualAddress <= at < old.VirtualAddress+len(before):
            before[at-old.VirtualAddress:at-old.VirtualAddress+width] = remap(target, report).to_bytes(width,"little")
    for item in report.get("metadata", {}).get("relative_tables", []):
        if old.VirtualAddress <= item["at"] < old.VirtualAddress+len(before):
            target,origin = remap(item["target"],report),remap(item["base"],report)
            distance = origin-target if item["subtract"] else target-origin
            width = item.get("width",4)
            before[item["at"]-old.VirtualAddress:item["at"]-old.VirtualAddress+width] = ((distance >> item["shift"]) & ((1 << (width*8))-1)).to_bytes(width,"little")
    lengths = (ROOT / "generated" / "instruction-lengths.bin").read_bytes()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    counts = dict(identical_instructions=0, equivalent_instructions=0, data_bytes=0)
    counts['certified_callback_thunks'] = len(callbacks)
    counts["direct_branch_boundaries"] = 0
    errors = []
    offset = 0
    limit = min(len(before), report["cpp_region_rva"]-old.VirtualAddress)
    excluded = {item["begin"]: item["end"] for item in report["replacements"]}
    widened = {item["rva"]: item for item in report.get("rva_map", {}).get("widened_branches", [])}
    while offset < limit:
        rva = old.VirtualAddress+offset
        if rva in excluded:
            offset += excluded[rva]-rva
            continue
        size = lengths[offset]
        if size == 255:
            raise ValueError(f"Invalid instruction tail at {rva:x}")
        if not size:
            end = offset+1
            while end < limit and not lengths[end] and old.VirtualAddress+end not in excluded:
                end += 1
            at = remap(rva, report)-new.VirtualAddress
            if before[offset:end] != after[at:at+end-offset]:
                errors.append((hex(rva), "Non-instruction data changed"))
            counts["data_bytes"] += end-offset
            offset = end
            continue
        mapped = remap(rva, report)
        at = mapped-new.VirtualAddress
        linked_size = size+(16 if rva in widened else 0)
        a, b = before[offset:offset+size], after[at:at+linked_size]
        # Validate control-flow boundaries independently of assembly semantic
        # comparison. An identical branch can still enter a misdecoded block.
        displacement = None
        if size == 5 and a[0] in (0xE8, 0xE9):
            displacement = struct.unpack_from("<i", a, 1)[0]
        elif size == 2 and (a[0] in (0xEB, 0xE0, 0xE1, 0xE2, 0xE3) or 0x70 <= a[0] <= 0x7F):
            displacement = struct.unpack_from("<b", a, 1)[0]
        elif size == 6 and a[0] == 0x0F and 0x80 <= a[1] <= 0x8F:
            displacement = struct.unpack_from("<i", a, 2)[0]
        if displacement is not None:
            target_offset = offset+size+displacement
            if 0 <= target_offset < len(lengths) and lengths[target_offset] == 255:
                errors.append((hex(rva), "Branch enters an instruction interior", hex(old.VirtualAddress+target_offset)))
            counts["direct_branch_boundaries"] += 1
        if a == b and mapped == rva:
            counts["identical_instructions"] += 1
        else:
            source = list(decoder.disasm_lite(a, rva))
            target = list(decoder.disasm_lite(b, mapped))
            operation = source[0][2] if source else None
            if operation in ("nop", "int3"):
                valid = b == bytes([0x90 if operation == "nop" else 0xcc])*linked_size
            elif operation and operation.startswith(("loop", "jrcxz", "jecxz")) and rva in widened:
                # This expansion is also executed with both successors in
                # layout_tests.py; here verify its linked branch destination.
                valid = len(target) >= 3 and target[0][2] == operation and target[1][2] == "jmp" and target[2][2] == "jmp" and int(target[2][3],16) == remap(int(source[0][3],16),report)
            else:
                valid = bool(source and target and instruction_key(source[0], report) == instruction_key(target[0])
                             and b[target[0][1]:] == b"\x90"*(linked_size-target[0][1]))
            if not valid and len(errors) < 40:
                errors.append((hex(rva), source, target, a.hex(), b.hex()))
            counts["equivalent_instructions"] += 1
        offset += size
    if errors:
        (output / "text-verification-errors.json").write_text(json.dumps(errors, indent=2))
        raise ValueError(f"Assembly semantics or data changed: {len(errors)} examples recorded")
    (output / "text-verification-errors.json").unlink(missing_ok=True)
    # Relocations into instructions must still address the same complete
    # absolute pointer, even if an assembler chose a different encoding.
    for block in original.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if old.VirtualAddress <= entry.rva < old.VirtualAddress+len(before) and entry.type == 10:
                target = struct.unpack("<Q", original.get_data(entry.rva, 8))[0]-original.OPTIONAL_HEADER.ImageBase
                expected = struct.pack("<Q", original.OPTIONAL_HEADER.ImageBase+remap(target, report))
                if expected != rebuilt.get_data(remap(entry.rva,report), 8):
                    raise ValueError(f"Absolute code relocation moved at {entry.rva:x}")
    return counts


def virtual_base_initializer(pe, report=None):
    # This real native initializer sets MSVC virtual-base tables using an
    # unannotated image-base-relative LEA, then calls two native constructors.
    # A stale table address reads a string as a virtual-base offset and faults.
    mapped_rva = lambda value: remap(value, report) if report else value
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if section.Name.rstrip(b"\0") in (b".text", b".rdata"):
            size = (max(section.Misc_VirtualSize, section.SizeOfRawData)+4095) & -4096
            emulator.mem_map(base+section.VirtualAddress, size)
            emulator.mem_write(base+section.VirtualAddress, section.get_data())
    destination = mapped_rva(0x11868068)
    emulator.mem_map(base+(destination & -4096),4096)
    stack = 0x100000000
    emulator.mem_map(stack,0x20000)
    emulator.reg_write(UC_X86_REG_RSP,stack+0x18000)
    emulator.emu_start(base+mapped_rva(0x3568ea),base+mapped_rva(0x35692f),count=1000)
    if emulator.reg_read(UC_X86_REG_RIP) != base+mapped_rva(0x35692f):
        raise ValueError("Virtual-base initializer did not return normally")
    # The two vbtable pointers and constructed vtables are image references.
    return [struct.unpack("<Q",emulator.mem_read(base+destination+offset,8))[0]-base
            for offset in (0,8,16,24,0x80,0x90)]


def native_domain_validation(pe, report=None):
    # Leaf Dvar_ValueInDomain has a bounded 12-case jump table but no unwind
    # entry. Verify every case, plus integer boundary behavior, after layout.
    base = pe.OPTIONAL_HEADER.ImageBase
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    emulator.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    emulator.mem_write(base+text.VirtualAddress,text.get_data())
    stack = 0x100000000
    emulator.mem_map(stack,0x10000)
    sentinel,initial_rsp = stack+0x100,stack+0xF000-8
    cases = [(kind,b"\0"*16,b"\0"*16) for kind in range(12)]
    cases += [(5,struct.pack("<i",value)+b"\0"*12,struct.pack("<ii",16,100)+b"\0"*8)
              for value in (15,16,19,100,101)]
    results = []
    for kind,value,domain in cases:
        emulator.mem_write(initial_rsp,struct.pack("<Q",sentinel))
        emulator.mem_write(stack+0x2000,value); emulator.mem_write(stack+0x3000,domain)
        for register,number in ((UC_X86_REG_RSP,initial_rsp),(UC_X86_REG_RCX,kind),
                                (UC_X86_REG_RDX,stack+0x2000),(UC_X86_REG_R8,stack+0x3000)):
            emulator.reg_write(register,number)
        emulator.emu_start(base+(remap(0x13EAD20,report) if report else 0x13EAD20),sentinel,count=1000)
        if emulator.reg_read(UC_X86_REG_RIP) != sentinel or emulator.reg_read(UC_X86_REG_RSP) != initial_rsp+8:
            raise ValueError(f"Native leaf domain dispatch failed for type {kind}")
        results.append(emulator.reg_read(UC_X86_REG_RAX)&255)
    if results[-5:] != [0,1,1,1,0]: raise ValueError("Integer domain boundaries changed")
    return results


def native_sparse_renderer_dispatch(pe, report=None):
    # The real renderer dispatch has four zero enum holes between eight valid
    # cases. Execute its indexed load and indirect jump for every valid case.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    scratch = 0x100000000
    machine.mem_map(scratch,4096)
    mapped_rva = lambda value: remap(value,report) if report else value
    results = []
    for kind in range(12):
        machine.mem_write(scratch+8,struct.pack("<I",kind))
        machine.reg_write(x86.UC_X86_REG_R11,scratch)
        machine.reg_write(x86.UC_X86_REG_R12,base)
        machine.emu_start(base+mapped_rva(0x18785F4),base+mapped_rva(0x1878600),count=100)
        target = machine.reg_read(x86.UC_X86_REG_RCX)
        if target:
            machine.emu_start(base+mapped_rva(0x1878600),base+target,count=2)
            if machine.reg_read(x86.UC_X86_REG_RIP) != base+target:
                raise ValueError("Native sparse renderer dispatch lost its case")
        results.append(target)
    return results


def native_masked_renderer_dispatch(pe, report=None):
    # A typed renderer record supplies enum values 5..11 via flags >> 23 & 15.
    # The biased table base points into preceding code; its seven real fields
    # start at 0x1927520. Execute the native indexed load and indirect jump.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = pe.sections[0]
    machine.mem_map(base+text.VirtualAddress,(text.SizeOfRawData+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    arena = 0x100000000
    machine.mem_map(arena,0x10000)
    moved = lambda value: remap(value,report) if report else value
    results = []
    for kind in range(5,12):
        machine.mem_write(arena+0x1008,struct.pack("<I",kind<<23))
        for register,value in ((x86.UC_X86_REG_RAX,arena+0x1000),
                               (x86.UC_X86_REG_RDI,arena+0x2000),
                               (x86.UC_X86_REG_RSP,arena+0xf000)):
            machine.reg_write(register,value)
        machine.emu_start(base+moved(0x192740C),base+moved(0x1927430),count=100)
        target = machine.reg_read(x86.UC_X86_REG_RAX)-base
        machine.emu_start(base+moved(0x1927430),base+target,count=1)
        if machine.reg_read(x86.UC_X86_REG_RIP) != base+target:
            raise ValueError("Native masked renderer dispatch lost its case")
        results.append(target)
    return results


def native_asset_hash_bucket(pe, report=None):
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = pe.sections[0]
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    moved = lambda rva: remap(rva,report) if report else rva
    for index in (0,1,0x6c0,0x2c08):
        machine.reg_write(x86.UC_X86_REG_R9,base)
        machine.reg_write(x86.UC_X86_REG_RCX,index)
        machine.emu_start(base+moved(0x15F89A4),base+moved(0x15F89AF),count=2)
        if machine.reg_read(x86.UC_X86_REG_RDX) != base+moved(0xEFA7408)+index*8:
            raise ValueError("Native indexed asset hash bucket uses a stale RVA")
    return 4


def native_script_allocator(pe, report=None):
    # Execute MT_Alloc itself, including its atomic bitmap updates. Repeated
    # string-sized allocations must consume separate blocks in the moved
    # bitmap; checking only the returned pointer misses reads from stale data.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = pe.sections[0]
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    moved = lambda rva: remap(rva,report) if report else rva
    hints,bitmap = base+moved(0xDF6E714),base+moved(0xDF6E800)
    page = hints & -4096
    machine.mem_map(page,((bitmap+0x10000-page+4095)//4096)*4096)
    machine.mem_write(bitmap,b"\xff"*0x10000)
    stack = 0x100000000
    machine.mem_map(stack,0x10000)
    sentinel,rsp = stack+0x100,stack+0xf000-8
    allocated = set()
    results = []
    for size in (12,12,24,24,48,48,96,96,192,192,384,384,768,768):
        machine.mem_write(rsp,struct.pack('<Q',sentinel))
        machine.reg_write(x86.UC_X86_REG_RSP,rsp)
        machine.reg_write(x86.UC_X86_REG_RCX,size)
        machine.reg_write(x86.UC_X86_REG_RDX,26)
        machine.emu_start(base+moved(0x1317930),sentinel,count=10000)
        if machine.reg_read(x86.UC_X86_REG_RIP) != sentinel:
            raise ValueError("Native script allocator did not return")
        index = machine.reg_read(x86.UC_X86_REG_RAX)
        blocks = 1 << (((size+15)//16-1).bit_length())
        occupied = set(range(index,index+blocks))
        if occupied & allocated:
            raise ValueError("Native script allocator reused a live string block")
        allocated.update(occupied)
        for block in occupied:
            word = struct.unpack('<I',machine.mem_read(bitmap+(block//32)*4,4))[0]
            if word & (0x80000000 >> (block%32)):
                raise ValueError("Native script allocator did not update its moved bitmap")
        results.append(index)
    return results


def native_lua_dispatch_initialization(pe, report=None):
    # Run the actual producer of LuaJIT's bytecode/fast-function dispatch
    # arrays and verify its 154 pointers, including its duplicate first table.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for section in pe.sections:
        if section.Name.rstrip(b"\0") in (b".text",b".rdata"):
            machine.mem_map(base+section.VirtualAddress,(max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)&-4096)
            machine.mem_write(base+section.VirtualAddress,section.get_data())
    stack = 0x100000000
    machine.mem_map(stack,0x20000)
    sentinel,rsp,state = stack+0x100,stack+0x1f000-8,stack+0x2000
    machine.mem_write(rsp,struct.pack("<Q",sentinel))
    machine.reg_write(x86.UC_X86_REG_RSP,rsp)
    machine.reg_write(x86.UC_X86_REG_RCX,state)
    machine.emu_start(base+(remap(0x20A0DE0,report) if report else 0x20A0DE0),sentinel,count=10000)
    if machine.reg_read(x86.UC_X86_REG_RIP) != sentinel:
        raise ValueError("Native LuaJIT dispatch initializer did not return")
    table = struct.unpack("<154Q",machine.mem_read(state+0xfb0,154*8))
    duplicate = struct.unpack("<89Q",machine.mem_read(state+0xfb0+0x4d0,89*8))
    return [value-base for value in (*table,*duplicate)]


def native_physics_leaf_dispatch(pe, report=None):
    # Stock physics type-compendium loading calls a leaf switch whose checked
    # EDX index is copied into RAX. It has no standalone unwind entry.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    stack = 0x100000000
    machine.mem_map(stack,0x10000)
    sentinel,rsp,record = stack+0x100,stack+0xf000-8,stack+0x2000
    results = []
    for kind in range(11):
        machine.mem_write(rsp,struct.pack("<Q",sentinel))
        machine.mem_write(record,b"\xA5"*0x150)
        machine.reg_write(x86.UC_X86_REG_RSP,rsp)
        machine.reg_write(x86.UC_X86_REG_RCX,record)
        machine.reg_write(x86.UC_X86_REG_RDX,kind)
        machine.emu_start(base+(remap(0x1E85820,report) if report else 0x1E85820),sentinel,count=1000)
        if machine.reg_read(x86.UC_X86_REG_RIP) != sentinel:
            raise ValueError(f"Native physics leaf dispatch failed for kind {kind}")
        results.append(bytes(machine.mem_read(record+0xfc,12)).hex())
    return results


def native_reflection_leaf_dispatch(pe, report=None):
    # Havok's enum/member accessors use byte selectors followed by compact RVA
    # tables. The first selector is all zero: its single target still relocates.
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    stack = 0x100000000
    machine.mem_map(stack,0x10000)
    sentinel,rsp,record = stack+0x100,stack+0xf000-8,stack+0x2000
    results = []
    for rva in (0x1BB4110,0x1BB4190):
        for kind in (-1,*range(64),0x7fff):
            machine.mem_write(rsp,struct.pack("<Q",sentinel))
            machine.mem_write(record,struct.pack("<h",kind)+b"\0"*126)
            machine.reg_write(x86.UC_X86_REG_RSP,rsp)
            machine.reg_write(x86.UC_X86_REG_RCX,record)
            machine.emu_start(base+(remap(rva,report) if report else rva),sentinel,count=1000)
            if machine.reg_read(x86.UC_X86_REG_RIP) != sentinel:
                raise ValueError("Native byte-selected reflection leaf did not return")
            results.append(machine.reg_read(x86.UC_X86_REG_RAX))
    return results


def native_dvar_insertion_lookup(pe, report=None):
    # Execute the actual native insertion body and checksum lookup. Registration
    # derives an indexed image base before accessing the hash table; resolving
    # only its initial exact-base load makes insertion and lookup disagree.
    mapped_rva = lambda value: remap(value,report) if report else value
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+text.VirtualAddress,(max(text.Misc_VirtualSize,text.SizeOfRawData)+4095)&-4096)
    machine.mem_write(base+text.VirtualAddress,text.get_data())
    globals_begin,globals_end = mapped_rva(0xE371000)&-4096,(mapped_rva(0xE43E9F0)+0x1b65*2+4095)&-4096
    machine.mem_map(base+globals_begin,globals_end-globals_begin)
    table = base+mapped_rva(0xE43E9F0)
    machine.mem_write(table,b"\xff\xff"*0x1b65)
    stack = 0x100000000
    machine.mem_map(stack,0x20000)
    initial_rsp,sentinel = stack+0x10000,stack+0x100
    results = []
    for index,checksum in enumerate((0x12345678,0x12345678+0x1b65,0x5f539ab9),7):
        record = bytearray(0x70)
        struct.pack_into("<I",record,8,checksum)
        struct.pack_into("<I",record,0x18,0x100)
        record[0x1d] = 9
        machine.mem_write(initial_rsp+0xa0,bytes(record))
        pointer = base+mapped_rva(0xE37EE30)+index*0x70
        machine.mem_write(base+mapped_rva(0xE371310)+index*8,struct.pack("<Q",pointer))
        for register,value in ((x86.UC_X86_REG_RSP,initial_rsp),(x86.UC_X86_REG_RCX,index),
                               (x86.UC_X86_REG_RDI,checksum),(x86.UC_X86_REG_RSI,1),(x86.UC_X86_REG_RBP,0)):
            machine.reg_write(register,value)
        machine.emu_start(base+mapped_rva(0x13E7ECE),base+mapped_rva(0x13E7FD1),count=1000)
        if machine.reg_read(x86.UC_X86_REG_RIP) != base+mapped_rva(0x13E7FD1):
            raise ValueError("Native dvar insertion did not release its hash-table lock")
        machine.mem_write(initial_rsp-8,struct.pack("<Q",sentinel))
        machine.reg_write(x86.UC_X86_REG_RSP,initial_rsp-8)
        machine.reg_write(x86.UC_X86_REG_RCX,checksum)
        machine.emu_start(base+mapped_rva(0x13E62C0),sentinel,count=1000)
        if machine.reg_read(x86.UC_X86_REG_RAX) != pointer:
            raise ValueError(f"Native dvar lookup lost inserted checksum {checksum:08x}")
        results.append(checksum)
    # The first two checksums share a bucket; the third lookup must still
    # traverse the original collision chain to find the earlier registration.
    machine.mem_write(initial_rsp-8,struct.pack("<Q",sentinel))
    machine.reg_write(x86.UC_X86_REG_RSP,initial_rsp-8)
    machine.reg_write(x86.UC_X86_REG_RCX,results[0])
    machine.emu_start(base+mapped_rva(0x13E62C0),sentinel,count=1000)
    if machine.reg_read(x86.UC_X86_REG_RAX) != base+mapped_rva(0xE37EE30)+7*0x70:
        raise ValueError("Native dvar hash collision chain changed after layout")
    return len(results)+1


def native_thread_creation(pe, report=None):
    mapped_rva = lambda value: remap(value, report) if report else value
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if section.Name.rstrip(b"\0") in (b".text", b".rdata"):
            size = (max(section.Misc_VirtualSize, section.SizeOfRawData)+4095) & -4096
            emulator.mem_map(base+section.VirtualAddress,size)
            emulator.mem_write(base+section.VirtualAddress,section.get_data())
    page = mapped_rva(0xD57F000)&-4096
    emulator.mem_map(base+page,0x2000)
    stack = 0x100000000
    emulator.mem_map(stack,0x20000)
    sentinel = stack+0x1000
    names = ("CreateThread","SetThreadPriority","ResumeThread")
    stubs = {stack+0x2000+16*i:name for i,name in enumerate(names)}
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        for item in dll.imports:
            name = item.name.decode() if item.name else ""
            if name in names:
                at = next(at for at,label in stubs.items() if label == name)
                emulator.mem_write(item.address,struct.pack("<Q",at))
    captured = []
    handle = 0x1234
    index = 0x17
    callback = base+mapped_rva(0x1BD3360)
    def call(uc,address,size,_):
        if address not in stubs: return
        name = stubs[address]
        rsp = uc.reg_read(UC_X86_REG_RSP)
        if name == "CreateThread":
            assert uc.reg_read(UC_X86_REG_RCX)==0 and uc.reg_read(UC_X86_REG_RDX)==0
            assert uc.reg_read(UC_X86_REG_R8)==base+mapped_rva(0x12D0190)
            assert uc.reg_read(UC_X86_REG_R9)==index
            flags,thread_id = struct.unpack("<QQ",uc.mem_read(rsp+0x28,16))
            assert flags == 4 and thread_id == base+mapped_rva(0xD57F420)+4*index
            uc.mem_write(thread_id,struct.pack("<I",0x5678))
            result = handle
        else:
            assert uc.reg_read(UC_X86_REG_RCX)==handle
            result = 1
        captured.append(name)
        uc.reg_write(UC_X86_REG_RAX,result)
        uc.reg_write(UC_X86_REG_RIP,struct.unpack("<Q",uc.mem_read(rsp,8))[0])
        uc.reg_write(UC_X86_REG_RSP,rsp+8)
    emulator.hook_add(unicorn.UC_HOOK_CODE,call)
    rsp = stack+0x18000-8
    emulator.reg_write(UC_X86_REG_RSP,rsp)
    emulator.reg_write(UC_X86_REG_RCX,callback)
    emulator.mem_write(rsp,struct.pack("<Q",sentinel))
    emulator.emu_start(base+mapped_rva(0x12CFE40),sentinel,count=1000)
    assert captured == list(names) and emulator.reg_read(UC_X86_REG_RAX)&255 == 1
    for at,value,width in ((0xD57F4E0+8*index,callback,8),(0xD57F650+8*index,handle,8),
                           (0xD57F420+4*index,0x5678,4),(0xD57F7C0+4*index,0xffffffff,4)):
        assert int.from_bytes(emulator.mem_read(base+mapped_rva(at),width),"little") == value
    return True


def registration(pe, rva, arguments=None, callsite=False, aslr_delta=0, report=None):
    mapped_rva = lambda value: remap(value, report) if report else value
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase+aslr_delta
    mapped = []
    for section in pe.sections:
        if section.Name.rstrip(b"\0") in (b".text", b".rdata", b".cpp", b".rwcpp"):
            size = (max(section.Misc_VirtualSize, section.SizeOfRawData)+4095) & -4096
            emulator.mem_map(base+section.VirtualAddress, size)
            emulator.mem_write(base+section.VirtualAddress, section.get_data())
            mapped.append((base+section.VirtualAddress, base+section.VirtualAddress+size))
    stack = 0x100000000
    emulator.mem_map(stack, 0x20000)
    scratch = stack+0x1000
    sentinel = stack+0x8000
    emulator.mem_write(sentinel, b"\xcc")
    cookie_rva = 0x5A543F8
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cookie_at = mapped_rva(0x13E66CD)
    cookie_instruction = next(i for i in decoder.disasm_lite(pe.get_data(cookie_at, 7), cookie_at))
    match = re.search(r"rip \+ (0x[0-9a-f]+)", cookie_instruction[3])
    cookie_rva = cookie_instruction[0]+cookie_instruction[1]+int(match[1], 16)
    extra_pages = {cookie_rva & -4096, mapped_rva(0xD386880) & -4096}
    if report:
        extra_pages.update(p["rva"] & -4096 for p in report["placements"] if p["placement"] == "native_bss_tail")
    for page in extra_pages:
        emulator.mem_map(base+page, 4096)
        mapped.append((base+page, base+page+4096))
    if aslr_delta:
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                address = base+entry.rva
                if entry.type == 10 and any(a <= address and address+8 <= b for a,b in mapped):
                    value = struct.unpack("<Q", emulator.mem_read(address, 8))[0]
                    emulator.mem_write(address, struct.pack("<Q", (value+aslr_delta) & 0xffffffffffffffff))
    captured = []

    def string(address):
        data = bytearray()
        while True:
            byte = bytes(emulator.mem_read(address+len(data), 1))
            if byte == b"\0":
                return data.decode()
            data.extend(byte)
            if len(data) > 2048:
                raise ValueError("Unterminated registration string")

    def ret(value=None):
        rsp = emulator.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", emulator.mem_read(rsp, 8))[0]
        if value is not None:
            emulator.reg_write(UC_X86_REG_RAX, value)
        emulator.reg_write(UC_X86_REG_RSP, rsp+8)
        emulator.reg_write(UC_X86_REG_RIP, target)

    def hook(uc, address, size, _):
        if address == base+mapped_rva(0xC84BD0):
            # Controlled dependency: these tests supply already-obfuscated tokens.
            ret(uc.reg_read(UC_X86_REG_RCX))
        elif address == base+mapped_rva(0x21CCF60):
            ret()
        elif address == base+mapped_rva(0x13E7D40):
            rsp = uc.reg_read(UC_X86_REG_RSP)
            initial, domain, description = struct.unpack("<QQQ", uc.mem_read(rsp+0x28, 24))
            captured.append(dict(name=string(uc.reg_read(UC_X86_REG_RCX)),
                checksum=uc.reg_read(UC_X86_REG_RDX)&0xffffffff, type=uc.reg_read(UC_X86_REG_R8)&255,
                flags=uc.reg_read(UC_X86_REG_R9)&0xffffffff,
                value=struct.unpack("<i", uc.mem_read(initial, 4))[0],
                minimum=struct.unpack("<i", uc.mem_read(domain, 4))[0],
                maximum=struct.unpack("<i", uc.mem_read(domain+4, 4))[0], description=string(description)))
            ret(0x123456789ABC)

    emulator.hook_add(unicorn.UC_HOOK_CODE, hook)
    saved_registers = {}
    for index, name in enumerate(("RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15")):
        register = getattr(x86, "UC_X86_REG_"+name)
        value = 0 if callsite and name == "RDI" else 0xA01234000000+index
        emulator.reg_write(register, value)
        saved_registers[register] = value
    if callsite:
        rsp = stack+0x18000
        emulator.reg_write(UC_X86_REG_RSP, rsp)
        emulator.reg_write(UC_X86_REG_RDI, 0)
        end = base+mapped_rva(0x12B146A)
    else:
        name, value, minimum, maximum, flags, description = arguments
        emulator.mem_write(scratch, name.encode()+b"\0")
        emulator.mem_write(scratch+1024, description.encode()+b"\0")
        rsp = stack+0x18000-8
        emulator.mem_write(rsp, struct.pack("<Q", sentinel))
        emulator.mem_write(rsp+0x28, struct.pack("<QQ", flags, scratch+1024))
        for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, scratch),
                                (UC_X86_REG_RDX, value & 0xffffffff), (UC_X86_REG_R8, minimum & 0xffffffff),
                                (UC_X86_REG_R9, maximum & 0xffffffff)):
            emulator.reg_write(register, value)
        end = sentinel
    emulator.emu_start(base+rva, end, count=20000)
    if len(captured) != 1 or emulator.reg_read(UC_X86_REG_RAX) != 0x123456789ABC:
        raise ValueError("Registration did not return the native core result")
    if emulator.reg_read(UC_X86_REG_RSP) != stack+0x18000 or any(emulator.reg_read(r) != v for r,v in saved_registers.items()):
        raise ValueError("Registration violated the Windows x64 stack/nonvolatile-register ABI")
    if callsite and struct.unpack("<Q", emulator.mem_read(base+mapped_rva(0xD386880), 8))[0] != 0x123456789ABC:
        raise ValueError("Registration did not store the returned dvar in the native global")
    return captured[0]


def memory_copy(pe, report=None):
    mapped_rva = lambda value: remap(value, report) if report else value
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    section = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    machine.mem_map(base+section.VirtualAddress, (section.SizeOfRawData+4095) & -4096)
    machine.mem_write(base+section.VirtualAddress, section.get_data())
    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".rdata")
    machine.mem_map(base+rdata.VirtualAddress, (rdata.SizeOfRawData+4095) & -4096)
    machine.mem_write(base+rdata.VirtualAddress, rdata.get_data())
    # Controlled CPU-dispatch dependency: select the native SSE2 path. The
    # exact Replay BT instruction at 0x21F6730 addresses this BSS flag.
    machine.mem_map(base+(mapped_rva(0x12EC2E60) & -4096), 4096)
    arena = 0x200000000
    machine.mem_map(arena, 0x10000)
    source, destination, stack, sentinel = arena+0x1000, arena+0x3000, arena+0x8000, arena+0xF000
    content = bytes((i*13+7) & 255 for i in range(2048))
    machine.mem_write(source, content)
    sizes = list(range(33))+[48,64,80,96,128]
    for size in sizes:
        machine.mem_write(destination-16, b"\xA5"*2080)
        machine.mem_write(stack-8, struct.pack("<Q", sentinel))
        for register, value in ((x86.UC_X86_REG_RSP, stack-8), (x86.UC_X86_REG_RCX, destination),
                                (x86.UC_X86_REG_RDX, source), (x86.UC_X86_REG_R8, size)):
            machine.reg_write(register, value)
        try:
            machine.emu_start(base+mapped_rva(0x21F64A0), sentinel, count=20000)
        except unicorn.UcError as error:
            raise ValueError(f"Native memcpy case {size}, RIP {machine.reg_read(x86.UC_X86_REG_RIP):x}: {error}") from error
        if bytes(machine.mem_read(destination, size)) != content[:size] or machine.reg_read(x86.UC_X86_REG_RAX) != destination:
            raise ValueError(f"Native memcpy indirect dispatch failed for size {size}")
        if bytes(machine.mem_read(destination-16, 16)) != b"\xA5"*16 or bytes(machine.mem_read(destination+size, 16)) != b"\xA5"*16:
            raise ValueError(f"Native memcpy overwrote its bounds for size {size}")
    return len(sizes)


def verify_frameless_leaf(code, rva, unwind_entries=()):
    """Prove reachable instructions need only the x64 leaf return-address pop.

    A compiler may omit .pdata for these functions. An unconditional tail jump
    may enter an exact function entry with its own unwind record after proving
    that this stub leaves the stack and preserved registers unchanged.
    Missing unwind metadata on a frame/call/nonvolatile save remains an error.
    """
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    pending, visited = [rva], set()
    preserved = {'rbx','ebx','bx','bl','bh','rbp','ebp','bp','bpl',
                 'rsi','esi','si','sil','rdi','edi','di','dil','rsp','esp','sp','spl'}
    preserved.update(f'r{n}{suffix}' for n in range(12,16) for suffix in ('','d','w','b'))
    preserved.update(f'{prefix}{n}' for n in range(6,16) for prefix in ('xmm','ymm','zmm'))
    while pending:
        at = pending.pop()
        if at in visited:
            continue
        if not rva <= at < rva+len(code):
            raise ValueError('Frameless leaf has an unverified external transfer')
        insn = next(decoder.disasm(code[at-rva:], at, count=1), None)
        if insn is None:
            raise ValueError('Frameless leaf has invalid code')
        visited.add(at)
        if insn.mnemonic == 'ret' and not insn.op_str:
            continue
        if insn.group(capstone.CS_GRP_CALL) or insn.group(capstone.CS_GRP_RET):
            raise ValueError('Function without unwind metadata changes the return stack')
        if preserved & {insn.reg_name(reg) for reg in insn.regs_access()[1]}:
            raise ValueError('Function without unwind metadata changes a preserved register')
        for op in insn.operands:
            if (op.type == capstone.x86.X86_OP_MEM and op.access & capstone.CS_AC_WRITE and
                    insn.reg_name(op.mem.base) in ('rsp','rbp','esp','ebp')):
                raise ValueError('Frameless leaf requires an explicit stack-store proof')
        if insn.group(capstone.CS_GRP_JUMP):
            if len(insn.operands)!=1 or insn.operands[0].type!=capstone.x86.X86_OP_IMM:
                raise ValueError('Frameless leaf has an unresolved branch')
            target = insn.operands[0].imm
            if not rva <= target < rva+len(code):
                if insn.mnemonic != 'jmp' or target not in unwind_entries:
                    raise ValueError('Frameless leaf has an unverified external transfer')
                continue
            pending.append(target)
            if insn.mnemonic == 'jmp':
                continue
        pending.append(at+insn.size)
    return len(visited)


def windows_image_mapping(path, pe, report):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileMappingW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
    kernel.CreateFileMappingW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    kernel.MapViewOfFile.restype = ctypes.c_void_p
    kernel.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    file = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0, None)
    if file == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    mapping = None
    view = None
    unwind_tests = 0
    leaf_tests = {}
    try:
        mapping = kernel.CreateFileMappingW(file, None, 0x1000002, 0, 0, None)
        if not mapping:
            raise ctypes.WinError(ctypes.get_last_error())
        view = kernel.MapViewOfFile(mapping, 4, 0, 0, 0)
        if not view:
            raise ctypes.WinError(ctypes.get_last_error())
        ntdll = ctypes.WinDLL("ntdll")
        unwind = ntdll.RtlVirtualUnwind
        unwind.argtypes = [wintypes.DWORD, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        unwind.restype = ctypes.c_void_p
        names = ("RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
        nonvolatile = {"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15"}
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        names_to_unwind = [p["symbol"] for p in report["replacements"]]
        unwind_entries = {entry.struct.BeginAddress for entry in pe.DIRECTORY_ENTRY_EXCEPTION}
        for name in names_to_unwind:
            rva = report["symbols"][name]
            entry = next((e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress == rva), None)
            if entry is None:
                placement = next(p for p in report['placements'] if p['symbol']==name)
                if any(e.struct.BeginAddress < rva+placement['size'] and e.struct.EndAddress > rva
                       for e in pe.DIRECTORY_ENTRY_EXCEPTION):
                    raise ValueError(f'Leaf {name} overlaps another function unwind record')
                try:
                    leaf_tests[name] = verify_frameless_leaf(pe.get_data(rva,placement['size']),rva,unwind_entries)
                except ValueError as error:
                    raise ValueError(f'Unwind validation failed for {name}: {error}') from error
                continue
            prologue_size = pe.get_data(entry.UnwindData, 2)[1]
            prologue = list(decoder.disasm_lite(pe.get_data(rva, prologue_size), rva))
            if sum(i[1] for i in prologue) != prologue_size:
                raise ValueError("Unwind prologue extent is not an instruction boundary")
            for stop in [rva]+[i[0]+i[1] for i in prologue]:
                # CONTEXT layout is the AMD64 definition in the installed
                # Windows SDK winnt.h: integer registers at 120, RIP at 248.
                stack_buffer = ctypes.create_string_buffer(0x6000)
                stack_at = (ctypes.addressof(stack_buffer)+15) & -16
                initial_rsp = stack_at+0x4000-8
                return_pc = 0x123456789ABC
                struct.pack_into("<Q", stack_buffer, initial_rsp-ctypes.addressof(stack_buffer), return_pc)
                machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
                stack_page = ctypes.addressof(stack_buffer) & -4096
                machine.mem_map(stack_page, 0x8000)
                machine.mem_write(ctypes.addressof(stack_buffer), bytes(stack_buffer))
                code_page = (view+rva) & -4096
                code_extent = ((view+entry.EndAddress+4095) & -4096)-code_page
                machine.mem_map(code_page, code_extent)
                machine.mem_write(view+rva, pe.get_data(rva, entry.EndAddress-rva))
                cookie_page = (view+remap(0x5A543F8,report)) & -4096
                machine.mem_map(cookie_page,4096)
                machine.mem_write(cookie_page,ctypes.string_at(cookie_page,4096))
                expected_registers = {}
                for index, register_name in enumerate(names):
                    register = getattr(x86, "UC_X86_REG_"+register_name)
                    value = initial_rsp if register_name == "RSP" else 0xB03412000000+index
                    machine.reg_write(register, value)
                    if register_name in nonvolatile:
                        expected_registers[register_name] = value
                if stop != rva:
                    machine.emu_start(view+rva, view+stop, count=100)
                ctypes.memmove(ctypes.addressof(stack_buffer), bytes(machine.mem_read(ctypes.addressof(stack_buffer), len(stack_buffer))), len(stack_buffer))
                context_buffer = ctypes.create_string_buffer(1248)
                context = (ctypes.addressof(context_buffer)+15) & -16
                ctypes.c_uint32.from_address(context+48).value = 0x10000B
                for index, register_name in enumerate(names):
                    ctypes.c_uint64.from_address(context+120+index*8).value = machine.reg_read(getattr(x86, "UC_X86_REG_"+register_name))
                ctypes.c_uint64.from_address(context+248).value = view+stop
                runtime = ctypes.create_string_buffer(struct.pack("<III", entry.BeginAddress, entry.EndAddress, entry.UnwindData))
                handler_data, establisher = ctypes.c_void_p(), ctypes.c_uint64()
                unwind(0, view, view+stop, ctypes.addressof(runtime), context, ctypes.byref(handler_data), ctypes.byref(establisher), None)
                if ctypes.c_uint64.from_address(context+248).value != return_pc or ctypes.c_uint64.from_address(context+152).value != initial_rsp+8:
                    raise ValueError(f"Windows could not unwind {name} at prologue offset {stop-rva}")
                for register_name, value in expected_registers.items():
                    if ctypes.c_uint64.from_address(context+120+names.index(register_name)*8).value != value:
                        raise ValueError(f"Windows unwind lost {register_name} in {name}")
                unwind_tests += 1
    finally:
        if view:
            kernel.UnmapViewOfFile(view)
        if mapping:
            kernel.CloseHandle(mapping)
        kernel.CloseHandle(file)
    return unwind_tests, leaf_tests


def main(output):
    report = json.loads((output / "build-report.json").read_text())
    source_provenance.validate_report(report)
    executable = Path(report["executable"])
    original = pefile.PE(str(ORIGINAL))
    rebuilt = pefile.PE(str(executable))
    checks = dict(sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                  original_sha256=hashlib.sha256(ORIGINAL.read_bytes()).hexdigest())
    if checks["sha256"] != report["sha256"] or checks["original_sha256"] != report["input_sha256"]:
        raise ValueError("Executable hash mismatch")
    checks["assembly"] = check_text(original, rebuilt, report, output)
    print("Assembly and non-instruction data verified", flush=True)
    checks["native_memcpy_cases"] = memory_copy(original)+memory_copy(rebuilt, report)
    before_initializer = virtual_base_initializer(original)
    after_initializer = virtual_base_initializer(rebuilt,report)
    if after_initializer != [remap(value,report) if value >= 0 else value for value in before_initializer]:
        raise ValueError("Native virtual-base initializer references are stale")
    checks["native_virtual_base_initializer"] = True
    checks["native_thread_creation"] = native_thread_creation(original) and native_thread_creation(rebuilt,report)
    domain_before = native_domain_validation(original)
    if native_domain_validation(rebuilt,report) != domain_before:
        raise ValueError("Native leaf domain switch changed after linking")
    checks["native_domain_switch_cases"] = len(domain_before)
    checks["native_dvar_insertion_lookup_cases"] = native_dvar_insertion_lookup(original)+native_dvar_insertion_lookup(rebuilt,report)
    physics_before = native_physics_leaf_dispatch(original)
    if native_physics_leaf_dispatch(rebuilt,report) != physics_before:
        raise ValueError("Native physics leaf dispatch changed after linking")
    checks["native_physics_leaf_dispatch_cases"] = len(physics_before)
    lua_before = native_lua_dispatch_initialization(original)
    if native_lua_dispatch_initialization(rebuilt,report) != [remap(value,report) for value in lua_before]:
        raise ValueError("Native LuaJIT dispatch pointers changed after linking")
    checks["native_lua_dispatch_pointers"] = len(lua_before)
    sparse_before = native_sparse_renderer_dispatch(original)
    if native_sparse_renderer_dispatch(rebuilt,report) != [remap(value,report) for value in sparse_before]:
        raise ValueError("Native sparse renderer switch changed after linking")
    checks["native_sparse_renderer_dispatch_cases"] = len(sparse_before)
    masked_before = native_masked_renderer_dispatch(original)
    if native_masked_renderer_dispatch(rebuilt,report) != [remap(value,report) for value in masked_before]:
        raise ValueError("Native masked renderer dispatch changed after linking")
    checks["native_masked_renderer_dispatch_cases"] = len(masked_before)
    reflection_before = native_reflection_leaf_dispatch(original)
    if native_reflection_leaf_dispatch(rebuilt,report) != reflection_before:
        raise ValueError("Native byte-selected reflection dispatch changed after linking")
    checks["native_reflection_leaf_dispatch_cases"] = len(reflection_before)
    if verify_spatial(rebuilt,report) != verify_spatial(original):
        raise ValueError("Native spatial initialization changed after linking")
    checks["native_spatial_initialization"] = verify_spatial(original)
    checks["native_asset_hash_bucket_cases"] = native_asset_hash_bucket(original)+native_asset_hash_bucket(rebuilt,report)
    allocator_before,allocator_after = native_script_allocator(original),native_script_allocator(rebuilt,report)
    if allocator_before != allocator_after:
        raise ValueError("Rebuilt script allocator differs from the native allocation sequence")
    checks["native_script_allocator_cases"] = len(allocator_before)+len(allocator_after)
    if native_font_callbacks(rebuilt,report)!=native_font_callbacks(original):
        raise ValueError("Native font callback data flow changed after linking")
    checks["native_font_outline_callbacks"] = 4
    checks["native_crt_destructors"] = dict(native=verify_crt(original),rebuilt=verify_crt(rebuilt,report))
    if remap(original.OPTIONAL_HEADER.AddressOfEntryPoint,report) != rebuilt.OPTIONAL_HEADER.AddressOfEntryPoint:
        raise ValueError("Native entry point changed")
    old_imports = [(x.dll, [(i.name, i.ordinal, original.OPTIONAL_HEADER.ImageBase+remap(i.address-original.OPTIONAL_HEADER.ImageBase,report)) for i in x.imports]) for x in original.DIRECTORY_ENTRY_IMPORT]
    new_imports = [(x.dll, [(i.name, i.ordinal, i.address) for i in x.imports]) for x in rebuilt.DIRECTORY_ENTRY_IMPORT]
    if old_imports != new_imports:
        raise ValueError("Native imports changed")
    entries = [entry.struct for entry in rebuilt.DIRECTORY_ENTRY_EXCEPTION]
    if [e.BeginAddress for e in entries] != sorted(e.BeginAddress for e in entries):
        raise ValueError("Unwind table is not sorted")
    if len(entries) != len(original.DIRECTORY_ENTRY_EXCEPTION)+report["cpp_unwind_entries"]-report["removed_unwind_entries"]:
        raise ValueError("Missing C++ unwind entries")
    checks["unwind_entries"] = len(entries)
    checks["import_dlls"] = len(new_imports)
    before = registration(original, 0x12B143C, callsite=True)
    after = registration(rebuilt, remap(0x12B143C,report), callsite=True, report=report)
    expected = before
    if before["value"] != 50 or after != expected:
        raise ValueError(f"Unexpected registration change: {before} -> {after}")
    checks["registration_before"] = before
    checks["registration_after"] = after
    cases = [("MKMQPNOTSN", 50, 16, 100, 0, "adjacent dvar"),
             ("CONTROL", -17, -200, 300, 0xA5A50123, "signed integer and flags"),
             ("MKQQKMRORQ", 50, 16, 100, 0, "generic registration stays generic")]
    for arguments in cases:
        a = registration(original, 0x13E7A00, arguments)
        b = registration(rebuilt, remap(0x13E7A00, report), arguments, report=report)
        if a != b:
            raise ValueError(f"Integer registration ABI mismatch: {a} -> {b}")
    checks["integer_abi_cases"] = len(cases)
    checks["registration_after_aslr"] = registration(rebuilt, remap(0x12B143C,report), callsite=True, aslr_delta=0x200000, report=report)
    if checks["registration_after_aslr"] != expected:
        raise ValueError("Registration changed under ASLR")
    for at, target, width in struct.iter_unpack("<III", (ROOT / "generated" / "data-fixups.bin").read_bytes()):
        if any(item["begin"] <= at < item["end"] for item in report["replacements"]):
            continue
        value = remap(target, report)+(original.OPTIONAL_HEADER.ImageBase if width == 8 else 0)
        if rebuilt.get_data(remap(at,report), width) != struct.pack("<Q" if width == 8 else "<I", value):
            raise ValueError(f"Native pointer/RVA resolution failed at {at:x}")
    checks["resolved_references"] = report["resolved_references"]
    checks["unresolved_symbols"] = report["unresolved_symbols"]
    checks["image_size"] = rebuilt.OPTIONAL_HEADER.SizeOfImage
    manifest = json.loads((ROOT / "generated" / "manifest.json").read_text())
    checks["serialized_map_bindings"] = compiler_identity.verify_map(rebuilt,manifest,report)
    native_proxy_patterns = json.loads((ROOT / "generated" / "proxy-patterns.json").read_text())
    checks["embedded_proxy_signature_registry"] = proxy_signature_registry.verify_pe(
        rebuilt, report, native_proxy_patterns, remap)
    compiler_identity.verify(executable.read_bytes()[:0x80], manifest, rebuilt.OPTIONAL_HEADER.SizeOfImage,report)
    checks["compiler_image_identity"] = True
    for signature in manifest["proxy_signatures"]:
        data = bytes.fromhex(signature["bytes"])
        if not report.get("rva_map", {}).get("insertions") and rebuilt.get_data(remap(signature["rva"],report), len(data)) != data:
            raise ValueError(f"Byte-sensitive proxy binding changed: {signature['name']}")
    metadata_count = 0
    retired_metadata = set(report.get('retired_metadata_fields', []))
    for at,target,width in struct.iter_unpack("<III",(ROOT / "generated" / "metadata-fixups.bin").read_bytes()):
        if at in retired_metadata or any(r["begin"] <= at < r["end"] for r in report["replacements"]):
            continue
        if rebuilt.get_data(remap(at,report),width) != remap(target,report).to_bytes(width,"little"):
            raise ValueError(f"Native metadata resolution failed at {at:x}")
        metadata_count += 1
    checks["metadata_rva_references"] = metadata_count
    for item in report.get("metadata", {}).get("relative_tables", []):
        target,origin = remap(item["target"],report),remap(item["base"],report)
        distance = origin-target if item["subtract"] else target-origin
        width = item.get("width",4)
        if rebuilt.get_data(remap(item["at"],report),width) != ((distance >> item["shift"]) & ((1 << (width*8))-1)).to_bytes(width,"little"):
            raise ValueError("Shifted switch table reference is stale")
    checks["switch_table_elements"] = len(report.get("metadata", {}).get("relative_tables", []))
    checks["rva_map"] = report.get("rva_map", {})
    checks["proxy_signatures"] = len(manifest["proxy_signatures"])
    checks["windows_virtual_unwind_cases"], checks['verified_frameless_leaves'] = windows_image_mapping(executable, rebuilt, report)
    checks["windows_sec_image_mapping"] = True
    checks["game_runtime_tested"] = False
    (output / "verification-report.json").write_text(json.dumps(checks, indent=2)+"\n")
    print(json.dumps(checks, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    main(parser.parse_args().build)
