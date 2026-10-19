"""Recover instruction assembly and initialized data for the pinned Replay build.

Executable instructions are emitted as mnemonics, never as an embedded text blob.
IDA boundaries are augmented with recursive decoding from unwind entries, known
instructions and relocated function pointers, because the old IDB has code gaps.
"""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import time

import capstone
import pefile
import metadata
import metadata_producers
import native_operand_references
import native_unproven

ROOT = Path(__file__).resolve().parents[1]
SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def preparation_inputs(output):
    """Recovery cache key covers algorithms and external analysis evidence."""
    paths = [ROOT/'tools'/name for name in ('recover.py', 'metadata.py', 'image_references.py',
                                           'native_functions.py', 'source_catalog.py',
                                           'native_operand_references.py', 'recovered_cpp_names.py',
                                           'metadata_producers.py', 'native_unproven.py')]
    paths += [output/name for name in ('code-items.bin', 'noncode-items.bin',
              'ida-rva-fixups.bin', 'ida-switch-references.json', 'ida-immediate-references.json',
              'proxy-signatures.json')]
    if (output / native_unproven.FILE).exists():
        paths.append(output / native_unproven.FILE)
    return [dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]


def retire_weak_overlaps(lengths, seen, confidence, offset, size, strong):
    """A proven instruction may supersede isolated IDA guesses, never proven code."""
    heads = set()
    for position in range(offset, offset+size):
        if not lengths[position]:
            continue
        head = position
        while head > 0 and lengths[head] == 255:
            head -= 1
        if head == offset and lengths[head] == size:
            continue
        if not strong or confidence[head] >= 2:
            raise ValueError(f'Conflicting proven instruction boundary at text offset {offset:x}')
        heads.add(head)
    retired = []
    for head in sorted(heads):
        end = head+lengths[head]
        retired.append((head, end))
        lengths[head:end] = b'\0'*(end-head)
        seen[head:end] = b'\0'*(end-head)
        confidence[head:end] = b'\0'*(end-head)
    return retired


def recover(executable, reuse_analysis=False):
    output = ROOT / "generated"
    initial_inputs = preparation_inputs(output)
    image_bytes = executable.read_bytes()
    if hashlib.sha256(image_bytes).hexdigest() != SHA256:
        raise ValueError("Input is not the verified Replay executable")
    pe = pefile.PE(data=image_bytes)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    start = text.VirtualAddress
    raw = text.get_data()
    end = start + len(raw)
    unproven = native_unproven.load(output, SHA256, hashlib.md5(image_bytes).hexdigest(),
                                   start, end, pe.get_data)
    unproven_mask = unproven.mask(start, len(raw))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lengths = bytearray(len(raw))
    known_heads = bytearray(len(raw))
    for rva, _ in struct.iter_unpack("<IB", (output / "code-items.bin").read_bytes()):
        if start <= rva < end and not unproven_mask[rva-start]:
            known_heads[rva-start] = 1
    known_data = bytearray(len(raw))
    tables = bytearray(len(raw))
    for rva, size, kind in struct.iter_unpack("<IIB", (output / "noncode-items.bin").read_bytes()):
        if kind == 2:
            known_data[rva-start:rva-start+size] = b"\x01" * size
        if kind == 2 and size >= 12 and not size % 4:
            position = rva-start
            if unproven.overlaps(rva, rva + size):
                continue
            if position+12 > len(raw):
                continue
            values = struct.unpack_from("<III", raw, position)
            if all(start <= value < end and known_heads[value-start] for value in values):
                stop = position+12
                item_end = min(position+size, len(raw))
                while stop+4 <= item_end:
                    target = struct.unpack_from("<I", raw, stop)[0]
                    if not start <= target < end:
                        break
                    stop += 4
                tables[position:stop] = b"\x01" * (stop-position)
    # Explicit image-relative DWORDs also identify dispatch targets which the
    # IDB did not decode. Never extend a table into an adjacent byte selector.
    reference_file = output / "ida-rva-fixups.bin"
    if reference_file.exists():
        for at,target,width in struct.iter_unpack("<III", reference_file.read_bytes()):
            if unproven.overlaps(at, at + width):
                continue  # Unproven IDA annotations are not relocation evidence.
            if width == 4 and start <= at < end and start <= target < end:
                if struct.unpack_from("<I", raw, at-start)[0] != target:
                    raise ValueError("IDA dispatch reference has the wrong provenance")
                tables[at-start:at-start+4] = b"\x01"*4
    switch_file = output / "ida-switch-references.json"
    if switch_file.exists():
        for item in json.loads(switch_file.read_text()):
            if unproven.overlaps(item['at'], item['at'] + item.get('width', 4)):
                continue
            if item["base"] == 0 and not item["subtract"] and not item["shift"] and start <= item["at"] < end:
                tables[item["at"]-start:item["at"]-start+4] = b"\x01"*4
    seen = bytearray(len(raw))
    confidence = bytearray(len(raw))
    boundary_repairs = []
    queue = collections.deque()
    recovered = 0
    decoded = 0
    conflicts = []

    def seed(rva, strong=False):
        if start <= rva < end and not tables[rva-start] and (
            (not seen[rva-start] and lengths[rva-start] != 255) or (strong and confidence[rva-start] < 2)):
            queue.append(rva)

    def drain(weak=False):
        nonlocal recovered, decoded
        changes = []
        old_recovered, old_decoded = recovered, decoded
        try:
            walk(changes if weak else None)
            return True
        except ValueError as error:
            if not weak:
                raise
            for offset, old, old_seen, old_confidence in reversed(changes):
                lengths[offset:offset+len(old)] = old
                seen[offset:offset+len(old)] = old_seen
                confidence[offset:offset+len(old)] = old_confidence
            recovered, decoded = old_recovered, old_decoded
            queue.clear()
            conflicts.append(str(error))
            return False

    def walk(changes):
        nonlocal recovered, decoded
        while queue:
            rva = queue.pop()
            offset = rva-start
            if seen[offset] and (changes is not None or confidence[offset] >= 2):
                continue
            while rva < end:
                if unproven.contains(rva):
                    raise ValueError(f'Native control flow reaches terminal unowned bytes at {rva:#x}')
                block = list(decoder.disasm_lite(raw[rva-start:rva-start+128], rva))
                if not block:
                    raise ValueError(f"Undecodable reachable instruction at {rva:x}")
                stopped = False
                for address, size, mnemonic, operands in block:
                    offset = address-start
                    if unproven.overlaps(address, address + size):
                        raise ValueError(f'Native instruction overlaps terminal unowned bytes at {address:#x}')
                    if seen[offset] and (changes is not None or confidence[offset] >= 2):
                        stopped = True
                        break
                    if tables[offset]:
                        raise ValueError(f"Instruction flow entered an inline jump table at {address:x}")
                    for a,b in retire_weak_overlaps(lengths,seen,confidence,offset,size,changes is None):
                        boundary_repairs.append(dict(begin=start+a,end=start+b,proven_instruction=address))
                    if changes is not None:
                        operation = mnemonic.split()[-1]
                        if operation in ("in", "out", "insb", "insd", "outsb", "outsd", "hlt", "cli", "sti", "retf", "iretd", "int1"):
                            raise ValueError(f"Privileged/invalid isolated IDA code at {address:x}")
                        if mnemonic == "movsxd" and re.match(r"e[a-z]+,", operands):
                            raise ValueError(f"Invalid isolated MOVSXD boundary at {address:x}")
                        if (operation.startswith("j") or operation.startswith("loop") or operation == "call") and re.fullmatch(r"0x[0-9a-f]+", operands):
                            if not start <= int(operands, 16) < end:
                                raise ValueError(f"Isolated code branches outside executable text at {address:x}")
                        match = re.search(r"rip(?:\s*([+-])\s*(0x[0-9a-f]+))?", operands)
                        if match:
                            displacement = int(match[2], 16) * (-1 if match[1] == "-" else 1) if match[2] else 0
                            if not 0 <= address+size+displacement < pe.OPTIONAL_HEADER.SizeOfImage:
                                raise ValueError(f"Isolated IDA code refers outside the image at {address:x}")
                    if changes is not None:
                        changes.append((offset, bytes(lengths[offset:offset+size]), bytes(seen[offset:offset+size]), bytes(confidence[offset:offset+size])))
                    if not known_heads[offset]:
                        recovered += 1
                    decoded += 1
                    if decoded % 1000000 == 0:
                        print(f"Decoded {decoded:,} instructions ({recovered:,} absent from IDA boundaries)", flush=True)
                    lengths[offset:offset+size] = bytes([size]) + b"\xff" * (size-1)
                    seen[offset] = 1
                    confidence[offset:offset+size] = bytes([1 if changes is not None else 2])*size
                    operation = mnemonic.split()[-1]
                    if operation.startswith("j") or operation.startswith("loop") or operation == "call":
                        if re.fullmatch(r"0x[0-9a-f]+", operands):
                            seed(int(operands, 16), strong=changes is None)
                    if operation in ("jmp", "ret", "retf", "iretq", "int3", "ud2"):
                        stopped = True
                        break
                    rva = address+size
                if stopped:
                    break
                if block[-1][0] + block[-1][1] != rva:
                    raise ValueError(f"Decoder did not advance at {rva:x}")

    if reuse_analysis:
        previous = json.loads((output / "manifest.json").read_text())
        if previous["input_sha256"] != SHA256:
            raise ValueError("Cached analysis belongs to another executable")
        lengths = bytearray((output / "instruction-lengths.bin").read_bytes())
        confidence_file = output/'instruction-confidence.bin'
        confidence = bytearray(confidence_file.read_bytes()) if confidence_file.exists() else bytearray(1 if x else 0 for x in lengths)
        if len(lengths) != len(raw):
            raise ValueError("Cached analysis has the wrong extent")
        for row in unproven.rows:
            first, last = row['begin'] - start, row['end'] - start
            if any(confidence[first:last][i] >= 2 and value for i, value in enumerate(lengths[first:last])):
                raise ValueError('Terminal unowned evidence conflicts with previously proven native code')
            lengths[first:last] = b'\0' * (last - first)
            confidence[first:last] = b'\0' * (last - first)
        recovered = previous["recovery"]["additional_instructions"]
    else:
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            rva = entry.struct.BeginAddress
            # Primary unwind entries are executable roots even when the old
            # IDB missed them. Chained ranges can describe inline jump tables.
            flags = pe.get_data(entry.struct.UnwindData, 1)[0] >> 3
            if start <= rva < end and (known_heads[rva-start] or not flags & 4):
                seed(rva)
        seed(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        drain()
        # Chained unwind ranges also start real cold/dispatch blocks. They
        # must precede isolated IDA roots: that database sometimes starts an
        # instruction in the middle of a block it did not recognize. A few
        # ranges cover inline tables, which seed() excludes. Reject other
        # non-executable chains transactionally instead of keeping guesses.
        chain_roots = 0
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            rva = entry.struct.BeginAddress
            flags = pe.get_data(entry.struct.UnwindData, 1)[0] >> 3
            if flags & 4 and start <= rva < end and not lengths[rva-start]:
                seed(rva)
                if queue:
                    drain(weak=True)
                    chain_roots += 1
        print(f"Examined {chain_roots:,} chained unwind roots", flush=True)
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            seed(entry.address)
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                if entry.type == 10:
                    pointer = struct.unpack("<Q", pe.get_data(entry.rva, 8))[0]
                    rva = pointer-pe.OPTIONAL_HEADER.ImageBase
                    if start <= rva < end:
                        seed(rva)
        drain()
        # Indirect dispatch blocks often have no standalone unwind entry and
        # were data/overlapping instructions in the old IDB. Decode table
        # targets before considering weaker isolated IDA instruction roots.
        position = 0
        table_roots = 0
        while position < len(tables):
            if tables[position]:
                seed(struct.unpack_from("<I", raw, position)[0])
                drain(weak=True)
                table_roots += 1
                position += 4
            else:
                position += 1
        print(f"Examined {table_roots:,} indirect dispatch roots", flush=True)
        print(f"Recovered {recovered:,} additional instructions from engine entry points", flush=True)
        for rva, _ in struct.iter_unpack("<IB", (output / "code-items.bin").read_bytes()):
            if unproven.contains(rva):
                continue
            seed(rva)
            drain(weak=True)
        if conflicts:
            (output / "rejected-ida-roots.json").write_text(json.dumps(conflicts, indent=2))
        (output / "instruction-lengths.bin").write_bytes(lengths)

    # Leaf callbacks have no unwind entry and may be entirely absent from the
    # IDB. A real RIP-relative LEA taking a padded, aligned text entry is code
    # provenance (the font outline move-to callback is one such entry). Decode
    # these transactionally, excluding all typed table bytes. Repeating also
    # covers further callback addresses exposed by the newly recovered code.
    # A cached analysis can still have omitted a leaf referenced by an actual
    # PE-relocated function pointer. Revisit only undecoded text targets; keep
    # the same table exclusions and transactional decoding as other callbacks.
    pointer_roots = set()
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type != 10: continue
            target = struct.unpack('<Q',pe.get_data(entry.rva,8))[0]-pe.OPTIONAL_HEADER.ImageBase
            offset = target-start
            if 0 <= offset < len(raw) and not lengths[offset] and not tables[offset]:
                seed(target)
                if queue and drain(weak=True): pointer_roots.add(target)
    print(f"Recovered {len(pointer_roots)} omitted entries from relocated native pointers",flush=True)
    (output / 'relocated-callback-roots.json').write_text(json.dumps(sorted(pointer_roots),indent=2)+'\n')
    callback_file = output / 'leaf-callback-roots.json'
    callback_roots = set(json.loads(callback_file.read_text())) if callback_file.exists() else set()
    attempted_callbacks = set()
    crt_callbacks = {}
    detailed = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detailed.detail = True
    def registered_crt_callback(position):
        # The pinned CRT atexit wrapper at 0x21CCE40 accepts its callback in
        # RCX. A constructor may restore RSP before tail-calling it. Adjacent
        # aligned destructors need not have a padding byte before their entry.
        if raw[position:position+3] != b'\x48\x8d\x0d': return False
        at = position+7
        for _ in range(6):
            if at >= len(raw) or lengths[at] in (0,255): return False
            instruction = next(detailed.disasm(raw[at:at+lengths[at]], start+at), None)
            if instruction is None: return False
            if instruction.mnemonic in ('call','jmp'):
                return (len(instruction.operands) == 1 and
                        instruction.operands[0].type == capstone.x86.X86_OP_IMM and
                        instruction.operands[0].imm == 0x21CCE40)
            if instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_RET): return False
            if any(instruction.reg_name(reg) in ('rcx','ecx','cx','cl','ch') for reg in instruction.regs_access()[1]): return False
            at += instruction.size
        return False
    while True:
        candidates = []
        for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]",raw):
            position = match.start()
            if lengths[position] != 7: continue
            target = start+position+7+struct.unpack_from("<i",raw,position+3)[0]
            offset = target-start
            if (target in attempted_callbacks or not 0 < offset < len(raw) or
                    lengths[offset] or tables[offset] or raw[offset] in (0x90,0xcc)):
                continue
            registered = registered_crt_callback(position)
            if not registered and (target & 15 or raw[offset-1] not in (0x90,0xcc)): continue
            if registered: crt_callbacks[target] = dict(site=start+position,target=target,registrar=0x21CCE40)
            candidates.append(target)
        if not candidates: break
        for target in candidates:
            if target in attempted_callbacks: continue
            attempted_callbacks.add(target)
            seed(target)
            if queue and drain(weak=True): callback_roots.add(target)
    print(f"Recovered {len(callback_roots)} padded leaf entries from native function-address LEAs",flush=True)
    callback_file.write_text(json.dumps(sorted(callback_roots),indent=2)+"\n")
    # Every directly registered native destructor must be executable code.
    # Keep this proof independent of whether an earlier pass recovered it.
    for match in re.finditer(rb'\x48\x8d\x0d',raw):
        position = match.start()
        if lengths[position] != 7 or not registered_crt_callback(position): continue
        target = start+position+7+struct.unpack_from('<i',raw,position+3)[0]
        if not start <= target < end or lengths[target-start] in (0,255):
            raise ValueError(f"CRT registered a destructor without a decoded entry: {target:x}")
        crt_callbacks[target] = dict(site=start+position,target=target,registrar=0x21CCE40)
    (output / 'crt-callback-roots.json').write_text(json.dumps(list(crt_callbacks.values()),indent=2)+'\n')
    print(f"Verified {len(crt_callbacks)} directly registered CRT destructor entries",flush=True)

    # Recover every function, independently of which C++ files are compiled.
    # Replacement ownership is computed by the linker from PE unwind families
    # and decoded leaf control flow, never from a hand-maintained span list.
    replacements = []
    if reuse_analysis:
        seen = bytearray(1 if size not in (0,255) else 0 for size in lengths)
    # The old IDB also decoded a few isolated bytes inside LuaJIT's generated
    # VM as false instructions. Reclassify that native unwind span from its
    # proven dispatch roots and actual incoming instruction/pointer references.
    # Keeping those weak boundaries would reject valid VM fallthrough blocks.
    detailed = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    detailed.detail = True
    vm_rows = metadata_producers.lua_dispatch_offsets(pe,detailed,lengths)
    vm_begin = vm_rows[0]["base"]
    vm_end = next(e.struct.EndAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress == vm_begin)
    if not all(vm_begin <= item["target"] < vm_end for item in vm_rows):
        raise ValueError("LuaJIT dispatch leaves its native VM unwind span")
    vm_first,vm_last = vm_begin-start,vm_end-start
    recovered -= sum(size not in (0,255) and not known_heads[vm_first+i]
                     for i,size in enumerate(lengths[vm_first:vm_last]))
    lengths[vm_first:vm_last] = b"\0"*(vm_last-vm_first)
    seen[vm_first:vm_last] = b"\0"*(vm_last-vm_first)
    confidence[vm_first:vm_last] = b"\0"*(vm_last-vm_first)
    (output / "instruction-lengths.bin").write_bytes(lengths)
    vm_roots = {vm_begin} | {item["target"] for item in vm_rows}
    for match in re.finditer(rb"[\xe8\xe9]",raw):
        offset = match.start()
        if lengths[offset] != 5 or offset+5 > len(raw): continue
        target = start+offset+5+struct.unpack_from("<i",raw,offset+1)[0]
        if vm_begin <= target < vm_end: vm_roots.add(target)
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]",raw):
        offset = match.start()
        if lengths[offset] != 7 or offset+7 > len(raw): continue
        target = start+offset+7+struct.unpack_from("<i",raw,offset+3)[0]
        if vm_begin <= target < vm_end: vm_roots.add(target)
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type == 10:
                target = struct.unpack("<Q",pe.get_data(entry.rva,8))[0]-pe.OPTIONAL_HEADER.ImageBase
                if vm_begin <= target < vm_end: vm_roots.add(target)
    for target in vm_roots: seed(target)
    drain()
    (output / "instruction-lengths.bin").write_bytes(lengths)
    print(f"Recovered LuaJIT VM from {len(vm_roots)} proven dispatch/call/pointer roots",flush=True)
    # Discover cases omitted from IDA's switch counts before emitting source.
    # Existing decoded heads terminate these walks; only new blocks need work.
    if reuse_analysis:
        seen = bytearray(1 if size not in (0,255) else 0 for size in lengths)
    recovery_states = set()
    while True:
        state = hashlib.sha256(lengths+confidence).digest()
        if state in recovery_states:
            raise ValueError('Native switch recovery made no progress or cycled')
        recovery_states.add(state)
        (output/'instruction-confidence.bin').write_bytes(confidence)
        analysis = metadata.recover(pe, output)
        for selector in analysis.get("byte_selectors", []):
            first = selector["at"]-start
            last = first+selector["size"]
            if first < 0 or last > len(lengths):
                continue  # selectors in initialized data are already data
            while first > 0 and lengths[first] == 255: first -= 1
            for at in range(first,last):
                if lengths[at] not in (0,255): last = max(last,at+lengths[at])
            lengths[first:last] = b"\0"*(last-first)
            seen[first:last] = b"\0"*(last-first)
            confidence[first:last] = b"\0"*(last-first)
        for item in analysis["relative_tables"]:
            if start <= item["at"] < end:
                table_offset = item["at"]-start
                width = item.get("width",4)
                tables[table_offset:table_offset+width] = b"\x01"*width
                # Old IDA/weak roots can have decoded table bytes as isolated
                # instructions. Retire the entire overlapping false instruction
                # before emitting assembly, including any prefix/operand tail.
                first = table_offset
                while first > 0 and lengths[first] == 255:
                    first -= 1
                last = table_offset+width
                for at in range(first,last):
                    if lengths[at] not in (0,255):
                        last = max(last,at+lengths[at])
                lengths[first:last] = b"\0"*(last-first)
                seen[first:last] = b"\0"*(last-first)
                confidence[first:last] = b"\0"*(last-first)
        (output / "instruction-lengths.bin").write_bytes(lengths)
        if not analysis["unrecovered_switch_targets"]:
            break
        for target in analysis["unrecovered_switch_targets"]:
            seed(target, strong=True)
        drain()
        (output / "instruction-lengths.bin").write_bytes(lengths)
    replacement_at = {item["begin"]: item for item in replacements}
    base = pe.OPTIONAL_HEADER.ImageBase
    fixups = {}
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type == 10:
                if unproven.overlaps(entry.rva, entry.rva + 8):
                    raise ValueError('Terminal unowned bytes contain a proven PE relocation; review their encoding')
                target = struct.unpack("<Q", pe.get_data(entry.rva, 8))[0]-base
                if 0 <= target < pe.OPTIONAL_HEADER.SizeOfImage:
                    fixups[entry.rva] = (target, 8)
    exports = pe.DIRECTORY_ENTRY_EXPORT.struct
    for index in range(exports.NumberOfFunctions):
        at = exports.AddressOfFunctions+index*4
        target = struct.unpack("<I", pe.get_data(at, 4))[0]
        if target:
            fixups[at] = (target, 4)
    # Recognized inline RVA jump tables are data references, not instructions.
    position = 0
    while position < len(tables):
        if tables[position]:
            target = struct.unpack_from("<I", raw, position)[0]
            fixups[start+position] = (target, 4)
            position += 4
        else:
            position += 1
    fixups_file = output / "data-fixups.bin"
    with fixups_file.open("wb") as data:
        for at, (target, width) in sorted(fixups.items()):
            data.write(struct.pack("<III", at, target, width))

    native_symbols = {}
    database = executable.with_suffix(".exe.sqlite")
    import source_catalog
    with sqlite3.connect(source_catalog.readonly_uri(database), uri=True) as db:
        db.execute('BEGIN')
        quarantine = source_catalog.function_quarantine(db, base)
        retired_rvas = {row['rva'] for row in quarantine.values()}
        rows = [(name, source_catalog.parse_integer(address, 'function address'))
                for identity, name, address in db.execute("SELECT id,name,address FROM functions")
                if identity not in quarantine]
        rows.extend((name, base+source_catalog.parse_integer(rva, 'symbol RVA'))
                    for rva, name, kind in db.execute("SELECT rva,name,kind FROM replay_ida_symbols")
                    if kind != 'function' or source_catalog.parse_integer(rva, 'symbol RVA') not in retired_rvas)
    ambiguous = set()
    for name, address in rows:
        rva = address-base
        if not 0 <= rva < pe.OPTIONAL_HEADER.SizeOfImage:
            continue
        if name in native_symbols and native_symbols[name] != rva:
            ambiguous.add(name)
        else:
            native_symbols[name] = rva
    for name in ambiguous:
        native_symbols.pop(name, None)
    native_symbols.update(Dvar_GenerateChecksum=0x13E66C0, Dvar_RegisterVariant=0x13E7D40,
                          Dvar_RegisterInt=0x13E7A00, ui_serverFrameDuration=0xD386880,
                          Sys_CheckCrashOrRerun=0x13FF110, Replay_CrashMarkerPath=0xE5C2E80,
                          Sys_InitCrashMarker=0x13FFE00,
                          Sys_ExitOnFileWriteError=0x1400850,
                          Sys_CheckRecommendedSettings=0x13FC940, Sys_OfferOptimalSettings=0x13FCC90,
                          Sys_InitHardwareConfig=0x13FCAD0, Dvar_SetFloat=0x13E91E0,
                          Dvar_SetInt=0x13E97B0, Dvar_SetString=0x13E9BE0,
                          Replay_CpuGHzDvar=0xE5C02D0, Replay_MemoryMbDvar=0xE5C02D8,
                          Replay_GpuNameDvar=0xE5C02E0, Replay_SettingsRevisionDvar=0xE5C02F0,
                          Replay_HardwareCpuGHz=0xE5BF670, Replay_HardwareMemoryMb=0xE5BF680,
                          Replay_HardwareGpuName=0xE5BF684)
    # Read-only debug-state bindings verified against this Replay image's
    # bodies/callers, rather than transferring the reconstructed source ABI.
    native_symbols.update(
        CL_ScreenMP_DrawOverlay=0x15E1340, CL_DrawText=0x15AAAA0,
        ScrPlace_EndFrame=0x15DB560, activeScreenPlacementMode=0xEF2DE9C,
        Sys_IsMainThread=0x12CF280, Com_Printf=0x12B0820,
        Com_FrontEndScene_IsActive=0x10C6BD0,
        CL_AllLocalClientsInactive=0x15CEA90, CL_IsLocalClientActive=0x15CEB10,
        CL_Mgr_GetControllerFromClient=0xD66C50,
        GamerProfile_IsProfileLoggedIn=0x15D7980,
        GamerProfile_GetMountButton=0x15D71F0, GamerProfile_GetMountButtonKBM=0x15D7210,
        GamerProfile_GetMountPullAwayEnabled=0x15D7250,
        GamerProfile_GetMountPullAwayEnabledKBM=0x15D7270,
        GamerProfile_GetToggleADSEnabledGamepad=0x15D75D0,
        GamerProfile_GetToggleADSEnabledKeyboard=0x15D75F0,
        GamerProfile_GetToggleScoreboardMapEnabled=0x15D7610,
        GamerProfile_GetVoiceMuteStrategy=0x15D76B0,
        Live_OnlineData_GetState=0x1039E20, Live_PatchFence_GetState=0x1039AE0,
        Live_PatchFence_GetErrorCode=0x1039AB0,
        Sys_EnterCriticalSection=0x13F54F0, Sys_LeaveCriticalSection=0x13F55F0,
        scrPlaceFull=0xEF2DEA0, cls_uiFont=0xEEB0C68,
        # CL_InitRenderer (0x15c35c0) registers Fira Mono Bold at 14 pixels;
        # 0x1932da0 is the three-argument native R_TextWidth body.
        cls_smallDevFont=0xEEB0C60, R_TextWidth=0x1932DA0,
        s_comDObjBuffer=0xD45EC50, s_comDObjCount=0xD45EC58,
        s_comDObjFreeCount=0xD460048, s_dvarCount=0xE3712D0,
        s_fenceObjects=0xB4AB990, s_fenceNames=0x411C8F0,
        Sys_IsDatabaseReady=0x12CF240, Stream_LevelInit_IsDone=0x13ACCB0,
        s_fastfileLoadModules=0xC4EA8E0, s_worldRequestQueue=0x24ED720,
        s_clientRequestQueue=0x24ED738, streamFrontendGlob=0xE2D0DA0)
    import_names = {}
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        for item in dll.imports:
            if item.name:
                name = item.name.decode()
                native_symbols["__imp_"+name] = item.address-base
                import_names[item.address-base] = name
    # Some Windows SDK prototypes do not use dllimport. Their direct calls
    # resolve to recovered import thunks, while __imp_* resolves to IAT data.
    position = 0
    while (position := raw.find(b"\xff\x25", position)) >= 0:
        if lengths[position] == 6:
            target = start+position+6+struct.unpack_from("<i", raw, position+2)[0]
            if target in import_names:
                name = import_names[target]
                native_symbols[name] = start+position
        position += 1
    symbol_file = output / "native-symbols.json"
    symbol_file.write_text(json.dumps(native_symbols, sort_keys=True, indent=2)+"\n")
    # MASM preserves Microsoft's directional register encodings at the proxy's
    # byte-sensitive bindings. These are instruction sources, not copied code.
    signatures = json.loads((output / "proxy-signatures.json").read_text())
    sensitive = {}
    detailed = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detailed.detail = True
    for signature in signatures:
        data = bytes.fromhex(signature["bytes"])
        if pe.get_data(signature["rva"], len(data)) != data:
            raise ValueError(f"Proxy signature is stale for this Replay image: {signature['name']}")
        for instruction in detailed.disasm(data, signature["rva"]):
            if len(instruction.operands) == 2 and all(o.type == capstone.x86.X86_OP_REG for o in instruction.operands):
                sensitive[instruction.address] = instruction
    native_source = output / "native-encodings.asm"
    with native_source.open("w", encoding="ascii", newline="\n") as source:
        source.write("; Recovered instructions at byte-sensitive native bindings.\n.code\n")
        for rva, instruction in sorted(sensitive.items()):
            source.write(f"PUBLIC native_{rva:08x}, native_end_{rva:08x}\nnative_{rva:08x} LABEL BYTE\n")
            if instruction.bytes[0] == 0x40 and not re.search(r"\b(spl|bpl|sil|dil)\b", instruction.op_str):
                source.write("db 040h ; redundant REX prefix present in the original instruction\n")
            operands = re.sub(r"0x([0-9a-f]+)", lambda m: "0"+m[1]+"h", instruction.op_str)
            source.write(f"{instruction.mnemonic} {operands}\nnative_end_{rva:08x} LABEL BYTE\n")
        source.write("END\n")

    # Export initialized data and describe the PE numerically; no original
    # executable or original .text image is an input to the subsequent build.
    sections = []
    for index, section in enumerate(pe.sections):
        name = section.Name.rstrip(b"\0").decode()
        item = dict(name=name, rva=section.VirtualAddress, virtual_size=section.Misc_VirtualSize,
                    raw_size=section.SizeOfRawData, flags=section.Characteristics)
        if name != ".text":
            filename = f"data-{index}-{name.lstrip('.')}.bin"
            (output / filename).write_bytes(section.get_data())
            item["file"] = filename
            item["sha256"] = hashlib.sha256(section.get_data()).hexdigest()
        sections.append(item)
    optional = {key: value for key, value in pe.OPTIONAL_HEADER.__dict__.items()
                if isinstance(value, int) and not key.startswith("_")}
    manifest = dict(backend_version=2, input_sha256=SHA256, input_md5=hashlib.md5(image_bytes).hexdigest(),
                    image_base=pe.OPTIONAL_HEADER.ImageBase,
                    timestamp=pe.FILE_HEADER.TimeDateStamp,
                    optional=optional, characteristics=pe.FILE_HEADER.Characteristics,
                    directories=[dict(rva=d.VirtualAddress, size=d.Size) for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY],
                    sections=sections, symbols_file=symbol_file.name,
                    symbols_sha256=hashlib.sha256(symbol_file.read_bytes()).hexdigest(),
                    fixups_file=fixups_file.name, fixups_sha256=hashlib.sha256(fixups_file.read_bytes()).hexdigest(),
                    replacements=replacements, short_references=[], chunks=[])
    if (output / native_unproven.FILE).exists():
        manifest['terminal_unowned_evidence'] = dict(file=native_unproven.FILE,
            sha256=hashlib.sha256((output / native_unproven.FILE).read_bytes()).hexdigest(),
            entries=unproven.entries, spans=len(unproven.rows))
    manifest["native_assembly"] = dict(file=native_source.name,
        instructions=[dict(rva=rva, size=i.size) for rva,i in sorted(sensitive.items())])
    manifest["proxy_signatures"] = signatures
    source_dir = output / "asm"
    source_dir.mkdir(exist_ok=True)
    counts = collections.Counter()
    rva_operands = native_operand_references.group(analysis['image_relative_operands'])
    offset = 0
    chunk_number = 0
    while offset < len(raw):
        origin = start+offset
        limit = min(offset+512*1024, len(raw))
        filename = f"replay_{origin:08x}.s"
        with (source_dir / filename).open("w", encoding="ascii", newline="\n") as source:
            source.write(f".intel_syntax noprefix\n.text\norigin:\n.set image, origin - 0x{origin:x}\n")
            while offset < limit:
                rva = start+offset
                if rva in sensitive:
                    size = sensitive[rva].size
                    source.write(f"# Compiled by MASM: {sensitive[rva].mnemonic} {sensitive[rva].op_str}\n.org 0x{rva-origin:x}, 0x90\n.fill {size}, 1, 0xcc\n")
                    offset += size
                    counts["native_assembler_instructions"] += 1
                    counts["native_assembler_bytes"] += size
                    continue
                if rva in replacement_at:
                    item = replacement_at[rva]
                    source.write(f"# Reserved for compiled {item['symbol']}\n.org 0x{rva-origin:x}, 0x90\n.fill {item['end']-rva}, 1, 0xcc\n")
                    counts["cpp_replacement_bytes"] += item["end"]-rva
                    offset += item["end"]-rva
                    continue
                size = lengths[offset]
                if size == 255:
                    raise ValueError(f"Unexpected instruction tail at {rva:x}")
                if size:
                    instructions = list(decoder.disasm_lite(raw[offset:offset+size], rva))
                    if len(instructions) != 1 or instructions[0][1] != size:
                        raise ValueError(f"Invalid instruction boundary at {rva:x}")
                    _, _, mnemonic, operands = instructions[0]
                    if mnemonic == "movabs":
                        mnemonic = "mov"
                    if mnemonic.startswith("bnd "):
                        mnemonic = "repne " + mnemonic[4:]
                    if mnemonic in ("comisd", "ucomisd"):
                        # Capstone 5 misreports the scalar memory width here.
                        operands = operands.replace("xmmword ptr", "qword ptr")
                    if mnemonic == "int1":
                        mnemonic = "icebp"
                    operation = mnemonic.split()[-1]
                    if (operation.startswith("j") or operation.startswith("loop") or operation == "call") and re.fullmatch(r"0x[0-9a-f]+", operands):
                        target = int(operands, 16)
                        if size < 5:
                            manifest["short_references"].append([rva, target])
                            operands = f"image + {operands}"
                        else:
                            operands = f"replay_rva_{target:08x}"
                            counts["symbolic_code_references"] += 1
                    if "rip" in operands:
                        match = re.search(r"rip(?:\s*([+-])\s*(0x[0-9a-f]+))?", operands)
                        displacement = int(match[2], 16) * (-1 if match[1] == "-" else 1) if match[2] else 0
                        target = rva+size+displacement
                        operands = operands[:match.start()]+f"rip + replay_rva_{target:08x}"+operands[match.end():]
                        counts["symbolic_data_references"] += 1
                    if rva in rva_operands:
                        references = rva_operands[rva]
                        operands = native_operand_references.symbolize(operands, references, rva)
                        counts['symbolic_image_relative_operands'] += len(references)
                    source.write(f".org 0x{rva-origin:x}, 0x90\n")
                    if operation in ("nop", "int3"):
                        source.write(f".fill {size}, 1, {0x90 if operation == 'nop' else 0xcc}\n")
                    else:
                        prefix = "{rex} " if raw[offset] == 0x40 else ""
                        if operation.startswith("j") and operation != "jrcxz" and size >= 5 and operands.startswith("replay_rva_"):
                            prefix += "{disp32} "
                        if operation in ("jmp", "call") and operands.startswith("ptr ["):
                            match = re.fullmatch(r"ptr \[(\w+)(?: ([+-]) (0x[0-9a-f]+))?\]", operands)
                            if not match:
                                raise ValueError(f"Unsupported far branch syntax at {rva:x}")
                            displacement = ("-" if match[2] == "-" else "")+(match[3] or "0")
                            source.write(f".att_syntax prefix\n{'ljmp' if operation == 'jmp' else 'lcall'} *{displacement}(%{match[1]})\n.intel_syntax noprefix\n")
                        elif operation in ("push", "pop") and operands in ("fs", "gs"):
                            # LLVM's Intel spelling defaults to a 16-bit stack
                            # operation; Replay's unprefixed form uses 64 bits.
                            source.write(f".att_syntax prefix\n{operation}q %{operands}\n.intel_syntax noprefix\n")
                        else:
                            source.write(f"{prefix}{mnemonic} {operands}\n")
                    counts["instructions"] += 1
                    counts["instruction_bytes"] += size
                    offset += size
                else:
                    stop = offset+1
                    while stop < limit and not lengths[stop] and start+stop not in replacement_at:
                        stop += 1
                    source.write(f"# Non-instruction data / padding, RVA 0x{rva:x}\n.org 0x{rva-origin:x}, 0x90\n")
                    for i in range(offset, stop, 32):
                        source.write(".byte "+", ".join(f"0x{b:02x}" for b in raw[i:min(i+32, stop)])+"\n")
                    counts["noninstruction_bytes"] += stop-offset
                    offset = stop
            source.write(f".org 0x{start+offset-origin:x}, 0x90\n")
        manifest["chunks"].append(dict(file=filename, rva=origin, size=start+offset-origin))
        chunk_number += 1
        print(f"Assembly chunk {chunk_number:02d}: 0x{origin:08x}, {start+offset-origin:,} bytes", flush=True)
    # Count final boundaries, including retirement of old false IDA roots.
    recovered = sum(size not in (0,255) and not known_heads[i] for i,size in enumerate(lengths))
    manifest["recovery"] = dict(counts, additional_instructions=recovered)
    (output/'instruction-confidence.bin').write_bytes(confidence)
    (output/'boundary-repairs.json').write_text(json.dumps(boundary_repairs,indent=2)+'\n')
    manifest["metadata"] = metadata.recover(pe, output)
    if preparation_inputs(output) != initial_inputs:
        raise ValueError('Recovery inputs changed during recovery; rerun compilation')
    manifest['preparation_inputs'] = initial_inputs
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    import source_catalog
    source_catalog.export(output, base, SHA256, native_symbols)
    import proxy_patterns
    proxy_patterns.export_native(executable)
    print(json.dumps(manifest["recovery"], indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    default_game_root = Path(os.environ.get("REPLAY_GAME_ROOT", r"E:\IW8\Builds\1.20-replay")).expanduser()
    default_exe = Path(os.environ.get("REPLAY_EXE", default_game_root / "game_dx12_ship_replay.exe")).expanduser()
    parser.add_argument("--exe", type=Path, default=default_exe)
    parser.add_argument("--reuse-analysis", action="store_true")
    arguments = parser.parse_args()
    recover(arguments.exe, arguments.reuse_analysis)
