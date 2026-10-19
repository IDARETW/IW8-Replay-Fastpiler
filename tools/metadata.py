"""Recover typed RVA references which PE base relocations do not describe.

This runs during recovery, against the pinned input. Linking reads only the
exported records. Layouts follow PE/COFF, the x64 unwind ABI, and MSVC's installed
ehdata.h/rttidata.h. Numeric words are never rebased just because they resemble
an address.
"""

import collections
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import struct

import capstone
import pefile
import image_references
import native_operand_references
import metadata_producers
import native_unproven

ROOT = Path(__file__).resolve().parents[1]


def recover(pe, output):
    rows = {}
    counts = collections.Counter()
    ownership_stack = []
    unwind_fields = {}
    funcinfo_fields = {}
    unwind_ownership = {}
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    base = pe.OPTIONAL_HEADER.ImageBase
    text_section = next(section for section in pe.sections if section.Name.rstrip(b'\0') == b'.text')
    unproven = native_unproven.load(output, hashlib.sha256(pe.__data__).hexdigest(),
        hashlib.md5(pe.__data__).hexdigest(), text_section.VirtualAddress,
        text_section.VirtualAddress + text_section.SizeOfRawData, pe.get_data)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    handler_kinds, handler_proof = metadata_producers.exception_handlers(
        pe, metadata_producers.function_names(pe, output), decoder)

    def values(at, count=1):
        data = pe.get_data(at, count*4)
        if len(data) != count*4:
            raise ValueError(f"Truncated metadata at {at:x}")
        return struct.unpack(f"<{count}I", data)

    def add(at, category, width=4):
        if unproven.overlaps(at, at + width):
            raise ValueError(f'Native metadata field overlaps terminal unowned bytes at {at:#x}')
        data = pe.get_data(at, width)
        target = int.from_bytes(data, "little")
        if target in (0, 1, 0xffffffff):
            return target
        if len(data) != width or not 0 < target < image_size:
            raise ValueError(f"Invalid {category} RVA at {at:x}: {target:x}")
        if at in rows and rows[at] != (target, width):
            raise ValueError("Conflicting metadata reference")
        rows[at] = (target, width)
        for fields in ownership_stack:
            fields.add(at)
        counts[category] += 1
        return target

    exports = pe.DIRECTORY_ENTRY_EXPORT.struct
    for offset in (12, 28, 32, 36):
        add(pe.get_rva_from_offset(exports.get_file_offset())+offset, "exports")
    for i in range(exports.NumberOfNames):
        add(exports.AddressOfNames+4*i, "export_names")
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        at = pe.get_rva_from_offset(dll.struct.get_file_offset())
        for offset in (0, 12, 16):
            add(at+offset, "import_descriptor")
        for table in {dll.struct.OriginalFirstThunk, dll.struct.FirstThunk}-{0}:
            for i, _ in enumerate(dll.imports):
                value = int.from_bytes(pe.get_data(table+8*i, 8), "little")
                if value and not value & (1 << 63):
                    add(table+8*i, "import_names", 8)
    for dll in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        if dll.struct.grAttrs != 1:
            raise ValueError("Unsupported VA-based delay imports")
        at = pe.get_rva_from_offset(dll.struct.get_file_offset())
        for offset in (4, 8, 12, 16, 20, 24):
            add(at+offset, "delay_descriptor")
        for table in {dll.struct.pINT, dll.struct.pIAT}-{0}:
            for i, _ in enumerate(dll.imports):
                value = int.from_bytes(pe.get_data(table+8*i, 8), "little")
                if value and not value & (1 << 63) and value < image_size:
                    add(table+8*i, "delay_names", 8)

    def resource(directory):
        for item in directory.entries:
            if hasattr(item, "directory"):
                resource(item.directory)
            else:
                add(pe.get_rva_from_offset(item.data.struct.get_file_offset()), "resource_data")
    resource(pe.DIRECTORY_ENTRY_RESOURCE)

    seen_unwind = set()
    seen_funcinfo = set()

    def handler_array(at, count):
        if count > 10000:
            raise ValueError("Invalid C++ handler count")
        for index in range(count):
            add(at+index*20+4, "catch_type")
            add(at+index*20+12, "catch_handler")

    def funcinfo(at):
        if at in seen_funcinfo:
            for fields in ownership_stack:
                fields.update(funcinfo_fields[at])
            return
        seen_funcinfo.add(at)
        funcinfo_fields[at] = set()
        ownership_stack.append(funcinfo_fields[at])
        fields = values(at, 10)
        if fields[0] & 0x1fffffff not in (0x19930520, 0x19930521, 0x19930522):
            raise ValueError(f"Unsupported C++ exception format at {at:x}")
        states, unwind_map, tries, try_map, ips, ip_map = fields[1:7]
        if max(states, tries, ips) > 100000:
            raise ValueError("Invalid C++ exception map count")
        for offset in (8, 16, 24, 32):
            add(at+offset, "funcinfo")
        for i in range(states):
            add(unwind_map+8*i+4, "unwind_funclet")
        for i in range(tries):
            entry = try_map+20*i
            count, handlers = values(entry+12, 2)
            add(entry+16, "try_map")
            handler_array(handlers, count)
        for i in range(ips):
            add(ip_map+8*i, "ip_state_map")
        if fields[8]:
            count, handlers = values(fields[8], 2)
            add(fields[8]+4, "exception_specification")
            handler_array(handlers, count)
        counts["funcinfo_records"] += 1
        ownership_stack.pop()

    def unwind(at):
        if at in seen_unwind:
            for fields in ownership_stack:
                fields.update(unwind_fields[at])
            return
        seen_unwind.add(at)
        unwind_fields[at] = set()
        ownership_stack.append(unwind_fields[at])
        header = pe.get_data(at, 4)
        if header[0] & 7 not in (1, 2):
            raise ValueError(f"Unsupported native unwind version at {at:x}")
        flags = header[0] >> 3
        extra = at+4+((header[2]+1) & ~1)*2
        if flags & 4:
            for offset in (0, 4, 8):
                add(extra+offset, "chained_unwind")
            unwind(values(extra+8)[0])
        elif flags & 3:
            handler = add(extra, "exception_handler")
            if handler_kinds.get(handler) == 'seh':
                count = values(extra+4)[0]
                if count > 100000:
                    raise ValueError("Invalid SEH scope count")
                for i in range(count):
                    for offset in (0, 4, 8, 12):
                        add(extra+8+16*i+offset, "seh_scope")
            elif handler_kinds.get(handler) == 'cpp':
                info = add(extra+4, "cpp_exception_info")
                funcinfo(info)
            elif handler_kinds.get(handler) != 'non-rva':
                raise ValueError(f"Unrecovered exception handler {handler:x}")
            # __GSHandlerCheck stores stack offsets. LuaJIT's sole custom
            # handler stores a compact non-RVA constant, not an address table.
        ownership_stack.pop()
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        unwind(entry.struct.UnwindData)
        unwind_ownership[str(entry.struct.BeginAddress)] = sorted(unwind_fields[entry.struct.UnwindData])

    # RTTI roots have an exact self RVA and a validated type descriptor. This
    # identifies complete-object locators, then follows their typed graph.
    seen_chd = set()
    def type_descriptor(at):
        return 0 < at < image_size and pe.get_data(at+16, 2) == b".?"

    def hierarchy(at):
        if at in seen_chd:
            return
        seen_chd.add(at)
        signature, attributes, count, array = values(at, 4)
        if signature or attributes > 7 or not 0 < count < 10000:
            raise ValueError(f"Invalid RTTI hierarchy {at:x}")
        add(at+12, "rtti_hierarchy")
        for i in range(count):
            descriptor = add(array+4*i, "rtti_base_array")
            fields = values(descriptor, 7)
            if not type_descriptor(fields[0]):
                raise ValueError("Invalid RTTI base type")
            add(descriptor, "rtti_type")
            if fields[5] & 0x40:
                add(descriptor+24, "rtti_base_hierarchy")
                hierarchy(fields[6])

    for section in pe.sections:
        if section.Name.rstrip(b"\0") not in (b".rdata", b"_RDATA"):
            continue
        raw = section.get_data()
        for offset in range(0, len(raw)-24, 4):
            signature, _, _, type_rva, chd, self_rva = struct.unpack_from("<6I", raw, offset)
            at = section.VirtualAddress+offset
            if signature == 1 and self_rva == at and type_descriptor(type_rva):
                for field in (12, 16, 20):
                    add(at+field, "rtti_locator")
                hierarchy(chd)
                counts["rtti_locators"] += 1

    # ThrowInfo roots come from LEA rdx immediately before _CxxThrowException.
    # A validated catchable-type array supplies the rest of the typed graph.
    # IDA's explicit RVA offsets additionally cover annotations, small image
    # relative dispatch tables, and any nonstandard native metadata.
    ida_file = output / "ida-rva-fixups.bin"
    if ida_file.exists():
        for at, target, width in struct.iter_unpack("<III", ida_file.read_bytes()):
            if unproven.overlaps(at, at + width):
                counts['rejected_unproven_ida_annotations'] += 1
                continue
            if at < pe.sections[0].VirtualAddress:
                continue  # the linker emits fresh PE headers and directories
            actual = int.from_bytes(pe.get_data(at, width), "little")
            if actual != target:
                raise ValueError(f"IDA RVA provenance mismatch at {at:x}")
            if at in rows and rows[at] != (target, width):
                raise ValueError("Conflicting IDA RVA reference")
            rows[at] = (target, width)
            counts["ida_rvas"] += 1
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    immediate_file = output / "ida-immediate-references.json"
    relative_operands = []
    lengths = (output / "instruction-lengths.bin").read_bytes()
    confidence_path = output/'instruction-confidence.bin'
    confidence = confidence_path.read_bytes() if confidence_path.exists() else bytes([2])*len(lengths)
    if len(confidence) != len(lengths):
        raise ValueError('Instruction confidence map has the wrong extent')
    text_start = pe.sections[0].VirtualAddress
    if immediate_file.exists():
        for item in json.loads(immediate_file.read_text()):
            if unproven.contains(item['rva']):
                counts['rejected_unproven_ida_annotations'] += 1
                continue
            instruction = next(decoder.disasm(pe.get_data(item["rva"], 15), item["rva"]))
            if lengths[item["rva"]-text_start] != instruction.size:
                counts["rejected_ida_code_annotations"] += 1
                continue
            displacement = item.get("kind") == "displacement"
            size = instruction.disp_size if displacement else instruction.imm_size
            offset = instruction.disp_offset if displacement else instruction.imm_offset
            value = int.from_bytes(instruction.bytes[offset:offset+size],"little")
            if displacement and offset and offset+4 <= instruction.size and int.from_bytes(instruction.bytes[offset:offset+4],"little") == item["target"]:
                # Capstone 5 reports disp16 for some operand-size-prefixed
                # instructions, although their AMD64 address displacement is 32 bits.
                size, value = 4, item["target"]
            if size != 4 or value != item["target"]:
                if displacement and any(o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP for o in instruction.operands):
                    continue  # already emitted as a symbolic RIP-relative COFF operand
                raise ValueError(f"Unsupported image-relative operand at {item['rva']:x}: {instruction.mnemonic} {instruction.op_str}")
            rows[item["rva"]+offset] = (item["target"], 4)
            counts["ida_immediates"] += 1
            candidates = [index for index,operand in enumerate(instruction.operands)
                          if (displacement and operand.type == capstone.x86.X86_OP_MEM and operand.mem.disp == item["target"])
                          or (not displacement and operand.type == capstone.x86.X86_OP_IMM and operand.imm == item["target"])]
            if len(candidates) != 1:
                raise ValueError(f"Ambiguous annotated image-relative operand at {item['rva']:x}")
            # IDA and Capstone assign different operand indexes to some
            # indirect control transfers. Source emission uses Capstone order.
            relative_operands.append(dict(item,operand=candidates[0]))
    proven, proof_counts = image_references.recover(pe.sections[0].get_data(), text_start, lengths, image_size)
    for item in native_operand_references.merge(relative_operands, proven):
        instruction = next(decoder.disasm(pe.get_data(item["rva"], 15), item["rva"]))
        rows[item["rva"]+instruction.disp_offset] = (item["target"], 4)
        relative_operands.append(item)
        counts["additional_image_base_operands"] += 1
    counts.update(proof_counts)
    # Instructions carry these operands as symbolic COFF ADDR32NB references.
    # The assembler chooses the actual field offset (e.g. when it omits an
    # ignored REX prefix), so original instruction byte offsets must not also
    # be treated as data fixup sites by the linker.
    for item in relative_operands:
        instruction = next(decoder.disasm(pe.get_data(item["rva"],15),item["rva"]))
        offset = instruction.disp_offset if item["kind"] == "displacement" else instruction.imm_offset
        rows.pop(item["rva"]+offset,None)
    filename = output / "metadata-fixups.bin"
    filename.write_bytes(b"".join(struct.pack("<III", at, target, width) for at,(target,width) in sorted(rows.items())))
    switch_file = output / "ida-switch-references.json"
    relative_tables = []
    for item in json.loads(switch_file.read_text()) if switch_file.exists() else []:
        if unproven.overlaps(item['at'], item['at'] + item.get('width', 4)):
            counts['rejected_unproven_ida_annotations'] += 1
            continue
        relative_tables.append(item)
    lua_offsets = metadata_producers.lua_dispatch_offsets(pe, decoder, lengths)
    relative_tables.extend(lua_offsets)
    # The matching IDB undercounts a few switch tables (including memcpy's
    # final 16-byte case). Prove these from indexed RVA loads followed by an
    # indirect jump, and extend only through decoded targets in the same
    # native unwind family. Adjacent byte selector arrays belong to neither.
    entries = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    begins = [e.BeginAddress for e in entries]
    roots = {}
    def root(entry):
        at, begin = entry.UnwindData, entry.BeginAddress
        visited = set()
        while at not in visited:
            visited.add(at)
            header = pe.get_data(at,4)
            if not header[0] >> 3 & 4: break
            extra = at+4+((header[2]+1)&~1)*2
            begin,_,at = values(extra,3)
        return begin
    for entry in entries: roots[entry.BeginAddress] = root(entry)
    def owner(at):
        index = bisect_right(begins,at)-1
        if index < 0 or at >= entries[index].EndAddress: return None
        return roots[entries[index].BeginAddress]
    def register_family(name):
        if name.startswith("e"): return "r"+name[1:]
        return name.removesuffix("d")
    table_sites = {i["at"] for i in relative_tables}
    operand_targets = {i["rva"]: i["target"] for i in relative_operands if i["kind"] == "displacement"}
    byte_selectors = {}
    unrecovered = set()
    for item in relative_tables:
        if item.get("hole"): continue
        target = item["target"]
        if not text_start <= target < text_start+len(lengths) or (lengths[target-text_start] == 255 and confidence[target-text_start] >= 2):
            raise ValueError(f"Relative dispatch targets an invalid instruction at {target:x}")
        if not lengths[target-text_start] or confidence[target-text_start] < 2: unrecovered.add(target)
    def bounded_cases(first):
        index_register = register_family(first.reg_name(first.operands[1].mem.index))
        preceding = []
        for at in range(max(text_start,first.address-64),first.address):
            size = lengths[at-text_start]
            if size in (0,255): continue
            instruction = next(decoder.disasm(pe.get_data(at,size),at),None)
            if instruction: preceding.append(instruction)
        for index,instruction in reversed(list(enumerate(preceding))):
            operands = instruction.operands
            if (instruction.mnemonic not in ("cmp","and") or len(operands)!=2 or
                operands[0].type != capstone.x86.X86_OP_REG or operands[1].type != capstone.x86.X86_OP_IMM or
                not 0 <= operands[1].imm < 65536): continue
            masked = instruction.mnemonic == "and"
            if masked and operands[1].imm & (operands[1].imm+1): continue
            following = preceding[index+1:]
            if not masked and (not following or following[0].mnemonic != "ja"): continue
            # A compiler may widen/copy the checked index before loading the
            # table (movsxd rax,edx in the stock Havok leaf dispatch). Prove its
            # uninterrupted fallthrough and retain only unmodified copies.
            bounded = {register_family(instruction.reg_name(operands[0].reg)): operands[1].imm+1}
            selectors = []
            end = instruction.address+instruction.size
            valid = True
            for step in following:
                if step.address != end: valid = False; break
                end = step.address+step.size
                if not masked and step is following[0]: continue
                if step.mnemonic == "call" or step.group(capstone.CS_GRP_JUMP): valid = False; break
                copy, limit = None, None
                if (step.mnemonic in ("mov","movsx","movsxd","movzx") and len(step.operands)==2 and
                    all(o.type == capstone.x86.X86_OP_REG for o in step.operands) and
                    step.operands[0].size >= 4 and step.operands[1].size <= 4 and
                    register_family(step.reg_name(step.operands[1].reg)) in bounded):
                    copy = register_family(step.reg_name(step.operands[0].reg))
                    limit = bounded[register_family(step.reg_name(step.operands[1].reg))]
                elif step.mnemonic == "cdqe" and "rax" in bounded:
                    copy = "rax"
                    limit = bounded["rax"]
                elif (step.mnemonic == "movzx" and len(step.operands)==2 and
                      step.operands[0].type == capstone.x86.X86_OP_REG and step.operands[0].size >= 4 and
                      step.operands[1].type == capstone.x86.X86_OP_MEM and step.operands[1].size == 1 and
                      step.operands[1].mem.index and step.operands[1].mem.scale == 1 and step.address in operand_targets):
                    checked = register_family(step.reg_name(step.operands[1].mem.index))
                    if checked in bounded:
                        selector = operand_targets[step.address]
                        size = bounded[checked]
                        data = pe.get_data(selector,size)
                        if len(data) != size: raise ValueError("Truncated bounded switch byte selector")
                        # A checked enum can first select a compact DWORD table.
                        # Even an all-zero selector proves a one-entry table.
                        copy = register_family(step.reg_name(step.operands[0].reg))
                        limit = max(data)+1
                        selectors.append((selector,size))
                for written in step.regs_access()[1]:
                    bounded.pop(register_family(step.reg_name(written)),None)
                if copy: bounded[copy] = limit
            if valid and end == first.address and index_register in bounded:
                for selector,size in selectors: byte_selectors[selector] = max(size,byte_selectors.get(selector,0))
                return dict(count=bounded[index_register],masked=masked)
        return None
    for item in relative_operands:
        if item["kind"] != "displacement": continue
        decoded = list(decoder.disasm(pe.get_data(item["rva"],48),item["rva"]))
        first = decoded[0]
        memories = [o for o in first.operands if o.type == capstone.x86.X86_OP_MEM]
        if (first.mnemonic not in ("mov","movsxd") or not memories or memories[0].size != 4 or
            memories[0].mem.scale != 4 or not memories[0].mem.index or first.operands[0].type != capstone.x86.X86_OP_REG):
            continue
        destination = register_family(first.reg_name(first.operands[0].reg))
        dispatch = any(i.mnemonic == "jmp" and len(i.operands)==1 and i.operands[0].type==capstone.x86.X86_OP_REG and register_family(i.reg_name(i.operands[0].reg))==destination for i in decoded[1:4])
        family = owner(item["rva"])
        bound_proof = bounded_cases(first)
        bound = bound_proof["count"] if bound_proof else None
        masked = bound_proof and bound_proof["masked"]
        if not dispatch or (family is None and bound is None): continue
        at = item["target"]
        # Sparse inline switches contain zero entries for invalid enum values.
        # Their containing native unwind range bounds the table even without
        # a local comparison (the index can come from a typed asset record).
        inline_count = None
        if text_start <= at < text_start+len(lengths) and family is not None and owner(at) == family:
            entry = entries[bisect_right(begins,at)-1]
            extent = entry.EndAddress-at
            if at > first.address and extent > 0 and not extent % 4:
                inline_count = extent//4
        for _ in range(bound if bound is not None else inline_count if inline_count is not None else 65536):
            raw = pe.get_data(at,4)
            if len(raw)!=4: break
            target = int.from_bytes(raw,"little")
            # Typed renderer enums use masked, biased tables: their nominal
            # base can lie in the preceding code, with only supported enum
            # entries in the physical DWORD array after the function. Keep
            # unsupported/code/padding entries unchanged; prove real targets
            # by the bounded mask and the dispatcher's native unwind family.
            if masked and (not text_start <= target < text_start+len(lengths) or
                           (family is not None and owner(target)!=family) or
                           (lengths[target-text_start] == 255 and confidence[target-text_start] >= 2)):
                at += 4
                continue
            if not target and (bound is not None or inline_count is not None):
                if at not in table_sites:
                    relative_tables.append(dict(at=at,target=0,base=0,subtract=False,shift=0,hole=True))
                    table_sites.add(at)
                    counts["sparse_switch_holes"] += 1
                at += 4
                continue
            if not text_start <= target < text_start+len(lengths) or (bound is None and owner(target)!=family):
                if bound is not None: raise ValueError(f"Bounded native switch has an invalid target at {at:x}")
                break
            if lengths[target-text_start] == 255 and confidence[target-text_start] >= 2:
                raise ValueError(f"Native switch enters an instruction interior at {target:x}")
            if not lengths[target-text_start] or confidence[target-text_start] < 2:
                unrecovered.add(target)
            if at not in table_sites:
                relative_tables.append(dict(at=at,target=target,base=0,subtract=False,shift=0))
                table_sites.add(at)
                counts["recovered_switch_elements"] += 1
                if masked: counts["masked_switch_elements"] += 1
                if family is None: counts["leaf_switch_elements"] += 1
            at += 4
    for item in relative_tables:
        distance = (item["base"]-item["target"]) if item["subtract"] else (item["target"]-item["base"])
        width = item.get("width",4)
        expected = (distance >> item["shift"]) & ((1 << (width*8))-1)
        if int.from_bytes(pe.get_data(item["at"],width),"little") != expected:
            raise ValueError("Switch table provenance mismatch")
    counts["switch_table_elements"] = len(relative_tables)
    counts["bounded_byte_selector_tables"] = len(byte_selectors)
    counts["lua_dispatch_word_offsets"] = len(lua_offsets)
    result = dict(file=filename.name, sha256=hashlib.sha256(filename.read_bytes()).hexdigest(), counts=dict(counts),
                  unwind_ownership=unwind_ownership,
                  image_relative_operands=relative_operands, relative_tables=relative_tables,
                  byte_selectors=[dict(at=at,size=size) for at,size in sorted(byte_selectors.items())],
                  exception_handler_provenance={str(at): proof for at, proof in handler_proof.items()},
                  unrecovered_switch_targets=sorted(unrecovered))
    (output / "metadata-report.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


if __name__ == "__main__":
    original = ROOT / "generated" / "manifest.json"
    manifest = json.loads(original.read_text())
    executable = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    if hashlib.sha256(executable.read_bytes()).hexdigest() != manifest["input_sha256"]:
        raise ValueError("Wrong Replay input")
    manifest["metadata"] = recover(pefile.PE(str(executable)), ROOT / "generated")
    original.write_text(json.dumps(manifest, indent=2)+"\n")
    print(json.dumps({key:value for key,value in manifest["metadata"].items() if key not in ("image_relative_operands","relative_tables","unrecovered_switch_targets")}, indent=2))
