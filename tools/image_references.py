"""Prove RVA operands from registers containing the native image base.

IDA's offset annotations are useful but incomplete. Follow a register only
after an exact RIP-relative LEA of RVA zero, and retain it across calls only
when the Windows x64 ABI preserves it. Track indexed image bases separately
so adding an array offset does not discard the relocation of its later RVA
displacement. Each recovered field has a decoded
instruction boundary and a control-flow/register provenance, not a numeric
address heuristic.
"""

import re
from collections import deque

import capstone
from capstone import x86


def family(name):
    if name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return "r"+name[1:]
    if name.startswith("r") and name.endswith(("d", "w", "b")):
        return name[:-1]
    return name


def recover(raw, text_rva, lengths, image_size):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    seeds = []
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", raw):
        offset = match.start()
        if lengths[offset] != 7 or offset+7 > len(raw):
            continue
        displacement = int.from_bytes(raw[offset+3:offset+7], "little", signed=True)
        if text_rva+offset+7+displacement == 0:
            seeds.append(text_rva+offset)
    # A temporary can precede the instruction that loads the image base.
    # Seed decoded LEAs as hypotheses, then retain only those whose value is
    # actually combined with a proven base. Spatial population initialization
    # uses lea r12,[r12+RVA]; lea rax,[rip+image]; add r12,rax.
    temporary_seeds = []
    for match in re.finditer(rb"[\x48-\x4f]\x8d", raw):
        offset = match.start()
        length = lengths[offset]
        if length in (0, 255):
            continue
        instruction = next(decoder.disasm(raw[offset:offset+length], text_rva+offset), None)
        if not instruction or instruction.size != length or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (destination.type == x86.X86_OP_REG and destination.size == 8 and
            source.type == x86.X86_OP_MEM and source.mem.base != x86.X86_REG_RIP and
            text_rva <= source.mem.disp < image_size):
            temporary_seeds.append(instruction.address)
    queue = deque((at, frozenset(), frozenset(), ()) for at in seeds+temporary_seeds)
    visited = set()
    records = {}
    dispatch_edges = set()
    nonvolatile = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15", "rsp"}
    while queue:
        at, bases, indexed_bases, temporary_rows = queue.popleft()
        key = (at, bases, indexed_bases, temporary_rows)
        if key in visited:
            continue
        visited.add(key)
        offset = at-text_rva
        if not 0 <= offset < len(raw) or lengths[offset] in (0, 255):
            continue
        instruction = next(decoder.disasm(raw[offset:offset+lengths[offset]], at), None)
        if not instruction or instruction.size != lengths[offset]:
            raise ValueError(f"Invalid image-base reference instruction at {at:x}")
        operands = instruction.operands
        next_bases = set(bases)
        next_indexed = set(indexed_bases)
        temporaries = dict(temporary_rows)
        next_temporaries = dict(temporaries)
        image_bases = bases | indexed_bases

        def prove_temporary(name):
            producer, operand, target = temporaries[name]
            records[producer] = dict(rva=producer,operand=operand,target=target,kind="displacement",
                                     provenance="RVA temporary combined with proven image base")

        # MSVC can keep RVA+index in a temporary until a later ADD or memory
        # operand supplies the image base. The string allocator uses this form
        # for bitmap reads and atomic updates. A numeric LEA alone proves
        # nothing; emit its relocation only after that actual consumer.
        if (instruction.mnemonic == "add" and len(operands) == 2 and
            all(o.type == x86.X86_OP_REG and o.size == 8 for o in operands)):
            first, second = (instruction.reg_name(o.reg) for o in operands)
            if first in temporaries and second in image_bases: prove_temporary(first)
            if second in temporaries and first in image_bases: prove_temporary(second)
        for operand_index, operand in enumerate(operands):
            if operand.type != x86.X86_OP_MEM:
                continue
            base_name = instruction.reg_name(operand.mem.base)
            index_name = instruction.reg_name(operand.mem.index)
            if base_name in image_bases and index_name in temporaries and operand.mem.scale == 1:
                prove_temporary(index_name)
            if index_name in image_bases and base_name in temporaries and operand.mem.scale == 1:
                prove_temporary(base_name)
            base_known = instruction.reg_name(operand.mem.base) in image_bases
            index_known = instruction.reg_name(operand.mem.index) in image_bases and operand.mem.scale == 1
            if base_known == index_known:
                continue
            target = operand.mem.disp
            field = instruction.disp_offset
            if not text_rva <= target < image_size:
                continue
            if not field or field+4 > instruction.size or int.from_bytes(instruction.bytes[field:field+4], "little") != target:
                raise ValueError(f"Unsupported proven RVA displacement at {at:x}")
            records[at] = dict(rva=at, operand=operand_index, target=target, kind="displacement",
                               provenance="image-base register flow")
            # A switch preserves the image-base register in its case blocks.
            # Follow only a DWORD table load, add of the proven image base,
            # and jump through that exact result register. Treating the jump
            # as a flow endpoint loses subsequent switches in the same case.
            if (instruction.mnemonic == "mov" and operand.size == 4 and
                    operand.mem.scale == 4 and operand.mem.index and
                    operands[0].type == x86.X86_OP_REG):
                following = list(decoder.disasm(raw[offset+instruction.size:offset+instruction.size+16], at+instruction.size))
                destination = family(instruction.reg_name(operands[0].reg))
                if len(following) >= 2:
                    add, jump = following[:2]
                    addition = (add.mnemonic == "add" and len(add.operands) == 2 and
                                all(o.type == x86.X86_OP_REG and o.size == 8 for o in add.operands) and
                                family(add.reg_name(add.operands[0].reg)) == destination and
                                add.reg_name(add.operands[1].reg) in bases)
                    transfer = (jump.mnemonic == "jmp" and len(jump.operands) == 1 and
                                jump.operands[0].type == x86.X86_OP_REG and
                                jump.reg_name(jump.operands[0].reg) == destination)
                    if addition and transfer and not indexed_bases.intersection(
                            {instruction.reg_name(operand.mem.base), instruction.reg_name(operand.mem.index)}):
                        table_offset = target-text_rva
                        for index in range(4096):
                            field_at = table_offset+index*4
                            if not 0 <= field_at <= len(raw)-4: break
                            case = int.from_bytes(raw[field_at:field_at+4], "little")
                            case_offset = case-text_rva
                            if not 0 <= case_offset < len(raw) or lengths[case_offset] in (0,255): break
                            dispatch_edges.add((jump.address,case))
                            case_temporaries = tuple(sorted((name,value) for name,value in temporaries.items() if name != destination))
                            queue.append((case,frozenset(bases-{destination}),frozenset(indexed_bases-{destination}),case_temporaries))
        for register in instruction.regs_access()[1]:
            next_bases.discard(family(instruction.reg_name(register)))
            next_indexed.discard(family(instruction.reg_name(register)))
            next_temporaries.pop(family(instruction.reg_name(register)),None)
        if instruction.mnemonic == "lea" and len(operands) == 2 and operands[1].type == x86.X86_OP_MEM:
            memory = operands[1].mem
            exact_base = memory.base == x86.X86_REG_RIP and at+instruction.size+memory.disp == 0
            base_name, index_name = instruction.reg_name(memory.base), instruction.reg_name(memory.index)
            copied_base = not memory.disp and (
                (base_name in bases and not memory.index) or
                (not memory.base and memory.scale == 1 and index_name in bases))
            # The base must occur exactly once with coefficient one. Preserve
            # zero-displacement indexed LEAs such as the native dvar insertion's
            # lea r8,[r8+rax*2]; its following table displacement is still an RVA.
            indexed_base = not memory.disp and (
                (base_name in image_bases and index_name not in image_bases) or
                (base_name not in image_bases and memory.scale == 1 and index_name in image_bases))
            if operands[0].size == 8:
                destination = instruction.reg_name(operands[0].reg)
                if exact_base or copied_base:
                    next_bases.add(destination)
                elif indexed_base:
                    next_indexed.add(destination)
                if (memory.base != x86.X86_REG_RIP and base_name not in image_bases and
                    index_name not in image_bases and text_rva <= memory.disp < image_size):
                    next_temporaries[destination] = (at,1,memory.disp)
                elif not memory.disp:
                    if base_name in temporaries and index_name not in temporaries and index_name not in image_bases:
                        next_temporaries[destination] = temporaries[base_name]
                    elif memory.scale == 1 and index_name in temporaries and base_name not in temporaries and base_name not in image_bases:
                        next_temporaries[destination] = temporaries[index_name]
        elif instruction.mnemonic == "mov" and len(operands) == 2 and all(o.type == x86.X86_OP_REG and o.size == 8 for o in operands):
            if instruction.reg_name(operands[1].reg) in bases:
                next_bases.add(instruction.reg_name(operands[0].reg))
            elif instruction.reg_name(operands[1].reg) in indexed_bases:
                next_indexed.add(instruction.reg_name(operands[0].reg))
            if instruction.reg_name(operands[1].reg) in temporaries:
                next_temporaries[instruction.reg_name(operands[0].reg)] = temporaries[instruction.reg_name(operands[1].reg)]
        if instruction.mnemonic == "call":
            next_bases.intersection_update(nonvolatile)
            next_indexed.intersection_update(nonvolatile)
            next_temporaries = {name:value for name,value in next_temporaries.items() if name in nonvolatile}
        next_rows = tuple(sorted(next_temporaries.items()))
        if instruction.group(capstone.CS_GRP_RET) or instruction.mnemonic in ("int3", "ud2"):
            continue
        if instruction.group(capstone.CS_GRP_JUMP):
            if operands and operands[0].type == x86.X86_OP_IMM and (next_bases or next_indexed or next_rows):
                queue.append((operands[0].imm, frozenset(next_bases),frozenset(next_indexed),next_rows))
            if instruction.mnemonic == "jmp":
                continue
        if next_bases or next_indexed or next_rows:
            queue.append((at+instruction.size, frozenset(next_bases),frozenset(next_indexed),next_rows))
    return list(records.values()), dict(image_base_seeds=len(seeds), image_base_flow_states=len(visited),
                                       image_rva_temporary_seeds=len(temporary_seeds),
                                       image_base_proven_operands=len(records),
                                       image_base_dispatch_edges=len(dispatch_edges))
