"""Derive native metadata producers without build-specific function RVAs."""
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import sqlite3

import capstone


def function_names(pe, output):
    import source_catalog
    config = json.loads((Path(__file__).resolve().parents[1] / 'replay-project.local.json').read_text())
    names = {}
    with sqlite3.connect(source_catalog.readonly_uri(Path(config['sqlite'])), uri=True) as db:
        db.execute('BEGIN')
        programs = db.execute('SELECT processor,md5sum FROM program').fetchall()
        if len(programs) != 1:
            raise ValueError('Metadata inventory must identify one native program')
        processor, md5 = programs[0]
        md5 = md5.hex() if isinstance(md5, bytes) else str(md5)
        if processor.lower() != 'pc64' or md5.lower() != hashlib.md5(pe.__data__).hexdigest():
            raise ValueError('Metadata symbol inventory belongs to a different executable')
        has_quarantine = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                    "AND name='replay_function_quarantine'").fetchone()
        query = 'SELECT f.name,f.address FROM functions f'
        if has_quarantine:
            query += (' WHERE NOT EXISTS (SELECT 1 FROM replay_function_quarantine q '
                      'WHERE q.function_id=f.id)')
        for name, address in db.execute(query):
            rva = source_catalog.parse_integer(address, 'metadata function address') - pe.OPTIONAL_HEADER.ImageBase
            names.setdefault(rva, set()).add(str(name or '').lstrip('_'))
    catalog = Path(output) / 'function-catalog.json'
    if catalog.is_file():
        data = json.loads(catalog.read_text())
        if data.get('image_sha256') != hashlib.sha256(pe.__data__).hexdigest():
            raise ValueError('Metadata alias catalog belongs to a different executable')
        for row in data.get('functions', []):
            if not row.get('quarantined'):
                names.setdefault(row['rva'], set()).update(
                    str(name).lstrip('_') for name in [row.get('name', ''), *row.get('aliases', [])])
    return names


def exception_handlers(pe, names, decoder):
    handlers = set()
    spans = {e.struct.BeginAddress: e.struct.EndAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        at = entry.struct.UnwindData
        header = pe.get_data(at, 4)
        if len(header) != 4:
            raise ValueError('Truncated exception producer metadata')
        flags = header[0] >> 3
        if flags & 3 and not flags & 4:
            extra = at + 4 + ((header[2] + 1) & ~1) * 2
            raw = pe.get_data(extra, 4)
            if len(raw) != 4:
                raise ValueError('Truncated native exception handler pointer')
            handlers.add(int.from_bytes(raw, 'little'))
    kinds, proof = {}, {}
    known = dict(GSHandlerCheck_SEH='seh', C_specific_handler='seh',
                 GSHandlerCheck_EH='cpp', CxxFrameHandler3='cpp',
                 GSHandlerCheck='non-rva', lj_err_unwind_win='non-rva')
    for handler in handlers:
        matches = {known[name] for name in names.get(handler, []) if name in known}
        if len(matches) > 1:
            raise ValueError('Conflicting native exception handler identities')
        if matches:
            kinds[handler] = matches.pop()
            proof[handler] = dict(basis='symbol-inventory', names=sorted(names[handler]))
    for wrapper in sorted(handlers):
        if not names.get(wrapper, set()) & {'GSHandlerCheck_SEH', 'GSHandlerCheck_EH'}:
            continue
        end = spans.get(wrapper)
        if end is None:
            raise ValueError('Named exception wrapper has no native PE function extent')
        calls = {i.operands[0].imm for i in decoder.disasm(pe.get_data(wrapper, end-wrapper), wrapper)
                 if i.mnemonic in ('call', 'jmp') and i.operands and
                 i.operands[0].type == capstone.x86.X86_OP_IMM}
        targets = (calls & handlers) - {wrapper}
        if len(targets) != 1:
            raise ValueError('Exception wrapper does not prove one native handler callee')
        target = targets.pop()
        if target in kinds and kinds[target] != kinds[wrapper]:
            raise ValueError('Exception wrapper contradicts its callee metadata layout')
        kinds[target] = kinds[wrapper]
        proof[target] = dict(basis='native-wrapper-call', wrapper_rva=wrapper, kind=kinds[wrapper])
    if handlers != set(kinds):
        raise ValueError('Unclassified native exception handler(s): ' +
                         ', '.join(hex(at) for at in sorted(handlers-set(kinds))))
    return kinds, proof


def lua_dispatch_offsets(pe, decoder, lengths):
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    raw, text_rva = text.get_data(), text.VirtualAddress
    entries = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    starts = [e.BeginAddress for e in entries]
    producers = []
    position = 0
    while True:
        position = raw.find(b'\x41\xbb', position)
        if position < 0:
            break
        at = text_rva + position
        position += 2
        if lengths[at-text_rva] != 6:
            continue
        steps = list(decoder.disasm(pe.get_data(at, 64), at))
        if not steps or steps[0].mnemonic != 'mov' or steps[0].operands[1].type != capstone.x86.X86_OP_IMM:
            continue
        count = steps[0].operands[1].imm
        if not 0 < count < 1024:
            continue
        bases = {}
        loop = None
        for step in steps[1:]:
            if step.mnemonic == 'lea' and len(step.operands) == 2:
                dest, value = step.operands
                if (dest.type == capstone.x86.X86_OP_REG and value.type == capstone.x86.X86_OP_MEM and
                        value.mem.base == capstone.x86.X86_REG_RIP):
                    bases[step.reg_name(dest.reg)] = step.address + step.size + value.mem.disp
            if step.mnemonic == 'movzx' and step.op_str == 'r8d, word ptr [r10]':
                loop = step
                break
            if step.group(capstone.CS_GRP_JUMP) or step.mnemonic == 'call':
                break
        if loop is None or not {'r10', 'rdi'} <= bases.keys():
            continue
        addition = None
        following = steps[steps.index(loop)+1:]
        for step in following:
            if step.mnemonic == 'add' and step.op_str == 'r8, rdi':
                addition = step
                break
            if (step.group(capstone.CS_GRP_JUMP) or step.group(capstone.CS_GRP_RET) or
                    step.mnemonic == 'call' or any(step.reg_name(reg) in
                    ('r8', 'r8d', 'r8w', 'r8b', 'rdi', 'edi', 'di', 'dil')
                    for reg in step.regs_access()[1])):
                break
        if addition is None:
            continue
        back_edge = next((step for step in following
                          if step.mnemonic == 'jne' and len(step.operands) == 1 and
                          step.operands[0].type == capstone.x86.X86_OP_IMM and
                          step.operands[0].imm == loop.address), None)
        if back_edge is None:
            continue
        body = [step for step in following if step.address < back_edge.address]
        if not any(step.mnemonic == 'lea' and step.op_str == 'r10, [r10 + 2]' for step in body):
            continue
        if not any(step.mnemonic == 'sub' and step.op_str == 'r11, 1' for step in body):
            continue
        owner = bisect_right(starts, at)-1
        if owner < 0 or at >= entries[owner].EndAddress:
            raise ValueError('Lua dispatch initializer lacks a native PE extent')
        begin, end = entries[owner].BeginAddress, entries[owner].EndAddress
        instructions = []
        for step in decoder.disasm(pe.get_data(begin, end-begin), begin):
            instructions.append(step)
            if step.mnemonic == 'ret':
                break
        fields = {bases['r10'] + index*2 for index in range(count)}
        for index, step in enumerate(instructions):
            if (step.mnemonic != 'movzx' or len(step.operands) != 2 or
                    step.operands[0].type != capstone.x86.X86_OP_REG or
                    step.reg_name(step.operands[0].reg) not in ('rax', 'eax') or
                    step.operands[1].type != capstone.x86.X86_OP_MEM):
                continue
            memory = step.operands[1]
            if memory.size != 2 or memory.mem.base != capstone.x86.X86_REG_RIP:
                continue
            if index+1 >= len(instructions) or instructions[index+1].mnemonic != 'add' or instructions[index+1].op_str != 'rax, rdi':
                raise ValueError('Lua fast-function WORD offset has an unproven VM base')
            fields.add(step.address + step.size + memory.mem.disp)
        if fields != set(range(bases['r10'], bases['r10']+len(fields)*2, 2)):
            raise ValueError('Lua dispatch WORD extent is not contiguous')
        producers.append((bases['rdi'], fields))
    if len(producers) != 1:
        raise ValueError('Expected one proven Lua dispatch initializer, found ' + str(len(producers)))
    origin, fields = producers[0]
    result = []
    for field in sorted(fields):
        data = pe.get_data(field, 2)
        if len(data) != 2:
            raise ValueError('Truncated native Lua dispatch WORD')
        result.append(dict(at=field, target=origin+int.from_bytes(data, 'little'),
                           base=origin, subtract=False, shift=0, width=2, signed=False,
                           provenance='LuaJIT dispatch initializer WORD offset'))
    return result
