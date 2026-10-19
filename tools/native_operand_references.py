"""Keep independently relocated operands on the same x64 instruction."""
import re


def identity(reference):
    return reference['rva'], reference['operand'], reference['kind']


def merge(existing, incoming):
    """Merge provenance for the same operand; retain other operands at its RVA."""
    by_operand = {identity(row): row for row in existing}
    if len(by_operand) != len(existing):
        raise ValueError('Duplicate native operand references')
    added = []
    for row in incoming:
        key = identity(row)
        old = by_operand.get(key)
        if old is not None:
            if old['target'] != row['target']:
                raise ValueError(f'Conflicting native operand reference at {row["rva"]:#x}')
            continue
        by_operand[key] = row
        added.append(row)
    return added


def group(references):
    grouped = {}
    for row in references:
        grouped.setdefault(row['rva'], []).append(row)
    for rows in grouped.values():
        merge(rows, ())
    return grouped


def symbolize(operands, references, rva):
    parts = operands.split(', ')
    for row in references:
        index = row['operand']
        if not isinstance(index, int) or not 0 <= index < len(parts):
            raise ValueError(f'Invalid native operand index at {rva:#x}')
        parts[index], changed = re.subn(
            rf'\b0x{row["target"]:x}\b', f'replay_rva_{row["target"]:08x}@IMGREL', parts[index])
        if changed != 1:
            raise ValueError(f'Image-relative source operand is ambiguous at {rva:#x}')
        # LLVM Intel syntax treats a bare symbolic expression as a memory
        # operand. Preserve an immediate's value semantics explicitly.
        if row['kind'] == 'immediate':
            parts[index] = 'offset ' + parts[index]
    return ', '.join(parts)
