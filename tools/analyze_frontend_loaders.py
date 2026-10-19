"""Compare verified Replay loader entries with the analysis-only 1.31 dump.

Matches preserve the asset type ID and all scalar constants other than the
root-size argument. Only PC-relative addresses and control-flow destinations
are masked. A matched head is a source-recovery lead, not a compatible reader.
"""
from __future__ import annotations

import argparse
from difflib import unified_diff
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path(os.environ.get('REPLAY_GAME_ROOT', r'E:\IW8\Builds\1.20-replay')) / 'game_dx12_ship_replay.exe'
REFERENCE = ROOT / "assets/mw131-reference/ModernWarfare_startup_dump.exe"
ORIGINAL_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def body(pe, entry, missing=()):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    result = []
    for ins in decoder.disasm(pe.get_data(entry, 65536), entry):
        if any(page <= ins.address < page + 4096 for page in missing):
            raise ValueError(f"Body crosses unreadable page at {ins.address:#x}")
        previous = result[-1] if result else None
        result.append(ins)
        if ins.mnemonic.startswith("ret"):
            return result
        if ins.mnemonic == "jmp" and previous and previous.mnemonic == "pop":
            return result
    raise ValueError(f"No linear epilogue found for {entry:#x}")


def head_pattern(instructions, count=16):
    pattern = bytearray()
    fixed = []
    for ins in instructions[:count]:
        start = len(pattern)
        pattern.extend(ins.bytes)
        fixed.extend([True] * ins.size)
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands):
            fixed[start + ins.disp_offset:start + ins.disp_offset + ins.disp_size] = [False] * ins.disp_size
        if ins.imm_size and (ins.mnemonic == "call" or ins.mnemonic.startswith("j") or
                (ins.mnemonic == "mov" and ins.op_str.startswith("r8d, "))):
            fixed[start + ins.imm_offset:start + ins.imm_offset + ins.imm_size] = [False] * ins.imm_size
    return bytes(pattern), fixed


def matches(pe, pattern, fixed, missing):
    runs = []
    start = 0
    for index in range(len(fixed) + 1):
        if index == len(fixed) or not fixed[index]:
            if index > start: runs.append((index - start, start))
            start = index + 1
    length, anchor_start = max(runs)
    if length < 8: return []
    anchor = pattern[anchor_start:anchor_start + length]
    hits = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000: continue
        data = section.get_data()
        offset = data.find(anchor)
        while offset >= 0:
            candidate = offset - anchor_start
            rva = section.VirtualAddress + candidate
            if candidate >= 0 and candidate + len(pattern) <= len(data) and not any(
                    rva < page + 4096 and page < rva + len(pattern) for page in missing):
                if all(not keep or data[candidate + index] == pattern[index] for index, keep in enumerate(fixed)):
                    hits.append(rva)
            offset = data.find(anchor, offset + 1)
    return hits


def normalized(ins):
    operands = re.sub(r"\[rip[^]]*\]", "[rip + global]", ins.op_str)
    if ins.mnemonic == "call": operands = "callee"
    elif ins.mnemonic.startswith("j"): operands = "branch"
    return ins.mnemonic + " " + operands


def unwind_spans(pe, entry):
    """Include lazy-prologue fragments chained to the entry's unwind record."""
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    entries = list(struct.iter_unpack("<III", pe.get_data(directory.VirtualAddress, directory.Size)))
    root = next((row for row in entries if row[0] == entry), None)
    if root is None:
        raise ValueError(f"No exact native unwind entry for {entry:#x}")
    accepted = {root}
    while True:
        previous = len(accepted)
        for row in entries:
            raw = pe.get_data(row[2], 4)
            if len(raw) != 4 or not raw[0] >> 3 & 4:
                continue
            trailer = row[2] + 4 + ((raw[2] + 1) & ~1) * 2
            parent = struct.unpack("<III", pe.get_data(trailer, 12))
            if parent in accepted:
                accepted.add(row)
        if len(accepted) == previous:
            return sorted((begin, end) for begin, end, _ in accepted)


def bounded_body(pe, entry, missing=()):
    """Follow reachable blocks within exact, transitively chained unwind spans."""
    spans = unwind_spans(pe, entry)
    end = max(stop for _, stop in spans)
    def contains(address):
        return any(begin <= address < stop for begin, stop in spans)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pending, visited = [entry], {}
    while pending:
        address = pending.pop()
        while address not in visited and contains(address):
            ins = next(decoder.disasm(pe.get_data(address, min(15, end - address)), address), None)
            if ins is None or any(address < page + 4096 and page < address + ins.size for page in missing):
                raise ValueError(f"Unreadable instruction at {address:#x}")
            visited[address] = ins
            if ins.mnemonic.startswith("ret"):
                break
            if ins.mnemonic.startswith("j"):
                if ins.operands[0].type != X86_OP_IMM:
                    raise ValueError(f"Indirect branch requires switch recovery at {address:#x}")
                target = ins.operands[0].imm
                if contains(target):
                    pending.append(target)
                elif ins.mnemonic != "jmp":
                    raise ValueError(f"Conditional branch leaves native span at {address:#x}")
                if ins.mnemonic == "jmp":
                    break  # Outside-span direct jumps are reported as tail calls.
            address += ins.size
    return [visited[at] for at in sorted(visited)], end


def compare_bounded(spec):
    name, old_text, new_text = spec.split(":")
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError("Invalid comparison label")
    meta = json.loads((ROOT / "evidence/mw131-reference-dump.json").read_text())
    if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() != ORIGINAL_SHA or not meta["analysis_only"] or \
            hashlib.sha256(REFERENCE.read_bytes()).hexdigest() != meta["dump_sha256"]:
        raise ValueError("Native input provenance changed")
    old_pe = pefile.PE(str(ORIGINAL), fast_load=True)
    new_pe = pefile.PE(str(REFERENCE), fast_load=True)
    old_entry, new_entry = int(old_text, 0), int(new_text, 0)
    old, old_end = bounded_body(old_pe, old_entry)
    new, new_end = bounded_body(new_pe, new_entry, meta["missing_pages"])
    for label, instructions in (("replay", old), ("mw131", new)):
        (ROOT / f"evidence/{label}-{name}-bounded.asm.txt").write_text(
            "".join(f"{ins.address:#x} {ins.mnemonic} {ins.op_str}\n" for ins in instructions))
    diff = "".join(unified_diff([normalized(ins) + "\n" for ins in old],
            [normalized(ins) + "\n" for ins in new], fromfile=f"Replay {old_entry:#x}",
            tofile=f"1.31 {new_entry:#x}", n=2))
    (ROOT / f"evidence/mw131-{name}-bounded-diff.txt").write_text(diff)
    report = dict(name=name, replay_sha256=ORIGINAL_SHA, reference_dump_sha256=meta["dump_sha256"],
        replay_rva=old_entry, replay_end=old_end, mw131_rva=new_entry, mw131_end=new_end,
        replay_instructions=len(old), mw131_instructions=len(new), scalar_diff_present=bool(diff),
        replay_unwind_spans=unwind_spans(old_pe, old_entry),
        mw131_unwind_spans=unwind_spans(new_pe, new_entry),
        coverage="Reachable direct control flow within exact native unwind spans, including transitively chained fragments. Calls not followed; relative targets masked. No nested-reader or consumer compatibility proof.")
    # Preserve what normalization deliberately masks. An equal scalar body is
    # insufficient evidence when a nested call or transfer global has changed.
    for label, instructions in (("replay", old), ("mw131", new)):
        report[label + "_direct_calls"] = [
            dict(site=ins.address, target=ins.operands[0].imm)
            for ins in instructions if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM]
        report[label + "_rip_references"] = [
            dict(site=ins.address, target=ins.address + ins.size + op.mem.disp)
            for ins in instructions for op in ins.operands
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
    (ROOT / f"evidence/mw131-{name}-bounded.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items()
        if not key.endswith(("_direct_calls", "_rip_references"))}, indent=2))


def main():
    meta = json.loads((ROOT / "evidence/mw131-reference-dump.json").read_text())
    if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() != ORIGINAL_SHA:
        raise ValueError("Replay provenance changed")
    if not meta["analysis_only"] or hashlib.sha256(REFERENCE.read_bytes()).hexdigest() != meta["dump_sha256"]:
        raise ValueError("Reference dump provenance changed")
    original = pefile.PE(str(ORIGINAL), fast_load=True)
    reference = pefile.PE(str(REFERENCE), fast_load=True)
    missing = meta["missing_pages"]
    pools = json.loads((ROOT / "evidence/mw131-asset-pools.json").read_text())["pools"]
    symbols = json.loads((ROOT / "generated/native-symbols.json").read_text())
    names = {value: key for key, value in symbols.items()}
    matched = []
    for pool in pools:
        if pool["size"] == pool["replay"]["size"]: continue
        entry = pool["replay"]["loader_rva"]
        old = body(original, entry)
        pattern, fixed = head_pattern(old)
        hits = matches(reference, pattern, fixed, missing)
        count = 16
        if not hits:
            # Keep the root read and type ID, but exclude the following nested
            # stream selection. A stream-block change is itself an ABI finding.
            count = 12
            pattern, fixed = head_pattern(old, count)
            hits = matches(reference, pattern, fixed, missing)
        matched.append({"asset": pool["name"], "replay_rva": entry,
                        "mw131_candidates": hits, "head_instructions": count,
                        "method": "Opcode head, fixed asset ID and scalar constants"})
    known = [
        ("Load_GfxWorld", 0xD92E80, 0x1D35C30),
        ("Load_GfxWorldSurfaces", 0xE305D0, 0x1DD4960),
        ("Load_MapEnts", 0xE0B520, 0x1DAEFE0),
        # Different register saves prevent a byte-head match. The native
        # unwind entry at 0x1D5C140 calls PushAsset(63), Load_Stream(...,112)
        # and the separately verified Load_XString at 0x1D77750. The nearby
        # preload entry instead calls Preload_XString and is excluded.
        ("Load_ScriptableDef", 0xDB9080, 0x1D5C140),
    ]
    for item in matched:
        if len(item["mw131_candidates"]) == 1 and item["replay_rva"] not in [old for _, old, _ in known]:
            known.append((names.get(item["replay_rva"], item["asset"]), item["replay_rva"], item["mw131_candidates"][0]))
    comparisons = []
    for name, old_rva, new_rva in known:
        old, new = body(original, old_rva), body(reference, new_rva, missing)
        for label, instructions in (("replay", old), ("mw131", new)):
            (ROOT / f"evidence/{label}-{name}.asm.txt").write_text(
                "".join(f"{ins.address:#x} {ins.mnemonic} {ins.op_str}\n" for ins in instructions))
        diff = "".join(unified_diff([normalized(ins) + "\n" for ins in old],
                [normalized(ins) + "\n" for ins in new],
                fromfile=f"Replay {old_rva:#x}", tofile=f"1.31 {new_rva:#x}", n=2))
        (ROOT / f"evidence/mw131-{name}-layout-diff.txt").write_text(diff)
        calls = []
        for label, instructions in (("replay", old), ("mw131", new)):
            calls.append({"build": label, "calls": [
                {"site_rva": ins.address, "target_rva": ins.operands[0].imm,
                 "replay_name": names.get(ins.operands[0].imm) if label == "replay" else None}
                for ins in instructions if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM]})
        comparisons.append({"name": name, "replay_rva": old_rva, "mw131_rva": new_rva,
                            "replay_linear_end": old[-1].address + old[-1].size,
                            "mw131_linear_end": new[-1].address + new[-1].size,
                            "replay_instructions": len(old), "mw131_instructions": len(new), "calls": calls})
    report = {"replay_sha256": ORIGINAL_SHA, "reference_sha256": meta["original_sha256"],
              "reference_dump_sha256": meta["dump_sha256"],
              "coverage": "Linear bodies through first return or pop/tail-jump epilogue; no whole-program behavior proof",
              "root_loader_head_matches": matched, "comparisons": comparisons}
    (ROOT / "evidence/mw131-loader-analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    for item in matched:
        print(item["asset"], hex(item["replay_rva"]), [hex(rva) for rva in item["mw131_candidates"]])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", metavar="NAME:REPLAY_RVA:MW131_RVA")
    args = parser.parse_args()
    if args.compare: compare_bounded(args.compare)
    else: main()
