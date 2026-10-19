"""Generate proxy signatures from pinned native recovery and freshly linked code.

The native signature export is a recovery input. Building reads that JSON and
the newly emitted executable only; it never opens the original executable.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re

import capstone
import pefile

from layout import from_report

ROOT = Path(__file__).resolve().parents[1]
PROXY = Path(os.environ['REPLAY_PROXY_SOURCE']).resolve() if os.environ.get('REPLAY_PROXY_SOURCE') else None


def pattern(pe, rva, proven=None):
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    decoder.detail = True
    data = pe.get_data(rva,64)
    mask = bytearray(b"\xff"*len(data))
    end = 0
    for instruction in decoder.disasm(data,rva):
        offset = instruction.address-rva
        for operand in instruction.operands:
            if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                mask[offset+instruction.disp_offset:offset+instruction.disp_offset+instruction.disp_size] = b"\0"*instruction.disp_size
        if (instruction.group(capstone.CS_GRP_JUMP) or instruction.mnemonic == "call") and instruction.imm_size:
            mask[offset+instruction.imm_offset:offset+instruction.imm_offset+instruction.imm_size] = b"\0"*instruction.imm_size
        if proven and instruction.address in proven:
            displacement = proven[instruction.address] == "displacement"
            field = instruction.disp_offset if displacement else instruction.imm_offset
            size = instruction.disp_size if displacement else instruction.imm_size
            mask[offset+field:offset+field+size] = b"\0"*size
        end = offset+instruction.size
    if end < 8:
        raise ValueError(f"Pattern at {rva:x} has too little decoded context")
    for relocation in getattr(pe,"DIRECTORY_ENTRY_BASERELOC",[]):
        for entry in relocation.entries:
            if entry.type == 10 and rva <= entry.rva < rva+end:
                at = entry.rva-rva
                mask[at:at+8] = b"\0"*min(8,end-at)
    return dict(bytes=data[:end].hex(),mask=mask[:end].hex())


def export_native(executable):
    if hashlib.sha256(executable.read_bytes()).hexdigest() != "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0":
        raise ValueError("Pattern source is not the pinned Replay input")
    pe = pefile.PE(str(executable),fast_load=True)
    pe.parse_data_directories(directories=[5])
    signatures = json.loads((ROOT/"generated/proxy-signatures.json").read_text())
    addresses = {s["rva"]:s["name"] for s in signatures}
    lengths = (ROOT/"generated/instruction-lengths.bin").read_bytes()
    if PROXY is not None and not PROXY.is_dir():
        raise ValueError(f"Configured proxy source directory does not exist: {PROXY}")
    sources = [(p,p.read_text(encoding="utf-8-sig")) for suffix in ("*.h","*.cpp") for p in (PROXY.glob(suffix) if PROXY is not None else []) if p.name not in ("replay_compiler_target.h","replay_patterns.h","replay_patterns.cpp")]
    constants = {}
    for _,source in sources:
        for name,value in re.findall(r"constexpr\s+uintptr_t\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+)",source):
            constants[name] = int(value,16)
    for path,source in sources:
        for expression in re.findall(r"replaycompiler::Address\(\s*\w+\s*,\s*([^()]+?)\)",source):
            if re.fullmatch(r"0x[0-9a-fA-F]+",expression):
                address = int(expression,16)
            else:
                address = constants.get(expression.split("::")[-1])
            if (address is not None and 0x1000 <= address < 0x2350d8e and
                    lengths[address-0x1000] not in (0,255)):
                addresses.setdefault(address,f"{path.stem}_{address:08x}")
    addresses.setdefault(pe.OPTIONAL_HEADER.AddressOfEntryPoint, "EntryPoint")
    metadata = json.loads((ROOT/"generated/metadata-report.json").read_text())
    proven = {i["rva"]:i["kind"] for i in metadata["image_relative_operands"]}
    entries = [dict(name=name,rva=rva,native=pattern(pe,rva,proven)) for rva,name in sorted(addresses.items())]
    (ROOT/"generated/proxy-patterns.json").write_text(json.dumps(entries,indent=2)+"\n")
    print(f"Exported {len(entries)} native proxy patterns")


def emit_compiled(executable, report, destination=None, expected_entries=None):
    executable = Path(executable)
    destination = Path(destination or os.environ.get('REPLAY_PROXY_PATTERNS_OUTPUT') or executable.parent / 'replay_patterns.inc')
    pe = pefile.PE(str(executable),fast_load=True)
    pe.parse_data_directories(directories=[5])
    entries = compiled_entries(pe, report)
    if expected_entries is not None and entries != expected_entries:
        raise ValueError("Final executable proxy signatures differ from the embedded registry")
    return _write_compiled(entries, executable, destination)


def compiled_entries(pe, report):
    """Derive linked signatures from a PE object, including an in-memory PE."""
    source = ROOT/"generated/proxy-patterns.json"
    if not source.exists():
        raise ValueError("Recover native proxy patterns before building")
    entries = json.loads(source.read_text())
    binding_sizes = {int(row["rva"]): len(bytes.fromhex(row["bytes"]))
                     for row in json.loads((ROOT/"generated/proxy-signatures.json").read_text())}
    metadata = json.loads((ROOT/"generated/metadata-report.json").read_text())
    proven = {from_report(i["rva"],report):i["kind"] for i in metadata["image_relative_operands"]}
    for entry in entries:
        entry["compiled"] = pattern(pe,from_report(entry["rva"],report),proven)
        # RPLYMAP2 carries exact source-sensitive bindings for known proxy
        # sites. Keep their registry variants within that proven binding
        # extent so the runtime can validate the pair before scanning.
        size = binding_sizes.get(int(entry["rva"]))
        if size:
            for variant in (entry["native"], entry["compiled"]):
                variant["bytes"] = variant["bytes"][:size*2]
                variant["mask"] = variant["mask"][:size*2]
    return entries


def _write_compiled(entries, executable, destination):
    identity_entries = json.loads(json.dumps(entries))
    for entry in identity_entries:
        for variant in (entry["native"],entry["compiled"]):
            variant["bytes"] = bytes(a&b for a,b in zip(bytes.fromhex(variant["bytes"]),bytes.fromhex(variant["mask"]))).hex()
    encoded = json.dumps(identity_entries,sort_keys=True,separators=(",",":")).encode()
    identity = hashlib.sha256(encoded).hexdigest()
    def array(data):
        return "{"+",".join(f"0x{v:02X}" for v in bytes.fromhex(data))+"}"
    lines = ["// Generated by tools/proxy_patterns.py from native recovery and linked code.",f'constexpr char PatternIdentity[] = "{identity}";',"constexpr Pattern Patterns[] = {"]
    for entry in entries:
        variants = []
        for name in ("native","compiled"):
            value = entry[name]
            variants.append("{"+f'{len(bytes.fromhex(value["bytes"]))},'+array(value["bytes"])+","+array(value["mask"])+"}")
        lines.append(f'    {{0x{entry["rva"]:08X}, "{entry["name"]}", {{{",".join(variants)}}}}},')
    lines.append("};\n")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines),encoding="ascii")
    (executable.parent/"proxy-patterns.json").write_text(json.dumps(dict(identity=identity,entries=entries),indent=2)+"\n")
    print(f"Generated {len(entries)} proxy patterns; identity {identity}")
    return dict(identity=identity,count=len(entries),header=str(destination))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--native",type=Path); parser.add_argument("--compiled",type=Path)
    arguments = parser.parse_args()
    if arguments.native: export_native(arguments.native)
    if arguments.compiled:
        emit_compiled(arguments.compiled,json.loads((arguments.compiled.parent/"build-report.json").read_text()))
