"""Discover Replay rewind-state locations from a hash-pinned target build.

This reports static bindings for a read-only live snapshot collector.  It does
not read process memory, write the game, or claim undocumented fields beyond
the instructions which consume them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_REPORT = ROOT / "scratch/skate-native-source-v2/build-frontend-skate-consolidated-v2/build-report.json"
DEFAULT_CATALOG = ROOT / "generated/function-catalog.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value, raw


def _function_by_id(catalog: dict[str, Any], identity: str) -> dict[str, Any]:
    rows = [row for row in catalog.get("functions", []) if row.get("id") == identity]
    if len(rows) != 1:
        raise ValueError(f"Catalog function id is missing or ambiguous: {identity}")
    return rows[0]


def _profile_for_build(build_report: dict[str, Any], build_path: Path) -> tuple[dict[str, Any], Path, str]:
    record = build_report.get("source_profile")
    if not isinstance(record, dict) or not record.get("path") or not record.get("sha256"):
        raise ValueError("Build report has no hash-pinned source profile")
    path = Path(record["path"])
    if not path.is_absolute():
        path = build_path.parent.parent / path
    path = path.resolve(strict=True)
    profile_raw = path.read_bytes()
    digest = hashlib.sha256(profile_raw).hexdigest()
    if digest != record["sha256"]:
        raise ValueError("Build report source profile hash is stale")
    profile = json.loads(profile_raw)
    if not isinstance(profile, dict):
        raise ValueError("Source profile must be a JSON object")
    return profile, path, digest


def _catalog_function(catalog: dict[str, Any], identity: str) -> dict[str, Any]:
    rows = [row for row in catalog.get("functions", []) if row.get("id") == identity]
    if len(rows) != 1:
        raise ValueError(f"Profile function identity is absent/ambiguous in catalog: {identity}")
    return rows[0]


def _instruction_row(ins: Any, image_base: int) -> dict[str, Any]:
    from capstone import x86_const

    row: dict[str, Any] = {
        "rva": int(ins.address - image_base), "next_rva": int(ins.address + ins.size - image_base),
        "bytes": bytes(ins.bytes).hex(),
        "mnemonic": ins.mnemonic, "op_str": ins.op_str,
        "rip_targets": [], "memory_operands": [], "direct_call_rvas": [],
        "direct_branch_rvas": [],
    }
    for operand in ins.operands:
        if operand.type == x86_const.X86_OP_MEM:
            mem = operand.mem
            item = {"base": ins.reg_name(mem.base) if mem.base else None,
                    "index": ins.reg_name(mem.index) if mem.index else None,
                    "scale": int(mem.scale), "disp": int(mem.disp),
                    "size": int(operand.size)}
            if mem.base == x86_const.X86_REG_RIP:
                item["target_rva"] = int(ins.address + ins.size + mem.disp - image_base)
                row["rip_targets"].append(item["target_rva"])
            row["memory_operands"].append(item)
        elif operand.type == x86_const.X86_OP_IMM:
            if ins.mnemonic == "call":
                row["direct_call_rvas"].append(int(operand.imm - image_base))
            elif ins.mnemonic == "jmp" or ins.mnemonic.startswith("j"):
                row["direct_branch_rvas"].append(int(operand.imm - image_base))
    return row


def _disassemble(pe: Any, start_rva: int, end_rva: int, image_base: int) -> list[dict[str, Any]]:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    if end_rva <= start_rva:
        raise ValueError("Disassembly interval is empty")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    code = pe.get_data(start_rva, end_rva - start_rva)
    rows = []
    expected_address = image_base + start_rva
    for ins in decoder.disasm(code, expected_address):
        if ins.address != expected_address:
            break
        rows.append(_instruction_row(ins, image_base))
        expected_address += ins.size
    if not rows:
        raise ValueError(f"No x64 instructions decoded at RVA {start_rva:#x}")
    return rows


def _reachable_function_rows(rows: list[dict[str, Any]], start_rva: int) -> list[dict[str, Any]]:
    """Keep only entry-reachable instruction rows, stopping at returns/tail jumps."""
    by_rva = {row["rva"]: row for row in rows}
    pending = [start_rva]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        while address in by_rva and address not in visited:
            row = by_rva[address]
            visited.add(address)
            mnemonic = row["mnemonic"]
            next_address = row["next_rva"]
            if mnemonic.startswith("ret") or mnemonic in ("ud2", "int3"):
                break
            if mnemonic == "jmp":
                targets = row["direct_branch_rvas"]
                if len(targets) == 1 and targets[0] in by_rva:
                    address = targets[0]
                    continue
                break
            if mnemonic.startswith("j") and mnemonic != "jmp":
                targets = row["direct_branch_rvas"]
                pending.extend(target for target in targets if target in by_rva)
            address = next_address
    return [by_rva[address] for address in sorted(visited)]


def _successors(row: dict[str, Any]) -> list[int]:
    mnemonic = row["mnemonic"]
    if mnemonic.startswith("ret") or mnemonic in ("ud2", "int3"):
        return []
    if mnemonic == "jmp":
        return list(row["direct_branch_rvas"])
    if mnemonic.startswith("j") and mnemonic != "jmp":
        return [*row["direct_branch_rvas"], row["next_rva"]]
    return [row["next_rva"]]


def _derive_verified_pointer_prefix(rows: list[dict[str, Any]], table_rva: int) -> dict[str, Any]:
    """Prove a fixed, initialized loop reads a bounded prefix of the pointer table."""
    by_rva = {row["rva"]: row for row in rows}
    entry_rva = min(by_rva)
    preds: dict[int, set[int]] = {address: set() for address in by_rva}
    for row in rows:
        for target in _successors(row):
            if target in preds:
                preds[target].add(row["rva"])
    dominators = {address: ({entry_rva} if address == entry_rva else set(by_rva))
                  for address in by_rva}
    changed = True
    while changed:
        changed = False
        for address in sorted(by_rva):
            if address == entry_rva:
                continue
            incoming = preds[address]
            common = set.intersection(*(dominators[pred] for pred in incoming)) if incoming else set()
            updated = {address} | common
            if updated != dominators[address]:
                dominators[address] = updated
                changed = True

    bases = []
    for row in rows:
        if row["mnemonic"] != "lea" or _leading_register(row["op_str"], "lea") is None:
            continue
        if any(mem.get("target_rva") == table_rva for mem in row["memory_operands"]):
            bases.append((row, _leading_register(row["op_str"], "lea")))
    if len(bases) != 1:
        raise ValueError("EndLoad path does not uniquely establish the pointer-table base")
    base_row, table_register = bases[0]

    loop_loads = [(row, mem) for row in rows if row["mnemonic"] == "mov"
                  for mem in row["memory_operands"]
                  if mem["base"] == table_register and mem["index"] is None
                  and mem["disp"] == 0 and mem["size"] == 8]
    backedges = [(row, row["direct_branch_rvas"][0]) for row in rows
                 if row["mnemonic"] in ("jb", "jnae") and len(row["direct_branch_rvas"]) == 1]
    matches = []
    for load_row, _ in loop_loads:
        for branch, target in backedges:
            if target != load_row["rva"]:
                continue
            prior = [row for row in rows if row["next_rva"] == branch["rva"]]
            if len(prior) != 1 or prior[0]["mnemonic"] != "cmp":
                continue
            operands = [part.strip().lower() for part in prior[0]["op_str"].split(",")]
            if len(operands) != 2 or not operands[1].startswith("0x") and not operands[1].isdigit():
                continue
            try:
                bound = int(operands[1], 0)
            except ValueError:
                continue
            if bound > 0:
                matches.append((load_row, branch, prior[0], operands[0], bound))
    if len(matches) != 1:
        raise ValueError("EndLoad path lacks a unique unsigned fixed-count backedge over table loads")
    loop_head, backedge, compare, counter, prefix_count = matches[0]
    if counter not in ("esi", "rsi", "eax", "rax", "ecx", "rcx", "ebx", "rbx"):
        raise ValueError("Pointer-prefix loop counter is not a supported general register")

    inits = [row for row in rows if row["mnemonic"] == "xor" and
             [part.strip().lower() for part in row["op_str"].split(",")] == [counter, counter] and
             row["rva"] < loop_head["rva"]]
    increments = [row for row in rows if row["mnemonic"] == "inc" and
                  row["op_str"].strip().lower() == counter and
                  loop_head["rva"] < row["rva"] < backedge["rva"]]
    pointer_steps = [row for row in rows if row["mnemonic"] == "add" and
                     [part.strip().lower() for part in row["op_str"].split(",")] == [table_register, "8"] and
                     loop_head["rva"] < row["rva"] < backedge["rva"]]
    if len(inits) != 1 or inits[0]["rva"] not in dominators[loop_head["rva"]]:
        raise ValueError("Loop counter is not uniquely initialized to zero before the loop")
    if base_row["rva"] not in dominators[loop_head["rva"]]:
        raise ValueError("Pointer-table base does not dominate the verified loop load")
    if len(increments) != 1 or len(pointer_steps) != 1:
        raise ValueError("Each pointer-table loop iteration must advance counter and pointer once")
    increment, pointer_step = increments[0], pointer_steps[0]
    if not (loop_head["rva"] < increment["rva"] < pointer_step["rva"] < compare["rva"] < backedge["rva"]):
        raise ValueError("Pointer-prefix loop updates are not ordered after each table load")

    # The updates must dominate the outer loop test. This permits a separate,
    # bounded inner loop in the body while rejecting paths that skip a read or
    # conditionally omit one of the two required increments.
    if increment["rva"] not in dominators[compare["rva"]] or \
            pointer_step["rva"] not in dominators[compare["rva"]]:
        raise ValueError("A path to the pointer-prefix loop test bypasses a required increment")
    if loop_head["rva"] not in dominators[compare["rva"]]:
        raise ValueError("A path to the pointer-prefix loop test bypasses the table load")
    write_mnemonics = {"mov", "lea", "add", "sub", "inc", "dec", "xor", "and",
                       "or", "imul", "shl", "shr", "neg", "not", "xchg"}
    for row in rows:
        if loop_head["rva"] <= row["rva"] < backedge["rva"]:
            if row["mnemonic"].startswith("ret"):
                raise ValueError("A pointer-prefix loop path returns before its bound comparison")
            if any(target < loop_head["rva"] or target > backedge["rva"]
                   for target in _successors(row)):
                raise ValueError("A pointer-prefix loop branch bypasses the proved loop bound")
            destination = row["op_str"].split(",", 1)[0].strip().lower()
            if row["mnemonic"] in write_mnemonics and destination == counter and row != increment:
                raise ValueError("Pointer-prefix counter has an unproved in-loop write")
            if row["mnemonic"] in write_mnemonics and destination == table_register and row != pointer_step:
                raise ValueError("Pointer-table cursor has an unproved in-loop write")

    return {
        "verified_prefix_count": prefix_count,
        "allocation_count": None,
        "full_table_count_unknown": True,
        "coverage": "verified-prefix",
        "evidence": {
            "counter_zero_init": inits[0], "table_base": base_row,
            "loop_head_load": loop_head, "counter_increment": increment,
            "pointer_increment": pointer_step, "count_compare": compare,
            "backedge": backedge,
        },
        "basis": "All entry-reachable iterations start at counter zero, read one 8-byte table entry, advance the table pointer by 8, increment the counter once, and branch back while counter is below the immediate bound.",
    }


def _find_profile_binding(profile: dict[str, Any], name: str) -> dict[str, Any]:
    rows = [row for row in profile.get("imports", []) if row.get("symbol") == name]
    if len(rows) != 1:
        raise ValueError(f"Profile must bind exactly one {name}: {len(rows)}")
    return rows[0]


def _compiled_symbol(build_report: dict[str, Any], symbol: str) -> int:
    value = build_report.get("symbols", {}).get(symbol)
    if type(value) is not int or value < 0:
        raise ValueError(f"Build report has no compiled RVA for {symbol}")
    return value


def _relative_stream_table_evidence(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Require an entry-reachable RIP table base and a 4-byte indexed read."""
    bases: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for row in rows:
        if row["mnemonic"] != "lea":
            continue
        operands = row["op_str"].lower().split(",", 1)
        if len(operands) != 2:
            continue
        register = operands[0].strip()
        for operand in row["memory_operands"]:
            if (operand.get("target_rva") is not None and operand["base"] == "rip" and
                    operand["index"] is None):
                bases.setdefault(register, []).append((operand["target_rva"], row))
    reads = []
    for row in rows:
        if row["mnemonic"] not in ("mov", "movzx", "movsxd"):
            continue
        operands = row["op_str"].lower().split(",", 1)
        if len(operands) != 2 or "ptr" not in operands[1]:
            continue
        for operand in row["memory_operands"]:
            if (operand["base"] in bases and operand["index"] is not None and
                    operand["scale"] == 4 and operand["size"] == 4):
                for target, lea in bases[operand["base"]]:
                    reads.append((target, lea, row, operand))
    targets = {target for target, *_ in reads}
    if len(targets) != 1 or len(reads) != 1:
        raise ValueError("Bound stream-delta function lacks a unique RIP table with a 4-byte stream-indexed read")
    target, lea, read, operand = reads[0]
    return {"table_rva": target, "base_register": operand["base"],
            "index_register": operand["index"], "stride": operand["scale"],
            "read_size": operand["size"],
            "base_instruction": {"rva": lea["rva"], "bytes": lea["bytes"], "op_str": lea["op_str"]},
            "read_instruction": {"rva": read["rva"], "bytes": read["bytes"], "op_str": read["op_str"]}}


def _relative_stream_call_argument(rows: list[dict[str, Any]], call: dict[str, Any]) -> dict[str, Any]:
    """Trace the resolver's masked token stream id into the helper's RCX arg."""
    import re

    def reg_name(value: str) -> str | None:
        value = value.strip().lower()
        aliases = {"rax": "a", "eax": "a", "ax": "a", "al": "a",
                   "rbx": "b", "ebx": "b", "bx": "b", "bl": "b",
                   "rcx": "c", "ecx": "c", "cx": "c", "cl": "c",
                   "rdx": "d", "edx": "d", "dx": "d", "dl": "d",
                   "rsi": "si", "esi": "si", "si": "si",
                   "rdi": "di", "edi": "di", "di": "di",
                   "rbp": "bp", "ebp": "bp", "bp": "bp",
                   "rsp": "sp", "esp": "sp", "sp": "sp"}
        if value in aliases:
            return aliases[value]
        match = re.fullmatch(r"(r(?:8|9|1[0-5]))(?:d|w|b)?", value)
        return match.group(1) if match else None

    def stack_offset(value: str) -> int | None:
        match = re.search(r"\[rsp(?:\s*\+\s*(0x[0-9a-f]+|[0-9]+))?\]", value.lower())
        return int(match.group(1), 0) if match and match.group(1) else 0 if match else None

    # Dominance is required so address-sorted code from a mutually exclusive
    # branch cannot be mistaken for the producer of this call argument.
    by_rva = {row["rva"]: row for row in rows}
    entry = min(by_rva)
    predecessors = {rva: set() for rva in by_rva}
    for row in rows:
        for target in _successors(row):
            if target in predecessors:
                predecessors[target].add(row["rva"])
    dominators = {rva: ({entry} if rva == entry else set(by_rva)) for rva in by_rva}
    changed = True
    while changed:
        changed = False
        for rva in sorted(by_rva):
            if rva == entry:
                continue
            incoming = predecessors[rva]
            common = set.intersection(*(dominators[item] for item in incoming)) if incoming else set()
            updated = {rva} | common
            if updated != dominators[rva]:
                dominators[rva] = updated
                changed = True

    registers: dict[str, tuple[str, list[int]]] = {}
    stack: dict[int, tuple[str, list[int]]] = {}
    for row in rows:
        if row["rva"] >= call["rva"]:
            break
        mnemonic = row["mnemonic"].lower()
        operands = row["op_str"].lower().split(",", 1)
        if len(operands) != 2:
            continue
        destination, source = (item.strip() for item in operands)
        destination_reg = reg_name(destination)
        destination_stack = stack_offset(destination)
        if mnemonic == "mov":
            source_reg = reg_name(source)
            source_stack = stack_offset(source)
            if destination_reg:
                if source_reg:
                    value = registers.get(source_reg)
                    if value:
                        registers[destination_reg] = (value[0], [*value[1], row["rva"]])
                    else:
                        registers.pop(destination_reg, None)
                elif source_stack is not None and source_stack in stack:
                    value = stack[source_stack]
                    registers[destination_reg] = (value[0], [*value[1], row["rva"]])
                elif (destination_reg != "sp" and "ptr [rcx" in source and
                      any(mem["base"] == "rcx" and mem["index"] is None and mem["size"] == 8
                          for mem in row["memory_operands"])):
                    registers[destination_reg] = ("token", [row["rva"]])
                else:
                    registers.pop(destination_reg, None)
            elif destination_stack is not None and reg_name(source):
                source_value = registers.get(reg_name(source))
                if source_value:
                    stack[destination_stack] = (source_value[0], [*source_value[1], row["rva"]])
                else:
                    stack.pop(destination_stack, None)
        elif mnemonic == "shr" and destination_reg:
            source_value = registers.get(destination_reg)
            if source_value and source_value[0] == "token" and source.strip() in ("0x20", "32"):
                registers[destination_reg] = ("token-high", [*source_value[1], row["rva"]])
            else:
                registers.pop(destination_reg, None)
        elif mnemonic == "and" and destination_reg:
            source_value = registers.get(destination_reg)
            if source_value and source_value[0] == "token-high" and source.strip() in ("0xf", "15"):
                registers[destination_reg] = ("stream-id", [*source_value[1], row["rva"]])
            else:
                registers.pop(destination_reg, None)
        elif destination_reg:
            registers.pop(destination_reg, None)
        elif destination_stack is not None:
            stack.pop(destination_stack, None)

    # The helper is a native uint32 stream function, so Win64 passes the first
    # argument in ECX. Require the resolver to establish it from token bits.
    value = registers.get("c")
    if not value or value[0] != "stream-id":
        raise ValueError("Resolver call to bound stream-delta function does not receive its token stream id in ECX")
    evidence_rvas = [*value[1], call["rva"]]
    if any(rva not in dominators.get(call["rva"], set()) for rva in evidence_rvas):
        raise ValueError("Resolver stream-id argument dataflow is not dominated by the token decode on every call path")
    return {"calling_convention_argument": "ECX (Win64 first integer argument)",
            "value": "(token >> 32) & 0xf", "instruction_rvas": evidence_rvas,
            "basis": "qword token load from resolver field, shift by 32, mask to four-bit stream id, then register/stack move into ECX"}


def _rip_global(rows: list[dict[str, Any]], *, register: str | None = None,
                index_scale: int | None = None) -> list[int]:
    result = []
    for row in rows:
        for mem in row["memory_operands"]:
            if "target_rva" not in mem:
                continue
            if register is not None and mem["base"] != register:
                continue
            if index_scale is not None and mem["scale"] != index_scale:
                continue
            result.append(mem["target_rva"])
    return sorted(set(result))


def _leading_register(op_str: str, mnemonic: str) -> str | None:
    import re
    match = re.match(r"\s*(\w+),", op_str.lower())
    return match.group(1) if match else None


def _state_displacements(rows: list[dict[str, Any]], state_register: str,
                        postload_flag_rva: int) -> dict[str, Any]:
    accesses: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        for mem in row["memory_operands"]:
            if mem["base"] == state_register and mem["index"] is None:
                accesses.setdefault(mem["disp"], []).append({
                    "instruction_rva": row["rva"], "bytes": row["bytes"],
                    "mnemonic": row["mnemonic"], "op_str": row["op_str"],
                    "width": mem["size"],
                })

    def one(offset: int, label: str, width: int = 4) -> dict[str, Any]:
        evidence = accesses.get(offset, [])
        if not evidence:
            raise ValueError(f"Could not derive {label} displacement from target code")
        if not any(row["width"] == width for row in evidence):
            raise ValueError(f"{label} access width differs from expected {width}")
        return {"offset": offset, "width": width, "evidence": evidence}

    indexed = [
        {"offset": mem["disp"], "width": mem["size"], "stride": mem["scale"],
         "instruction_rva": row["rva"], "bytes": row["bytes"],
         "mnemonic": row["mnemonic"], "op_str": row["op_str"]}
        for row in rows for mem in row["memory_operands"]
        if mem["base"] == state_register and mem["index"] is not None and mem["size"] == 4
    ]
    entry_strides = {row["stride"] for row in indexed}
    fields_by_offset: dict[int, list[dict[str, Any]]] = {}
    for row in indexed:
        fields_by_offset.setdefault(row["offset"], []).append(row)
    if entry_strides != {8} or set(fields_by_offset) != {0, 4} or any(
            row["width"] != 4 for values in fields_by_offset.values() for row in values):
        raise ValueError("Indexed history row stride/field widths are not uniquely instruction-proven")

    flag_cmp = [row for row in rows if row["mnemonic"] == "cmp" and
                postload_flag_rva in row["rip_targets"] and "0" in row["op_str"].split(",")[-1]]
    if len(flag_cmp) != 1:
        raise ValueError("Postload-mode compare is missing or ambiguous")
    cmp_row = flag_cmp[0]
    branch_rows = [row for row in rows if row["rva"] >= cmp_row["next_rva"] and
                   row["rva"] <= cmp_row["next_rva"] + 16 and
                   row["mnemonic"] in ("je", "jz", "jne", "jnz")]
    if len(branch_rows) != 1:
        raise ValueError("Postload-mode compare is not followed by a supported conditional branch")
    branch = branch_rows[0]
    if len(branch["direct_branch_rvas"]) != 1:
        raise ValueError("Postload-mode branch target is not a direct unique address")
    branch_target = branch["direct_branch_rvas"][0]
    by_rva = {row["rva"]: row for row in rows}

    def first_eax_scalar(start: int) -> int:
        visited: set[int] = set()
        current = start
        while current in by_rva and current not in visited:
            visited.add(current)
            row = by_rva[current]
            if row["mnemonic"] == "mov" and row["op_str"].lower().startswith("eax, dword ptr"):
                matches = [mem for mem in row["memory_operands"]
                           if mem["base"] == state_register and mem["index"] is None and mem["size"] == 4]
                if len(matches) == 1:
                    return matches[0]["disp"]
            if row["mnemonic"].startswith("ret") or row["mnemonic"] == "jmp":
                if row["mnemonic"] == "jmp" and len(row["direct_branch_rvas"]) == 1:
                    current = row["direct_branch_rvas"][0]
                    continue
                break
            current = row["next_rva"]
        raise ValueError("Could not identify the scalar loaded on one postload branch")

    taken_offset = first_eax_scalar(branch_target)
    fallthrough_offset = first_eax_scalar(branch["next_rva"])
    if taken_offset == fallthrough_offset:
        raise ValueError("Postload branch paths do not select distinct state fields")
    # The compare is against zero: equality selects the zero-mode (ordinary
    # load) history count; inequality selects the postload walk cursor.
    taken_is_zero = branch["mnemonic"] in ("je", "jz")
    count_offset = taken_offset if taken_is_zero else fallthrough_offset
    walk_offset = fallthrough_offset if taken_is_zero else taken_offset

    direct_accesses = {offset: values for offset, values in accesses.items()}
    current_values = sorted({mem["disp"] for row in rows if row["mnemonic"] == "mov" and
        row["op_str"].lower().startswith("ebx, dword ptr") for mem in row["memory_operands"]
        if mem["base"] == state_register and mem["index"] is None and mem["size"] == 4})
    last_values = sorted({mem["disp"] for row in rows if row["mnemonic"] == "cmp" and
        row["op_str"].lower().startswith("r11d, dword ptr") for mem in row["memory_operands"]
        if mem["base"] == state_register and mem["index"] is None and mem["size"] == 4})
    if len(current_values) != 1 or len(last_values) != 1:
        raise ValueError("Current-rewind or last-expected scalar is ambiguous")
    return {
        "history_count": one(count_offset, "historyCount"),
        "current_rewind": one(current_values[0], "currentRewind"),
        "history_walk_index": one(walk_offset, "historyWalkIndex"),
        "last_expected_offset": one(last_values[0], "lastExpectedOffset"),
        "history_entries": {"base_offset": 0, "stride": 8,
            "start_expected_offset": {"offset": 0, "width": 4,
                "evidence": fields_by_offset[0]},
            "rewind_value": {"offset": 4, "width": 4,
                "evidence": fields_by_offset[4]},
            "end_offset_or_discard_range": "not accessed by the analyzed adjustment helper"},
        "mode_branch": {"compare": cmp_row, "branch": branch,
            "zero_mode_role": "history_count", "nonzero_mode_role": "history_walk_index"},
        "unclassified_state_accesses": [
            {"offset": offset, "accesses": values}
            for offset, values in sorted(accesses.items())
            if offset not in {count_offset, current_values[0], walk_offset, last_values[0]}
        ],
    }


def _discover_from_instruction_rows(adjust: list[dict[str, Any]], resolve: list[dict[str, Any]],
                                    relative_base: list[dict[str, Any]], fix: list[dict[str, Any]],
                                    end_load: list[dict[str, Any]], pe: Any,
                                    image_base: int) -> dict[str, Any]:
    # DB_AdjustPackedOffset loads a stream-indexed pointer from an RIP-relative
    # table using 8-byte entries. Keep the instruction evidence that proves
    # both the global base and indexed load.
    table_candidates = []
    for index, row in enumerate(adjust[:-1]):
        for mem in row["memory_operands"]:
            if "target_rva" not in mem:
                continue
            reg = None
            reg = _leading_register(row["op_str"], row["mnemonic"])
            if row["mnemonic"] != "lea" or not any(mem.get("target_rva") is not None
                    for mem in row["memory_operands"]):
                reg = None
            if not reg:
                continue
            following = adjust[index + 1]
            for load in following["memory_operands"]:
                if load["base"] == reg and load["index"] is not None and load["scale"] == 8:
                    table_candidates.append((mem["target_rva"], row, following, load))
    if len({candidate[0] for candidate in table_candidates}) != 1:
        raise ValueError("Could not uniquely derive the per-stream rewind pointer table")
    table_rva = table_candidates[0][0]
    table_evidence = [{"instruction_rva": row["rva"], "bytes": row["bytes"],
                       "op_str": row["op_str"]}
                      for _, row, _, _ in table_candidates]

    # The resolver's relative flag calls this helper; the helper indexes a
    # dword table by stream ID. Its RIP-relative global is the expected asset
    # start-offset array used to encode tag-0x15 pointers.
    relative_array = []
    for row in relative_base:
        for mem in row["memory_operands"]:
            if mem.get("target_rva") is None:
                continue
            if row["mnemonic"] == "lea" and mem["scale"] == 1:
                target = mem["target_rva"]
                if any(other["base"] == _leading_register(row["op_str"], "lea")
                       and other["index"] is not None and other["scale"] == 4
                       for candidate in relative_base for other in candidate["memory_operands"]):
                    relative_array.append((target, row))
    if len({target for target, _ in relative_array}) != 1:
        raise ValueError("Could not derive the asset-relative expected-start table")
    rel_rva, rel_ins = relative_array[0]

    # The one-byte compare against zero controls which of the two state fields
    # is read. This binds the mode byte by width and branch use, not by name.
    postload_flag_operands = [mem for row in adjust if row["mnemonic"] == "cmp" and
        "0" in row["op_str"].split(",")[-1] for mem in row["memory_operands"]
        if mem.get("target_rva") is not None and mem["size"] == 1]
    if len(postload_flag_operands) != 1:
        raise ValueError("Postload/history-mode byte is not uniquely instruction-proven")
    postload_flag_rva = postload_flag_operands[0]["target_rva"]

    # DB_PatchMem_FixStreamAlignment exposes streamPosGlob.posIndex, actual
    # cursor, and archive-block data table via RIP/base-relative operands.
    cursor_globals = [target for row in fix for target in row["rip_targets"]
                      if row["mnemonic"] == "mov" and row["op_str"].lower().startswith("r10,")]
    index_globals = [target for row in fix for target in row["rip_targets"]
                     if row["mnemonic"] == "mov" and row["op_str"].lower().startswith("edx,")]
    block_table_rva = None
    block_evidence = []
    for row in fix:
        if row["mnemonic"] != "lea":
            continue
        for mem in row["memory_operands"]:
            if mem.get("target_rva") is not None:
                continue
        # Target block base uses an image-base register plus a static disp,
        # followed by streamIndex*16. Extract that pair from textual evidence.
    import re
    base_leas = [row for row in fix if row["mnemonic"] == "lea" and
                 any(mem.get("target_rva") == 0 for mem in row["memory_operands"])]
    block_rows = [row for row in fix if row["mnemonic"] == "lea" and
                  any(mem.get("target_rva") is None and mem["base"] not in (None, "rip")
                      and mem["disp"] > 0 for mem in row["memory_operands"])]
    if base_leas and block_rows:
        # The image-base lea resolves to RVA 0; the following lea displacement
        # is therefore the archive block table RVA. Its use is corroborated by
        # a preceding `shl rax,4` and `add base,index` sequence.
        for row in block_rows:
            mem = next(mem for mem in row["memory_operands"] if mem.get("target_rva") is None
                       and mem["base"] not in (None, "rip") and mem["disp"] > 0)
            if mem and any(other["mnemonic"] == "shl" and "0x4" in other["op_str"].lower()
                             for other in fix):
                block_table_rva = mem["disp"]
                block_evidence.append({"instruction_rva": row["rva"], "bytes": row["bytes"],
                                       "op_str": row["op_str"], "stride": 16})
    if not cursor_globals or not index_globals:
        raise ValueError("Could not bind current stream cursor/index globals")

    displacements = _state_displacements(adjust, "r10", postload_flag_rva)
    prefix_proof = _derive_verified_pointer_prefix(end_load, table_rva)
    # The token decoder proves only the encodable index domain. It does not
    # prove the allocation length of either array, and mapped image extent or
    # neighboring globals cannot establish the array count.
    token_domain_proven = any(row["mnemonic"] == "and" and
        row["op_str"].lower().startswith("ebx,") and
        row["op_str"].lower().endswith("0xf") for row in resolve)
    allocation_count = None
    history_stride = displacements["history_entries"]["stride"]
    first_scalar = min(displacements[name]["offset"] for name in
        ("history_count", "current_rewind", "history_walk_index", "last_expected_offset"))
    first_scalar_names = [name for name in
        ("history_count", "current_rewind", "history_walk_index", "last_expected_offset")
        if displacements[name]["offset"] == first_scalar]
    if len(first_scalar_names) != 1:
        raise ValueError("First scalar boundary for bounded history capture is ambiguous")
    first_scalar_name = first_scalar_names[0]

    return {
        "rewind_pointer_table": {
            "rva": table_rva, "entry_stride": 8,
            "adjacent_relative_start_table_rva": rel_rva,
            "count": allocation_count,
            "count_status": "unproved; no explicit allocation length or checked table bound",
            "encoded_index_domain": {"maximum": 15, "proved": token_domain_proven},
            "verified_prefix_count": prefix_proof["verified_prefix_count"],
            "allocation_count": None,
            "full_table_count_unknown": True,
            "coverage": "verified-prefix",
            "prefix_proof": prefix_proof,
            "evidence": table_evidence,
        },
        "rewind_record": displacements,
        "asset_relative_expected_start_table": {
            "rva": rel_rva, "entry_stride": 4, "count": allocation_count,
            "count_status": "unproved; no explicit allocation length or checked table bound",
            "evidence": [{"instruction_rva": rel_ins["rva"], "bytes": rel_ins["bytes"],
                          "op_str": rel_ins["op_str"]}],
        },
        "postload_mode_flag": {"rva": postload_flag_rva, "width": 1,
                               "evidence": [row for row in adjust if postload_flag_rva in row["rip_targets"]]},
        "stream_globals": {
            "actual_cursor_pointer_rvas": sorted(set(cursor_globals)),
            "active_stream_index_rvas": sorted(set(index_globals)),
            "archive_block_table_rva": block_table_rva,
            "archive_block_entry_stride": 16 if block_table_rva is not None else None,
            "archive_block_evidence": block_evidence,
            "evidence": [{"instruction_rva": row["rva"], "bytes": row["bytes"],
                          "op_str": row["op_str"]}
                         for row in fix if row["rip_targets"]],
        },
        "limits": [
            "The token encodes a four-bit stream index, but the table allocation lengths are not proven; adjacency or mapped section extent is not used as an entry count.",
            "The target adjustment helper reads 8-byte history rows as startExpectedOffset and rewind; it does not read discard end offsets or forAsset flags.",
            "The asset-relative table is indexed at 4-byte stride but its allocation extent is unproved and is omitted from capture_layout.",
            "Only the verified pointer-table prefix is capturable; the full table count and stream IDs beyond that prefix remain unknown.",
            "No current-asset stack depth or frame layout is derived here; only the expected-start array consumed by relative-token resolution is bound.",
        ],
        "capture_layout": {
            "pointer_table_rva": table_rva, "pointer_stride": 8,
            "stream_count": prefix_proof["verified_prefix_count"],
            "allocation_count": None,
            "full_table_count_unknown": True,
            "coverage": "verified-prefix",
            "pointer_table_proof": prefix_proof,
            "history": {"offset": 0, "stride": displacements["history_entries"]["stride"],
                "capacity": None,
                "max_capture_entries": first_scalar // history_stride,
                "bound_kind": "non-overlap-read-bound",
                "bound_evidence": {"first_scalar_name": first_scalar_name,
                    "first_scalar_offset": first_scalar,
                    "instruction_evidence": displacements[first_scalar_name]["evidence"]},
                "fields": {"start_expected_offset": {"offset": 0, "size": 4},
                           "rewind": {"offset": 4, "size": 4}}},
            "scalars": {"history_count": {"offset": displacements["history_count"]["offset"], "size": 4},
                "current_rewind": {"offset": displacements["current_rewind"]["offset"], "size": 4},
                "history_walk_index": {"offset": displacements["history_walk_index"]["offset"], "size": 4},
                "last_expected_offset": {"offset": displacements["last_expected_offset"]["offset"], "size": 4}},
            "globals": {"postload": {"rva": postload_flag_rva, "size": 1}},
        },
    }


def discover_bindings(executable: Path, build_report_path: Path,
                      catalog_path: Path) -> dict[str, Any]:
    executable = executable.resolve(strict=True)
    build_report_path = build_report_path.resolve(strict=True)
    catalog_path = catalog_path.resolve(strict=True)
    build, build_raw = _json(build_report_path)
    catalog, catalog_raw = _json(catalog_path)
    exe_hash = sha256_file(executable)
    # The staged copy may live beside the game executable. Exact byte identity
    # is the binding; the historical source path in the report is provenance.
    if build.get("sha256") != exe_hash:
        raise ValueError("Build report executable hash does not match target bytes")
    if catalog.get("image_sha256") != build.get("input_sha256"):
        raise ValueError("Catalog image does not match the build report input image")
    profile, profile_path, profile_hash = _profile_for_build(build, build_report_path)
    if profile.get("source_image_sha256") != catalog.get("image_sha256"):
        raise ValueError("Source profile and catalog image identities differ")

    from capstone import x86_const
    import pefile
    pe = pefile.PE(str(executable), fast_load=True)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if image_base != int(catalog.get("image_base", -1)):
        raise ValueError("Executable image base differs from catalog")

    binding_names = ("DB_AdjustPackedOffset", "DB_PatchMem_FixStreamAlignment",
                     "DB_OffsetAliasStreamDelta",
                     "DB_ResolvePackedOffsetAddressInPlace")
    functions = {}
    for name in binding_names:
        binding = _find_profile_binding(profile, name)
        identity = binding.get("symbol_id")
        catalog_row = _function_by_id(catalog, identity)
        compiled_rva = _compiled_symbol(build, name)
        functions[name] = {"symbol_id": identity, "catalog_name": catalog_row.get("name"),
                           "native_rva": int(catalog_row["rva"]), "compiled_rva": compiled_rva,
                           "catalog_aliases": catalog_row.get("aliases", [])}

    # Resolve the relative-start helper from the resolver's direct call edge.
    resolve_start = functions["DB_ResolvePackedOffsetAddressInPlace"]["compiled_rva"]
    adjust_start = functions["DB_AdjustPackedOffset"]["compiled_rva"]
    relative_target = functions["DB_OffsetAliasStreamDelta"]["compiled_rva"]
    fix_start = functions["DB_PatchMem_FixStreamAlignment"]["compiled_rva"]
    end_load_start = _compiled_symbol(build, "DB_PatchMem_EndLoad")
    # A fixed bounded decode followed by entry-reachability avoids truncation
    # at internal labels such as sym_* in the build report.
    resolve = _reachable_function_rows(
        _disassemble(pe, resolve_start, resolve_start + 0x1000, image_base), resolve_start)
    adjust = _reachable_function_rows(
        _disassemble(pe, adjust_start, adjust_start + 0x1000, image_base), adjust_start)
    fix = _reachable_function_rows(
        _disassemble(pe, fix_start, fix_start + 0x1000, image_base), fix_start)
    end_load = _reachable_function_rows(
        _disassemble(pe, end_load_start, end_load_start + 0x1000, image_base), end_load_start)

    # The exact profile/catalog binding identifies the stream-delta function;
    # require a reachable resolver call, decoded token-stream argument flow,
    # and that function's RIP-relative 4-byte stream-indexed table signature.
    helper_rows = _reachable_function_rows(
        _disassemble(pe, relative_target, relative_target + 0x100, image_base), relative_target)
    relative_table_evidence = _relative_stream_table_evidence(helper_rows)
    relative_calls = [row for row in resolve if relative_target in row["direct_call_rvas"]]
    if len(relative_calls) != 1:
        raise ValueError("Resolver must have one reachable direct call to its profile-bound stream-delta function")
    relative_call_argument = _relative_stream_call_argument(resolve, relative_calls[0])
    relative_base = helper_rows
    resolved = _discover_from_instruction_rows(adjust, resolve, relative_base,
                                               fix, end_load, pe, image_base)
    function_rows = {}
    for name, start, rows in (("DB_AdjustPackedOffset", adjust_start, adjust),
                              ("DB_PatchMem_FixStreamAlignment", fix_start, fix),
                              ("DB_ResolvePackedOffsetAddressInPlace", resolve_start, resolve),
                              ("DB_PatchMem_EndLoad", end_load_start, end_load),
                              ("asset_relative_start_helper", relative_target, relative_base)):
        function_rows[name] = {"start_rva": start,
            "instruction_count": len(rows),
            "instructions_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
            "evidence_scope": "entry-reachable instruction stream; full rows omitted from compact binding receipt"}

    return {
        "schema": "replay-native-rewind-bindings-v1",
        "status": "bindings_discovered_with_explicit_limits",
        "target": {"path": str(executable), "sha256": exe_hash,
                   "image_base": image_base, "build_report_path": str(build_report_path),
                   "build_report_sha256": hashlib.sha256(build_raw).hexdigest(),
                   "catalog_path": str(catalog_path),
                   "catalog_sha256": hashlib.sha256(catalog_raw).hexdigest(),
                   "source_profile_path": str(profile_path), "source_profile_sha256": profile_hash},
        "functions": functions,
        "end_load_function": {"compiled_rva": end_load_start},
        "instruction_evidence": function_rows,
        "relative_start_helper": {"compiled_rva": relative_target,
            "profile_binding": functions["DB_OffsetAliasStreamDelta"],
            "call_edge_evidence": relative_calls,
            "call_argument_dataflow": relative_call_argument,
            "stream_table_access": relative_table_evidence},
        "bindings": {key: value for key, value in resolved.items() if key != "capture_layout"},
        "capture_layout": resolved["capture_layout"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, default=DEFAULT_BUILD_REPORT)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = discover_bindings(args.exe, args.build_report, args.catalog)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "output": str(args.output),
                      "rewind_table_rva": manifest["bindings"]["rewind_pointer_table"]["rva"],
                      "rewind_table_allocation_count": manifest["bindings"]["rewind_pointer_table"]["count"],
                      "verified_prefix_count": manifest["capture_layout"]["stream_count"],
                      "coverage": manifest["capture_layout"]["coverage"],
                      "full_table_count_unknown": manifest["capture_layout"]["full_table_count_unknown"]}))


if __name__ == "__main__":
    main()
