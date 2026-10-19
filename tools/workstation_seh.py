"""Fail-closed Win64 handler-data rendering for workstation assembly edits.

The assembly backend owns code layout and labels. This module serializes
recovered scope metadata only through symbolic labels, then verifies that LLVM
emitted the expected PE/COFF exception-handler relocations. It deliberately
does not accept numeric RVAs in generated handler tables.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import coff


_SYMBOL = re.compile(r"(?:fn_[0-9a-f]{16}|sym_[0-9a-f]{16}|L_[A-Za-z0-9_$]+)\Z")
_LABEL = re.compile(r"L_[A-Za-z0-9_$]+\Z")
_ADDR32NB = 3


@dataclass(frozen=True)
class ScopeRecord:
    """One recovered SCOPE_TABLE entry, expressed with emitted-code labels."""

    begin: str
    end: str
    handler: str | None
    jump_target: str | None


@dataclass(frozen=True)
class RvaField:
    """A 32-bit image-relative field targeting an emitted label/function."""

    target: str


def _valid_symbol(value: str, *, label_only: bool = False) -> str:
    if not isinstance(value, str) or not _SYMBOL.fullmatch(value):
        raise ValueError(f"Expected a stable function ID or emitted label, got {value!r}")
    if label_only and not _LABEL.fullmatch(value):
        raise ValueError(f"Expected an emitted-code label, got {value!r}")
    return value


def render_rva_fields(fields: list[int | RvaField]) -> list[str]:
    """Render typed handler-data words; references become real ADDR32NB relocs."""
    output = []
    for value in fields:
        if isinstance(value, RvaField):
            output.append(f".long {_valid_symbol(value.target)}@IMGREL")
        elif isinstance(value, int) and 0 <= value <= 0xFFFFFFFF:
            output.append(f".long 0x{value:08x}")
        else:
            raise ValueError(f"Handler-data integer is outside uint32: {value!r}")
    return output


def render_scope_handler(handler_id: str, records: list[ScopeRecord], *,
                         label_order: list[str], flags: int = 1) -> str:
    """Emit an MSVC C-specific scope table with code bounds resolved by labels.

    `label_order` is the ordered list of labels in the edited function. The
    caller derives each label from a recovered source boundary; this function
    refuses missing/reordered boundaries rather than writing numeric RVAs.
    """
    handler_id = _valid_symbol(handler_id)
    if not handler_id.startswith("fn_"):
        raise ValueError("A native exception handler must use its stable function-catalog ID")
    if flags not in (1, 3):
        raise ValueError("C-specific scope tables require exception-handler flags 1 or 3")
    if len(records) > 100000:
        raise ValueError("Unreasonable scope-table record count")
    order = {}
    for index, label in enumerate(label_order):
        label = _valid_symbol(label, label_only=True)
        if label in order:
            raise ValueError(f"Duplicate emitted label: {label}")
        order[label] = index
    words: list[int | RvaField] = [len(records)]
    for record in records:
        begin = _valid_symbol(record.begin, label_only=True)
        end = _valid_symbol(record.end, label_only=True)
        target = _valid_symbol(record.jump_target, label_only=True) if record.jump_target else None
        handler = _valid_symbol(record.handler) if record.handler else None
        if begin not in order or end not in order or (target and target not in order):
            raise ValueError("Every scope code boundary must resolve to an emitted label")
        if order[begin] >= order[end]:
            raise ValueError("Scope end label must follow its begin label")
        words.extend((RvaField(begin), RvaField(end), RvaField(handler) if handler else 0,
                      RvaField(target) if target else 0))
    handler_flags = ", @except" + (", @unwind" if flags & 2 else "")
    lines = [f".seh_handler {handler_id}{handler_flags}", ".seh_handlerdata"]
    lines.extend(render_rva_fields(words))
    # LLVM's integrated assembler requires leaving the handler-data section
    # before the matching .seh_endproc directive.
    lines.append(".text")
    return "\n".join(lines)


def render_cpp_funcinfo_handler(handler_id: str, funcinfo_id: str, *, flags: int) -> str:
    """Emit C++ handler data through a stable catalog identity, never a raw RVA."""
    handler_id = _valid_symbol(handler_id)
    funcinfo_id = _valid_symbol(funcinfo_id)
    if not handler_id.startswith("fn_"):
        raise ValueError("A native language handler must use a stable function identity")
    if not (funcinfo_id.startswith("sym_") or funcinfo_id.startswith("L_")):
        raise ValueError("C++ FuncInfo must use a stable data identity or generated label")
    if flags not in (1, 2, 3):
        raise ValueError("Win64 handler flags must select EHANDLER and/or UHANDLER")
    handler_flags = []
    if flags & 1:
        handler_flags.append("@except")
    if flags & 2:
        handler_flags.append("@unwind")
    return "\n".join([f".seh_handler {handler_id}, " + ", ".join(handler_flags),
                       ".seh_handlerdata", f".long {funcinfo_id}@IMGREL", ".text"])


def llvm_bin() -> Path:
    configured = os.environ.get("REPLAY_LLVM_ROOT")
    candidates = []
    if configured:
        path = Path(configured).expanduser()
        candidates.extend((path, path / "bin"))
    found = shutil.which("clang")
    if found:
        candidates.append(Path(found).parent)
    candidates.append(Path(r"C:\Program Files\LLVM\bin"))
    for path in candidates:
        if (path / "clang.exe").is_file():
            return path.resolve()
        if (path / "clang").is_file():
            return path.resolve()
    raise FileNotFoundError("LLVM clang not found; set REPLAY_LLVM_ROOT to the LLVM root or bin directory")


def compile_and_verify(source: str) -> dict:
    """Assemble a fixture and verify the real COFF exception metadata shape."""
    with tempfile.TemporaryDirectory(prefix="replay-workstation-seh-") as directory:
        root = Path(directory)
        assembly = root / "handler.s"
        obj_path = root / "handler.obj"
        assembly.write_text(source, encoding="ascii", newline="\n")
        compiler = llvm_bin() / "clang.exe"
        subprocess.run([str(compiler), "--target=x86_64-pc-windows-msvc", "-c", "-x", "assembler",
                        str(assembly), "-o", str(obj_path)], check=True, capture_output=True, text=True)
        obj = coff.read(obj_path)
        xdata = [section for section in obj["sections"] if section["name"] == ".xdata"]
        pdata = [section for section in obj["sections"] if section["name"] == ".pdata"]
        if len(xdata) != 1 or len(pdata) != 1 or len(pdata[0]["data"]) != 12:
            raise ValueError("Expected one function .pdata record and one .xdata section")
        report = verify_handler_object(obj)
        if report is None:
            raise ValueError("COFF function has no regenerated exception-handler record")
        return {"object_size": obj_path.stat().st_size, **report, "passed": True}


def verify_handler_object(obj: dict) -> dict | None:
    """Validate compiler-emitted handler RVAs in an already parsed COFF object."""
    xdata = [section for section in obj["sections"] if section["name"] == ".xdata" and section["data"]]
    if not xdata:
        return None
    if len(xdata) != 1:
        raise ValueError("Assembly replacement must emit one .xdata section")
    payload = xdata[0]["data"]
    if len(payload) < 4 or payload[0] & 7 not in (1, 2):
        raise ValueError("COFF unwind record has an invalid header")
    # Ordinary compiler unwind records have no language handler data.
    if payload[0] >> 3 & 3 == 0:
        return None
    if not (payload[0] >> 3) & 3:
        raise ValueError("COFF unwind record has malformed exception-handler metadata")
    slots = payload[2]
    handler_field = 4 + ((slots + 1) & ~1) * 2
    if handler_field + 4 > len(payload):
        raise ValueError("Truncated COFF handler data")
    relocations = xdata[0]["relocations"]
    if not relocations or any(kind != _ADDR32NB for _, _, kind in relocations):
        raise ValueError("Handler addresses must use image-relative ADDR32NB relocations")
    offsets = {offset for offset, _, _ in relocations}
    if handler_field not in offsets:
        raise ValueError("The handler RVA relocation is missing")
    handler_reloc = next((symbol for offset, symbol, _ in relocations if offset == handler_field), None)
    handler_symbol = obj["symbols"].get(handler_reloc, {}).get("name")
    if not handler_symbol or not handler_symbol.startswith("fn_"):
        raise ValueError("Language-handler reference is not a stable native function symbol")
    # The recovered MSVC C++ EH record carries a single RVA to FuncInfo.
    # Scope tables instead begin with an integer count and have no relocation
    # at this word. Stable data identities keep the source independent of RVA.
    if handler_field + 4 in offsets:
        funcinfo_reloc = next(symbol for offset, symbol, _ in relocations
                              if offset == handler_field + 4)
        funcinfo_symbol = obj["symbols"].get(funcinfo_reloc, {}).get("name", "")
        if not (re.fullmatch(r"sym_[0-9a-f]{16}", funcinfo_symbol) or
                re.fullmatch(r"L_[A-Za-z0-9_$]+", funcinfo_symbol)):
            raise ValueError("C++ FuncInfo reference is not a stable identity or generated label")
        if len(payload) != handler_field + 8:
            raise ValueError("Unexpected bytes after the C++ FuncInfo language-data pointer")
        return {"xdata_size": len(payload), "handler_field_offset": handler_field,
                "handler_symbol": handler_symbol, "language_data": "cpp-funcinfo",
                "handler_flags": payload[0] >> 3 & 3,
                "funcinfo_symbol": funcinfo_symbol, "addr32nb_relocations": len(relocations),
                "passed": True}
    scope_count = int.from_bytes(payload[handler_field+4:handler_field+8], "little")
    if scope_count > 100000:
        raise ValueError("Invalid emitted scope-table count")
    expected_end = handler_field + 8 + scope_count * 16
    if expected_end > len(payload):
        raise ValueError("Truncated emitted scope table")
    required_scope_relocs = {handler_field + 8 + i * 4
                             for i in range(scope_count * 4) if i % 4 != 3}
    # Jump-target fields can be the literal zero sentinel. Every other
    # scope member must be relocated to a label/function.
    if not required_scope_relocs.issubset(offsets):
        raise ValueError("One or more scope-table RVA fields lack COFF relocations")
    return {"xdata_size": len(payload), "handler_field_offset": handler_field,
            "handler_symbol": handler_symbol, "scope_count": scope_count,
            "handler_flags": payload[0] >> 3 & 3,
            "addr32nb_relocations": len(relocations), "scope_table_end": expected_end,
            "passed": True}
