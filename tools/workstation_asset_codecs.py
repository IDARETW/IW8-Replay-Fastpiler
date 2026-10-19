"""Replay 1.20 editable asset codecs.

The input to these codecs is a typed asset body emitted by the fastfile
extractor. This module deliberately does not discover byte ranges inside an
opaque fastfile; that belongs to the typed reader in workstation_fastfiles.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import csv
import io
import re
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import struct
import zlib


GSCBIN_MAGIC = 0x00435347
MAX_GSCBIN_SECTION = 64 << 20
DEFAULT_SAB_GENERATOR = Path("__REPLAY_SAB_GENERATOR_NOT_CONFIGURED__")
SAB_MAGIC = 0x23585532
SAB_HEADER_SIZE = 688
SAB_ENTRY_SIZE = 44
SAB_CHECKSUM_SIZE = 16
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LUAJIT_DECOMPILER = ROOT / "tools" / "bin" / "luajit-decompiler-v2.exe"
DEFAULT_LUAJIT_DECOMPILER_SHA256 = "52742bb206108880c20ba0a147e2be7690bbd9181a735e63047bd01bbc54eae6"
DEFAULT_ACTS = Path("__REPLAY_ACTS_NOT_CONFIGURED__")
DEFAULT_REPLAY_EXECUTABLE = Path("__REPLAY_EXECUTABLE_NOT_CONFIGURED__")
DEFAULT_REPLAY_ACTS = Path("__REPLAY_ACTS_NOT_CONFIGURED__")
DEFAULT_REPLAY_LUA_PROFILE_NAME = "replay120_lua_native"
DEFAULT_REPLAY_LUA_PROFILE = DEFAULT_REPLAY_ACTS.parent / f"{DEFAULT_REPLAY_LUA_PROFILE_NAME}.json"
REPLAY_LUA_IMAGE_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
DEFAULT_GSC_TOOL = Path(os.environ.get(
    "REPLAY_GSC_TOOL", str(Path(__file__).resolve().parent / "bin" / "gsc-tool-1.5.1" / "gsc-tool.exe")))
LUAJIT_MAGIC = b"\x1bLJ\x02"
DEFAULT_DXBC_TOOL = ROOT / "tools" / "bin" / "cmd_Decompiler-1.3.16" / "cmd_Decompiler.exe"
DEFAULT_DXBC_TOOL_SHA256 = "67582ced9261b8fb23a50cee09c788c821d0524d40264721369b410d5321dab8"
DEFAULT_TEXCONV_TOOL = ROOT / "tools" / "bin" / "texconv-may2026.exe"
DEFAULT_TEXCONV_TOOL_SHA256 = "dcfdec10244e02cf5037fba089c55fb7e1326b1c8181742d77d15fa5cb5eef06"
DDS_MAGIC = b"DDS "
DDS_HEADER_SIZE = 124
DDS_DX10_HEADER_SIZE = 20


def _codec_tool(value, variable: str, fallback: Path, reviewed_hash: str | None = None) -> Path:
    """Select the configured tool at call time, including after server imports."""
    if value is None and not os.environ.get(variable) and fallback.name.startswith("__REPLAY_"):
        raise ValueError(f"{variable} is not configured; run setup-workstation.ps1 or set {variable}")
    tool = Path(value or os.environ.get(variable) or fallback).expanduser().resolve()
    configured = os.environ.get(variable)
    expected = os.environ.get(variable + '_SHA256') if (
        value is None or configured and tool == Path(configured).expanduser().resolve()) else None
    if tool == fallback.resolve() and reviewed_hash:
        expected = reviewed_hash
    if expected and tool.is_file() and hashlib.sha256(tool.read_bytes()).hexdigest() != expected.casefold():
        raise ValueError(f"Configured {variable} binary hash differs from its setup receipt")
    return tool

# Replay GfxPixelFormat to DXGI_FORMAT mappings supported by the verified
# compressed-image pipeline. Other texture formats are rejected explicitly.
_REPLAY_BC_DXGI = {
    33: 71, 34: 72, 35: 74, 36: 75, 37: 77, 38: 78,
    39: 80, 40: 83, 41: 84, 42: 95, 43: 96, 44: 98, 45: 99,
}
_DXGI_REPLAY_BC = {dxgi: replay for replay, dxgi in _REPLAY_BC_DXGI.items()}
_REPLAY_LINEAR_DXGI = {6: 28, 7: 29}  # RGBA8 UNORM / sRGB.
_DXGI_REPLAY_LINEAR = {dxgi: replay for replay, dxgi in _REPLAY_LINEAR_DXGI.items()}
_DXGI_REPLAY = {**_DXGI_REPLAY_BC, **_DXGI_REPLAY_LINEAR}
_BC_BLOCK_BYTES = {
    33: 8, 34: 8, 35: 16, 36: 16, 37: 16, 38: 16, 39: 8,
    40: 16, 41: 16, 42: 16, 43: 16, 44: 16, 45: 16,
}
_LINEAR_PIXEL_BYTES = {6: 4, 7: 4}
_REPLAY_DXGI_NAMES = {
    6: "R8G8B8A8_UNORM", 7: "R8G8B8A8_UNORM_SRGB",
    33: "BC1_UNORM", 34: "BC1_UNORM_SRGB", 35: "BC2_UNORM",
    36: "BC2_UNORM_SRGB", 37: "BC3_UNORM", 38: "BC3_UNORM_SRGB",
    39: "BC4_UNORM", 40: "BC5_UNORM", 41: "BC5_SNORM",
    42: "BC6H_UF16", 43: "BC6H_SF16", 44: "BC7_UNORM",
    45: "BC7_UNORM_SRGB",
}


@dataclass(frozen=True)
class GscbinInfo:
    source_size: int
    bytecode_size: int
    source_bytes: bytes
    bytecode: bytes
    compressed_source: bytes


@dataclass(frozen=True)
class LuaJitInfo:
    version: int
    flags: int
    stripped: bool
    ffi: bool
    fr2: bool
    payload_offset: int


def inspect_luajit_bytecode(blob: bytes) -> LuaJitInfo:
    """Validate the known LuaJIT v2 envelope of a Replay LuaFile body."""
    if not isinstance(blob, bytes) or len(blob) < 5 or blob[:4] != LUAJIT_MAGIC:
        raise ValueError("LuaFile is not a LuaJIT bytecode v2 chunk")
    flags = blob[4]
    if flags & ~0x0F:
        raise ValueError(f"LuaJIT chunk has unsupported flag bits 0x{flags:02x}")
    if len(blob) == 5:
        raise ValueError("LuaJIT chunk has no prototype payload")
    return LuaJitInfo(2, flags, bool(flags & 0x02), bool(flags & 0x04),
                      bool(flags & 0x08), 5)


def decompile_luajit_bytecode(blob: bytes, *, name: str = "asset",
                              decompiler: Path | None = None) -> str:
    """Render a Replay LuaJIT v2 chunk as editable Lua source.

    This is an editing view, not a bytecode-preserving round trip. A target
    matched compiler is still required to rebuild a LuaFile.
    """
    inspect_luajit_bytecode(blob)
    try:
        from workstation_luajit_chunk import split_luajit_file_payload
    except ModuleNotFoundError:
        from tools.workstation_luajit_chunk import split_luajit_file_payload
    boundary = split_luajit_file_payload(blob)
    # Strip only the optional outer LuaFile NUL. The structural parser keeps
    # the LuaJIT zero-length-prototype marker inside the chunk; no byte is
    # appended or removed based only on the file's last byte.
    decompiler_payload = boundary.chunk
    decompiler = _codec_tool(decompiler, 'REPLAY_LUAJIT_DECOMPILER', DEFAULT_LUAJIT_DECOMPILER,
                            DEFAULT_LUAJIT_DECOMPILER_SHA256)
    if not decompiler.is_file():
        raise FileNotFoundError(f"LuaJIT decompiler is unavailable: {decompiler}")
    if decompiler.resolve() == DEFAULT_LUAJIT_DECOMPILER.resolve():
        digest = hashlib.sha256(decompiler.read_bytes()).hexdigest()
        if digest != DEFAULT_LUAJIT_DECOMPILER_SHA256:
            raise ValueError("Pinned LuaJIT decompiler hash does not match the reviewed tool")
    with tempfile.TemporaryDirectory(prefix="replay-luajit-decompile-") as temporary:
        root = Path(temporary)
        safe_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "asset"
        source = root / f"{safe_stem}.luac"
        output = root / "out"
        output.mkdir()
        source.write_bytes(decompiler_payload)
        try:
            result = subprocess.run(
                [str(decompiler), str(source), "-o", str(output), "-s", "-f"],
                capture_output=True, text=True, timeout=120, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError('LuaJIT decompilation exceeded 120 seconds; no edit was staged') from error
        candidates = list(output.glob("*.lua"))
        if result.returncode != 0 or len(candidates) != 1:
            details = (result.stderr or result.stdout or "no decompiler output").strip()
            raise RuntimeError(f"LuaJIT decompilation failed: {details}")
        try:
            return candidates[0].read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Decompiler output is not valid UTF-8 source") from error


def compile_luajit_source(source: str, *, acts_exe: Path | None = None,
                          replay_executable: Path | None = None,
                          profile_path: Path | None = None,
                          profile_name: str = DEFAULT_REPLAY_LUA_PROFILE_NAME,
                          asset_name: str = "asset") -> bytes:
    """Compatibility wrapper returning just the native LuaFile payload."""
    payload, _receipt = compile_luajit_source_with_receipt(
        source, acts_exe=acts_exe, replay_executable=replay_executable,
        profile_path=profile_path, profile_name=profile_name, asset_name=asset_name)
    return payload


def compile_luajit_source_with_receipt(
        source: str, *, acts_exe: Path | None = None,
        replay_executable: Path | None = None,
        profile_path: Path | None = None,
        profile_name: str = DEFAULT_REPLAY_LUA_PROFILE_NAME,
        asset_name: str = "asset") -> tuple[bytes, dict]:
    """Delegate the legacy public entry point to the canonical compiler."""
    try:
        from workstation_lua_compile import compile_luajit_source_with_receipt as compile_canonical
    except ModuleNotFoundError:
        from tools.workstation_lua_compile import compile_luajit_source_with_receipt as compile_canonical
    return compile_canonical(
        source, acts_exe=acts_exe, replay_executable=replay_executable,
        profile_path=profile_path, profile_name=profile_name, asset_name=asset_name)


@dataclass(frozen=True)
class SabEntry:
    asset_id: int
    sample_bytes: int
    seek_bytes: int
    hybrid_pcm_bytes: int
    flags0: int
    flags1: int
    frame_count: int
    sample_rate: int
    channels: int
    looping: bool
    codec: int
    data_offset: int
    payload_md5: str


@dataclass(frozen=True)
class SabInfo:
    entries: tuple[SabEntry, ...]
    data_offset: int
    file_size: int


def inspect_gscbin(blob: bytes) -> GscbinInfo:
    """Validate and expose the two sections in a native ScriptFile GSCBIN body."""
    if len(blob) < 16:
        raise ValueError("GSCBIN is shorter than its 16-byte header")
    magic, compressed_size, source_size, bytecode_size = struct.unpack_from("<4I", blob)
    if magic != GSCBIN_MAGIC:
        raise ValueError(f"Unexpected GSCBIN magic 0x{magic:08x}")
    if (not 0 < compressed_size <= MAX_GSCBIN_SECTION or
            not 0 < source_size <= MAX_GSCBIN_SECTION or
            not 0 < bytecode_size <= MAX_GSCBIN_SECTION or
            16 + compressed_size + bytecode_size != len(blob)):
        raise ValueError("GSCBIN section sizes are invalid or do not consume the body")
    compressed = blob[16:16 + compressed_size]
    inflater = zlib.decompressobj()
    try:
        source = inflater.decompress(compressed, source_size + 1)
    except zlib.error as error:
        raise ValueError(f"GSCBIN source section is not valid zlib data: {error}") from error
    if (len(source) != source_size or not inflater.eof or inflater.unconsumed_tail or
            inflater.unused_data):
        raise ValueError("GSCBIN compressed source length or stream boundary is invalid")
    bytecode = blob[16 + compressed_size:]
    return GscbinInfo(source_size, bytecode_size, source, bytecode, compressed)


def pack_gscbin_sections(compressed_source: bytes, source_size: int,
                         bytecode: bytes) -> bytes:
    """Repack typed native ScriptFile source/bytecode children as GSCBIN.

    The archive adapter can preserve compressed source and bytecode children
    independently; this function validates their lengths and joins them into
    the standalone body accepted by GSC Tool.
    """
    if (not isinstance(compressed_source, bytes) or not compressed_source or
            not isinstance(bytecode, bytes) or not bytecode or
            not isinstance(source_size, int) or not 0 < source_size <= MAX_GSCBIN_SECTION or
            len(compressed_source) > MAX_GSCBIN_SECTION or len(bytecode) > MAX_GSCBIN_SECTION):
        raise ValueError("ScriptFile child sections have invalid types or lengths")
    body = struct.pack("<4I", GSCBIN_MAGIC, len(compressed_source), source_size,
                       len(bytecode)) + compressed_source + bytecode
    inspect_gscbin(body)
    return body


def inspect_sab_v10(blob: bytes) -> SabInfo:
    """Validate native resident SAB v10 table/checksum bounds and sample extents."""
    if len(blob) < SAB_HEADER_SIZE:
        raise ValueError("SAB bank is shorter than its 688-byte header")
    magic, version, entry_size, checksum_size = struct.unpack_from("<4I", blob)
    if (magic, version, entry_size, checksum_size) != (
            SAB_MAGIC, 10, SAB_ENTRY_SIZE, SAB_CHECKSUM_SIZE):
        raise ValueError("SAB header is not Replay v10 with the verified record sizes")
    count = struct.unpack_from("<I", blob, 20)[0]
    bank_size, index_offset, checksum_offset = struct.unpack_from("<QQQ", blob, 32)
    payload_size = struct.unpack_from("<I", blob, 679)[0]
    if (count > 1_000_000 or bank_size != len(blob) or index_offset < SAB_HEADER_SIZE or
            index_offset + count * SAB_ENTRY_SIZE > len(blob) or checksum_offset < SAB_HEADER_SIZE or
            checksum_offset + count * SAB_CHECKSUM_SIZE > len(blob)):
        raise ValueError("SAB index extents or declared bank size are invalid")
    index_extent = (index_offset, index_offset + count * SAB_ENTRY_SIZE)
    checksum_extent = (checksum_offset, checksum_offset + count * SAB_CHECKSUM_SIZE)
    if (count and (index_extent[0] < checksum_extent[1] and checksum_extent[0] < index_extent[1]) or
            struct.unpack_from("<I", blob, 28)[0] != 16 or payload_size > len(blob) - SAB_HEADER_SIZE):
        raise ValueError("SAB sample payload extent or alignment metadata is invalid")

    entries = []
    intervals = []
    for index in range(count):
        at = index_offset + index * SAB_ENTRY_SIZE
        asset_id, size, seek_bytes, frames, hybrid_bytes, offset, rate, channels, looping, codec = \
            struct.unpack_from("<IIIIIQIBBB", blob, at)
        flags0 = struct.unpack_from("<I", blob, at + 8)[0]
        flags1 = struct.unpack_from("<I", blob, at + 16)[0]
        extent_size = seek_bytes + size + hybrid_bytes
        sample_at = offset + seek_bytes
        if (not asset_id or not size or not frames or not 1 <= rate <= 384_000 or
                channels not in range(1, 9) or looping not in (0, 1) or
                offset < SAB_HEADER_SIZE or offset + extent_size > len(blob) or
                (extent_size and (sample_at < index_extent[1] and index_extent[0] < sample_at + size or
                                  sample_at < checksum_extent[1] and checksum_extent[0] < sample_at + size))):
            raise ValueError(f"SAB entry {index} has invalid sample metadata or payload bounds")
        checksum_at = checksum_offset + index * SAB_CHECKSUM_SIZE
        expected_md5 = blob[checksum_at:checksum_at + SAB_CHECKSUM_SIZE]
        sample = blob[sample_at:sample_at + size]
        if hashlib.md5(sample).digest() != expected_md5:
            raise ValueError(f"SAB entry {index} FLAC payload checksum mismatch")
        intervals.append((offset, offset + extent_size, index))
        entries.append(SabEntry(asset_id, size, seek_bytes, hybrid_bytes, flags0, flags1,
                                frames, rate, channels, bool(looping), codec, offset,
                                expected_md5.hex()))
    intervals.sort()
    for prior, current in zip(intervals, intervals[1:]):
        if prior[1] > current[0]:
            raise ValueError(f"SAB payloads {prior[2]} and {current[2]} overlap")
    payload_offset = min((entry.data_offset + entry.seek_bytes for entry in entries), default=len(blob))
    return SabInfo(tuple(entries), payload_offset, len(blob))


def generate_sab_v10(root: Path, sources: list[dict], output: Path,
                     generator: Path | None = None) -> tuple[bytes, list[dict], SabInfo]:
    """Author a native SAB v10 bank from PCM WAV sources using the existing generator.

    This does not create a SndBank/SndAliasList XAsset. It compiles sample audio
    into a resident SAB bank and returns its native alias metadata separately.
    """
    if not sources:
        raise ValueError("At least one native sample source is required")
    generator = _codec_tool(generator, 'REPLAY_SAB_GENERATOR', DEFAULT_SAB_GENERATOR)
    if not generator.is_file():
        raise FileNotFoundError(f"Replay SAB authoring tool does not exist: {generator}")
    spec = importlib.util.spec_from_file_location("replay_workstation_sound_generator", generator.resolve())
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load Replay SAB authoring module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = root.resolve()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    aliases = module.generate(root, sources, output)
    if not output.is_file():
        raise RuntimeError("SAB authoring tool did not write a bank")
    bank = output.read_bytes()
    return bank, aliases, inspect_sab_v10(bank)


def export_localize_entries(entries: list[dict]) -> str:
    """Export a typed Localize asset's ordered key/value children as JSON."""
    normalized = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"key", "value"}:
            raise ValueError(f"Localize entry {index} must contain exactly key and value")
        key, value = entry["key"], entry["value"]
        if not isinstance(key, str) or not key:
            raise ValueError(f"Localize entry {index} has an empty or non-text key")
        if value is not None and not isinstance(value, str):
            raise ValueError(f"Localize entry {index} value must be text or null")
        normalized.append({"key": key, "value": value})
    return json.dumps({"schema": 1, "entries": normalized}, ensure_ascii=False,
                      indent=2) + "\n"


def import_localize_entries(document: str) -> list[dict]:
    """Validate edited Localize JSON and return ordered native string children."""
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError as error:
        raise ValueError(f"Localize JSON is invalid: {error}") from error
    if not isinstance(parsed, dict) or parsed.get("schema") != 1 or not isinstance(parsed.get("entries"), list):
        raise ValueError("Localize document must have schema 1 and an entries array")
    export_localize_entries(parsed["entries"])
    return [{"key": row["key"], "value": row["value"]} for row in parsed["entries"]]


def _stringtable_hash(value: str) -> int:
    result = 0
    for byte in value.encode("utf-8"):
        # Replay sign-extends char before its C-locale tolower call. Only
        # ASCII A-Z is folded; UTF-8 high bytes contribute signed values.
        lowered = byte + 32 if 65 <= byte <= 90 else byte
        result = (result * 31 + (lowered if lowered < 128 else lowered - 256)) & 0xffffffff
    return result


def encode_stringtable_sections(name: str, rows: list[list[str]]) -> dict[str, object]:
    """Build the verified 48-byte Replay StringTable root and typed sections.

    Pointer words remain symbolic follows tokens for the native fastfile writer
    to resolve into stream positions. Replay's Load_StringTable trace confirms
    the root and child sizes; its native cell accessor confirms row-major order.
    Packing these sections into a fastfile remains the writer's responsibility.
    """
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("StringTable name must be nonempty text without NUL")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], list) or not rows[0]:
        raise ValueError("StringTable requires at least one nonempty row")
    columns = len(rows[0])
    if len(rows) > 1_000_000 or columns > 65_535 or any(
            not isinstance(row, list) or len(row) != columns or
            any(not isinstance(cell, str) or "\x00" in cell for cell in row)
            for row in rows):
        raise ValueError("StringTable rows must be rectangular text cells")
    dictionary: list[str] = []
    indices: dict[str, int] = {}
    cells: list[int] = []
    for row in rows:
        for value in row:
            index = indices.get(value)
            if index is None:
                index = len(dictionary)
                if index >= 65_536:
                    raise ValueError("StringTable dictionary exceeds the ushort cell index range")
                indices[value] = index
                dictionary.append(value)
            cells.append(index)
    header = bytearray(48)
    struct.pack_into("<QIII", header, 0, 0xffffffffffffffff,
                     columns, len(rows), len(dictionary))
    for offset in (24, 32, 40):
        struct.pack_into("<Q", header, offset, 0xffffffffffffffff)
    cell_bytes = struct.pack(f"<{len(cells)}H", *cells)
    hash_bytes = struct.pack(f"<{len(dictionary)}I",
                             *(_stringtable_hash(value) for value in dictionary))
    return {"name": name, "header": bytes(header), "cells": cell_bytes,
            "hashes": hash_bytes, "dictionary": dictionary,
            "rows": len(rows), "columns": columns}


def decode_stringtable_sections(name: str, header: bytes, cells: bytes,
                                hashes: bytes, dictionary: list[str]) -> list[list[str]]:
    """Decode verified Replay StringTable sections into editable rows."""
    if not isinstance(header, bytes) or len(header) != 48:
        raise ValueError("Replay StringTable root must be exactly 48 bytes")
    columns, row_count, string_count = struct.unpack_from("<III", header, 8)
    if (not isinstance(name, str) or not name or not columns or not row_count or
            string_count != len(dictionary) or row_count > 1_000_000 or columns > 65_535):
        raise ValueError("StringTable dimensions or dictionary count are invalid")
    expected_cells = row_count * columns
    if (len(cells) != expected_cells * 2 or len(hashes) != string_count * 4 or
            any(not isinstance(value, str) or "\x00" in value for value in dictionary)):
        raise ValueError("StringTable child section lengths do not match the native header")
    stored_hashes = struct.unpack(f"<{string_count}I", hashes) if string_count else ()
    if any(_stringtable_hash(value) != stored for value, stored in zip(dictionary, stored_hashes)):
        raise ValueError("StringTable dictionary hash does not match its value")
    indexes = struct.unpack(f"<{expected_cells}H", cells) if expected_cells else ()
    if any(index >= string_count for index in indexes):
        raise ValueError("StringTable cell references an absent dictionary entry")
    return [[dictionary[indexes[row * columns + col]] for col in range(columns)]
            for row in range(row_count)]


def parse_stringtable_csv(payload: bytes) -> list[list[str]]:
    """Parse ACTS-exported StringTable CSV into editable rectangular rows."""
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("StringTable CSV must be UTF-8 text") from error
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as error:
        raise ValueError(f"StringTable CSV is malformed: {error}") from error
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        raise ValueError("StringTable CSV must contain nonempty rectangular rows")
    return rows


def serialize_stringtable_csv(rows: list[list[str]]) -> bytes:
    """Serialize editable StringTable rows in the quoted ACTS CSV form."""
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        raise ValueError("StringTable CSV rows must be nonempty and rectangular")
    if any(not isinstance(cell, str) for row in rows for cell in row):
        raise ValueError("StringTable CSV cells must be text")
    output = io.StringIO(newline="")
    csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
    return output.getvalue().encode("utf-8")


def _asset_stem(name: str) -> str:
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name) or name in (".", ".."):
        raise ValueError("Asset name must be one safe filename component")
    return name


def _dxbc_tool_stem(asset_name: str) -> str:
    """Map native shader identity to a safe private tool filename component."""
    if not isinstance(asset_name, str) or not asset_name:
        raise ValueError("DXBC asset identity must be nonempty text")
    try:
        return _asset_stem(asset_name)
    except ValueError:
        # Native shader names can contain namespace separators. They are not
        # filesystem paths; use a deterministic private stem without changing
        # the XAsset identity carried by the transaction receipt.
        return "shader_" + hashlib.sha256(asset_name.encode("utf-8")).hexdigest()[:24]


def _run_gsc_tool(tool: Path, mode: str, input_path: Path, cwd: Path) -> None:
    if mode not in ("decomp", "comp"):
        raise ValueError("GSC Tool mode must be decomp or comp")
    if not tool.is_file():
        raise FileNotFoundError(f"GSC Tool executable does not exist: {tool}")
    result = subprocess.run(
        [str(tool), "-g", "iw8", "-s", "pc", "-m", mode, str(input_path)],
        cwd=cwd, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        diagnostic = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(f"GSC Tool {mode} failed ({result.returncode}): {diagnostic}")


# Replay stores signed 24-bit local code displacements with a reserved low
# tag bit. The native VM target is operand + (delta >> 1); GSC Tool's IW8
# disassembler interprets the same bytes as a full unscaled displacement.
# Convert only a private GSCBIN working copy for editing, and restore the tag
# when accepting GSC Tool output. These opcodes and widths match the pinned
# Replay ScriptFile bytecode walker and DB_ConvertScriptFileLocalReferences.
_GSC_NO_DATA = {1, 3, 20, 22, 40, 48, 52, 68, 69, 70, 71, 81, 82, 91,
                99, 104, 107, 113, 116, 140, 142, 147, 161, 185, 186,
                187, 188}
_GSC_CODE2 = {11, 14, 25, 27, 28, 29, 30, 31, 32, 33, 34, 50, 80, 85,
              102, 114, 126, 127, 128, 129, 130, 131}
_GSC_CODE3 = {35, 51, 79, 132, 137, 152, 169, 170, 171, 172}
_GSC_CODE4 = {4, 5, 7, 8, 23, 24, 37, 41, 44, 53, 56, 60, 72, 73, 76,
              95, 101, 109, 110, 112, 122, 123, 134, 138, 141, 148, 173,
              174, 175, 176, 181, 182, 183, 184}
_GSC_TWO_SOURCE_CODE4 = {5, 23, 101, 138}
_GSC_TWO_SOURCE_CODE3 = {96, 117, 146, 150}
_GSC_SOURCE_TOKEN_CODE3 = {177, 178, 179, 180}
_GSC_SOURCE_TOKEN_CODE4 = {181, 182, 183, 184}
_GSC_LOCAL_REFERENCES = {0x29, 0x33, 0x35, 0x48, 0x4F, 0x89, 0x98}


def _script_instructions(code: bytes):
    pc = 1
    while pc < len(code):
        start = pc
        opcode = code[pc]
        pc += 1
        if opcode in _GSC_NO_DATA or opcode == 98:
            pc += 1
        elif opcode in _GSC_CODE2:
            pc += 2
        elif opcode in (_GSC_CODE3 | _GSC_TWO_SOURCE_CODE3 |
                        _GSC_SOURCE_TOKEN_CODE3):
            pc += 3
        elif opcode in (_GSC_CODE4 | _GSC_TWO_SOURCE_CODE4 |
                        _GSC_SOURCE_TOKEN_CODE4):
            pc += 4
        elif opcode == 19:
            pc += 12
        elif opcode == 86:
            if pc + 2 > len(code):
                raise ValueError(f"Truncated Replay switch at bytecode offset {start:#x}")
            pc += 2 + 7 * struct.unpack_from("<H", code, pc)[0]
        elif opcode == 145:
            pc += 8
        elif opcode == 160:
            pc += 5
        elif opcode in (166, 189):
            if pc >= len(code):
                raise ValueError(f"Truncated Replay variable-width opcode at {start:#x}")
            pc += 1 + code[pc]
        elif opcode > 153 and opcode not in (165, 167, 168):
            raise ValueError(f"Unsupported Replay opcode {opcode:#x} at {start:#x}")
        if pc > len(code):
            raise ValueError(f"Replay opcode {opcode:#x} overruns bytecode at {start:#x}")
        yield start, opcode, pc


def _convert_gsc_local_reference_scale(body: bytes, *, to_replay: bool) -> bytes:
    info = inspect_gscbin(body)
    code = bytearray(info.bytecode)
    decoded = list(_script_instructions(code))
    boundaries = {pc for pc, _, _ in decoded} | {len(code)}
    entries = {pc for pc, opcode, _ in decoded
               if opcode in (0xA6, 0x4B, 0xBD)}
    # Replay uses the same shifted signed-24 representation for switch-table
    # case displacements as for local calls. GSC Tool's IW8/PC disassembler
    # reads those displacements unshifted, so normalize both reference kinds.
    refs = []
    for pc, opcode, _ in decoded:
        if opcode in _GSC_LOCAL_REFERENCES:
            refs.append((pc + 1, opcode, pc))
        elif opcode == 0x56:
            count = struct.unpack_from("<H", code, pc + 1)[0]
            refs.extend((pc + 7 + index * 7, opcode, pc)
                        for index in range(count))
    if not refs:
        return body

    # Validate the entire input before mutating any operand. In Replay form,
    # every doubled displacement must be even and land on a valid target.
    for operand, opcode, pc in refs:
        delta = int.from_bytes(code[operand:operand + 3], "little", signed=True)
        valid_targets = entries if opcode in _GSC_LOCAL_REFERENCES else boundaries
        if to_replay:
            target = operand + delta
            if target not in valid_targets:
                kind = "local call" if opcode in _GSC_LOCAL_REFERENCES else "switch case"
                raise ValueError(f"GSC Tool {kind} at {pc:#x} does not target a code boundary")
        else:
            if delta & 1:
                raise ValueError(f"Replay code displacement at {pc:#x} has an untaggable low bit")
            target = operand + (delta >> 1)
            if target not in valid_targets:
                kind = "local call" if opcode in _GSC_LOCAL_REFERENCES else "switch case"
                raise ValueError(f"Replay {kind} at {pc:#x} does not target a code boundary")

    for operand, _, _ in refs:
        delta = int.from_bytes(code[operand:operand + 3], "little", signed=True)
        converted = delta * 2 if to_replay else delta >> 1
        if not -(1 << 23) <= converted < (1 << 23):
            raise ValueError(f"Code displacement at {operand:#x} exceeds signed 24-bit range")
        code[operand:operand + 3] = converted.to_bytes(3, "little", signed=True)

    header = struct.pack("<4I", GSCBIN_MAGIC, len(info.compressed_source),
                         info.source_size, len(code))
    return header + info.compressed_source + bytes(code)


def normalize_replay_scriptfile_for_gsc_tool(body: bytes) -> bytes:
    """Return a private GSC Tool-compatible copy of a native Replay GSCBIN."""
    return _convert_gsc_local_reference_scale(body, to_replay=False)


def count_replay_scriptfile_local_references(body: bytes) -> int:
    """Count local-function operands in one size-validated GSCBIN body."""
    info = inspect_gscbin(body)
    return sum(opcode in _GSC_LOCAL_REFERENCES
               for _, opcode, _ in _script_instructions(info.bytecode))


def count_replay_scriptfile_switch_cases(body: bytes) -> int:
    """Count case-relative operands in native Replay switch tables."""
    info = inspect_gscbin(body)
    return sum(struct.unpack_from("<H", info.bytecode, pc + 1)[0]
               for pc, opcode, _ in _script_instructions(info.bytecode)
               if opcode == 0x56)


def decompile_scriptfile(body: bytes, tool: Path | None = None,
                         asset_name: str = "script") -> str:
    """Return editable IW8 GSC source from one complete native GSCBIN body."""
    inspect_gscbin(body)
    stem = _asset_stem(asset_name)
    with tempfile.TemporaryDirectory(prefix="replay-gsc-decompile-") as tmp:
        root = Path(tmp)
        binary = root / f"{stem}.gscbin"
        binary.write_bytes(normalize_replay_scriptfile_for_gsc_tool(body))
        _run_gsc_tool(_codec_tool(tool, 'REPLAY_GSC_TOOL', DEFAULT_GSC_TOOL), "decomp", Path(binary.name), root)
        output = root / "decompiled" / "iw8" / f"{stem}.gsc"
        if not output.is_file():
            raise RuntimeError("GSC Tool reported success without writing editable GSC source")
        try:
            return output.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("GSC Tool output is not UTF-8 source text") from error


def compile_scriptfile(source: str, tool: Path | None = None,
                       asset_name: str = "script") -> bytes:
    """Compile editable IW8 GSC source into a validated native GSCBIN body."""
    if not isinstance(source, str) or not source.strip():
        raise ValueError("GSC source must be nonempty text")
    stem = _asset_stem(asset_name)
    with tempfile.TemporaryDirectory(prefix="replay-gsc-compile-") as tmp:
        root = Path(tmp)
        source_path = root / "source" / f"{stem}.gsc"
        source_path.parent.mkdir()
        source_path.write_bytes(source.encode("utf-8"))
        _run_gsc_tool(_codec_tool(tool, 'REPLAY_GSC_TOOL', DEFAULT_GSC_TOOL), "comp",
                      Path("source") / source_path.name, root)
        output = root / "compiled" / "iw8" / f"{stem}.gscbin"
        if not output.is_file():
            raise RuntimeError("GSC Tool reported success without writing a compiled GSCBIN")
        body = output.read_bytes()
        inspect_gscbin(body)
        return _convert_gsc_local_reference_scale(body, to_replay=True)


def _replay_mip_size(width: int, height: int, replay_format: int) -> int:
    if replay_format in _BC_BLOCK_BYTES:
        return max(1, (width + 3) // 4) * max(1, (height + 3) // 4) * _BC_BLOCK_BYTES[replay_format]
    if replay_format in _LINEAR_PIXEL_BYTES:
        return width * height * _LINEAR_PIXEL_BYTES[replay_format]
    raise ValueError(f"Replay image format {replay_format} is outside the supported DDS subset")


def _replay_chain_layout(width: int, height: int, mip_count: int,
                         replay_format: int) -> list[tuple[int, int]]:
    if replay_format not in _BC_BLOCK_BYTES and replay_format not in _LINEAR_PIXEL_BYTES:
        raise ValueError(f"Replay image format {replay_format} is outside the supported DDS subset")
    if (not isinstance(width, int) or not isinstance(height, int) or
            width < 1 or height < 1 or width > 0xFFFF or height > 0xFFFF):
        raise ValueError("DDS dimensions must be positive 16-bit values")
    max_levels = max(width, height).bit_length()
    if not isinstance(mip_count, int) or not 1 <= mip_count <= max_levels:
        raise ValueError("DDS mip count is outside the complete 2D mip-chain bound")
    result = []
    for level in range(mip_count):
        raw = _replay_mip_size(max(1, width >> level), max(1, height >> level), replay_format)
        result.append((raw, (raw + 15) & ~15))
    return result


def export_replay_image_mips_to_dds(width: int, height: int, replay_format: int,
                                    mip_count: int, resident_pixels: bytes) -> bytes:
    """Wrap a Replay BC chain as an editable standard DDS/DX10 file.

    Native subresources use 16-byte strides. Export strips only those padding
    bytes, preserving compressed texel blocks exactly.
    """
    layout = _replay_chain_layout(width, height, mip_count, replay_format)
    expected = sum(stride for _, stride in layout)
    if len(resident_pixels) != expected:
        raise ValueError(f"resident payload is {len(resident_pixels)} bytes; expected {expected}")
    linear = replay_format in _BC_BLOCK_BYTES
    flags = 0x1 | 0x2 | 0x4 | 0x1000 | (0x80000 if linear else 0x8)
    if mip_count > 1:
        flags |= 0x20000
    header = bytearray(DDS_HEADER_SIZE)
    struct.pack_into("<7I", header, 0, DDS_HEADER_SIZE, flags, height, width,
                     layout[0][0] if linear else width * _LINEAR_PIXEL_BYTES[replay_format],
                     0, mip_count if mip_count > 1 else 0)
    struct.pack_into("<II4s5I", header, 72, 32, 0x4, b"DX10", 0, 0, 0, 0, 0)
    caps = 0x1000 | ((0x8 | 0x400000) if mip_count > 1 else 0)
    struct.pack_into("<5I", header, 104, caps, 0, 0, 0, 0)
    dxgi = _REPLAY_BC_DXGI.get(replay_format, _REPLAY_LINEAR_DXGI.get(replay_format))
    if dxgi is None:
        raise ValueError(f"Replay image format {replay_format} has no DDS DXGI mapping")
    dx10 = struct.pack("<5I", dxgi, 3, 0, 1, 0)
    output = bytearray(DDS_MAGIC + header + dx10)
    cursor = 0
    for raw_size, stride in layout:
        output.extend(resident_pixels[cursor:cursor + raw_size])
        cursor += stride
    return bytes(output)


def import_dds_to_replay_image_mips(dds: bytes) -> tuple[int, int, int, int, bytes]:
    """Convert strict single-2D DDS/DX10 data to Replay resident mip strides."""
    if len(dds) < 4 + DDS_HEADER_SIZE + DDS_DX10_HEADER_SIZE or dds[:4] != DDS_MAGIC:
        raise ValueError("DDS header is truncated or has an invalid signature")
    header = dds[4:4 + DDS_HEADER_SIZE]
    size, flags, height, width, linear_size, depth, mip_field = struct.unpack_from("<7I", header)
    if size != DDS_HEADER_SIZE or not (flags & 0x1 and flags & 0x2 and flags & 0x4):
        raise ValueError("DDS header size or required dimension flags are invalid")
    pf_size, pf_flags = struct.unpack_from("<II", header, 72)
    if pf_size != 32 or not (pf_flags & 0x4) or header[80:84] != b"DX10":
        raise ValueError("Only explicit DDS/DX10 headers are supported")
    dxgi, dimension, misc, array_size, _misc2 = struct.unpack_from(
        "<5I", dds, 4 + DDS_HEADER_SIZE)
    if dimension != 3 or array_size != 1 or (misc & 0x4) or depth not in (0, 1):
        raise ValueError("DDS must be one 2D non-cubemap texture")
    replay_format = _DXGI_REPLAY.get(dxgi)
    if replay_format is None:
        raise ValueError(f"DXGI format {dxgi} is outside the supported Replay DDS mapping")
    mip_count = mip_field or 1
    layout = _replay_chain_layout(width, height, mip_count, replay_format)
    if replay_format in _BC_BLOCK_BYTES:
        if linear_size != layout[0][0]:
            raise ValueError("DDS top-level linear size disagrees with the texture format")
    elif linear_size != width * _LINEAR_PIXEL_BYTES[replay_format]:
        raise ValueError("DDS top-level pitch disagrees with the texture format")
    cursor = 4 + DDS_HEADER_SIZE + DDS_DX10_HEADER_SIZE
    if len(dds) != cursor + sum(raw for raw, _stride in layout):
        raise ValueError("DDS pixel data is truncated or has trailing bytes")
    resident = bytearray()
    for raw_size, stride in layout:
        resident.extend(dds[cursor:cursor + raw_size])
        resident.extend(bytes(stride - raw_size))
        cursor += raw_size
    return width, height, replay_format, mip_count, bytes(resident)


def _resident_resource_layout(width: int, height: int, depth: int, elements: int,
                              mip_count: int, replay_format: int) -> list[tuple[int, int]]:
    """Return the standard DDS subresource order and Replay's 16-byte strides.

    Arrays are serialized element-major, then mip-major. Volumes are one DDS
    subresource per mip, with all depth slices contiguous within that mip.
    Cube interpretation is deliberately excluded because the Replay root's
    cube discriminator is not proven by the current target layout.
    """
    if type(depth) is not int or type(elements) is not int or depth < 1 or elements < 1:
        raise ValueError("resident image depth and element count must be positive integers")
    if depth > 1 and elements != 1:
        raise ValueError("combined volume-array images are outside the supported DDS contract")
    if depth == 1 and elements > 0xFFFF:
        raise ValueError("DDS array count exceeds the Replay image root")
    if (type(width) is not int or type(height) is not int or
            width < 1 or height < 1 or width > 0xFFFF or height > 0xFFFF or depth > 0xFFFF):
        raise ValueError("resident image dimensions exceed the Replay image root")
    max_levels = max(width, height, depth).bit_length()
    if not 1 <= mip_count <= max_levels:
        raise ValueError("DDS mip count exceeds the resource dimension chain")
    result = []
    if depth > 1:
        for level in range(mip_count):
            raw = _replay_mip_size(max(1, width >> level), max(1, height >> level), replay_format)
            raw *= max(1, depth >> level)
            result.append((raw, (raw + 15) & ~15))
    else:
        for _element in range(elements):
            for level in range(mip_count):
                raw = _replay_mip_size(max(1, width >> level), max(1, height >> level), replay_format)
                result.append((raw, (raw + 15) & ~15))
    return result


def export_replay_image_resource_to_dds(width: int, height: int, depth: int, elements: int,
                                        replay_format: int, mip_count: int,
                                        resident_pixels: bytes, *, flags: int = 0) -> bytes:
    """Export a resident 2D array or volume as strict DDS/DX10 bytes.

    The native 232-byte root remains authoritative. This wrapper does not
    rewrite dimensions and refuses ambiguous cube/atlas/fallback/streamed flags.
    """
    if not isinstance(resident_pixels, bytes):
        raise ValueError("resident image payload must be bytes")
    if flags & 0x40:
        raise ValueError("image flag 0x40 has no verified DDS resource interpretation")
    if replay_format not in _REPLAY_BC_DXGI and replay_format not in _REPLAY_LINEAR_DXGI:
        raise ValueError(f"Replay image format {replay_format} has no DDS DXGI mapping")
    layout = _resident_resource_layout(width, height, depth, elements, mip_count, replay_format)
    if len(resident_pixels) != sum(stride for _raw, stride in layout):
        raise ValueError("resident payload length differs from computed subresource schedule")
    linear = replay_format in _BC_BLOCK_BYTES
    top_raw = _replay_mip_size(width, height, replay_format) * (depth if depth > 1 else 1)
    header_flags = 0x1 | 0x2 | 0x4 | 0x1000 | (0x80000 if linear else 0x8)
    if mip_count > 1:
        header_flags |= 0x20000
    if depth > 1:
        header_flags |= 0x800000
    header = bytearray(DDS_HEADER_SIZE)
    struct.pack_into("<7I", header, 0, DDS_HEADER_SIZE, header_flags, height, width,
                     top_raw if linear else width * _LINEAR_PIXEL_BYTES[replay_format],
                     depth if depth > 1 else 0, mip_count if mip_count > 1 else 0)
    struct.pack_into("<II4s5I", header, 72, 32, 0x4, b"DX10", 0, 0, 0, 0, 0)
    caps = 0x1000 | ((0x8 | 0x400000) if mip_count > 1 else 0)
    caps2 = 0x200000 if depth > 1 else 0
    struct.pack_into("<5I", header, 104, caps, caps2, 0, 0, 0)
    dxgi = _REPLAY_BC_DXGI.get(replay_format, _REPLAY_LINEAR_DXGI.get(replay_format))
    dimension = 4 if depth > 1 else 3
    dx10 = struct.pack("<5I", dxgi, dimension, 0, elements if depth == 1 else 1, 0)
    output = bytearray(DDS_MAGIC + header + dx10)
    cursor = 0
    for raw_size, stride in layout:
        if any(resident_pixels[cursor + raw_size:cursor + stride]):
            raise ValueError("resident subresource has nonzero alignment bytes; lossless DDS export is unavailable")
        output.extend(resident_pixels[cursor:cursor + raw_size])
        cursor += stride
    return bytes(output)


def import_dds_to_replay_image_resource(dds: bytes) -> tuple[int, int, int, int, int, int, bytes]:
    """Import a strict 2D array or volume DDS into Replay resident subresource strides."""
    if len(dds) < 4 + DDS_HEADER_SIZE + DDS_DX10_HEADER_SIZE or dds[:4] != DDS_MAGIC:
        raise ValueError("DDS header is truncated or has an invalid signature")
    header = dds[4:4 + DDS_HEADER_SIZE]
    size, flags, height, width, pitch, depth, mip_field = struct.unpack_from("<7I", header)
    if size != DDS_HEADER_SIZE or not (flags & 0x1 and flags & 0x2 and flags & 0x4):
        raise ValueError("DDS header size or required dimension flags are invalid")
    pf_size, pf_flags = struct.unpack_from("<II", header, 72)
    if pf_size != 32 or not (pf_flags & 0x4) or header[80:84] != b"DX10":
        raise ValueError("Only explicit DDS/DX10 headers are supported")
    dxgi, dimension, misc, array_size, misc2 = struct.unpack_from(
        "<5I", dds, 4 + DDS_HEADER_SIZE)
    if misc & 0x4 or misc2 or array_size < 1:
        raise ValueError("cubemaps and misc DDS resource flags are unsupported")
    caps2 = struct.unpack_from("<I", header, 108)[0]
    if dimension == 3 and depth in (0, 1):
        depth = 1
        if flags & 0x800000 or caps2 & 0x200000:
            raise ValueError("DDS 2D dimension carries volume depth flags/caps")
    elif dimension == 4 and depth > 1 and array_size == 1:
        if not flags & 0x800000 or not (caps2 & 0x200000):
            raise ValueError("DDS volume dimension lacks matching depth flags/caps")
    else:
        raise ValueError("DDS resource must be a 2D array or a 3D volume")
    replay_format = _DXGI_REPLAY.get(dxgi)
    if replay_format is None:
        raise ValueError(f"DXGI format {dxgi} is outside the supported Replay DDS mapping")
    mip_count = mip_field or 1
    elements = array_size if depth == 1 else 1
    layout = _resident_resource_layout(width, height, depth, elements, mip_count, replay_format)
    linear = replay_format in _BC_BLOCK_BYTES
    expected_pitch = _replay_mip_size(width, height, replay_format) * (depth if depth > 1 else 1) if linear else width * _LINEAR_PIXEL_BYTES[replay_format]
    if pitch != expected_pitch:
        raise ValueError("DDS top-level pitch/linear size disagrees with the native format")
    cursor = 4 + DDS_HEADER_SIZE + DDS_DX10_HEADER_SIZE
    raw_total = sum(raw for raw, _stride in layout)
    if len(dds) != cursor + raw_total:
        raise ValueError("DDS pixel data is truncated or has trailing bytes")
    resident = bytearray()
    for raw_size, stride in layout:
        resident.extend(dds[cursor:cursor + raw_size])
        resident.extend(bytes(stride - raw_size))
        cursor += raw_size
    return width, height, depth, elements, replay_format, mip_count, bytes(resident)


# Kept as aliases for callers that previously selected this BC-only API name.
export_replay_bc_mips_to_dds = export_replay_image_mips_to_dds
import_dds_to_replay_bc_mips = import_dds_to_replay_image_mips


def _run_texconv(tool: Path, arguments: list[str], cwd: Path) -> None:
    if not tool.is_file():
        raise FileNotFoundError(f"DirectXTex texconv does not exist: {tool}")
    if tool.resolve() == DEFAULT_TEXCONV_TOOL.resolve():
        actual = hashlib.sha256(tool.read_bytes()).hexdigest()
        if actual != DEFAULT_TEXCONV_TOOL_SHA256:
            raise ValueError("Pinned texconv hash does not match the workstation tool receipt")
    result = subprocess.run([str(tool), *arguments], cwd=cwd, capture_output=True,
                            text=True, timeout=180, check=False)
    if result.returncode:
        diagnostic = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(f"DirectXTex texconv failed ({result.returncode}): {diagnostic}")


def export_replay_image_mips_to_png(width: int, height: int, replay_format: int,
                                    mip_count: int, resident_pixels: bytes,
                                    tool: Path | None = None) -> bytes:
    """Decode a Replay resident mip chain to an editable top-mip PNG."""
    if replay_format not in _REPLAY_DXGI_NAMES:
        raise ValueError(f"Replay image format {replay_format} has no DirectXTex mapping")
    tool = _codec_tool(tool, 'REPLAY_TEXCONV', DEFAULT_TEXCONV_TOOL, DEFAULT_TEXCONV_TOOL_SHA256)
    dds = export_replay_image_mips_to_dds(width, height, replay_format, mip_count, resident_pixels)
    with tempfile.TemporaryDirectory(prefix="replay-image-export-") as tmp:
        root = Path(tmp)
        source = root / "image.dds"
        source.write_bytes(dds)
        _run_texconv(tool.resolve(), ["-ft", "png", "-o", str(root), source.name], root)
        output = root / "image.png"
        if not output.is_file():
            raise RuntimeError("texconv succeeded without writing the requested PNG")
        return output.read_bytes()


def import_png_to_replay_image_mips(png: bytes, replay_format: int, mip_count: int,
                                    tool: Path | None = None) -> tuple[int, int, int, int, bytes]:
    """Encode an edited PNG to Replay format and rebuild native mip strides."""
    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Image source must be a PNG file")
    tool = _codec_tool(tool, 'REPLAY_TEXCONV', DEFAULT_TEXCONV_TOOL, DEFAULT_TEXCONV_TOOL_SHA256)
    if replay_format not in _REPLAY_DXGI_NAMES:
        raise ValueError(f"Replay image format {replay_format} has no DirectXTex mapping")
    if not isinstance(mip_count, int) or mip_count < 1:
        raise ValueError("Requested mip count must be positive")
    with tempfile.TemporaryDirectory(prefix="replay-image-import-") as tmp:
        root = Path(tmp)
        source = root / "image.png"
        source.write_bytes(png)
        _run_texconv(tool.resolve(), ["-dx10", "-y", "-f", _REPLAY_DXGI_NAMES[replay_format],
                                     "-m", str(mip_count), "-o", str(root), source.name], root)
        output = root / "image.dds"
        if not output.is_file():
            raise RuntimeError("texconv succeeded without writing the requested DDS")
        width, height, actual_format, actual_mips, resident = import_dds_to_replay_image_mips(
            output.read_bytes())
        if actual_format != replay_format or actual_mips != mip_count:
            raise ValueError("texconv DDS format or mip count differs from requested image layout")
        return width, height, actual_format, actual_mips, resident


def _validate_dxbc(bytecode: bytes) -> None:
    if len(bytecode) < 32 or bytecode[:4] != b"DXBC":
        raise ValueError("Shader input is not a complete DXBC container")
    declared = struct.unpack_from("<I", bytecode, 24)[0]
    if declared != len(bytecode):
        raise ValueError("DXBC declared extent does not match its byte length")


def dxbc_native_shader_type(bytecode: bytes) -> int:
    """Return the Replay XAsset type for one well-formed SM5 DXBC program.

    Native type IDs are 12 compute, 14 vertex, 15 hull, 16 domain and 17 pixel. Merely
    checking the DXBC magic is insufficient: the asset root's type controls
    the loader and pipeline stage, so ambiguous or malformed token chunks are
    rejected before any editor or child writer accepts the bytes.
    """
    _validate_dxbc(bytecode)
    if len(bytecode) < 40:
        raise ValueError("DXBC container has no complete shader chunk directory")
    count = struct.unpack_from("<I", bytecode, 28)[0]
    if count > (len(bytecode) - 32) // 4:
        raise ValueError("DXBC chunk directory exceeds its container")
    stages = []
    ranges = []
    for index in range(count):
        offset = struct.unpack_from("<I", bytecode, 32 + index * 4)[0]
        if offset > len(bytecode) - 8:
            raise ValueError("DXBC chunk starts outside its container")
        chunk_type = bytecode[offset:offset + 4]
        chunk_size = struct.unpack_from("<I", bytecode, offset + 4)[0]
        if chunk_size > len(bytecode) - offset - 8:
            raise ValueError("DXBC chunk exceeds its container")
        bounds = (offset, offset + 8 + chunk_size)
        if any(bounds[0] < prior[1] and prior[0] < bounds[1] for prior in ranges):
            raise ValueError("DXBC chunk directory contains overlapping chunks")
        ranges.append(bounds)
        if chunk_type in (b"SHDR", b"SHEX"):
            if chunk_size < 8 or chunk_size % 4:
                raise ValueError("DXBC shader token chunk has an invalid extent")
            version, token_count = struct.unpack_from("<II", bytecode, offset + 8)
            if token_count != chunk_size // 4:
                raise ValueError("DXBC shader token count differs from the chunk extent")
            stages.append(version >> 16)
    if len(stages) != 1:
        raise ValueError("DXBC must contain exactly one SHDR/SHEX shader token chunk")
    native_type = {0: 17, 1: 14, 3: 15, 4: 16, 5: 12}.get(stages[0])
    if native_type is None:
        raise ValueError(f"DXBC shader stage {stages[0]} is outside the supported Replay SM5 types")
    return native_type


def _run_dxbc_tool(tool: Path, mode: str, input_path: Path, cwd: Path,
                   reflection_reference: Path | None = None) -> None:
    if mode == "disassemble":
        command = [str(tool), "-d", "-V", input_path.name]
    elif mode == "assemble":
        command = [str(tool), "-a", input_path.name]
        if reflection_reference is not None:
            command[1:1] = ["--copy-reflection", str(reflection_reference.resolve())]
    else:
        raise ValueError("DXBC operation must be disassemble or assemble")
    if not tool.is_file():
        raise FileNotFoundError(f"3DMigoto DXBC tool does not exist: {tool}")
    if tool.resolve() == DEFAULT_DXBC_TOOL.resolve():
        actual = hashlib.sha256(tool.read_bytes()).hexdigest()
        if actual != DEFAULT_DXBC_TOOL_SHA256:
            raise ValueError("Pinned cmd_Decompiler binary hash does not match the workstation tool receipt")
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            timeout=120, check=False)
    if result.returncode:
        diagnostic = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(f"DXBC {mode} failed ({result.returncode}): {diagnostic}")


def disassemble_dxbc(bytecode: bytes, tool: Path | None = None,
                     asset_name: str = "shader") -> str:
    """Return editable Flugan SM5 assembly from a native DXBC shader.

    ``-V`` asks the pinned tool to reassemble and compare the DXBC sections
    before returning text, so unsupported assembly cases fail closed.
    """
    _validate_dxbc(bytecode)
    tool = _codec_tool(tool, 'REPLAY_DXBC_TOOL', DEFAULT_DXBC_TOOL, DEFAULT_DXBC_TOOL_SHA256)
    stem = _dxbc_tool_stem(asset_name)
    with tempfile.TemporaryDirectory(prefix="replay-dxbc-disassemble-") as tmp:
        root = Path(tmp)
        source = root / f"{stem}.dxbc"
        source.write_bytes(bytecode)
        _run_dxbc_tool(tool.resolve(), "disassemble", source, root)
        assembly = root / f"{stem}.asm"
        if not assembly.is_file():
            raise RuntimeError("DXBC disassembler succeeded without writing SM5 assembly")
        try:
            source = assembly.read_text(encoding="utf-8")
            # The disassembler's wall-clock comment is not shader source.
            # Keep revisions stable across extraction and save validation.
            return re.sub(r'(?m)^(//\s+using 3Dmigoto v[0-9.]+) on [^\r\n]*', r'\1', source)
        except UnicodeDecodeError as error:
            raise ValueError("SM5 assembly output is not UTF-8 text") from error


def disassemble_native_shader(bytecode: bytes, native_type_id: int,
                              tool: Path | None = None,
                              asset_name: str = "shader") -> dict[str, object]:
    """Disassemble only a DXBC program whose token stage matches its XAsset.

    Unsupported disassembly/round-trip diagnostics are returned verbatim as a
    read-only result. No placeholder assembly is ever presented as editable.
    Structural or stage mismatches remain hard errors.
    """
    stage = dxbc_native_shader_type(bytecode)
    if stage != native_type_id:
        raise ValueError("DXBC shader stage does not match the native XAsset type")
    try:
        content = disassemble_dxbc(bytecode, tool=tool, asset_name=asset_name)
    except RuntimeError as error:
        return dict(editable=False, native_type_id=native_type_id,
                    codec_error=str(error), assembly=None)
    return dict(editable=True, native_type_id=native_type_id,
                codec_error=None, assembly=content)


def assemble_dxbc(assembly: str, tool: Path | None = None,
                  asset_name: str = "shader",
                  reflection_reference: Path | None = None) -> bytes:
    """Assemble editable Flugan SM5 assembly into a DXBC container.

    The assembly must carry signatures, as the native disassembler emits. A
    reference DXBC may be passed only to copy reflection/signature sections.
    """
    if not isinstance(assembly, str) or not assembly.strip():
        raise ValueError("SM5 assembly must be nonempty text")
    tool = _codec_tool(tool, 'REPLAY_DXBC_TOOL', DEFAULT_DXBC_TOOL, DEFAULT_DXBC_TOOL_SHA256)
    stem = _dxbc_tool_stem(asset_name)
    if reflection_reference is not None:
        reference = reflection_reference.read_bytes()
        _validate_dxbc(reference)
    with tempfile.TemporaryDirectory(prefix="replay-dxbc-assemble-") as tmp:
        root = Path(tmp)
        source = root / f"{stem}.asm"
        source.write_text(assembly, encoding="utf-8", newline="\n")
        _run_dxbc_tool(tool.resolve(), "assemble", source, root, reflection_reference)
        output = root / f"{stem}.shdr"
        if not output.is_file():
            raise RuntimeError("DXBC assembler succeeded without writing a shader container")
        bytecode = output.read_bytes()
        _validate_dxbc(bytecode)
        return bytecode


def capability_report() -> dict[str, dict[str, object]]:
    """Expose only codec paths that are implemented and name the current gaps."""
    return {
        "rawfile": {
            "status": "partial", "native_type": 51,
            "row_create": True,
            "row_create_modes": ["text", "base64"],
            "row_remove": True,
            "decode": "Trace-owned RawFile zlib or inline buffers become UTF-8 text or lossless Base64",
            "encode": "Native buffer recompilation, both length fields, full stream-5 relocation and semantic reread of every retained RawFile",
            "reason": "CFG, graph, vision and other owned inline RawFiles support revisioned source edits and native FF/FP replacement packaging. Allocated buffers retain their encoding; an empty null-buffer row can grow when its inline name and exact stream-5 insertion cursor are trace-proven, using zlib for the new allocation. Unique text or lossless Base64 rows can be appended; removal requires exclusive final-row root, name, payload and EOF ownership. Each table mutation is rebuilt and reread natively. Ambiguous/shared/reference buffers and null-buffer rows with packed names or uncertain cursors are unsupported. Existing RawFile content edits may join any present subset of same-layout resident image replacements, SoundBank volume/pitch edits, one Localize append and one LuaFile append. Each mutation receives a fresh full-zone native reread; mixed RawFile row mutations remain unsupported",
        },
        "gsc": {
            "status": "partial",
            "decode": "Replay IW8 GSCBIN to editable GSC through GSC Tool when the function-name table resolves all imports",
            "encode": "editable GSC through GSC Tool to a size-checked GSCBIN body for resolved scripts",
            "reason": "All 11 verified mp_frontend3 scripts decompile after Replay local-call operands and switch operands are normalized. Native growth and batch packaging pass reader checks; a live native registration capture matches the edited frontend source and bytecode hashes",
        },
        "lua": {
            "status": "partial",
            "row_create": True,
            "row_remove": True,
            "decode": "ACTS exports stock Replay LuaFile bytecode as editable Lua source; the pinned LuaJIT v2 decompiler is available for supported chunks",
            "encode": "compile_luajit_source_with_receipt invokes pinned Replay LuaJIT APIs, reloads the emitted bytecode through target lua_loadx, and records compiler/profile/API hashes and complete diagnostics; workstation_luafile relocates one typed LuaFile edit in a full zone and revalidates every asset with Replay",
            "reason": "Same-size, growth, shrink, multiple Lua edits and mixed GSC/Lua edits pass full-zone native reader checks. Unique inline LuaFile rows also support revisioned creation/removal with a fresh full-zone native walk after every table mutation. The canonical compiler output passed a live edited-Lua menu test; source recovery remains limited to supported LuaJIT chunks",
        },
        "shader": {
            "status": "partial",
            "row_create": True,
            "row_create_types": [17],
            "native_types": {"12": "compute", "14": "vertex", "15": "hull", "16": "domain", "17": "pixel"},
            "typed_root_layout": "Trace-owned 40-byte roots, inline XAsset names, DXBC children, and native SHDR/SHEX stage match are required for types 12/14-17; compute additionally binds its fixed packed stream-5 name token to the owner-local resolve event and requires unique whole-zone physical child ownership; types 15/16 bind their packed debug-name pointer to the owner-local resolve event and string span",
            "read_only_cases": ["compute programs rejected by the configured DXBC round-trip tool", "shared null hull/domain aliases", "programs rejected by the configured DXBC round-trip tool"],
            "reason": "Trace-owned Replay type-12/14/15/16/17 DXBC children are exposed only when the native 40-byte root, child ownership and SM5 stage match. Type-12 compute roots also require the exact owner-local packed-name callback and unique whole-zone physical child ownership. Variable-size edits use the shared alignment-aware stream-5 relocator and do not rewrite the type-12 root word at byte 36. The configured, hash-verified DXBC tool must accept strict disassemble/reassemble validation; rejection diagnostics are preserved. GPU/runtime rendering remains a separate gate",
        },
        "image": {
            "status": "partial",
            "resident_resize": True,
            "mip_editing": True,
            "resident_resource_dds": True,
            "reason": "Resident 2D RGBA8/BC images retain the PNG painter/import path. Trace-owned 2D arrays and volumes with a supported DXGI format and exact computed payload extent have whole-resource DDS import/export; saves preserve root dimensions, depth/array count, format and mip count and replace only the traced same-size payload. Nonzero padding, streamed/atlas/fallback layouts and unverified cube flags fail closed. Full-zone Replay reread remains required; live renderer acceptance and subresource painting are not claimed",
        },
        "stringtable": {
            "status": "partial",
            "row_create": True,
            "row_remove": True,
            "reason": "CSV edits support owned type-54 tables, including an initially empty stock table when its zero-length sections and alignment callbacks are proved by the native trace. Creation appends a 48-byte root with the Replay 2/4/8-byte child schedule. Removal requires an exclusive final inline row at exact serialized EOF with no inbound aliases. Layout, relocation and stream reservations are derived from the complete trace; each package rereads the full zone and compares edited cells and retained table payloads.",
        },
        "localize": {
            "status": "partial",
            "reason": "Trace-owned Localize value edits and staged row creation/removal support native fastfile packaging, retained-key comparison and revision history. A created entry passed live registration and menu checks. Removal requires a trace-owned inline row with no inbound references; final-row removal additionally requires exclusive serialized EOF ownership. One append may join a supported subset of same-layout resident images, RawFile replacements, SoundBank volume/pitch edits and one LuaFile append; other mixed row combinations remain unsupported",
        },
        "omnvar": {
            "status": "partial",
            "reason": "Authored Omnvar definitions are editable through the verified type-54 StringTable omnvars/mp/omnvars.csv (219 rows, 14 columns). Growth and stream-5 relocation pass full native rereads; separate runtime OmnvarDef manipulation is not verified",
        },
        "sfx": {
            "status": "partial",
            "soundbank_alias_scalars": True,
            "soundbank_native_package_verified": True,
            "reason": "Resident SoundBank type-21 aliases expose verified volume and pitch ranges through the JSON asset editor. Unknown parameter words have compact, immutable offset/hex inspection; names, IDs, order, counts and all other record bytes are preserved. Volume/pitch edits can join the supported mixed native transaction after relocation resolves each bank again. Same-extent edits pass a complete Replay native reread and typed semantic readback for one stock SoundBank. Other SoundBank root fields remain read-only. PCM WAV preview/import and resident SAB replacement stay a separate path; other codecs and audible runtime playback remain unverified",
        },
    }
