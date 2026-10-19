"""Derive and validate bounded Replay D3D12 live-capture checkpoints.

This module does not launch or modify the game.  It turns the pinned SQLite
evidence into a runtime contract: resolve the game's ID3D12Device pointer,
then break on methods obtained from that object's vtable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct


REPLAY_IMAGE_BASE = 0x140000000
DEVICE_GLOBAL_VA = 0x150C79C20
DEVICE_GLOBAL_RVA = DEVICE_GLOBAL_VA - REPLAY_IMAGE_BASE
DEVICE_EVIDENCE_FUNCTION = "R_DX12_GetResourceSize"
DEVICE_EVIDENCE_RVA = 26066288

CREATE_GRAPHICS_PIPELINE_STATE_SLOT = 10
CREATE_COMMITTED_RESOURCE_SLOT = 27
CREATE_PLACED_RESOURCE_SLOT = 29
GET_COPYABLE_FOOTPRINTS_SLOT = 38
GET_RESOURCE_DESC_SLOT = 10

SHADER_STAGES = {
    "VS": (0x08, 0x10),
    "PS": (0x18, 0x20),
    "DS": (0x28, 0x30),
    "HS": (0x38, 0x40),
    "GS": (0x48, 0x50),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_sqlite_device_evidence(database: Path) -> dict:
    """Require the named Replay function to prove the device global and ABI."""
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "select id,name,rva,assembly,pseudocode from functions where name=?",
            (DEVICE_EVIDENCE_FUNCTION,),
        ).fetchone()
    if row is None or int(row[2]) != DEVICE_EVIDENCE_RVA:
        raise ValueError("Pinned Replay D3D12 device evidence function is missing or moved")
    assembly, pseudocode = row[3] or "", row[4] or ""
    if "qword_150C79C20" not in assembly or "qword_150C79C20" not in pseudocode:
        raise ValueError("Device evidence no longer binds qword_150C79C20")
    # GetCopyableFootprints is ID3D12Device vtable slot 38 (38 * 8 == 0x130).
    if not re.search(r"\+\s*304LL", pseudocode):
        raise ValueError("Device evidence no longer calls verified vtable slot 38")
    if not re.search(r"call\s+qword ptr \[[a-z0-9]+\+130h\]", assembly):
        raise ValueError("SQLite assembly does not confirm ID3D12Device slot 38")
    return {
        "sqlite_function_id": row[0],
        "name": row[1],
        "original_rva": int(row[2]),
        "device_global_original_rva": DEVICE_GLOBAL_RVA,
        "verified_method": "ID3D12Device::GetCopyableFootprints",
        "verified_vtable_slot": GET_COPYABLE_FOOTPRINTS_SLOT,
    }


def map_original_rva(report: dict, original_rva: int) -> int:
    matches = [entry for entry in report.get("rva_map", {}).get("ranges", [])
               if entry["begin"] <= original_rva < entry["end"]]
    if len(matches) != 1:
        raise ValueError(f"Original RVA {original_rva:#x} does not map through exactly one build range")
    entry = matches[0]
    return entry["mapped_begin"] + original_rva - entry["begin"]


def unmap_mapped_rva(report: dict, mapped_rva: int) -> int:
    """Invert one mapped RVA using the build report's actual three-field range schema."""
    matches = []
    for entry in report.get("rva_map", {}).get("ranges", []):
        mapped_end = entry["mapped_begin"] + entry["end"] - entry["begin"]
        if entry["mapped_begin"] <= mapped_rva < mapped_end:
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError(f"Mapped RVA {mapped_rva:#x} does not map through exactly one build range")
    entry = matches[0]
    return entry["begin"] + mapped_rva - entry["mapped_begin"]


def parse_graphics_shader_bytecodes(desc: bytes) -> dict[str, tuple[int, int]]:
    """Parse the five D3D12_SHADER_BYTECODE fields from a native x64 descriptor."""
    if len(desc) < 0x58:
        raise ValueError("D3D12 graphics pipeline descriptor prefix is truncated")
    return {stage: struct.unpack_from("<QQ", desc, pointer_offset)
            for stage, (pointer_offset, _) in SHADER_STAGES.items()}


def matching_shader_stages(desc: bytes, read, wanted_sha256: str,
                           maximum_shader_bytes: int = 1 << 20) -> list[dict]:
    matches = []
    for stage, (address, size) in parse_graphics_shader_bytecodes(desc).items():
        if not address or not size:
            continue
        if size > maximum_shader_bytes:
            raise ValueError(f"{stage} shader bytecode exceeds the bounded capture limit")
        payload = read(address, size)
        if len(payload) != size:
            raise ValueError(f"{stage} shader bytecode capture is incomplete")
        digest = hashlib.sha256(payload).hexdigest()
        if digest == wanted_sha256:
            matches.append({"stage": stage, "address": address, "size": size, "sha256": digest})
    return matches


def parse_resource_desc(desc: bytes) -> dict:
    """Parse the Windows SDK x64 D3D12_RESOURCE_DESC (56 bytes)."""
    if len(desc) != 56:
        raise ValueError("D3D12 resource descriptor must be exactly 56 bytes")
    dimension = struct.unpack_from("<I", desc, 0)[0]
    alignment, width = struct.unpack_from("<QQ", desc, 8)
    height = struct.unpack_from("<I", desc, 24)[0]
    depth, mip_levels = struct.unpack_from("<HH", desc, 28)
    fmt, sample_count, sample_quality, layout, flags = struct.unpack_from("<IIIII", desc, 32)
    return dict(dimension=dimension, alignment=alignment, width=width, height=height,
                depth_or_array_size=depth, mip_levels=mip_levels, format=fmt,
                sample_count=sample_count, sample_quality=sample_quality,
                layout=layout, flags=flags)


def validate_d3d12_resource_desc_header(header: Path) -> dict:
    """Pin the SDK declaration and native x64 layout used by GetDesc capture."""
    text = header.read_text(encoding="utf-8", errors="replace")
    required = (
        "typedef struct D3D12_RESOURCE_DESC",
        "D3D12_RESOURCE_DIMENSION Dimension;",
        "UINT64 Width;",
        "UINT Height;",
        "UINT16 DepthOrArraySize;",
        "UINT16 MipLevels;",
        "DXGI_FORMAT Format;",
        "DXGI_SAMPLE_DESC SampleDesc;",
        "D3D12_TEXTURE_LAYOUT Layout;",
        "D3D12_RESOURCE_FLAGS Flags;",
        "virtual D3D12_RESOURCE_DESC STDMETHODCALLTYPE GetDesc( void) = 0;",
    )
    missing = [fragment for fragment in required if fragment not in text]
    if missing:
        raise ValueError("Windows SDK d3d12.h lacks the pinned ID3D12Resource::GetDesc contract")
    return {
        "path": str(header.resolve()),
        "sha256": sha256_file(header),
        "method": "ID3D12Resource::GetDesc",
        "vtable_slot": GET_RESOURCE_DESC_SLOT,
        "return_type": "D3D12_RESOURCE_DESC",
        "x64_size": 56,
    }


def is_target_texture(desc: bytes, *, width: int, height: int,
                      depth_or_array_size: int = 1, mip_levels: int = 1) -> bool:
    parsed = parse_resource_desc(desc)
    return (parsed["dimension"] == 3 and parsed["width"] == width and
            parsed["height"] == height and parsed["depth_or_array_size"] == depth_or_array_size and
            parsed["mip_levels"] == mip_levels)


def is_replay_format7_resident_texture(desc: bytes, *, width: int = 4, height: int = 4) -> bool:
    """Validate Replay GfxImage format 7's native D3D12 resource contract."""
    parsed = parse_resource_desc(desc)
    return (parsed["dimension"] == 3 and parsed["width"] == width and
            parsed["height"] == height and parsed["depth_or_array_size"] == 1 and
            parsed["mip_levels"] == 1 and parsed["format"] in (27, 28, 29) and
            parsed["sample_count"] == 1)


def resource_desc_semantically_equal(left: bytes, right: bytes) -> bool:
    """Compare every declared D3D12_RESOURCE_DESC field, excluding tail padding."""
    return parse_resource_desc(left) == parse_resource_desc(right)


def successful_com_creation(hresult: int, output_pointer: int) -> bool:
    """Apply SUCCEEDED(hr) and require the API to have returned an interface."""
    return (hresult & 0x80000000) == 0 and output_pointer != 0


def build_contract(database: Path, executable: Path, build_report: Path | None = None) -> dict:
    evidence = validate_sqlite_device_evidence(database)
    mapped_device_rva = DEVICE_GLOBAL_RVA
    report_identity = None
    if build_report:
        report = json.loads(build_report.read_text(encoding="utf-8"))
        executable_sha = sha256_file(executable)
        if report.get("sha256") != executable_sha:
            raise ValueError("Build report does not describe the selected executable")
        mapped_device_rva = map_original_rva(report, DEVICE_GLOBAL_RVA)
        report_identity = {"path": str(build_report.resolve()), "sha256": executable_sha}
    return {
        "schema": "replay-d3d12-live-checkpoints-v1",
        "target": {"executable": str(executable.resolve()), "sha256": sha256_file(executable),
                   "database": str(database.resolve()), "database_sha256": sha256_file(database),
                   "build_report": report_identity},
        "device": {**evidence, "mapped_device_global_rva": mapped_device_rva,
                   "runtime_resolution": "read image_base + mapped RVA, dereference device, then dereference vtable"},
        "checkpoints": {
            "shader_pso": {
                "method": "ID3D12Device::CreateGraphicsPipelineState", "vtable_slot": 10,
                "entry": "RDX points to D3D12_GRAPHICS_PIPELINE_STATE_DESC; hash bounded VS/PS/DS/HS/GS bytecode",
                "return": "RAX is HRESULT; dereference the pre-call R9 output address",
                "success": "matching program SHA256, HRESULT SUCCEEDED, and non-null output PSO",
            },
            "texture_committed": {
                "method": "ID3D12Device::CreateCommittedResource", "vtable_slot": 27,
                "entry": "R9 points to D3D12_RESOURCE_DESC under Windows x64 COM ABI",
                "return": "RAX is HRESULT; dereference stack argument 8 output address",
            },
            "texture_placed": {
                "method": "ID3D12Device::CreatePlacedResource", "vtable_slot": 29,
                "entry": "R9 points to D3D12_RESOURCE_DESC under Windows x64 ABI",
                "return": "RAX is HRESULT; dereference stack argument 8 output address",
            },
        },
        "bounds": {"maximum_shader_bytes": 1 << 20, "maximum_matching_calls": 1,
                   "maximum_method_hits": 20000, "timeout_seconds": 120},
        "claim_limit": "A matched successful COM call proves native GPU object creation. Texture dimensions alone do not bind the resource to $black; require the loader root/name capture on the same run.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--build-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contract = build_contract(args.database, args.executable, args.build_report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "schema": contract["schema"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
