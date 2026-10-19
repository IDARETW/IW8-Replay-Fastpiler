"""Verify every emitted native shader against its pinned 1.31 source bytes.

The output is deliberately limited to a shader-only stored Replay fastfile.
This check establishes serialization and bytecode preservation, not scene ABI
compatibility or GPU pipeline creation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
FOLLOWS = (1 << 64) - 2
INSERT = (1 << 64) - 3
SHARED = (1 << 64) - 1


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dxbc_stage(code):
    assert code[:4] == b"DXBC" and len(code) >= 32
    size, count = struct.unpack_from("<II", code, 24)
    assert size == len(code) and count <= (size - 32) // 4
    stages = []
    for index in range(count):
        offset = struct.unpack_from("<I", code, 32 + 4 * index)[0]
        assert offset <= size - 8
        chunk_size = struct.unpack_from("<I", code, offset + 4)[0]
        assert chunk_size <= size - offset - 8
        if code[offset:offset + 4] in (b"SHDR", b"SHEX"):
            assert chunk_size >= 8
            stages.append(struct.unpack_from("<I", code, offset + 8)[0] >> 16)
    assert len(stages) == 1 and stages[0] in (0, 1, 3, 4)
    return {0: 17, 1: 14, 3: 15, 4: 16}[stages[0]]


def verify(metadata):
    manifest = json.loads(metadata.read_text())
    inputs = manifest.get("Inputs") or [{
        "Name": "common", "Path": manifest["Input"], "Sha256": manifest["InputSha256"]}]
    sources = {}
    alias_map = {}
    if manifest.get("LocalMpAliases") or manifest.get("LocalMpNamespace"):
        alias_bytes = Path(manifest["AliasMap"]).read_bytes()
        assert sha(alias_bytes) == manifest["AliasMapSha256"]
        for line in alias_bytes.decode("ascii").splitlines():
            kind, original, alias = line.split("\t")
            key = (int(kind), alias)
            assert key not in alias_map
            alias_map[key] = original
    for source in inputs:
        data = Path(source["Path"]).read_bytes()
        assert sha(data) == source["Sha256"]
        sources[source["Name"]] = data
    data = Path(manifest["Output"]).read_bytes()
    assert sha(data) == manifest["OutputSha256"]
    assert data[:8] == b"IWffc100"
    assert struct.unpack_from("<II", data, 8) == (11, 4087)
    assert data[16:20] == b"\0" * 4 and data[0x88:0x8c] == b"\x01IWC"
    resident = struct.unpack_from("<Q", data, 20)[0]
    assert resident == len(data) - 0x88
    body = data[0x8c:]
    strings, loaded, pointer, count, read_pos, assets = struct.unpack_from("<IIQIIQ", body)
    assert (strings, loaded, pointer, read_pos, assets) == (0, 0, 0, 0, FOLLOWS)
    assert count == manifest["ShaderCount"] == len(manifest["Definitions"])
    cursor = 32 + count * 16
    records = []
    seen = set()
    pattern = re.compile(r"([0-9a-f]{1,32}) offset=(\d+) bytes=(\d+) type=(14|15|16|17)(?: source=(\w+))?(?: aliasof=([0-9a-f]{32}))?")
    for index, text in enumerate(manifest["Definitions"]):
        match = pattern.fullmatch(text)
        assert match, text
        name, offset, size, asset_type, source, alias_of = match.groups()
        offset, size, asset_type = int(offset), int(size), int(asset_type)
        source = source or "common"
        native_type, padding, insertion = struct.unpack_from("<IIQ", body, 32 + 16 * index)
        assert (native_type, padding, insertion) == (asset_type, 0, INSERT)
        name_bytes = name.encode() + b"\0"
        source_name_bytes = (alias_of or name).encode() + b"\0"
        source_data = sources[source]
        assert source_data[offset:offset + len(source_name_bytes)] == source_name_bytes
        if alias_of:
            assert alias_map[(asset_type, name)] == alias_of
        source_header = source_data[offset - 40:offset]
        source_fields = struct.unpack("<QQQQII", source_header)
        assert source_fields[0] == FOLLOWS and source_fields[2:4] == (0, FOLLOWS)
        assert source_fields[4] == size
        source_code = offset + len(source_name_bytes)
        if source_fields[1] in (FOLLOWS, SHARED):
            end = source_data.find(b"\0", source_code, source_code + 256)
            assert end >= source_code
            source_code = end + 1
        else:
            assert source_fields[1] == 0 or (
                source_fields[1] >> 32 == 5 and source_fields[1] & 0xffffffff)
        code = source_data[source_code:source_code + size]
        assert len(code) == size and dxbc_stage(code) == asset_type
        expected_header = bytearray(source_header)
        expected_header[8:16] = b"\0" * 8
        assert body[cursor:cursor + 40] == expected_header
        cursor += 40
        assert body[cursor:cursor + len(name_bytes)] == name_bytes
        cursor += len(name_bytes)
        assert body[cursor:cursor + size] == code
        cursor += size
        key = (asset_type, name)
        assert key not in seen
        seen.add(key)
        records.append(dict(name=name, type=asset_type, source=source, alias_of=alias_of, size=size,
                            native_hash=hex(source_fields[5]), bytecode_sha256=sha(code)))
    assert cursor == len(body), "Unconsumed output bytes"
    assert {(record["type"], record["name"]) for record in records if record["alias_of"]} == set(alias_map)
    if manifest.get("LocalMpNamespace"):
        assert all(record["alias_of"] for record in records)
    return dict(passed=True, output_sha256=sha(data), shader_count=count,
                types=dict(Counter(record["type"] for record in records)),
                sources=dict(Counter(record["source"] for record in records)),
                scene_compatibility_verified=False, shaders=records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, default=ROOT / "evidence/mw131-converted-shader-zone.json")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/mw131-converted-code-shaders-verification.json")
    args = parser.parse_args()
    result = verify(args.metadata)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "shaders"}, indent=2))
