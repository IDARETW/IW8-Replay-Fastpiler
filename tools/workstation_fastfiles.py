"""Native Replay 1.20 fastfile framing, decoding, and reader-walk workspace.

Whole-body container repacking is supported. Typed asset writes remain
fail-closed except for the ScriptFile inline-child contract whose physical
ownership and stream-6 tail behavior are proved by a complete native trace.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Sequence

try:
    from .inspect_frontend_asset_table import inspect as inspect_xasset_list
except ImportError:  # Direct tools/*.py execution keeps the tools directory on sys.path.
    from inspect_frontend_asset_table import inspect as inspect_xasset_list


HEADER_SIZE = 0x88
FRAME_MARKER = b"\x01IWC"
MAGIC_UNSECURED = b"IWffc100"
HEADER_VERSION_REPLAY = 11
XFILE_VERSION_REPLAY = 0xFF7
STREAM_COUNT = 11
SHADER_TYPE_IDS = {"computeshader": 12, "vertexshader": 14, "hullshader": 15,
                   "domainshader": 16, "pixelshader": 17}
SHADER_TYPE_NAMES = {value: key for key, value in SHADER_TYPE_IDS.items()}
SHADER_TYPES = frozenset(SHADER_TYPE_IDS.values())
ACTS_DEFAULT = Path(os.environ.get("REPLAY_ACTS", "__REPLAY_ACTS_NOT_CONFIGURED__"))
REPLAY_EXECUTABLE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
REPLAY_EXECUTABLE_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
_TRACE_CAPABILITY_CACHE: dict[str, bool] = {}


def _acts_supports_replay_stream_trace(acts: Path) -> bool:
    """Probe CLI help so older installed ACTS binaries retain normal inventory support."""
    tool = acts_tool_identity(acts)
    digest = hashlib.sha256(json.dumps(tool, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    if digest not in _TRACE_CAPABILITY_CACHE:
        try:
            probe = subprocess.run([str(acts), "--noUpdater", "fastfile", "--help"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   check=False, timeout=30)
            output = probe.stdout.decode("utf-8", errors="replace")
            _TRACE_CAPABILITY_CACHE[digest] = "--trace-replay-streams" in output
        except (OSError, subprocess.TimeoutExpired):
            _TRACE_CAPABILITY_CACHE[digest] = False
    return _TRACE_CAPABILITY_CACHE[digest]
DEFAULT_GSC_TOOL = Path(os.environ.get(
    "REPLAY_GSC_TOOL",
    str(Path(__file__).resolve().parent / "bin" / "gsc-tool-1.5.1" / "gsc-tool.exe")))
OBSERVED_REPLAY_SOURCE_REVISIONS = (4045, 4047, 4053, 4065, 4083, 4085, 4087)
# Additional signed-source transient pairs are admitted only after a concrete
# ACTS decode, strict XAsset table parse, and complete Replay native walk.
# This is a read profile only; output writers and stored-frame containers keep
# their narrower transient 0/1 contract.
OBSERVED_REPLAY_NONSTANDARD_TRANSIENT_PROFILES = frozenset(
    {(4045, transient) for transient in range(7, 14)} |
    {(4065, 5), (4083, 2), (4083, 3), (4083, 5)})


class UnsupportedAssetGraphError(RuntimeError):
    """Raised when a table entry lacks a complete, hash-pinned native reader walk."""


class AssetNotFoundError(KeyError):
    pass


@dataclass(frozen=True)
class AssetRequestSnapshot:
    """One request's fully checked decoded zone and native-walk evidence.

    This object is passed through one public create/get/list/preflight call only.
    It is never retained on the workspace or shared between requests.
    """
    zone_id: str
    workspace_identity: tuple[str, ...]
    cache_path: Path
    decode_receipt: dict
    body: "ZoneBody"
    body_path: Path
    source_path: Path
    source_profile: dict | None
    native_walk: dict | None
    native_rows: list[dict] | None


class ReadOnlyAssetError(RuntimeError):
    """Raised until a typed writer and complete native package schedule exist."""


@dataclass(frozen=True)
class DecodedAsset:
    """Adapter passed between a proven reader schedule and semantic codecs.

    Child names are type-specific; `provenance` must identify zone/body hashes,
    XAsset index, and each child's stream and serialized ownership evidence.
    """

    asset_id: str
    zone_id: str
    type_id: int
    name: str | None
    serialized_root: bytes
    children: dict[str, bytes | int]
    provenance: dict


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def _u64(data: bytes, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_native_package_copy(staged_ff: str | Path, staged_fp: str | Path,
                               output_ff: str | Path, output_fp: str | Path,
                               *, expected_ff_sha256: str,
                               expected_fp_sha256: str) -> tuple[str, str]:
    """Require copied FF/FP bytes to remain the package accepted by the native reader."""
    expected = (expected_ff_sha256, expected_fp_sha256)
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
           for value in expected):
        raise ValueError("native-read package receipt hashes are missing or malformed")
    if (sha256_file(staged_ff), sha256_file(staged_fp)) != expected:
        raise ValueError("staged FF/FP changed after the exact native-read package receipt")
    copied = (sha256_file(output_ff), sha256_file(output_fp))
    if copied != expected:
        raise ValueError("copied FF/FP differ from the exact native-read package")
    return copied


def ordered_asset_identity_sha256(rows: Sequence[dict]) -> str:
    """Hash the native reader's ordered top-level type/name journal identity."""
    identities = [[row.get("type_id"), row.get("name")] for row in rows]
    return hashlib.sha256(json.dumps(identities, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _pending_content_sha(row: dict) -> str:
    """Return the source-text digest for legacy and versioned edit snapshots."""
    recorded = row.get("content_sha256")
    if isinstance(recorded, str) and re.fullmatch(r"[0-9a-f]{64}", recorded):
        return recorded
    return hashlib.sha256(str(row.get("content", "")).encode("utf-8")).hexdigest()


def parse_image_data_url(content: str, original_mip_count: int) -> tuple[bytes, int]:
    """Decode the editor PNG envelope and its optional requested mip count."""
    header, separator, encoded = content.partition(",") if isinstance(content, str) else ("", "", "")
    match = re.fullmatch(r"data:image/png(?:;mips=([1-9][0-9]*))?;base64", header)
    if not separator or not match or not isinstance(original_mip_count, int) or original_mip_count < 1:
        raise ValueError("image editor expects a PNG data URL with optional ;mips=N")
    try:
        png = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("image editor PNG data URL is malformed") from error
    return png, int(match.group(1)) if match.group(1) else original_mip_count


def parse_image_dds_data_url(content: str) -> bytes:
    """Decode the lossless resident-resource DDS editor envelope."""
    header, separator, encoded = content.partition(",") if isinstance(content, str) else ("", "", "")
    if not separator or header != "data:application/octet-stream;base64":
        raise ValueError("image resource editor expects an application/octet-stream DDS data URL")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("image resource DDS data URL is malformed") from error
    if not payload.startswith(b"DDS "):
        raise ValueError("image resource data URL does not contain a DDS file")
    return payload


def _resident_image_typed_layout(layout: dict) -> dict:
    """Return the established PNG identity, extending it only for complex DDS resources."""
    width, height, depth, elements = layout["dimensions"]
    identity = dict(root_archive_offset=layout["root_archive_offset"],
                    name_archive_offset=layout["name_archive_offset"],
                    child_archive_offset=layout["payload_archive_offset"],
                    child_bytes=len(layout["payload"]), format=layout["format"],
                    dimensions=list(layout["dimensions"]), level_count=layout["level_count"])
    if depth != 1 or elements != 1:
        identity.update(flags=layout["flags"],
                        resource_kind="volume" if depth > 1 else "2d-array",
                        array_count=elements if depth == 1 else 1,
                        volume_depth=depth if depth > 1 else 1,
                        atlas_token=struct.unpack_from("<Q", layout["root_bytes"], 8)[0],
                        fallback_token=struct.unpack_from("<Q", layout["root_bytes"], 0xD8)[0],
                        cube_status="unverified; native root flag semantics remain opaque")
    return identity


def _validate_resident_image_typed_layout(expected: dict, layout: dict) -> None:
    """Validate immutable core geometry; complex-resource metadata is mandatory for DDS."""
    actual = _resident_image_typed_layout(layout)
    core_keys = ("root_archive_offset", "name_archive_offset", "child_archive_offset",
                 "child_bytes", "format", "dimensions", "level_count")
    if not isinstance(expected, dict) or any(expected.get(key) != actual[key] for key in core_keys):
        raise ValueError("image root/child layout changed; reload before saving")
    if len(layout["dimensions"]) != 4:
        raise ValueError("resident image dimensions are malformed")
    complex_resource = layout["dimensions"][2] != 1 or layout["dimensions"][3] != 1
    if complex_resource:
        complex_keys = ("flags", "resource_kind", "array_count", "volume_depth",
                        "atlas_token", "fallback_token", "cube_status")
        if any(key not in expected or expected.get(key) != actual[key] for key in complex_keys):
            raise ValueError("complex DDS source identity is incomplete or changed; reload before saving")
    else:
        # If an older DDS draft happens to carry expanded fields, validate each
        # one instead of trusting or silently discarding it.
        optional_native_fields = {
            "flags": layout["flags"],
            "atlas_token": struct.unpack_from("<Q", layout["root_bytes"], 8)[0],
            "fallback_token": struct.unpack_from("<Q", layout["root_bytes"], 0xD8)[0],
        }
        if any(key in expected and expected.get(key) != value
               for key, value in optional_native_fields.items()):
            raise ValueError("image root flags or child references changed; reload before saving")


def _edit_snapshot_revision(row: dict) -> str:
    """Bind an immutable edit revision to payload, compiler receipt, and source identity."""
    content_sha = _pending_content_sha(row)
    receipt = row.get("compiler_receipt")
    receipt_digest = None
    if isinstance(receipt, dict):
        receipt_digest = hashlib.sha256(json.dumps(
            receipt, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
    basis = {
        "schema": "replay120-immutable-edit-snapshot-v1",
        "asset_id": row.get("asset_id"),
        "type_id": row.get("type_id"),
        "name": row.get("name"),
        "content_sha256": content_sha,
        "edited_payload_sha256": row.get("edited_payload_sha256"),
        "compiler_receipt_sha256": row.get("compiler_receipt_sha256"),
        "compiler_receipt_actual_sha256": receipt_digest,
        "native_source_identity": row.get("native_source_identity"),
    }
    canonical = json.dumps(basis, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_pending_snapshot(cache_path: Path, index: int, asset_id: str,
                                body: ZoneBody) -> tuple[Path, dict, Path]:
    """Validate immutable staged bytes without requiring the source/tool to remain current."""
    current_path = cache_path / "pending-edits" / str(index) / "current.json"
    row = json.loads(current_path.read_text(encoding="utf-8"))
    revision = row.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ValueError("staged edit has no valid immutable revision")
    snapshot_path = current_path.parent / f"{revision}.json"
    if not snapshot_path.is_file() or json.loads(snapshot_path.read_text(encoding="utf-8")) != row:
        raise ValueError("staged edit differs from its immutable revision snapshot")
    if (row.get("asset_id") != asset_id or row.get("xasset_index") != index or
            row.get("type_id") != body.assets[index].type_id):
        raise ValueError("staged edit snapshot does not identify this XAsset row")
    if row.get("schema") == 3:
        if (_pending_content_sha(row) != hashlib.sha256(str(row.get("content", "")).encode("utf-8")).hexdigest() or
                _edit_snapshot_revision(row) != revision):
            raise ValueError("staged edit content or source/tool snapshot digest is invalid")
    elif hashlib.sha256(str(row.get("content", "")).encode("utf-8")).hexdigest() != revision:
        raise ValueError("legacy staged edit text differs from its content revision")
    if not isinstance(row.get("content"), str):
        raise ValueError("staged edit content is not text")
    payload_rel = Path(row.get("edited_payload_path", ""))
    if payload_rel.name != str(payload_rel) or payload_rel.is_absolute():
        raise ValueError("staged edit payload path is invalid")
    payload_path = current_path.parent / payload_rel
    if not payload_path.is_file() or sha256_file(payload_path) != row.get("edited_payload_sha256"):
        raise ValueError("staged edit payload does not match its immutable snapshot")
    return current_path, row, payload_path


def _pe_import_names(path: Path) -> set[str]:
    """Read direct PE imports using only the standard library."""
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"ACTS dependency is not a PE image: {path}")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"ACTS dependency has an invalid PE header: {path}")
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directory_offset = 112 if magic == 0x20b else 96 if magic == 0x10b else None
    if directory_offset is None or optional_size < directory_offset + 16:
        raise ValueError(f"ACTS dependency has an unsupported PE optional header: {path}")
    import_rva, import_size = struct.unpack_from("<II", data, optional + directory_offset + 8)
    if not import_rva or not import_size:
        return set()
    section_table = optional + optional_size
    sections = []
    for i in range(section_count):
        at = section_table + i * 40
        if at + 40 > len(data):
            raise ValueError(f"ACTS dependency has a truncated PE section table: {path}")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, at + 8)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))

    def rva_offset(rva: int) -> int:
        for address, extent, raw_offset, raw_size in sections:
            if address <= rva < address + extent:
                offset = raw_offset + rva - address
                if offset >= raw_offset + raw_size or offset >= len(data):
                    break
                return offset
        raise ValueError(f"ACTS dependency import RVA is unmapped: {path}")

    imports = set()
    descriptor = rva_offset(import_rva)
    end = min(len(data), descriptor + import_size)
    while descriptor + 20 <= end:
        fields = struct.unpack_from("<IIIII", data, descriptor)
        if not any(fields):
            break
        name_offset = rva_offset(fields[3])
        name_end = data.find(b"\0", name_offset, min(len(data), name_offset + 4096))
        if name_end < 0:
            raise ValueError(f"ACTS dependency has an unterminated PE import name: {path}")
        imports.add(data[name_offset:name_end].decode("ascii", errors="strict"))
        descriptor += 20
    return imports


def acts_tool_identity(acts_path: str | Path) -> dict:
    """Pin ACTS executable, its adjacent native DLL closure, and shipped data files."""
    executable = Path(acts_path).resolve(strict=True)
    pending = [executable]
    pending.extend(path.resolve(strict=True) for path in executable.parent.glob("*.dll")
                   if path.is_file())
    binaries: dict[str, dict] = {}
    external_imports: set[str] = set()
    while pending:
        binary = pending.pop()
        key = binary.name.casefold()
        if key in binaries:
            continue
        imports = _pe_import_names(binary)
        binaries[key] = dict(name=binary.name, bytes=binary.stat().st_size,
                             sha256=sha256_file(binary), imports=sorted(imports))
        for name in imports:
            local = binary.parent / name
            if local.is_file():
                pending.append(local.resolve(strict=True))
            else:
                external_imports.add(name)
    data_files = []
    data_root = executable.parent / "data"
    if data_root.is_dir():
        for path in sorted((p for p in data_root.rglob("*") if p.is_file()),
                           key=lambda p: p.relative_to(data_root).as_posix().casefold()):
            data_files.append(dict(path=path.relative_to(data_root).as_posix(),
                                   bytes=path.stat().st_size, sha256=sha256_file(path)))
    return dict(schema=1, executable_name=executable.name,
                executable_sha256=binaries[executable.name.casefold()]["sha256"],
                binaries=sorted(binaries.values(), key=lambda item: item["name"].casefold()),
                external_imports=sorted(external_imports, key=str.casefold),
                data_files=data_files)


@dataclass(frozen=True)
class SourceFastfileHeader:
    """Observed source FF header profile, before ACTS decompresses it."""

    magic: str
    header_version: int
    xfile_version: int
    compression: int
    encryption: int
    transient_type: int
    file_bytes: int
    resident_part_size: int
    inner_marker: str
    signature_bytes_sha256: str

    @classmethod
    def parse(cls, raw: bytes, file_bytes: int | None = None) -> "SourceFastfileHeader":
        if len(raw) < 0xA0:
            raise ValueError("truncated source Replay FF header")
        if raw[:8] != b"IWffa100":
            raise ValueError("source decoder currently requires signed IW Replay FFs")
        header_version, xfile_version = struct.unpack_from("<II", raw, 8)
        if header_version != HEADER_VERSION_REPLAY:
            raise ValueError("source FF header version is not Replay 1.20 version 11")
        compression, encryption, transient = raw[0x10:0x13]
        if compression != 1 or encryption != 0:
            raise ValueError("unsupported source FF compression/encryption profile")
        # This exact signed Replay profile was read by the pinned ACTS Replay
        # 1.20 decoder and complete native walker (xfile 4045, transient 13).
        # Keep it source-read-only: pack_replay_uncompressed and the unsigned
        # IWC writer continue to admit only their established transient values.
        if transient not in (0, 1) and \
                (xfile_version, transient) not in OBSERVED_REPLAY_NONSTANDARD_TRANSIENT_PROFILES:
            raise ValueError("unknown Replay transient file type")
        marker = raw[0x88:0x90]
        if marker != b"IWffs100":
            raise ValueError("source FF authentication-header marker is missing")
        file_bytes = len(raw) if file_bytes is None else file_bytes
        resident = _u32(raw, 0x14)
        if resident != file_bytes - 0x88:
            raise ValueError("resident part extent disagrees with source file length")
        return cls(magic=raw[:8].decode("ascii"), header_version=header_version,
                   xfile_version=xfile_version, compression=compression,
                   encryption=encryption, transient_type=transient,
                   file_bytes=file_bytes, resident_part_size=resident,
                   inner_marker=marker.decode("ascii"),
                   signature_bytes_sha256=hashlib.sha256(raw[0x90:0xA0]).hexdigest())


def _source_header(path: Path) -> SourceFastfileHeader:
    with path.open("rb") as stream:
        prefix = stream.read(0xA0)
    return SourceFastfileHeader.parse(prefix, file_bytes=path.stat().st_size)


def _stream_header_details(path: Path, *, patch: bool = False) -> dict:
    """Read decoded-size and stream reservations from an FF or FP/FC header."""
    with path.open("rb") as stream:
        prefix = stream.read(4096)
    if patch:
        offsets = [match.start() for match in re.finditer(rb"IWff[ac]100", prefix)]
        if len(offsets) != 2 or offsets[0] != 56:
            raise ValueError(f"unrecognized patch header pair: {path}")
        header_at = offsets[1]
    else:
        header_at = 0
    return _stream_header_details_from_bytes(prefix, header_at)


def _stream_header_details_from_bytes(data: bytes, header_at: int) -> dict:
    if header_at < 0 or header_at + 0x88 > len(data):
        raise ValueError("truncated stream reservation header")
    return dict(decoded_size=_u64(data, header_at + 0x20),
                block_sizes=list(struct.unpack_from("<11Q", data, header_at + 0x30)))


@dataclass(frozen=True)
class AssetHeader:
    """One 16-byte XAsset table entry; payload boundary remains type-reader-owned."""

    index: int
    type_id: int
    pointer_token: int


@dataclass(frozen=True)
class ZoneBody:
    """Decoded XFile body plus its structurally checked XAssetList inventory."""

    data: bytes
    script_string_count: int
    asset_table_offset: int
    first_payload_offset: int
    assets: tuple[AssetHeader, ...]
    source_sha256: str

    @classmethod
    def parse(cls, data: bytes) -> "ZoneBody":
        table = inspect_xasset_list(data)
        rows = tuple(AssetHeader(row["index"], row["type_id"],
                                 int(row["pointer_token"], 16))
                     for row in table["assets"])
        return cls(data=data,
                   script_string_count=table["script_string_count"],
                   asset_table_offset=table["asset_table_offset"],
                   first_payload_offset=table["first_payload_offset"],
                   assets=rows,
                   source_sha256=hashlib.sha256(data).hexdigest())


@dataclass(frozen=True)
class StoredReplayFastfile:
    """Native Replay 1.20 unsigned, unencrypted, stored-frame FF container.

    The eleven stream sizes are logical memory reservations. Their sum may be
    larger than the stored body because stream-4 calc/zero-fill reservations
    are not serialized bytes.
    """

    header: bytes
    frame_marker: bytes
    body: ZoneBody
    stream_sizes: tuple[int, ...]
    preload_walk_size: int
    transient_type: int
    source_sha256: str

    @classmethod
    def parse(cls, raw: bytes) -> "StoredReplayFastfile":
        if len(raw) < HEADER_SIZE + len(FRAME_MARKER):
            raise ValueError("truncated Replay fastfile")
        if raw[:8] != MAGIC_UNSECURED:
            raise ValueError("only native unsecured Replay stored fastfiles are supported")
        header_version, xfile_version = struct.unpack_from("<II", raw, 8)
        if (header_version, xfile_version) != (HEADER_VERSION_REPLAY, XFILE_VERSION_REPLAY):
            raise ValueError("fastfile version does not match Replay 1.20")
        compression, encryption, transient_type = raw[0x10:0x13]
        if compression != 0 or encryption != 0:
            raise ValueError("compressed/encrypted fastfiles require the native decode pipeline")
        if transient_type not in (0, 1):
            raise ValueError("unsupported Replay stored-frame transient type")
        resident_size = _u32(raw, 0x14)
        always_loaded_size = _u32(raw, 0x1C)
        decoded_size = _u64(raw, 0x20)
        preload_walk_size = _u64(raw, 0x28)
        if raw[HEADER_SIZE:HEADER_SIZE + 4] != FRAME_MARKER:
            raise ValueError("unsupported stored-frame marker")
        body_bytes = raw[HEADER_SIZE + 4:]
        if decoded_size != len(body_bytes):
            raise ValueError("XFile decoded size differs from stored body length")
        if resident_size != len(body_bytes) + len(FRAME_MARKER):
            raise ValueError("resident part size differs from stored-frame extent")
        if always_loaded_size != len(body_bytes):
            raise ValueError("always-loaded size differs from decoded XFile body")
        stream_sizes = tuple(_u64(raw, 0x30 + 8 * i) for i in range(STREAM_COUNT))
        if sum(stream_sizes) < len(body_bytes):
            raise ValueError("stream reservations are smaller than serialized body")
        body = ZoneBody.parse(body_bytes)
        return cls(header=raw[:HEADER_SIZE], frame_marker=raw[HEADER_SIZE:HEADER_SIZE + 4],
                   body=body, stream_sizes=stream_sizes,
                   preload_walk_size=preload_walk_size, transient_type=transient_type,
                   source_sha256=hashlib.sha256(raw).hexdigest())

    def to_bytes(self, body: ZoneBody | None = None,
                 stream_sizes: Sequence[int] | None = None,
                 preload_walk_size: int | None = None) -> bytes:
        """Write a validated stored-frame container, preserving opaque header data.

        When replacing the body, callers must provide new logical stream sizes;
        no implicit size inference is made from an opaque serialized body.
        """
        target = self.body if body is None else body
        sizes = self.stream_sizes if stream_sizes is None else tuple(stream_sizes)
        if len(sizes) != STREAM_COUNT or any(not isinstance(x, int) or x < 0 for x in sizes):
            raise ValueError("exactly eleven nonnegative stream sizes are required")
        if body is not None and stream_sizes is None and body.data != self.body.data:
            raise ValueError("replacement body requires explicit stream reservation sizes")
        if body is not None and body.data != self.body.data and preload_walk_size is None:
            raise ValueError("replacement body requires explicit preload-walk metadata")
        walk_size = self.preload_walk_size if preload_walk_size is None else preload_walk_size
        if not isinstance(walk_size, int) or walk_size < 0 or walk_size > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("preload-walk size must be an unsigned 64-bit value")
        if sum(sizes) < len(target.data):
            raise ValueError("stream reservations are smaller than serialized body")
        if len(target.data) > 0xFFFFFFFF - len(FRAME_MARKER):
            raise ValueError("Replay resident body exceeds 32-bit header size")
        header = bytearray(self.header)
        struct.pack_into("<I", header, 0x14, len(target.data) + len(FRAME_MARKER))
        struct.pack_into("<I", header, 0x1C, len(target.data))
        struct.pack_into("<Q", header, 0x20, len(target.data))
        struct.pack_into("<Q", header, 0x28, walk_size)
        for index, size in enumerate(sizes):
            struct.pack_into("<Q", header, 0x30 + 8 * index, size)
        output = bytes(header) + FRAME_MARKER + target.data
        # Parse our own output so invalid body/table edits cannot escape as a
        # seemingly installable fastfile.
        StoredReplayFastfile.parse(output)
        return output


def pack_replay_uncompressed(body: bytes, stream_sizes: Sequence[int],
                             xfile_version: int = 0xFF7,
                             transient_type: int = 0,
                             chunk_size: int = 0x10000) -> bytes:
    """Pack a complete decoded Replay body as unsigned uncompressed IWC chunks.

    This is a container writer only. It preserves the body exactly and requires
    caller-provided final (post-FP/FC) stream reservations; it does not relocate
    or rewrite assets.
    """
    ZoneBody.parse(body)
    sizes = tuple(stream_sizes)
    if (len(sizes) != STREAM_COUNT or any(not isinstance(x, int) or x < 0 or x > 0xFFFFFFFFFFFFFFFF
                                           for x in sizes)):
        raise ValueError("exactly eleven unsigned stream reservations are required")
    if xfile_version != 0xFF7:
        raise ValueError("Replay 1.20 output must target XFile version 0xff7")
    if transient_type not in (0, 1) or not 1 <= chunk_size <= 0x10000:
        raise ValueError("invalid Replay transient type or IWC chunk size")
    if len(body) > 0xFFFFFFFF:
        raise ValueError("decoded Replay body exceeds the IWC 32-bit size field")

    output = bytearray(0x94)
    output[:8] = b"IWffc100"
    struct.pack_into("<II", output, 8, HEADER_VERSION_REPLAY, xfile_version)
    output[16:19] = bytes((0, 0, transient_type))
    struct.pack_into("<I", output, 0x1C, len(body))
    struct.pack_into("<Q", output, 0x20, len(body))
    for index, size in enumerate(sizes):
        struct.pack_into("<Q", output, 0x30 + index * 8, size)
    struct.pack_into("<I", output, 0x88, 0x43574902)
    struct.pack_into("<I", output, 0x8C, len(body))
    struct.pack_into("<I", output, 0x90, chunk_size | (1 << 24))
    for start in range(0, len(body), chunk_size):
        block = body[start:start + chunk_size]
        output.extend(struct.pack("<III", len(block), len(block), 0))
        output.extend(block)
        output.extend(b"\0" * ((-len(output)) & 3))
    struct.pack_into("<I", output, 0x14, len(output) - 0x88)
    unpacked = unpack_replay_uncompressed(bytes(output))
    if unpacked != body:
        raise ValueError("IWC writer self-check changed decoded body bytes")
    return bytes(output)


def unpack_replay_uncompressed(raw: bytes) -> bytes:
    """Strictly parse the uncompressed IWC subset emitted by this module."""
    return _parse_replay_uncompressed(raw)["body"]


def _parse_replay_uncompressed(raw: bytes) -> dict:
    """Validate the exact unsigned IWC framing emitted by this module.

    This parser deliberately does not accept the separate stored-frame format,
    signed ``IWffa100`` inputs, or compressed IWC variants. Stream reservations
    are returned as logical header values; the Replay native walk remains the
    authority for whether each reservation covers the actual stream high-water.
    """
    if not isinstance(raw, bytes) or len(raw) < 0x94 or raw[:8] != b"IWffc100":
        raise ValueError("invalid Replay IWC container")
    version, xfile_version = struct.unpack_from("<II", raw, 8)
    if (version, xfile_version) != (HEADER_VERSION_REPLAY, XFILE_VERSION_REPLAY):
        raise ValueError("unsupported Replay IWC version")
    if raw[16] != 0 or raw[17] != 0 or raw[18] not in (0, 1) or raw[19] != 0:
        raise ValueError("unsupported Replay IWC compression, encryption, or transient fields")
    if struct.unpack_from("<I", raw, 0x14)[0] != len(raw) - HEADER_SIZE:
        raise ValueError("IWC resident size does not match file extent")
    if struct.unpack_from("<I", raw, 0x18)[0] != 0:
        raise ValueError("IWC reserved header word is nonzero")
    body_size = _u64(raw, 0x20)
    if body_size > 0xFFFFFFFF or struct.unpack_from("<I", raw, 0x1C)[0] != body_size:
        raise ValueError("IWC decoded and always-loaded sizes disagree")
    if _u64(raw, 0x28) != 0:
        raise ValueError("IWC preload-walk field is outside the emitted format")
    stream_sizes = tuple(struct.unpack_from("<11Q", raw, 0x30))
    if len(stream_sizes) != STREAM_COUNT:
        raise ValueError("IWC stream reservation count is invalid")
    if (struct.unpack_from("<I", raw, 0x88)[0] != 0x43574902 or
            struct.unpack_from("<I", raw, 0x8C)[0] != body_size):
        raise ValueError("invalid IWC body header")
    descriptor = struct.unpack_from("<I", raw, 0x90)[0]
    chunk_size, algorithm = descriptor & 0xFFFFFF, descriptor >> 24
    if not 1 <= chunk_size <= 0x10000 or algorithm != 1:
        raise ValueError("container is not the supported uncompressed IWC profile")
    at, output = 0x94, bytearray()
    while len(output) < body_size:
        if at + 12 > len(raw):
            raise ValueError("truncated IWC chunk header")
        packed, unpacked, counter = struct.unpack_from("<III", raw, at)
        at += 12
        expected = min(chunk_size, body_size - len(output))
        if (packed != expected or unpacked != expected or counter != 0 or
                at + packed > len(raw)):
            raise ValueError("invalid uncompressed IWC chunk")
        output.extend(raw[at:at + packed])
        at += packed
        aligned = (at + 3) & ~3
        if aligned > len(raw) or any(raw[at:aligned]):
            raise ValueError("invalid IWC chunk alignment padding")
        at = aligned
    if at != len(raw) or len(output) != body_size:
        raise ValueError("IWC chunks do not end at the container boundary")
    body = bytes(output)
    ZoneBody.parse(body)
    return dict(body=body, header=dict(magic="IWffc100", header_version=version,
                                       xfile_version=xfile_version,
                                       compression=raw[16], encryption=raw[17],
                                       transient_type=raw[18]),
                resident_part_size=len(raw) - HEADER_SIZE,
                decoded_size=body_size, block_sizes=list(stream_sizes),
                chunk_size=chunk_size)


def make_replay_header_only_patch(template_patch: bytes, fastfile: bytes) -> bytes:
    """Build the native 0x148-byte Replay zero-payload FP/FC for an emitted FF.

    Replay's IW reader accepts a header-only patch when its previous header
    exactly matches the emitted file. The writer keeps identical previous and
    target headers for an already merged replacement, but clears the opaque
    patch fields: carrying those fields from a source delta advertises payload
    blocks that are absent from this zero-payload patch.
    """
    if len(template_patch) < 0x148 or template_patch[:8] != b"IWffd100":
        raise ValueError("template is not a bounded Replay IW FP/FC patch")
    if struct.unpack_from("<II", template_patch, 8)[0] != 6:
        raise ValueError("template patch version is not Replay patch version 6")
    if struct.unpack_from("<I", template_patch, 0x0C)[0] != 4:
        raise ValueError("template patch flags are outside the emitted Replay header-only profile")
    if len(fastfile) < 0x94 or fastfile[:8] != b"IWffc100":
        raise ValueError("replacement must be a native Replay uncompressed IWC FF")
    if struct.unpack_from("<II", fastfile, 8) != (11, 0xFF7):
        raise ValueError("replacement FF header does not target Replay XFile 0xff7")
    body = unpack_replay_uncompressed(fastfile)
    header = fastfile[:0x88]
    prefix = bytearray(template_patch[:0x38])
    prefix[0x10:0x38] = bytes(0x28)
    patch = bytes(prefix) + header + header
    if len(patch) != 0x148:
        raise AssertionError("header-only patch extent changed")
    # Cross-check through the same header-pair parser used by the workspace.
    from frontend_catalog import fastfile_header
    expected = dict(magic="IWffc100", header_version=11, xfile_version=0xFF7,
                    compression=0, encryption=0,
                    transient_type=fastfile[0x12])
    if fastfile_header(patch[0x38:0x38 + 0x88]) != expected or \
            fastfile_header(patch[0xC0:0xC0 + 0x88]) != expected:
        raise ValueError("generated no-op patch headers do not match emitted FF")
    if _u64(header, 0x20) != len(body):
        raise ValueError("replacement XFile size differs from no-op patch header")
    return patch


def replace_scriptfile_inline_children(body_data: bytes, asset_index: int, asset_name: str,
                                       trace_asset: dict, replacement_gscbin: bytes,
                                       expected_body_sha256: str | None = None,
                                       trace_safety: dict | None = None,
                                       allow_stream6_tail_growth: bool = False) -> tuple[bytes, dict]:
    """Replace one proven inline ScriptFile's serialized children.

    All contracts require the complete 40-byte root, inline name, and two
    stream-6 children. A changed child extent is accepted only when a complete
    zone trace proves this ScriptFile owns every stream-6 allocation, its
    children end at that stream's high-water mark, and no packed target points
    into stream 6. This avoids downstream relocation because this block has no
    later allocations or packed references in the captured zone.
    """
    from workstation_asset_codecs import inspect_gscbin

    body = ZoneBody.parse(body_data)
    if expected_body_sha256 is not None and body.source_sha256 != expected_body_sha256:
        raise ValueError("trace evidence belongs to a different decoded body")
    if not isinstance(asset_index, int) or not 0 <= asset_index < len(body.assets):
        raise ValueError("ScriptFile asset index is out of range")
    header = body.assets[asset_index]
    if header.type_id != 52:
        raise ValueError("selected XAsset is not a ScriptFile")
    if trace_asset.get("xasset_index") != asset_index or trace_asset.get("type_id") != 52 or \
            trace_asset.get("name") != asset_name:
        raise ValueError("native trace owner does not match selected ScriptFile identity")
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("native trace row has no physical read spans")
    roots = [s for s in spans if s.get("origin") == "load_stream_call" and
             s.get("reader_start_arg") == 0 and s.get("size") == 40]
    if len(roots) != 1:
        raise ValueError("ScriptFile must have exactly one traced 40-byte root read")
    root_at = roots[0].get("archive_offset")
    if not isinstance(root_at, int) or root_at + 40 > len(body.data):
        raise ValueError("ScriptFile root extent falls outside the decoded body")
    name_token, compressed_len, source_len, bytecode_len, reserved, buffer_token, bytecode_token = \
        struct.unpack_from("<QiiiIQQ", body.data, root_at)
    if name_token != 0xFFFFFFFFFFFFFFFF or buffer_token != 0xFFFFFFFFFFFFFFFE or \
            bytecode_token != 0xFFFFFFFFFFFFFFFE or reserved != 0:
        raise ValueError("ScriptFile root is not the proven inline-name/two-inline-child contract")
    if min(compressed_len, source_len, bytecode_len) <= 0:
        raise ValueError("ScriptFile child lengths must be positive for this writer")
    name_spans = [s for s in spans if s.get("origin") == "string_data" and
                  s.get("archive_offset") == root_at + 40 and
                  s.get("size") == len(asset_name.encode("utf-8")) + 1]
    if len(name_spans) != 1 or body.data[root_at + 40:root_at + 40 + len(asset_name) + 1] != \
            asset_name.encode("utf-8") + b"\0":
        raise ValueError("ScriptFile inline name is not an exact trace-owned span")
    child_start = root_at + 40 + len(asset_name.encode("utf-8")) + 1
    children = [s for s in spans if s.get("origin") == "load_stream_call" and
                s.get("reader_start_arg") == 0 and s.get("archive_offset", -1) >= child_start]
    children.sort(key=lambda s: s["archive_offset"])
    if len(children) != 2 or any(s.get("destination_stream_location", {}).get("stream") != 6
                                  for s in children):
        raise ValueError("ScriptFile must have exactly two owned AtStart stream-6 children")
    compressed_span, bytecode_span = children
    if (compressed_span["archive_offset"] != child_start or
            compressed_span["size"] != compressed_len or
            bytecode_span["archive_offset"] != child_start + compressed_len or
            bytecode_span["size"] != bytecode_len):
        raise ValueError("traced ScriptFile children do not match root lengths/serialized order")
    original_payload = struct.pack("<4I", 0x00435347, compressed_len,
                                   source_len, bytecode_len) + \
        body.data[compressed_span["archive_offset"]:compressed_span["archive_offset"] + compressed_len] + \
        body.data[bytecode_span["archive_offset"]:bytecode_span["archive_offset"] + bytecode_len]
    original = inspect_gscbin(original_payload)
    replacement = inspect_gscbin(replacement_gscbin)
    if original.bytecode_size != bytecode_len:
        raise ValueError("GSCBIN bytecode section disagrees with the proven ScriptFile root")
    extent_delta = (len(replacement.compressed_source) + len(replacement.bytecode) -
                    compressed_len - bytecode_len)
    child_high = max(s["destination_stream_location"]["offset"] + s["size"]
                     for s in (compressed_span, bytecode_span))
    if extent_delta:
        if not allow_stream6_tail_growth:
            raise ValueError("edited ScriptFile changes a child extent; relocation is unsupported")
        if not isinstance(trace_safety, dict):
            raise ValueError("changed child extent requires complete-zone stream/reference proof")

        def metric(container: dict, key: int, default=0):
            return container.get(key, container.get(str(key), default))

        original_child_extent = compressed_len + bytecode_len
        stream6_high = metric(trace_safety.get("global_max_destination_offsets", {}), 6)
        stream6_loads = metric(trace_safety.get("global_physical_load_count_by_stream", {}), 6)
        stream6_bytes = metric(trace_safety.get("global_physical_load_bytes_by_stream", {}), 6)
        stream6_targets = metric(trace_safety.get("packed_target_stream_counts", {}), 6)
        alias_tags = trace_safety.get("packed_alias_token_highword_counts", {})
        if any(not isinstance(int(tag), int) or int(tag) != 5 for tag in alias_tags):
            raise ValueError("stream-6 growth has a packed alias with an unclassified target tag")
        asset_loads = metric(trace_asset.get("physical_load_count_by_stream", {}), 6)
        asset_bytes = metric(trace_asset.get("physical_load_bytes_by_stream", {}), 6)
        asset_high = metric(trace_asset.get("max_destination_offsets", {}), 6)
        if (stream6_targets != 0 or stream6_loads != 2 or
                stream6_bytes != original_child_extent or
                asset_loads != 2 or asset_bytes != original_child_extent or
                stream6_high != child_high or asset_high != child_high):
            raise ValueError("stream-6 growth lacks sole-owner tail/no-packed-target proof")
    if (replacement.source_size > 0x7FFFFFFF or
            len(replacement.compressed_source) > 0x7FFFFFFF or
            len(replacement.bytecode) > 0x7FFFFFFF):
        raise ValueError("edited ScriptFile lengths exceed the Replay signed fields")
    changed = bytearray(body.data)
    struct.pack_into("<iii", changed, root_at + 8,
                     len(replacement.compressed_source), replacement.source_size,
                     len(replacement.bytecode))
    old_children_end = bytecode_span["archive_offset"] + bytecode_len
    new_children = replacement.compressed_source + replacement.bytecode
    changed[child_start:old_children_end] = new_children
    result = bytes(changed)
    reparsed = ZoneBody.parse(result)
    if reparsed.assets != body.assets or len(result) - len(body.data) != extent_delta:
        raise ValueError("ScriptFile replacement changed XAsset table or unexpected body extent")
    return result, dict(asset_index=asset_index, asset_name=asset_name,
                        root_archive_offset=root_at, root_bytes=40,
                        name_archive_offset=root_at + 40,
                        compressed_source_archive_offset=compressed_span["archive_offset"],
                        compressed_source_bytes=len(replacement.compressed_source),
                        bytecode_archive_offset=child_start + len(replacement.compressed_source),
                        bytecode_bytes=len(replacement.bytecode), source_bytes=replacement.source_size,
                        old_body_sha256=body.source_sha256,
                        new_body_sha256=reparsed.source_sha256,
                        body_extent_unchanged=len(result) == len(body.data),
                        xasset_table_unchanged=True,
                        stream6_extent_delta=extent_delta,
                        stream6_new_high_water=(stream6_high + extent_delta if extent_delta and trace_safety else
                                                child_high + extent_delta),
                        packed_alias_token_highword_counts=(trace_safety or {}).get(
                            "packed_alias_token_highword_counts", {}),
                        relocation_policy=("same-extent replacement preserves every later physical and resident offset"
                                           if not extent_delta else
                                           "accepted because the complete captured zone has no later stream-6 allocation or packed target"))


def replace_scriptfiles_inline_children(body_data: bytes, edits: Sequence[dict],
                                        trace_report: dict,
                                        expected_body_sha256: str | None = None) -> tuple[bytes, dict]:
    """Rewrite a subset of ScriptFiles that exclusively own a contiguous stream-6 run.

    The MP frontend trace proves that all stream-6 bytes belong to ScriptFile
    source/bytecode children. Splices run from highest to lowest original body
    offset, so earlier recorded offsets remain valid. This contract refuses
    any zone with another stream-6 owner, non-inline children, gaps, or packed
    references into stream 6.
    """
    original = bytes(body_data)
    body = ZoneBody.parse(original)
    original_sha = hashlib.sha256(original).hexdigest()
    if expected_body_sha256 and original_sha != expected_body_sha256:
        raise ValueError("decoded zone body SHA-256 differs from traced source")
    if (trace_report.get("xasset_count") != len(body.assets) or
            trace_report.get("serialized_bytes_read") != len(original)):
        raise ValueError("full native trace does not prove this body's complete table and EOF")
    rows = {row.get("xasset_index"): row
            for row in trace_report.get("selected_assets", [])
            if row.get("type_id") == 52}
    if not rows or len(rows) != trace_report.get("selected_count"):
        raise ValueError("trace report must contain every ScriptFile root in the zone")
    if any(not isinstance(index, int) or index < 0 or index >= len(body.assets) or
           body.assets[index].type_id != 52 for index in rows):
        raise ValueError("trace ScriptFile rows do not match the XAsset table")

    def metric(container: dict, key):
        return container.get(key, container.get(str(key), 0))

    high_water = metric(trace_report.get("global_max_destination_offsets", {}), 6)
    load_count = metric(trace_report.get("global_physical_load_count_by_stream", {}), 6)
    load_bytes = metric(trace_report.get("global_physical_load_bytes_by_stream", {}), 6)
    if metric(trace_report.get("packed_target_stream_counts", {}), 6):
        raise ValueError("packed references target stream 6; growth relocation is unsupported")
    if (load_count != 2 * len(rows) or
            sum(metric(row.get("physical_load_count_by_stream", {}), 6) for row in rows.values()) != load_count or
            sum(metric(row.get("physical_load_bytes_by_stream", {}), 6) for row in rows.values()) != load_bytes or
            high_water != load_bytes):
        raise ValueError("ScriptFiles do not exclusively own all stream-6 physical allocations")
    alias_tags = trace_report.get("packed_alias_token_highword_counts", {})
    # Native traces resolve both 0x5 global packed tokens and 0x15 asset-local
    # aliases in this zone to stream 5. Any other alias tag is unproven here.
    if any(not isinstance(int(tag), int) or int(tag) not in (5, 0x15) for tag in alias_tags):
        raise ValueError("ScriptFile relocation has an alias tag outside traced stream-5 forms")

    schedule = []
    next_stream6_offset = 0
    previous_archive_end = 0
    for index in sorted(rows):
        row = rows[index]
        root_reads = [span for span in row.get("read_spans", [])
                      if span.get("origin") == "load_stream_call" and
                      span.get("reader_start_arg") == 0 and span.get("size") == 40]
        child_reads = [span for span in row.get("read_spans", [])
                       if span.get("origin") == "load_stream_call" and
                       span.get("reader_start_arg") == 0 and
                       metric(span.get("destination_stream_location", {}), "stream") == 6]
        if len(root_reads) != 1 or len(child_reads) != 2:
            raise ValueError(f"ScriptFile {index} lacks one 40-byte root and exactly two child reads")
        child_reads.sort(key=lambda span: span["archive_offset"])
        first, second = child_reads
        first_at = first["archive_offset"]
        second_at = second["archive_offset"]
        first_dest = metric(first["destination_stream_location"], "offset")
        second_dest = metric(second["destination_stream_location"], "offset")
        if (first_dest != next_stream6_offset or
                second_dest != first_dest + first["size"] or
                second_at != first_at + first["size"]):
            raise ValueError(f"ScriptFile {index} child spans are not contiguous in archive and stream 6")
        root_at = root_reads[0]["archive_offset"]
        if (root_at != row.get("serialized_cursor_begin") or root_at < previous_archive_end or
                root_at >= first_at or first_at + first["size"] + second["size"] > len(original)):
            raise ValueError(f"ScriptFile {index} root/child spans are outside the source body")
        name_token, compressed_len, source_len, bytecode_len, reserved, source_ptr, bytecode_ptr = \
            struct.unpack_from("<QiiiIQQ", original, root_at)
        if (compressed_len != first["size"] or bytecode_len != second["size"] or
                reserved != 0 or source_ptr != 0xFFFFFFFFFFFFFFFE or
                bytecode_ptr != 0xFFFFFFFFFFFFFFFE):
            raise ValueError(f"ScriptFile {index} root lengths or inline sentinels disagree with its trace")
        original_packet = struct.pack("<4I", 0x00435347, compressed_len,
                                      source_len, bytecode_len) + \
                          original[first_at:first_at + first["size"]] + \
                          original[second_at:second_at + second["size"]]
        from workstation_asset_codecs import inspect_gscbin
        inspect_gscbin(original_packet)
        schedule.append(dict(index=index, row=row, root_offset=root_at,
                             first=first, second=second, stream6_offset=first_dest,
                             name_token=name_token, compressed_len=compressed_len,
                             source_len=source_len, bytecode_len=bytecode_len))
        previous_archive_end = second_at + second["size"]
        next_stream6_offset += first["size"] + second["size"]
    if next_stream6_offset != high_water:
        raise ValueError("ScriptFile schedule does not cover the complete stream-6 high-water")

    by_index = {item["index"]: item for item in schedule}
    edit_map = {}
    from workstation_asset_codecs import inspect_gscbin
    for edit in edits:
        index = edit.get("xasset_index")
        if index not in by_index or index in edit_map:
            raise ValueError("each edit must select one unique ScriptFile in the complete trace")
        if edit.get("name") != by_index[index]["row"].get("name"):
            raise ValueError(f"ScriptFile {index} name differs from the traced native asset")
        payload = edit.get("payload")
        if not isinstance(payload, bytes):
            raise TypeError("ScriptFile replacement must be a compiled GSCBIN payload")
        edit_map[index] = dict(payload=payload, info=inspect_gscbin(payload))
    if not edit_map:
        raise ValueError("at least one ScriptFile edit is required")

    updated = bytearray(original)
    for index, edit in edit_map.items():
        info = edit["info"]
        if max(len(info.compressed_source), info.source_size, len(info.bytecode)) > 0x7FFFFFFF:
            raise ValueError("edited ScriptFile section exceeds signed root fields")
        struct.pack_into("<iii", updated, by_index[index]["root_offset"] + 8,
                         len(info.compressed_source), info.source_size, len(info.bytecode))

    proofs = []
    for index in sorted(edit_map,
                        key=lambda i: by_index[i]["first"]["archive_offset"], reverse=True):
        item, edit = by_index[index], edit_map[index]
        first, second = item["first"], item["second"]
        old_end = second["archive_offset"] + second["size"]
        new_children = edit["payload"][16:]
        updated[first["archive_offset"]:old_end] = new_children
        delta = len(new_children) - (old_end - first["archive_offset"])
        proofs.append(dict(xasset_index=index, name=item["row"].get("name"),
                           root_offset_original=item["root_offset"],
                           child_offset_original=first["archive_offset"],
                           old_child_extent=old_end - first["archive_offset"],
                           new_child_extent=len(new_children), extent_delta=delta,
                           old_compressed_source_bytes=item["compressed_len"],
                           new_compressed_source_bytes=len(edit["info"].compressed_source),
                           old_source_bytes=item["source_len"],
                           new_source_bytes=edit["info"].source_size,
                           old_bytecode_bytes=item["bytecode_len"],
                           new_bytecode_bytes=len(edit["info"].bytecode)))

    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if reparsed.assets != body.assets:
        raise ValueError("ScriptFile multi-edit changed the XAsset table")
    delta_by_child = {proof["child_offset_original"]: proof["extent_delta"] for proof in proofs}
    for proof in proofs:
        root_at = proof["root_offset_original"] + sum(
            delta for child_at, delta in delta_by_child.items() if child_at < proof["root_offset_original"])
        root = struct.unpack_from("<QiiiIQQ", result, root_at)
        if (root[1] != proof["new_compressed_source_bytes"] or
                root[2] != proof["new_source_bytes"] or root[3] != proof["new_bytecode_bytes"]):
            raise ValueError("ScriptFile root sizes failed after multi-asset relocation")
    total_delta = sum(proof["extent_delta"] for proof in proofs)
    return result, dict(xasset_table_unchanged=True,
                        all_stream6_allocations_owned_by_scriptfiles=True,
                        packed_stream6_targets=0,
                        original_stream6_high_water=high_water,
                        new_stream6_high_water=high_water + total_delta,
                        stream6_extent_delta=total_delta,
                        edit_order="descending-original-archive-offset",
                        edited_assets=sorted(proofs, key=lambda row: row["xasset_index"]))


def replace_scriptfile_same_extent(body_data: bytes, asset_index: int, asset_name: str,
                                   trace_asset: dict, replacement_gscbin: bytes,
                                   expected_body_sha256: str | None = None) -> tuple[bytes, dict]:
    """Compatibility wrapper for strictly same-size ScriptFile edits."""
    return replace_scriptfile_inline_children(body_data, asset_index, asset_name,
                                              trace_asset, replacement_gscbin,
                                              expected_body_sha256,
                                              allow_stream6_tail_growth=False)


def load_fastfile(path: str | Path) -> StoredReplayFastfile:
    return StoredReplayFastfile.parse(Path(path).read_bytes())


def inventory(path: str | Path) -> dict:
    """Return container provenance and table rows, without inventing root spans."""
    archive = load_fastfile(path)
    return {
        "format": "replay120-stored-fastfile-inventory-v1",
        "path": str(Path(path).resolve()),
        "sha256": archive.source_sha256,
        "header_version": HEADER_VERSION_REPLAY,
        "xfile_version": XFILE_VERSION_REPLAY,
        "transient_type": archive.transient_type,
        "body_bytes": len(archive.body.data),
        "stream_reservations": list(archive.stream_sizes),
        "stream_calc_bytes": sum(archive.stream_sizes) - len(archive.body.data),
        "script_string_count": archive.body.script_string_count,
        "asset_table_offset": archive.body.asset_table_offset,
        "first_payload_offset": archive.body.first_payload_offset,
        "assets": [dict(index=row.index, type_id=row.type_id,
                         pointer_token=f"0x{row.pointer_token:016x}",
                         root_span=None,
                         root_span_note="requires typed reader/allocation schedule")
                   for row in archive.body.assets],
    }


def _unsigned_iwc_header_only_patch(source: Path, raw: bytes, observed: dict,
                                   layout: dict, *, required: bool) -> tuple[list[dict], dict]:
    """Validate an optional/required exact zero-payload Replay FP pair."""
    from frontend_catalog import fastfile_header
    fp = source.with_suffix(".fp")
    fc = source.with_suffix(".fc")
    if fc.exists():
        if required:
            raise ValueError("unsigned IWC input requires exactly one adjacent header-only .fp")
        raise ValueError("unsigned IWC input does not support an adjacent .fc")
    if not fp.is_file():
        if required:
            raise ValueError("unsigned IWC input requires exactly one adjacent header-only .fp")
        return [], {**observed, **layout}
    patch_bytes = fp.read_bytes()
    if len(patch_bytes) != 0x148 or patch_bytes[:8] != b"IWffd100":
        raise ValueError("unsigned IWC .fp must be the exact 0x148-byte Replay patch")
    patch_version, patch_flags = struct.unpack_from("<II", patch_bytes, 8)
    if patch_version != 6 or patch_flags != 4:
        raise ValueError("unsigned IWC .fp is outside the emitted Replay patch v6/flags-4 profile")
    if any(patch_bytes[0x10:0x38]):
        raise ValueError("unsigned IWC .fp carries unsupported patch payload metadata")
    if (patch_bytes[0x38:0xC0] != raw[:0x88] or
            patch_bytes[0xC0:0x148] != raw[:0x88]):
        raise ValueError("unsigned IWC .fp previous/target headers do not exactly match its FF")
    previous = fastfile_header(patch_bytes[0x38:0xC0])
    target = fastfile_header(patch_bytes[0xC0:0x148])
    if previous != observed or target != observed:
        raise ValueError("unsigned IWC .fp header pair differs from its validated FF")
    previous_layout = _stream_header_details_from_bytes(patch_bytes, 0x38)
    target_layout = _stream_header_details_from_bytes(patch_bytes, 0xC0)
    if previous_layout != layout or target_layout != layout:
        raise ValueError("unsigned IWC .fp stream reservations differ from its FF")
    patch = dict(path=fp, extension=".fp", header_version=patch_version,
                 previous=previous, target=target,
                 previous_layout=previous_layout, target_layout=target_layout,
                 bytes=len(patch_bytes), sha256=hashlib.sha256(patch_bytes).hexdigest())
    return [patch], {**target, **target_layout}


def _unsigned_iwc_source_profile(source: Path) -> dict:
    """Validate the supported stored-frame and emitted chunked IWC inputs."""
    raw = source.read_bytes()
    from frontend_catalog import fastfile_header

    base_header = fastfile_header(raw[:0x88])
    if raw[0x88:0x8C] == FRAME_MARKER:
        # Native stored-frame v1: header + the existing 4-byte frame marker +
        # an exact uncompressed Replay body. This is a reader path only; the
        # writer continues to emit the separately validated IWC-v2 chunk form.
        stored = StoredReplayFastfile.parse(raw)
        layout = _stream_header_details_from_bytes(raw[:0x88], 0)
        observed = base_header
        patches, final_header = _unsigned_iwc_header_only_patch(
            source, raw, observed, layout, required=False)
        return dict(path=source, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                    input_format="replay120-stored-frame-v1", header=observed,
                    header_signature_marker=None, patches=patches,
                    final_header=final_header, signature_verified=False,
                    stored_body_sha256=stored.body.source_sha256,
                    stored_xasset_count=len(stored.body.assets))

    parsed = _parse_replay_uncompressed(raw)
    observed = parsed["header"]
    if base_header != observed:
        raise ValueError("unsigned IWC header fields disagree with the strict container parser")
    layout = _stream_header_details_from_bytes(raw[:0x88], 0)
    patches, final_header = _unsigned_iwc_header_only_patch(
        source, raw, observed, layout, required=True)
    return dict(path=source, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                input_format="replay120-iwc-uncompressed-v1", header=observed,
                header_signature_marker=None, patches=patches,
                final_header=final_header,
                signature_verified=False)


def source_profile(path: str | Path) -> dict:
    """Validate a signed Replay source or the exact emitted unsigned IWC subset."""
    from frontend_catalog import file_formats

    source = Path(path).resolve(strict=True)
    if source.suffix.casefold() != ".ff":
        raise ValueError("source package must be an .ff file")
    with source.open("rb") as stream:
        source_magic = stream.read(8)
    if source_magic == b"IWffc100":
        return _unsigned_iwc_source_profile(source)
    info = file_formats(source)
    base_header = info.get("base")
    if not base_header:
        raise ValueError("source FF header is not a supported signed IW header")
    header = _source_header(source)
    observed = dict(magic=header.magic, header_version=header.header_version,
                    xfile_version=header.xfile_version, compression=header.compression,
                    encryption=header.encryption, transient_type=header.transient_type)
    if base_header != observed:
        raise ValueError("source header fields disagree between envelope and header parser")

    patches = []
    prior = base_header
    prior_layout = _stream_header_details(source)
    with source.open("rb") as stream:
        preceding_header_bytes = stream.read(0x88)
    zero_payload_chain = True
    for extension in (".fp", ".fc"):
        patch = source.with_suffix(extension)
        if not patch.is_file():
            continue
        patch_info = file_formats(patch)
        if patch_info.get("previous") != prior:
            raise ValueError(f"{extension} patch previous header does not match preceding FF chain")
        with patch.open("rb") as stream:
            patch_bytes = stream.read(0x148)
        header_offsets = [match.start() for match in re.finditer(rb"IWff[ac]100", patch_bytes)]
        if len(header_offsets) != 2 or header_offsets[0] != 56:
            raise ValueError(f"{extension} patch has no bounded previous/target header pair")
        previous_layout = _stream_header_details_from_bytes(patch_bytes, header_offsets[0])
        target_layout = _stream_header_details_from_bytes(patch_bytes, header_offsets[1])
        if previous_layout != prior_layout:
            raise ValueError(f"{extension} previous stream reservations differ from preceding header")
        patch_bytes_total = patch.stat().st_size
        previous_header = patch_info["previous"]
        target_header = patch_info["target"]
        header_transition_only = dict(previous_header, xfile_version=target_header["xfile_version"]) == target_header
        previous_header_bytes = patch_bytes[0x38:0xC0]
        target_header_bytes = patch_bytes[0xC0:0x148]
        normalized_previous_header = bytearray(previous_header_bytes)
        normalized_previous_header[0x0C:0x10] = target_header_bytes[0x0C:0x10]
        header_bytes_transition_only = bytes(normalized_previous_header) == target_header_bytes
        header_only_zero_payload = bool(
            extension == ".fp" and patch_bytes_total == 0x148 and
            len(patch_bytes) == 0x148 and patch_bytes[:8] == b"IWffd100" and
            struct.unpack_from("<II", patch_bytes, 8) == (6, 4) and
            not any(patch_bytes[0x10:0x38]) and
            previous_layout == target_layout and header_transition_only and
            header_bytes_transition_only and
            previous_header_bytes == preceding_header_bytes)
        # These exact FP files contain only their 0x148-byte previous/target
        # header pair, with equal decoded extents and stream reservations.
        # Record the full bytes and classify them separately from body patches.
        patches.append(dict(path=patch, extension=extension,
                            header_version=patch_info["patch_version"],
                            previous=patch_info["previous"], target=patch_info["target"],
                            previous_layout=previous_layout, target_layout=target_layout,
                            previous_header_hex=patch_bytes[0x38:0xC0].hex(),
                            target_header_hex=patch_bytes[0xC0:0x148].hex(),
                            header_only_zero_payload=header_only_zero_payload,
                            bytes=patch_bytes_total, sha256=sha256_file(patch)))
        zero_payload_chain = zero_payload_chain and header_only_zero_payload
        prior = patch_info["target"]
        prior_layout = target_layout
        preceding_header_bytes = target_header_bytes
    zero_payload_chain = bool(patches) and zero_payload_chain
    return dict(path=source, bytes=source.stat().st_size,
                sha256=sha256_file(source), header=observed,
                header_signature_marker=header.inner_marker,
                signature_block_sha256=header.signature_bytes_sha256,
                observed_replay_revisions=list(OBSERVED_REPLAY_SOURCE_REVISIONS),
                revision_seen_in_observed_set=header.xfile_version in OBSERVED_REPLAY_SOURCE_REVISIONS,
                patches=patches, final_header={**prior, **prior_layout},
                header_only_zero_payload_chain=zero_payload_chain)


def _assert_run_inputs_unchanged(source: Path, source_before: dict,
                                 acts: Path, acts_before: dict,
                                 replay_executable: Path | None = None,
                                 replay_sha_before: str | None = None) -> None:
    """Reject results produced across an ACTS or source/patch replacement."""
    acts_after = acts_tool_identity(acts)
    if acts_after != acts_before:
        raise RuntimeError("ACTS executable/dependency closure changed during subprocess")
    if replay_executable is not None and sha256_file(replay_executable) != replay_sha_before:
        raise RuntimeError("Replay executable changed during subprocess")
    source_after = source_profile(source)
    before_patches = [(row["extension"], row["sha256"]) for row in source_before.get("patches", [])]
    after_patches = [(row["extension"], row["sha256"]) for row in source_after.get("patches", [])]
    if (source_after.get("sha256") != source_before.get("sha256") or
            before_patches != after_patches):
        raise RuntimeError("source fastfile or FP/FC patch chain changed during subprocess")


def _cache_receipt(path: Path, expected_key: str, *, include_body: bool = False):
    receipt_path = path / "decode-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("cache_key") != expected_key or receipt.get("status") != "decoded-and-validated":
        raise ValueError("existing fastfile cache entry has no matching successful receipt")
    for output in receipt.get("outputs", []):
        output_path = path / output["relative_path"]
        if not output_path.is_file() or output_path.stat().st_size != output["bytes"] or \
                sha256_file(output_path) != output["sha256"]:
            raise ValueError(f"cached decode output failed receipt validation: {output_path}")
    final_path = path / receipt["final_body_relative_path"]
    body = ZoneBody.parse(final_path.read_bytes())
    if body.source_sha256 != receipt["final_body_sha256"]:
        raise ValueError("cached decoded XAssetList no longer matches its receipt")
    return (receipt, body) if include_body else receipt


def _unsigned_iwc_decoder_sources() -> list[dict]:
    """Pin the Python modules that validate and decode the emitted IWC form."""
    import frontend_catalog
    import inspect_frontend_asset_table

    root = Path(__file__).resolve().parents[1]
    modules = (Path(__file__).resolve(),
               Path(frontend_catalog.__file__).resolve(strict=True),
               Path(inspect_frontend_asset_table.__file__).resolve(strict=True))
    rows = []
    for path in modules:
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("unsigned IWC decoder dependency escapes the project source root")
        rows.append(dict(path=path.relative_to(root).as_posix(), sha256=sha256_file(path)))
    rows.sort(key=lambda row: row["path"].casefold())
    if len({row["path"] for row in rows}) != len(rows):
        raise ValueError("unsigned IWC decoder dependency list is ambiguous")
    return rows


def _decode_unsigned_iwc_fastfile(source: Path, cache: Path, acts: Path,
                                 executable: Path, timeout_seconds: int,
                                 profile: dict) -> dict:
    """Cache a strictly framed unsigned Replay body without invoking ACTS."""
    input_format = profile.get("input_format")
    stored_frame = input_format == "replay120-stored-frame-v1"
    if not stored_frame and input_format != "replay120-iwc-uncompressed-v1":
        raise ValueError("unsupported unsigned Replay source format")
    decoder_name = ("strict-python-replay120-stored-frame-v1" if stored_frame else
                    "strict-python-replay120-iwc-uncompressed-v1")
    acts_tool = acts_tool_identity(acts)
    decoder_sources = _unsigned_iwc_decoder_sources()
    replay_sha = sha256_file(executable)
    if replay_sha != REPLAY_EXECUTABLE_SHA256:
        raise ValueError("Replay 1.20 target executable hash differs from pinned profile")
    key_material = dict(schema=1, source_layout_schema=2,
                        input_format=profile["input_format"],
                        source_sha256=profile["sha256"],
                        patch_sha256s=[row["sha256"] for row in profile["patches"]],
                        acts_sha256=acts_tool["executable_sha256"],
                        acts_tool_identity=acts_tool,
                        replay_executable_sha256=replay_sha,
                        decoder=decoder_name,
                        python_decoder_sources=decoder_sources)
    cache_key = hashlib.sha256(json.dumps(key_material, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
    parent = cache / source.stem
    target = parent / cache_key
    if target.exists():
        cached = _cache_receipt(target, cache_key)
        if cached.get("decoder_sources") != decoder_sources:
            raise ValueError("unsigned IWC decode cache helper identity mismatch")
        return cached
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".decode-{cache_key[:12]}-", dir=parent))
    decoded_dir = temporary / "decoded"
    decoded_dir.mkdir()
    log_path = temporary / "decode.log"
    try:
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != profile["sha256"]:
            raise RuntimeError("unsigned IWC source changed after profile validation")
        if stored_frame:
            stored = StoredReplayFastfile.parse(raw)
            from frontend_catalog import fastfile_header
            parsed = dict(body=stored.body.data, header=fastfile_header(raw[:0x88]),
                          block_sizes=list(stored.stream_sizes))
            if stored.body.source_sha256 != profile.get("stored_body_sha256") or \
                    len(stored.body.assets) != profile.get("stored_xasset_count"):
                raise RuntimeError("stored-frame XAsset table changed after source profiling")
        else:
            parsed = _parse_replay_uncompressed(raw)
        if (parsed["header"] != profile["header"] or
                parsed["block_sizes"] != profile["final_header"].get("block_sizes")):
            raise RuntimeError("unsigned IWC header changed after profile validation")
        base_dec = decoded_dir / f"{source.name}.dec"
        base_dec.write_bytes(parsed["body"])
        log_path.write_text(
            ("Strict Replay 1.20 stored-frame v1 validated; XAsset table parsed and body copied.\n"
             if stored_frame else
             "Strict Replay 1.20 unsigned IWC framing validated; body copied without decompression.\n"),
            encoding="utf-8")
        _assert_run_inputs_unchanged(source, profile, acts, acts_tool,
                                     executable, replay_sha)
        if _unsigned_iwc_decoder_sources() != decoder_sources:
            raise RuntimeError("unsigned IWC decoder helper changed during validation")
        body = ZoneBody.parse(base_dec.read_bytes())
        if len(body.data) != profile["final_header"].get("decoded_size"):
            raise ValueError("IWC decoded size differs from the validated FF header")
        outputs = [dict(relative_path=str(base_dec.relative_to(temporary)),
                        bytes=base_dec.stat().st_size, sha256=sha256_file(base_dec))]
        authenticity = dict(source_signature_marker=None, signature_block_sha256=None,
                            cryptographic_signature_verified=False,
                            note="Unsigned emitted IWC framing was validated; no signature is present or claimed.")
        receipt = dict(
            schema=2, status="decoded-and-validated", cache_key=cache_key,
            source=profile,
            decoder=decoder_name,
            decoder_sources=decoder_sources,
            tools=dict(acts_path=str(acts), acts_sha256=acts_tool["executable_sha256"],
                       acts_tool_identity=acts_tool, command=[],
                       replay_executable_path=str(executable),
                       replay_executable_sha256=replay_sha),
            outputs=outputs,
            final_body_relative_path=str(base_dec.relative_to(temporary)),
            final_body_bytes=len(body.data), final_body_sha256=body.source_sha256,
            xasset_table=dict(script_string_count=body.script_string_count,
                              asset_count=len(body.assets),
                              asset_table_offset=body.asset_table_offset,
                              first_payload_offset=body.first_payload_offset),
            reader_graph=dict(status="table-only", asset_root_spans=None,
                              reason="fresh native Replay walk is required before workspace acceptance"),
            authenticity=authenticity,
            logs=dict(relative_path="decode.log", sha256=sha256_file(log_path)))
        (temporary / "decode-receipt.json").write_text(
            json.dumps(receipt, indent=2, default=str) + "\n", encoding="utf-8")
        if target.exists():
            raise FileExistsError(f"cache entry appeared concurrently: {target}")
        temporary.replace(target)
        return _cache_receipt(target, cache_key)
    except Exception as error:
        (temporary / "decode-error.json").write_text(json.dumps(
            {"source": str(source), "cache_key": cache_key,
             "error": f"{type(error).__name__}: {error}", "decoder": key_material["decoder"],
             "log_sha256": sha256_file(log_path) if log_path.exists() else None},
            indent=2) + "\n", encoding="utf-8")
        raise


def decode_source_fastfile(source_path: str | Path, cache_root: str | Path,
                           acts_path: str | Path = ACTS_DEFAULT,
                           replay_executable: str | Path = REPLAY_EXECUTABLE,
                           timeout_seconds: int = 1800) -> dict:
    """Decode a signed Replay source with ACTS or the exact emitted unsigned IWC subset.

    ACTS is called in generic IW-decompressor mode for signed inputs only. The
    supported unsigned IWC writer output is already uncompressed, so its body
    is copied only after strict framing/table checks. Neither path claims
    cryptographic signature verification or complete typed asset-graph traversal.
    """
    source = Path(source_path).resolve(strict=True)
    cache = Path(cache_root).resolve()
    if not source.is_file():
        raise ValueError("source fastfile must be a regular file")
    if cache == source.parent or cache.is_relative_to(source.parent):
        raise ValueError("decoded cache must be outside the game zone directory")
    if not 1 <= timeout_seconds <= 24 * 60 * 60:
        raise ValueError("decode timeout must be between 1 second and 24 hours")
    acts = Path(acts_path).resolve(strict=True)
    executable = Path(replay_executable).resolve(strict=True)
    profile = source_profile(source)
    acts_tool = acts_tool_identity(acts)
    acts_sha = acts_tool["executable_sha256"]
    replay_sha = sha256_file(executable)
    if replay_sha != REPLAY_EXECUTABLE_SHA256:
        raise ValueError("Replay 1.20 target executable hash differs from pinned profile")

    if profile.get("input_format") in {
            "replay120-iwc-uncompressed-v1", "replay120-stored-frame-v1"}:
        return _decode_unsigned_iwc_fastfile(source, cache, acts, executable,
                                            timeout_seconds, profile)
    command_flags = ["--noUpdater", "fastfile", "-d", "-p", "-l", "-o"]
    key_material = dict(source_layout_schema=2, source_sha256=profile["sha256"],
                        patch_sha256s=[row["sha256"] for row in profile["patches"]],
                        acts_sha256=acts_sha, acts_tool_identity=acts_tool,
                        replay_executable_sha256=replay_sha,
                        command=command_flags, schema=1)
    cache_key = hashlib.sha256(json.dumps(key_material, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
    parent = cache / source.stem
    target = parent / cache_key
    if target.exists():
        return _cache_receipt(target, cache_key)

    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".decode-{cache_key[:12]}-", dir=parent))
    decoded_dir = temporary / "decoded"
    decoded_dir.mkdir()
    log_path = temporary / "acts.log"
    command = [str(acts), *command_flags, str(decoded_dir), str(source)]
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       check=False, timeout=timeout_seconds)
        _assert_run_inputs_unchanged(source, profile, acts, acts_tool,
                                     executable, replay_sha)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if completed.returncode != 0:
            raise RuntimeError(f"ACTS failed with exit code {completed.returncode}; see {log_path}")
        if f"Loading {source}" not in log_text or "(IW)" not in log_text:
            raise ValueError("ACTS did not identify the input as an IW fastfile")
        base_dec = decoded_dir / f"{source.name}.dec"
        if not base_dec.is_file() or f"Dump ff into {base_dec}" not in log_text:
            raise ValueError("ACTS did not emit the expected base decoded body")

        patch_decodes = []
        header_only_reuse = bool(profile.get("header_only_zero_payload_chain"))
        if header_only_reuse:
            base_body = ZoneBody.parse(base_dec.read_bytes())
            if len(base_body.data) != profile["final_header"].get("decoded_size"):
                raise ValueError("header-only FP target decoded size differs from unchanged base body")
            patch_application = dict(
                mode="header-only-fp-no-body-change",
                note="ACTS emitted only the base .dec; exact zero-payload FP headers and equal layouts prove the serialized body is unchanged.",
                patches=[dict(extension=row["extension"], sha256=row["sha256"],
                              previous_header_hex=row["previous_header_hex"],
                              target_header_hex=row["target_header_hex"],
                              previous_layout=row["previous_layout"],
                              target_layout=row["target_layout"])
                         for row in profile["patches"]])
        else:
            patch_application = dict(mode=("acts-patch-outputs-required"
                                          if profile["patches"] else "no-patch"))
            for patch in profile["patches"]:
                patch_dec = decoded_dir / f"{source.stem}{patch['extension']}.dec"
                patched_dec = decoded_dir / f"{source.stem}{patch['extension']}.patched.dec"
                if not patch_dec.is_file() or not patched_dec.is_file():
                    raise ValueError(f"ACTS did not emit decoded and patched {patch['extension']} outputs")
                if f"Dump {patch['extension'][1:]} patch into {patch_dec}" not in log_text or \
                        f"Dump patched data into {patched_dec}" not in log_text:
                    raise ValueError(f"ACTS log does not corroborate {patch['extension']} output paths")
                patch_decodes.append(dict(extension=patch["extension"],
                                          decoded=patch_dec, patched=patched_dec))
        final_body = patch_decodes[-1]["patched"] if patch_decodes else base_dec
        body = ZoneBody.parse(final_body.read_bytes())
        if len(body.data) != profile["final_header"].get("decoded_size"):
            raise ValueError("patched decoded size differs from the FP/FC target header")
        logs_sha = sha256_file(log_path)
        outputs = []
        for output_path in [base_dec] + [p for pair in patch_decodes for p in (pair["decoded"], pair["patched"])]:
            outputs.append(dict(relative_path=str(output_path.relative_to(temporary)),
                                bytes=output_path.stat().st_size,
                                sha256=sha256_file(output_path)))
        receipt = dict(
            schema=2, status="decoded-and-validated", cache_key=cache_key,
            source=profile,
            tools=dict(acts_path=str(acts), acts_sha256=acts_sha,
                       acts_tool_identity=acts_tool,
                       command=command, replay_executable_path=str(executable),
                       replay_executable_sha256=replay_sha),
            outputs=outputs,
            final_body_relative_path=str(final_body.relative_to(temporary)),
            final_body_bytes=len(body.data), final_body_sha256=body.source_sha256,
            xasset_table=dict(script_string_count=body.script_string_count,
                              asset_count=len(body.assets),
                              asset_table_offset=body.asset_table_offset,
                              first_payload_offset=body.first_payload_offset),
            patch_application=patch_application,
            reader_graph=dict(status="table-only", asset_root_spans=None,
                              reason="full root spans require per-type Replay reader/allocation schedules"),
            authenticity=dict(source_signature_marker=header_marker(profile),
                              signature_block_sha256=profile["signature_block_sha256"],
                              cryptographic_signature_verified=False,
                              note="ACTS generic decompression succeeded; no independent RSA signature verification is claimed."),
            logs=dict(relative_path="acts.log", sha256=logs_sha),
        )
        (temporary / "decode-receipt.json").write_text(
            json.dumps(receipt, indent=2, default=str) + "\n", encoding="utf-8")
        if target.exists():
            raise FileExistsError(f"cache entry appeared concurrently: {target}")
        temporary.replace(target)
        return _cache_receipt(target, cache_key)
    except Exception as error:
        (temporary / "decode-error.json").write_text(json.dumps({
            "source": str(source), "cache_key": cache_key,
            "error": f"{type(error).__name__}: {error}",
            "acts_command": command,
            "acts_log_sha256": sha256_file(log_path) if log_path.exists() else None,
        }, indent=2) + "\n", encoding="utf-8")
        raise


def walk_native_fastfile(source_path: str | Path, decoded_receipt: dict,
                         cache_path: str | Path, acts_path: str | Path = ACTS_DEFAULT,
                         replay_executable: str | Path = REPLAY_EXECUTABLE,
                         timeout_seconds: int = 1800) -> dict:
    """Run ACTS' pinned Replay 1.20 native reader over a decoded source FF.

    This validates ordered top-level dispatch, nested native allocation/read
    schedules, and complete serialized-stream consumption. ACTS currently does
    not publish per-XAsset root/child archive spans, so this receipt never
    pretends that a successful zone walk makes every asset independently
    editable.
    """
    source = Path(source_path).resolve(strict=True)
    cache_path = Path(cache_path).resolve(strict=True)
    acts = Path(acts_path).resolve(strict=True)
    executable = Path(replay_executable).resolve(strict=True)
    acts_tool = acts_tool_identity(acts)
    acts_sha = acts_tool["executable_sha256"]
    replay_sha = sha256_file(executable)
    if replay_sha != REPLAY_EXECUTABLE_SHA256:
        raise ValueError("Replay 1.20 target executable hash differs from pinned profile")
    body_path = cache_path / decoded_receipt["final_body_relative_path"]
    body = ZoneBody.parse(body_path.read_bytes())
    if body.source_sha256 != decoded_receipt.get("final_body_sha256"):
        raise ValueError("decoded body changed after generic decode receipt")
    source_profile_row = decoded_receipt.get("source", {})
    if source_profile_row.get("sha256") != sha256_file(source):
        raise ValueError("source fastfile changed after generic decode receipt")
    trace_enabled = _acts_supports_replay_stream_trace(acts)
    command_flags = ["--noUpdater", "fastfile", "-r", "mw19replay", "-g",
                     str(executable), "--noAssetDump"]
    if trace_enabled:
        command_flags.append("--trace-replay-streams")
    command_flags.append("-l")
    identity = dict(schema=2, body_sha256=body.source_sha256,
                    source_sha256=source_profile_row["sha256"],
                    source_name=source.name,
                    patch_sha256s=[p["sha256"] for p in source_profile_row.get("patches", [])],
                    acts_sha256=acts_sha, acts_tool_identity=acts_tool,
                    replay_executable_sha256=replay_sha,
                    command_flags=command_flags)
    if trace_enabled:
        import workstation_native_references
        # A changed reference recognizer gets a fresh cache key. Otherwise an
        # old derived inventory would reject every later extraction attempt.
        identity["reference_inventory_normalizer_sha256"] = sha256_file(
            Path(workstation_native_references.__file__))
    walk_key = hashlib.sha256(json.dumps(identity, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()
    target = cache_path / "native-walk" / walk_key
    if target.exists():
        return _validate_native_walk_receipt(target, walk_key, body, source)

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".native-walk-{walk_key[:12]}-",
                                      dir=target.parent))
    # ACTS appends zone, handler, and asset paths. Keep that output hierarchy
    # short on Windows; immutable validated artifacts still land in `target`.
    short_root = Path(tempfile.mkdtemp(prefix=f"rwt-{walk_key[:8]}-",
                                       dir=cache_path.parent.parent))
    output_dir = short_root / "o"
    output_dir.mkdir()
    log_path = temporary / "acts-native.log"
    command = [str(acts), *command_flags, "-o", str(output_dir), str(source)]
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       check=False, timeout=timeout_seconds)
        _assert_run_inputs_unchanged(source, source_profile_row, acts, acts_tool,
                                     executable, replay_sha)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if completed.returncode != 0 or f"Loading {source}" not in log_text or \
                "Replay:" not in log_text:
            raise RuntimeError(f"ACTS native Replay walk failed; see {log_path}")
        manifests = list(output_dir.glob("mw19replay/*/manifest.json"))
        if len(manifests) != 1:
            raise ValueError("ACTS native walk did not emit exactly one Replay manifest")
        native_manifest_path = manifests[0]
        native_manifest = json.loads(native_manifest_path.read_text(encoding="utf-8"))
        if not native_manifest.get("complete") or not native_manifest.get("success"):
            raise ValueError("ACTS native Replay walk receipt is incomplete or unsuccessful")
        source_header = source_profile_row.get("header", {})
        if native_manifest.get("profile") != "replay-1.20" or \
                native_manifest.get("input_xfile_version") != source_header.get("xfile_version"):
            raise ValueError("ACTS native walk profile/source revision mismatch")
        final_header = source_profile_row.get("final_header", {})
        if native_manifest.get("xfile_version") != final_header.get("xfile_version"):
            raise ValueError("ACTS native walk target revision mismatch")
        if native_manifest.get("top_level_index") != len(body.assets):
            raise ValueError("ACTS native walk did not visit every XAsset table row")
        if native_manifest.get("serialized_bytes_read") != len(body.data):
            raise ValueError("ACTS native walk did not consume the complete decoded body")
        if native_manifest.get("failed") != 0 or native_manifest.get("unavailable") != 0:
            raise ValueError("ACTS native walk reported failed or unavailable assets")
        journal_path = native_manifest_path.parent / native_manifest.get("journal", "assets.jsonl")
        journal_rows = [json.loads(line) for line in journal_path.read_text(
            encoding="utf-8").splitlines() if line.strip()]
        native_dir = temporary / "native"
        native_dir.mkdir()
        relative_manifest = Path("native") / "manifest.json"
        relative_journal = Path("native") / "assets.jsonl"
        relative_strings = Path("native") / native_manifest.get("script_strings_file", "script_strings.json")
        shutil.copy2(native_manifest_path, temporary / relative_manifest)
        shutil.copy2(journal_path, temporary / relative_journal)
        strings_path = native_manifest_path.parent / native_manifest.get("script_strings_file", "script_strings.json")
        if strings_path.is_file():
            shutil.copy2(strings_path, temporary / relative_strings)
        trace_path = native_manifest_path.parent / native_manifest.get("stream_trace", "stream-trace.jsonl")
        relative_trace = Path("native") / "stream-trace.jsonl"
        if trace_enabled:
            if not trace_path.is_file():
                raise ValueError("ACTS trace-enabled native walk did not emit its Replay stream journal")
            shutil.copy2(trace_path, temporary / relative_trace)
        inventory_fields = {}
        if len(journal_rows) != len(body.assets):
            if not trace_enabled:
                raise ValueError("reference-only table coverage requires a complete native stream trace")
            from workstation_native_references import normalize_native_inventory
            import workstation_native_references
            inventory = normalize_native_inventory(body.data, trace_path, native_manifest, journal_rows)
            inventory_path = native_dir / "normalized-inventory.json"
            inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
            # Raw ACTS files remain byte-for-byte intact. Only this separately
            # named manifest adds trace-derived references; tested stays native.
            accounted = dict(native_manifest, reference_only_rows=inventory["reference_only_rows"])
            accounted_path = native_dir / "manifest-reference-accounted.json"
            accounted_path.write_text(json.dumps(accounted, indent=2) + "\n", encoding="utf-8")
            inventory_fields = dict(
                raw_manifest_relative_path=relative_manifest.as_posix(),
                raw_manifest_sha256=sha256_file(temporary / relative_manifest),
                normalized_inventory_relative_path=inventory_path.relative_to(temporary).as_posix(),
                normalized_inventory_sha256=sha256_file(inventory_path),
                inventory_normalizer_sha256=sha256_file(Path(workstation_native_references.__file__)))
            relative_manifest = accounted_path.relative_to(temporary)
            validate_native_walk_artifacts(accounted, inventory["normalized_rows"], body)
        else:
            validate_native_walk_artifacts(native_manifest, journal_rows, body)
        if (trace_enabled and identity["reference_inventory_normalizer_sha256"] !=
                sha256_file(Path(workstation_native_references.__file__))):
            raise ValueError("native reference inventory implementation changed during extraction")
        receipt = dict(schema=2, status="native-zone-reader-pass", walk_key=walk_key,
                       identity=identity, command=command,
                       source_relative_path=source.name,
                       decoded_body_sha256=body.source_sha256,
                       xasset_count=len(body.assets), loaded_assets=native_manifest["loaded_assets"],
                       serialized_bytes_read=native_manifest["serialized_bytes_read"],
                       manifest_relative_path=relative_manifest.as_posix(),
                       journal_relative_path=relative_journal.as_posix(),
                       script_strings_relative_path=relative_strings.as_posix() if strings_path.is_file() else None,
                       stream_trace_enabled=trace_enabled,
                       stream_trace_relative_path=relative_trace.as_posix() if trace_enabled else None,
                       stream_trace_bytes=trace_path.stat().st_size if trace_enabled else None,
                       stream_trace_sha256=sha256_file(trace_path) if trace_enabled else None,
                       stream_trace_events=native_manifest.get("stream_trace_events") if trace_enabled else None,
                       manifest_sha256=sha256_file(temporary / relative_manifest),
                       journal_sha256=sha256_file(temporary / relative_journal),
                       acts_log_sha256=sha256_file(temporary / "acts-native.log"),
                       root_child_spans="unavailable-from-current-ACTS-journal",
                       writer_ready=False, **inventory_fields)
        (temporary / "native-walk-receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        _validate_native_walk_receipt(temporary, walk_key, body, source)
        temporary.replace(target)
        shutil.rmtree(short_root, ignore_errors=True)
        return _validate_native_walk_receipt(target, walk_key, body, source)
    except Exception as error:
        (temporary / "native-walk-error.json").write_text(json.dumps(
            dict(source=str(source), walk_key=walk_key, command=command,
                 diagnostic_output_path=str(short_root),
                 error=f"{type(error).__name__}: {error}",
                 log_sha256=sha256_file(log_path) if log_path.exists() else None),
            indent=2) + "\n", encoding="utf-8")
        raise


def _validate_native_walk_receipt(target: Path, walk_key: str,
                                  body: ZoneBody, source: Path) -> dict:
    receipt_path = target / "native-walk-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("walk_key") != walk_key or receipt.get("status") != "native-zone-reader-pass":
        raise ValueError("native walk cache receipt identity/status mismatch")
    if receipt.get("decoded_body_sha256") != body.source_sha256 or \
            receipt.get("xasset_count") != len(body.assets):
        raise ValueError("native walk cache receipt no longer matches decoded body")
    if receipt.get("source_relative_path") != source.name:
        raise ValueError("native walk cache receipt source mismatch")
    manifest_path = target / receipt["manifest_relative_path"]
    journal_path = target / receipt["journal_relative_path"]
    if sha256_file(manifest_path) != receipt.get("manifest_sha256") or \
            sha256_file(journal_path) != receipt.get("journal_sha256"):
        raise ValueError("native walk cached manifest/journal hash mismatch")
    trace_relative = receipt.get("stream_trace_relative_path")
    trace_path = target / trace_relative if trace_relative else None
    if receipt.get("stream_trace_enabled") and (
            not trace_path or not trace_path.is_file() or
            trace_path.stat().st_size != receipt.get("stream_trace_bytes") or
            sha256_file(trace_path) != receipt.get("stream_trace_sha256")):
        raise ValueError("native walk stream trace cache failed receipt validation")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = _validated_walk_inventory(target, receipt, body, manifest, rows)
    validate_native_walk_artifacts(manifest, rows, body)
    receipt["cache_path"] = str(target)
    return receipt


def _validated_walk_inventory(target: Path, receipt: dict, body: ZoneBody,
                              manifest: dict, raw_rows: list[dict]) -> list[dict]:
    """Validate the derived table view against unchanged native evidence."""
    relative = receipt.get("normalized_inventory_relative_path")
    if not relative:
        if manifest.get("reference_only_rows"):
            raise ValueError("reference-accounted walk has no derived inventory receipt")
        return raw_rows
    import workstation_native_references
    if (not receipt.get("stream_trace_enabled") or
            sha256_file(Path(workstation_native_references.__file__)) != receipt.get("inventory_normalizer_sha256")):
        raise ValueError("native reference inventory implementation or trace contract changed")
    def artifact(key: str, hash_key: str) -> Path:
        path = (target / receipt[key]).resolve(strict=True)
        if not path.is_relative_to(target.resolve()) or sha256_file(path) != receipt.get(hash_key):
            raise ValueError("native reference inventory artifact path/hash mismatch")
        return path
    raw_path = artifact("raw_manifest_relative_path", "raw_manifest_sha256")
    inventory_path = artifact("normalized_inventory_relative_path", "normalized_inventory_sha256")
    original = json.loads(raw_path.read_text(encoding="utf-8"))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    references = inventory.get("reference_only_rows")
    if (inventory.get("schema") != "replay120-native-normalized-inventory-v1" or
            inventory.get("body_sha256") != body.source_sha256 or
            inventory.get("trace_sha256") != receipt.get("stream_trace_sha256") or
            inventory.get("raw_tested_count") != original.get("tested") or
            original.get("tested") != len(raw_rows) or
            inventory.get("normalized_inventory_count") != len(body.assets) or
            not isinstance(references, list) or not references or
            manifest != dict(original, reference_only_rows=references)):
        raise ValueError("derived native reference inventory differs from raw walk evidence")
    rows = inventory.get("normalized_rows")
    validate_native_walk_artifacts(manifest, rows, body)
    refs = {row["index"]: row for row in references}
    retained = [row for index, row in enumerate(rows) if index not in refs]
    if len(retained) != len(raw_rows):
        raise ValueError("derived native inventory loses raw tested rows")
    raw_index = 0
    for index, row in enumerate(rows):
        if index in refs:
            if row != refs[index]:
                raise ValueError("derived reference row differs from its indexed evidence")
            start, size = row.get("name_archive_offset"), row.get("name_bytes")
            if (type(start) is not int or type(size) is not int or start < 0 or size < 2 or
                    start + size > len(body.data) or
                    body.data[start:start + size] != row["name"].encode("utf-8") + b"\0"):
                raise ValueError("derived reference name differs from its exact serialized bytes")
        else:
            raw = raw_rows[raw_index]
            raw_index += 1
            expected = dict(raw, index=index,
                            pointer_token=hex(body.assets[index].pointer_token),
                            status=raw.get("status", "native-tested"))
            if row != expected:
                raise ValueError("normalized table inventory changed a raw tested row")
    return rows


def validate_native_walk_artifacts(manifest: dict, rows: list[dict],
                                   body: ZoneBody) -> None:
    """Strictly validate ACTS zone-level native traversal against the table."""
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            not isinstance(rows, list) or len(rows) != len(body.assets) or
            any(not isinstance(row, dict) for row in rows)):
        raise ValueError("native walk cache artifacts are incomplete")
    references = manifest.get("reference_only_rows", [])
    if not isinstance(references, list):
        raise ValueError("native walk reference coverage is malformed")
    reference_indices = set()
    for reference in references:
        if not isinstance(reference, dict):
            raise ValueError("native walk reference descriptor is malformed")
        index = reference.get("index")
        name = reference.get("name")
        if (type(index) is not int or not 0 <= index < len(body.assets) or
                index in reference_indices or type(reference.get("type_id")) is not int or
                reference["type_id"] != body.assets[index].type_id or
                type(reference.get("pointer_token")) is not int or
                reference["pointer_token"] != 0xfffffffffffffffd or
                body.assets[index].pointer_token != 0xfffffffffffffffd or
                not isinstance(name, str) or len(name) < 2 or not name.startswith(",") or "\0" in name or
                rows[index].get("name") != name or rows[index].get("status") != "reference"):
            raise ValueError("native walk reference descriptor differs from exact table identity")
        reference_indices.add(index)
    if type(manifest.get("top_level_index")) is not int or \
            manifest["top_level_index"] != len(body.assets) or \
            type(manifest.get("tested")) is not int or \
            manifest["tested"] + len(references) != len(body.assets) or \
            manifest.get("serialized_bytes_read") != len(body.data):
        raise ValueError("native walk counts/EOF disagree with decoded body")
    if (type(manifest.get("failed")) is not int or manifest["failed"] != 0 or
            type(manifest.get("unavailable")) is not int or manifest["unavailable"] != 0):
        raise ValueError("native walk reports failed or unavailable rows")
    for i, (row, header) in enumerate(zip(rows, body.assets, strict=True)):
        if row.get("type_id") != header.type_id or not isinstance(row.get("name"), str):
            raise ValueError(f"cached native walk row {i} differs from XAsset table order/type")


def _read_native_rows(cache_path: Path, body: ZoneBody,
                      require_trace: bool = False) -> tuple[dict, list[dict]]:
    candidates = list((cache_path / "native-walk").glob("*/native-walk-receipt.json"))
    # Prefer the strongest cached evidence deterministically when several
    # successful walks cover the same body (e.g. a prior walk without tracing).
    def trace_priority(path: Path):
        try:
            has_trace = bool(json.loads(path.read_text(encoding="utf-8")).get("stream_trace_enabled"))
        except (OSError, ValueError, TypeError):
            has_trace = False
        return (not has_trace, str(path))
    candidates.sort(key=trace_priority)
    for candidate in candidates:
        try:
            receipt = json.loads(candidate.read_text(encoding="utf-8"))
            if receipt.get("decoded_body_sha256") != body.source_sha256:
                continue
            if require_trace and (not receipt.get("stream_trace_enabled") or
                                  not receipt.get("stream_trace_relative_path")):
                continue
            target = candidate.parent
            receipt = _validate_native_walk_receipt(target, receipt.get("walk_key"), body,
                                          Path(receipt.get("identity", {}).get("source_name", "missing.ff")))
            if receipt.get("normalized_inventory_relative_path"):
                inventory = json.loads((target / receipt["normalized_inventory_relative_path"]).read_text(encoding="utf-8"))
                rows = inventory["normalized_rows"]
            else:
                journal = target / receipt["journal_relative_path"]
                rows = [json.loads(line) for line in journal.read_text(
                    encoding="utf-8").splitlines() if line.strip()]
            return receipt, rows
        except (OSError, ValueError, KeyError, TypeError):
            continue
    raise UnsupportedAssetGraphError("zone has no complete cached native Replay walk")


def _native_walk_artifact(walk_receipt: dict, relative_key: str) -> Path:
    """Resolve a native-walk artifact against its own receipt directory.

    The walk cache is nested below the decoded-body cache. Receipt paths are
    relative to that walk directory, never to the outer zone cache.
    """
    base = walk_receipt.get("cache_path")
    relative = walk_receipt.get(relative_key)
    if not isinstance(base, str) or not isinstance(relative, str):
        raise ValueError("native walk receipt has no artifact base/path")
    target = (Path(base) / relative).resolve(strict=True)
    walk_root = Path(base).resolve(strict=True)
    if not target.is_relative_to(walk_root):
        raise ValueError("native walk artifact escapes its receipt directory")
    return target


def _export_native_type(source: Path, zone_id: str, body: ZoneBody,
                        cache_path: Path, walk_receipt: dict, native_rows: list[dict],
                        type_id: int, type_name: str, acts_path: Path,
                        replay_executable: Path = REPLAY_EXECUTABLE,
                        timeout_seconds: int = 1800) -> tuple[Path, dict]:
    """Export ACTS semantic payloads for one native type and bind by ordered row."""
    if not re.fullmatch(r"[a-z0-9_]+", type_name):
        raise ValueError("native asset exporter type name is malformed")
    source = source.resolve(strict=True)
    source_snapshot = source_profile(source)
    walk_identity = walk_receipt.get("identity", {})
    if (walk_identity.get("source_sha256") != source_snapshot.get("sha256") or
            walk_identity.get("patch_sha256s") != [p["sha256"] for p in source_snapshot["patches"]]):
        raise ValueError("native export source differs from cached reader walk")
    if type_id not in {row.type_id for row in body.assets}:
        raise AssetNotFoundError(type_id)
    acts_tool = acts_tool_identity(acts_path)
    acts_sha = acts_tool["executable_sha256"]
    replay_sha = sha256_file(replay_executable)
    key_data = dict(schema=2, body_sha256=body.source_sha256,
                    source_sha256=source_snapshot["sha256"],
                    patch_sha256s=[p["sha256"] for p in source_snapshot["patches"]],
                    type_id=type_id,
                    type_name=type_name, acts_sha256=acts_sha,
                    acts_tool_identity=acts_tool,
                    replay_executable_sha256=replay_sha)
    export_key = hashlib.sha256(json.dumps(key_data, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
    target = cache_path / "native-exports" / export_key
    if target.exists():
        index_path = target / "asset-payload-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if (index.get("export_key") != export_key or index.get("body_sha256") != body.source_sha256 or
                index.get("source_sha256") != source_snapshot["sha256"] or
                index.get("native_walk_key") != walk_receipt.get("walk_key") or
                index.get("type_id") != type_id or index.get("type_name") != type_name):
            raise ValueError("cached native payload export identity mismatch")
        expected = [(i, row) for i, row in enumerate(native_rows)
                    if row.get("type_id") == type_id and row.get("status") != "reference"]
        if len(index.get("items", [])) != len(expected):
            raise ValueError("cached native payload export inventory mismatch")
        for rank, ((asset_index, native_row), entry) in enumerate(zip(expected, index["items"], strict=True)):
            if (entry.get("rank") != rank or entry.get("asset_index") != asset_index or
                    entry.get("type_id") != type_id or entry.get("name") != native_row.get("name")):
                raise ValueError("cached native payload export row identity mismatch")
            relative = Path(entry["payload_relative_path"])
            payload_path = (target / relative).resolve(strict=True)
            if relative.is_absolute() or ".." in relative.parts or not payload_path.is_relative_to(target.resolve()):
                raise ValueError("cached native payload path escapes its export")
            if (not payload_path.is_file() or payload_path.stat().st_size != entry.get("payload_bytes") or
                    sha256_file(payload_path) != entry["payload_sha256"]):
                raise ValueError("cached native payload failed hash validation")
        return target, index

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".native-export-{export_key[:12]}-",
                                      dir=target.parent))
    # ACTS joins asset names onto output paths; keep the native export root
    # shallow so long virtual paths such as scripts/mp/maps/... stay below
    # the Windows MAX_PATH boundary.
    short_root = Path(tempfile.mkdtemp(prefix=f"rpx-{export_key[:8]}-"))
    if len(str(short_root)) > 80:
        shutil.rmtree(short_root)
        raise ValueError("system temporary directory is too long for safe ACTS asset export")
    output_dir = short_root / "o"
    output_dir.mkdir()
    log_path = temporary / "acts-export.log"
    command = [str(acts_path), "--noUpdater", "fastfile", "-r", "mw19replay",
               "-g", str(replay_executable), "-o", str(output_dir),
               "-a", type_name, "-l", str(source)]
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       check=False, timeout=timeout_seconds)
        _assert_run_inputs_unchanged(source, source_snapshot, acts_path, acts_tool,
                                     replay_executable, replay_sha)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if completed.returncode != 0 or f"Loading {source}" not in log_text or "Replay:" not in log_text:
            raise RuntimeError(f"ACTS {type_name} payload export failed; see {log_path}")
        manifests = list(output_dir.glob("mw19replay/*/manifest.json"))
        if len(manifests) != 1:
            raise ValueError("ACTS payload export did not emit exactly one manifest")
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = [(i, row) for i, row in enumerate(native_rows)
                    if row.get("type_id") == type_id and row.get("status") != "reference"]
        if (not manifest.get("complete") or not manifest.get("success") or
                manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                manifest.get("tested") != len(expected)):
            raise ValueError("ACTS payload export did not successfully export all rows of this type")
        journal_path = manifest_path.parent / manifest.get("journal", "assets.jsonl")
        exported_rows = [json.loads(line) for line in journal_path.read_text(
            encoding="utf-8").splitlines() if line.strip()]
        if len(exported_rows) != len(expected):
            raise ValueError("ACTS payload export journal row count differs from type rows")
        payload_root = temporary / "payloads"
        payload_root.mkdir()
        entries = []
        for rank, ((asset_index, native_row), exported) in enumerate(zip(expected, exported_rows, strict=True)):
            if exported.get("type_id") != type_id or exported.get("name") != native_row.get("name"):
                raise ValueError(f"ACTS payload export row {rank} does not match native table identity")
            relative = exported.get("file")
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("ACTS payload export returned an unsafe file path")
            payload_source = manifest_path.parent / relative
            if not payload_source.is_file():
                raise ValueError("ACTS payload export journal payload is missing")
            # Virtual asset names may be very long. Rank is already bound to
            # the exact ordered native row, so keep only its format suffix in
            # the private cache path rather than repeating that virtual name.
            payload_relative = Path("payloads") / f"{rank:06d}{payload_source.suffix}"
            payload_target = temporary / payload_relative
            payload_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(payload_source, payload_target)
            entries.append(dict(asset_index=asset_index, type_id=type_id,
                                type_name=type_name, name=native_row["name"],
                                rank=rank, format=exported.get("format"),
                                payload_bytes=payload_target.stat().st_size,
                                payload_sha256=sha256_file(payload_target),
                                payload_relative_path=payload_relative.as_posix(),
                                exporter_status=exported.get("status")))
        shutil.copy2(manifest_path, temporary / "manifest.json")
        shutil.copy2(journal_path, temporary / "assets.jsonl")
        index = dict(schema=1, export_key=export_key, body_sha256=body.source_sha256,
                     zone_id=zone_id, type_id=type_id, type_name=type_name,
                     acts_sha256=acts_sha, replay_executable_sha256=replay_sha,
                     source_sha256=walk_receipt["identity"]["source_sha256"],
                     native_walk_key=walk_receipt["walk_key"], items=entries)
        (temporary / "asset-payload-index.json").write_text(
            json.dumps(index, indent=2) + "\n", encoding="utf-8")
        temporary.replace(target)
        shutil.rmtree(short_root)
        return target, index
    except Exception as error:
        # Preserve ACTS output for diagnosis; the short path is included in the
        # error record and can be inspected without recursing the game install.
        (temporary / "export-error.json").write_text(json.dumps(
            dict(type_name=type_name, command=command, acts_output=str(short_root),
                 error=f"{type(error).__name__}: {error}",
                 log_sha256=sha256_file(log_path) if log_path.exists() else None),
            indent=2) + "\n", encoding="utf-8")
        raise


def _assert_native_candidate_artifacts(native: dict, output: Path) -> None:
    """Require the reader's FF/FP/FC snapshot to still match disk exactly."""
    artifacts = native.get("candidate_artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("native StringTable proof has no candidate-artifact snapshot")
    output = output.resolve(strict=False)
    for suffix in (".ff", ".fp", ".fc"):
        expected = artifacts.get(suffix)
        path = output if suffix == ".ff" else output.with_suffix(suffix)
        if not isinstance(expected, dict) or expected.get("path") != str(path):
            raise ValueError(f"native candidate {suffix} path does not match package output")
        exists = path.is_file()
        if expected.get("exists") is not exists:
            raise ValueError(f"native candidate {suffix} existence changed")
        if exists:
            if (type(expected.get("bytes")) is not int or expected["bytes"] != path.stat().st_size or
                    not isinstance(expected.get("sha256"), str) or
                    sha256_file(path) != expected["sha256"]):
                raise ValueError(f"native candidate {suffix} changed after native verification")
        elif expected.get("bytes") is not None or expected.get("sha256") is not None:
            raise ValueError(f"native candidate {suffix} absence record is inconsistent")


def _export_and_compare_stringtable_semantics(
        *, native: dict, output: Path, updated: bytes, verification_path: Path,
        zone_id: str, native_rows: list[dict], acts_path: Path, replay_executable: Path,
        timeout: int, source_index_path: Path, source_body_sha256: str,
        source_fastfile_sha256: str, source_walk_key: str, edited_name: str,
        edited_asset_index: int, expected_rows: list[list[str]]) -> tuple[dict, str]:
    """Export all type-54 payloads in a fresh per-build cache and compare semantics."""
    helper_path = Path(__file__).with_name("workstation_stringtable_semantics.py").resolve(strict=True)
    helper_sha = sha256_file(helper_path)
    _assert_native_candidate_artifacts(native, output)

    raw_manifest_path = Path(native.get("raw_manifest_path", "")).resolve(strict=True)
    raw_manifest_sha = native.get("raw_manifest_sha256")
    if not isinstance(raw_manifest_sha, str) or sha256_file(raw_manifest_path) != raw_manifest_sha:
        raise ValueError("fresh StringTable semantic export raw manifest hash differs from native receipt")
    raw_manifest = json.loads(raw_manifest_path.read_text(encoding="utf-8"))
    manifest_root = raw_manifest_path.parent.resolve(strict=True)

    def artifact_path(key: str, default: str) -> Path:
        relative = Path(raw_manifest.get(key, default))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"native StringTable manifest has unsafe {key} path")
        path = (manifest_root / relative).resolve(strict=True)
        if not path.is_relative_to(manifest_root):
            raise ValueError(f"native StringTable {key} escapes its manifest directory")
        return path

    output_trace_path = artifact_path("stream_trace", "stream-trace.jsonl")
    output_journal_path = artifact_path("journal", "assets.jsonl")
    trace_sha = native.get("trace_summary", {}).get("stream_trace_sha256")
    journal_sha = native.get("journal_sha256")
    if (sha256_file(output_trace_path) != trace_sha or
            sha256_file(output_journal_path) != journal_sha):
        raise ValueError("fresh StringTable semantic export trace or journal hash differs from native receipt")

    output_profile = source_profile(output)
    output_patch_sha256s = [patch_row["sha256"] for patch_row in output_profile.get("patches", [])]
    output_body_sha = hashlib.sha256(updated).hexdigest()
    output_walk_binding = dict(
        output_fastfile_sha256=output_profile["sha256"],
        output_patch_sha256s=output_patch_sha256s,
        output_body_sha256=output_body_sha,
        raw_manifest_sha256=raw_manifest_sha,
        stream_trace_sha256=trace_sha,
        journal_sha256=journal_sha,
        normalized_asset_identity_sha256=native.get("normalized_asset_identity_sha256"),
        tested=native["manifest"].get("tested"),
        top_level_index=native["manifest"].get("top_level_index"),
        serialized_bytes_read=native["manifest"].get("serialized_bytes_read"))
    output_walk_key = hashlib.sha256(json.dumps(
        output_walk_binding, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    output_walk_receipt = dict(
        walk_key=output_walk_key,
        identity=dict(source_sha256=output_profile["sha256"],
                      patch_sha256s=output_patch_sha256s))
    output_body = ZoneBody.parse(updated)
    candidate_export_root, _candidate_export_index = _export_native_type(
        output, zone_id, output_body, verification_path, output_walk_receipt,
        native_rows, 54, "stringtable", acts_path, replay_executable,
        timeout_seconds=timeout)
    from workstation_stringtable_semantics import compare_stringtable_exports
    proof = compare_stringtable_exports(
        source_index_path=source_index_path,
        output_index_path=candidate_export_root / "asset-payload-index.json",
        edited_name=edited_name, edited_asset_index=edited_asset_index,
        expected_rows=expected_rows, source_body_sha256=source_body_sha256,
        source_fastfile_sha256=source_fastfile_sha256,
        source_walk_key=source_walk_key, output_body_sha256=output_body_sha,
        output_fastfile_sha256=output_profile["sha256"], output_walk_key=output_walk_key)

    # Protect the complete evidence chain across ACTS extraction/comparison.
    _assert_native_candidate_artifacts(native, output)
    if (sha256_file(raw_manifest_path) != raw_manifest_sha or
            sha256_file(output_trace_path) != trace_sha or
            sha256_file(output_journal_path) != journal_sha):
        raise RuntimeError("native StringTable artifacts changed during semantic export")
    if sha256_file(helper_path) != helper_sha:
        raise RuntimeError("StringTable semantic proof helper changed during output export")
    proof["raw_manifest_sha256"] = raw_manifest_sha
    proof["native_trace_sha256"] = trace_sha
    proof["native_journal_sha256"] = journal_sha
    proof["candidate_artifacts"] = native["candidate_artifacts"]
    return proof, helper_sha


def _omnvar_helper_module_identities() -> dict[str, dict[str, str]]:
    """Current source identities required to revalidate Omnvar save/build proofs."""
    modules = {
        "validator": __import__("workstation_omnvars"),
        "resolver": __import__("workstation_omnvar_includes"),
        "stringtable": __import__("workstation_stringtable"),
        "asset_codecs": __import__("workstation_asset_codecs"),
        "trace_index": __import__("workstation_trace_index"),
        "semantic_export": __import__("workstation_stringtable_semantics"),
    }
    current = {name: Path(module.__file__).resolve(strict=True) for name, module in modules.items()}
    current["fastfiles"] = Path(__file__).resolve(strict=True)
    return {name: dict(path=str(path), sha256=sha256_file(path))
            for name, path in current.items()}


def _omnvar_helper_modules_match(saved: object) -> bool:
    if not isinstance(saved, dict):
        return False
    try:
        current = _omnvar_helper_module_identities()
    except (OSError, ImportError, AttributeError):
        return False
    if set(saved) != set(current):
        return False
    return all(isinstance(saved[name], dict) and
               saved[name].get("path") == current[name]["path"] and
               saved[name].get("sha256") == current[name]["sha256"]
               for name in current)


def _prepare_omnvar_mp_source_proof(
        *, source: Path, zone_id: str, body: ZoneBody, cache_path: Path,
        walk_receipt: dict, native_rows: list[dict], root_index: int,
        root_name: str, original_rows: list[list[str]], export_root: Path,
        export_index: dict, trace_path: Path, manifest_path: Path,
        edited_rows: list[list[str]] | None = None) -> tuple[dict, dict]:
    """Resolve and bind MP Omnvar includes to native type-54 source rows.

    ACTS CSV payloads are candidates only. Every root/include table must match
    the ordered native journal and pass ``inspect_stringtable`` against the
    decoded body and complete trace. Other StringTables never use this path.
    """
    from workstation_omnvar_includes import (
        bind_omnvar_include_closure, discover_omnvar_include_closure,
        read_type54_packed_resolutions)
    from workstation_stringtable import inspect_stringtable, validate_complete_stream5_allocations
    from workstation_trace_index import build_read_span_index
    from workstation_omnvars import validate_omnvar_mp_edit

    if root_name.replace("\\", "/").casefold() != "omnvars/mp/omnvars.csv":
        raise ValueError("MP Omnvar validation was requested for a different StringTable")
    if (not walk_receipt.get("stream_trace_enabled") or
            sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
            sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
        raise ValueError("Omnvar validation requires the unchanged complete native trace and manifest")
    helper_modules = _omnvar_helper_module_identities()
    discovery = discover_omnvar_include_closure(
        root_name, original_rows, native_rows=native_rows,
        export_root=export_root, export_index=export_index,
        expected_body_sha256=body.source_sha256,
        expected_native_walk_key=walk_receipt["walk_key"])
    selected = {item["asset_index"] for item in discovery["tables"]}
    trace_index = build_read_span_index(trace_path, manifest_path, len(body.data))
    stream5_allocation_context = validate_complete_stream5_allocations(trace_index)
    traces = {item["index"]: item for item in trace_index.get("assets", [])
              if isinstance(item.get("index"), int)}
    packed_resolutions = read_type54_packed_resolutions(
        trace_path, selected, trace_index["event_count"])
    if sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256"):
        raise ValueError("native trace changed while binding Omnvar root-name pointer callbacks")
    closure = bind_omnvar_include_closure(
        discovery, body_data=body.data, body_sha256=body.source_sha256,
        trace_sha256=walk_receipt["stream_trace_sha256"], trace_assets=traces,
        global_string_data_spans=trace_index.get("string_data_spans", []),
        packed_resolutions=packed_resolutions,
        inspect_stringtable=inspect_stringtable)
    closure["stream5_allocation_context"] = stream5_allocation_context
    by_index = {item["asset_index"]: item for item in closure["tables"]}
    root_proof = by_index.get(root_index)
    if (root_proof is None or root_proof.get("name") != root_name or
            native_rows[root_index].get("type_id") != 54 or
            native_rows[root_index].get("name") != root_name):
        raise ValueError("native-bound Omnvar closure does not contain the selected root row")
    validation = None
    if edited_rows is not None:
        validation = validate_omnvar_mp_edit(
            original_rows, edited_rows, asset_path=root_name,
            included_definition_names=closure["included_definition_names"],
            client_limit=None)
    proof = dict(
        schema="replay120-omnvar-mp-save-validation-v1",
        status="native-body-trace-bound",
        asset_path=root_name,
        root_asset_index=root_index,
        source_body_sha256=body.source_sha256,
        source_fastfile_sha256=walk_receipt.get("identity", {}).get("source_sha256"),
        native_walk_key=walk_receipt["walk_key"],
        native_manifest_sha256=walk_receipt["manifest_sha256"],
        stream_trace_sha256=walk_receipt["stream_trace_sha256"],
        source_closure=closure,
        edit_validation=validation,
        modules=helper_modules)
    root_trace = dict(traces[root_index])
    root_trace.update(index=root_index, xasset_index=root_index, type_id=54, name=root_name)
    return proof, root_trace


def _omnvar_validation_sha256(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


def _native_stringtable_export_rows(export_root: Path, export_index: dict,
                                    table_indices: set[int]) -> dict[int, list[list[str]]]:
    root = export_root.resolve(strict=True)
    items_by_index = {}
    for item in export_index.get("items", []):
        index = item.get("asset_index")
        if type(index) is int:
            if index in items_by_index:
                raise ValueError("native StringTable export has duplicate asset indices")
            items_by_index[index] = item
    result = {}
    for index in sorted(table_indices):
        item = items_by_index.get(index)
        relative = Path(str(item.get("payload_relative_path", ""))) if item else Path()
        if (item is None or item.get("type_id") != 54 or relative.is_absolute() or
                ".." in relative.parts):
            raise ValueError("Omnvar closure table differs from the native type-54 source export")
        payload_path = (root / relative).resolve(strict=True)
        if (not payload_path.is_relative_to(root) or not payload_path.is_file() or
                payload_path.stat().st_size != item.get("payload_bytes") or
                sha256_file(payload_path) != item.get("payload_sha256")):
            raise ValueError("native Omnvar CSV export payload failed path/hash verification")
        result[index] = list(csv.reader(io.StringIO(
            payload_path.read_bytes().decode("utf-8-sig"), newline="")))
    return result


def _validate_omnvar_effective_closure(
        source_closure: dict,
        source_rows_by_index: dict[int, list[list[str]]],
        staged_rows_by_index: dict[int, dict]) -> dict:
    """Validate staged CSVs against the effective, native-bound MP closure.

    The closure membership and include edges must already have been resolved
    and bound to the complete source body/trace by workstation_omnvar_includes.
    Staged rows can only target those exact native members. This validates the
    shared MP row schema on each member and then checks duplicate native name
    hashes against the effective staged definition set.
    """
    from workstation_omnvars import validate_omnvar_mp_edit, validate_omnvar_mp_rows

    if (not isinstance(source_closure, dict) or
            source_closure.get("status") != "native-body-trace-bound" or
            not re.fullmatch(r"[0-9a-f]{64}", str(source_closure.get("source_body_sha256", ""))) or
            not re.fullmatch(r"[0-9a-f]{64}", str(source_closure.get("source_trace_sha256", ""))) or
            not re.fullmatch(r"[0-9a-f]{64}", str(source_closure.get("native_walk_key", "")))):
        raise ValueError("Omnvar effective validation requires a complete body/trace-bound source closure")
    tables = source_closure.get("tables")
    edges = source_closure.get("include_edges")
    if not isinstance(tables, list) or not tables or not isinstance(edges, list):
        raise ValueError("Omnvar source closure has no bounded table/edge inventory")
    if len(tables) > 32 or len(edges) > 31:
        raise ValueError("Omnvar source closure exceeds its native include resolver bounds")
    roots = [item for item in tables
             if isinstance(item, dict) and
             str(item.get("name", "")).replace("\\", "/").casefold() ==
             "omnvars/mp/omnvars.csv"]
    if len(roots) != 1:
        raise ValueError("Omnvar native closure must contain exactly one MP root")
    root_index = roots[0].get("asset_index")
    if type(root_index) is not int or root_index < 0:
        raise ValueError("Omnvar native closure has an invalid MP root index")
    by_index = {}
    for item in tables:
        index = item.get("asset_index") if isinstance(item, dict) else None
        name = item.get("name") if isinstance(item, dict) else None
        if (type(index) is not int or index < 0 or not isinstance(name, str) or not name or
                index in by_index or index not in source_rows_by_index):
            raise ValueError("Omnvar closure contains an ambiguous or missing source table row")
        by_index[index] = item
    if set(source_rows_by_index) != set(by_index):
        raise ValueError("Omnvar source CSV set differs from the bound closure members")
    if set(staged_rows_by_index) - set(by_index):
        raise ValueError("staged Omnvar edit targets a table outside the resolved include closure")

    def include_and_definition_names(rows: list[list[str]]) -> tuple[list[str], list[str]]:
        includes, definitions = [], []
        saw_definition = False
        for row in rows:
            if row and row[0] == "include":
                if saw_definition or len(row) < 2:
                    raise ValueError("Omnvar include rows must precede definitions and include a path")
                includes.append(row[1])
            elif row:
                saw_definition = True
                definitions.append(row[0])
        return includes, definitions

    effective_rows: dict[int, list[list[str]]] = {}
    validation_source_rows: dict[int, list[list[str]]] = {}
    validation_effective_rows: dict[int, list[list[str]]] = {}
    source_column_counts: dict[int, int] = {}
    source_hashes: dict[int, str] = {}
    effective_hashes: dict[int, str] = {}
    effective_names: dict[int, list[str]] = {}
    effective_includes: dict[int, list[str]] = {}
    for index, item in by_index.items():
        source_rows = source_rows_by_index[index]
        is_root = index == root_index
        table_name = item["name"]
        if not source_rows or any(not isinstance(row, list) for row in source_rows):
            raise ValueError(f"Omnvar source table {table_name!r} has malformed CSV rows")
        source_column_count = len(source_rows[0])
        if source_column_count < 8 or any(len(row) != source_column_count for row in source_rows):
            raise ValueError(f"Omnvar source table {table_name!r} has an inconsistent or unsupported row width")
        source_column_counts[index] = source_column_count

        def normalize_for_proven_schema(rows: list[list[str]]) -> list[list[str]]:
            if any(not isinstance(row, list) or len(row) != source_column_count for row in rows):
                raise ValueError(
                    f"Omnvar table {table_name!r} must preserve its native {source_column_count}-column row layout")
            return [list(row[:14]) + ([""] * max(0, 14 - len(row))) for row in rows]

        normalized_source_rows = normalize_for_proven_schema(source_rows)
        source_validation = validate_omnvar_mp_rows(
            normalized_source_rows, asset_path=table_name,
            original_rows=normalized_source_rows,
            native_include_member=not is_root)
        source_includes, source_names = include_and_definition_names(source_rows)
        if (source_validation.get("row_count") != item.get("row_count") or
                source_validation.get("include_paths") != item.get("include_paths") or
                source_includes != item.get("include_paths") or
                source_names != item.get("definition_names")):
            raise ValueError(f"Omnvar source table {table_name!r} differs from its native-bound closure metadata")
        staged = staged_rows_by_index.get(index)
        rows = [list(row) for row in staged["rows"]] if staged else [list(row) for row in source_rows]
        normalized_rows = normalize_for_proven_schema(rows)
        includes, names = include_and_definition_names(rows)
        if includes != source_includes:
            raise ValueError(f"Omnvar table {table_name!r} changed its native include directives")
        source_tail_by_name = {row[0]: row[14:] for row in source_rows
                              if row and row[0] != "include" and len(row) > 14}
        effective_by_name = {row[0]: row for row in rows if row and row[0] != "include"}
        for name, source_tail in source_tail_by_name.items():
            effective_row = effective_by_name.get(name)
            if effective_row is not None and effective_row[14:] != source_tail:
                raise ValueError(f"Omnvar table {table_name!r} changed opaque native extension columns")
        effective_rows[index] = rows
        validation_source_rows[index] = normalized_source_rows
        validation_effective_rows[index] = normalized_rows
        effective_names[index] = names
        effective_includes[index] = includes
        source_hashes[index] = hashlib.sha256(json.dumps(
            source_rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        effective_hashes[index] = hashlib.sha256(json.dumps(
            rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()

    children: dict[int, list[int]] = {index: [] for index in by_index}
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("Omnvar native include edge is malformed")
        source_index = edge.get("source_asset_index")
        target_index = edge.get("target_asset_index")
        if (type(source_index) is not int or type(target_index) is not int or
                source_index not in by_index or target_index not in by_index or
                by_index[source_index].get("name") != edge.get("source_name") or
                by_index[target_index].get("name") != edge.get("target_name")):
            raise ValueError("Omnvar native include edge does not match the bound table identities")
        children[source_index].append(target_index)

    by_name_key: dict[str, list[int]] = {}
    for index, item in by_index.items():
        key = str(item["name"]).replace("\\", "/").casefold()
        by_name_key.setdefault(key, []).append(index)
    expected_edges = []
    for source_index, include_paths in effective_includes.items():
        for include_path in include_paths:
            targets = by_name_key.get(include_path.replace("\\", "/").casefold(), [])
            if len(targets) != 1:
                raise ValueError("Omnvar effective include path is missing or ambiguous in the bound closure")
            expected_edges.append((source_index, targets[0], include_path))
    actual_edges = [(edge["source_asset_index"], edge["target_asset_index"], edge["include_path"])
                    for edge in edges]
    if sorted(expected_edges) != sorted(actual_edges):
        raise ValueError("Omnvar include edges do not exactly match the source table directives")

    def descendants(index: int) -> list[int]:
        found: list[int] = []
        visiting: set[int] = set()

        def visit(parent: int) -> None:
            for child in children[parent]:
                if child in visiting or child in found:
                    raise ValueError("Omnvar effective closure contains a cycle or multiply reached table")
                visiting.add(child)
                found.append(child)
                visit(child)
                visiting.remove(child)

        visit(index)
        return found

    validation_rows = []
    for index in sorted(staged_rows_by_index):
        staged = staged_rows_by_index[index]
        item = by_index[index]
        effective_descendant_names = [name for child in descendants(index)
                                      for name in effective_names[child]]
        edit_validation = validate_omnvar_mp_edit(
            validation_source_rows[index], validation_effective_rows[index],
            asset_path=item["name"], included_definition_names=effective_descendant_names,
            native_include_member=index != root_index, client_limit=None)
        validation_rows.append(dict(asset_index=index, name=item["name"],
                                    revision=staged.get("revision"),
                                    validation=edit_validation))

    # This validates the complete effective definition set, including sibling
    # include branches, even when only an included table was staged.
    effective_included_names = [name for index in descendants(root_index)
                                for name in effective_names[index]]
    if set(descendants(root_index)) != set(by_index) - {root_index}:
        raise ValueError("Omnvar source closure contains a table unreachable from the MP root")
    root_validation = validate_omnvar_mp_edit(
        validation_source_rows[root_index], validation_effective_rows[root_index],
        asset_path=by_index[root_index]["name"],
        included_definition_names=effective_included_names, client_limit=None)
    proof = dict(schema="replay120-omnvar-effective-closure-edit-validation-v1",
                 status="effective-native-bound-closure-validated",
                 source_body_sha256=source_closure["source_body_sha256"],
                 source_trace_sha256=source_closure["source_trace_sha256"],
                 native_walk_key=source_closure["native_walk_key"],
                 root_asset_index=root_index,
                 tables=[dict(asset_index=index, name=by_index[index]["name"],
                              source_rows_sha256=source_hashes[index],
                              effective_rows_sha256=effective_hashes[index],
                              row_count=len(source_rows_by_index[index]),
                              source_column_count=source_column_counts[index],
                              effective_column_count=source_column_counts[index],
                              include_paths=effective_includes[index],
                              definition_names=effective_names[index])
                         for index in sorted(by_index)],
                 staged_table_validations=validation_rows,
                 effective_root_validation=root_validation)
    proof["validation_sha256"] = _omnvar_validation_sha256(proof)
    return proof


def header_marker(profile: dict) -> str:
    return "IWffs100" if profile.get("header_signature_marker") == "IWffs100" else "unknown"


class FastfileWorkspace:
    """Filesystem-backed source FF workspace with provenance-pinned decoding.

    `list_fastfiles` is an envelope/catalog view. `extract` performs generic
    decoding and a hash-pinned native Replay reader walk. Asset editing methods
    still require per-asset ownership spans and a complete native writer rather
    than treating table rows as serialized asset roots.
    """

    def __init__(self, root: str | Path, cache_root: str | Path,
                 game_root: str | Path, acts_path: str | Path | None = None,
                 replay_executable: str | Path | None = None,
                 lua_acts_path: str | Path | None = None):
        self.root = Path(root).resolve(strict=True)
        self.cache_root = Path(cache_root).resolve()
        self.game_root = Path(game_root).resolve(strict=True)
        selected_acts = acts_path or os.environ.get("REPLAY_ACTS")
        if not selected_acts:
            raise ValueError("REPLAY_ACTS is not configured; run setup-workstation.ps1 or pass acts_path")
        self.acts_path = Path(selected_acts).resolve(strict=True)
        # Lua source compilation may use a separately patched ACTS build.
        # Native fastfile decode, trace, write, and reread always stay on
        # self.acts_path so changing the Lua compiler cannot change FF reader
        # identity or behavior.
        lua_acts = lua_acts_path or os.environ.get("REPLAY_LUA_ACTS") or self.acts_path
        self.lua_acts_path = Path(lua_acts).expanduser().resolve(strict=True)
        self.replay_executable = Path(replay_executable).resolve() if replay_executable else \
            (self.game_root.parent / "game_dx12_ship_replay.exe").resolve()
        if not self.root.is_dir() or not self.game_root.is_dir():
            raise ValueError("workspace and game roots must be directories")
        if self.cache_root == self.game_root or self.cache_root.is_relative_to(self.game_root):
            raise ValueError("cache root must be outside the game directory")
        self.index_path = self.cache_root / "source-fastfile-index-v1.json"

    def _zone_path(self, relative_path: str | Path) -> Path:
        candidate = Path(relative_path)
        if candidate.is_absolute() or any(part in ("..", "") for part in candidate.parts):
            raise ValueError("fastfile path must be a confined relative path")
        path = (self.game_root / candidate).resolve(strict=True)
        if not path.is_relative_to(self.game_root) or path.suffix.casefold() != ".ff":
            raise ValueError("path must identify an .ff inside the configured game root")
        return path

    def list_fastfiles(self, query: str = "", offset: int = 0,
                       limit: int = 100) -> dict:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        needle = query.casefold()
        try:
            stored = json.loads(self.index_path.read_text(encoding="utf-8"))
            if not isinstance(stored, dict) or stored.get("schema") != 1 or \
                    stored.get("game_root") != str(self.game_root):
                indexed = {}
            else:
                indexed = stored.get("files", {})
                if not isinstance(indexed, dict):
                    indexed = {}
        except (OSError, ValueError, TypeError):
            indexed = {}
        rows = []
        fresh_index = {}
        for path in self.game_root.rglob("*.ff"):
            relative = path.relative_to(self.game_root).as_posix()
            stat = path.stat()
            old = indexed.get(relative)
            if old and old.get("bytes") == stat.st_size and old.get("mtime_ns") == stat.st_mtime_ns:
                row = dict(old["row"])
            else:
                try:
                    header = _source_header(path)
                    row = dict(relative_path=relative, status="source-header-checked",
                               bytes=stat.st_size,
                               source_xfile_version=header.xfile_version,
                               transient_type=header.transient_type)
                except (OSError, ValueError) as error:
                    row = dict(relative_path=relative, status="unsupported-or-invalid",
                               bytes=stat.st_size, error=str(error))
            fresh_index[relative] = dict(bytes=stat.st_size, mtime_ns=stat.st_mtime_ns, row=row)
            if needle and needle not in relative.casefold():
                continue
            rows.append(row)
        self.cache_root.mkdir(parents=True, exist_ok=True)
        index_temp = self.index_path.with_suffix(".tmp")
        index_temp.write_text(json.dumps(dict(schema=1, game_root=str(self.game_root),
                                              files=fresh_index), separators=(",", ":")),
                              encoding="utf-8")
        index_temp.replace(self.index_path)
        rows.sort(key=lambda row: row["relative_path"].casefold())
        return dict(total=len(rows), offset=offset, limit=limit,
                    items=rows[offset:offset + limit])

    def extract(self, relative_path: str | Path) -> dict:
        source = self._zone_path(relative_path)
        receipt = decode_source_fastfile(source, self.cache_root, self.acts_path,
                                         self.replay_executable)
        decode_path = self.cache_root / source.stem / receipt["cache_key"]
        native_receipt = walk_native_fastfile(source, receipt, decode_path, self.acts_path,
                                              self.replay_executable)
        receipt["zone_id"] = receipt["cache_key"]
        receipt["native_walk"] = native_receipt
        receipt["decoded_body_path"] = str(
            self.cache_root / source.stem / receipt["cache_key"] /
            receipt["final_body_relative_path"])
        receipt["relative_path"] = source.relative_to(self.game_root).as_posix()
        return receipt

    def list_assets(self, zone_id: str, query: str = "", offset: int = 0,
                    limit: int = 100) -> dict:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        cache_matches = list(self.cache_root.glob(f"*/{zone_id}/decode-receipt.json"))
        cache_guess = cache_matches[0].parent if len(cache_matches) == 1 else self.cache_root / "missing"
        has_pending = any(cache_guess.glob('pending-edits/op-*/current.json'))
        snapshot = self._validated_asset_snapshot(zone_id, require_trace=False,
                                                  validate_source=has_pending)
        cache_path, body = snapshot.cache_path, snapshot.body
        native_walk_receipt, native_rows = snapshot.native_walk, snapshot.native_rows
        needle = query.casefold()
        rows = []
        operation_rows = []
        if has_pending:
            from workstation_localize_crud import operations as localize_operations
            from workstation_luafile_crud import operations as luafile_operations
            from workstation_scriptfile_crud import operations as scriptfile_operations
            from workstation_rawfile_crud import operations as rawfile_operations
            from workstation_stringtable_crud import operations as stringtable_operations
            from workstation_shader_crud import operations as shader_operations
            operation_rows.extend(localize_operations(self, zone_id, _snapshot=snapshot))
            operation_rows.extend(luafile_operations(self, zone_id, _snapshot=snapshot))
            operation_rows.extend(scriptfile_operations(self, zone_id, _snapshot=snapshot))
            operation_rows.extend(rawfile_operations(self, zone_id, _snapshot=snapshot))
            operation_rows.extend(stringtable_operations(self, zone_id, _snapshot=snapshot))
            operation_rows.extend(shader_operations(self, zone_id, _snapshot=snapshot))
        removal_indices = {row['index'] for row in operation_rows if row['operation'] == 'remove'}
        for i, header in enumerate(body.assets):
            native_row = native_rows[i] if native_rows and i < len(native_rows) else None
            row = dict(asset_id=f"{zone_id}:{header.index}", index=header.index,
                       type_id=header.type_id,
                       pointer_token=f"0x{header.pointer_token:016x}",
                       name=native_row.get("name") if native_row else None,
                       root_span=None,
                       editable=bool(native_row and
                                     ((header.type_id == 21 and native_row.get("type") == "soundbank") or
                                      (header.type_id == 41 and native_row.get("type") == "localize") or
                                      (header.type_id == 51 and native_row.get("type") == "rawfile") or
                                      (header.type_id == 62 and native_row.get("type") == "luafile")) and
                                     header.pointer_token == 0xfffffffffffffffe),
                       graph_status=("soundbank-alias-scalars-typed-read-on-open"
                                     if native_row and header.type_id == 21 else
                                     "localize-entry-typed-read-on-open"
                                     if native_row and header.type_id == 41 else
                                     "luafile-root-and-child-typed-read-on-open"
                                     if native_row and header.type_id == 62 else
                                     "native-zone-reader-pass-root-spans-unavailable"
                                     if native_row else "typed-reader-schedule-unavailable"),
                       native_type_name=native_row.get("type") if native_row else None)
            if i in removal_indices:
                row.update(operation='remove', editable=False, graph_status='native-row-removal-staged')
            if native_row and native_row.get("status") == "reference":
                row.update(editable=False, graph_status="native-reference-only",
                           reference_only=True)
            if native_row and header.type_id == 54 and native_row.get("type") == "stringtable":
                row.update(row_remove_supported=False,
                           row_remove_reason="Removal requires final inline-name StringTable ownership; open the row for native eligibility")
            searchable = f"{row['index']} {row['type_id']} {row['pointer_token']} {row['name'] or ''}".casefold()
            if needle and needle not in searchable:
                continue
            rows.append(row)
        for operation in operation_rows:
            if operation['operation'] == 'append' and (not needle or needle in f"{operation['type']} {operation['name']}".casefold()):
                rows.append(dict(asset_id=operation['asset_id'], index=None, type_id=operation['type_id'], type=operation['type'],
                                 name=operation['name'], editable=True, operation='append',
                                 graph_status='native-row-append-staged'))
        return dict(zone_id=zone_id,
                    coverage=("native-zone-reader-pass-no-root-spans" if native_rows else "xasset-table-only"),
                    typed_graph_ready=False,
                    native_walk=({key: native_walk_receipt[key] for key in (
                        "status", "walk_key", "xasset_count", "loaded_assets",
                        "serialized_bytes_read", "writer_ready")}
                                 if native_walk_receipt else None),
                    total=len(rows), offset=offset, limit=limit,
                    items=rows[offset:offset + limit],
                    note="Rows identify XAsset table entries only; no root or child byte spans are inferred.")

    def _staged_asset_staleness(self, pending: dict, body: ZoneBody, index: int,
                                native: dict, walk_receipt: dict,
                                source_path: Path, *,
                                _snapshot: AssetRequestSnapshot | None = None) -> str | None:
        """Return why an otherwise intact staged snapshot cannot be used now."""
        if (pending.get("type_id") != body.assets[index].type_id or
                pending.get("name") != native.get("name")):
            return "staged edit belongs to a different native XAsset type or name"
        if pending.get("source_body_sha256") != body.source_sha256:
            return "staged edit belongs to another decoded source body"
        content_sha = _pending_content_sha(pending)
        if hashlib.sha256(pending["content"].encode("utf-8")).hexdigest() != content_sha:
            return "staged source text differs from its recorded content hash"
        receipt = pending.get("compiler_receipt")
        if not isinstance(receipt, dict):
            return "staged asset has no compiler receipt"
        canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
        if hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256"):
            return "staged compiler receipt hash is stale"
        if (receipt.get("source", {}).get("sha256") != content_sha or
                receipt.get("asset_name") != native.get("name") or
                receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
            return "staged compiler receipt no longer describes its source and payload"
        expected_status = {14: "replay120-dxbc-assemble-pass",
                           15: "replay120-dxbc-assemble-pass",
                           16: "replay120-dxbc-assemble-pass",
                           17: "replay120-dxbc-assemble-pass",
                           19: "replay120-resident-image-encode-pass",
                           52: "gsc-tool-native-payload-pass",
                           54: "replay120-stringtable-encode-pass",
                           62: "target-lua-loadx-reload-pass",
                           41: "replay120-localize-value-encode-pass",
                           51: "replay120-rawfile-encode-pass",
                           21: "replay120-soundbank-alias-scalars-pass"}.get(body.assets[index].type_id)
        if expected_status and receipt.get("status") != expected_status:
            return "staged compiler receipt uses a different asset compiler contract"
        compiler_staleness = self._compiler_identity_staleness(pending, body.assets[index].type_id)
        if compiler_staleness:
            return compiler_staleness
        try:
            profile = (_snapshot.source_profile if _snapshot is not None
                       else source_profile(source_path))
            identity = pending.get("native_source_identity", {})
            if (identity.get("body_sha256") != body.source_sha256 or
                    identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [patch["sha256"] for patch in profile.get("patches", [])]):
                return "staged source FF/body/native trace identity is stale"
        except (OSError, ValueError, KeyError, TypeError) as error:
            return f"staged source identity could not be validated: {error}"
        type_id = body.assets[index].type_id
        try:
            if type_id == 52:
                tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                compiler = receipt.get("compiler", {})
                if compiler.get("path") != str(tool) or compiler.get("tool_identity") != acts_tool_identity(tool):
                    return "staged GSC compiler identity is stale"
            elif type_id in (*SHADER_TYPES, 19):
                from workstation_asset_codecs import DEFAULT_DXBC_TOOL, DEFAULT_TEXCONV_TOOL
                import workstation_asset_codecs as codec_module
                tool = Path(os.environ.get(
                    "REPLAY_DXBC_TOOL" if type_id in SHADER_TYPES else "REPLAY_TEXCONV",
                    str(DEFAULT_DXBC_TOOL if type_id in SHADER_TYPES else DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                compiler = receipt.get("compiler", {})
                if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                        compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                    return "staged shader/image compiler identity is stale"
        except (OSError, ValueError, KeyError, TypeError) as error:
            return f"staged compiler tool identity could not be validated: {error}"
        return None

    def _compiler_identity_staleness(self, pending: dict, type_id: int) -> str | None:
        """Compare a staged compiler receipt with the tools that would consume it now."""
        receipt = pending.get("compiler_receipt")
        if not isinstance(receipt, dict):
            return "staged edit has no immutable compiler receipt"
        compiler = receipt.get("compiler", {})
        try:
            if type_id == 52:
                import workstation_asset_codecs as codec_module
                tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                if (compiler.get("path") != str(tool) or
                        compiler.get("tool_identity") != acts_tool_identity(tool) or
                        compiler.get("codec_module_path") != str(Path(codec_module.__file__).resolve()) or
                        compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                    return "staged GSC tool or codec module identity is stale"
            elif type_id == 62:
                import workstation_asset_codecs as codec_module
                from workstation_lua_compile import compiler_module_identity
                acts = Path(getattr(self, "lua_acts_path", self.acts_path)).resolve(strict=True)
                replay = self.replay_executable.resolve(strict=True)
                profile_name = "replay120_lua_native"
                profile = self._lua_compiler_profile_path(acts, profile_name)
                profile_data = json.loads(profile.read_text(encoding="utf-8"))
                provenance = profile_data.get("__provenance", {})
                bindings = provenance.get("bindings", {})
                required = {"lua_newstate", "lua_loadx", "lj_cf_string_dump", "writer_buf"}
                if compiler.get("dump_options", {}).get("strip") is True:
                    required.add("lua_pushboolean")
                if not required.issubset(bindings):
                    return "current Lua compiler profile is missing required Replay bindings"
                current = {
                    "path": str(acts),
                    "sha256": sha256_file(acts),
                    "common_library_path": str(acts.with_name("acts-common.dll")),
                    "common_library_sha256": sha256_file(acts.with_name("acts-common.dll")),
                    "tool_identity": acts_tool_identity(acts),
                    "profile_name": profile_name,
                    "profile_path": str(profile),
                    "profile_sha256": sha256_file(profile),
                    "profile_database_sha256": provenance.get("database_sha256"),
                    "profile_catalog_sha256": provenance.get("catalog_sha256") or provenance.get("compiler_catalog_sha256"),
                    "replay_executable_path": str(replay),
                    "replay_executable_sha256": sha256_file(replay),
                    "codec_module_path": str(Path(codec_module.__file__).resolve()),
                    "codec_module_sha256": sha256_file(Path(codec_module.__file__)),
                    **compiler_module_identity(),
                }
                for key, value in current.items():
                    if compiler.get(key) != value:
                        return f"staged Lua compiler identity is stale ({key})"
                recorded_bindings = compiler.get("api_bindings", {})
                if recorded_bindings != {name: dict(bindings[name]) for name in sorted(required)}:
                    return "staged Lua compiler API bindings are stale"
            elif type_id == 54:
                import workstation_asset_codecs as codec_module
                import workstation_stringtable as writer_module
                identities = {
                    "codec_module_path": str(Path(codec_module.__file__).resolve()),
                    "codec_module_sha256": sha256_file(Path(codec_module.__file__)),
                    "writer_module_path": str(Path(writer_module.__file__).resolve()),
                    "writer_module_sha256": sha256_file(Path(writer_module.__file__)),
                }
                for key, value in identities.items():
                    if compiler.get(key) != value:
                        return f"staged StringTable codec identity is stale ({key})"
            elif type_id == 51:
                import workstation_rawfile as rawfile_module
                writer_path = Path(rawfile_module.__file__).resolve()
                if (compiler.get("writer_module_path") != str(writer_path) or
                        compiler.get("writer_module_sha256") != sha256_file(writer_path)):
                    return "staged RawFile writer identity is stale"
            elif type_id == 21:
                import workstation_soundbank as soundbank_module
                writer_path = Path(soundbank_module.__file__).resolve()
                if (compiler.get("writer_module_path") != str(writer_path) or
                        compiler.get("writer_module_sha256") != sha256_file(writer_path)):
                    return "staged SoundBank writer identity is stale"
            elif type_id == 41:
                import workstation_localize as localize_module
                identity = {
                    "writer_module_path": str(Path(localize_module.__file__).resolve()),
                    "writer_module_sha256": sha256_file(Path(localize_module.__file__)),
                }
                for key, value in identity.items():
                    if compiler.get(key) != value:
                        return f"staged Localize writer identity is stale ({key})"
            elif type_id in (*SHADER_TYPES, 19):
                from workstation_asset_codecs import DEFAULT_DXBC_TOOL, DEFAULT_TEXCONV_TOOL
                import workstation_asset_codecs as codec_module
                variable = "REPLAY_TEXCONV" if type_id == 19 else "REPLAY_DXBC_TOOL"
                default = DEFAULT_TEXCONV_TOOL if type_id == 19 else DEFAULT_DXBC_TOOL
                tool = Path(os.environ.get(variable, str(default))).resolve(strict=True)
                if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                        compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                    return "staged shader/image tool or codec module identity is stale"
        except (OSError, ValueError, KeyError, TypeError) as error:
            return f"staged compiler identity could not be validated: {error}"
        return None

    @staticmethod
    def _lua_compiler_profile_path(acts_path: Path, profile_name: str) -> Path:
        """Return ACTS's actual :profile lookup and reject unsupported path overrides.

        ACTS GameData resolves a colon-prefixed game name as
        ``GetProgDir() / '<name>.json'``. The Lua compiler passes
        ``:<profile_name>`` as that game name, so an arbitrary
        REPLAY_ACTS_PROFILE path is not consumed by ACTS even though the
        Python codec can read it. Only accept the environment override when
        it names the exact adjacent file that ACTS will load.
        """
        expected = acts_path.resolve(strict=True).with_name(f"{profile_name}.json")
        override = os.environ.get("REPLAY_LUA_ACTS_PROFILE")
        if override:
            selected = Path(override).expanduser().resolve(strict=True)
            if selected != expected.resolve(strict=True):
                raise ValueError(
                    "REPLAY_LUA_ACTS_PROFILE is unsupported for ACTS :profile_name lookup; "
                    f"ACTS will load {expected}, not {selected}")
        return expected.resolve(strict=True)

    def _read_typed_soundbank(self, snapshot: AssetRequestSnapshot, index: int,
                              native: dict) -> dict:
        """Read one resident type-21 bank through its complete, pinned native trace."""
        import workstation_soundbank as soundbank_module
        walk = snapshot.native_walk
        if not walk.get("stream_trace_enabled"):
            raise UnsupportedAssetGraphError("SoundBank editing requires the complete native stream trace")
        profile = snapshot.source_profile
        if (profile.get("sha256") != walk.get("identity", {}).get("source_sha256") or
                [p.get("sha256") for p in profile.get("patches", [])] !=
                walk.get("identity", {}).get("patch_sha256s")):
            raise ValueError("SoundBank native walk belongs to a stale source FF/patch chain")
        trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
        if (sha256_file(trace_path) != walk.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk.get("manifest_sha256")):
            raise ValueError("SoundBank native trace or manifest failed walk receipt validation")
        body_path = snapshot.cache_path / snapshot.decode_receipt["final_body_relative_path"]
        receipt = soundbank_module.read_native_soundbank(
            body_path=body_path, source_fastfile=snapshot.source_path,
            manifest_path=manifest_path, trace_path=trace_path,
            asset_index=index, asset_name=native["name"])
        if (receipt.get("provenance", {}).get("source_body", {}).get("sha256") != snapshot.body.source_sha256 or
                receipt.get("provenance", {}).get("native_manifest", {}).get("sha256") != walk.get("manifest_sha256") or
                receipt.get("provenance", {}).get("native_trace", {}).get("sha256") != walk.get("stream_trace_sha256")):
            raise ValueError("SoundBank typed receipt differs from the current body/native walk")
        return receipt

    def _soundbank_source_identity(self, snapshot: AssetRequestSnapshot, index: int,
                                   receipt: dict) -> dict:
        walk, profile = snapshot.native_walk, snapshot.source_profile
        return dict(body_sha256=snapshot.body.source_sha256,
                    source_fastfile_sha256=profile["sha256"],
                    native_walk_key=walk["walk_key"],
                    native_manifest_sha256=walk["manifest_sha256"],
                    stream_trace_sha256=walk["stream_trace_sha256"],
                    xasset_index=index,
                    root_span={"archive_offset": receipt["root_archive_span"][0], "bytes": 512},
                    record_span={"archive_offset": receipt["asset_archive_span"][0],
                                 "bytes": receipt["asset_bytes"],
                                 "sha256": hashlib.sha256(snapshot.body.data[
                                     receipt["asset_archive_span"][0]:receipt["asset_archive_span"][1]]).hexdigest()},
                    typed_layout={"schema": receipt["schema"],
                                  "asset_archive_span": receipt["asset_archive_span"],
                                  "root_archive_span": receipt["root_archive_span"],
                                  "alias_list_table": receipt["alias_list_table"],
                                  "alias_child_arrays": receipt["alias_child_arrays"],
                                  "reader_identity_sha256": receipt["source_identity_sha256"]})

    def get_asset(self, asset_id: str, *, original: bool = False, _snapshot=None) -> dict:
        """Read saved content, or the immutable native asset without staged overlays."""
        zone_id, separator, index_text = asset_id.rpartition(":")
        if original and index_text.startswith('new-'):
            raise ValueError('An appended asset has no original fastfile row')
        if _snapshot is not None:
            self._require_asset_request_snapshot(_snapshot, zone_id)
        typed_new = re.fullmatch(r"new-(19)-([0-9a-f]{32})", index_text) if separator else None
        if typed_new:
            snapshot = self._validated_asset_snapshot(zone_id)
            from workstation_image_crud import get_new_resident_image_asset
            return get_new_resident_image_asset(self, asset_id, _snapshot=snapshot)
        if separator and re.fullmatch(r"new-(?:(?:12|14|15|16|17)-)?[0-9a-f]{32}", index_text):
            snapshot = self._validated_asset_snapshot(zone_id)
            digest = index_text.removeprefix("new-")
            operation_ids = (
                ("localize", "op-a-" + digest),
                ("rawfile", "op-a-r-" + digest),
                ("luafile", "op-a-l-" + digest),
                ("scriptfile", "op-a-s-" + digest),
                ("stringtable", "op-a-t-" + digest),
                ("pixelshader", "op-a-p-" + digest),
            )
            typed_shader = re.fullmatch(r"new-(12|14|15|16|17)-([0-9a-f]{32})", index_text)
            if typed_shader:
                from workstation_shader_crud import operations as shader_operations
                matches = [row for row in shader_operations(self, zone_id, _snapshot=snapshot)
                           if row.get("asset_id") == asset_id]
                if len(matches) != 1:
                    raise KeyError(asset_id)
                return dict(**{k: v for k, v in matches[0].items() if not k.startswith("_")},
                    editable=True, archive_writable=False,
                    package_status="Shader append queued for complete native reread")
            matches = [(kind, snapshot.cache_path / "pending-edits" / operation_id / "current.json")
                       for kind, operation_id in operation_ids
                       if (snapshot.cache_path / "pending-edits" / operation_id / "current.json").is_file()]
            if len(matches) != 1:
                if not matches:
                    raise KeyError(asset_id)
                raise ValueError("new asset identity is owned by multiple pending asset families")
            kind = matches[0][0]
            if kind == "localize":
                from workstation_localize_crud import get_new_localize_asset
                return get_new_localize_asset(self, asset_id, _snapshot=snapshot)
            if kind == "rawfile":
                from workstation_rawfile_crud import get_new_rawfile_asset
                return get_new_rawfile_asset(self, asset_id, _snapshot=snapshot)
            if kind == "luafile":
                from workstation_luafile_crud import get_new_luafile_asset
                return get_new_luafile_asset(self, asset_id, _snapshot=snapshot)
            if kind == "stringtable":
                from workstation_stringtable_crud import get_new_stringtable_asset
                return get_new_stringtable_asset(self, asset_id, _snapshot=snapshot)
            if kind == "pixelshader":
                from workstation_shader_crud import get_new_shader_asset
                return get_new_shader_asset(self, asset_id, _snapshot=snapshot)
            if kind == "image":
                from workstation_image_crud import get_new_resident_image_asset
                return get_new_resident_image_asset(self, asset_id, _snapshot=snapshot)
            from workstation_scriptfile_crud import get_new_scriptfile_asset
            return get_new_scriptfile_asset(self, asset_id, _snapshot=snapshot)
        if not separator or not index_text.isdecimal():
            raise ValueError("asset_id must be '<zone-cache-key>:<xasset-index>'")
        index = int(index_text)
        snapshot = _snapshot or self._validated_asset_snapshot(zone_id)
        cache_path, decode_receipt, body = (snapshot.cache_path,
                                             snapshot.decode_receipt, snapshot.body)
        if index >= len(body.assets):
            raise AssetNotFoundError(asset_id)
        walk_receipt, native_rows = snapshot.native_walk, snapshot.native_rows
        header, native = body.assets[index], native_rows[index]
        if native.get("status") == "reference":
            reference = dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=header.type_id, type=native.get("type", "reference"),
                        name=native["name"], content=None, language="text", extension="txt",
                        revision=None, editable=False, archive_writable=False,
                        reference_only=True, payload_format="native external asset reference",
                        package_status="Reference-only row; edit the asset in its owning fastfile")
            if header.type_id in (19, 51, 54):
                reference.update(row_remove_supported=False,
                    row_remove_reason=f"Reference-only {native.get('type', 'asset')} cannot be removed from this owner zone")
            return reference
        removal = cache_path / 'pending-edits' / f'op-r-{index}' / 'current.json'
        if not original and removal.exists():
            operation_record = json.loads(removal.read_text(encoding='utf-8'))
            if operation_record.get('type_id') == 41:
                from workstation_localize_crud import operations
            elif operation_record.get('type_id') == 62:
                from workstation_luafile_crud import operations
            elif operation_record.get('type_id') == 52:
                from workstation_scriptfile_crud import operations
            elif operation_record.get('type_id') == 51:
                from workstation_rawfile_crud import operations
            elif operation_record.get('type_id') == 54:
                from workstation_stringtable_crud import operations
            elif operation_record.get('type_id') == 19:
                from workstation_image_crud import operations
            else:
                raise ValueError('staged removal has an unsupported asset type')
            matched = [row for row in operations(self, zone_id, _snapshot=snapshot)
                       if row['asset_id'] == asset_id]
            if len(matched) != 1:
                raise ValueError('native row removal identity is ambiguous')
            public_row = {key: value for key, value in matched[0].items() if not key.startswith('_')}
            return public_row | dict(editable=False, archive_writable=False,
                        pending_path=str(removal), payload_format=f"Native {matched[0]['type']} row removal",
                        package_status='Removal queued; Restore original cancels this operation with history retained')
        if header.type_id == 17 and native.get("type") == "pixelshader" and native.get("name") == "null.hlsl":
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=17, type="pixelshader", name="null.hlsl",
                        content=None, language="dxbc-asm", extension="asm", revision=None,
                        editable=False, archive_writable=False,
                        payload_format="name-only Replay pixel shader asset",
                        package_status="read-only: null.hlsl is name-only and has no traced DXBC child")
        current_path = cache_path / "pending-edits" / str(index) / "current.json"
        if not original and current_path.is_file():
            current_path, pending, pending_payload = _validate_pending_snapshot(
                cache_path, index, asset_id, body)
            stale_reason = self._staged_asset_staleness(
                pending, body, index, native, walk_receipt,
                Path(decode_receipt["source"]["path"]).resolve(strict=True),
                _snapshot=snapshot)
            if stale_reason:
                source_identity = pending.get("native_source_identity", {})
                return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                            type_id=header.type_id, type=native.get("type"), name=native.get("name"),
                            content=pending.get("content"), language=pending.get("language"),
                            extension=pending.get("extension"), revision=pending.get("revision"),
                            content_sha256=_pending_content_sha(pending),
                            editable=False, archive_writable=False, stale=True,
                            codec_error=stale_reason, pending_path=str(current_path),
                            original_payload_sha256=pending.get("original_payload_sha256"),
                            edited_payload_sha256=pending.get("edited_payload_sha256"),
                            edited_payload_bytes=pending_payload.stat().st_size,
                            source=source_identity,
                            compiler_receipt=pending.get("compiler_receipt"),
                            compiler_receipt_sha256=pending.get("compiler_receipt_sha256"),
                            package_status="stale staged source is preserved for inspection and exact-revision discard")
            if ((header.type_id in SHADER_TYPES and native.get("type") == SHADER_TYPE_NAMES[header.type_id]) or
                    (header.type_id == 19 and native.get("type") == "image")) and not isinstance(pending.get("compiler_receipt"), dict):
                raise ValueError("staged shader/image edit has no immutable conversion receipt")
            if pending.get("source_body_sha256") != body.source_sha256:
                raise ValueError("staged asset edit belongs to another decoded source body")
            snapshot_path = current_path.parent / f"{pending.get('revision', '')}.json"
            if (not snapshot_path.is_file() or
                    json.loads(snapshot_path.read_text(encoding="utf-8")) != pending or
                    pending.get("asset_id") != asset_id or
                    pending.get("type_id") != header.type_id or pending.get("name") != native.get("name")):
                raise ValueError("staged edit differs from its immutable revision snapshot or native asset")
            pending_relative = Path(pending.get("edited_payload_path", ""))
            if pending_relative.name != str(pending_relative) or pending_relative.is_absolute():
                raise ValueError("staged asset payload path is invalid")
            pending_payload = current_path.parent / pending_relative
            if not pending_payload.is_file() or sha256_file(pending_payload) != pending.get("edited_payload_sha256"):
                raise ValueError("staged asset payload failed revision-cache hash validation")
            if pending.get("compiler_receipt") is not None:
                encoded = json.dumps(pending["compiler_receipt"], sort_keys=True,
                                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                if hashlib.sha256(encoded).hexdigest() != pending.get("compiler_receipt_sha256"):
                    raise ValueError("staged native compiler receipt failed immutable snapshot validation")
                if (pending["compiler_receipt"].get("source", {}).get("sha256") != _pending_content_sha(pending) or
                        pending["compiler_receipt"].get("asset_name") != native.get("name")):
                    raise ValueError("staged native compiler receipt does not match source/name revision")
                expected_status = {14: "replay120-dxbc-assemble-pass",
                                   15: "replay120-dxbc-assemble-pass",
                                   16: "replay120-dxbc-assemble-pass",
                                   17: "replay120-dxbc-assemble-pass",
                                   19: "replay120-resident-image-encode-pass",
                                   52: "gsc-tool-native-payload-pass",
                                   54: "replay120-stringtable-encode-pass",
                                   62: "target-lua-loadx-reload-pass",
                                   41: "replay120-localize-value-encode-pass",
                                   51: "replay120-rawfile-encode-pass",
                                   21: "replay120-soundbank-alias-scalars-pass"}.get(header.type_id)
                if (expected_status is not None and
                        pending["compiler_receipt"].get("status") != expected_status):
                    raise ValueError("staged compiler receipt has the wrong native asset compiler contract")
                if (pending["compiler_receipt"].get("result", {}).get("native_payload_sha256") !=
                        pending.get("edited_payload_sha256")):
                    raise ValueError("staged compiler receipt does not describe its payload")
            source_identity = pending.get("native_source_identity", {})
            if header.type_id in (*SHADER_TYPES, 19, 21, 41, 51, 52, 54, 62):
                if hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending):
                    raise ValueError("staged asset source text differs from its immutable revision")
                trace_walk = walk_receipt
                current_source = snapshot.source_profile
                if (source_identity.get("body_sha256") != body.source_sha256 or
                        source_identity.get("native_walk_key") != trace_walk.get("walk_key") or
                        source_identity.get("source_fastfile_sha256") != current_source.get("sha256") or
                        source_identity.get("source_fastfile_sha256") != trace_walk.get("identity", {}).get("source_sha256") or
                        source_identity.get("native_manifest_sha256") != trace_walk.get("manifest_sha256") or
                        source_identity.get("stream_trace_sha256") != trace_walk.get("stream_trace_sha256")):
                    raise ValueError("staged source body/FF/walk/trace identity is stale")
                if header.type_id == 52 and pending.get("compiler_receipt") is not None:
                    tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                    tool_identity = acts_tool_identity(tool)
                    receipt_compiler = pending["compiler_receipt"].get("compiler", {})
                    if (receipt_compiler.get("path") != str(tool) or
                            receipt_compiler.get("tool_identity") != tool_identity):
                        raise ValueError("staged GSC compiler identity is stale")
                if header.type_id in (*SHADER_TYPES, 19) and pending.get("compiler_receipt") is not None:
                    from workstation_asset_codecs import DEFAULT_DXBC_TOOL, DEFAULT_TEXCONV_TOOL
                    import workstation_asset_codecs as codec_module
                    tool = Path(os.environ.get(
                        "REPLAY_DXBC_TOOL" if header.type_id in SHADER_TYPES else "REPLAY_TEXCONV",
                        str(DEFAULT_DXBC_TOOL if header.type_id in SHADER_TYPES else DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                    compiler = pending["compiler_receipt"].get("compiler", {})
                    if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                            compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                        raise ValueError("staged shader/image editor tool identity is stale")
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=header.type_id, type=native["type"], name=native["name"],
                        content=pending["content"], language=pending["language"],
                        revision=pending["revision"], editable=True, archive_writable=False,
                        original_payload_sha256=pending["original_payload_sha256"],
                        edited_payload_sha256=pending["edited_payload_sha256"],
                        source=dict(body_sha256=body.source_sha256,
                                    native_walk_key=walk_receipt["walk_key"],
                                    source_fastfile_sha256=source_identity.get("source_fastfile_sha256"),
                                    native_manifest_sha256=source_identity.get("native_manifest_sha256"),
                                    stream_trace_sha256=source_identity.get("stream_trace_sha256"),
                                    xasset_index=index,
                                    root_span=source_identity.get("root_span"),
                                    record_span=source_identity.get("record_span"),
                                    typed_layout=source_identity.get("typed_layout")),
                        compiler_receipt=pending.get("compiler_receipt"),
                        compiler_receipt_sha256=pending.get("compiler_receipt_sha256"),
                        pending_path=str(current_path),
                        package_status=("LuaFile and mixed ScriptFile/LuaFile batches can be preflighted and packaged against this exact trace; "
                                        "archive_writable remains false until plan eligibility passes"
                                        if header.type_id == 62 else
                                        "Compiled native child saved; Compile game validates the batch and rereads the complete replacement FF/FP before publication"
                                        if header.type_id in (*SHADER_TYPES, 19) else None))
        type_id, type_name = header.type_id, native.get("type")
        if type_id == 51 and type_name == "rawfile":
            from workstation_rawfile import get_rawfile_asset
            return get_rawfile_asset(self, asset_id, snapshot, index)
        if type_id == 41 and type_name == "localize":
            from workstation_trace_index import build_read_span_index
            from workstation_localize import inspect_localize_entry
            trace_relative = walk_receipt.get("stream_trace_relative_path")
            manifest_relative = walk_receipt.get("manifest_relative_path")
            if not walk_receipt.get("stream_trace_enabled") or not trace_relative or not manifest_relative:
                raise UnsupportedAssetGraphError("Localize editing requires the complete native stream trace")
            profile = snapshot.source_profile
            if (profile.get("sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    [row["sha256"] for row in profile.get("patches", [])] !=
                    walk_receipt.get("identity", {}).get("patch_sha256s")):
                raise ValueError("Localize native walk belongs to a stale source FF/patch chain")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                raise ValueError("Localize trace/manifest failed walk receipt hash validation")
            trace_index = build_read_span_index(
                trace_path, manifest_path, len(body.data),
                selected_assets={index})
            trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("complete native trace does not contain this LocalizeEntry")
            trace_asset.update(index=index, xasset_index=index, type_id=41, name=native["name"])
            layout, values = inspect_localize_entry(body.data, index, native["name"], trace_asset,
                                                    expected_body_sha256=body.source_sha256)
            source_identity = dict(
                body_sha256=body.source_sha256, source_fastfile_sha256=profile["sha256"],
                native_walk_key=walk_receipt["walk_key"],
                native_manifest_sha256=walk_receipt["manifest_sha256"],
                stream_trace_sha256=walk_receipt["stream_trace_sha256"], xasset_index=index,
                root_span=dict(archive_offset=layout.root_archive_offset, bytes=16),
                record_span=dict(archive_offset=layout.root_archive_offset,
                                 bytes=layout.archive_end-layout.root_archive_offset,
                                 sha256=layout.source_record_sha256),
                typed_layout=dict(root_archive_offset=layout.root_archive_offset,
                                  root_stream_offset=layout.root_stream_offset,
                                  key_archive_offset=layout.key_archive_offset,
                                  key_stream_offset=layout.key_stream_offset,
                                  key_bytes=layout.key_bytes,
                                  value_archive_offset=layout.value_archive_offset,
                                  value_stream_offset=layout.value_stream_offset,
                                  value_bytes=layout.value_bytes,
                                  record_sha256=layout.source_record_sha256))
            revision = hashlib.sha256(values["value"].encode("utf-8")).hexdigest()
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=41, type="localize", name=native["name"],
                        content=values["value"], language="text", extension="txt",
                        revision=revision, editable=True, archive_writable=False,
                        payload_format="Replay LocalizeEntry stream-5 value string",
                        payload_bytes=layout.value_bytes,
                        payload_sha256=hashlib.sha256(body.data[layout.value_archive_offset:
                                                               layout.value_archive_offset+layout.value_bytes]).hexdigest(),
                        source=dict(**source_identity, trace_path=str(trace_path),
                                    manifest_path=str(manifest_path)),
                        package_status="NUL-free UTF-8 Localize value edits use the complete native trace; keys and XAsset rows remain immutable")
        if type_id == 21 and type_name == "soundbank":
            receipt = self._read_typed_soundbank(snapshot, index, native)
            import workstation_soundbank as soundbank_module
            document = soundbank_module.soundbank_edit_document(receipt)
            content = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            identity = self._soundbank_source_identity(snapshot, index, receipt)
            revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=21, type="soundbank", name=native["name"],
                        content=content, language="json", extension="json",
                        revision=revision, editable=True, archive_writable=False,
                        payload_format="Replay SndAlias verified float fields",
                        payload_bytes=receipt["asset_bytes"],
                        payload_sha256=identity["record_span"]["sha256"],
                        source=identity,
                        package_status="Verified alias float fields are editable; names, IDs, order, counts, and unknown record bytes stay fixed")
        if ((type_id in SHADER_TYPES and type_name == SHADER_TYPE_NAMES[type_id]) or
                (type_id == 19 and type_name == "image")):
            from workstation_trace_index import build_read_span_index
            from workstation_native_asset_edits import read_native_shader, read_resident_image
            trace_relative = walk_receipt.get("stream_trace_relative_path")
            manifest_relative = walk_receipt.get("manifest_relative_path")
            if not walk_receipt.get("stream_trace_enabled") or not trace_relative or not manifest_relative:
                raise UnsupportedAssetGraphError("shader/image editing requires the complete native stream trace")
            profile = snapshot.source_profile
            if (profile.get("sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    [row["sha256"] for row in profile.get("patches", [])] !=
                    walk_receipt.get("identity", {}).get("patch_sha256s")):
                raise ValueError("shader/image native walk belongs to a stale source FF/patch chain")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                raise ValueError("shader/image native trace or manifest failed its walk receipt")
            trace_index = build_read_span_index(
                trace_path, manifest_path, len(body.data),
                selected_assets=None if type_id == 12 else {index})
            trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("complete native trace does not contain the selected shader/image")
            trace_asset.update(index=index, type_id=type_id, name=native["name"])
            trace_asset["indexed_string_data_spans"] = trace_index["string_data_spans"]
            trace_asset["indexed_physical_spans"] = trace_index["_all_physical_spans"]
            trace_asset["_all_physical_spans"] = trace_index["_all_physical_spans"]
            source_identity = dict(body_sha256=body.source_sha256,
                                   source_fastfile_sha256=profile["sha256"],
                                   native_walk_key=walk_receipt["walk_key"],
                                   native_manifest_sha256=walk_receipt["manifest_sha256"],
                                   stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                   xasset_index=index)
            if type_id in SHADER_TYPES:
                from workstation_asset_codecs import disassemble_native_shader, DEFAULT_DXBC_TOOL
                layout = read_native_shader(body.data, dict(native, index=index), trace_asset,
                                            body.source_sha256, trace_assets=trace_index["assets"])
                if not layout.get("editable", True):
                    return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                                type_id=type_id, type=type_name, name=native["name"],
                                content=None, language="dxbc-asm", extension="asm", revision=None,
                                editable=False, archive_writable=False,
                                payload_format="shared Replay hull/domain null shader alias",
                                source=dict(**source_identity,
                                            root_span=dict(archive_offset=layout["root_archive_offset"], bytes=40),
                                            typed_layout=dict(root_archive_offset=layout["root_archive_offset"],
                                                              shared_null_alias=True),
                                            trace_path=str(trace_path), manifest_path=str(manifest_path)),
                                package_status=layout["reason"])
                tool = Path(os.environ.get("REPLAY_DXBC_TOOL", str(DEFAULT_DXBC_TOOL))).resolve(strict=True)
                tool_before = sha256_file(tool)
                decoded = disassemble_native_shader(layout["program"], type_id,
                                                    tool=tool, asset_name=native["name"])
                if sha256_file(tool) != tool_before:
                    raise RuntimeError("DXBC disassembler changed during extraction")
                if not decoded["editable"]:
                    return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                                type_id=type_id, type=type_name, name=native["name"],
                                content=None, language="dxbc-asm", extension="asm", revision=None,
                                editable=False, archive_writable=False,
                                codec_error=decoded["codec_error"],
                                payload_format="trace-owned inline DXBC shader",
                                payload_bytes=len(layout["program"]),
                                payload_sha256=layout["program_sha256"],
                                source=dict(**source_identity,
                                            root_span=dict(archive_offset=layout["root_archive_offset"], bytes=40),
                                            record_span=dict(archive_offset=layout["program_archive_offset"],
                                                             bytes=len(layout["program"]),
                                                             sha256=layout["program_sha256"]),
                                            trace_path=str(trace_path), manifest_path=str(manifest_path)),
                                package_status="read-only: pinned DXBC tool rejected disassembly/round-trip; see codec_error")
                content = decoded["assembly"]
                language, extension = "dxbc-asm", "asm"
                source_identity["root_span"] = dict(archive_offset=layout["root_archive_offset"], bytes=40)
                source_identity["record_span"] = dict(archive_offset=layout["program_archive_offset"],
                                                       bytes=len(layout["program"]),
                                                       sha256=layout["program_sha256"])
                source_identity["typed_layout"] = dict(root_archive_offset=layout["root_archive_offset"],
                                                        name_archive_offset=layout["name_archive_offset"],
                                                        child_archive_offset=layout["program_archive_offset"],
                                                        child_bytes=len(layout["program"]),
                                                        debug_name=layout["debug_name"],
                                                        debug_name_stream_location=layout["debug_name_stream_location"])
                payload_bytes, payload_sha = len(layout["program"]), layout["program_sha256"]
                payload_format = "Replay inline DXBC shader child"
            else:
                from workstation_asset_codecs import (export_replay_image_mips_to_png,
                    export_replay_image_resource_to_dds, _REPLAY_DXGI_NAMES, DEFAULT_TEXCONV_TOOL)
                layout = read_resident_image(body.data, dict(native, index=index), trace_asset,
                                             body.source_sha256)
                width, height, depth, elements = layout["dimensions"]
                complex_resource = depth != 1 or elements != 1
                if complex_resource:
                    atlas_token, fallback_token = struct.unpack_from("<Q", layout["root_bytes"], 8)[0], struct.unpack_from("<Q", layout["root_bytes"], 0xD8)[0]
                    if atlas_token or fallback_token:
                        raise UnsupportedAssetGraphError("array/volume DDS export requires a resident image without atlas or fallback children")
                    dds = export_replay_image_resource_to_dds(
                        width, height, depth, elements, layout["format"],
                        layout["level_count"], layout["payload"], flags=layout["flags"])
                    content = "data:application/octet-stream;base64," + base64.b64encode(dds).decode("ascii")
                    language, extension = "image/dds-base64", "dds"
                    tool_before = None
                else:
                    if layout["format"] not in _REPLAY_DXGI_NAMES:
                        raise UnsupportedAssetGraphError(f"Replay image format {layout['format']} has no supported PNG codec")
                    tool = Path(os.environ.get("REPLAY_TEXCONV", str(DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                    tool_before = sha256_file(tool)
                    png = export_replay_image_mips_to_png(width, height, layout["format"],
                                                          layout["level_count"], layout["payload"], tool=tool)
                    if sha256_file(tool) != tool_before:
                        raise RuntimeError("image decoder changed during extraction")
                    content = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
                    language, extension = "image/png-base64", "png"
                source_identity["root_span"] = dict(archive_offset=layout["root_archive_offset"], bytes=232)
                source_identity["record_span"] = dict(archive_offset=layout["payload_archive_offset"],
                                                       bytes=len(layout["payload"]),
                                                       sha256=layout["payload_sha256"])
                source_identity["typed_layout"] = _resident_image_typed_layout(layout)
                payload_bytes, payload_sha = len(layout["payload"]), layout["payload_sha256"]
                payload_format = ("Replay resident inline image pixels exported as lossless DDS subresources"
                                  if complex_resource else "Replay resident inline image pixels")
            revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
            row_remove_supported = False
            row_remove_reason = "Only an exclusive inline final XAsset tail can be removed"
            if type_id == 19 and index == len(body.assets) - 1:
                try:
                    from workstation_image_row_operations import remove_final_resident_image_tail
                    remove_final_resident_image_tail(body.data, index, native["name"],
                        dict(native, index=index), trace_asset, body.source_sha256, trace_path, manifest_path,
                        expected_trace_sha256=walk_receipt["stream_trace_sha256"],
                        expected_manifest_sha256=walk_receipt["manifest_sha256"])
                    row_remove_supported, row_remove_reason = True, None
                except (ValueError, KeyError, IndexError) as error:
                    row_remove_reason = str(error)
            if type_id in SHADER_TYPES:
                row_remove_supported = (index == len(body.assets) - 1 and
                    isinstance(trace_asset.get("read_spans"), list) and bool(trace_asset["read_spans"]) and
                    max((span.get("archive_offset", -1) + span.get("size", 0)
                         for span in trace_asset["read_spans"]), default=-1) == len(body.data))
                row_remove_reason = (None if row_remove_supported else
                    "Only an exclusive shader row at the exact serialized tail can be removed.")
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=type_id, type=type_name, name=native["name"],
                        content=content, language=language, extension=extension,
                        revision=revision, editable=True, archive_writable=False,
                        payload_format=payload_format, payload_bytes=payload_bytes,
                        payload_sha256=payload_sha,
                        source=dict(**source_identity, trace_path=str(trace_path),
                                    manifest_path=str(manifest_path)),
                        **({"row_remove_supported": row_remove_supported,
                            "row_remove_reason": row_remove_reason} if type_id in (*SHADER_TYPES, 19) else {}),
                        package_status="same-extent native child replacement is supported; packaging requires the full-zone Replay reread gate")
        if type_id == 62 and type_name == "luafile":
            # LuaFile is a separate typed contract from ScriptFile: use the
            # captured full-zone trace to prove its 24-byte root and inline
            # stream-5 child before exposing source to the editor.
            from workstation_asset_codecs import decompile_luajit_bytecode
            from workstation_luafile import inspect_luafile
            from workstation_luajit_chunk import split_luajit_file_payload
            trace_relative = walk_receipt.get("stream_trace_relative_path")
            manifest_relative = walk_receipt.get("manifest_relative_path")
            if not walk_receipt.get("stream_trace_enabled") or not trace_relative or not manifest_relative:
                raise UnsupportedAssetGraphError("LuaFile editing requires the complete native stream trace")
            current_source = snapshot.source_profile
            if (current_source.get("sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    [row["sha256"] for row in current_source.get("patches", [])] !=
                    walk_receipt.get("identity", {}).get("patch_sha256s")):
                raise ValueError("LuaFile cached walk belongs to a stale source FF/FP/FC chain")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (not trace_path.is_file() or not manifest_path.is_file() or
                    sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                raise ValueError("LuaFile native trace/manifest failed walk-receipt hash validation")
            from workstation_trace_index import build_read_span_index
            trace_index = build_read_span_index(trace_path, manifest_path, len(body.data),
                                                selected_assets={index})
            trace_asset = next((row for row in trace_index["assets"]
                                if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("complete trace does not contain the selected LuaFile")
            trace_asset.update(xasset_index=index, name=native["name"])
            layout, native_payload = inspect_luafile(
                body.data, index, native["name"], trace_asset,
                expected_body_sha256=body.source_sha256)
            # Validate the exact source child, then let the decompiler receive
            # the native LuaFile payload (including its terminal NUL when
            # present). The chunk parser handles the optional outer NUL
            # rather than stripping or reconstructing bytes in this caller.
            split_luajit_file_payload(native_payload)
            content = decompile_luajit_bytecode(native_payload, name=native["name"])
            revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
            return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                        type_id=type_id, type=type_name, name=native["name"],
                        content=content, language="lua", extension="lua",
                        revision=revision, editable=True,
                        # Direct replacement and staged append/remove each have
                        # separate full-zone native readback gates.
                        archive_writable=False,
                        payload_format="Replay LuaJIT v2 native child",
                        payload_bytes=len(native_payload),
                        payload_sha256=hashlib.sha256(native_payload).hexdigest(),
                        source=dict(body_sha256=body.source_sha256,
                                    source_fastfile_sha256=walk_receipt["identity"]["source_sha256"],
                                    native_walk_key=walk_receipt["walk_key"],
                                    native_manifest_sha256=walk_receipt["manifest_sha256"],
                                    stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                    xasset_index=index,
                                    root_span=dict(archive_offset=layout.root_archive_offset,
                                                   bytes=24),
                                    bytecode_span=dict(archive_offset=layout.bytecode_archive_offset,
                                                       stream=layout.bytecode_stream,
                                                       stream_offset=layout.bytecode_stream_offset,
                                                       bytes=layout.bytecode_bytes),
                                    trace_path=str(trace_path),
                                    manifest_path=str(manifest_path)),
                        package_status=("LuaFile edit is staged only after compiler/source identity checks; "
                                        "row operations package through sequential full-zone Replay rereads"))
        if type_id not in (52, 54) or type_name not in ("scriptfile", "stringtable"):
            raise UnsupportedAssetGraphError(
                f"{type_name or type_id} has no registered semantic editor payload codec")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        if type_id in (52, 54):
            profile = snapshot.source_profile
            if (profile.get("sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    [row["sha256"] for row in profile.get("patches", [])] !=
                    walk_receipt.get("identity", {}).get("patch_sha256s")):
                raise ValueError("ScriptFile native walk belongs to a stale source FF/patch chain")
        export_root, export_index = _export_native_type(
            source, zone_id, body, cache_path, walk_receipt, native_rows,
            type_id, type_name, self.acts_path, self.replay_executable)
        item = next((entry for entry in export_index["items"] if entry["asset_index"] == index), None)
        if item is None:
            raise ValueError("type-filtered exporter did not return requested XAsset row")
        payload_path = export_root / item["payload_relative_path"]
        payload = payload_path.read_bytes()
        codec_tool = None
        if type_name == "scriptfile":
            from workstation_asset_codecs import decompile_scriptfile
            tool = DEFAULT_GSC_TOOL.resolve(strict=True)
            codec_tool = dict(path=str(tool), sha256=sha256_file(tool))
            try:
                content = decompile_scriptfile(payload, tool, str(index))
            except (RuntimeError, ValueError) as error:
                return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                            type_id=type_id, type=type_name, name=native["name"],
                            content=None, language="gsc", extension="gsc",
                            revision=None, editable=False, archive_writable=False,
                            payload_format=item["format"], payload_bytes=item["payload_bytes"],
                            payload_sha256=item["payload_sha256"], payload_path=str(payload_path),
                            codec_error=str(error),
                            source=dict(body_sha256=body.source_sha256,
                                        source_fastfile_sha256=walk_receipt["identity"]["source_sha256"],
                                        native_walk_key=walk_receipt["walk_key"],
                                        xasset_index=index, root_span=None, codec_tool=codec_tool),
                            package_status="not-repackable-without-root-child-relocation-schedule")
            language, extension = "gsc", "gsc"
        else:
            content = payload.decode("utf-8-sig")
            parsed_rows = list(csv.reader(io.StringIO(content, newline="")))
            language, extension = "csv", "csv"
            if type_name == "stringtable":
                profile = source_profile(source)
                if (profile.get("sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                        [row["sha256"] for row in profile.get("patches", [])] !=
                        walk_receipt.get("identity", {}).get("patch_sha256s")):
                    raise ValueError("StringTable native walk belongs to a stale source FF/patch chain")
                if not walk_receipt.get("stream_trace_enabled"):
                    raise UnsupportedAssetGraphError("StringTable editing requires the complete native stream trace")
                trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                        sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                    raise ValueError("StringTable trace/manifest failed walk-receipt hash validation")
                from workstation_trace_index import build_read_span_index
                from workstation_stringtable import inspect_stringtable, validate_complete_stream5_allocations
                trace_index = build_read_span_index(trace_path, manifest_path, len(body.data))
                stream5_allocation_context = validate_complete_stream5_allocations(trace_index)
                trace_asset = next((row for row in trace_index["assets"]
                                    if row.get("index") == index), None)
                if trace_asset is None:
                    raise ValueError("complete trace does not contain the selected StringTable")
                trace_asset.update(xasset_index=index, type_id=54, name=native["name"])
                layout, parsed_rows = inspect_stringtable(
                    body.data, index, native["name"], trace_asset, parsed_rows,
                    expected_body_sha256=body.source_sha256,
                    global_string_data_spans=trace_index.get("string_data_spans", []))
                source_identity = dict(body_sha256=body.source_sha256,
                                       source_fastfile_sha256=profile["sha256"],
                                       native_walk_key=walk_receipt["walk_key"],
                                       native_manifest_sha256=walk_receipt["manifest_sha256"],
                                       stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                        stream5_allocation_context=stream5_allocation_context,
                                       xasset_index=index,
                                       root_span=dict(archive_offset=layout.root_archive_offset,
                                                      bytes=48),
                                       record_span=dict(archive_offset=layout.root_archive_offset,
                                                        bytes=layout.archive_end-layout.root_archive_offset,
                                                        sha256=layout.source_record_sha256))
                revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
                removable = (index == len(body.assets) - 1 and
                             layout.name_pointer_mode == "inline" and
                             all(token in (0xffffffffffffffff, 0xfffffffffffffffe)
                                 for token in layout.pointer_tokens) and
                             layout.archive_end == len(body.data) and
                             trace_asset.get("end_cursor") == len(body.data))
                removal_reason = (None if removable else
                    "Only a final inline-name StringTable whose complete root, dictionary and stream-5 record end at the serialized EOF is eligible")
                return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                            type_id=54, type="stringtable", name=native["name"],
                            content=content, language="csv", extension="csv",
                            revision=revision, editable=True, archive_writable=False,
                            row_remove_supported=removable, row_remove_reason=removal_reason,
                            payload_format=item["format"], payload_bytes=item["payload_bytes"],
                            payload_sha256=item["payload_sha256"], payload_path=str(payload_path),
                            source=source_identity,
                            package_status="single StringTable edits use the complete native trace and relocate packed block-5 aliases")
        revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return dict(asset_id=asset_id, zone_id=zone_id, index=index,
                    type_id=type_id, type=type_name, name=native["name"],
                    content=content, language=language, extension=extension,
                    revision=revision, editable=True, archive_writable=False,
                    payload_format=item["format"], payload_bytes=item["payload_bytes"],
                    payload_sha256=item["payload_sha256"], payload_path=str(payload_path),
                    source=dict(body_sha256=body.source_sha256,
                                source_fastfile_sha256=walk_receipt["identity"]["source_sha256"],
                                native_walk_key=walk_receipt["walk_key"],
                                native_manifest_sha256=walk_receipt.get("manifest_sha256") if type_id == 52 else None,
                                stream_trace_sha256=walk_receipt.get("stream_trace_sha256") if type_id == 52 else None,
                                xasset_index=index, root_span=None, codec_tool=codec_tool),
                    package_status="not-repackable-without-root-child-relocation-schedule")

    def save_asset(self, asset_id: str, content: str, revision: str) -> dict:
        if not isinstance(content, str) or not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("save_asset requires text content and a SHA-256 revision")
        current = self.get_asset(asset_id)
        if current["revision"] != revision:
            raise ValueError("Asset revision conflict; reload before saving")
        if current.get("stale") or not current.get("editable"):
            raise ValueError("staged source is stale or read-only; discard it or reload the asset before saving")
        if current.get('operation') == 'append':
            return self.create_asset(current['zone_id'], name=current['name'], content=content,
                                     type=current.get('type', 'localize'), revision=revision,
                                     editor_mode=current.get('editor_mode'))
        return self._compile_asset_edit(asset_id, content, current)

    def recompile_asset(self, asset_id: str, revision: str) -> dict:
        """Recompile preserved draft source without discarding its old revision.

        The shared compiler path revalidates the native body, source chain,
        trace and typed spans before publishing. A changed compiler may be
        accepted; changed asset ownership may not.
        """
        current = self.get_asset(asset_id)
        if not isinstance(revision, str) or current.get("revision") != revision:
            raise ValueError("Asset revision conflict; reload before recompiling")
        if (not current.get("pending_path") or current.get("operation") or
                current.get("type_id") not in (*SHADER_TYPES, 19, 21, 41, 51, 52, 54, 62) or
                not isinstance(current.get("content"), str)):
            raise ValueError("Recompile requires an existing supported source edit")
        return self._compile_asset_edit(asset_id, current["content"], current)

    def _compile_asset_edit(self, asset_id: str, content: str, current: dict) -> dict:
        zone_id, index = current["zone_id"], current["index"]
        cache_path, decode_receipt = self._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache_path / decode_receipt["final_body_relative_path"]).read_bytes())
        source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        expected_pending = None
        if current.get("pending_path"):
            _, expected_pending, _ = _validate_pending_snapshot(
                cache_path, index, asset_id, body)
            if expected_pending.get("revision") != current.get("revision"):
                raise ValueError("Asset revision conflict; reload before saving")
        walk_receipt, native_rows = _read_native_rows(cache_path, body)
        native = native_rows[index]
        compile_receipt = None
        source_identity = current.get("source", {})
        if native["type"] == "soundbank":
            import workstation_soundbank as soundbank_module
            if body.assets[index].type_id != 21 or native_rows[index].get("type_id") != 21:
                raise ValueError("SoundBank type/name identity changed; reload before saving")
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            profile = source_profile(source_path)
            walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
            native = native_rows[index]
            if (native.get("type") != "soundbank" or native.get("name") != current.get("name") or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    source_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [patch["sha256"] for patch in profile.get("patches", [])]):
                raise ValueError("SoundBank source body/FF/native walk identity changed; reload before saving")
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            receipt = self._read_typed_soundbank(snapshot, index, native)
            current_identity = self._soundbank_source_identity(snapshot, index, receipt)
            if source_identity.get("typed_layout") != current_identity.get("typed_layout"):
                raise ValueError("SoundBank root/list/alias layout changed; reload before saving")
            changes = soundbank_module.validate_soundbank_edit_document(content, receipt)
            if not changes:
                raise ValueError("SoundBank edit does not change a supported alias field")
            payload = content.encode("utf-8")
            writer_path = Path(soundbank_module.__file__).resolve()
            writer_before = sha256_file(writer_path)
            compile_receipt = dict(
                schema="replay120-soundbank-alias-scalar-compile-receipt-v1",
                status="replay120-soundbank-alias-scalars-pass",
                asset_name=native["name"],
                source=dict(sha256=hashlib.sha256(payload).hexdigest(), utf8_bytes=len(payload)),
                compiler=dict(writer_module_path=str(writer_path), writer_module_sha256=writer_before),
                input=dict(reader_identity_sha256=receipt["source_identity_sha256"],
                           changed_aliases=len(changes),
                           changed_fields=sum(len(row["fields"]) for row in changes)),
                result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                            native_payload_bytes=len(payload),
                            payload_contract="narrow semantic SoundBank alias scalar document",
                            changes=changes))
            payload_format = "Replay SndAlias verified float edits"
            if sha256_file(writer_path) != writer_before:
                raise RuntimeError("SoundBank reader/writer module changed during staging")
        elif native["type"] == "localize":
            import workstation_localize as localize_module
            from workstation_trace_index import build_read_span_index
            from workstation_localize import (inspect_localize_entry,
                                              replace_localize_values_with_relocation)
            walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            profile = source_profile(source_path)
            if (body.assets[index].type_id != 41 or native_rows[index].get("type_id") != 41 or
                    native_rows[index].get("name") != native["name"] or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    source_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [patch["sha256"] for patch in profile.get("patches", [])]):
                raise ValueError("Localize source body/FF/native walk identity changed; reload before saving")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (not walk_receipt.get("stream_trace_enabled") or
                    sha256_file(trace_path) != source_identity.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != source_identity.get("native_manifest_sha256")):
                raise ValueError("Localize trace or manifest changed; reload before saving")
            trace_index = build_read_span_index(trace_path, manifest_path, len(body.data),
                                                selected_assets={index})
            trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("complete native trace has no selected LocalizeEntry")
            trace_asset.update(index=index, xasset_index=index, type_id=41, name=native["name"])
            layout, values = inspect_localize_entry(body.data, index, native["name"], trace_asset,
                                                    expected_body_sha256=body.source_sha256)
            expected_layout = source_identity.get("typed_layout", {})
            layout_values = dict(root_archive_offset=layout.root_archive_offset,
                                 root_stream_offset=layout.root_stream_offset,
                                 key_archive_offset=layout.key_archive_offset,
                                 key_stream_offset=layout.key_stream_offset,
                                 key_bytes=layout.key_bytes,
                                 value_archive_offset=layout.value_archive_offset,
                                 value_stream_offset=layout.value_stream_offset,
                                 value_bytes=layout.value_bytes,
                                 record_sha256=layout.source_record_sha256)
            source_value_hash = hashlib.sha256(values["value"].encode("utf-8") + b"\0").hexdigest()
            original_value_hash = current.get("original_payload_sha256", current.get("payload_sha256"))
            if expected_layout != layout_values or source_value_hash != original_value_hash:
                raise ValueError("Localize root/key/value spans or current semantic value changed; reload before saving")
            payload = content.encode("utf-8") + b"\0"
            # Even equal-length values can be shared by other localization
            # keys. Replay the complete pointer graph before staging any edit.
            _, replacement = replace_localize_values_with_relocation(
                body.data, [dict(asset_index=index, asset_name=native["name"],
                                 trace_asset=trace_asset, value=content,
                                 expected_key=native["name"], expected_value=values["value"])],
                body.source_sha256, trace_path, manifest_path)
            codec_before = sha256_file(Path(localize_module.__file__))
            status = "replay120-localize-value-encode-pass"
            payload_format = "Replay LocalizeEntry stream-5 value string"
            compile_receipt = dict(
                schema="replay120-localize-value-compile-receipt-v1", status=status,
                asset_name=native["name"],
                source=dict(sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                            utf8_bytes=len(content.encode("utf-8"))),
                compiler=dict(writer_module_path=str(Path(localize_module.__file__).resolve()),
                              writer_module_sha256=codec_before),
                input=dict(asset_index=index, key=native["name"],
                           source_value_sha256=hashlib.sha256(values["value"].encode("utf-8")).hexdigest(),
                           source_value_bytes=layout.value_bytes),
                result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                            native_payload_bytes=len(payload), payload_contract="NUL-terminated UTF-8 value bytes"),
                replacement=replacement)
            if sha256_file(Path(localize_module.__file__)) != codec_before:
                raise RuntimeError("Localize typed writer changed during staging")
        elif native["type"] == "rawfile":
            from workstation_rawfile import compile_rawfile_asset
            payload, payload_format, compile_receipt = compile_rawfile_asset(
                self, asset_id, content, current, body, cache_path, walk_receipt, native)
        elif native["type"] in (*SHADER_TYPE_IDS, "image"):
            from workstation_trace_index import build_read_span_index
            from workstation_native_asset_edits import (
                read_inline_shader, read_resident_image,
                replace_inline_shader, replace_resident_image)
            if not isinstance(current.get("content"), str):
                raise ValueError("shader/image editor content is not text")
            walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            profile = source_profile(source_path)
            expected_type_id = (SHADER_TYPE_IDS[native["type"]]
                                if native["type"] in SHADER_TYPE_IDS else 19)
            if (body.assets[index].type_id != expected_type_id or native_rows[index].get("type_id") != expected_type_id or
                    native_rows[index].get("name") != native["name"] or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    source_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [patch["sha256"] for patch in profile.get("patches", [])]):
                raise ValueError("shader/image source FF/body/walk identity changed; reload before saving")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (not walk_receipt.get("stream_trace_enabled") or
                    sha256_file(trace_path) != source_identity.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != source_identity.get("native_manifest_sha256")):
                raise ValueError("shader/image trace or manifest changed; reload before saving")
            trace_index = build_read_span_index(trace_path, manifest_path, len(body.data),
                                                selected_assets=None if body.assets[index].type_id == 12 else {index})
            trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("complete native trace has no selected shader/image")
            trace_asset.update(index=index, type_id=body.assets[index].type_id, name=native["name"])
            trace_asset["indexed_string_data_spans"] = trace_index["string_data_spans"]
            trace_asset["indexed_physical_spans"] = trace_index["_all_physical_spans"]
            if native["type"] in SHADER_TYPE_IDS:
                from workstation_asset_codecs import assemble_dxbc, DEFAULT_DXBC_TOOL
                import workstation_asset_codecs as codec_module
                layout = read_inline_shader(body.data, dict(native, index=index), trace_asset,
                                            body.source_sha256,
                                            trace_assets=trace_index["assets"])
                if source_identity.get("typed_layout") != dict(
                        root_archive_offset=layout["root_archive_offset"],
                        name_archive_offset=layout["name_archive_offset"],
                        child_archive_offset=layout["program_archive_offset"],
                        child_bytes=len(layout["program"]),
                        debug_name=layout["debug_name"],
                        debug_name_stream_location=layout["debug_name_stream_location"]):
                    raise ValueError("shader root/child ownership changed; reload before saving")
                tool = Path(os.environ.get("REPLAY_DXBC_TOOL", str(DEFAULT_DXBC_TOOL))).resolve(strict=True)
                tool_before = sha256_file(tool)
                codec_before = sha256_file(Path(codec_module.__file__))
                payload = assemble_dxbc(content, tool=tool, asset_name=native["name"])
                if sha256_file(tool) != tool_before or sha256_file(Path(codec_module.__file__)) != codec_before:
                    raise RuntimeError("DXBC assembler or codec changed during compilation")
                if len(payload) == len(layout["program"]):
                    _, replacement_receipt = replace_inline_shader(
                        body.data, dict(native, index=index), trace_asset, body.source_sha256, payload,
                        trace_assets=trace_index["assets"])
                else:
                    from workstation_variable_native_edits import apply_variable_native_edits
                    _, transaction = apply_variable_native_edits(body.data, [dict(
                        kind="shader", asset_row=dict(native, index=index),
                        trace_asset=trace_asset, trace_assets=trace_index["assets"], payload=payload)],
                        body_path=cache_path / decode_receipt["final_body_relative_path"],
                        journal_path=_native_walk_artifact(walk_receipt, "journal_relative_path"),
                        trace_path=trace_path, manifest_path=manifest_path,
                        replay_executable=self.replay_executable)
                    replacement_receipt = transaction
                status = "replay120-dxbc-assemble-pass"
                payload_format = "Replay inline DXBC shader child"
                compile_receipt = dict(
                    schema="replay120-dxbc-compile-receipt-v1", status=status,
                    asset_name=native["name"],
                    source=dict(sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                                utf8_bytes=len(content.encode("utf-8"))),
                    compiler=dict(path=str(tool), sha256=tool_before,
                                  codec_module_sha256=codec_before),
                    result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                                native_payload_bytes=len(payload), payload_contract="inline DXBC"),
                    replacement=replacement_receipt)
            else:
                from workstation_asset_codecs import (
                    import_png_to_replay_image_mips, import_dds_to_replay_image_resource,
                    DEFAULT_TEXCONV_TOOL)
                import workstation_asset_codecs as codec_module
                layout = read_resident_image(body.data, dict(native, index=index), trace_asset,
                                             body.source_sha256)
                dds_mode = isinstance(content, str) and content.startswith("data:application/octet-stream;base64,")
                if dds_mode:
                    dds = parse_image_dds_data_url(content)
                    out_width, out_height, out_depth, out_elements, out_format, out_mips, payload = \
                        import_dds_to_replay_image_resource(dds)
                    requested_mips = layout["level_count"]
                else:
                    png, requested_mips = parse_image_data_url(content, layout["level_count"])
                expected_layout = source_identity.get("typed_layout", {})
                _validate_resident_image_typed_layout(expected_layout, layout)
                width, height, depth, elements = layout["dimensions"]
                codec_before = sha256_file(Path(codec_module.__file__))
                if dds_mode:
                    # Pin the same configured DirectXTex tool identity as the
                    # existing image editor even though strict DDS import
                    # itself needs no transcoder.
                    tool = Path(os.environ.get("REPLAY_TEXCONV", str(DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                    tool_before = sha256_file(tool)
                    if (out_depth, out_elements) != (depth, elements):
                        raise ValueError("DDS import changed the native resident depth or array count")
                else:
                    if depth != 1 or elements != 1:
                        raise UnsupportedAssetGraphError("complex resident images require the whole-resource DDS editor")
                    tool = Path(os.environ.get("REPLAY_TEXCONV", str(DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                    tool_before = sha256_file(tool)
                    out_width, out_height, out_format, out_mips, payload = import_png_to_replay_image_mips(
                        png, layout["format"], requested_mips, tool=tool)
                if (sha256_file(tool) != tool_before or
                        sha256_file(Path(codec_module.__file__)) != codec_before):
                    raise RuntimeError("image encoder or codec changed during conversion")
                if (out_format != layout["format"] or out_mips != layout["level_count"] or
                        (out_width, out_height) != (width, height)):
                    raise ValueError("PNG conversion changed the Replay format or requested mip count")
                if len(payload) == len(layout["payload"]):
                    _, replacement_receipt = replace_resident_image(
                        body.data, dict(native, index=index), trace_asset, body.source_sha256, payload)
                elif dds_mode:
                    raise ValueError("DDS import changed the native resident payload extent")
                else:
                    from workstation_variable_native_edits import apply_variable_native_edits
                    _, transaction = apply_variable_native_edits(body.data, [dict(
                        kind="image", asset_row=dict(native, index=index), trace_asset=trace_asset,
                        width=out_width, height=out_height, mip_count=out_mips, payload=payload)],
                        body_path=cache_path / decode_receipt["final_body_relative_path"],
                        journal_path=_native_walk_artifact(walk_receipt, "journal_relative_path"),
                        trace_path=trace_path, manifest_path=manifest_path,
                        replay_executable=self.replay_executable)
                    replacement_receipt = transaction
                status = "replay120-resident-image-encode-pass"
                payload_format = "Replay resident inline image pixels"
                compile_receipt = dict(
                    schema="replay120-resident-image-compile-receipt-v1", status=status,
                    asset_name=native["name"],
                    source=dict(sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                                utf8_bytes=len(content.encode("utf-8"))),
                    compiler=dict(path=str(tool), sha256=tool_before,
                                  codec_module_sha256=codec_before),
                    input=dict(format=layout["format"], dimensions=list(layout["dimensions"]),
                               level_count=layout["level_count"],
                               source_container="DDS/DX10 resident resource" if dds_mode else "PNG"),
                    result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                                native_payload_bytes=len(payload), payload_contract="inline resident image mip chain",
                                width=out_width, height=out_height, mip_count=out_mips,
                                depth=out_depth if dds_mode else depth,
                                elements=out_elements if dds_mode else elements,
                                variable_extent=len(payload) != len(layout["payload"])),
                    replacement=replacement_receipt)
        elif native["type"] == "luafile":
            import workstation_asset_codecs as codec_module
            from workstation_lua_compile import compile_luajit_source_with_receipt
            profile_name = "replay120_lua_native"
            profile_path = self._lua_compiler_profile_path(self.lua_acts_path, profile_name)
            walk_receipt, _ = _read_native_rows(cache_path, body, require_trace=True)
            if (body.assets[index].type_id != 62 or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") !=
                    walk_receipt.get("identity", {}).get("source_sha256")):
                raise ValueError("LuaFile source body/native walk identity changed; reload before saving")
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            current_source = source_profile(source_path)
            if (current_source.get("sha256") != walk_receipt["identity"].get("source_sha256") or
                    [row["sha256"] for row in current_source.get("patches", [])] !=
                    walk_receipt["identity"].get("patch_sha256s")):
                raise ValueError("LuaFile source FF/FP/FC chain changed since extraction")
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (sha256_file(trace_path) != source_identity.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != source_identity.get("native_manifest_sha256") or
                    not walk_receipt.get("stream_trace_enabled")):
                raise ValueError("LuaFile trace/manifest identity changed; reload before saving")
            codec_before = sha256_file(Path(codec_module.__file__))
            acts_before = acts_tool_identity(self.lua_acts_path)
            replay_before = sha256_file(self.replay_executable)
            profile_before = sha256_file(profile_path)
            from workstation_luafile import luafile_compiler_input_name
            compiler_input_name = luafile_compiler_input_name(native["name"])
            payload, compile_receipt = compile_luajit_source_with_receipt(
                content, acts_exe=self.lua_acts_path,
                replay_executable=self.replay_executable,
                profile_path=profile_path,
                profile_name=profile_name,
                asset_name=compiler_input_name)
            compile_receipt["asset_name"] = native["name"]
            compile_receipt["compiler_input_name"] = compiler_input_name
            compiler = compile_receipt["compiler"]
            compiler.update(tool_identity=acts_before,
                            codec_module_path=str(Path(codec_module.__file__).resolve()),
                            codec_module_sha256=codec_before)
            if (acts_tool_identity(self.lua_acts_path) != acts_before or
                    sha256_file(self.replay_executable) != replay_before or
                    sha256_file(profile_path) != profile_before or
                    sha256_file(Path(codec_module.__file__)) != codec_before or
                    compiler.get("sha256") != acts_before.get("executable_sha256") or
                    compiler.get("profile_sha256") != profile_before or
                    compiler.get("replay_executable_sha256") != replay_before):
                raise RuntimeError("Lua compiler, profile, Replay image, or codec changed during compilation")
            payload_format = "Replay LuaJIT v2 native LuaFile child"
        elif native["type"] == "scriptfile":
            import workstation_asset_codecs as codec_module
            from workstation_asset_codecs import compile_scriptfile
            walk_receipt, _ = _read_native_rows(cache_path, body, require_trace=True)
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            current_source = source_profile(source_path)
            if (body.assets[index].type_id != 52 or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != current_source.get("sha256") or
                    source_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [row["sha256"] for row in current_source.get("patches", [])]):
                raise ValueError("ScriptFile source body/FF/walk/trace identity changed; reload before saving")
            tool = DEFAULT_GSC_TOOL.resolve(strict=True)
            tool_before = acts_tool_identity(tool)
            codec_before = sha256_file(Path(codec_module.__file__))
            payload = compile_scriptfile(content, tool, str(index))
            tool_after = acts_tool_identity(tool)
            codec_after = sha256_file(Path(codec_module.__file__))
            if tool_after != tool_before or codec_after != codec_before:
                raise RuntimeError("GSC compiler, dependencies, or codec changed during compilation")
            compile_receipt = dict(
                schema="replay120-gsc-compile-receipt-v1",
                status="gsc-tool-native-payload-pass",
                asset_name=native["name"],
                source=dict(sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                            utf8_bytes=len(content.encode("utf-8"))),
                compiler=dict(path=str(tool), tool_identity=tool_before,
                              codec_module_path=str(Path(codec_module.__file__).resolve()),
                              codec_module_sha256=codec_before),
                result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                            native_payload_bytes=len(payload),
                            payload_contract="Replay ScriptFile GSCBIN after Replay local-reference scaling"))
            payload_format = "gsc-tool gscbin"
        elif native["type"] == "stringtable":
            import workstation_asset_codecs as codec_module
            import workstation_stringtable as writer_module
            parsed_rows = list(csv.reader(io.StringIO(content, newline="")))
            from workstation_asset_codecs import encode_stringtable_sections
            walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
            source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
            current_source = source_profile(source_path)
            if (body.assets[index].type_id != 54 or native_rows[index].get("type_id") != 54 or
                    native_rows[index].get("name") != native["name"] or
                    source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != current_source.get("sha256") or
                    source_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                    walk_receipt.get("identity", {}).get("patch_sha256s") !=
                    [patch["sha256"] for patch in current_source.get("patches", [])]):
                raise ValueError("StringTable source body/FF/native-trace identity changed; reload before saving")
            if not walk_receipt.get("stream_trace_enabled"):
                raise UnsupportedAssetGraphError("StringTable editing requires a complete native stream trace")
            from workstation_stringtable import inspect_stringtable
            trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
            if (sha256_file(trace_path) != source_identity.get("stream_trace_sha256") or
                    sha256_file(manifest_path) != source_identity.get("native_manifest_sha256")):
                raise ValueError("StringTable source trace or manifest changed; reload before saving")
            original_root = source_identity.get("root_span", {})
            original_record = source_identity.get("record_span", {})
            export_root, export_index = _export_native_type(
                source_path, zone_id, body, cache_path, walk_receipt, native_rows,
                54, "stringtable", self.acts_path, self.replay_executable)
            original_item = next((entry for entry in export_index["items"]
                                 if entry.get("asset_index") == index), None)
            if original_item is None:
                raise ValueError("native StringTable export is missing its XAsset row")
            original_csv = (export_root / original_item["payload_relative_path"]).read_bytes()
            original_rows = list(csv.reader(io.StringIO(original_csv.decode("utf-8-sig"), newline="")))
            from workstation_trace_index import build_read_span_index
            from workstation_stringtable import validate_complete_stream5_allocations
            trace_index = build_read_span_index(trace_path, manifest_path, len(body.data))
            stream5_allocation_context = validate_complete_stream5_allocations(trace_index)
            omnvar_proof = None
            if native["name"].replace("\\", "/").casefold() == "omnvars/mp/omnvars.csv":
                omnvar_proof, trace_asset = _prepare_omnvar_mp_source_proof(
                    source=source_path, zone_id=zone_id, body=body, cache_path=cache_path,
                    walk_receipt=walk_receipt, native_rows=native_rows, root_index=index,
                    root_name=native["name"], original_rows=original_rows,
                    edited_rows=parsed_rows, export_root=export_root,
                    export_index=export_index, trace_path=trace_path,
                    manifest_path=manifest_path)
            else:
                trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
                if trace_asset is None:
                    raise ValueError("complete native trace does not contain this StringTable")
                trace_asset.update(xasset_index=index, type_id=54, name=native["name"])
            layout, _ = inspect_stringtable(
                body.data, index, native["name"], trace_asset, original_rows,
                expected_body_sha256=body.source_sha256,
                global_string_data_spans=trace_index.get("string_data_spans", []))
            if (original_root.get("archive_offset") != layout.root_archive_offset or
                    original_record.get("archive_offset") != layout.root_archive_offset or
                    original_record.get("sha256") != layout.source_record_sha256):
                raise ValueError("StringTable source root/record spans changed since extraction")
            codec_before = sha256_file(Path(codec_module.__file__))
            writer_before = sha256_file(Path(writer_module.__file__))
            sections = encode_stringtable_sections(native["name"], parsed_rows)
            payload_format = "Replay StringTable typed-section-packet"
            payload = json.dumps(dict(schema=1, kind="stringtable-sections",
                                      name=sections["name"], rows=sections["rows"],
                                      columns=sections["columns"],
                                      header_base64=base64.b64encode(sections["header"]).decode("ascii"),
                                      cells_base64=base64.b64encode(sections["cells"]).decode("ascii"),
                                      hashes_base64=base64.b64encode(sections["hashes"]).decode("ascii"),
                                      dictionary=sections["dictionary"]),
                                 sort_keys=True, separators=(",", ":")).encode("utf-8")
            compile_receipt = dict(
                schema="replay120-stringtable-compile-receipt-v1",
                status="replay120-stringtable-encode-pass",
                asset_name=native["name"],
                source=dict(sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                            utf8_bytes=len(content.encode("utf-8"))),
                compiler=dict(codec_module_path=str(Path(codec_module.__file__).resolve()),
                              codec_module_sha256=codec_before,
                              writer_module_path=str(Path(writer_module.__file__).resolve()),
                              writer_module_sha256=writer_before),
                input=dict(rows=sections["rows"], columns=sections["columns"],
                           dictionary_count=len(sections["dictionary"])),
                result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                            native_payload_bytes=len(payload),
                            payload_contract="Replay StringTable semantic row-major CSV typed sections"))
            if omnvar_proof is not None:
                compile_receipt["omnvar_mp_validation"] = omnvar_proof
            if (sha256_file(Path(codec_module.__file__)) != codec_before or
                    sha256_file(Path(writer_module.__file__)) != writer_before):
                raise RuntimeError("StringTable codec or writer changed during staging")
            if omnvar_proof is not None:
                if not _omnvar_helper_modules_match(omnvar_proof.get("modules")):
                    raise RuntimeError("Omnvar validator, include resolver, StringTable, codec or trace-index helper changed during staging")
        else:
            raise UnsupportedAssetGraphError("no semantic payload writer is registered for this asset type")
        # Converters may run out of process. Recheck the exact native inputs
        # before publishing, even when only the compiler was stale on entry.
        # A recompile is not permission to rebase preserved edits onto another
        # FF chain, decoded body, asset journal, or pointer-ownership trace.
        trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
        current_cache, current_decode = self._validated_zone_receipt(zone_id)
        current_profile = source_profile(source_path)
        if (current_cache != cache_path or current_decode != decode_receipt or
                sha256_file(cache_path / decode_receipt["final_body_relative_path"]) != body.source_sha256 or
                current_profile.get("sha256") != source_identity.get("source_fastfile_sha256") or
                [patch["sha256"] for patch in current_profile.get("patches", [])] !=
                walk_receipt.get("identity", {}).get("patch_sha256s") or
                sha256_file(trace_path) != source_identity.get("stream_trace_sha256") or
                sha256_file(manifest_path) != source_identity.get("native_manifest_sha256")):
            raise ValueError("Native asset source inputs changed during compilation; reload before saving")
        content_revision = hashlib.sha256(content.encode("utf-8")).hexdigest()
        pending_dir = cache_path / "pending-edits" / str(index)
        current_path = pending_dir / "current.json"
        if current_path.exists():
            if expected_pending is None:
                raise ValueError("Asset revision changed during compilation; reload before saving")
            _, latest, _ = _validate_pending_snapshot(cache_path, index, asset_id, body)
            if latest != expected_pending:
                raise ValueError("Asset revision changed during compilation; reload before saving")
        elif expected_pending is not None:
            raise ValueError("Asset edit was removed during compilation; reload before saving")
        pending_dir.mkdir(parents=True, exist_ok=True)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        payload_path = pending_dir / f"{content_revision}.{payload_sha256}.payload"
        if payload_path.exists() and sha256_file(payload_path) != payload_sha256:
            raise ValueError("staged payload path collides with different immutable bytes")
        payload_path.write_bytes(payload)
        row = dict(schema=3,
                   asset_id=asset_id, zone_id=zone_id, xasset_index=index,
                   type_id=body.assets[index].type_id, type=native["type"], name=native["name"],
                   content=content, language=current["language"],
                   content_sha256=content_revision, revision=None,
                   source_body_sha256=body.source_sha256,
                   original_payload_sha256=(current["original_payload_sha256"]
                                             if "original_payload_sha256" in current
                                             else current["payload_sha256"]),
                   edited_payload_sha256=payload_sha256,
                   edited_payload_bytes=len(payload), edited_payload_format=payload_format,
                   edited_payload_path=payload_path.name, archive_writable=False,
                   pending_reason=("LuaFile edits require an unchanged source FF/patch chain and complete native trace"
                                   if native["type"] == "luafile" else
                                   "Localize values may change UTF-8 length; key/name and XAsset rows remain immutable"
                                   if native["type"] == "localize" else
                                   "StringTable edits require one type-54 table and a complete native trace"
                                   if native["type"] == "stringtable" else
                                    "SoundBank aliases use trace-owned field writes and a full-zone native reread"
                                    if native["type"] == "soundbank" else
                                   "shader/image edits require trace-owned child serialization and full-zone native reread"
                                   if native["type"] in (*SHADER_TYPE_IDS, "image") else
                                   "native zone writer/root-child relocation schedule unavailable"))
        if compile_receipt is not None:
            canonical_receipt = json.dumps(compile_receipt, sort_keys=True,
                                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            row["compiler_receipt"] = compile_receipt
            row["compiler_receipt_sha256"] = hashlib.sha256(canonical_receipt).hexdigest()
            row["native_source_identity"] = dict(
                body_sha256=source_identity["body_sha256"],
                source_fastfile_sha256=source_identity["source_fastfile_sha256"],
                native_walk_key=source_identity["native_walk_key"],
                native_manifest_sha256=source_identity["native_manifest_sha256"],
                stream_trace_sha256=source_identity["stream_trace_sha256"],
                xasset_index=index,
                root_span=source_identity.get("root_span"),
                record_span=source_identity.get("record_span"),
                typed_layout=source_identity.get("typed_layout"))
        new_revision = _edit_snapshot_revision(row)
        row["revision"] = new_revision
        snapshot_path = pending_dir / f"{new_revision}.json"
        if snapshot_path.exists():
            prior_snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            if prior_snapshot != row:
                raise ValueError("immutable edit snapshot digest collides with different staged data")
        snapshot_tmp = snapshot_path.with_suffix(".tmp")
        snapshot_tmp.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        snapshot_tmp.replace(snapshot_path)
        temporary = current_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        temporary.replace(current_path)
        return dict(asset_id=asset_id, revision=new_revision, status="semantic-edit-staged",
                    content_sha256=content_revision,
                    editable=True, archive_writable=False,
                    edited_payload_sha256=row["edited_payload_sha256"],
                    edited_payload_bytes=row["edited_payload_bytes"],
                    edited_payload_format=payload_format, pending_path=str(current_path),
                    compiler_receipt_sha256=row.get("compiler_receipt_sha256"),
                    native_source_identity=row.get("native_source_identity"),
                    blocked_reason=row["pending_reason"])

    def _request_asset_snapshot(self, zone_id: str, snapshots: dict, *,
                                require_trace: bool = True) -> AssetRequestSnapshot:
        snapshot = snapshots.get(zone_id)
        if snapshot is not None:
            self._require_asset_request_snapshot(snapshot, zone_id)
            if (not require_trace or
                    (snapshot.native_walk and snapshot.native_walk.get("stream_trace_enabled") and
                     snapshot.native_rows is not None)):
                return snapshot
        snapshot = self._validated_asset_snapshot(zone_id, require_trace=require_trace)
        snapshots[zone_id] = snapshot
        return snapshot

    def list_pending_edits(self, zone_id: str | None = None, query: str = "",
                           offset: int = 0, limit: int = 100, *, _snapshots=None) -> dict:
        """List hash-validated staged edits; these are not yet packaged into an FF."""
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        zones = [zone_id] if zone_id is not None else None
        snapshots = {} if _snapshots is None else _snapshots
        current_paths = []
        scoped_cache_path = None
        if zones:
            if not re.fullmatch(r"[0-9a-f]{64}", zone_id):
                raise ValueError("zone_id must be a content-addressed decode cache key")
            # Resolve the requested identity through the same validated zone
            # receipt used by readers.  Scanning every sibling zone under a
            # source stem can leak another zone's pending operations, and a
            # glob rooted at the zone directory is one level shallower than
            # the unscoped cache layout.
            cache_path, _ = self._validated_zone_receipt(zone_id)
            scoped_cache_path = cache_path.resolve(strict=True)
            current_paths = list((cache_path / "pending-edits").glob("*/current.json"))
        else:
            roots = list(self.cache_root.iterdir()) if self.cache_root.is_dir() else []
            for root in roots:
                if not root.is_dir():
                    continue
                for current_path in root.glob("*/pending-edits/*/current.json"):
                    current_paths.append(current_path)
        items = []
        needle = query.casefold()
        for current_path in current_paths:
            row = {}
            try:
                row = json.loads(current_path.read_text(encoding="utf-8"))
                zone = row["zone_id"]
                row_cache = current_path.parent.parent.parent.resolve(strict=True)
                if scoped_cache_path is not None:
                    if zone != zone_id:
                        raise ValueError("pending edit zone identity differs from the requested zone")
                    expected_cache = scoped_cache_path
                else:
                    expected_cache, _ = self._validated_zone_receipt(zone)
                    expected_cache = expected_cache.resolve(strict=True)
                if (row_cache != expected_cache or
                        not current_path.resolve(strict=True).is_relative_to(expected_cache)):
                    raise ValueError("pending edit path is outside its validated zone cache")
                needs_native_snapshot = (row.get('schema') == 4 or row.get('type') in (
                    *SHADER_TYPE_IDS, "image", "scriptfile", "luafile", "stringtable", "localize", "rawfile"))
                if needs_native_snapshot:
                    snapshot = self._request_asset_snapshot(zone, snapshots, require_trace=True)
                    cache_path, decode_receipt, body = (snapshot.cache_path,
                        snapshot.decode_receipt, snapshot.body)
                else:
                    snapshot = None
                    cache_path, decode_receipt = self._validated_zone_receipt(zone)
                    body = ZoneBody.parse((cache_path / decode_receipt["final_body_relative_path"]).read_bytes())
                if row.get('schema') == 4:
                    from workstation_asset_operations import validate_operation
                    if row.get('type_id') == 41:
                        from workstation_localize_crud import _inputs
                        identity = _inputs(self, zone, _snapshot=snapshot)[-1]
                    elif row.get('type_id') == 62:
                        from workstation_luafile_crud import _workspace_inputs
                        identity = _workspace_inputs(self, zone, _snapshot=snapshot)[-1]
                    elif row.get('type_id') == 52:
                        from workstation_scriptfile_crud import _operation_cache, _workspace_inputs
                        inputs = _workspace_inputs(self, zone, _snapshot=snapshot)
                        identity = inputs[-2]
                        cache_path = _operation_cache(self, zone, cache_path)
                    elif row.get('type_id') == 54:
                        from workstation_stringtable_crud import _workspace_inputs
                        identity = _workspace_inputs(self, zone, _snapshot=snapshot)[-1]
                    elif row.get('type_id') == 51:
                        from workstation_rawfile_crud import _inputs
                        identity = _inputs(self, zone, _snapshot=snapshot)[-2]
                    elif row.get('type_id') in SHADER_TYPES:
                        from workstation_shader_crud import _inputs
                        identity = _inputs(self, zone, _snapshot=snapshot)[-1]
                    elif row.get('type_id') == 19:
                        from workstation_image_crud import _source
                        identity = _source(self, zone, snapshot)[-1]
                    else:
                        raise ValueError('unsupported staged row-operation type')
                    row, payload = validate_operation(cache_path, current_path, identity)
                    if row.get('type_id') == 62:
                        from workstation_luafile_crud import operations as luafile_operations
                        checked = [item for item in luafile_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('LuaFile operation compiler/source identity is stale')
                    elif row.get('type_id') == 52:
                        from workstation_scriptfile_crud import operations as scriptfile_operations
                        checked = [item for item in scriptfile_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('ScriptFile operation compiler/source identity is stale')
                    elif row.get('type_id') == 54:
                        from workstation_stringtable_crud import operations as stringtable_operations
                        checked = [item for item in stringtable_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('StringTable operation source/writer identity is stale')
                    elif row.get('type_id') == 51:
                        from workstation_rawfile_crud import operations as rawfile_operations
                        checked = [item for item in rawfile_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('RawFile operation source/writer identity is stale')
                    elif row.get('type_id') in SHADER_TYPES:
                        from workstation_shader_crud import operations as shader_operations
                        checked = [item for item in shader_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('Shader operation source/writer identity is stale')
                    elif row.get('type_id') == 19:
                        from workstation_image_crud import operations as image_operations
                        checked = [item for item in image_operations(self, zone, _snapshot=snapshot)
                                   if item.get('operation_id') == row.get('operation_id')]
                        if len(checked) != 1 or checked[0].get('revision') != row.get('revision'):
                            raise ValueError('resident image operation source/writer identity is stale')
                    if not needle or needle in f"{zone} {row['type']} {row['name']} {row['operation']}".casefold():
                        items.append(dict(asset_id=row['asset_id'], zone_id=zone, index=row['index'],
                                          revision=row['revision'], type=row['type'], type_id=row['type_id'],
                                          name=row['name'], operation=row['operation'], operation_id=row['operation_id'],
                                          content_sha256=row['content_sha256'], edited_payload_sha256=row['edited_payload_sha256'],
                                          pending_path=str(current_path), status='staged',
                                          edited_payload_bytes=len(payload)))
                    continue
                index = int(row["xasset_index"])
                if row.get("schema") not in (1, 2, 3) or index < 0 or index >= len(body.assets):
                    raise ValueError("pending edit index/schema is invalid")
                _, row, _ = _validate_pending_snapshot(cache_path, index, row.get("asset_id"), body)
                if row.get("source_body_sha256") != body.source_sha256:
                    raise ValueError("pending edit source body hash does not match its zone")
                if (index >= len(body.assets) or
                        body.assets[index].type_id != row.get("type_id")):
                    raise ValueError("pending edit type/index differs from the XAsset table")
                payload_rel = Path(row.get("edited_payload_path", ""))
                if payload_rel.name != str(payload_rel) or payload_rel.is_absolute():
                    raise ValueError("pending edit payload path is invalid")
                payload_path = current_path.parent / payload_rel
                payload_hash = sha256_file(payload_path) if payload_path.is_file() else None
                if payload_hash != row.get("edited_payload_sha256"):
                    raise ValueError("pending edit payload hash mismatch")
                compiler_receipt = row.get("compiler_receipt")
                if ((row.get("type_id") in SHADER_TYPES and row.get("type") == SHADER_TYPE_NAMES[row.get("type_id")]) or
                        (row.get("type_id") == 19 and row.get("type") == "image")) and not isinstance(compiler_receipt, dict):
                    raise ValueError("pending shader/image edit has no immutable conversion receipt")
                if compiler_receipt is not None:
                    canonical = json.dumps(compiler_receipt, sort_keys=True,
                                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    if hashlib.sha256(canonical).hexdigest() != row.get("compiler_receipt_sha256"):
                        raise ValueError("pending compiler receipt hash mismatch")
                    expected_status = {14: "replay120-dxbc-assemble-pass",
                                       15: "replay120-dxbc-assemble-pass",
                                       16: "replay120-dxbc-assemble-pass",
                                       17: "replay120-dxbc-assemble-pass",
                                       19: "replay120-resident-image-encode-pass",
                                       52: "gsc-tool-native-payload-pass",
                                       54: "replay120-stringtable-encode-pass",
                                       62: "target-lua-loadx-reload-pass",
                                       41: "replay120-localize-value-encode-pass",
                                       51: "replay120-rawfile-encode-pass",
                                       21: "replay120-soundbank-alias-scalars-pass"}.get(row.get("type_id"))
                    if (compiler_receipt.get("result", {}).get("native_payload_sha256") != payload_hash or
                            (expected_status is not None and compiler_receipt.get("status") != expected_status) or
                            compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(row) or
                            compiler_receipt.get("asset_name") != row.get("name")):
                        raise ValueError("pending native compiler receipt does not describe the staged payload/source")
                    if row.get("type_id") == 52:
                        compiler = compiler_receipt.get("compiler", {})
                        tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                        if compiler.get("path") != str(tool) or compiler.get("tool_identity") != acts_tool_identity(tool):
                            raise ValueError("pending GSC compiler tool identity is stale")
                snapshot_path = current_path.parent / f"{row.get('revision')}.json"
                if (row.get("asset_id") != f"{zone}:{index}" or
                        not re.fullmatch(r"[0-9a-f]{64}", str(row.get("revision", ""))) or
                        not snapshot_path.is_file() or
                        json.loads(snapshot_path.read_text(encoding="utf-8")) != row):
                    raise ValueError("pending edit identity/revision is invalid")
                check_source_identity = (row.get("type") in (*SHADER_TYPE_IDS, "image", "luafile", "stringtable", "localize", "rawfile") or
                                         (row.get("type") == "scriptfile" and compiler_receipt is not None))
                if check_source_identity:
                    if snapshot is None:
                        snapshot = self._request_asset_snapshot(zone, snapshots, require_trace=True)
                        cache_path, decode_receipt, body = (snapshot.cache_path,
                            snapshot.decode_receipt, snapshot.body)
                    walk_receipt, native_rows = snapshot.native_walk, snapshot.native_rows
                    source_path = Path(decode_receipt["source"]["path"]).resolve(strict=True)
                    stale_reason = self._staged_asset_staleness(
                        row, body, index, native_rows[index], walk_receipt, source_path,
                        _snapshot=snapshot)
                    if stale_reason:
                        result = dict(asset_id=row["asset_id"], zone_id=zone, index=index,
                                      type=row["type"], type_id=row["type_id"], name=row["name"],
                                      revision=row["revision"], content_sha256=_pending_content_sha(row),
                                      edited_payload_sha256=payload_hash,
                                      edited_payload_bytes=payload_path.stat().st_size,
                                      pending_path=str(current_path), archive_writable=False,
                                      compiler_receipt_sha256=row.get("compiler_receipt_sha256"),
                                      native_source_identity=row.get("native_source_identity"),
                                      status="stale", error=stale_reason)
                        if not needle or needle in f"{zone} {index} {row['type']} {row['name']}".casefold():
                            items.append(result)
                        continue
                    profile = snapshot.source_profile
                    native_identity = row.get("native_source_identity", {})
                    expected_type_id = {**SHADER_TYPE_IDS, "image": 19,
                                        "scriptfile": 52, "stringtable": 54, "luafile": 62,
                                        "localize": 41, "rawfile": 51}.get(row.get("type"))
                    if (expected_type_id is None or index >= len(native_rows) or
                            native_rows[index].get("type_id") != expected_type_id or
                            body.assets[index].type_id != expected_type_id or
                            native_rows[index].get("name") != row.get("name") or
                            native_identity.get("body_sha256") != body.source_sha256 or
                            native_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                            native_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                            native_identity.get("source_fastfile_sha256") != walk_receipt.get("identity", {}).get("source_sha256") or
                            native_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                            native_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("pending asset source body/FF/walk/trace identity is stale")
                    if row.get("type") in (*SHADER_TYPE_IDS, "image"):
                        from workstation_asset_codecs import DEFAULT_DXBC_TOOL, DEFAULT_TEXCONV_TOOL
                        import workstation_asset_codecs as codec_module
                        tool = Path(os.environ.get(
                            "REPLAY_DXBC_TOOL" if row["type_id"] in SHADER_TYPES else "REPLAY_TEXCONV",
                            str(DEFAULT_DXBC_TOOL if row["type_id"] in SHADER_TYPES else DEFAULT_TEXCONV_TOOL))).resolve(strict=True)
                        compiler = compiler_receipt.get("compiler", {})
                        if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                                compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                            raise ValueError("pending shader/image editor tool identity is stale")
                result = dict(asset_id=row["asset_id"], zone_id=zone, index=index,
                              type=row["type"], name=row["name"], revision=row["revision"],
                              edited_payload_sha256=payload_hash,
                              edited_payload_bytes=payload_path.stat().st_size,
                              pending_path=str(current_path), archive_writable=False,
                              compiler_receipt_sha256=row.get("compiler_receipt_sha256"),
                              native_source_identity=row.get("native_source_identity"))
                if not needle or needle in f"{zone} {index} {row['type']} {row['name']}".casefold():
                    items.append(result)
            except (KeyError, TypeError, ValueError, OSError) as error:
                stale_item = None
                if isinstance(row, dict) and row.get("type") in (
                        *SHADER_TYPE_IDS, "image", "scriptfile", "luafile", "stringtable", "localize", "rawfile"):
                    try:
                        stale_zone = row["zone_id"]
                        stale_cache, stale_decode = self._validated_zone_receipt(stale_zone)
                        stale_body = ZoneBody.parse((stale_cache / stale_decode["final_body_relative_path"]).read_bytes())
                        stale_index = int(row["xasset_index"])
                        if 0 <= stale_index < len(stale_body.assets):
                            _, intact, intact_payload = _validate_pending_snapshot(
                                stale_cache, stale_index, row["asset_id"], stale_body)
                            stale_item = dict(asset_id=intact["asset_id"], zone_id=stale_zone,
                                              index=stale_index, type=intact["type"],
                                              type_id=intact["type_id"], name=intact["name"],
                                              revision=intact["revision"],
                                              content_sha256=_pending_content_sha(intact),
                                              edited_payload_sha256=intact["edited_payload_sha256"],
                                              edited_payload_bytes=intact_payload.stat().st_size,
                                              pending_path=str(current_path), archive_writable=False,
                                              compiler_receipt_sha256=intact.get("compiler_receipt_sha256"),
                                              native_source_identity=intact.get("native_source_identity"),
                                              status="stale", error=str(error))
                    except (KeyError, TypeError, ValueError, OSError):
                        stale_item = None
                if stale_item is not None:
                    items.append(stale_item)
                    continue
                items.append(dict(asset_id=row.get("asset_id") if isinstance(row, dict) else None,
                                  zone_id=row.get("zone_id") if isinstance(row, dict) else None,
                                  status="invalid", error=str(error), pending_path=str(current_path)))
        items.sort(key=lambda item: (item.get("zone_id") or "", item.get("index") if isinstance(item.get("index"), int) else -1,
                                     item.get('operation_id', '')))
        return dict(total=len(items), offset=offset, limit=limit, items=items[offset:offset + limit])

    def discard_asset_edit(self, asset_id: str, revision: str) -> dict:
        """Remove the current staged revision only when the caller's revision is current."""
        zone_id, separator, index_text = asset_id.rpartition(":")
        typed_new = re.fullmatch(r'new-(19)-([0-9a-f]{32})', index_text) if separator else None
        if separator and re.fullmatch(r'new-(?:(?:12|14|15|16|17|19)-)?[0-9a-f]{32}|[0-9]+', index_text):
            cache, _ = self._validated_zone_receipt(zone_id)
            operation_ids = ([{19: 'op-a-i-'}.get(int(typed_new.group(1)), 'op-a-') + typed_new.group(2)]
                             if typed_new else ['op-a-' + index_text.removeprefix('new-'),
                              'op-a-l-' + index_text.removeprefix('new-'),
                              'op-a-s-' + index_text.removeprefix('new-'),
                              'op-a-t-' + index_text.removeprefix('new-')]
                             if index_text.startswith('new-') else ['op-r-' + index_text])
            operation_id = next((candidate for candidate in operation_ids
                                 if (cache / 'pending-edits' / candidate / 'current.json').exists()), None)
            if operation_id is None and index_text.startswith('new-'):
                for candidate in (cache / 'pending-edits').glob('op-a-p-*/current.json'):
                    try:
                        pending = json.loads(candidate.read_text(encoding='utf-8'))
                        if pending.get('asset_id') == asset_id and pending.get('type_id') in (12, 14, 15, 16, 17):
                            if operation_id is not None:
                                raise ValueError('shader asset identity is ambiguous across pending operations')
                            operation_id = candidate.parent.name
                    except (OSError, json.JSONDecodeError):
                        continue
            if operation_id is not None:
                from workstation_asset_operations import discard_operation
                return dict(**discard_operation(cache, operation_id, revision), asset_id=asset_id,
                            status='staged-operation-discarded')
        if not separator or not index_text.isdecimal() or not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("discard requires an asset id and exact staged revision digest")
        cache_path, decode_receipt = self._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache_path / decode_receipt["final_body_relative_path"]).read_bytes())
        index = int(index_text)
        if index < 0 or index >= len(body.assets):
            raise AssetNotFoundError(asset_id)
        current_path, row, payload_path = _validate_pending_snapshot(cache_path, index, asset_id, body)
        if row.get("revision") != revision:
            raise ValueError("Asset revision conflict; reload before discarding")
        current_path.unlink()
        return dict(asset_id=asset_id, discarded_revision=revision,
                    status="staged-edit-discarded", retained_snapshot=str(current_path.parent / f"{revision}.json"),
                    edited_payload_path=str(payload_path),
                    source_body_sha256=row.get("source_body_sha256"), stale_source=bool(
                        row.get("source_body_sha256") != body.source_sha256))

    def plan_pending_edits(self, zone_id: str | None = None) -> dict:
        """Preflight every active staged revision without compiling or running ACTS.

        This checks pending-file hashes, source/cache identity, native trace
        availability, and the complete type-52 stream-6 ownership contract.
        It intentionally returns blocked zones instead of silently omitting
        stale cache ids or unsupported asset types.
        """
        snapshots = {}
        listed = self.list_pending_edits(zone_id, limit=1000, _snapshots=snapshots)
        all_items = list(listed["items"])
        for offset in range(1000, listed["total"], 1000):
            all_items.extend(self.list_pending_edits(zone_id, offset=offset, limit=1000,
                                                     _snapshots=snapshots)["items"])
        plan = self._plan_pending_rows(all_items, _snapshots=snapshots)
        # A plan is externally actionable, so recheck each pinned zone after all
        # family validators have completed. This is one end-of-request barrier,
        # not a cache carried into later requests.
        for snapshot in snapshots.values():
            self._assert_asset_snapshot_current(snapshot)
        return plan

    def _plan_pending_rows(self, all_items: Sequence[dict], *, _snapshots=None) -> dict:
        """Validate an explicit staged row set through the normal family gates.

        Sequential mixed transactions use this to preflight each family from
        one immutable source. No cache files or pending revisions are hidden or
        rewritten; publication still compares the complete queued edit set.
        """
        grouped: dict[str, list[dict]] = {}
        snapshots = {} if _snapshots is None else _snapshots
        invalid = []
        for row in all_items:
            candidate_zone = row.get("zone_id")
            if row.get("status") == "invalid" or not isinstance(candidate_zone, str):
                invalid.append(dict(asset_id=row.get("asset_id"), zone_id=candidate_zone,
                                    revision=row.get("revision"), reason=row.get("error", "invalid pending row")))
                continue
            grouped.setdefault(candidate_zone, []).append(row)
        zones = []
        for current_zone, rows in sorted(grouped.items()):
            edit_rows = [dict(asset_id=row.get("asset_id"), revision=row.get("revision"),
                              type=row.get("type"), name=row.get("name"),
                              **({"operation": row['operation'], "operation_id": row['operation_id']}
                                 if row.get('operation') else {})) for row in rows]
            entry = dict(zone_id=current_zone, relative_path=None, edits=edit_rows,
                         packageable=False, support=None, reason=None)
            try:
                if any(row.get("status") == "stale" for row in rows):
                    raise UnsupportedAssetGraphError("one or more staged edits have stale source/compiler identity")
                snapshot = self._request_asset_snapshot(current_zone, snapshots, require_trace=True)
                cache_path, decode_receipt = snapshot.cache_path, snapshot.decode_receipt
                source, profile = snapshot.source_path, snapshot.source_profile
                if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
                    raise UnsupportedAssetGraphError("source FC replacement semantics are not yet proven")
                try:
                    entry["relative_path"] = source.relative_to(self.game_root).as_posix()
                except ValueError:
                    raise ValueError("source fastfile is outside the configured shipped game root")
                body = snapshot.body
                walk_receipt, native_rows = snapshot.native_walk, snapshot.native_rows
                if not walk_receipt.get("stream_trace_enabled"):
                    raise UnsupportedAssetGraphError("native stream trace is unavailable")
                types = {row.get('type') for row in rows}
                mixed_types = ({'image', 'rawfile', 'soundbank', 'localize', 'luafile',
                                'scriptfile', 'stringtable'} | set(SHADER_TYPE_IDS))
                if len(types) > 1 and types <= mixed_types:
                    from workstation_mixed_asset_crud import plan_mixed_asset_crud
                    entry['proof'] = plan_mixed_asset_crud(self, current_zone, rows,
                                                           _snapshot=snapshot)
                    content_replacements = entry['proof'].get('mode') == 'content-replacements'
                    entry.update(packageable=True,
                                 support=('mixed-content-family-replacements-full-trace'
                                          if content_replacements else
                                          'mixed-image-localize-luafile-native-transaction'), reason=None)
                    zones.append(entry)
                    continue
                if any(row.get('operation') for row in rows):
                    if len(types) > 1:
                        raise UnsupportedAssetGraphError('row operation families lack a complete mixed native writer')
                    operation_types = {row.get('type') for row in rows if row.get('operation')}
                    if len(operation_types) != 1:
                        raise UnsupportedAssetGraphError('row operations cannot be mixed across asset types')
                    operation_type = next(iter(operation_types))
                    if operation_type == 'localize':
                        from workstation_localize_crud import plan_localize_crud
                        entry['proof'] = plan_localize_crud(self, current_zone, rows,
                                                            _snapshot=snapshot)
                        support = 'localize-sequential-native-row-operations'
                    elif operation_type == 'stringtable':
                        from workstation_stringtable_crud import plan_stringtable_crud
                        entry['proof'] = plan_stringtable_crud(self, current_zone, rows,
                                                               _snapshot=snapshot)
                        support = entry['proof']['support']
                    elif operation_type == 'rawfile':
                        from workstation_rawfile_crud import plan_rawfile_rows
                        entry['proof'] = plan_rawfile_rows(self, current_zone, rows,
                                                           _snapshot=snapshot)
                        support = 'rawfile-sequential-native-row-operations'
                    elif operation_type == 'luafile':
                        if not all(row.get('operation') and row.get('type') == 'luafile' for row in rows):
                            raise UnsupportedAssetGraphError('LuaFile row operations cannot be mixed with staged child replacements')
                        from workstation_luafile_crud import plan_luafile_crud
                        entry['proof'] = plan_luafile_crud(self, current_zone, rows,
                                                           _snapshot=snapshot)
                        support = 'luafile-sequential-native-row-operations'
                    elif operation_type == 'scriptfile':
                        if not all(row.get('operation') in ('append', 'remove') and row.get('type') == 'scriptfile' for row in rows):
                            raise UnsupportedAssetGraphError('ScriptFile supports one append or one exclusive final-row removal operation')
                        from workstation_scriptfile_crud import plan_scriptfile_crud
                        entry['proof'] = plan_scriptfile_crud(self, current_zone, rows,
                                                              _snapshot=snapshot)
                        support = entry['proof']['support']
                    elif operation_type in ('computeshader', 'vertexshader', 'hullshader', 'domainshader', 'pixelshader'):
                        if not all(row.get('operation') in ('append', 'remove') and row.get('type') == operation_type
                                   for row in rows):
                            raise UnsupportedAssetGraphError('shader row operations support one exact same-stage append or final-row removal only')
                        from workstation_shader_crud import plan_pixelshader_crud
                        entry['proof'] = plan_pixelshader_crud(self, current_zone, rows,
                                                               _snapshot=snapshot)
                        support = entry['proof']['support']
                    elif operation_type == 'image':
                        if not all(row.get('operation') in ('append', 'remove') and row.get('type') == 'image'
                                   for row in rows):
                            raise UnsupportedAssetGraphError('resident image supports one append or exclusive final-row removal')
                        from workstation_image_crud import plan_resident_image_crud
                        entry['proof'] = plan_resident_image_crud(self, current_zone, rows,
                                                                  _snapshot=snapshot)
                        support = entry['proof']['support']
                    else:
                        raise UnsupportedAssetGraphError('unsupported native row-operation type')
                    entry.update(packageable=True, support=support, reason=None)
                    zones.append(entry)
                    continue
                for staged in rows:
                    staged_index = staged.get("index")
                    if (not isinstance(staged_index, int) or not 0 <= staged_index < len(body.assets) or
                            staged_index >= len(native_rows)):
                        raise ValueError("staged edit index is outside the native XAsset table")
                    _current_path, staged_snapshot, _staged_payload = _validate_pending_snapshot(
                        cache_path, staged_index, staged.get("asset_id"), body)
                    if staged_snapshot.get("revision") != staged.get("revision"):
                        raise ValueError("staged compiler snapshot changed during preflight")
                    stale = self._staged_asset_staleness(
                        staged_snapshot, body, staged_index, native_rows[staged_index],
                        walk_receipt, source)
                    if stale:
                        raise ValueError(stale)
                types = {row.get("type") for row in rows}
                if types == {"soundbank"}:
                    import workstation_soundbank as soundbank_module
                    bank_snapshot = self._request_asset_snapshot(current_zone, snapshots, require_trace=True)
                    bank_changes = []
                    seen_indices = set()
                    for staged in rows:
                        index = staged.get("index")
                        if (not isinstance(index, int) or index in seen_indices or
                                not 0 <= index < len(body.assets) or body.assets[index].type_id != 21 or
                                native_rows[index].get("type") != "soundbank" or
                                native_rows[index].get("name") != staged.get("name")):
                            raise ValueError("staged SoundBank identity is invalid or duplicated")
                        seen_indices.add(index)
                        pending_path = Path(staged["pending_path"])
                        pending = json.loads(pending_path.read_text(encoding="utf-8"))
                        receipt = self._read_typed_soundbank(bank_snapshot, index, native_rows[index])
                        identity = self._soundbank_source_identity(bank_snapshot, index, receipt)
                        if pending.get("native_source_identity", {}).get("typed_layout") != identity["typed_layout"]:
                            raise ValueError("staged SoundBank alias layout differs from the current trace")
                        changes = soundbank_module.validate_soundbank_edit_document(pending["content"], receipt)
                        if not changes:
                            raise ValueError("staged SoundBank document contains no supported field changes")
                        compiler = pending.get("compiler_receipt", {}).get("compiler", {})
                        writer_path = Path(soundbank_module.__file__).resolve()
                        if (pending.get("compiler_receipt", {}).get("status") != "replay120-soundbank-alias-scalars-pass" or
                                compiler.get("writer_module_path") != str(writer_path) or
                                compiler.get("writer_module_sha256") != sha256_file(writer_path)):
                            raise ValueError("staged SoundBank writer receipt is stale")
                        bank_changes.append({"asset_id": staged["asset_id"], "revision": staged["revision"],
                                             "index": index, "name": staged["name"],
                                             "reader_identity_sha256": receipt["source_identity_sha256"],
                                             "changes": changes})
                    entry.update(packageable=True,
                                 support="same-extent-soundbank-alias-scalars",
                                 proof={"edit_count": len(bank_changes),
                                        "changed_aliases": sum(len(x["changes"]) for x in bank_changes),
                                        "changed_fields": sum(sum(len(a["fields"]) for a in x["changes"])
                                                               for x in bank_changes),
                                        "edits": bank_changes}, reason=None)
                    zones.append(entry)
                    continue
                if types == {"rawfile"}:
                    from workstation_rawfile import plan_rawfile_edits
                    _, relocation, raw_edits = plan_rawfile_edits(self, snapshot, rows)
                    entry.update(packageable=True, support="rawfile-full-trace-block5-relocation",
                        proof=dict(edit_count=len(raw_edits), relocation=relocation), reason=None)
                    zones.append(entry)
                    continue
                if types == {"scriptfile", "luafile"}:
                    if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("mixed native walk differs from the current source FF/patch chain")
                    script_indices = [i for i, asset in enumerate(body.assets) if asset.type_id == 52]
                    lua_indices = [row.get("index") for row in rows if row.get("type") == "luafile"]
                    if (any(not isinstance(i, int) or i < 0 or i >= len(body.assets) or
                            body.assets[i].type_id != 62 for i in lua_indices) or
                            any(native_rows[i].get("type_id") != 52 for i in script_indices)):
                        raise ValueError("mixed pending edit identities differ from typed native XAsset rows")
                    trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                    manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                    from workstation_trace_index import build_read_span_index
                    selected = set(script_indices) | set(lua_indices)
                    trace_index = build_read_span_index(trace_path, manifest_path,
                                                        len(body.data), selected_assets=selected)
                    traced = {asset["index"]: asset for asset in trace_index["assets"]}
                    script_edits, lua_edits = [], []
                    for row in rows:
                        index = row["index"]
                        pending_path = Path(row["pending_path"])
                        pending = json.loads(pending_path.read_text(encoding="utf-8"))
                        snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
                        if (not snapshot_path.is_file() or
                                pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                                pending.get("revision") != row.get("revision") or
                                pending.get("source_body_sha256") != body.source_sha256 or
                                hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                            raise ValueError("mixed edit revision differs from immutable source snapshot")
                        source_identity = pending.get("native_source_identity", {})
                        if (source_identity.get("body_sha256") != body.source_sha256 or
                                source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                                source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                                source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                                source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256")):
                            raise ValueError("mixed edit source identity differs from the current body/trace")
                        compiler_receipt = pending.get("compiler_receipt")
                        if not isinstance(compiler_receipt, dict):
                            raise ValueError("mixed edits require immutable compiler receipts for both asset types")
                        canonical = json.dumps(compiler_receipt, sort_keys=True,
                                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        expected_status = ("gsc-tool-native-payload-pass" if row["type"] == "scriptfile"
                                           else "target-lua-loadx-reload-pass")
                        if (hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256") or
                                compiler_receipt.get("status") != expected_status or
                                compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                                compiler_receipt.get("asset_name") != row.get("name")):
                            raise ValueError("mixed edit compiler receipt is invalid for its source revision")
                        payload_path = pending_path.parent / pending["edited_payload_path"]
                        payload = payload_path.read_bytes()
                        if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                                compiler_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
                            raise ValueError("mixed edit payload differs from compiler receipt")
                        if row["type"] == "scriptfile":
                            tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                            compiler = compiler_receipt.get("compiler", {})
                            if (compiler.get("path") != str(tool) or
                                    compiler.get("tool_identity") != acts_tool_identity(tool)):
                                raise ValueError("mixed GSC compiler identity changed")
                            script_edits.append(dict(xasset_index=index, name=row["name"], payload=payload))
                        else:
                            trace_asset = traced.get(index)
                            if trace_asset is None:
                                raise ValueError("mixed trace is missing a selected LuaFile")
                            trace_asset.update(xasset_index=index, type_id=62, name=row["name"])
                            lua_edits.append(dict(asset_index=index, asset_name=row["name"],
                                                  trace_asset=trace_asset, payload=payload))
                    from workstation_mixed_script_luafile import replace_mixed_script_luafile_batch
                    _, writer_proof = replace_mixed_script_luafile_batch(
                        body.data, script_edits, lua_edits, body.source_sha256,
                        str(trace_path), str(manifest_path), trace_index, native_rows,
                        list(profile["final_header"]["block_sizes"]))
                    entry["packageable"] = True
                    entry["reason"] = None
                    entry["support"] = "mixed-scriptfile-luafile-full-trace-relocation"
                    entry["proof"] = dict(native_walk_key=walk_receipt["walk_key"],
                                          native_manifest_sha256=walk_receipt["manifest_sha256"],
                                          stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                          xasset_count=len(body.assets), edit_count=len(rows),
                                          stream_reservation_sizes=writer_proof["stream_reservation_sizes"],
                                          writer=writer_proof)
                    zones.append(entry)
                    continue
                if types == {"localize"}:
                    if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("Localize native walk differs from current source FF/patch chain")
                    indices = [row.get("index") for row in rows]
                    if (len(set(indices)) != len(indices) or
                            any(not isinstance(i, int) or i < 0 or i >= len(body.assets) or
                                body.assets[i].type_id != 41 or native_rows[i].get("type_id") != 41 or
                                native_rows[i].get("type") != "localize"
                                for i in indices)):
                        raise ValueError("Localize batch identity differs from the native XAsset rows")
                    trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                    manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                    if (not walk_receipt.get("stream_trace_enabled") or
                            sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                            sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                        raise ValueError("Localize batch requires the unchanged complete native trace")
                    from workstation_trace_index import build_read_span_index
                    from workstation_localize import (inspect_localize_entry,
                                                      replace_localize_values_with_relocation)
                    traced_index = build_read_span_index(trace_path, manifest_path, len(body.data),
                                                         selected_assets=set(indices))
                    traced = {asset["index"]: asset for asset in traced_index["assets"]}
                    localize_edits = []
                    for planned in rows:
                        index = planned["index"]
                        pending_path = Path(planned["pending_path"])
                        pending = json.loads(pending_path.read_text(encoding="utf-8"))
                        snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
                        if (not snapshot_path.is_file() or
                                pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                                pending.get("schema") != 3 or
                                pending.get("revision") != planned.get("revision") or
                                pending.get("type") != "localize" or pending.get("type_id") != 41 or
                                pending.get("name") != planned.get("name") or
                                pending.get("source_body_sha256") != body.source_sha256 or
                                hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() !=
                                _pending_content_sha(pending)):
                            raise ValueError("pending Localize edit differs from its immutable schema-3 snapshot")
                        identity = pending.get("native_source_identity", {})
                        if (identity.get("body_sha256") != body.source_sha256 or
                                identity.get("source_fastfile_sha256") != profile.get("sha256") or
                                identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                                identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                                identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256") or
                                identity.get("xasset_index") != index):
                            raise ValueError("Localize edit is bound to a different source body/FF/native trace")
                        compile_receipt = pending.get("compiler_receipt")
                        payload_path = pending_path.parent / pending.get("edited_payload_path", "")
                        payload = payload_path.read_bytes()
                        encoded_receipt = json.dumps(compile_receipt, sort_keys=True,
                                                     separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        if (hashlib.sha256(encoded_receipt).hexdigest() != pending.get("compiler_receipt_sha256") or
                                compile_receipt.get("status") != "replay120-localize-value-encode-pass" or
                                compile_receipt.get("asset_name") != planned.get("name") or
                                compile_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                                compile_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256") or
                                sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                                payload != pending["content"].encode("utf-8") + b"\0"):
                            raise ValueError("Localize typed value payload/compiler receipt is stale")
                        trace_asset = traced.get(index)
                        if trace_asset is None or native_rows[index].get("name") != planned.get("name"):
                            raise ValueError("complete Localize trace lacks the selected name/index row")
                        trace_asset.update(index=index, xasset_index=index, type_id=41, name=planned["name"])
                        layout, values = inspect_localize_entry(
                            body.data, index, planned["name"], trace_asset,
                            expected_body_sha256=body.source_sha256)
                        expected_layout = dict(root_archive_offset=layout.root_archive_offset,
                                               root_stream_offset=layout.root_stream_offset,
                                               key_archive_offset=layout.key_archive_offset,
                                               key_stream_offset=layout.key_stream_offset,
                                               key_bytes=layout.key_bytes,
                                               value_archive_offset=layout.value_archive_offset,
                                               value_stream_offset=layout.value_stream_offset,
                                               value_bytes=layout.value_bytes,
                                               record_sha256=layout.source_record_sha256)
                        if identity.get("typed_layout") != expected_layout:
                            raise ValueError("Localize key/value ownership changed since editor load")
                        localize_edits.append(dict(asset_index=index, asset_name=planned["name"],
                                                   trace_asset=trace_asset, value=pending["content"],
                                                   expected_key=values["key"], expected_value=values["value"]))
                    _, writer_proof = replace_localize_values_with_relocation(
                        body.data, localize_edits, body.source_sha256,
                        trace_path, manifest_path)
                    entry["packageable"] = True
                    entry["reason"] = None
                    entry["support"] = "trace-relocated-localize-batch"
                    entry["proof"] = dict(native_walk_key=walk_receipt["walk_key"],
                                          native_manifest_sha256=walk_receipt["manifest_sha256"],
                                          stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                          xasset_count=len(body.assets), edit_count=len(localize_edits),
                                          writer=writer_proof,
                                          append_remove_supported=False,
                                          key_and_xasset_rows_immutable=True)
                    zones.append(entry)
                    continue
                if types == {"stringtable"}:
                    if len(rows) != 1:
                        indices = [row.get("index") for row in rows]
                        if (any(type(index) is not int for index in indices) or
                                len(set(indices)) != len(indices)):
                            raise ValueError("multiple StringTable edits must resolve to distinct XAsset indices")
                        omnvar_closure = None
                        root_index = next((index for index, native in enumerate(native_rows)
                                           if native.get("type_id") == 54 and
                                           isinstance(native.get("name"), str) and
                                           native["name"].replace("\\", "/").casefold() ==
                                           "omnvars/mp/omnvars.csv"), None)
                        if root_index is not None:
                            source_export_root, source_export = _export_native_type(
                                source, current_zone, body, cache_path, walk_receipt,
                                native_rows, 54, "stringtable", self.acts_path,
                                self.replay_executable)
                            root_export = next((item for item in source_export["items"]
                                                if item.get("asset_index") == root_index), None)
                            if root_export is None:
                                raise ValueError("native source export omits the MP Omnvar root table")
                            root_csv = (source_export_root / root_export["payload_relative_path"]).read_bytes()
                            root_rows = list(csv.reader(io.StringIO(
                                root_csv.decode("utf-8-sig"), newline="")))
                            closure_proof, _ = _prepare_omnvar_mp_source_proof(
                                source=source, zone_id=current_zone, body=body,
                                cache_path=cache_path, walk_receipt=walk_receipt,
                                native_rows=native_rows, root_index=root_index,
                                root_name="omnvars/mp/omnvars.csv", original_rows=root_rows,
                                export_root=source_export_root, export_index=source_export,
                                trace_path=_native_walk_artifact(
                                    walk_receipt, "stream_trace_relative_path"),
                                manifest_path=_native_walk_artifact(
                                    walk_receipt, "manifest_relative_path"))
                            closure_indices = sorted({
                                item.get("asset_index")
                                for item in closure_proof.get("source_closure", {}).get("tables", [])
                                if type(item.get("asset_index")) is int})
                            source_closure = closure_proof.get("source_closure")
                        single_plans = []
                        for staged in sorted(rows, key=lambda row: row["index"]):
                            isolated = self._plan_pending_rows([staged], _snapshots=snapshots)
                            isolated_zone = next((item for item in isolated["zones"]
                                                  if item.get("zone_id") == current_zone), None)
                            if (isolated.get("status") != "ready" or isolated_zone is None or
                                    not isolated_zone.get("packageable") or
                                    isolated_zone.get("support") !=
                                    "stringtable-full-trace-block5-relocation"):
                                detail = (isolated_zone.get("reason") if isolated_zone else
                                          "; ".join(str(item.get("reason", "invalid edit"))
                                                     for item in isolated.get("invalid_edits", [])))
                                raise UnsupportedAssetGraphError(
                                    "each StringTable edit must independently pass the existing full-trace preflight"
                                    f" (asset {staged.get('asset_id')}: {detail or 'no detailed reason'})")
                            single_plans.append(isolated_zone)
                        if omnvar_closure is None and root_index is not None:
                            source_rows_by_index = {}
                            source_items_by_index = {}
                            for item in source_export.get("items", []):
                                asset_index = item.get("asset_index")
                                if type(asset_index) is int:
                                    if asset_index in source_items_by_index:
                                        raise ValueError("native StringTable export has duplicate asset indices")
                                    source_items_by_index[asset_index] = item
                            for closure_table in source_closure.get("tables", []):
                                table_index = closure_table.get("asset_index")
                                item = source_items_by_index.get(table_index)
                                if (item is None or item.get("type_id") != 54 or
                                        item.get("name") != closure_table.get("name")):
                                    raise ValueError("Omnvar closure table differs from the native source export")
                                relative = Path(str(item.get("payload_relative_path", "")))
                                if relative.is_absolute() or ".." in relative.parts:
                                    raise ValueError("native Omnvar CSV export has an unsafe path")
                                payload_path = (source_export_root / relative).resolve(strict=True)
                                if (not payload_path.is_relative_to(source_export_root.resolve(strict=True)) or
                                        not payload_path.is_file() or
                                        payload_path.stat().st_size != item.get("payload_bytes") or
                                        sha256_file(payload_path) != item.get("payload_sha256")):
                                    raise ValueError("native Omnvar CSV export payload failed hash verification")
                                source_rows_by_index[table_index] = list(csv.reader(io.StringIO(
                                    payload_path.read_bytes().decode("utf-8-sig"), newline="")))
                            staged_closure_rows = {}
                            for staged_row in rows:
                                staged_index = staged_row.get("index")
                                if staged_index not in closure_indices:
                                    continue
                                if staged_row.get("name") != source_items_by_index[staged_index].get("name"):
                                    raise ValueError("staged Omnvar table name differs from its native closure member")
                                current_path = Path(staged_row["pending_path"]).resolve(strict=True)
                                pending = json.loads(current_path.read_text(encoding="utf-8"))
                                revision = pending.get("revision")
                                immutable = current_path.parent / f"{revision}.json"
                                if (pending != json.loads(immutable.read_text(encoding="utf-8")) or
                                        pending.get("revision") != staged_row.get("revision") or
                                        pending.get("type") != "stringtable" or pending.get("type_id") != 54 or
                                        pending.get("name") != staged_row.get("name") or
                                        pending.get("source_body_sha256") != body.source_sha256 or
                                        not isinstance(pending.get("content"), str) or
                                        hashlib.sha256(pending["content"].encode("utf-8")).hexdigest() !=
                                        _pending_content_sha(pending)):
                                    raise ValueError("staged Omnvar table differs from its immutable source-bound revision")
                                staged_closure_rows[staged_index] = dict(
                                    revision=revision,
                                    rows=list(csv.reader(io.StringIO(pending["content"], newline=""))))
                            effective_validation = _validate_omnvar_effective_closure(
                                source_closure, source_rows_by_index, staged_closure_rows)
                            omnvar_closure = dict(
                                root_index=root_index, table_indices=closure_indices,
                                source_closure_sha256=_omnvar_validation_sha256(source_closure),
                                staged_table_indices=sorted(staged_closure_rows),
                                effective_validation=effective_validation)
                        entry.update(
                            packageable=True,
                            support="stringtable-sequential-full-trace-relocation",
                            reason=None,
                            proof=dict(edit_count=len(rows),
                                       native_walk_key=walk_receipt["walk_key"],
                                       native_manifest_sha256=walk_receipt["manifest_sha256"],
                                       stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                       source_body_sha256=body.source_sha256,
                                       edits=[item["proof"] for item in single_plans],
                                       omnvar_closure=omnvar_closure,
                                       retrace_after_each_edit=True,
                                       retained_semantics_required=True))
                        zones.append(entry)
                        continue
                    planned = rows[0]
                    index = planned.get("index")
                    if (not isinstance(index, int) or not 0 <= index < len(body.assets) or
                            body.assets[index].type_id != 54 or native_rows[index].get("type_id") != 54 or
                            native_rows[index].get("name") != planned.get("name")):
                        raise ValueError("staged asset identity no longer matches a StringTable XAsset row")
                    if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("StringTable native walk differs from current source FF/patch chain")
                    pending_path = Path(planned["pending_path"])
                    pending = json.loads(pending_path.read_text(encoding="utf-8"))
                    snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
                    if (not snapshot_path.is_file() or pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                            pending.get("revision") != planned.get("revision") or
                            pending.get("type") != "stringtable" or pending.get("type_id") != 54 or
                            pending.get("name") != planned.get("name") or
                            pending.get("source_body_sha256") != body.source_sha256 or
                            hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                        raise ValueError("pending StringTable revision differs from immutable source snapshot")
                    source_identity = pending.get("native_source_identity", {})
                    if (source_identity.get("body_sha256") != body.source_sha256 or
                            source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                            source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                            source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                            source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256")):
                        raise ValueError("StringTable edit is bound to a stale source body/native trace")
                    compiler_receipt = pending.get("compiler_receipt")
                    if (not isinstance(compiler_receipt, dict) or
                            compiler_receipt.get("status") != "replay120-stringtable-encode-pass" or
                            compiler_receipt.get("asset_name") != planned.get("name") or
                            compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending)):
                        raise ValueError("StringTable edit lacks its matching semantic encoder receipt")
                    omnvar_validation = compiler_receipt.get("omnvar_mp_validation")
                    if omnvar_validation is not None:
                        if not _omnvar_helper_modules_match(omnvar_validation.get("modules")):
                            raise ValueError("Omnvar validation helper changed; resave the staged Omnvar table")
                    compiler_identity_error = self._compiler_identity_staleness(pending, 54)
                    if compiler_identity_error:
                        raise ValueError(compiler_identity_error)
                    canonical = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False).encode("utf-8")
                    if hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256"):
                        raise ValueError("StringTable semantic encoder receipt hash changed")
                    payload_path = pending_path.parent / pending["edited_payload_path"]
                    payload = payload_path.read_bytes()
                    if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                            hashlib.sha256(payload).hexdigest() != compiler_receipt.get("result", {}).get("native_payload_sha256")):
                        raise ValueError("StringTable staged semantic payload differs from its receipt")
                    replacement_rows = list(csv.reader(io.StringIO(pending["content"], newline="")))
                    from workstation_asset_codecs import encode_stringtable_sections
                    sections = encode_stringtable_sections(planned["name"], replacement_rows)
                    if (sections["rows"] != compiler_receipt.get("input", {}).get("rows") or
                            sections["columns"] != compiler_receipt.get("input", {}).get("columns") or
                            len(sections["dictionary"]) != compiler_receipt.get("input", {}).get("dictionary_count")):
                        raise ValueError("StringTable CSV no longer matches its staged section receipt")
                    expected_payload = json.dumps(
                        dict(schema=1, kind="stringtable-sections", name=sections["name"],
                             rows=sections["rows"], columns=sections["columns"],
                             header_base64=base64.b64encode(sections["header"]).decode("ascii"),
                             cells_base64=base64.b64encode(sections["cells"]).decode("ascii"),
                             hashes_base64=base64.b64encode(sections["hashes"]).decode("ascii"),
                             dictionary=sections["dictionary"]),
                        sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if payload != expected_payload:
                        raise ValueError("StringTable staged sections differ from the complete regenerated encoding")
                    trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                    manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                    if (not walk_receipt.get("stream_trace_enabled") or
                            sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                            sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
                        raise ValueError("StringTable edit requires the unchanged complete native stream trace")
                    from workstation_trace_index import build_read_span_index
                    from workstation_stringtable import (
                        inspect_stringtable, replace_stringtable_rows,
                        validate_complete_stream5_allocations)
                    trace_index = build_read_span_index(trace_path, manifest_path, len(body.data))
                    stream5_allocation_context = validate_complete_stream5_allocations(trace_index)
                    traced = next((asset for asset in trace_index["assets"] if asset.get("index") == index), None)
                    if traced is None:
                        raise ValueError("native stream trace omits the selected StringTable")
                    traced.update(xasset_index=index, type_id=54, name=planned["name"])
                    export_root, export_index = _export_native_type(
                        source, current_zone, body, cache_path, walk_receipt, native_rows,
                        54, "stringtable", self.acts_path, self.replay_executable)
                    source_item = next((item for item in export_index["items"]
                                        if item.get("asset_index") == index), None)
                    if source_item is None:
                        raise ValueError("native StringTable export omits its XAsset row")
                    original_csv = (export_root / source_item["payload_relative_path"]).read_bytes()
                    original_rows = list(csv.reader(io.StringIO(
                        original_csv.decode("utf-8-sig"), newline="")))
                    layout, _ = inspect_stringtable(
                        body.data, index, planned["name"], traced, original_rows,
                        body.source_sha256,
                        global_string_data_spans=trace_index.get("string_data_spans", []))
                    if (source_identity.get("root_span", {}).get("archive_offset") != layout.root_archive_offset or
                            source_identity.get("record_span", {}).get("sha256") != layout.source_record_sha256):
                        raise ValueError("StringTable root/record provenance changed since editor load")
                    _, writer_proof = replace_stringtable_rows(
                        body.data, index, planned["name"], traced, original_rows,
                        replacement_rows, body.source_sha256, trace_path, manifest_path,
                        full_trace_index=trace_index)
                    reservation_deltas = writer_proof["stream_reservation_deltas"]
                    reservations = [int(profile["final_header"]["block_sizes"][block]) +
                                    int(reservation_deltas.get(str(block), 0))
                                    for block in range(STREAM_COUNT)]
                    if any(size < 0 for size in reservations):
                        raise ValueError("StringTable relocation produced a negative stream reservation")
                    entry["packageable"] = True
                    entry["support"] = "stringtable-full-trace-block5-relocation"
                    entry["reason"] = None
                    entry["proof"] = dict(native_walk_key=walk_receipt["walk_key"],
                                          native_manifest_sha256=walk_receipt["manifest_sha256"],
                                          stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                          xasset_count=len(body.assets), edit_count=1,
                                          stream_reservation_sizes=reservations,
                                          stream_reservation_deltas=writer_proof["stream_reservation_deltas"],
                                          writer=writer_proof)
                    zones.append(entry)
                    continue
                elif types and types <= {*SHADER_TYPE_IDS, "image"}:
                    if len({row.get("index") for row in rows}) != len(rows):
                        raise ValueError("same-extent shader/image batch contains duplicate XAsset indices")
                    if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("shader/image native walk differs from current source FF/patch chain")
                    trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                    manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                    from workstation_trace_index import build_read_span_index
                    indices = {row.get("index") for row in rows}
                    if any(not isinstance(i, int) or i < 0 or i >= len(body.assets) for i in indices):
                        raise ValueError("shader/image batch contains an invalid XAsset index")
                    compute_batch = any(row.get("type") == "computeshader" for row in rows)
                    trace_index = build_read_span_index(
                        trace_path, manifest_path, len(body.data),
                        selected_assets=None if compute_batch else indices)
                    traced = {asset["index"]: asset for asset in trace_index["assets"]}
                    spans, edit_proofs, variable_edits = [], [], []
                    all_native_edits, has_variable_extent = [], False
                    for planned in rows:
                        type_id = (SHADER_TYPE_IDS[planned["type"]]
                                   if planned["type"] in SHADER_TYPE_IDS else 19)
                        index = planned["index"]
                        if (body.assets[index].type_id != type_id or native_rows[index].get("type_id") != type_id or
                                native_rows[index].get("name") != planned.get("name")):
                            raise ValueError("staged shader/image identity differs from native XAsset row")
                        if type_id in (15, 16) and planned.get("name") == "null_vshsds.hlsl":
                            raise UnsupportedAssetGraphError("shared null hull/domain aliases are read-only")
                        pending_path = Path(planned["pending_path"])
                        pending = json.loads(pending_path.read_text(encoding="utf-8"))
                        snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
                        if (not snapshot_path.is_file() or
                                pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                                pending.get("revision") != planned.get("revision") or
                                pending.get("type_id") != type_id or pending.get("type") != planned.get("type") or
                                pending.get("name") != planned.get("name") or
                                pending.get("source_body_sha256") != body.source_sha256 or
                                hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                            raise ValueError("pending shader/image revision differs from immutable source snapshot")
                        source_identity = pending.get("native_source_identity", {})
                        if (source_identity.get("body_sha256") != body.source_sha256 or
                                source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                                source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                                source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                                source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256")):
                            raise ValueError("shader/image staged edit is bound to stale source/trace identity")
                        trace_asset = traced.get(index)
                        if trace_asset is None:
                            raise ValueError("complete native trace has no selected shader/image")
                        trace_asset.update(index=index, type_id=type_id, name=planned["name"])
                        trace_asset["indexed_string_data_spans"] = trace_index["string_data_spans"]
                        trace_asset["indexed_physical_spans"] = trace_index["_all_physical_spans"]
                        payload_path = pending_path.parent / pending["edited_payload_path"]
                        payload = payload_path.read_bytes()
                        compiler_receipt = pending.get("compiler_receipt")
                        if not isinstance(compiler_receipt, dict):
                            raise ValueError("shader/image edit has no immutable tool receipt")
                        canonical = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode("utf-8")
                        expected_status = ("replay120-resident-image-encode-pass" if type_id == 19 else
                                           "replay120-dxbc-assemble-pass")
                        if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                                hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256") or
                                compiler_receipt.get("status") != expected_status or
                                compiler_receipt.get("asset_name") != planned["name"] or
                                compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                                compiler_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
                            raise ValueError("shader/image staged child differs from its immutable tool receipt")
                        if type_id in SHADER_TYPES:
                            from workstation_native_asset_edits import read_inline_shader, replace_inline_shader
                            layout = read_inline_shader(
                                body.data, dict(native_rows[index], index=index), trace_asset,
                                body.source_sha256, trace_assets=trace_index["assets"])
                            child_offset, child_size = layout["program_archive_offset"], len(layout["program"])
                            current_layout = dict(root_archive_offset=layout["root_archive_offset"],
                                                  name_archive_offset=layout["name_archive_offset"],
                                                  child_archive_offset=child_offset, child_bytes=child_size)
                            if type_id in (12, 15, 16):
                                current_layout.update(debug_name=layout["debug_name"],
                                                      debug_name_stream_location=layout["debug_name_stream_location"])
                            if len(payload) == child_size:
                                _, writer_proof = replace_inline_shader(
                                    body.data, dict(native_rows[index], index=index), trace_asset,
                                    body.source_sha256, payload, trace_assets=trace_index["assets"])
                                if payload != layout["program"]:
                                    has_variable_extent = True
                            else:
                                has_variable_extent = True
                                writer_proof = {"status":"variable-shader-edit-pending-transaction"}
                                variable_edits.append(dict(kind="shader", asset_row=dict(native_rows[index], index=index),
                                                           trace_asset=trace_asset,
                                                           trace_assets=trace_index["assets"], payload=payload))
                            all_native_edits.append(dict(kind="shader", asset_row=dict(native_rows[index], index=index),
                                                         trace_asset=trace_asset,
                                                         trace_assets=trace_index["assets"], payload=payload))
                        else:
                            from workstation_native_asset_edits import read_resident_image, replace_resident_image
                            layout = read_resident_image(body.data, dict(native_rows[index], index=index),
                                                         trace_asset, body.source_sha256)
                            width, height, depth, elements = layout["dimensions"]
                            dds_mode = compiler_receipt.get("input", {}).get("source_container") == "DDS/DX10 resident resource"
                            if (depth != 1 or elements != 1) and not dds_mode:
                                raise UnsupportedAssetGraphError("3D/array images require whole-resource DDS source")
                            if not dds_mode:
                                from workstation_asset_codecs import _REPLAY_DXGI_NAMES
                            if not dds_mode and layout["format"] not in _REPLAY_DXGI_NAMES:
                                raise UnsupportedAssetGraphError("image format is outside the supported DirectXTex codec set")
                            child_offset, child_size = layout["payload_archive_offset"], len(layout["payload"])
                            current_layout = _resident_image_typed_layout(layout)
                            if dds_mode and (current_layout["atlas_token"] or current_layout["fallback_token"]):
                                raise UnsupportedAssetGraphError("DDS array/volume replacement cannot preserve atlas/fallback children")
                            result_layout = compiler_receipt.get("result", {})
                            output_dimensions = (result_layout.get("width", current_layout["dimensions"][0]),
                                                 result_layout.get("height", current_layout["dimensions"][1]))
                            output_mips = result_layout.get("mip_count", current_layout["level_count"])
                            if dds_mode and (result_layout.get("depth") != depth or result_layout.get("elements") != elements):
                                raise ValueError("staged DDS resource shape differs from the native image root")
                            if (output_dimensions == tuple(current_layout["dimensions"][:2]) and
                                    output_mips == current_layout["level_count"] and len(payload) == child_size):
                                _, writer_proof = replace_resident_image(
                                    body.data, dict(native_rows[index], index=index), trace_asset,
                                    body.source_sha256, payload)
                            else:
                                has_variable_extent = True
                                writer_proof = {"status":"variable-image-edit-pending-transaction"}
                                variable_edits.append(dict(kind="image", asset_row=dict(native_rows[index], index=index),
                                    trace_asset=trace_asset, width=output_dimensions[0], height=output_dimensions[1],
                                    mip_count=output_mips, payload=payload))
                            all_native_edits.append(dict(kind="image", asset_row=dict(native_rows[index], index=index),
                                trace_asset=trace_asset, width=output_dimensions[0], height=output_dimensions[1],
                                mip_count=output_mips, payload=payload))
                        if source_identity.get("typed_layout") != current_layout:
                            raise ValueError("shader/image root/child trace layout changed since editor load")
                        spans.append((child_offset, child_offset + child_size, payload))
                        edit_proofs.append(dict(asset_id=planned["asset_id"], revision=planned["revision"],
                                                type=planned["type"], name=planned["name"],
                                                typed_layout=current_layout, writer=writer_proof))
                    spans.sort(key=lambda span: span[0])
                    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
                        raise ValueError("same-extent shader/image child spans overlap")
                    if has_variable_extent:
                        from workstation_variable_native_edits import apply_variable_native_edits
                        updated, transaction = apply_variable_native_edits(body.data, all_native_edits,
                            body_path=cache_path / decode_receipt["final_body_relative_path"],
                            journal_path=_native_walk_artifact(walk_receipt, "journal_relative_path"),
                            trace_path=trace_path, manifest_path=manifest_path,
                            replay_executable=self.replay_executable)
                        support = "variable-native-shader-image-batch"
                    else:
                        updated = bytearray(body.data)
                        for begin, end, payload in spans:
                            if len(payload) != end - begin:
                                raise ValueError("same-extent shader/image replacement changed a child span")
                            updated[begin:end] = payload
                        updated = bytes(updated); transaction = None
                        support = "same-extent-native-shader-image-batch"
                    if ZoneBody.parse(updated).assets != body.assets:
                        raise ValueError("shader/image batch changed the XAsset table")
                    entry["packageable"] = True
                    entry["support"] = support
                    entry["reason"] = None
                    entry["proof"] = dict(native_walk_key=walk_receipt["walk_key"],
                                          native_manifest_sha256=walk_receipt["manifest_sha256"],
                                          stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                          xasset_count=len(body.assets), edit_count=len(edit_proofs),
                                          children_nonoverlapping=True, edits=edit_proofs,
                                          transaction=transaction,
                                          stream_reservation_sizes=(transaction or {}).get("stream_reservation_sizes"))
                    # This branch is already fully preflighted and same-extent;
                    # do not fall through into ScriptFile-only validation below.
                    zones.append(entry)
                    continue
                elif types == {"luafile"}:
                    if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                            walk_receipt.get("identity", {}).get("patch_sha256s") !=
                            [patch["sha256"] for patch in profile.get("patches", [])]):
                        raise ValueError("LuaFile native walk differs from the current source FF/patch chain")
                    if any(native_rows[row.get("index", -1)].get("type_id") != 62 or
                           body.assets[row.get("index", -1)].type_id != 62
                           for row in rows if isinstance(row.get("index"), int) and
                           0 <= row.get("index", -1) < len(native_rows)):
                        raise ValueError("staged asset identity no longer matches a LuaFile table row")
                    if any(not isinstance(row.get("index"), int) or row["index"] < 0 or
                           row["index"] >= len(native_rows) for row in rows):
                        raise ValueError("staged LuaFile index is outside the native table")
                    trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
                    manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
                    from workstation_trace_index import build_read_span_index
                    selected = {row["index"] for row in rows}
                    trace_index = build_read_span_index(trace_path, manifest_path,
                                                        len(body.data), selected_assets=selected)
                    traced = {asset["index"]: asset for asset in trace_index["assets"]}
                    actual_edits = []
                    for row in rows:
                        pending_path = Path(row["pending_path"])
                        pending = json.loads(pending_path.read_text(encoding="utf-8"))
                        if (pending.get("revision") != row.get("revision") or
                                pending.get("type") != "luafile" or
                                pending.get("native_source_identity", {}).get("body_sha256") != body.source_sha256 or
                                pending.get("native_source_identity", {}).get("source_fastfile_sha256") != profile.get("sha256") or
                                pending.get("native_source_identity", {}).get("native_walk_key") != walk_receipt["walk_key"] or
                                pending.get("native_source_identity", {}).get("native_manifest_sha256") != walk_receipt["manifest_sha256"] or
                                pending.get("native_source_identity", {}).get("stream_trace_sha256") != walk_receipt["stream_trace_sha256"]):
                            raise ValueError("pending LuaFile revision is bound to a different body/native trace")
                        compiler_receipt = pending.get("compiler_receipt")
                        if (not isinstance(compiler_receipt, dict) or
                                compiler_receipt.get("status") != "target-lua-loadx-reload-pass" or
                                compiler_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
                            raise ValueError("pending LuaFile edit lacks its matching native compiler receipt")
                        canonical = json.dumps(compiler_receipt, sort_keys=True,
                                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        if hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256"):
                            raise ValueError("pending LuaFile compiler receipt digest is invalid")
                        payload_path = pending_path.parent / pending["edited_payload_path"]
                        payload = payload_path.read_bytes()
                        if sha256_file(payload_path) != pending.get("edited_payload_sha256"):
                            raise ValueError("pending LuaFile bytecode changed after staging")
                        trace_asset = traced.get(row["index"])
                        if trace_asset is None:
                            raise ValueError("complete stream trace has no selected LuaFile")
                        trace_asset.update(xasset_index=row["index"], name=row["name"], type_id=62)
                        actual_edits.append(dict(asset_index=row["index"], asset_name=row["name"],
                                                 trace_asset=trace_asset, payload=payload))
                    from workstation_luafile import replace_luafiles_inline_children
                    _, writer_proof = replace_luafiles_inline_children(
                        body.data, actual_edits, body.source_sha256,
                        trace_path, manifest_path)
                    reservations = writer_proof.get("stream_reservation_sizes") or profile["final_header"]["block_sizes"]
                    entry["packageable"] = True
                    entry["reason"] = None
                    entry["support"] = "luafile-inline-child-full-trace-relocation"
                    entry["proof"] = dict(native_walk_key=walk_receipt["walk_key"],
                                          native_manifest_sha256=walk_receipt["manifest_sha256"],
                                          stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                                          xasset_count=len(body.assets), edit_count=len(actual_edits),
                                          stream_reservation_sizes=reservations,
                                          stream_reservation_deltas=writer_proof.get("stream_reservation_deltas"),
                                          writer=writer_proof,
                                          mixed_scriptfile_luafile_edits_supported=False)
                elif types == {"scriptfile"}:
                    for row in rows:
                        index = row.get("index")
                        if (not isinstance(index, int) or index < 0 or index >= len(native_rows) or
                                native_rows[index].get("type_id") != 52 or
                                body.assets[index].type_id != 52):
                            raise ValueError("staged asset identity no longer matches a ScriptFile table row")
                else:
                    unsupported = sorted(str(value) for value in types)
                    raise UnsupportedAssetGraphError(
                        f"package batch must contain only ScriptFiles or only LuaFiles; got: {', '.join(unsupported)}")
                if types == {"luafile"}:
                    zones.append(entry)
                    continue
                for row in rows:
                    index = row.get("index")
                    if (not isinstance(index, int) or index < 0 or index >= len(native_rows) or
                            native_rows[index].get("type_id") != 52 or
                            body.assets[index].type_id != 52):
                        raise ValueError("staged asset identity no longer matches a ScriptFile table row")
                from analyze_workstation_asset_spans import analyze
                trace_report = analyze(self.cache_root, current_zone, {52})
                actual_edits = []
                for row in rows:
                    pending_path = Path(row["pending_path"])
                    pending = json.loads(pending_path.read_text(encoding="utf-8"))
                    if pending.get("revision") != row.get("revision"):
                        raise ValueError("pending edit revision changed during preflight")
                    snapshot = json.loads((pending_path.parent / f"{pending['revision']}.json").read_text(encoding="utf-8"))
                    if (snapshot != pending or pending.get("asset_id") != row.get("asset_id") or
                            pending.get("type") != "scriptfile" or
                            hashlib.sha256(pending.get("content", "").encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                        raise ValueError("pending source text, snapshot, and revision are inconsistent")
                    payload_path = pending_path.parent / pending["edited_payload_path"]
                    payload = payload_path.read_bytes()
                    if sha256_file(payload_path) != pending.get("edited_payload_sha256"):
                        raise ValueError("pending payload hash changed during preflight")
                    actual_edits.append(dict(xasset_index=row["index"], name=row["name"], payload=payload))
                _, writer_proof = replace_scriptfiles_inline_children(
                    body.data, actual_edits, trace_report, body.source_sha256)
                entry["packageable"] = True
                entry["reason"] = None
                entry["support"] = "scriptfile-inline-children-trace-owned"
                entry["proof"] = dict(native_walk_key=trace_report["native_walk_key"],
                                      native_manifest_sha256=trace_report["native_manifest_sha256"],
                                      stream_trace_sha256=trace_report["stream_trace_sha256"],
                                      xasset_count=len(body.assets),
                                      edit_count=len(actual_edits),
                                      stream6_extent_delta=writer_proof["stream6_extent_delta"],
                                      stream6_high_water=writer_proof["new_stream6_high_water"],
                                      all_stream6_allocations_owned_by_scriptfiles=True,
                                      packed_stream6_targets=0)
            except (KeyError, OSError, ValueError, TypeError, UnsupportedAssetGraphError) as error:
                entry["reason"] = str(error)
            zones.append(entry)
        status = ("empty" if not zones and not invalid else
                  "ready" if zones and all(row["packageable"] for row in zones) and not invalid else
                  "blocked")
        return dict(schema=1, status=status, zones=zones, invalid_edits=invalid,
                    total_zones=len(zones), total_edits=sum(len(row["edits"]) for row in zones),
                    note="Preflight validates current staged revisions and typed trace ownership; it does not compile assets or produce output files.")

    def restore_asset_edit(self, asset_id: str, revision: str,
                           expected_current_revision: str | None = None) -> dict:
        """Restore a prior immutable staged revision, with optional optimistic concurrency."""
        if not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("revision must be a SHA-256 digest")
        zone_id, separator, index_text = asset_id.rpartition(":")
        if not separator or not index_text.isdecimal():
            raise ValueError("asset_id must be '<zone-cache-key>:<xasset-index>'")
        cache_path, decode_receipt = self._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache_path / decode_receipt["final_body_relative_path"]).read_bytes())
        index = int(index_text)
        if index < 0 or index >= len(body.assets):
            raise AssetNotFoundError(asset_id)
        pending_dir = cache_path / "pending-edits" / str(index)
        current_path = pending_dir / "current.json"
        if expected_current_revision is not None:
            current_rev = None
            if current_path.is_file():
                current_rev = json.loads(current_path.read_text(encoding="utf-8")).get("revision")
            if current_rev != expected_current_revision:
                raise ValueError("Asset revision conflict; reload before restoring")
        snapshot_path = pending_dir / f"{revision}.json"
        if not snapshot_path.is_file():
            raise KeyError(f"unknown staged revision: {revision}")
        row = json.loads(snapshot_path.read_text(encoding="utf-8"))
        if row.get("asset_id") != asset_id or row.get("revision") != revision or row.get("source_body_sha256") != body.source_sha256:
            raise ValueError("staged snapshot identity or source hash is invalid")
        payload_rel = Path(row.get("edited_payload_path", ""))
        if payload_rel.name != str(payload_rel) or payload_rel.is_absolute():
            raise ValueError("staged snapshot payload path is invalid")
        payload_path = pending_dir / payload_rel
        if not payload_path.is_file() or sha256_file(payload_path) != row.get("edited_payload_sha256"):
            raise ValueError("staged snapshot payload hash mismatch")
        temporary = current_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        temporary.replace(current_path)
        return dict(asset_id=asset_id, revision=revision, status="staged-edit-restored",
                    pending_path=str(current_path), edited_payload_sha256=row["edited_payload_sha256"],
                    archive_writable=False)

    def _build_soundbank_replacement(self, zone_id: str, cache_path: Path,
                                     decode_receipt: dict, body: ZoneBody,
                                     plan: dict, output: Path, timeout: int) -> dict:
        """Apply public alias scalar words and validate the complete replacement FF natively."""
        import workstation_soundbank as soundbank_module
        planned = list(plan.get("edits", []))
        if not planned:
            raise UnsupportedAssetGraphError("SoundBank package requires at least one staged alias edit")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        if any(p.get("extension") == ".fc" for p in profile.get("patches", [])):
            raise UnsupportedAssetGraphError("source FC replacement semantics are not yet proven")
        snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
        walk, native_rows = snapshot.native_walk, snapshot.native_rows
        if (walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk.get("identity", {}).get("patch_sha256s") !=
                [p.get("sha256") for p in profile.get("patches", [])]):
            raise ValueError("SoundBank walk does not match the current source FF/patch chain")
        trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
        if (sha256_file(trace_path) != walk.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk.get("manifest_sha256")):
            raise ValueError("SoundBank trace or manifest changed after preflight")
        indices = [int(item["asset_id"].rsplit(":", 1)[1]) for item in planned]
        if len(set(indices)) != len(indices):
            raise ValueError("SoundBank package repeats an XAsset index")
        body_bytes = body.data
        updated = bytearray(body_bytes)
        changed_offsets, edit_proofs = set(), []
        for item in planned:
            index = int(item["asset_id"].rsplit(":", 1)[1])
            if (not 0 <= index < len(body.assets) or body.assets[index].type_id != 21 or
                    native_rows[index].get("type") != "soundbank" or
                    native_rows[index].get("name") != item.get("name")):
                raise ValueError("SoundBank package identity differs from its native XAsset row")
            pending_path = cache_path / "pending-edits" / str(index) / "current.json"
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            if pending.get("revision") != item.get("revision") or pending.get("source_body_sha256") != body.source_sha256:
                raise ValueError("SoundBank revision/body changed after package preflight")
            receipt = self._read_typed_soundbank(snapshot, index, native_rows[index])
            source_identity = pending.get("native_source_identity", {})
            expected_identity = self._soundbank_source_identity(snapshot, index, receipt)
            if (source_identity.get("typed_layout") != expected_identity["typed_layout"] or
                    source_identity.get("native_walk_key") != walk.get("walk_key") or
                    source_identity.get("stream_trace_sha256") != walk.get("stream_trace_sha256") or
                    source_identity.get("native_manifest_sha256") != walk.get("manifest_sha256")):
                raise ValueError("staged SoundBank source layout/trace identity is stale")
            changes = soundbank_module.validate_soundbank_edit_document(pending["content"], receipt)
            local, writer_proof = soundbank_module.replace_soundbank_alias_scalars(
                body_bytes, receipt, changes)
            for write in writer_proof["writes"]:
                offset = write["archive_offset"]
                if offset in changed_offsets or updated[offset:offset + 4] != bytes.fromhex(write["source_bits"]):
                    raise ValueError("SoundBank field write overlaps or no longer matches source bytes")
                changed_offsets.add(offset)
                updated[offset:offset + 4] = local[offset:offset + 4]
            edit_proofs.append(dict(asset_id=item["asset_id"], revision=item["revision"],
                                    name=item["name"], source_identity_sha256=receipt["source_identity_sha256"],
                                    changes=changes, writer=writer_proof))
        updated = bytes(updated)
        if updated == body_bytes or ZoneBody.parse(updated).assets != body.assets:
            raise ValueError("SoundBank scalar package is a no-op or changed the XAsset table")
        packed = pack_replay_uncompressed(updated, profile["final_header"]["block_sizes"],
                                          profile["final_header"]["xfile_version"],
                                          profile["header"]["transient_type"])
        if unpack_replay_uncompressed(packed) != updated:
            raise AssertionError("SoundBank FF framing changed the edited body")
        if output.exists() or any(output.with_suffix(ext).exists() for ext in (".fp", ".fc")):
            raise FileExistsError("replacement FF/patch output already exists")
        acts_before, replay_before = acts_tool_identity(self.acts_path), sha256_file(self.replay_executable)
        output.parent.mkdir(parents=True, exist_ok=True)
        sidecars = []
        try:
            output.write_bytes(packed)
            for patch in profile.get("patches", []):
                target = output.with_suffix(patch["extension"])
                target.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), packed))
                sidecars.append(dict(path=str(target), bytes=target.stat().st_size,
                                     sha256=sha256_file(target),
                                     replaces_stale_source_patch=str(patch["path"])))
            with tempfile.TemporaryDirectory(prefix="rwt-soundbank-package-") as temporary:
                from roundtrip_replay_fastfile import verify_native
                native = verify_native(output, updated, source, self.acts_path,
                                       self.replay_executable, Path(temporary), timeout, trace=True)
                manifest = native["manifest"]
                if (not manifest.get("complete") or not manifest.get("success") or
                        manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                        manifest.get("loaded_assets") != walk.get("loaded_assets") or
                        manifest.get("serialized_bytes_read") != len(updated) or
                        native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256")) !=
                        ordered_asset_identity_sha256(native_rows)):
                    raise ValueError("SoundBank package native reread did not validate the complete XAsset table/body")
                output_trace = Path(native["manifest_path"]).parent / manifest.get("stream_trace", "stream-trace.jsonl")
                output_manifest = Path(native["manifest_path"])
                with tempfile.TemporaryDirectory(prefix="rwt-soundbank-body-") as body_temp:
                    verified_body_path = Path(body_temp) / "output.body"
                    verified_body_path.write_bytes(updated)
                    for proof in edit_proofs:
                        idx = int(proof["asset_id"].rsplit(":", 1)[1])
                        reread = soundbank_module.read_native_soundbank(
                            body_path=verified_body_path, source_fastfile=output,
                            manifest_path=output_manifest, trace_path=output_trace,
                            asset_index=idx, asset_name=proof["name"])
                        doc = soundbank_module.soundbank_edit_document(reread)
                        pending = json.loads((cache_path / "pending-edits" / str(idx) / "current.json").read_text(encoding="utf-8"))
                        if soundbank_module.validate_soundbank_edit_document(
                                pending["content"], reread):
                            raise ValueError("native reread SoundBank semantics differ from the staged alias fields")
            _assert_run_inputs_unchanged(source, profile, self.acts_path, acts_before,
                                         self.replay_executable, replay_before)
            receipt = dict(schema="replay120-soundbank-alias-scalar-package-v1",
                           status="native-full-zone-soundbank-alias-scalar-package-pass",
                           source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                           native_walk_key=walk["walk_key"], edits=edit_proofs,
                           writer=dict(same_extent=True, xasset_table_unchanged=True,
                                       only_trace_owned_alias_float_words_changed=True,
                                       changed_float_word_offsets=sorted(changed_offsets)),
                           output_fastfile=dict(path=str(output), bytes=output.stat().st_size,
                                                sha256=sha256_file(output)), sidecars=sidecars,
                           native_reader=dict(complete=manifest.get("complete"), success=manifest.get("success"),
                                              loaded_assets=manifest.get("loaded_assets"), tested=manifest.get("tested"),
                                              failed=manifest.get("failed"), unavailable=manifest.get("unavailable"),
                                              serialized_bytes_read=manifest.get("serialized_bytes_read"),
                                              journal_sha256=native["journal_sha256"],
                                              acts_tool_identity=native["acts_tool_identity"],
                                              replay_executable_sha256=native["replay_executable_sha256"]))
            receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            return dict(status=receipt["status"], zone_id=zone_id,
                        edits=[dict(asset_id=row["asset_id"], revision=row["revision"]) for row in edit_proofs],
                        output_fastfile=str(output), output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(receipt_path),
                        native_reader_status=manifest.get("status"), native_reader_loaded=manifest.get("loaded_assets"),
                        native_reader_tested=manifest.get("tested"), edit_proof=receipt["writer"],
                        runtime_visual_status="not-tested")
        except Exception:
            output.unlink(missing_ok=True)
            for sidecar in sidecars:
                Path(sidecar["path"]).unlink(missing_ok=True)
            raise

    def _build_native_child_replacement(self, zone_id: str, cache_path: Path,
                                        decode_receipt: dict, body: ZoneBody,
                                        plan: dict, output: Path, timeout: int) -> dict:
        """Package nonoverlapping same-extent shader/image children and reread the full zone."""
        planned_edits = list(plan.get("edits", []))
        if not planned_edits:
            raise UnsupportedAssetGraphError("same-extent shader/image package requires at least one edit")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        if any(patch.get("extension") == ".fc" for patch in profile.get("patches", [])):
            raise UnsupportedAssetGraphError("source FC replacement semantics are not yet proven")
        walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
        if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk_receipt.get("identity", {}).get("patch_sha256s") !=
                [patch["sha256"] for patch in profile.get("patches", [])]):
            raise ValueError("shader/image walk does not match the current source FF/patch chain")
        trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
        if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
            raise ValueError("shader/image trace or manifest changed after preflight")
        indices = [int(item["asset_id"].rsplit(":", 1)[1]) for item in planned_edits]
        if len(set(indices)) != len(indices):
            raise ValueError("same-extent shader/image package has duplicate asset indices")
        compute_batch = any(item.get("type") == "computeshader" for item in planned_edits)
        trace_index = __import__("workstation_trace_index").build_read_span_index(
            trace_path, manifest_path, len(body.data),
            selected_assets=None if compute_batch else set(indices))
        traced = {row["index"]: row for row in trace_index["assets"]}
        spans, edit_receipts, variable_edits = [], [], []
        all_native_edits, has_variable_extent = [], False
        from workstation_asset_codecs import DEFAULT_DXBC_TOOL, DEFAULT_TEXCONV_TOOL
        import workstation_asset_codecs as codec_module
        for planned in planned_edits:
            index = int(planned["asset_id"].rsplit(":", 1)[1])
            type_name = planned.get("type")
            type_id = (SHADER_TYPE_IDS.get(type_name)
                       if type_name in SHADER_TYPE_IDS else 19 if type_name == "image" else None)
            if type_id is None or index < 0 or index >= len(body.assets):
                raise ValueError("queued shader/image type or index is invalid")
            if (body.assets[index].type_id != type_id or native_rows[index].get("type_id") != type_id or
                    native_rows[index].get("name") != planned.get("name")):
                raise ValueError("staged shader/image identity differs from the source XAsset row")
            if type_id in (15, 16) and planned.get("name") == "null_vshsds.hlsl":
                raise UnsupportedAssetGraphError("shared null hull/domain aliases are read-only")
            pending_path = cache_path / "pending-edits" / str(index) / "current.json"
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
            if (not snapshot_path.is_file() or pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                    pending.get("revision") != planned.get("revision") or
                    pending.get("source_body_sha256") != body.source_sha256 or
                    hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                raise ValueError("shader/image edit revision changed after preflight")
            source_identity = pending.get("native_source_identity", {})
            if (source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256")):
                raise ValueError("shader/image edit was staged against a stale source/trace identity")
            payload_path = pending_path.parent / pending["edited_payload_path"]
            payload = payload_path.read_bytes()
            compiler_receipt = pending.get("compiler_receipt")
            if not isinstance(compiler_receipt, dict):
                raise ValueError("shader/image edit has no immutable compiler receipt")
            encoded = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False).encode("utf-8")
            expected_status = "replay120-resident-image-encode-pass" if type_id == 19 else "replay120-dxbc-assemble-pass"
            if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                    hashlib.sha256(encoded).hexdigest() != pending.get("compiler_receipt_sha256") or
                    compiler_receipt.get("status") != expected_status or
                    compiler_receipt.get("asset_name") != planned.get("name") or
                    compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                    compiler_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
                raise ValueError("shader/image native child or compiler receipt changed after preflight")
            tool = Path(os.environ.get("REPLAY_TEXCONV" if type_id == 19 else "REPLAY_DXBC_TOOL",
                                      str(DEFAULT_TEXCONV_TOOL if type_id == 19 else DEFAULT_DXBC_TOOL))).resolve(strict=True)
            compiler = compiler_receipt.get("compiler", {})
            if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                    compiler.get("codec_module_sha256") != sha256_file(Path(codec_module.__file__))):
                raise ValueError("shader/image conversion tool or codec identity changed after preflight")
            trace_asset = traced.get(index)
            if trace_asset is None:
                raise ValueError("full native trace omits a selected shader/image")
            trace_asset.update(index=index, type_id=type_id, name=planned["name"])
            trace_asset["indexed_string_data_spans"] = trace_index["string_data_spans"]
            trace_asset["indexed_physical_spans"] = trace_index["_all_physical_spans"]
            if type_id in SHADER_TYPES:
                from workstation_native_asset_edits import read_inline_shader, replace_inline_shader
                current = read_inline_shader(
                    body.data, dict(native_rows[index], index=index), trace_asset,
                    body.source_sha256, trace_assets=trace_index["assets"])
                begin, length = current["program_archive_offset"], len(current["program"])
                layout = dict(root_archive_offset=current["root_archive_offset"],
                              name_archive_offset=current["name_archive_offset"],
                              child_archive_offset=begin, child_bytes=length)
                if type_id in (12, 15, 16):
                    layout.update(debug_name=current["debug_name"],
                                  debug_name_stream_location=current["debug_name_stream_location"])
                if len(payload) == length:
                    _, writer_proof = replace_inline_shader(
                        body.data, dict(native_rows[index], index=index), trace_asset,
                        body.source_sha256, payload, trace_assets=trace_index["assets"])
                    if payload != current["program"]:
                        has_variable_extent = True
                else:
                    has_variable_extent = True
                    writer_proof = {"status":"variable-shader-edit-pending-transaction"}
                    variable_edits.append(dict(kind="shader", asset_row=dict(native_rows[index], index=index),
                                               trace_asset=trace_asset,
                                               trace_assets=trace_index["assets"], payload=payload))
                all_native_edits.append(dict(kind="shader", asset_row=dict(native_rows[index], index=index),
                                             trace_asset=trace_asset,
                                             trace_assets=trace_index["assets"], payload=payload))
            else:
                from workstation_native_asset_edits import read_resident_image, replace_resident_image
                current = read_resident_image(body.data, dict(native_rows[index], index=index),
                                              trace_asset, body.source_sha256)
                width, height, depth, elements = current["dimensions"]
                dds_mode = compiler_receipt.get("input", {}).get("source_container") == "DDS/DX10 resident resource"
                if (depth != 1 or elements != 1) and not dds_mode:
                    raise UnsupportedAssetGraphError("3D/array images require whole-resource DDS source")
                if not dds_mode:
                    from workstation_asset_codecs import _REPLAY_DXGI_NAMES
                if not dds_mode and current["format"] not in _REPLAY_DXGI_NAMES:
                    raise UnsupportedAssetGraphError("image format is outside the supported DirectXTex codec set")
                begin, length = current["payload_archive_offset"], len(current["payload"])
                atlas_token = struct.unpack_from("<Q", current["root_bytes"], 8)[0]
                fallback_token = struct.unpack_from("<Q", current["root_bytes"], 0xD8)[0]
                layout = _resident_image_typed_layout(current)
                if dds_mode and (atlas_token or fallback_token):
                    raise UnsupportedAssetGraphError("DDS array/volume replacement cannot preserve atlas/fallback children")
                result_layout = compiler_receipt.get("result", {})
                width = result_layout.get("width", current["dimensions"][0])
                height = result_layout.get("height", current["dimensions"][1])
                mips = result_layout.get("mip_count", current["level_count"])
                if (dds_mode and (result_layout.get("depth") != depth or result_layout.get("elements") != elements)):
                    raise ValueError("staged DDS resource shape differs from the native image root")
                if ((width, height) == tuple(current["dimensions"][:2]) and
                        mips == current["level_count"] and len(payload) == length):
                    _, writer_proof = replace_resident_image(
                        body.data, dict(native_rows[index], index=index), trace_asset,
                        body.source_sha256, payload)
                else:
                    if dds_mode:
                        raise ValueError("whole-resource DDS replacement changed the resident image extent")
                    has_variable_extent = True
                    writer_proof = {"status":"variable-image-edit-pending-transaction"}
                    variable_edits.append(dict(kind="image", asset_row=dict(native_rows[index], index=index),
                        trace_asset=trace_asset, width=width, height=height, mip_count=mips, payload=payload))
                all_native_edits.append(dict(kind="image", asset_row=dict(native_rows[index], index=index),
                    trace_asset=trace_asset, width=width, height=height, mip_count=mips, payload=payload))
            if source_identity.get("typed_layout") != layout:
                raise ValueError("shader/image trace-owned layout differs from staged identity")
            spans.append((begin, begin + length, payload))
            edit_receipts.append(dict(asset_id=planned["asset_id"], revision=planned["revision"],
                                      type=type_name, name=planned["name"],
                                      edited_payload_sha256=pending["edited_payload_sha256"],
                                      compiler_receipt_sha256=pending["compiler_receipt_sha256"],
                                      compiler_receipt=compiler_receipt,
                                      typed_layout=layout, writer=writer_proof))
        spans.sort(key=lambda span: span[0])
        if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
            raise ValueError("same-extent shader/image child spans overlap")
        if has_variable_extent:
            from workstation_variable_native_edits import apply_variable_native_edits
            updated, transaction = apply_variable_native_edits(body.data, all_native_edits,
                body_path=cache_path / decode_receipt["final_body_relative_path"],
                journal_path=_native_walk_artifact(walk_receipt, "journal_relative_path"),
                trace_path=trace_path, manifest_path=manifest_path,
                replay_executable=self.replay_executable)
            stream_sizes = list(transaction["stream_reservation_sizes"])
        else:
            updated_buffer = bytearray(body.data)
            for begin, end, payload in spans:
                if len(payload) != end - begin:
                    raise ValueError("same-extent shader/image replacement changed a child extent")
                updated_buffer[begin:end] = payload
            updated = bytes(updated_buffer); transaction = None
            stream_sizes = list(profile["final_header"]["block_sizes"])
        if ZoneBody.parse(updated).assets != body.assets:
            raise ValueError("shader/image batch changed the XAsset table")
        packed = pack_replay_uncompressed(updated, stream_sizes,
                                          profile["final_header"]["xfile_version"],
                                          profile["header"]["transient_type"])
        if unpack_replay_uncompressed(packed) != updated:
            raise AssertionError("native FF framing changed the edited same-extent body")
        if output.exists() or any(output.with_suffix(ext).exists() for ext in (".fp", ".fc")):
            raise FileExistsError("replacement FF/patch output already exists")
        acts_before, replay_before = acts_tool_identity(self.acts_path), sha256_file(self.replay_executable)
        output.parent.mkdir(parents=True, exist_ok=True)
        sidecars = []
        try:
            output.write_bytes(packed)
            for patch in profile.get("patches", []):
                target = output.with_suffix(patch["extension"])
                target.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), packed))
                sidecars.append(dict(path=str(target), bytes=target.stat().st_size,
                                     sha256=sha256_file(target),
                                     replaces_stale_source_patch=str(patch["path"])))
            with tempfile.TemporaryDirectory(prefix="rwt-native-child-package-") as temporary:
                from roundtrip_replay_fastfile import verify_native
                native = verify_native(output, updated, source, self.acts_path,
                                       self.replay_executable, Path(temporary), timeout, trace=True)
            manifest = native["manifest"]
            if [Path(item).suffix for item in manifest.get("applied_patches", [])] != [
                    patch["extension"] for patch in profile.get("patches", [])]:
                raise ValueError("Replay did not apply the replacement shader/image patch chain")
            if (not manifest.get("complete") or not manifest.get("success") or
                    manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                    manifest.get("tested", -1) + len(manifest.get("reference_only_rows", [])) != len(native_rows) or
                    manifest.get("loaded_assets") != walk_receipt.get("loaded_assets") or
                    manifest.get("serialized_bytes_read") != len(updated)):
                raise ValueError("Replay full-zone reread did not match the source asset count/EOF")
            if native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256")) != ordered_asset_identity_sha256(native_rows):
                raise ValueError("same-extent edit changed native XAsset order, type, or names")
            highwaters = {int(key): value for key, value in
                          native.get("trace_summary", {}).get("max_destination_offsets", {}).items()}
            if any(highwaters.get(stream, 0) > stream_sizes[stream]
                   for stream in range(STREAM_COUNT)):
                raise ValueError("native shader/image stream high-water exceeds its packaged reservation")
            _assert_run_inputs_unchanged(source, profile, self.acts_path, acts_before,
                                         self.replay_executable, replay_before)
            if unpack_replay_uncompressed(output.read_bytes()) != updated:
                raise ValueError("published FF body differs from the validated replacement")
            receipt = dict(schema=("replay120-variable-native-child-package-v1" if transaction else
                                   "replay120-same-extent-native-child-package-v1"),
                           status=("native-full-zone-variable-child-package-pass" if transaction else
                                   "native-full-zone-same-extent-child-package-pass"),
                           source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                           native_walk_key=walk_receipt["walk_key"],
                           native_manifest_sha256=walk_receipt["manifest_sha256"],
                           stream_trace_sha256=walk_receipt["stream_trace_sha256"], edits=edit_receipts,
                           writer=dict(children_nonoverlapping=True,
                                       body_size_unchanged=not transaction,
                                       xasset_table_unchanged=True,
                                       stream_reservations_unchanged=not transaction,
                                       variable_transaction=transaction,
                                       edited_child_spans=[dict(begin=begin, end=end, bytes=end-begin)
                                                           for begin, end, _ in spans]),
                           output_fastfile=dict(path=str(output), bytes=output.stat().st_size,
                                                sha256=sha256_file(output), stream_reservations=stream_sizes),
                           sidecars=sidecars,
                           native_reader=dict(complete=manifest.get("complete"), success=manifest.get("success"),
                                              loaded_assets=manifest.get("loaded_assets"), tested=manifest.get("tested"),
                                              failed=manifest.get("failed"), unavailable=manifest.get("unavailable"),
                                              serialized_bytes_read=manifest.get("serialized_bytes_read"),
                                              trace_summary=native.get("trace_summary"),
                                              journal_sha256=native["journal_sha256"],
                                              journal_asset_identity_sha256=native["journal_asset_identity_sha256"],
                                              acts_tool_identity=native["acts_tool_identity"],
                                              replay_executable_sha256=native["replay_executable_sha256"]))
            receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            return dict(status=receipt["status"], zone_id=zone_id,
                        edits=[dict(asset_id=row["asset_id"], revision=row["revision"]) for row in edit_receipts],
                        output_fastfile=str(output), output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(receipt_path),
                        native_reader_status=manifest.get("status"),
                        native_reader_loaded=manifest.get("loaded_assets"),
                        native_reader_tested=manifest.get("tested"),
                        edit_proof=receipt["writer"], runtime_visual_status="not-tested")
        except Exception:
            output.unlink(missing_ok=True)
            for item in sidecars:
                Path(item["path"]).unlink(missing_ok=True)
            raise

    def _build_localize_replacement(self, zone_id: str, cache_path: Path,
                                    decode_receipt: dict, body: ZoneBody,
                                    plan: dict, output: Path, timeout: int) -> dict:
        """Package a trace-relocated Localize value batch with full Replay reread."""
        from workstation_localize import replace_localize_values_with_relocation
        from workstation_trace_index import build_read_span_index

        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk, native_rows = _read_native_rows(cache_path, body, require_trace=True)
        if (walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk.get("identity", {}).get("patch_sha256s") !=
                [patch["sha256"] for patch in profile.get("patches", [])]):
            raise ValueError("Localize native walk differs from the packaged source FF/patch chain")
        trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
        if (sha256_file(trace_path) != walk.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk.get("manifest_sha256")):
            raise ValueError("Localize package trace or manifest changed after preflight")
        from workstation_localize_inventory import read_localize_inventory, compare_localize_inventory
        baseline_root, baseline_index = _export_native_type(
            source, zone_id, body, cache_path, walk, native_rows, 41, "localize", self.acts_path,
            self.replay_executable, timeout)
        baseline_inventory = read_localize_inventory(baseline_root, baseline_index["items"],
                                                      native_rows, cached=True)
        selected = {int(row["asset_id"].rsplit(":", 1)[1]) for row in plan["edits"]}
        trace_index = build_read_span_index(trace_path, manifest_path, len(body.data),
                                            selected_assets=selected)
        traced = {row["index"]: row for row in trace_index["assets"]}
        edits, expected_values, edit_receipts = [], {}, []
        import workstation_localize as localize_module
        writer_path = Path(localize_module.__file__).resolve(strict=True)
        writer_hash = sha256_file(writer_path)
        for planned in plan["edits"]:
            index = int(planned["asset_id"].rsplit(":", 1)[1])
            pending_path = cache_path / "pending-edits" / str(index) / "current.json"
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            snapshot = pending_path.parent / f"{pending.get('revision', '')}.json"
            if (not snapshot.is_file() or pending != json.loads(snapshot.read_text(encoding="utf-8")) or
                                pending.get("schema") != 3 or
                    pending.get("revision") != planned.get("revision") or pending.get("type_id") != 41 or
                    pending.get("type") != "localize" or pending.get("name") != planned.get("name") or
                    pending.get("source_body_sha256") != body.source_sha256):
                raise ValueError("queued Localize revision differs from its immutable source snapshot")
            identity = pending.get("native_source_identity", {})
            if (identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    identity.get("native_walk_key") != walk.get("walk_key") or
                    identity.get("native_manifest_sha256") != walk.get("manifest_sha256") or
                    identity.get("stream_trace_sha256") != walk.get("stream_trace_sha256") or
                    identity.get("body_sha256") != body.source_sha256 or identity.get("xasset_index") != index):
                raise ValueError("queued Localize revision is tied to another source FF/body/trace")
            receipt = pending.get("compiler_receipt")
            canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")
            payload_path = pending_path.parent / pending["edited_payload_path"]
            payload = payload_path.read_bytes()
            compiler_staleness = self._compiler_identity_staleness(pending, 41)
            if sha256_file(writer_path) != writer_hash or compiler_staleness:
                raise ValueError(compiler_staleness or "Localize writer changed during package")
            if (hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256") or
                    receipt.get("status") != "replay120-localize-value-encode-pass" or
                    receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                    receipt.get("asset_name") != planned.get("name") or
                    receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256") or
                    sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                    payload != pending["content"].encode("utf-8") + b"\0"):
                raise ValueError("queued Localize payload/compiler receipt failed immutable validation")
            native = native_rows[index]
            trace_asset = traced.get(index)
            if (index >= len(body.assets) or body.assets[index].type_id != 41 or
                    native.get("type_id") != 41 or native.get("name") != planned.get("name") or
                    trace_asset is None):
                raise ValueError("queued Localize XAsset identity is absent from current native trace")
            trace_asset.update(index=index, xasset_index=index, type_id=41, name=planned["name"])
            edits.append(dict(asset_index=index, asset_name=planned["name"],
                              trace_asset=trace_asset, value=pending["content"]))
            expected_values[index] = pending["content"]
            edit_receipts.append(dict(asset_id=planned["asset_id"], revision=planned["revision"],
                                      content_sha256=_pending_content_sha(pending),
                                      edited_payload_sha256=sha256_file(payload_path),
                                      compiler_receipt_sha256=pending["compiler_receipt_sha256"],
                                      compiler_receipt=receipt))
        updated, relocation = replace_localize_values_with_relocation(
            body.data, edits, body.source_sha256, trace_path, manifest_path)
        if ZoneBody.parse(updated).assets != body.assets:
            raise AssertionError("Localize writer changed XAsset order or inventory")
        stream_sizes = list(profile["final_header"]["block_sizes"])
        if len(stream_sizes) != 11:
            raise ValueError("source FF does not carry all eleven Replay stream reservations")
        new_stream5_high_water = relocation.get("stream5_new_high_water")
        if not isinstance(new_stream5_high_water, int) or new_stream5_high_water < 0:
            raise ValueError("Localize relocation omitted its recalculated stream-5 high-water")
        stream_sizes[5] = max(stream_sizes[5], new_stream5_high_water)
        packed = pack_replay_uncompressed(updated, stream_sizes,
                                          profile["final_header"]["xfile_version"],
                                          profile["header"]["transient_type"])
        if unpack_replay_uncompressed(packed) != updated:
            raise AssertionError("native FF framing changed the Localize-edited body")
        if output.exists() or output.with_suffix(".fp").exists() or output.with_suffix(".fc").exists():
            raise FileExistsError("Localize package output or patch sidecar already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        acts_before, replay_before = acts_tool_identity(self.acts_path), sha256_file(self.replay_executable)
        output.write_bytes(packed)
        sidecars = []
        try:
            for patch in profile.get("patches", []):
                source_patch = Path(patch["path"]).resolve(strict=True)
                target = output.with_suffix(patch["extension"])
                target.write_bytes(make_replay_header_only_patch(source_patch.read_bytes(), packed))
                sidecars.append(dict(path=str(target), sha256=sha256_file(target), bytes=target.stat().st_size,
                                     replaces_stale_source_patch=str(source_patch)))
            reader_work = output.with_suffix(output.suffix + ".native-reader")
            if reader_work.exists():
                raise FileExistsError(reader_work)
            from roundtrip_replay_fastfile import verify_native
            native_read = verify_native(output, updated, source, self.acts_path,
                                        self.replay_executable, reader_work, timeout, trace=True)
            manifest = native_read["manifest"]
            if ([Path(item).suffix for item in manifest.get("applied_patches", [])] !=
                    [patch["extension"] for patch in profile.get("patches", [])]):
                raise ValueError("Replay did not apply the replacement Localize patch chain")
            if manifest.get("loaded_assets") != walk.get("loaded_assets"):
                raise ValueError("Localize batch changed the native loaded-asset count")
            if native_read.get("normalized_asset_identity_sha256", native_read.get("journal_asset_identity_sha256")) != ordered_asset_identity_sha256(native_rows):
                raise ValueError("Localize batch changed native XAsset type/order/name identity")
            if unpack_replay_uncompressed(output.read_bytes()) != updated:
                raise ValueError("packaged Localize body differs from the relocated source body")
            # ACTS exports the values parsed back through the native reader. Bind the
            # complete JSON inventory to exact XAsset indices and verify every
            # retained value and its order, including unedited alias targets.
            # ACTS writes one file per Localize entry and older Windows builds
            # can fail those writes when the output root is nested under the
            # long workstation cache path. Keep only this transient export in
            # the short system temp root; the input FF keeps its caller-chosen
            # basename (including eng_code_post_gfx.ff).
            reader_work.mkdir(parents=True, exist_ok=True)
            semantic_log = reader_work / "localize-semantic-export.log"
            semantic_diagnostic = reader_work / "localize-semantic-export-diagnostic.json"
            with tempfile.TemporaryDirectory(prefix="rwtloc-") as temporary_export_root:
                export_root = Path(temporary_export_root)
                if len(str(export_root)) > 80:
                    raise ValueError("system temporary directory is too long for safe ACTS asset export")
                command = [str(self.acts_path), "--noUpdater", "fastfile", "-r", "mw19replay",
                           "-g", str(self.replay_executable), "-o", str(export_root),
                           "-a", "localize", "-l", str(output)]
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, check=False, timeout=timeout)
                semantic_log.write_text(completed.stdout or "", encoding="utf-8")
                manifests = list(export_root.glob("mw19replay/*/manifest.json"))
                diagnostic = dict(command=command, return_code=completed.returncode,
                                  stdout_path=str(semantic_log),
                                  temporary_export_root=str(export_root),
                                  exported_basename=output.name,
                                  manifest_count=len(manifests))
                if len(manifests) == 1:
                    export_manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
                    diagnostic["manifest"] = {key: export_manifest.get(key) for key in
                                              ("profile", "complete", "success", "tested", "failed",
                                               "unavailable", "loaded_assets", "serialized_bytes_read")}
                    journal_path = manifests[0].parent / export_manifest.get("journal", "assets.jsonl")
                    diagnostic["journal_exists"] = journal_path.is_file()
                    if journal_path.is_file() and (completed.returncode != 0 or
                            not export_manifest.get("success") or export_manifest.get("failed") != 0 or
                            export_manifest.get("unavailable") != 0):
                        # Preserve the failed-entry details before TemporaryDirectory
                        # removes ACTS's potentially huge payload tree.
                        shutil.copy2(manifests[0], reader_work / "localize-semantic-export-manifest.json")
                        shutil.copy2(journal_path, reader_work / "localize-semantic-export-assets.jsonl")
                semantic_diagnostic.write_text(json.dumps(diagnostic, indent=2) + "\n",
                                                encoding="utf-8")
                if completed.returncode != 0 or len(manifests) != 1:
                    raise ValueError(
                        f"ACTS Localize semantic export failed; see {semantic_log} and {semantic_diagnostic}")
                export_manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
                journal_path = manifests[0].parent / export_manifest.get("journal", "assets.jsonl")
                exported = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
                            if line.strip()]
                if (not export_manifest.get("complete") or not export_manifest.get("success") or
                        export_manifest.get("failed") != 0 or export_manifest.get("unavailable") != 0 or
                        export_manifest.get("tested") != len([row for row in native_rows if row.get("type_id") == 41])):
                    raise ValueError(
                        f"ACTS Localize semantic export did not cover the complete type-41 inventory; "
                        f"see {semantic_log} and {semantic_diagnostic}")
                actual_inventory = read_localize_inventory(manifests[0].parent, exported, native_rows)
                semantic_comparison = compare_localize_inventory(
                    baseline_inventory, actual_inventory,
                    {native_rows[index]["name"]: value for index, value in expected_values.items()})
                semantic_readback = [{key: row[key] for key in ("asset_index", "name", "value_sha256")}
                                     for row in actual_inventory if row["asset_index"] in expected_values]
                diagnostic["semantic_readback"] = semantic_comparison
                semantic_diagnostic.write_text(json.dumps(diagnostic, indent=2) + "\n",
                                               encoding="utf-8")
            _assert_run_inputs_unchanged(source, profile, self.acts_path, acts_before,
                                         self.replay_executable, replay_before)
            proof = dict(schema="replay120-localize-trace-relocated-batch-package-v1",
                         status="native-full-zone-localize-batch-package-pass",
                         source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                         native_walk_key=walk["walk_key"], native_manifest_sha256=walk["manifest_sha256"],
                         stream_trace_sha256=walk["stream_trace_sha256"], edits=edit_receipts,
                         relocation=relocation,
                         output_fastfile=dict(path=str(output), sha256=sha256_file(output),
                                              bytes=output.stat().st_size, stream_reservations=stream_sizes),
                         sidecars=sidecars,
                         native_reader=dict(complete=manifest.get("complete"), success=manifest.get("success"),
                                            loaded_assets=manifest.get("loaded_assets"),
                                            tested=manifest.get("tested"), failed=manifest.get("failed"),
                                            unavailable=manifest.get("unavailable"),
                                            serialized_bytes_read=manifest.get("serialized_bytes_read"),
                                            journal_sha256=native_read["journal_sha256"],
                                            journal_asset_identity_sha256=native_read["journal_asset_identity_sha256"],
                                            trace_summary=native_read.get("trace_summary")),
                         semantic_readback=dict(**semantic_comparison, edits=semantic_readback,
                                                baseline_export_key=baseline_index["export_key"],
                                                baseline_index_sha256=sha256_file(
                                                    baseline_root / "asset-payload-index.json")),
                         semantic_export=dict(output_basename=output.name,
                                              temporary_root=str(export_root),
                                              temporary_root_cleaned=True,
                                              stdout_path=str(semantic_log),
                                              stdout_sha256=sha256_file(semantic_log),
                                              diagnostic_path=str(semantic_diagnostic),
                                              diagnostic_sha256=sha256_file(semantic_diagnostic)),
                         support_limit="NUL-free UTF-8 ordinary/shared-inline Localize values; "
                                       "other Localize values sharing edited text are preserved; "
                                       "keys and XAsset rows are immutable; unsupported aliases fail closed")
            proof_path = output.with_suffix(output.suffix + ".edit-receipt.json")
            proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
            return dict(schema=proof["schema"], status=proof["status"], zone_id=zone_id,
                        edits=[dict(asset_id=row["asset_id"], revision=row["revision"]) for row in edit_receipts],
                        output_fastfile=str(output), output_fastfile_sha256=proof["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(proof_path),
                        native_reader_status=manifest.get("status"),
                        native_reader_loaded=manifest.get("loaded_assets"),
                        semantic_readback=proof["semantic_readback"], edit_proof=relocation,
                        support_limit=proof["support_limit"])
        except Exception:
            output.unlink(missing_ok=True)
            for row in sidecars:
                Path(row["path"]).unlink(missing_ok=True)
            raise

    def _build_luafile_replacement(self, zone_id: str, cache_path: Path,
                                   decode_receipt: dict, body: ZoneBody,
                                   plan: dict, output: Path, timeout: int) -> dict:
        """Build LuaFile-only or mixed edits and verify the native zone reader."""
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
            raise UnsupportedAssetGraphError("source FC replacement semantics are not yet proven")
        walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
        if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk_receipt.get("identity", {}).get("patch_sha256s") !=
                [patch["sha256"] for patch in profile.get("patches", [])]):
            raise ValueError("LuaFile native walk differs from current source FF/patch chain")
        trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
        if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
            raise ValueError("LuaFile trace/manifest changed after preflight")
        mixed = plan.get("support") == "mixed-scriptfile-luafile-full-trace-relocation"
        lua_indices = [int(item["asset_id"].rsplit(":", 1)[1])
                       for item in plan["edits"] if item.get("type") == "luafile"]
        script_indices = ([i for i, asset in enumerate(body.assets) if asset.type_id == 52]
                          if mixed else [])
        indices = sorted(set(lua_indices) | set(script_indices))
        trace_index = __import__("workstation_trace_index").build_read_span_index(
            trace_path, manifest_path, len(body.data), selected_assets=set(indices))
        traced = {row["index"]: row for row in trace_index["assets"]}
        lua_edits, script_edits = [], []
        edit_receipts = []
        for planned in plan["edits"]:
            index = int(planned["asset_id"].rsplit(":", 1)[1])
            expected_type = 52 if planned.get("type") == "scriptfile" else 62
            if (index >= len(native_rows) or native_rows[index].get("type_id") != expected_type or
                    body.assets[index].type_id != expected_type):
                raise ValueError("queued asset no longer matches its native XAsset row")
            pending_path = cache_path / "pending-edits" / str(index) / "current.json"
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            snapshot_path = pending_path.parent / f"{pending.get('revision', '')}.json"
            if (pending != json.loads(snapshot_path.read_text(encoding="utf-8")) or
                    pending.get("revision") != planned.get("revision") or
                    pending.get("source_body_sha256") != body.source_sha256 or
                    hashlib.sha256(str(pending.get("content", "")).encode("utf-8")).hexdigest() != _pending_content_sha(pending)):
                raise ValueError("queued LuaFile revision changed after preflight")
            source_identity = pending.get("native_source_identity", {})
            if (source_identity.get("body_sha256") != body.source_sha256 or
                    source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
                    source_identity.get("native_walk_key") != walk_receipt.get("walk_key") or
                    source_identity.get("native_manifest_sha256") != walk_receipt.get("manifest_sha256") or
                    source_identity.get("stream_trace_sha256") != walk_receipt.get("stream_trace_sha256")):
                raise ValueError("queued LuaFile source identity no longer matches the current zone trace")
            compiler_receipt = pending.get("compiler_receipt")
            stale_compiler = self._compiler_identity_staleness(pending, expected_type)
            if stale_compiler:
                raise ValueError(stale_compiler)
            encoded_receipt = json.dumps(compiler_receipt, sort_keys=True,
                                         separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            expected_status = ("gsc-tool-native-payload-pass" if expected_type == 52
                               else "target-lua-loadx-reload-pass")
            if (hashlib.sha256(encoded_receipt).hexdigest() != pending.get("compiler_receipt_sha256") or
                    compiler_receipt.get("status") != expected_status or
                    compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                    compiler_receipt.get("asset_name") != planned.get("name")):
                raise ValueError("queued native compiler receipt changed or does not match its source")
            payload_path = pending_path.parent / pending["edited_payload_path"]
            payload = payload_path.read_bytes()
            if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                    hashlib.sha256(payload).hexdigest() != compiler_receipt.get("result", {}).get("native_payload_sha256")):
                raise ValueError("queued LuaFile native payload changed after staging")
            if expected_type == 52:
                tool = DEFAULT_GSC_TOOL.resolve(strict=True)
                compiler = compiler_receipt.get("compiler", {})
                if (compiler.get("path") != str(tool) or
                        compiler.get("tool_identity") != acts_tool_identity(tool)):
                    raise ValueError("queued GSC compiler identity changed after preflight")
                script_edits.append(dict(xasset_index=index, name=planned["name"], payload=payload))
            else:
                trace_asset = traced.get(index)
                if trace_asset is None or native_rows[index].get("name") != planned.get("name"):
                    raise ValueError("queued LuaFile lacks its matching native trace/name row")
                trace_asset.update(xasset_index=index, type_id=62, name=planned["name"])
                lua_edits.append(dict(asset_index=index, asset_name=planned["name"],
                                      trace_asset=trace_asset, payload=payload))
            edit_receipts.append(dict(asset_id=planned["asset_id"], revision=planned["revision"],
                                      edited_payload_sha256=sha256_file(payload_path),
                                      compiler_receipt_sha256=pending["compiler_receipt_sha256"],
                                      compiler_receipt=compiler_receipt))

        if mixed:
            from workstation_mixed_script_luafile import replace_mixed_script_luafile_batch
            updated, relocation = replace_mixed_script_luafile_batch(
                body.data, script_edits, lua_edits, body.source_sha256,
                str(trace_path), str(manifest_path), trace_index, native_rows,
                list(profile["final_header"]["block_sizes"]))
        else:
            from workstation_luafile import replace_luafiles_inline_children
            updated, relocation = replace_luafiles_inline_children(
                body.data, lua_edits, body.source_sha256, trace_path, manifest_path)
        stream_sizes = list(relocation.get("stream_reservation_sizes") or
                            profile["final_header"]["block_sizes"])
        packed = pack_replay_uncompressed(
            updated, stream_sizes, profile["final_header"]["xfile_version"],
            profile["header"]["transient_type"])
        if unpack_replay_uncompressed(packed) != updated:
            raise AssertionError("native IWC framing changed the relocated LuaFile body")
        if output.exists():
            raise FileExistsError(output)
        for extension in (".fp", ".fc"):
            if output.with_suffix(extension).exists():
                raise FileExistsError(output.with_suffix(extension))

        acts_before = acts_tool_identity(self.acts_path)
        replay_before = sha256_file(self.replay_executable)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(packed)
        sidecars = []
        for patch in profile.get("patches", []):
            source_patch = Path(patch["path"]).resolve(strict=True)
            target_patch = output.with_suffix(patch["extension"])
            target_patch.write_bytes(make_replay_header_only_patch(source_patch.read_bytes(), packed))
            sidecars.append(dict(path=str(target_patch), bytes=target_patch.stat().st_size,
                                 sha256=sha256_file(target_patch),
                                 replaces_stale_source_patch=str(source_patch)))
        try:
            with tempfile.TemporaryDirectory(prefix="rwt-luafile-package-") as temporary:
                from roundtrip_replay_fastfile import verify_native
                native = verify_native(output, updated, source, self.acts_path,
                                       self.replay_executable, Path(temporary), timeout, trace=True)
            manifest = native["manifest"]
            applied = manifest.get("applied_patches", [])
            if [Path(item).suffix for item in applied] != [patch["extension"] for patch in profile.get("patches", [])]:
                raise ValueError("Replay did not apply the replacement LuaFile patch chain")
            if manifest.get("loaded_assets") != walk_receipt.get("loaded_assets"):
                raise ValueError("LuaFile replacement changed the exact native loaded-asset count")
            if native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256")) != ordered_asset_identity_sha256(native_rows):
                raise ValueError("LuaFile replacement changed native XAsset type/order/name journal")
            native_highwaters = {int(key): value for key, value in
                                 native["trace_summary"]["max_destination_offsets"].items()}
            if any(native_highwaters.get(stream, 0) > stream_sizes[stream]
                   for stream in range(STREAM_COUNT)):
                raise ValueError("native LuaFile stream high-water exceeds an FF reservation")
            expected_stream5 = relocation.get("stream5_new_high_water", relocation.get("stream5_high_water"))
            if expected_stream5 is not None and native_highwaters.get(5) != expected_stream5:
                raise ValueError("native stream-5 high-water differs from LuaFile relocation plan")
            expected_stream6 = relocation.get("stream6_high_water")
            if expected_stream6 is not None and native_highwaters.get(6) != expected_stream6:
                raise ValueError("native stream-6 high-water differs from mixed ScriptFile relocation plan")
            _assert_run_inputs_unchanged(source, profile, self.acts_path, acts_before,
                                         self.replay_executable, replay_before)
            body_output = unpack_replay_uncompressed(output.read_bytes())
            if body_output != updated:
                raise ValueError("packaged LuaFile body differs from relocated source body")
            proof = dict(schema=("replay120-mixed-scriptfile-luafile-workspace-package-v1" if mixed
                                 else "replay120-luafile-workspace-package-v1"),
                         status=("native-full-zone-mixed-scriptfile-luafile-package-pass" if mixed
                                 else "native-full-zone-luafile-package-pass"),
                         source_fastfile_sha256=profile["sha256"],
                         source_body_sha256=body.source_sha256,
                         native_walk_key=walk_receipt["walk_key"],
                         native_manifest_sha256=walk_receipt["manifest_sha256"],
                         stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                         edits=edit_receipts, relocation=relocation,
                         output_fastfile=dict(path=str(output), bytes=output.stat().st_size,
                                             sha256=sha256_file(output),
                                             stream_reservations=stream_sizes),
                         sidecars=sidecars,
                         native_reader=dict(complete=manifest.get("complete"), success=manifest.get("success"),
                                            loaded_assets=manifest.get("loaded_assets"),
                                            tested=manifest.get("tested"), failed=manifest.get("failed"),
                                            unavailable=manifest.get("unavailable"),
                                            serialized_bytes_read=manifest.get("serialized_bytes_read"),
                                            trace_summary=native.get("trace_summary"),
                                            journal_sha256=native["journal_sha256"],
                                            journal_asset_identity_sha256=native["journal_asset_identity_sha256"],
                                            acts_tool_identity=native["acts_tool_identity"],
                                            replay_executable_sha256=native["replay_executable_sha256"]))
            receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
            receipt_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
            return dict(schema=proof["schema"], status=proof["status"], zone_id=zone_id,
                        edits=[dict(asset_id=row["asset_id"], revision=row["revision"])
                               for row in edit_receipts],
                        output_fastfile=str(output),
                        output_fastfile_sha256=proof["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(receipt_path),
                        native_reader_status=manifest.get("status"),
                        native_reader_loaded=manifest.get("loaded_assets"),
                        native_reader_tested=manifest.get("tested"),
                        edit_proof=relocation,
                        compiler_receipts=[dict(asset_id=row["asset_id"],
                                                compiler_receipt_sha256=row["compiler_receipt_sha256"],
                                                compiler_receipt=row["compiler_receipt"])
                                           for row in edit_receipts],
                        support_limit=("Mixed stream-5/stream-6 edits use one full-zone trace; only ScriptFile+LuaFile "
                                       "transactions with typed inline children and no stream-6 packed targets are supported"
                                       if mixed else
                                       "LuaFile-only transactions use the full-zone stream-5 relocator"))
        except Exception:
            output.unlink(missing_ok=True)
            for row in sidecars:
                Path(row["path"]).unlink(missing_ok=True)
            raise

    def _build_multiple_stringtable_replacement(self, zone_id: str, cache_path: Path,
                                               decode_receipt: dict, body: ZoneBody,
                                               plan: dict, output: Path,
                                               timeout: int) -> dict:
        """Apply distinct staged StringTables in sequence, retracing every result."""
        planned_edits = list(plan.get("edits", []))
        if len(planned_edits) < 2:
            raise ValueError("multi-StringTable packaging requires at least two staged tables")
        closure_contract = plan.get("proof", {}).get("omnvar_closure")
        if closure_contract is not None:
            closure_indices = closure_contract.get("table_indices")
            root_index = closure_contract.get("root_index")
            effective_contract = closure_contract.get("effective_validation")
            if (not isinstance(closure_indices, list) or type(root_index) is not int or
                    any(type(index) is not int for index in closure_indices) or
                    not isinstance(effective_contract, dict) or
                    effective_contract.get("status") != "effective-native-bound-closure-validated" or
                    not re.fullmatch(r"[0-9a-f]{64}", str(closure_contract.get("source_closure_sha256", ""))) or
                    not re.fullmatch(r"[0-9a-f]{64}", str(effective_contract.get("validation_sha256", "")))):
                raise ValueError("multi-StringTable Omnvar closure contract is malformed")
            edited_indices = {int(row["asset_id"].rsplit(":", 1)[1]) for row in planned_edits}
            planned_closure_indices = sorted(edited_indices & set(closure_indices))
            if planned_closure_indices != closure_contract.get("staged_table_indices"):
                raise ValueError("planned Omnvar staged members differ from the combined closure proof")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
        if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk_receipt.get("identity", {}).get("patch_sha256s") !=
                [patch["sha256"] for patch in profile.get("patches", [])]):
            raise ValueError("StringTable walk differs from current source FF/patch chain")
        if (not walk_receipt.get("stream_trace_enabled") or
                any(patch.get("extension") != ".fp" for patch in profile.get("patches", []))):
            raise UnsupportedAssetGraphError(
                "multi-StringTable packaging requires the complete verified FP trace contract")
        if len(profile.get("patches", [])) > 1:
            raise UnsupportedAssetGraphError(
                "multi-StringTable packaging currently supports at most one source FP sidecar")
        original_trace = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
        original_manifest = _native_walk_artifact(walk_receipt, "manifest_relative_path")
        if (sha256_file(original_trace) != walk_receipt.get("stream_trace_sha256") or
                sha256_file(original_manifest) != walk_receipt.get("manifest_sha256")):
            raise ValueError("StringTable source trace or manifest changed after preflight")

        indices = [int(row["asset_id"].rsplit(":", 1)[1]) for row in planned_edits]
        if len(set(indices)) != len(indices):
            raise ValueError("multi-StringTable plan contains duplicate XAsset indices")
        from workstation_asset_codecs import encode_stringtable_sections
        from workstation_stringtable import inspect_stringtable, replace_stringtable_rows
        from workstation_trace_index import build_read_span_index
        from roundtrip_replay_fastfile import verify_native

        # Export and pin every source table once. These payloads are the baseline
        # for retained-table semantic comparisons after the final native reread.
        export_root, export_index = _export_native_type(
            source, zone_id, body, cache_path, walk_receipt, native_rows,
            54, "stringtable", self.acts_path, self.replay_executable)
        source_items = {int(row["asset_index"]): row for row in export_index["items"]}
        source_closure = None
        source_rows_by_index = {}
        if closure_contract is not None:
            closure_indices = set(closure_contract["table_indices"])
            source_rows_by_index = _native_stringtable_export_rows(
                export_root, export_index, closure_indices)
            root_name = native_rows[root_index].get("name")
            if (not isinstance(root_name, str) or
                    root_name.replace("\\", "/").casefold() != "omnvars/mp/omnvars.csv" or
                    root_index not in source_rows_by_index):
                raise ValueError("Omnvar root native identity changed since combined preflight")
            source_closure_proof, _ = _prepare_omnvar_mp_source_proof(
                source=source, zone_id=zone_id, body=body, cache_path=cache_path,
                walk_receipt=walk_receipt, native_rows=native_rows, root_index=root_index,
                root_name=root_name, original_rows=source_rows_by_index[root_index],
                export_root=export_root, export_index=export_index,
                trace_path=original_trace, manifest_path=original_manifest)
            source_closure = source_closure_proof.get("source_closure")
            current_indices = sorted(item.get("asset_index") for item in source_closure.get("tables", [])
                                     if type(item.get("asset_index")) is int)
            if (current_indices != sorted(closure_indices) or
                    _omnvar_validation_sha256(source_closure) !=
                    closure_contract["source_closure_sha256"]):
                raise ValueError("native Omnvar closure changed since combined preflight")
        original_trace_index = build_read_span_index(
            original_trace, original_manifest, len(body.data))
        original_traces = {int(row["index"]): row for row in original_trace_index["assets"]}
        staged = []
        for planned in sorted(planned_edits, key=lambda row: int(row["asset_id"].rsplit(":", 1)[1])):
            index = int(planned["asset_id"].rsplit(":", 1)[1])
            if (index < 0 or index >= len(body.assets) or body.assets[index].type_id != 54 or
                    native_rows[index].get("type_id") != 54 or
                    native_rows[index].get("name") != planned.get("name")):
                raise ValueError("staged StringTable identity differs from its original native XAsset row")
            source_item = source_items.get(index)
            if source_item is None or source_item.get("name") != planned.get("name"):
                raise ValueError("native source export does not uniquely contain the staged StringTable")
            pending_path = (cache_path / "pending-edits" / str(index) / "current.json").resolve(strict=True)
            if not pending_path.is_relative_to(cache_path.resolve(strict=True)):
                raise ValueError("planned StringTable path escapes its zone cache")
            if ("pending_path" in planned and
                    Path(planned["pending_path"]).resolve(strict=True) != pending_path):
                raise ValueError("planned StringTable path differs from its selected native row")
            _current, pending, payload_path = _validate_pending_snapshot(
                cache_path, index, planned["asset_id"], body)
            if pending.get("revision") != planned.get("revision") or pending.get("name") != planned.get("name"):
                raise ValueError("StringTable revision changed after preflight")
            stale = self._staged_asset_staleness(
                pending, body, index, native_rows[index], walk_receipt, source)
            if stale:
                raise ValueError(stale)
            receipt = pending.get("compiler_receipt")
            canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")
            if (not isinstance(receipt, dict) or
                    hashlib.sha256(canonical).hexdigest() != pending.get("compiler_receipt_sha256") or
                    receipt.get("status") != "replay120-stringtable-encode-pass" or
                    receipt.get("asset_name") != planned.get("name") or
                    receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                    sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                    receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
                raise ValueError("StringTable compiler receipt or payload changed after preflight")
            stale_compiler = self._compiler_identity_staleness(pending, 54)
            if stale_compiler:
                raise ValueError(stale_compiler)
            edited_rows = list(csv.reader(io.StringIO(pending["content"], newline="")))
            sections = encode_stringtable_sections(planned["name"], edited_rows)
            expected_payload = json.dumps(
                dict(schema=1, kind="stringtable-sections", name=sections["name"],
                     rows=sections["rows"], columns=sections["columns"],
                     header_base64=base64.b64encode(sections["header"]).decode("ascii"),
                     cells_base64=base64.b64encode(sections["cells"]).decode("ascii"),
                     hashes_base64=base64.b64encode(sections["hashes"]).decode("ascii"),
                     dictionary=sections["dictionary"]),
                sort_keys=True, separators=(",", ":")).encode("utf-8")
            if payload_path.read_bytes() != expected_payload:
                raise ValueError("StringTable encoded sections differ from the immutable staged CSV")
            original_payload = (export_root / source_item["payload_relative_path"]).read_bytes()
            original_rows = list(csv.reader(io.StringIO(
                original_payload.decode("utf-8-sig"), newline="")))
            trace_asset = original_traces.get(index)
            if trace_asset is None or trace_asset.get("type_id") != 54:
                raise ValueError("complete source trace omits a staged StringTable")
            trace_asset.update(xasset_index=index, type_id=54, name=planned["name"])
            layout, _ = inspect_stringtable(
                body.data, index, planned["name"], trace_asset, original_rows,
                body.source_sha256,
                global_string_data_spans=original_trace_index.get("string_data_spans", []))
            source_identity = pending.get("native_source_identity", {})
            if (source_identity.get("root_span", {}).get("archive_offset") != layout.root_archive_offset or
                    source_identity.get("record_span", {}).get("archive_offset") != layout.root_archive_offset or
                    source_identity.get("record_span", {}).get("sha256") != layout.source_record_sha256):
                raise ValueError("StringTable typed source spans differ from the immutable staged edit")
            omnvar_proof = None
            if planned["name"].replace("\\", "/").casefold() == "omnvars/mp/omnvars.csv":
                omnvar_proof, _ = _prepare_omnvar_mp_source_proof(
                    source=source, zone_id=zone_id, body=body, cache_path=cache_path,
                    walk_receipt=walk_receipt, native_rows=native_rows, root_index=index,
                    root_name=planned["name"], original_rows=original_rows,
                    edited_rows=edited_rows, export_root=export_root,
                    export_index=export_index, trace_path=original_trace,
                    manifest_path=original_manifest)
                if receipt.get("omnvar_mp_validation") != omnvar_proof:
                    raise ValueError("Omnvar native validation differs from the saved StringTable edit")
                modules = omnvar_proof.get("modules", {})
                if not modules or any(sha256_file(item["path"]) != item["sha256"]
                                      for item in modules.values()):
                    raise ValueError("Omnvar validation modules changed after staging")
            staged.append(dict(planned=planned, pending=pending, index=index,
                               original_rows=original_rows, edited_rows=edited_rows,
                               original_trace_asset=trace_asset))

        if closure_contract is not None:
            staged_closure_rows = {
                edit["index"]: dict(rows=edit["edited_rows"],
                                    revision=edit["planned"].get("revision"))
                for edit in staged if edit["index"] in closure_contract["table_indices"]
            }
            effective_validation = _validate_omnvar_effective_closure(
                source_closure, source_rows_by_index, staged_closure_rows)
            if (effective_validation.get("validation_sha256") !=
                    closure_contract["effective_validation"].get("validation_sha256")):
                raise ValueError("effective Omnvar closure edits differ from the validated batch plan")

        if output.exists():
            raise FileExistsError(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
        if receipt_path.exists():
            raise FileExistsError(receipt_path)
        verification_root = cache_path / "package-verification"
        verification_root.mkdir(parents=True, exist_ok=True)
        case_root = Path(tempfile.mkdtemp(prefix="stringtable-batch-", dir=verification_root))
        stage_body = body.data
        reservations = [int(value) for value in profile["final_header"]["block_sizes"]]
        trace_path, manifest_path = original_trace, original_manifest
        stage_receipts = []
        final_stage = None
        created_outputs = []
        acts_before, replay_before = acts_tool_identity(self.acts_path), sha256_file(self.replay_executable)
        try:
            for ordinal, edit in enumerate(staged, 1):
                current_body = ZoneBody.parse(stage_body)
                index = edit["index"]
                if (index >= len(current_body.assets) or current_body.assets[index].type_id != 54 or
                        native_rows[index].get("name") != edit["planned"].get("name")):
                    raise ValueError("relocated native table identity no longer matches its immutable source target")
                trace_index = build_read_span_index(trace_path, manifest_path, len(stage_body))
                traced = next((row for row in trace_index["assets"] if row.get("index") == index), None)
                if traced is None or traced.get("type_id") != 54:
                    raise ValueError("fresh complete native trace omits the next StringTable edit target")
                traced.update(xasset_index=index, type_id=54,
                              name=edit["planned"]["name"])
                next_body, relocation = replace_stringtable_rows(
                    stage_body, index, edit["planned"]["name"], traced,
                    edit["original_rows"], edit["edited_rows"],
                    hashlib.sha256(stage_body).hexdigest(), trace_path, manifest_path,
                    full_trace_index=trace_index)
                if ZoneBody.parse(next_body).assets != body.assets:
                    raise ValueError("StringTable relocation changed the XAsset table")
                deltas = relocation["stream_reservation_deltas"]
                next_reservations = [reservations[stream] + int(deltas.get(str(stream), 0))
                                     for stream in range(STREAM_COUNT)]
                if any(value < 0 for value in next_reservations):
                    raise ValueError("sequential StringTable relocation produced a negative reservation")
                packed = pack_replay_uncompressed(
                    next_body, next_reservations,
                    profile["final_header"]["xfile_version"],
                    profile["header"]["transient_type"])
                if unpack_replay_uncompressed(packed) != next_body:
                    raise AssertionError("sequential StringTable FF framing changed the relocated body")
                stage_dir = case_root / f"stage-{ordinal:02d}"
                stage_dir.mkdir()
                # ACTS selects a native zone by its canonical fastfile stem,
                # and its Windows file enumerator silently skips legacy paths
                # at the MAX_PATH boundary. Keep the temporary input short.
                stage_input_dir = Path(tempfile.mkdtemp(prefix="stm-"))
                stage_ff = stage_input_dir / f"{source.stem}.ff"
                stage_ff.write_bytes(packed)
                stage_sidecar = stage_ff.with_suffix(".fp")
                if profile.get("patches"):
                    source_patch = Path(profile["patches"][0]["path"]).resolve(strict=True)
                    stage_sidecar.write_bytes(make_replay_header_only_patch(source_patch.read_bytes(), packed))
                native = verify_native(stage_ff, next_body, source, self.acts_path,
                                       self.replay_executable, stage_dir / "native", timeout, trace=True)
                manifest = native["manifest"]
                if ([Path(path).suffix for path in manifest.get("applied_patches", [])] !=
                        [".fp" for _ in profile.get("patches", [])] or
                        manifest.get("loaded_assets") != walk_receipt.get("loaded_assets") or
                        native.get("normalized_asset_identity_sha256",
                                   native.get("journal_asset_identity_sha256")) !=
                        ordered_asset_identity_sha256(native_rows)):
                    raise ValueError("sequential StringTable native reread changed patch, count, or ordered identity")
                highwaters = {int(key): value for key, value in
                              native["trace_summary"]["max_destination_offsets"].items()}
                if (any(highwaters.get(stream, 0) > next_reservations[stream]
                        for stream in range(STREAM_COUNT)) or
                        highwaters.get(5) != relocation.get("new_stream5_high_water")):
                    raise ValueError("sequential StringTable native high-water differs from relocation proof")
                raw_manifest_path = Path(native["raw_manifest_path"]).resolve(strict=True)
                raw_manifest = json.loads(raw_manifest_path.read_text(encoding="utf-8"))
                trace_path = raw_manifest_path.parent / raw_manifest.get("stream_trace", "stream-trace.jsonl")
                manifest_path = raw_manifest_path
                stage_receipts.append(dict(ordinal=ordinal, asset_id=edit["planned"]["asset_id"],
                                           revision=edit["planned"]["revision"],
                                           relocation=relocation,
                                           package_sha256=sha256_file(stage_ff),
                                           native=native, reservations=next_reservations))
                stage_body, reservations = next_body, next_reservations
                final_stage = (stage_ff, stage_sidecar if stage_sidecar.exists() else None,
                               native, next_body)

            if final_stage is None:
                raise AssertionError("multi-StringTable loop produced no package stage")
            stage_ff, stage_fp, native, final_body = final_stage
            source_profile_row = profile
            _assert_run_inputs_unchanged(source, source_profile_row, self.acts_path,
                                         acts_before, self.replay_executable, replay_before)
            raw_manifest_path = Path(native["raw_manifest_path"]).resolve(strict=True)
            trace_path = raw_manifest_path.parent / native["manifest"].get("stream_trace", "stream-trace.jsonl")
            trace_sha = native.get("trace_summary", {}).get("stream_trace_sha256")
            journal_path = raw_manifest_path.parent / native["manifest"].get("journal", "assets.jsonl")
            if sha256_file(trace_path) != trace_sha or sha256_file(journal_path) != native.get("journal_sha256"):
                raise ValueError("final StringTable native trace or journal changed before semantic export")
            output_profile = source_profile(stage_ff)
            output_patch_sha256s = [row["sha256"] for row in output_profile.get("patches", [])]
            output_body_sha = hashlib.sha256(final_body).hexdigest()
            output_walk_binding = dict(output_fastfile_sha256=output_profile["sha256"],
                                       output_patch_sha256s=output_patch_sha256s,
                                       output_body_sha256=output_body_sha,
                                       raw_manifest_sha256=native["raw_manifest_sha256"],
                                       stream_trace_sha256=trace_sha,
                                       journal_sha256=native["journal_sha256"],
                                       normalized_asset_identity_sha256=native.get("normalized_asset_identity_sha256"),
                                       tested=native["manifest"].get("tested"),
                                       top_level_index=native["manifest"].get("top_level_index"),
                                       serialized_bytes_read=native["manifest"].get("serialized_bytes_read"))
            output_walk_key = hashlib.sha256(json.dumps(
                output_walk_binding, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            output_walk = dict(walk_key=output_walk_key,
                               identity=dict(source_sha256=output_profile["sha256"],
                                             patch_sha256s=output_patch_sha256s))
            candidate_root, candidate_index = _export_native_type(
                stage_ff, zone_id, ZoneBody.parse(final_body), case_root / "semantic-export",
                output_walk, native_rows, 54, "stringtable", self.acts_path,
                self.replay_executable, timeout_seconds=timeout)
            source_doc = json.loads((export_root / "asset-payload-index.json").read_text(encoding="utf-8"))
            candidate_doc = json.loads((candidate_root / "asset-payload-index.json").read_text(encoding="utf-8"))
            if len(source_doc.get("items", [])) != len(candidate_doc.get("items", [])):
                raise ValueError("final native export changed the number of StringTable assets")
            expected_by_identity = {
                (row["index"], row["planned"]["name"]): row["edited_rows"] for row in staged}
            source_payloads, candidate_payloads = {}, {}
            for doc, root, result in ((source_doc, export_root, source_payloads),
                                       (candidate_doc, candidate_root, candidate_payloads)):
                for row in doc["items"]:
                    identity = (row["asset_index"], row["name"])
                    payload_path = (root / row["payload_relative_path"]).resolve(strict=True)
                    if not payload_path.is_relative_to(root.resolve(strict=True)) or sha256_file(payload_path) != row["payload_sha256"]:
                        raise ValueError("StringTable semantic export payload failed path/hash verification")
                    result[identity] = payload_path.read_bytes()
            if set(source_payloads) != set(candidate_payloads):
                raise ValueError("final native export changed the StringTable identity set or order")
            retained_checked = edited_checked = 0
            for identity, source_payload in source_payloads.items():
                candidate_payload = candidate_payloads[identity]
                if identity in expected_by_identity:
                    actual = list(csv.reader(io.StringIO(candidate_payload.decode("utf-8-sig"), newline="")))
                    if actual != expected_by_identity[identity]:
                        raise ValueError(f"final native StringTable differs from staged CSV for {identity!r}")
                    edited_checked += 1
                else:
                    if candidate_payload != source_payload:
                        raise ValueError(f"retained StringTable payload changed for {identity!r}")
                    retained_checked += 1
            if edited_checked != len(staged):
                raise ValueError("final native semantic export did not verify every staged StringTable")
            _assert_run_inputs_unchanged(source, profile, self.acts_path,
                                         acts_before, self.replay_executable, replay_before)
            if unpack_replay_uncompressed(stage_ff.read_bytes()) != final_body:
                raise ValueError("final staged FF body differs from the fully relocated body")

            # Requested output paths are untouched until every stage, native
            # trace, and retained-table semantic check has passed.
            stage_ff_bytes = stage_ff.read_bytes()
            expected_output_ff_sha256 = output_profile["sha256"]
            if hashlib.sha256(stage_ff_bytes).hexdigest() != expected_output_ff_sha256:
                raise ValueError("native-verified staged FF bytes changed before publication")
            with output.open("xb") as stream:
                created_outputs.append(output)
                stream.write(stage_ff_bytes)
            if sha256_file(output) != expected_output_ff_sha256:
                raise ValueError("published FF hash differs from the native-verified staged FF")
            sidecars = []
            if stage_fp is not None:
                target_fp = output.with_suffix(".fp")
                stage_fp_bytes = stage_fp.read_bytes()
                expected_output_fp_sha256 = output_patch_sha256s[0]
                if hashlib.sha256(stage_fp_bytes).hexdigest() != expected_output_fp_sha256:
                    raise ValueError("native-verified staged FP bytes changed before publication")
                with target_fp.open("xb") as stream:
                    created_outputs.append(target_fp)
                    stream.write(stage_fp_bytes)
                if sha256_file(target_fp) != expected_output_fp_sha256:
                    raise ValueError("published FP hash differs from the native-verified staged FP")
                sidecars.append(dict(path=str(target_fp), bytes=target_fp.stat().st_size,
                                     sha256=expected_output_fp_sha256,
                                     replaces_stale_source_patch=str(profile["patches"][0]["path"])))
            receipt = dict(
                schema="replay120-stringtable-batch-package-v1",
                status="native-full-zone-stringtable-batch-package-pass",
                source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                native_walk_key=walk_receipt["walk_key"],
                source_native_manifest_sha256=walk_receipt["manifest_sha256"],
                source_stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                edits=[dict(asset_id=row["planned"]["asset_id"], revision=row["planned"]["revision"],
                            edited_payload_sha256=row["pending"]["edited_payload_sha256"],
                            compiler_receipt_sha256=row["pending"]["compiler_receipt_sha256"])
                       for row in staged],
                stages=[dict(ordinal=row["ordinal"], asset_id=row["asset_id"], revision=row["revision"],
                             relocation=row["relocation"], package_sha256=row["package_sha256"],
                             reservations=row["reservations"],
                             native_reader=dict(complete=row["native"]["manifest"].get("complete"),
                                                success=row["native"]["manifest"].get("success"),
                                                loaded_assets=row["native"]["manifest"].get("loaded_assets"),
                                                tested=row["native"]["manifest"].get("tested"),
                                                failed=row["native"]["manifest"].get("failed"),
                                                unavailable=row["native"]["manifest"].get("unavailable"),
                                                trace_summary=row["native"].get("trace_summary")))
                       for row in stage_receipts],
                semantic_comparison=dict(status="pass", edited_tables_checked=edited_checked,
                                         retained_tables_checked=retained_checked,
                                         source_index_sha256=sha256_file(export_root / "asset-payload-index.json"),
                                         output_index_sha256=sha256_file(candidate_root / "asset-payload-index.json")),
                output_fastfile=dict(path=str(output), bytes=output.stat().st_size,
                                     sha256=sha256_file(output), stream_reservations=reservations),
                sidecars=sidecars,
                native_reader=dict(complete=native["manifest"].get("complete"),
                                   success=native["manifest"].get("success"),
                                   loaded_assets=native["manifest"].get("loaded_assets"),
                                   tested=native["manifest"].get("tested"),
                                   failed=native["manifest"].get("failed"),
                                   unavailable=native["manifest"].get("unavailable"),
                                   trace_summary=native.get("trace_summary"),
                                   journal_sha256=native["journal_sha256"],
                                   journal_asset_identity_sha256=native["journal_asset_identity_sha256"],
                                   acts_tool_identity=native["acts_tool_identity"],
                                   replay_executable_sha256=native["replay_executable_sha256"]))
            receipt_text = json.dumps(receipt, indent=2) + "\n"
            with receipt_path.open("x", encoding="utf-8") as stream:
                created_outputs.append(receipt_path)
                stream.write(receipt_text)
            return dict(schema=receipt["schema"], status=receipt["status"], zone_id=zone_id,
                        edits=[dict(asset_id=row["planned"]["asset_id"], revision=row["planned"]["revision"])
                               for row in staged], output_fastfile=str(output),
                        output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(receipt_path),
                        native_reader_status=native["manifest"].get("status"),
                        native_reader_loaded=native["manifest"].get("loaded_assets"),
                        native_reader_tested=native["manifest"].get("tested"),
                        semantic_comparison=receipt["semantic_comparison"])
        except Exception:
            for created in reversed(created_outputs):
                created.unlink(missing_ok=True)
            raise

    def _build_stringtable_replacement(self, zone_id: str, cache_path: Path,
                                       decode_receipt: dict, body: ZoneBody,
                                       plan: dict, output: Path,
                                       timeout: int) -> dict:
        """Package one StringTable edit through the complete trace relocator."""
        if len(plan.get("edits", [])) != 1:
            raise UnsupportedAssetGraphError("StringTable packaging currently supports one table per zone")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk_receipt, native_rows = _read_native_rows(cache_path, body, require_trace=True)
        if (walk_receipt.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                walk_receipt.get("identity", {}).get("patch_sha256s") !=
                [patch["sha256"] for patch in profile.get("patches", [])]):
            raise ValueError("StringTable walk differs from current source FF/patch chain")
        if any(patch.get("extension") != ".fp" for patch in profile.get("patches", [])):
            raise UnsupportedAssetGraphError("StringTable replacement supports only the verified FP patch chain")
        if not walk_receipt.get("stream_trace_enabled"):
            raise UnsupportedAssetGraphError("StringTable packaging requires the complete native stream trace")
        trace_path = _native_walk_artifact(walk_receipt, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk_receipt, "manifest_relative_path")
        if (sha256_file(trace_path) != walk_receipt.get("stream_trace_sha256") or
                sha256_file(manifest_path) != walk_receipt.get("manifest_sha256")):
            raise ValueError("StringTable trace or manifest changed after preflight")
        planned = plan["edits"][0]
        index = int(planned["asset_id"].rsplit(":", 1)[1])
        if (index < 0 or index >= len(body.assets) or body.assets[index].type_id != 54 or
                native_rows[index].get("type_id") != 54 or native_rows[index].get("name") != planned.get("name")):
            raise ValueError("staged StringTable identity differs from its native XAsset row")
        # Public plans contain asset identities and revisions, not cache paths.
        # Resolve storage from the validated zone and selected row instead of
        # requiring the private listing representation to cross this boundary.
        pending_path = (cache_path / "pending-edits" / str(index) / "current.json").resolve(strict=True)
        if not pending_path.is_relative_to(cache_path.resolve(strict=True)):
            raise ValueError("staged StringTable path escapes its zone cache")
        if ("pending_path" in planned and
                Path(planned["pending_path"]).resolve(strict=True) != pending_path):
            raise ValueError("planned StringTable path differs from its selected native row")
        _current, pending, payload_path = _validate_pending_snapshot(
            cache_path, index, planned["asset_id"], body)
        if pending.get("revision") != planned.get("revision") or pending.get("name") != planned.get("name"):
            raise ValueError("StringTable revision changed after preflight")
        stale = self._staged_asset_staleness(pending, body, index, native_rows[index],
                                             walk_receipt, source)
        if stale:
            raise ValueError(stale)
        compiler_receipt = pending["compiler_receipt"]
        canonical_receipt = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")
        if (hashlib.sha256(canonical_receipt).hexdigest() != pending.get("compiler_receipt_sha256") or
                compiler_receipt.get("source", {}).get("sha256") != _pending_content_sha(pending) or
                compiler_receipt.get("asset_name") != planned.get("name") or
                sha256_file(payload_path) != pending.get("edited_payload_sha256") or
                compiler_receipt.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
            raise ValueError("StringTable receipt or compiled sections changed after preflight")
        replacement_rows = list(csv.reader(io.StringIO(pending["content"], newline="")))
        from workstation_asset_codecs import encode_stringtable_sections
        from workstation_stringtable import inspect_stringtable, replace_stringtable_rows
        sections = encode_stringtable_sections(planned["name"], replacement_rows)
        expected_payload = json.dumps(
            dict(schema=1, kind="stringtable-sections", name=sections["name"],
                 rows=sections["rows"], columns=sections["columns"],
                 header_base64=base64.b64encode(sections["header"]).decode("ascii"),
                 cells_base64=base64.b64encode(sections["cells"]).decode("ascii"),
                 hashes_base64=base64.b64encode(sections["hashes"]).decode("ascii"),
                 dictionary=sections["dictionary"]),
            sort_keys=True, separators=(",", ":")).encode("utf-8")
        if payload_path.read_bytes() != expected_payload:
            raise ValueError("StringTable section packet differs from its complete source-text encoding")
        export_root, export_index = _export_native_type(
            source, zone_id, body, cache_path, walk_receipt, native_rows,
            54, "stringtable", self.acts_path, self.replay_executable)
        source_item = next((row for row in export_index["items"] if row.get("asset_index") == index), None)
        if source_item is None:
            raise ValueError("native StringTable export omits the selected source asset")
        original_csv = (export_root / source_item["payload_relative_path"]).read_bytes()
        original_rows = list(csv.reader(io.StringIO(original_csv.decode("utf-8-sig"), newline="")))
        from workstation_trace_index import build_read_span_index
        from workstation_stringtable import validate_complete_stream5_allocations
        trace_index = build_read_span_index(trace_path, manifest_path, len(body.data))
        stream5_allocation_context = validate_complete_stream5_allocations(trace_index)
        omnvar_proof = None
        if planned["name"].replace("\\", "/").casefold() == "omnvars/mp/omnvars.csv":
            omnvar_proof, trace_asset = _prepare_omnvar_mp_source_proof(
                source=source, zone_id=zone_id, body=body, cache_path=cache_path,
                walk_receipt=walk_receipt, native_rows=native_rows, root_index=index,
                root_name=planned["name"], original_rows=original_rows,
                edited_rows=replacement_rows, export_root=export_root,
                export_index=export_index, trace_path=trace_path,
                manifest_path=manifest_path)
            if compiler_receipt.get("omnvar_mp_validation") != omnvar_proof:
                raise ValueError("Omnvar include/native source proof changed since save; reload and save again")
            saved_modules = compiler_receipt["omnvar_mp_validation"].get("modules", {})
            if not saved_modules or any(sha256_file(item["path"]) != item["sha256"]
                                        for item in saved_modules.values()):
                raise ValueError("Omnvar validator or native include-inspection helper changed since save")
        else:
            trace_asset = next((row for row in trace_index["assets"] if row.get("index") == index), None)
            if trace_asset is None:
                raise ValueError("native trace omits the selected StringTable")
            trace_asset.update(xasset_index=index, type_id=54, name=planned["name"])
        layout, _ = inspect_stringtable(
            body.data, index, planned["name"], trace_asset, original_rows,
            body.source_sha256,
            global_string_data_spans=trace_index.get("string_data_spans", []))
        source_identity = pending.get("native_source_identity", {})
        if (source_identity.get("root_span", {}).get("archive_offset") != layout.root_archive_offset or
                source_identity.get("record_span", {}).get("archive_offset") != layout.root_archive_offset or
                source_identity.get("record_span", {}).get("sha256") != layout.source_record_sha256):
            raise ValueError("StringTable source typed spans differ from the saved edit")
        updated, relocation = replace_stringtable_rows(
            body.data, index, planned["name"], trace_asset, original_rows,
            replacement_rows, body.source_sha256, trace_path, manifest_path,
            full_trace_index=trace_index)
        if ZoneBody.parse(updated).assets != body.assets:
            raise ValueError("StringTable relocation changed the XAsset table")
        deltas = relocation["stream_reservation_deltas"]
        reservations = [int(profile["final_header"]["block_sizes"][stream]) +
                        int(deltas.get(str(stream), 0)) for stream in range(STREAM_COUNT)]
        if (reservations != plan.get("proof", {}).get("stream_reservation_sizes") or
                any(size < 0 for size in reservations)):
            raise ValueError("StringTable reservations changed after preflight")
        packed = pack_replay_uncompressed(updated, reservations,
                                          profile["final_header"]["xfile_version"],
                                          profile["header"]["transient_type"])
        if unpack_replay_uncompressed(packed) != updated:
            raise AssertionError("StringTable fastfile framing changed its relocated body")
        if output.exists():
            raise FileExistsError(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        acts_before, replay_before = acts_tool_identity(self.acts_path), sha256_file(self.replay_executable)
        output.write_bytes(packed)
        sidecars = []
        try:
            for patch in profile.get("patches", []):
                target_patch = output.with_suffix(".fp")
                target_patch.write_bytes(make_replay_header_only_patch(
                    Path(patch["path"]).resolve(strict=True).read_bytes(), packed))
                sidecars.append(dict(path=str(target_patch), bytes=target_patch.stat().st_size,
                                     sha256=sha256_file(target_patch),
                                     replaces_stale_source_patch=str(Path(patch["path"]).resolve(strict=True))))
            # Keep the native journal and trace in the cache on failure as well as
            # success. Published replacements must never be the only evidence
            # available for diagnosing a rejected relocation.
            verification_root = cache_path / "package-verification"
            verification_root.mkdir(parents=True, exist_ok=True)
            verification_path = Path(tempfile.mkdtemp(
                prefix="stringtable-", dir=verification_root))
            (verification_path / "expected-identities.json").write_text(
                json.dumps([[row.get("type_id"), row.get("name")] for row in native_rows],
                           ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            from roundtrip_replay_fastfile import verify_native
            native = verify_native(output, updated, source, self.acts_path,
                                   self.replay_executable, verification_path, timeout, trace=True)
            (verification_path / "verification-result.json").write_text(
                json.dumps(native, indent=2) + "\n", encoding="utf-8")
            manifest = native["manifest"]
            applied = manifest.get("applied_patches", [])
            if [Path(path).suffix for path in applied] != [".fp" for _ in profile.get("patches", [])]:
                raise ValueError("Replay did not apply the complete replacement FP chain")
            if manifest.get("loaded_assets") != walk_receipt.get("loaded_assets"):
                raise ValueError("StringTable replacement changed the exact loaded-asset count")
            if native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256")) != ordered_asset_identity_sha256(native_rows):
                raise ValueError("StringTable replacement changed XAsset type/order/name journal; "
                                 f"native evidence: {verification_path}")
            highwaters = {int(key): value for key, value in
                          native["trace_summary"]["max_destination_offsets"].items()}
            if any(highwaters.get(stream, 0) > reservations[stream] for stream in range(STREAM_COUNT)):
                raise ValueError("native StringTable stream high-water exceeds an FF reservation")
            if highwaters.get(5) != relocation.get("new_stream5_high_water"):
                raise ValueError("native StringTable stream-5 high-water differs from relocation proof")
            # Every supported StringTable edit needs a fresh semantic readback,
            # not just Omnvar tables. The fresh per-build verification path
            # prevents cache-key collisions across different native walks.
            stringtable_semantic_proof, stringtable_semantic_helper_sha256 = (
                _export_and_compare_stringtable_semantics(
                    native=native, output=output, updated=updated,
                    verification_path=verification_path, zone_id=zone_id,
                    native_rows=native_rows, acts_path=self.acts_path,
                    replay_executable=self.replay_executable, timeout=timeout,
                    source_index_path=export_root / "asset-payload-index.json",
                    source_body_sha256=body.source_sha256,
                    source_fastfile_sha256=walk_receipt["identity"]["source_sha256"],
                    source_walk_key=walk_receipt["walk_key"],
                    edited_name=planned["name"], edited_asset_index=index,
                    expected_rows=replacement_rows))
            _assert_run_inputs_unchanged(source, profile, self.acts_path, acts_before,
                                         self.replay_executable, replay_before)
            if unpack_replay_uncompressed(output.read_bytes()) != updated:
                raise ValueError("packaged body differs from the relocated StringTable body")
            if omnvar_proof is not None:
                final_modules = omnvar_proof.get("modules", {})
                if not _omnvar_helper_modules_match(final_modules):
                    raise RuntimeError("Omnvar validation helper changed during native verification")
            receipt = dict(schema="replay120-stringtable-workspace-package-v1",
                           status="native-full-zone-stringtable-package-pass",
                           source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                           native_walk_key=walk_receipt["walk_key"],
                           native_manifest_sha256=walk_receipt["manifest_sha256"],
                           stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                           edit=dict(asset_id=planned["asset_id"], revision=planned["revision"],
                                     edited_payload_sha256=pending["edited_payload_sha256"],
                                     compiler_receipt_sha256=pending["compiler_receipt_sha256"],
                                     compiler_receipt=compiler_receipt),
                           relocation=relocation,
                           stringtable_semantic_export=dict(
                               helper_sha256=stringtable_semantic_helper_sha256,
                               proof=stringtable_semantic_proof),
                           output_fastfile=dict(path=str(output), bytes=output.stat().st_size,
                                                sha256=sha256_file(output), stream_reservations=reservations),
                           sidecars=sidecars,
                           native_reader=dict(complete=manifest.get("complete"), success=manifest.get("success"),
                                              loaded_assets=manifest.get("loaded_assets"),
                                              tested=manifest.get("tested"), failed=manifest.get("failed"),
                                              unavailable=manifest.get("unavailable"),
                                              serialized_bytes_read=manifest.get("serialized_bytes_read"),
                                              trace_summary=native.get("trace_summary"),
                                              journal_sha256=native["journal_sha256"],
                                              journal_asset_identity_sha256=native["journal_asset_identity_sha256"],
                                              acts_tool_identity=native["acts_tool_identity"],
                                              replay_executable_sha256=native["replay_executable_sha256"]))
            receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            return dict(schema=receipt["schema"], status=receipt["status"], zone_id=zone_id,
                        edits=[dict(asset_id=planned["asset_id"], revision=planned["revision"])],
                        output_fastfile=str(output), output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
                        sidecars=sidecars, receipt_path=str(receipt_path),
                        native_reader_status=manifest.get("status"),
                        native_reader_loaded=manifest.get("loaded_assets"),
                        native_reader_tested=manifest.get("tested"), edit_proof=relocation)
        except Exception:
            output.unlink(missing_ok=True)
            for row in sidecars:
                Path(row["path"]).unlink(missing_ok=True)
            raise

    def build_fastfile_with_pending_edits(self, zone_id: str,
                                          output_path: str | Path,
                                          timeout: int = 1800,
                                          expected_edits: Sequence[dict] | None = None) -> dict:
        """Package staged edits from one trace-proven zone.

        The output and generated header-only FP/FC replace stale source patches;
        source files are never modified. Each asset family selects a dedicated
        writer with the ownership and full-zone native reread contract it needs.
        """
        cache_path, decode_receipt = self._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache_path / decode_receipt["final_body_relative_path"]).read_bytes())
        plan = self.plan_pending_edits(zone_id)
        zone_plan = next((row for row in plan["zones"] if row["zone_id"] == zone_id), None)
        if zone_plan is None or not zone_plan.get("packageable"):
            reason = zone_plan.get("reason") if zone_plan else "no active staged edits for this zone"
            raise UnsupportedAssetGraphError(f"pending edit plan is not packageable: {reason}")
        if expected_edits is not None:
            expected = sorted((str(row.get("asset_id")), str(row.get("revision")))
                              for row in expected_edits)
            planned = sorted((str(row["asset_id"]), str(row["revision"]))
                             for row in zone_plan["edits"])
            if expected != planned:
                raise ValueError("queued edit snapshot differs from the current preflight plan")
        output = Path(output_path).resolve()
        if output.suffix.casefold() != ".ff" or output.is_relative_to(self.game_root):
            raise ValueError("replacement FF output must be an .ff outside the configured game directory")
        for sidecar in (output.with_suffix(".fp"), output.with_suffix(".fc")):
            if sidecar.exists():
                raise FileExistsError(f"replacement patch sidecar already exists: {sidecar}")
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        if any(row.get("extension") == ".fc" for row in decode_receipt["source"].get("patches", [])):
            raise UnsupportedAssetGraphError("source FC replacement semantics are not yet proven")
        if zone_plan.get("support") == "stringtable-sequential-full-trace-relocation":
            return self._build_multiple_stringtable_replacement(
                zone_id, cache_path, decode_receipt, body, zone_plan, output, timeout)
        if zone_plan.get("support") == "stringtable-full-trace-block5-relocation":
            return self._build_stringtable_replacement(zone_id, cache_path, decode_receipt,
                                                       body, zone_plan, output, timeout)
        if zone_plan.get("support") in (
                "stringtable-csv-append-native-transaction",
                "stringtable-exclusive-final-row-removal-native-transaction"):
            from workstation_stringtable_crud import build_workspace_stringtable_crud
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_workspace_stringtable_crud(self, zone_id, zone_plan["proof"], output,
                                                    timeout, _snapshot=snapshot)
        if zone_plan.get("support") == "same-extent-soundbank-alias-scalars":
            return self._build_soundbank_replacement(zone_id, cache_path, decode_receipt,
                                                     body, zone_plan, output, timeout)
        if zone_plan.get("support") == "rawfile-full-trace-block5-relocation":
            from workstation_rawfile import build_rawfile_replacement
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_rawfile_replacement(self, snapshot, zone_plan, output, timeout)
        if zone_plan.get("support") == "rawfile-sequential-native-row-operations":
            from workstation_rawfile_crud import build_rawfile_row_transaction
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_rawfile_row_transaction(self, zone_id, zone_plan["proof"], output,
                                                 timeout, _snapshot=snapshot)
        if zone_plan.get('support') == 'localize-sequential-native-row-operations':
            from workstation_localize_crud import build_localize_crud
            return build_localize_crud(self, zone_id, zone_plan, output, timeout)
        if zone_plan.get('support') == 'luafile-sequential-native-row-operations':
            from workstation_luafile_crud import build_workspace_luafile_crud
            return build_workspace_luafile_crud(self, zone_id, zone_plan, output, timeout)
        if zone_plan.get('support') == 'native-shader-exclusive-final-row-removal-transaction':
            from workstation_shader_crud import build_workspace_shader_remove
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_workspace_shader_remove(self, zone_id, zone_plan['proof'], output,
                                                 timeout, _snapshot=snapshot)
        if zone_plan.get('support') in ('pixelshader-row-append-native-transaction', 'native-shader-row-append-transaction'):
            from workstation_shader_crud import build_workspace_pixelshader_crud
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_workspace_pixelshader_crud(self, zone_id, zone_plan['proof'], output,
                                                   timeout, _snapshot=snapshot)
        if zone_plan.get('support') == 'resident-image-row-native-transaction':
            from workstation_image_crud import build_workspace_resident_image_crud
            snapshot = self._validated_asset_snapshot(zone_id, require_trace=True)
            return build_workspace_resident_image_crud(self, zone_id, zone_plan['proof'], output,
                                                       timeout, _snapshot=snapshot)
        if zone_plan.get('support') in (
                'scriptfile-inline-row-append-native-transaction',
                'scriptfile-exclusive-final-row-removal-native-transaction'):
            from workstation_scriptfile_crud import build_workspace_scriptfile_crud
            return build_workspace_scriptfile_crud(self, zone_id, zone_plan, output, timeout)
        if zone_plan.get('support') == 'mixed-image-localize-luafile-native-transaction':
            from workstation_mixed_asset_crud import build_workspace_mixed_asset_crud
            return build_workspace_mixed_asset_crud(self, zone_id, zone_plan, output, timeout)
        if zone_plan.get('support') == 'mixed-content-family-replacements-full-trace':
            from workstation_mixed_content_replacements import build_content_replacements
            return build_content_replacements(self, zone_id, zone_plan, output, timeout)
        if zone_plan.get("support") in (
                "luafile-inline-child-full-trace-relocation",
                "mixed-scriptfile-luafile-full-trace-relocation"):
            return self._build_luafile_replacement(zone_id, cache_path, decode_receipt,
                                                   body, zone_plan, output, timeout)
        if zone_plan.get("support") in ("same-extent-localize-batch",
                                          "trace-relocated-localize-batch"):
            return self._build_localize_replacement(zone_id, cache_path, decode_receipt,
                                                    body, zone_plan, output, timeout)
        if zone_plan.get("support") in ("same-extent-native-shader-image-batch",
                                        "variable-native-shader-image-batch"):
            return self._build_native_child_replacement(zone_id, cache_path, decode_receipt,
                                                        body, zone_plan, output, timeout)
        staged_edits = []
        for planned in zone_plan["edits"]:
            index = int(planned["asset_id"].rsplit(":", 1)[1])
            current_path = cache_path / "pending-edits" / str(index) / "current.json"
            staged = json.loads(current_path.read_text(encoding="utf-8"))
            if (staged.get("revision") != planned["revision"] or
                    staged.get("source_body_sha256") != body.source_sha256):
                raise ValueError("staged ScriptFile revision/body changed after preflight")
            stale = self._compiler_identity_staleness(staged, 52)
            if stale:
                raise ValueError(stale)
            payload_path = current_path.parent / staged["edited_payload_path"]
            if sha256_file(payload_path) != staged.get("edited_payload_sha256"):
                raise ValueError("staged ScriptFile payload hash changed after preflight")
            staged_edits.append(dict(xasset_index=index, name=staged["name"],
                                     asset_id=staged["asset_id"],
                                     content=staged["content"],
                                     edited_payload_sha256=staged["edited_payload_sha256"],
                                     revision=staged["revision"]))

        from analyze_workstation_asset_spans import analyze
        from repack_workstation_scriptfiles import run as repack_scriptfiles
        span_report = analyze(self.cache_root, zone_id, {52})
        output.parent.mkdir(parents=True, exist_ok=True)
        result = repack_scriptfiles(source, self.cache_root, zone_id, span_report,
                                   staged_edits, output, self.acts_path,
                                   self.replay_executable, DEFAULT_GSC_TOOL, timeout)
        return dict(status=result["status"], zone_id=zone_id,
                    edits=[dict(asset_id=row["asset_id"], revision=row["revision"])
                           for row in staged_edits],
                    output_fastfile=result["output_fastfile"],
                    output_fastfile_sha256=result["output_fastfile_sha256"],
                    sidecars=result["sidecars"],
                    receipt_path=str(output.with_suffix(output.suffix + ".edit-receipt.json")),
                    native_reader_status=result["native_reader"]["manifest"].get("status"),
                    native_reader_loaded=result["native_reader"]["manifest"].get("loaded_assets"),
                    native_reader_tested=result["native_reader"]["manifest"].get("tested"),
                    edit_proof=result["edit_proof"], support_limit=result["support_limit"])

    def _zone_cache_directory(self, zone_id: str) -> str:
        cache_path, _ = self._validated_zone_receipt(zone_id)
        return cache_path.parent.name

    def _reject_cross_type_pending_new_identity(self, zone_id: str, name: str,
                                                requested_type: str,
                                                _snapshot: AssetRequestSnapshot | None = None) -> None:
        # Shader-created rows use type-qualified IDs; the legacy name-only
        # collision check below applies only to older name-keyed operation IDs.
        if requested_type in ("computeshader", "vertexshader", "hullshader", "domainshader", "pixelshader"):
            return
        aliases = {"scriptfile": "scriptfile", "gsc": "scriptfile",
                   "luafile": "luafile", "lua": "luafile", "localize": "localize",
                   "stringtable": "stringtable", "rawfile": "rawfile",
                   }
        kind = aliases.get(requested_type)
        if kind is None:
            return
        if kind == "scriptfile":
            from workstation_scriptfile_crud import _native_scriptfile_name
            name = _native_scriptfile_name(name)
        identity = hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]
        asset_id = f"{zone_id}:new-{identity}"
        modules = {
            "scriptfile": "workstation_scriptfile_crud",
            "luafile": "workstation_luafile_crud",
            "localize": "workstation_localize_crud",
            "rawfile": "workstation_rawfile_crud",
            "stringtable": "workstation_stringtable_crud",
        }
        for other_kind, module_name in modules.items():
            if other_kind == kind:
                continue
            module = __import__(module_name, fromlist=["operations"])
            for row in module.operations(self, zone_id, _snapshot=_snapshot):
                if row.get("operation") == "append" and row.get("asset_id") == asset_id:
                    raise ValueError(
                        f"pending {other_kind} append already owns this new-asset identity")

    def create_asset(self, zone_id: str, name: str, content: str, type: str = 'localize',
                     revision: str | None = None, editor_mode: str | None = None) -> dict:
        if not isinstance(name, str) or not isinstance(type, str):
            raise ValueError("asset name and type must be text")
        if editor_mode is not None and (type != 'rawfile' or editor_mode not in ('text', 'base64')):
            raise ValueError("editor_mode is supported only for RawFile text or base64 creation")
        if type in ('scriptfile', 'gsc', 'luafile', 'lua', 'localize', 'rawfile', 'stringtable',
                    'computeshader', 'vertexshader', 'hullshader', 'domainshader', 'pixelshader', 'image'):
            request_snapshot = self._validated_asset_snapshot(zone_id)
        else:
            request_snapshot = None
        self._reject_cross_type_pending_new_identity(zone_id, name, type,
                                                    _snapshot=request_snapshot)
        if type in ('scriptfile', 'gsc'):
            from workstation_scriptfile_crud import create_scriptfile_asset
            return create_scriptfile_asset(self, zone_id, name, content, revision,
                                           _snapshot=request_snapshot)
        if type in ('luafile', 'lua'):
            from workstation_luafile_crud import create_luafile_asset
            return create_luafile_asset(self, zone_id, name, content, revision,
                                        _snapshot=request_snapshot)
        if type == 'rawfile':
            from workstation_rawfile_crud import create_rawfile_asset
            return create_rawfile_asset(self, zone_id, name, content, revision,
                                        mode=editor_mode or 'text', _snapshot=request_snapshot)
        if type == 'stringtable':
            from workstation_stringtable_crud import create_stringtable_asset
            return create_stringtable_asset(self, zone_id, name, content, revision,
                                            _snapshot=request_snapshot)
        if type in ('computeshader', 'vertexshader', 'hullshader', 'domainshader', 'pixelshader'):
            from workstation_shader_crud import create_shader_asset
            return create_shader_asset(self, zone_id, name, content, type, revision,
                                       _snapshot=request_snapshot)
        if type == 'image':
            from workstation_image_crud import create_resident_image_asset
            return create_resident_image_asset(self, zone_id, name, content, revision,
                                               _snapshot=request_snapshot)
        from workstation_localize_crud import create_localize_asset
        return create_localize_asset(self, zone_id, name, content, type, revision,
                                     _snapshot=request_snapshot)

    def remove_asset(self, asset_id: str, revision: str) -> dict:
        current = self.get_asset(asset_id)
        if current.get('type') in ('computeshader', 'vertexshader', 'hullshader', 'domainshader', 'pixelshader'):
            from workstation_shader_crud import remove_shader_asset
            return remove_shader_asset(self, asset_id, revision)
        if current.get('type') == 'scriptfile':
            from workstation_scriptfile_crud import remove_scriptfile_asset
            return remove_scriptfile_asset(self, asset_id, revision)
        if current.get('type') == 'luafile':
            from workstation_luafile_crud import remove_luafile_asset
            return remove_luafile_asset(self, asset_id, revision)
        if current.get('type') == 'stringtable':
            from workstation_stringtable_crud import remove_stringtable_asset
            return remove_stringtable_asset(self, asset_id, revision)
        if current.get('type') == 'rawfile':
            from workstation_rawfile_crud import remove_rawfile_asset
            return remove_rawfile_asset(self, asset_id, revision)
        if current.get('type') == 'image':
            from workstation_image_crud import remove_resident_image_asset
            return remove_resident_image_asset(self, asset_id, revision)
        from workstation_localize_crud import remove_localize_asset
        return remove_localize_asset(self, asset_id, revision)

    def _validated_zone_receipt(self, zone_id: str) -> tuple[Path, dict]:
        if not re.fullmatch(r"[0-9a-f]{64}", zone_id):
            raise ValueError("zone_id must be a content-addressed decode cache key")
        matches = list(self.cache_root.glob(f"*/{zone_id}/decode-receipt.json"))
        if len(matches) != 1:
            raise KeyError(f"unknown or ambiguous decoded zone id: {zone_id}")
        cache_path = matches[0].parent
        receipt = _cache_receipt(cache_path, zone_id)
        return cache_path, receipt

    def _validated_asset_snapshot(self, zone_id: str, *, require_trace: bool = True,
                                  validate_source: bool = True) -> AssetRequestSnapshot:
        """Read and verify a zone's large inputs once for one public request."""
        if not re.fullmatch(r"[0-9a-f]{64}", zone_id):
            raise ValueError("zone_id must be a content-addressed decode cache key")
        matches = list(self.cache_root.glob(f"*/{zone_id}/decode-receipt.json"))
        if len(matches) != 1:
            raise KeyError(f"unknown or ambiguous decoded zone id: {zone_id}")
        cache_path = matches[0].parent
        decode_receipt, body = _cache_receipt(cache_path, zone_id, include_body=True)
        body_path = (cache_path / decode_receipt["final_body_relative_path"]).resolve(strict=True)
        source_path = Path(decode_receipt["source"]["path"]).resolve(strict=validate_source)
        profile = source_profile(source_path) if validate_source else None
        try:
            walk, native_rows = _read_native_rows(cache_path, body, require_trace=require_trace)
        except UnsupportedAssetGraphError:
            if require_trace:
                raise
            walk, native_rows = None, None
        if walk and profile is not None and (
                walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
                     walk.get("identity", {}).get("patch_sha256s") !=
                     [patch["sha256"] for patch in profile.get("patches", [])] or
                     (require_trace and not walk.get("stream_trace_enabled"))):
            raise ValueError("native zone snapshot does not match the current source FF/patch chain")
        return AssetRequestSnapshot(zone_id, self._asset_workspace_identity(), cache_path,
                                    decode_receipt, body, body_path, source_path, profile,
                                    walk, native_rows)

    def _asset_workspace_identity(self) -> tuple[str, ...]:
        return tuple(str(path.resolve()) for path in (
            self.root, self.cache_root, self.game_root, self.acts_path,
            self.lua_acts_path, self.replay_executable))

    def _require_asset_request_snapshot(self, snapshot: AssetRequestSnapshot,
                                        zone_id: str) -> None:
        """Reject snapshots from another workspace or zone."""
        if not isinstance(snapshot, AssetRequestSnapshot):
            raise TypeError("asset request snapshot has an unsupported type")
        if snapshot.zone_id != zone_id:
            raise ValueError("asset request snapshot belongs to another zone")
        if snapshot.workspace_identity != self._asset_workspace_identity():
            raise ValueError("asset request snapshot belongs to another workspace")
        if not snapshot.cache_path.is_relative_to(self.cache_root):
            raise ValueError("asset request snapshot cache is outside this workspace")
        if snapshot.source_path != Path(snapshot.decode_receipt["source"]["path"]).resolve():
            raise ValueError("asset request snapshot source does not match its decode receipt")

    def _assert_asset_snapshot_current(self, snapshot: AssetRequestSnapshot) -> None:
        """Freshly revalidate pinned source/cache/walk inputs before staging."""
        self._require_asset_request_snapshot(snapshot, snapshot.zone_id)
        if snapshot.source_profile is None:
            raise ValueError("asset request snapshot lacks the source profile required for staging")
        current = self._validated_asset_snapshot(snapshot.zone_id, require_trace=True)
        if not current.source_profile or not snapshot.native_walk or not current.native_walk:
            raise RuntimeError("native asset walk disappeared during the request; nothing was staged")
        before = (snapshot.source_profile.get("sha256"),
                  tuple((row.get("extension"), row.get("sha256"))
                        for row in snapshot.source_profile.get("patches", [])),
                  snapshot.body.source_sha256, snapshot.native_walk.get("walk_key"),
                  snapshot.native_walk.get("manifest_sha256"),
                  snapshot.native_walk.get("stream_trace_sha256"))
        after = (current.source_profile.get("sha256"),
                 tuple((row.get("extension"), row.get("sha256"))
                       for row in current.source_profile.get("patches", [])),
                 current.body.source_sha256, current.native_walk.get("walk_key"),
                 current.native_walk.get("manifest_sha256"),
                 current.native_walk.get("stream_trace_sha256"))
        if before != after:
            raise RuntimeError("native asset source changed during the request; nothing was staged")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fastfile", type=Path,
                        help="native Replay 1.20 unsigned stored-frame .ff")
    parser.add_argument("--output", type=Path,
                        help="write JSON inventory (stdout when omitted)")
    args = parser.parse_args()
    report = inventory(args.fastfile)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
