"""Exact-version uncompressed IWC container writer for source XFile 4289.

This is intentionally separate from ``workstation_fastfiles``' public Replay
4087 writer. It only repacks an already decoded/post-patch body; it does not
rewrite assets or claim that a body has been made semantically compatible.
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path
from typing import Sequence

from workstation_fastfiles import ZoneBody, SourceFastfileHeader

HEADER_SIZE = 0x88
IWC_HEADER_SIZE = 0x94
IWC_FRAME_MARKER = b"\x02IWC"
UNSECURED_MAGIC = b"IWffc100"
SIGNED_MAGIC = b"IWffa100"
PATCH_MAGIC = b"IWffd100"
HEADER_VERSION = 11
XFILE_VERSION = 4289
STREAM_COUNT = 11
MAX_CHUNK = 0x10000


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _header_profile(header: bytes) -> dict:
    if len(header) != HEADER_SIZE or header[:8] not in (SIGNED_MAGIC, UNSECURED_MAGIC):
        raise ValueError("expected a complete Replay FF header")
    version, xfile = struct.unpack_from("<II", header, 8)
    return {
        "magic": header[:8].decode("ascii"),
        "header_version": version,
        "xfile_version": xfile,
        "compression": header[0x10],
        "encryption": header[0x11],
        "transient_type": header[0x12],
        "decoded_size": _u64(header, 0x20),
        "preload_walk_size": _u64(header, 0x28),
        "stream_sizes": list(struct.unpack_from("<11Q", header, 0x30)),
    }


def inspect_4289_source(ff: bytes, fp: bytes) -> dict:
    """Validate a signed 4289 FF and its native version-6 FP header pair."""
    if len(ff) < 0xA0 or ff[:8] != SIGNED_MAGIC:
        raise ValueError("source FF must have the native signed Replay header")
    source = SourceFastfileHeader.parse(ff[:0xA0], file_bytes=len(ff))
    if source.xfile_version != XFILE_VERSION:
        raise ValueError(f"expected source XFile 4289, got {source.xfile_version}")
    if len(fp) < 0x148 or fp[:8] != PATCH_MAGIC:
        raise ValueError("source FP is truncated or has an unexpected magic")
    if struct.unpack_from("<II", fp, 8) != (6, 4):
        raise ValueError("source FP version pair is not Replay patch version 6/4")
    offsets = [m.start() for m in re.finditer(rb"IWff[ac]100", fp[:0x148])]
    if offsets != [0x38, 0xC0]:
        raise ValueError("source FP does not contain the bounded previous/target headers")
    previous = fp[0x38:0xC0]
    target = fp[0xC0:0x148]
    prev_info, final_info = _header_profile(previous), _header_profile(target)
    if previous != ff[:HEADER_SIZE]:
        raise ValueError("FP previous header does not exactly match the source FF")
    for label, info in (("previous", prev_info), ("target", final_info)):
        if info["header_version"] != HEADER_VERSION or info["xfile_version"] != XFILE_VERSION:
            raise ValueError(f"FP {label} header is not the source XFile 4289 profile")
        if info["compression"] != 1 or info["encryption"] != 0:
            raise ValueError(f"FP {label} header is not the signed source profile")
    if final_info["decoded_size"] < prev_info["decoded_size"]:
        raise ValueError("FP target decoded size unexpectedly shrinks the source")
    return {
        "source_ff_sha256": hashlib.sha256(ff).hexdigest(),
        "source_fp_sha256": hashlib.sha256(fp).hexdigest(),
        "source_xfile_version": XFILE_VERSION,
        "source_header": prev_info,
        "final_header": final_info,
        "fp_header_pair_offsets": offsets,
    }


def pack_uncompressed_4289(body: bytes, template_target_header: bytes,
                           *, stream_sizes: Sequence[int] | None = None,
                           preload_walk_size: int | None = None,
                           chunk_size: int = MAX_CHUNK) -> bytes:
    """Pack an already relocated, final-version-4289 body into uncompressed IWC.

    ``template_target_header`` must be the target 0x88-byte header from the
    matching source FP. Its stream reservations and preload-walk value are
    retained unless an explicit final value is supplied by a relocation proof.
    """
    ZoneBody.parse(body)
    info = _header_profile(template_target_header)
    if info["header_version"] != HEADER_VERSION or info["xfile_version"] != XFILE_VERSION:
        raise ValueError("template target header is not XFile 4289")
    if info["magic"] != SIGNED_MAGIC.decode("ascii") or info["compression"] != 1 or info["encryption"] != 0:
        raise ValueError("template target header is not the observed signed 4289 source profile")
    if info["transient_type"] not in (0, 1):
        raise ValueError("unsupported source transient type")
    if not 1 <= chunk_size <= MAX_CHUNK:
        raise ValueError("invalid IWC chunk size")
    sizes = tuple(info["stream_sizes"] if stream_sizes is None else stream_sizes)
    if len(sizes) != STREAM_COUNT or any(type(size) is not int or not 0 <= size <= 0xFFFFFFFFFFFFFFFF
                                         for size in sizes):
        raise ValueError("exactly eleven unsigned 64-bit stream reservations are required")
    # In the 4289 source profile the sum of the eleven stream reservations is
    # smaller than the decoded serialization size (as observed in the pinned
    # c3s5 FF/FP pair). They describe native stream allocations, not a partition
    # of the serialized body; do not impose the 4087 writer's sum invariant.
    walk_size = info["preload_walk_size"] if preload_walk_size is None else preload_walk_size
    if type(walk_size) is not int or not 0 <= walk_size <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("preload walk size must be an unsigned 64-bit value")
    if len(body) > 0xFFFFFFFF:
        raise ValueError("body exceeds the native 32-bit always-loaded field")

    header = bytearray(template_target_header)
    header[:8] = UNSECURED_MAGIC
    header[0x10:0x12] = b"\0\0"
    # Source signature/hash bytes are invalid after rewriting and are unused by
    # the unsecured container profile.
    header[0x18:0x20] = bytes(8)
    struct.pack_into("<I", header, 0x14, 0)  # set after framing is complete
    struct.pack_into("<I", header, 0x1C, len(body))
    struct.pack_into("<Q", header, 0x20, len(body))
    struct.pack_into("<Q", header, 0x28, walk_size)
    struct.pack_into("<11Q", header, 0x30, *sizes)

    output = bytearray(header)
    output.extend(IWC_FRAME_MARKER)
    output.extend(struct.pack("<I", len(body)))
    output.extend(struct.pack("<I", chunk_size | (1 << 24)))
    for start in range(0, len(body), chunk_size):
        block = body[start:start + chunk_size]
        output.extend(struct.pack("<III", len(block), len(block), 0))
        output.extend(block)
        output.extend(bytes((-len(output)) & 3))
    struct.pack_into("<I", output, 0x14, len(output) - HEADER_SIZE)
    packed = bytes(output)
    if unpack_uncompressed_4289(packed) != body:
        raise AssertionError("XFile 4289 IWC self-check changed body bytes")
    return packed


def unpack_uncompressed_4289(raw: bytes) -> bytes:
    """Strictly decode this module's uncompressed 4289 IWC framing subset."""
    if len(raw) < IWC_HEADER_SIZE or raw[:8] != UNSECURED_MAGIC:
        raise ValueError("invalid unsecured Replay IWC container")
    version, xfile = struct.unpack_from("<II", raw, 8)
    if (version, xfile) != (HEADER_VERSION, XFILE_VERSION) or raw[0x10:0x12] != b"\0\0":
        raise ValueError("container is not the unsecured XFile 4289 profile")
    if raw[0x88:0x8C] != IWC_FRAME_MARKER:
        raise ValueError("missing XFile stream-frame marker")
    body_size = _u64(raw, 0x20)
    if _u32(raw, 0x14) != len(raw) - HEADER_SIZE or _u32(raw, 0x1C) != body_size:
        raise ValueError("resident or always-loaded extent disagrees with container")
    # Do not compare reservation sum to body_size: 4289's observed source
    # profile has a 97,172,302-byte reservation sum and a 135,140,036-byte body.
    if _u32(raw, 0x8C) != body_size:
        raise ValueError("IWC declared body size disagrees with FF header")
    descriptor = _u32(raw, 0x90)
    chunk_size, algorithm = descriptor & 0xFFFFFF, descriptor >> 24
    if not 1 <= chunk_size <= MAX_CHUNK or algorithm != 1:
        raise ValueError("unsupported IWC chunk profile")
    cursor, result = IWC_HEADER_SIZE, bytearray()
    while len(result) < body_size:
        if cursor + 12 > len(raw):
            raise ValueError("truncated IWC chunk header")
        packed, expanded, counter = struct.unpack_from("<III", raw, cursor)
        cursor += 12
        if (packed == 0 or packed != expanded or packed > chunk_size or counter != 0 or
                packed > body_size - len(result) or cursor + packed > len(raw)):
            raise ValueError("invalid uncompressed IWC chunk")
        result.extend(raw[cursor:cursor + packed])
        cursor += packed
        aligned = (cursor + 3) & ~3
        if any(raw[cursor:aligned]):
            raise ValueError("nonzero IWC alignment padding")
        cursor = aligned
    if cursor != len(raw) or len(result) != body_size:
        raise ValueError("IWC chunks do not end at the exact container boundary")
    body = bytes(result)
    ZoneBody.parse(body)
    return body


def make_header_only_fp_4289(template_fp: bytes, emitted_ff: bytes) -> bytes:
    """Emit a zero-payload FP whose previous/target headers equal the new FF."""
    if len(template_fp) < 0x148 or template_fp[:8] != PATCH_MAGIC:
        raise ValueError("template is not a bounded native Replay FP")
    if struct.unpack_from("<II", template_fp, 8) != (6, 4):
        raise ValueError("FP template is not patch version 6/4")
    if len(emitted_ff) < IWC_HEADER_SIZE or emitted_ff[:8] != UNSECURED_MAGIC:
        raise ValueError("replacement is not an uncompressed IWC FF")
    if struct.unpack_from("<II", emitted_ff, 8) != (HEADER_VERSION, XFILE_VERSION):
        raise ValueError("replacement FF is not XFile 4289")
    unpack_uncompressed_4289(emitted_ff)
    prefix = bytearray(template_fp[:0x38])
    # These bytes describe the payload blocks in the source delta. A no-op FP
    # has no such blocks, so retain only the observed fixed prefix fields.
    prefix[0x10:0x38] = bytes(0x28)
    header = emitted_ff[:HEADER_SIZE]
    result = bytes(prefix) + header + header
    if len(result) != 0x148:
        raise AssertionError("header-only 4289 FP extent changed")
    if result[0x38:0xC0] != result[0xC0:0x148]:
        raise AssertionError("header-only 4289 FP headers differ")
    return result


def write_4289_pair(body: bytes, source_ff: bytes, source_fp: bytes,
                    output_ff: str | Path, *,
                    stream_sizes: Sequence[int] | None = None,
                    preload_walk_size: int | None = None) -> dict:
    """Write isolated FF/FP outputs using source final-header reservations."""
    profile = inspect_4289_source(source_ff, source_fp)
    target_header = source_fp[0xC0:0x148]
    source_final_size = profile["final_header"]["decoded_size"]
    if len(body) != source_final_size and (stream_sizes is None or preload_walk_size is None):
        raise ValueError("a changed 4289 body size requires explicit final stream reservations and preload-walk size")
    packed = pack_uncompressed_4289(body, target_header,
                                    stream_sizes=stream_sizes,
                                    preload_walk_size=preload_walk_size)
    patch = make_header_only_fp_4289(source_fp, packed)
    ff_path = Path(output_ff)
    fp_path = ff_path.with_suffix(".fp")
    ff_path.parent.mkdir(parents=True, exist_ok=True)
    if ff_path.exists() or fp_path.exists():
        raise FileExistsError("refusing to overwrite an existing 4289 package output")
    ff_path.write_bytes(packed)
    fp_path.write_bytes(patch)
    return {
        "schema": 1,
        "source": profile,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "output_ff": str(ff_path.resolve()),
        "output_ff_sha256": hashlib.sha256(packed).hexdigest(),
        "output_fp": str(fp_path.resolve()),
        "output_fp_sha256": hashlib.sha256(patch).hexdigest(),
        "output_xfile_version": XFILE_VERSION,
        "output_decoded_size": len(body),
        "output_stream_sizes": list(struct.unpack_from("<11Q", packed, 0x30)),
        "output_preload_walk_size": _u64(packed, 0x28),
        "decoded_size_delta_from_source_final": len(body) - source_final_size,
        "stream_reservation_sum_is_body_partition": False,
        "byte_exact_body_roundtrip": unpack_uncompressed_4289(packed) == body,
        "header_only_fp_matches_output": patch[0x38:0xC0] == packed[:HEADER_SIZE] == patch[0xC0:0x148],
    }
