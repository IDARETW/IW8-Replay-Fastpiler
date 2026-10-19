"""Parse LuaJIT v2 chunk boundaries inside Replay LuaFile payloads.

Valid native LuaFile children end at the LuaJIT zero-length-prototype marker.
Historical ACTS outputs added a second NUL, which the Replay VM rejects. The
reader can recognize that legacy wrapper for diagnosis and source recovery;
new compiler output must use allow_native_nul=False.
"""

from __future__ import annotations

from dataclasses import dataclass


MAGIC = b"\x1bLJ"
SUPPORTED_FLAGS = 0x0F
STRIP_FLAG = 0x02


@dataclass(frozen=True)
class LuaJitChunkBoundary:
    chunk: bytes
    chunk_bytes: int
    native_payload_bytes: int
    trailing_native_nul: bool
    prototype_count: int
    stripped: bool
    version: int
    flags: int


def _read_uleb128(data: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if cursor >= len(data) or shift >= 35:
            raise ValueError("LuaJIT chunk has a truncated or oversized ULEB128")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7


def split_luajit_file_payload(payload: bytes, *, allow_native_nul: bool = True
                                ) -> LuaJitChunkBoundary:
    """Return the exact LuaJIT chunk and validate its optional outer NUL.

    The format marker is the ULEB128 zero length following all prototypes.
    Historical ACTS output can include a second zero byte after the marker.
    It is recognized only for source recovery; it is not a valid native chunk.
    """
    if not isinstance(payload, bytes) or len(payload) < 7 or payload[:3] != MAGIC:
        raise ValueError("LuaFile payload is not a complete LuaJIT bytecode v2 chunk")
    version = payload[3]
    flags = payload[4]
    if version not in (1, 2):
        raise ValueError(f"unsupported LuaJIT bytecode version {version}")
    valid_flags = SUPPORTED_FLAGS if version == 2 else SUPPORTED_FLAGS & ~0x08
    if flags & ~valid_flags:
        raise ValueError(f"LuaJIT chunk has unsupported flag bits 0x{flags:02x}")

    cursor = 5
    if not flags & STRIP_FLAG:
        name_size, cursor = _read_uleb128(payload, cursor)
        if name_size > len(payload) - cursor:
            raise ValueError("LuaJIT chunk name exceeds the payload")
        cursor += name_size

    prototypes = 0
    while True:
        block_size, after_size = _read_uleb128(payload, cursor)
        if block_size == 0:
            chunk_end = after_size
            break
        if block_size > len(payload) - after_size:
            raise ValueError("LuaJIT prototype block exceeds the payload")
        cursor = after_size + block_size
        prototypes += 1

    if prototypes == 0:
        raise ValueError("LuaJIT chunk has no prototype blocks")
    trailing = payload[chunk_end:]
    if trailing:
        if not allow_native_nul or trailing != b"\0":
            raise ValueError("LuaFile payload has bytes after the LuaJIT end marker")
    return LuaJitChunkBoundary(
        chunk=payload[:chunk_end], chunk_bytes=chunk_end,
        native_payload_bytes=len(payload), trailing_native_nul=bool(trailing),
        prototype_count=prototypes, stripped=bool(flags & STRIP_FLAG),
        version=version, flags=flags)
