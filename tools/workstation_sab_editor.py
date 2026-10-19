"""Bounded editor for Replay v10 resident SAB sound banks.

Only the entry payload is re-encoded.  All other entry payloads and all opaque
checksum bytes are copied exactly.  The 16-byte checksum values are preserved
as uninterpreted data; their meaning is not established by this module.
"""
from __future__ import annotations

import argparse
import ctypes.util
import hashlib
import io
import importlib
import json
import os
import platform
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAGIC = 0x23585532
HEADER_SIZE = 688
ENTRY_SIZE = 44
CHECKSUM_SIZE = 16
DATA_START = 4096
ROW = struct.Struct("<IIIIIQIBBB")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _align(value: int, boundary: int = 16) -> int:
    if boundary <= 0 or boundary & (boundary - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + boundary - 1) & ~(boundary - 1)


@dataclass(frozen=True)
class SabRow:
    index: int
    file_id: int
    size: int
    seek: int
    frames: int
    hybrid: int
    offset: int
    rate: int
    channels: int
    looping: int
    codec: int
    raw: bytes

    @property
    def extent_size(self) -> int:
        return self.size + self.hybrid


@dataclass(frozen=True)
class SabBank:
    raw: bytes
    version: int
    build_version: int
    count: int
    index_offset: int
    index_gap: bytes
    checksum_offset: int
    trailing: bytes
    asset_section_size: int
    rows: tuple[SabRow, ...]
    checksums: tuple[bytes, ...]


def parse_sab(data: bytes) -> SabBank:
    """Parse and bounds-check the known 688-byte / 44-byte Replay v10 layout."""
    if len(data) < HEADER_SIZE:
        raise ValueError("SAB is shorter than its 688-byte header")
    magic, version, row_size, digest_size = struct.unpack_from("<IIII", data, 0)
    if magic != MAGIC or version != 10:
        raise ValueError("unsupported SAB magic/version")
    if row_size != ENTRY_SIZE or digest_size != CHECKSUM_SIZE:
        raise ValueError("unsupported SAB row/checksum widths")
    count = struct.unpack_from("<I", data, 20)[0]
    build_version = struct.unpack_from("<I", data, 28)[0]
    bank_size, index_offset, checksum_offset = struct.unpack_from("<QQQ", data, 32)
    asset_section_size = struct.unpack_from("<I", data, 679)[0]
    if bank_size != len(data):
        raise ValueError("declared SAB bank size differs from file length")
    if count == 0:
        raise ValueError("empty SAB index is unsupported")
    index_end = index_offset + count * ENTRY_SIZE
    checksum_end = checksum_offset + count * CHECKSUM_SIZE
    if index_offset < DATA_START or index_end > len(data):
        raise ValueError("SAB row table is out of bounds")
    if checksum_offset < index_end or checksum_end > len(data):
        raise ValueError("SAB checksum table is out of bounds")
    if asset_section_size > len(data) - HEADER_SIZE:
        raise ValueError("SAB asset-section size exceeds native header bounds")
    rows: list[SabRow] = []
    checksums: list[bytes] = []
    ids: set[int] = set()
    for i in range(count):
        pos = index_offset + i * ENTRY_SIZE
        vals = ROW.unpack_from(data, pos)
        file_id, size, seek, frames, hybrid, offset, rate, channels, looping, codec = vals
        row_raw = data[pos:pos + ENTRY_SIZE]
        if file_id in ids:
            raise ValueError(f"duplicate SAB file ID {file_id}")
        ids.add(file_id)
        if not size or not frames or not rate or channels not in (1, 2):
            raise ValueError(f"invalid dimensions in SAB row {i}")
        if seek > size:
            raise ValueError(f"seek extent exceeds encoded size in SAB row {i}")
        if offset < DATA_START or offset + size + hybrid > index_offset:
            raise ValueError(f"SAB payload extent is outside data region in row {i}")
        rows.append(SabRow(i, file_id, size, seek, frames, hybrid, offset, rate,
                           channels, looping, codec, row_raw))
        cpos = checksum_offset + i * CHECKSUM_SIZE
        checksums.append(data[cpos:cpos + CHECKSUM_SIZE])
    physical_rows = sorted(rows, key=lambda row: (row.offset, row.offset + row.extent_size))
    previous_end = DATA_START
    for row in physical_rows:
        if row.offset < previous_end:
            raise ValueError(f"overlapping SAB payload extents at row {row.index}")
        previous_end = row.offset + row.extent_size
    if previous_end > index_offset:
        raise ValueError("SAB payload overlaps its row table")
    index_end = index_offset + count * ENTRY_SIZE
    return SabBank(data, version, build_version, count, index_offset,
                   data[index_end:checksum_offset], checksum_offset,
                   data[checksum_end:], asset_section_size, tuple(rows), tuple(checksums))


def _flac_streaminfo(rate: int, channels: int, frames: int, bits: int = 16) -> bytes:
    packed = (rate << 44) | ((channels - 1) << 41) | ((bits - 1) << 36) | frames
    return (struct.pack(">HH", 4096, 4096) + bytes(6) + packed.to_bytes(8, "big") + bytes(16))


def _wrap_frames(raw: bytes, rate: int, channels: int, frames: int,
                 streaminfo: bytes | None = None) -> bytes:
    info = streaminfo or _flac_streaminfo(rate, channels, frames)
    if len(info) != 34:
        raise ValueError("FLAC STREAMINFO must contain 34 bytes")
    return b"fLaC" + bytes((0x80, 0, 0, 34)) + info + raw


def _flac_frames(encoded: bytes) -> tuple[bytes, bytes]:
    if not encoded.startswith(b"fLaC"):
        raise ValueError("sound encoder did not return FLAC")
    pos = 4
    info = None
    while True:
        if pos + 4 > len(encoded):
            raise ValueError("truncated FLAC metadata")
        head = encoded[pos]
        last, kind = bool(head & 0x80), head & 0x7F
        size = int.from_bytes(encoded[pos + 1:pos + 4], "big")
        start, end = pos + 4, pos + 4 + size
        if end > len(encoded):
            raise ValueError("FLAC metadata block exceeds encoded data")
        if kind == 0:
            if info is not None or size != 34:
                raise ValueError("invalid FLAC STREAMINFO")
            info = encoded[start:end]
        pos = end
        if last:
            break
    if info is None or pos >= len(encoded):
        raise ValueError("FLAC stream lacks STREAMINFO or audio frames")
    return info, encoded[pos:]


def _soundfile(soundfile_root: Path | str | None):
    if soundfile_root is not None:
        import sys
        path = str(Path(soundfile_root).resolve())
        if path not in sys.path:
            sys.path.insert(0, path)
    import numpy as np
    import soundfile as sf
    return np, sf


def soundfile_identity(soundfile_root: Path | str | None = None) -> dict[str, Any]:
    """Return stable codec dependency identity without process-local handles."""
    np, sf = _soundfile(soundfile_root)
    try:
        numpy_core = importlib.import_module("numpy._core._multiarray_umath")
    except ImportError:  # NumPy 1.x package path
        numpy_core = importlib.import_module("numpy.core._multiarray_umath")
    soundfile_path = Path(sf.__file__).resolve(strict=True)
    numpy_path = Path(np.__file__).resolve(strict=True)
    core_path = Path(numpy_core.__file__).resolve(strict=True)
    result: dict[str, Any] = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "soundfile_version": sf.__version__,
        "soundfile_module_path": str(soundfile_path),
        "soundfile_module_sha256": _sha(soundfile_path.read_bytes()),
        "libsndfile_version": getattr(sf, "__libsndfile_version__", None),
        "numpy_version": np.__version__,
        "numpy_module_path": str(numpy_path),
        "numpy_module_sha256": _sha(numpy_path.read_bytes()),
        "numpy_core_module_path": str(core_path),
        "numpy_core_module_sha256": _sha(core_path.read_bytes()),
    }
    packaged = getattr(sf, "_packaged_libname", None)
    if packaged:
        libpath = soundfile_path.parent / "_soundfile_data" / packaged
        if not libpath.is_file():
            raise ValueError("packaged libsndfile library is missing")
        libpath = libpath.resolve(strict=True)
        result["libsndfile_library_name"] = libpath.name
        result["libsndfile_library_path"] = str(libpath)
        result["libsndfile_library_sha256"] = _sha(libpath.read_bytes())
    else:
        library = ctypes.util.find_library("sndfile")
        if not library:
            raise ValueError("cannot identify the loaded libsndfile implementation")
        result["libsndfile_library_name"] = os.path.basename(library)
        candidate = Path(library)
        if candidate.is_file():
            candidate = candidate.resolve(strict=True)
            result["libsndfile_library_path"] = str(candidate)
            result["libsndfile_library_sha256"] = _sha(candidate.read_bytes())
    return result


def _validate_pcm16_wav(data: bytes) -> tuple[int, int, int]:
    """Return (rate, channels, frames), accepting only integer PCM16 RIFF/WAVE."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("authored input must be a RIFF/WAVE file")
    declared_size = struct.unpack_from("<I", data, 4)[0] + 8
    if declared_size != len(data):
        raise ValueError("WAV RIFF size does not match input length")
    pos, fmt, audio = 12, None, None
    while pos + 8 <= len(data):
        tag = data[pos:pos + 4]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        start, end = pos + 8, pos + 8 + size
        if end > len(data):
            raise ValueError("WAV chunk exceeds input bounds")
        if tag == b"fmt ":
            if fmt is not None or size < 16:
                raise ValueError("WAV has duplicate or short fmt chunk")
            fmt = struct.unpack_from("<HHIIHH", data, start)
        elif tag == b"data":
            if audio is not None:
                raise ValueError("multiple WAV data chunks are unsupported")
            audio = data[start:end]
        pos = end + (size & 1)
    if pos != len(data) or fmt is None or audio is None:
        raise ValueError("WAV chunks are incomplete or malformed")
    encoding, channels, rate, byte_rate, block_align, bits = fmt
    if encoding != 1 or bits != 16:
        raise ValueError("authored WAV must use integer PCM16 encoding")
    if channels not in (1, 2) or not rate or block_align != channels * 2 or byte_rate != rate * block_align:
        raise ValueError("WAV sample format fields are inconsistent or unsupported")
    if not audio or len(audio) % block_align:
        raise ValueError("WAV data size is not a whole PCM frame count")
    if rate >= 1 << 20:
        raise ValueError("WAV sample rate exceeds the native FLAC STREAMINFO field")
    return rate, channels, len(audio) // block_align


def rewrite_entry(data: bytes, file_id: int, authored_wav: bytes, *,
                  soundfile_root: Path | str | None = None) -> tuple[bytes, dict[str, Any]]:
    """Replace one codec-8 entry from PCM WAV, returning bank bytes and receipt.

    Authored rate, channel count and frame count replace the corresponding
    known row fields. Looping, identity and opaque bytes are retained; hybrid
    entries are rejected until their separate payload ownership is defined.
    """
    bank = parse_sab(data)
    matches = [row for row in bank.rows if row.file_id == file_id]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one SAB row for file ID {file_id}")
    target = matches[0]
    if target.codec != 8:
        raise ValueError(f"codec {target.codec} is not supported; only Replay codec 8 is proven")
    if target.hybrid:
        raise ValueError("cannot edit an entry with hybrid bytes until their semantics are proven")
    wav_rate_expected, wav_channels, wav_frames = _validate_pcm16_wav(authored_wav)
    np, sf = _soundfile(soundfile_root)
    pcm, wav_rate = sf.read(io.BytesIO(authored_wav), dtype="int16", always_2d=True)
    if wav_rate != wav_rate_expected or pcm.shape != (wav_frames, wav_channels):
        raise ValueError("authored WAV decoder dimensions differ from its PCM16 header")
    source_payload = data[target.offset:target.offset + target.size]
    source_frames = source_payload[target.seek:]
    source_pcm, source_rate = sf.read(io.BytesIO(_wrap_frames(
        source_frames, target.rate, target.channels, target.frames)),
        dtype="int16", always_2d=True)
    if source_rate != target.rate or source_pcm.shape != (target.frames, target.channels):
        raise ValueError("selected codec-8 source payload does not match its row metadata")
    encoded_io = io.BytesIO()
    sf.write(encoded_io, pcm, wav_rate, format="FLAC", subtype="PCM_16")
    streaminfo, new_frames = _flac_frames(encoded_io.getvalue())
    roundtrip, roundtrip_rate = sf.read(io.BytesIO(_wrap_frames(
        new_frames, wav_rate, wav_channels, wav_frames, streaminfo)),
        dtype="int16", always_2d=True)
    if roundtrip_rate != wav_rate or not np.array_equal(roundtrip, pcm):
        raise ValueError("new raw FLAC frames do not reproduce authored PCM exactly")

    out = bytearray(data[:DATA_START])
    new_rows: list[SabRow] = []
    physical_rows = sorted(bank.rows, key=lambda row: (row.offset, row.offset + row.extent_size))
    payloads: dict[int, bytes] = {}
    row_values: dict[int, tuple[int, int, int, bytearray]] = {}
    for row in bank.rows:
        if row.file_id == file_id:
            payload = new_frames
            size, seek, hybrid = len(payload), 0, 0
            raw_row = bytearray(row.raw)
            struct.pack_into("<III", raw_row, 4, size, seek, wav_frames)
            struct.pack_into("<I", raw_row, 16, hybrid)
            struct.pack_into("<IB", raw_row, 28, wav_rate, wav_channels)
        else:
            payload = data[row.offset:row.offset + row.extent_size]
            size, seek, hybrid = row.size, row.seek, row.hybrid
            raw_row = bytearray(row.raw)
        if len(payload) != size + hybrid:
            raise ValueError(f"payload length mismatch while preserving row {row.index}")
        payloads[row.index] = payload
        row_values[row.index] = (size, seek, hybrid, raw_row)
    cursor = DATA_START
    for row in physical_rows:
        out.extend(data[cursor:row.offset])  # preserve every original opaque gap byte
        offset = len(out)
        payload = payloads[row.index]
        size, seek, hybrid, raw_row = row_values[row.index]
        struct.pack_into("<Q", raw_row, 20, offset)
        rate, channels, frames = (wav_rate, wav_channels, wav_frames) if row.file_id == file_id else (row.rate, row.channels, row.frames)
        new_rows.append(SabRow(row.index, row.file_id, size, seek, frames,
                               hybrid, offset, rate, channels, row.looping,
                               row.codec, bytes(raw_row)))
        out.extend(payload)
        cursor = row.offset + row.extent_size
    out.extend(data[cursor:bank.index_offset])
    new_index = _align(len(out))
    out.extend(bytes(new_index - len(out)))
    new_rows_by_index = {row.index: row for row in new_rows}
    new_rows = [new_rows_by_index[row.index] for row in bank.rows]
    for row in new_rows:
        out.extend(row.raw)
    out.extend(bank.index_gap)
    new_checksum_offset = len(out)
    for digest in bank.checksums:
        out.extend(digest)
    trailing = bank.trailing
    out.extend(trailing)
    new_size = len(out)
    struct.pack_into("<Q", out, 32, new_size)
    struct.pack_into("<Q", out, 40, new_index)
    struct.pack_into("<Q", out, 48, new_checksum_offset)
    new_asset_section = bank.asset_section_size + new_size - len(data)
    if not 0 <= new_asset_section <= new_size - HEADER_SIZE:
        raise ValueError("rebased asset-section size violates header bounds")
    struct.pack_into("<I", out, 679, new_asset_section)
    result = bytes(out)
    reread = parse_sab(result)
    final_target = reread.rows[target.index]
    if final_target.file_id != file_id or final_target.codec != 8:
        raise ValueError("rewritten selected row failed structural readback")
    if (final_target.rate, final_target.channels, final_target.frames) != (wav_rate, wav_channels, wav_frames):
        raise ValueError("rewritten row dimensions differ from the authored WAV")
    final_pcm, final_rate = sf.read(io.BytesIO(_wrap_frames(
        result[final_target.offset + final_target.seek:final_target.offset + final_target.size],
        final_target.rate, final_target.channels, final_target.frames)),
        dtype="int16", always_2d=True)
    if final_rate != wav_rate or not np.array_equal(final_pcm, pcm):
        raise ValueError("serialized SAB dimensions/payload do not reproduce the authored PCM")
    if final_target.raw[:4] != target.raw[:4] or final_target.raw[33:] != target.raw[33:]:
        raise ValueError("selected SAB identity, loop, codec or opaque tail bytes changed")
    if reread.checksums != bank.checksums or result[56:72] != data[56:72]:
        raise ValueError("opaque checksum fields unexpectedly changed")
    for before, after in zip(bank.rows, reread.rows):
        if before.file_id == file_id:
            continue
        a = data[before.offset:before.offset + before.extent_size]
        b = result[after.offset:after.offset + after.extent_size]
        if a != b or before.raw[:20] + before.raw[28:] != after.raw[:20] + after.raw[28:]:
            raise ValueError(f"untouched SAB row {before.index} changed")
    receipt = {
        "schema": "replay120-sab-v10-entry-edit-v1",
        "input_sha256": _sha(data), "output_sha256": _sha(result),
        "input_bytes": len(data), "output_bytes": len(result),
        "soundfile_version": sf.__version__,
        "libsndfile_version": getattr(sf, "__libsndfile_version__", None),
        "numpy_version": np.__version__,
        "soundfile_module_path": str(Path(sf.__file__).resolve()),
        "numpy_module_path": str(Path(np.__file__).resolve()),
        "codec_dependencies": soundfile_identity(soundfile_root),
        "file_id": file_id, "row_index": target.index, "codec": target.codec,
        "source_pcm_sha256": _sha(source_pcm.tobytes()),
        "authored_pcm_sha256": _sha(pcm.tobytes()),
        "output_pcm_sha256": _sha(roundtrip.tobytes()),
        "output_pcm_equals_authored": bool(np.array_equal(roundtrip, pcm)),
        "rate": wav_rate, "channels": wav_channels, "frames": wav_frames,
        "source_dimensions": {"rate": target.rate, "channels": target.channels, "frames": target.frames},
        "authored_dimensions": {"rate": wav_rate, "channels": wav_channels, "frames": wav_frames},
        "dimensions_changed": (target.rate, target.channels, target.frames) != (wav_rate, wav_channels, wav_frames),
        "old_payload_bytes": target.size, "new_payload_bytes": len(new_frames),
        "old_seek_bytes": target.seek, "new_seek_bytes": 0,
        "old_hybrid_bytes": target.hybrid, "new_hybrid_bytes": 0,
        "old_offset": target.offset, "new_offset": final_target.offset,
        "index_offset": reread.index_offset, "checksum_offset": reread.checksum_offset,
        "opaque_entry_checksums_preserved": reread.checksums == bank.checksums,
        "opaque_header_checksum_preserved": result[56:72] == data[56:72],
        "opaque_trailing_bytes_preserved": result[-len(trailing):] == trailing if trailing else True,
        "physical_payload_order_preserved": [r.file_id for r in sorted(reread.rows, key=lambda r: r.offset)] ==
                                             [r.file_id for r in physical_rows],
        "opaque_index_checksum_gap_preserved": reread.index_gap == bank.index_gap,
        "preserved_physical_gap_bytes": True,
        "untouched_payloads_and_row_fields_preserved": True,
        "checksum_semantics": "opaque and preserved; algorithm/meaning unverified",
        "playback_verified": False,
    }
    packaged_lib = getattr(sf, "_packaged_libname", None)
    if packaged_lib:
        lib_path = Path(sf.__file__).resolve().parent / "_soundfile_data" / packaged_lib
        if lib_path.is_file():
            receipt["libsndfile_library_path"] = str(lib_path.resolve())
            receipt["libsndfile_library_sha256"] = _sha(lib_path.read_bytes())
    return result, receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wav", type=Path, required=True)
    parser.add_argument("--file-id", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--soundfile-root", type=Path)
    args = parser.parse_args()
    edited, receipt = rewrite_entry(args.source.read_bytes(), args.file_id,
                                    args.wav.read_bytes(),
                                    soundfile_root=args.soundfile_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(edited)
    receipt["source_path"] = str(args.source.resolve())
    receipt["wav_path"] = str(args.wav.resolve())
    receipt["output_path"] = str(args.output.resolve())
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
