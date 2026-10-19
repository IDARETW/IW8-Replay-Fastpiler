"""Binary RPLYSIG1 registry embedded in a recompiled Replay PE."""

import hashlib
import struct

MAGIC = b"RPLYSIG1"
VERSION = 1
HEADER_SIZE = 72
RECORD_SIZE = 36
MAX_RECORDS = 512
MAX_PATTERN = 64
SECTION_CHARACTERISTICS = 0x40000040


def _signature(value, label):
    try:
        code = bytes.fromhex(value["bytes"])
        mask = bytes.fromhex(value["mask"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid {label} signature encoding") from error
    if not 1 <= len(code) <= MAX_PATTERN or len(mask) != len(code):
        raise ValueError(f"Invalid {label} signature extent")
    if not any(byte == 0xFF for byte in mask):
        raise ValueError(f"{label} signature has no fully fixed byte")
    return code, mask


def encode(entries):
    entries = sorted(entries, key=lambda item: int(item["rva"]))
    if not 1 <= len(entries) <= MAX_RECORDS:
        raise ValueError("RPLYSIG1 record count is outside 1..512")
    if len({int(item["rva"]) for item in entries}) != len(entries):
        raise ValueError("RPLYSIG1 native RVAs must be unique")

    records_at = HEADER_SIZE
    strings_at = records_at + len(entries) * RECORD_SIZE
    strings = bytearray()
    string_ranges = []
    for entry in entries:
        try:
            name = entry["name"].encode("ascii")
        except (AttributeError, UnicodeEncodeError) as error:
            raise ValueError("RPLYSIG1 names must be nonempty single-line ASCII") from error
        if not name or any(byte in name for byte in (0, 10, 13)) or len(name) > 0xFFFF:
            raise ValueError("RPLYSIG1 names must be nonempty single-line ASCII")
        string_ranges.append((len(strings), len(name)))
        strings.extend(name)
    blob_at = strings_at + len(strings)
    blob = bytearray()
    records = bytearray()
    previous_rva = -1
    for entry, (name_offset, name_size) in zip(entries, string_ranges):
        native_code, native_mask = _signature(entry["native"], "native")
        linked_code, linked_mask = _signature(entry["compiled"], "linked")
        rva = int(entry["rva"])
        if not 0 <= rva <= 0xFFFFFFFF or rva <= previous_rva:
            raise ValueError("RPLYSIG1 native RVAs must be strictly increasing uint32 values")
        previous_rva = rva
        native_bytes_at = len(blob)
        blob.extend(native_code)
        native_mask_at = len(blob)
        blob.extend(native_mask)
        linked_bytes_at = len(blob)
        blob.extend(linked_code)
        linked_mask_at = len(blob)
        blob.extend(linked_mask)
        records.extend(struct.pack("<IIHHIIIIII", rva, name_offset, name_size, 0,
                                   native_bytes_at, native_mask_at, len(native_code),
                                   linked_bytes_at, linked_mask_at, len(linked_code)))
    if len(blob) > 0xFFFFFFFF:
        raise ValueError("RPLYSIG1 blob exceeds uint32 size")
    body = bytes(records + strings + blob)
    digest = hashlib.sha256(body).digest()
    header = struct.pack("<8s7I32sI", MAGIC, VERSION, len(entries), records_at,
                         strings_at, len(strings), blob_at, len(blob), digest, 0)
    assert len(header) == HEADER_SIZE
    return header + body


def decode(section_bytes):
    data = bytes(section_bytes)
    if len(data) < HEADER_SIZE:
        raise ValueError("RPLYSIG1 section is shorter than its header")
    magic, version, count, records_at, strings_at, strings_size, blob_at, blob_size, digest, reserved = \
        struct.unpack_from("<8s7I32sI", data)
    if magic != MAGIC or version != VERSION or reserved != 0:
        raise ValueError("Unsupported RPLYSIG1 header")
    if not 1 <= count <= MAX_RECORDS or records_at != HEADER_SIZE:
        raise ValueError("Invalid RPLYSIG1 record table")
    if strings_at != records_at + count * RECORD_SIZE:
        raise ValueError("Invalid RPLYSIG1 string table offset")
    if blob_at != strings_at + strings_size or blob_size != len(data) - blob_at:
        raise ValueError("Invalid RPLYSIG1 blob bounds")
    if hashlib.sha256(data[HEADER_SIZE:]).digest() != digest:
        raise ValueError("RPLYSIG1 body SHA-256 mismatch")
    strings = data[strings_at:blob_at]
    blob = data[blob_at:]
    entries = []
    previous_rva = -1
    for index in range(count):
        rva, name_at, name_size, record_reserved, native_at, native_mask_at, native_size, \
            linked_at, linked_mask_at, linked_size = struct.unpack_from(
                "<IIHHIIIIII", data, records_at + index * RECORD_SIZE)
        if record_reserved or rva <= previous_rva:
            raise ValueError("RPLYSIG1 records are not canonical and strictly sorted")
        previous_rva = rva
        if not name_size or name_at + name_size > len(strings):
            raise ValueError("RPLYSIG1 name lies outside its string table")
        name_bytes = strings[name_at:name_at + name_size]
        if any(byte in name_bytes for byte in (0, 10, 13)):
            raise ValueError("RPLYSIG1 name contains a forbidden delimiter")
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("RPLYSIG1 name is not ASCII") from error
        def take_signature(code_at, mask_at, size, label):
            if not 1 <= size <= MAX_PATTERN or code_at + size > len(blob) or mask_at + size > len(blob):
                raise ValueError(f"RPLYSIG1 {label} signature lies outside its blob")
            code = blob[code_at:code_at + size]
            mask = blob[mask_at:mask_at + size]
            if not any(byte == 0xFF for byte in mask):
                raise ValueError(f"RPLYSIG1 {label} signature has no fixed byte")
            return {"bytes": code.hex(), "mask": mask.hex()}
        entries.append({"name": name, "rva": rva,
                        "native": take_signature(native_at, native_mask_at, native_size, "native"),
                        "compiled": take_signature(linked_at, linked_mask_at, linked_size, "linked")})
    return {"version": version, "identity": digest.hex(), "entries": entries,
            "body_sha256": digest.hex()}


def verify_pe(pe, report, expected_native_entries, map_rva):
    """Validate the embedded registry against native recovery and linked bytes."""
    sections = [section for section in pe.sections if section.Name.rstrip(b"\0") == b".rplsig"]
    if len(sections) != 1:
        raise ValueError("Expected exactly one embedded .rplsig section")
    section = sections[0]
    if section.Characteristics != SECTION_CHARACTERISTICS:
        raise ValueError("Embedded .rplsig section is not initialized read-only data")
    data = section.get_data()[:section.Misc_VirtualSize]
    parsed = decode(data)
    expected = sorted(expected_native_entries, key=lambda row: int(row["rva"]))
    actual = parsed["entries"]
    if len(actual) != len(expected):
        raise ValueError("Embedded proxy registry count differs from native recovery")
    for row, source in zip(actual, expected):
        native_code = bytes.fromhex(row["native"]["bytes"])
        native_mask = bytes.fromhex(row["native"]["mask"])
        source_code = bytes.fromhex(source["native"]["bytes"])
        source_mask = bytes.fromhex(source["native"]["mask"])
        if (row["name"] != source["name"] or row["rva"] != int(source["rva"]) or
                len(native_code) > len(source_code) or
                native_code != source_code[:len(native_code)] or
                native_mask != source_mask[:len(native_mask)]):
            raise ValueError(f"Embedded native signature differs at {row['rva']:#x}")
        linked_rva = map_rva(row["rva"], report)
        code = bytes.fromhex(row["compiled"]["bytes"])
        if pe.get_data(linked_rva, len(code)) != code:
            raise ValueError(f"Embedded linked signature bytes differ at {row['rva']:#x}")
    return {"identity": parsed["identity"], "count": len(actual),
            "section_rva": section.VirtualAddress, "section_size": section.Misc_VirtualSize}
