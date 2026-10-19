"""Versioned compiler provenance stored in the new PE's DOS stub area."""

import struct

MAGIC = b"RPLYCMP1"
OFFSET = 0x40
SIZE = 0x40


def encode(manifest, image_size):
    magic = b"RPLYCMP2" if manifest.get("rva_map", {}).get("insertions") else MAGIC
    return struct.pack("<8s32sIIIIQ", magic, bytes.fromhex(manifest["input_sha256"]),
        manifest["optional"]["SizeOfImage"], image_size,
        manifest.get("linked_entry_rva", manifest["optional"]["AddressOfEntryPoint"]), manifest["timestamp"],
        manifest["image_base"])


def verify(header, manifest, image_size, report=None):
    if report:
        manifest = dict(manifest, rva_map=report.get("rva_map", {}), linked_entry_rva=report["entry_rva"])
    if header[OFFSET:OFFSET+SIZE] != encode(manifest, image_size):
        raise ValueError("Compiler image identity does not match the source manifest")


def encode_map(manifest, sections):
    ranges = manifest["rva_map"]["ranges"]
    bindings = manifest["proxy_signatures"]
    data = bytearray(struct.pack("<8sIIII", b"RPLYMAP2", 2, len(ranges), len(bindings), 24+len(ranges)*12))
    for item in ranges:
        data.extend(struct.pack("<III", item["begin"], item["end"], item["mapped_begin"]))
    for binding in bindings:
        old = bytes.fromhex(binding["bytes"])
        item = next(r for r in ranges if r["begin"] <= binding["rva"] < r["end"])
        at = item["mapped_begin"]+binding["rva"]-item["begin"]
        section = next(s for s in sections if s["rva"] <= at < s["rva"]+len(s["data"]))
        new = bytes(section["data"][at-section["rva"]:at-section["rva"]+len(old)])
        if len(old) > 64 or len(old) != len(new):
            raise ValueError("Compiler binding signature exceeds ABI limit")
        data.extend(struct.pack("<II64s64s", binding["rva"], len(old), old, new))
    return bytes(data)


def verify_map(pe, manifest, report):
    """Check the serialized address map and both binding signatures."""
    sections = [s for s in pe.sections if s.Name.rstrip(b"\0") == b".rplmap"]
    if not report.get("rva_map", {}).get("insertions"):
        if sections:
            raise ValueError("Unexpected compiler address-map section")
        return 0
    if len(sections) != 1 or sections[0].Characteristics != 0x40000040:
        raise ValueError("Missing read-only compiler address map")
    data = sections[0].get_data()[:sections[0].Misc_VirtualSize]
    magic, version, range_count, binding_count, offset = struct.unpack_from("<8sIIII",data)
    ranges = report["rva_map"]["ranges"]
    bindings = manifest["proxy_signatures"]
    if (magic,version,range_count,binding_count,offset) != (b"RPLYMAP2",2,len(ranges),len(bindings),24+12*len(ranges)):
        raise ValueError("Compiler address-map header differs from the link report")
    if len(data) != offset+136*binding_count:
        raise ValueError("Compiler address-map extent is invalid")
    for index,item in enumerate(ranges):
        if struct.unpack_from("<III",data,24+12*index) != (item["begin"],item["end"],item["mapped_begin"]):
            raise ValueError("Compiler address-map range differs from the link report")
    for index,binding in enumerate(bindings):
        at,size,original,linked = struct.unpack_from("<II64s64s",data,offset+136*index)
        expected = bytes.fromhex(binding["bytes"])
        if at != binding["rva"] or size != len(expected) or original != expected.ljust(64,b"\0"):
            raise ValueError("Compiler binding provenance differs from recovered source")
        row = next(r for r in ranges if r["begin"] <= at < r["end"])
        mapped = row["mapped_begin"]+at-row["begin"]
        if linked != pe.get_data(mapped,size).ljust(64,b"\0"):
            raise ValueError("Compiler binding signature differs from linked code")
    return binding_count
