"""Audit all retained native metadata, loader pointers, and initialized data bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
from types import SimpleNamespace

import pefile

from layout import Layout, from_report, encode_relative_table

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path(os.environ.get('REPLAY_GAME_ROOT', r'E:\IW8\Builds\1.20-replay')) / 'game_dx12_ship_replay.exe'


def audit(directory):
    report = json.loads((directory / "build-report.json").read_text())
    original = pefile.PE(str(ORIGINAL), fast_load=True)
    rebuilt = pefile.PE(report["executable"], fast_load=True)
    for image in (original, rebuilt):
        image.parse_data_directories(directories=[0, 1, 3, 5, 9, 10, 13])
    digest = hashlib.sha256(Path(report["executable"]).read_bytes()).hexdigest()
    if digest != report["sha256"]:
        raise ValueError("Relocation audit artifact changed")
    if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() != report["input_sha256"]:
        raise ValueError("Relocation audit native control differs from the recovered input")
    mapped = lambda value: from_report(value, report)
    retired = lambda at: any(row["begin"] <= at < row["end"] for row in report["replacements"])
    original_base = original.OPTIONAL_HEADER.ImageBase
    original_size = original.OPTIONAL_HEADER.SizeOfImage
    extent = rebuilt.OPTIONAL_HEADER.SizeOfHeaders
    for section in sorted(rebuilt.sections, key=lambda s: s.VirtualAddress):
        if section.VirtualAddress < extent or section.VirtualAddress % rebuilt.OPTIONAL_HEADER.SectionAlignment:
            raise ValueError("Fresh PE sections overlap or lose their virtual alignment")
        extent = section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData)
    if extent > rebuilt.OPTIONAL_HEADER.SizeOfImage:
        raise ValueError("Fresh PE image extent does not cover all sections")
    if rebuilt.OPTIONAL_HEADER.AddressOfEntryPoint != mapped(original.OPTIONAL_HEADER.AddressOfEntryPoint):
        raise ValueError("Fresh PE entry point was not shifted")
    for index, old in enumerate(original.OPTIONAL_HEADER.DATA_DIRECTORY):
        new = rebuilt.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        if index in (3, 5): continue  # rebuilt active unwind and loader tables
        if index == 6:
            if new.VirtualAddress or new.Size:
                raise ValueError("Fresh build advertises the original compiler's debug directory")
            continue
        if index == 4 and (old.VirtualAddress or old.Size):
            raise ValueError("Signed input needs a separate certificate reconstruction policy")
        if (new.VirtualAddress, new.Size) != (mapped(old.VirtualAddress) if old.VirtualAddress else 0, old.Size):
            raise ValueError(f"Native PE directory was not resolved: {index}")
    executable_sections = [(s.VirtualAddress, s.VirtualAddress+s.Misc_VirtualSize)
                           for s in rebuilt.sections if s.Characteristics & 0x20000000]
    entries = {tuple(e.struct.__dict__[k] for k in ("BeginAddress", "EndAddress", "UnwindData"))
               for e in rebuilt.DIRECTORY_ENTRY_EXCEPTION}
    if len(entries) != len(rebuilt.DIRECTORY_ENTRY_EXCEPTION):
        raise ValueError("Duplicate runtime function entries")
    # The pinned native image has one zero-length runtime record. Preserve its
    # exact mapped tuple, while rejecting a newly introduced empty record.
    native_empty = {(mapped(e.struct.BeginAddress), mapped(e.struct.EndAddress), mapped(e.struct.UnwindData))
                    for e in original.DIRECTORY_ENTRY_EXCEPTION
                    if e.struct.BeginAddress == e.struct.EndAddress}
    for begin, end, unwind in entries:
        if begin == end and (begin, end, unwind) not in native_empty:
            raise ValueError("New runtime function has an empty code range")
        if not any(a <= begin <= end <= b for a, b in executable_sections):
            raise ValueError("Runtime function points outside an executable section")
        if len(rebuilt.get_data(unwind, 4)) != 4:
            raise ValueError("Runtime function lacks an unwind header")
    retained = 0
    retained_original = []
    for entry in original.DIRECTORY_ENTRY_EXCEPTION:
        row = entry.struct
        overlaps = [r for r in report["replacements"] if r["begin"] < row.EndAddress and r["end"] > row.BeginAddress]
        if overlaps:
            if not any(r["begin"] <= row.BeginAddress < row.EndAddress <= r["end"] for r in overlaps):
                raise ValueError("Replacement splits a native unwind family")
            continue
        if (mapped(row.BeginAddress), mapped(row.EndAddress), mapped(row.UnwindData)) not in entries:
            raise ValueError(f"Retained native runtime function is missing or stale: {row.BeginAddress:x}")
        retained += 1
        retained_original.append((row.BeginAddress, row.EndAddress, row.UnwindData))
    old_relocations = [e for block in original.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type]
    new_relocation_rows = [e.rva for block in rebuilt.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type == 10]
    new_relocations = set(new_relocation_rows)
    if len(new_relocation_rows) != len(new_relocations):
        raise ValueError("Duplicate loader relocation sites")
    expected_relocations = {mapped(e.rva) for e in old_relocations if not retired(e.rva)} | set(report["additional_base_relocations"])
    if expected_relocations != new_relocations:
        raise ValueError("Active loader relocations differ from retained native and compiled C++ pointer sites")
    if any(e.type != 10 for e in old_relocations) or any(e.type not in (0, 10) for b in rebuilt.DIRECTORY_ENTRY_BASERELOC for e in b.entries):
        raise ValueError("Unsupported loader relocation type")
    loader_pointers = 0
    for entry in old_relocations:
        if retired(entry.rva): continue
        site = mapped(entry.rva)
        if site not in new_relocations:
            raise ValueError(f"Native loader relocation was lost: {entry.rva:x}")
        value = int.from_bytes(original.get_data(entry.rva, 8), "little")
        expected = original_base + mapped(value-original_base) if original_base <= value < original_base+original_size else value
        if int.from_bytes(rebuilt.get_data(site, 8), "little") != expected:
            raise ValueError(f"Native loader pointer was not resolved: {entry.rva:x}")
        loader_pointers += 1
    old_exports = {(s.name, s.ordinal): s for s in original.DIRECTORY_ENTRY_EXPORT.symbols}
    new_exports = {(s.name, s.ordinal): s for s in rebuilt.DIRECTORY_ENTRY_EXPORT.symbols}
    if old_exports.keys() != new_exports.keys():
        raise ValueError("Native export identities changed")
    for key, old in old_exports.items():
        new = new_exports[key]
        if new.address != mapped(old.address) or new.forwarder != old.forwarder:
            raise ValueError("Native export target changed after shifting")

    import_functions = delay_functions = 0
    for attribute in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        before, after = getattr(original, attribute, []), getattr(rebuilt, attribute, [])
        if len(before) != len(after):
            raise ValueError("Native import DLL count changed")
        for old_dll, new_dll in zip(before, after):
            if old_dll.dll != new_dll.dll or len(old_dll.imports) != len(new_dll.imports):
                raise ValueError("Native import identity changed")
            for old, new in zip(old_dll.imports, new_dll.imports):
                if (new.name, new.ordinal, new.address) != (old.name, old.ordinal, original_base+mapped(old.address-original_base)):
                    raise ValueError("Native import thunk moved without resolving its identity and address")
                if attribute == "DIRECTORY_ENTRY_IMPORT": import_functions += 1
                else: delay_functions += 1
    for field in ("StartAddressOfRawData", "EndAddressOfRawData", "AddressOfIndex", "AddressOfCallBacks"):
        old = getattr(original.DIRECTORY_ENTRY_TLS.struct, field)
        new = getattr(rebuilt.DIRECTORY_ENTRY_TLS.struct, field)
        if new != original_base+mapped(old-original_base):
            raise ValueError(f"Native TLS field was not resolved: {field}")
    crt_callbacks = json.loads((ROOT / 'generated/crt-callback-roots.json').read_text())
    lengths = (ROOT / 'generated/instruction-lengths.bin').read_bytes()
    text_start = original.sections[0].VirtualAddress
    for callback in crt_callbacks:
        site, target = callback['site'], callback['target']
        old_code, new_code = original.get_data(site,7), rebuilt.get_data(mapped(site),7)
        if (old_code[:3] != b'\x48\x8d\x0d' or new_code[:3] != b'\x48\x8d\x0d' or
            site+7+int.from_bytes(old_code[3:],'little',signed=True) != target or
            mapped(site)+7+int.from_bytes(new_code[3:],'little',signed=True) != mapped(target) or
            lengths[target-text_start] in (0,255)):
            raise ValueError('Direct CRT destructor registration has a stale or undecoded target')

    patches = {}
    retired_metadata = set(report.get('retired_metadata_fields', []))
    for file in ("data-fixups.bin", "metadata-fixups.bin"):
        for at, target, width in struct.iter_unpack("<III", (ROOT / "generated" / file).read_bytes()):
            if retired(at) or (file == 'metadata-fixups.bin' and at in retired_metadata): continue
            value = mapped(target) + (original_base if width == 8 and file == "data-fixups.bin" else 0)
            encoded = value.to_bytes(width, "little")
            if at in patches and patches[at] != encoded:
                raise ValueError("Conflicting typed relocation records")
            patches[at] = encoded
    for item in report["metadata"].get("relative_tables", []):
        if not retired(item["at"]):
            encoded = encode_relative_table(item, mapped(item["target"]), mapped(item["base"]))
            if item["at"] in patches and patches[item["at"]] != encoded:
                raise ValueError("Conflicting table and metadata records")
            patches[item["at"]] = encoded
    unwind_adjustments = {}
    if report["rva_map"]["widened_branches"]:
        view = SimpleNamespace(points=[e["rva"] for e in report["rva_map"]["insertions"]], map=mapped)
        unwind_adjustments = Layout.unwind_offsets(view, retained_original, original.get_data)
        for at, value in unwind_adjustments.items():
            encoded = bytes([value])
            if at in patches and patches[at] != encoded:
                raise ValueError("Conflicting unwind and typed metadata records")
            patches[at] = encoded
    sections = []
    for section in original.sections:
        name = section.Name.rstrip(b"\0").decode("ascii")
        if name in (".text", ".pdata", ".reloc"): continue
        expected = bytearray(section.get_data())
        fields = 0
        for at, encoded in patches.items():
            offset = at-section.VirtualAddress
            if not 0 <= offset < len(expected): continue
            if offset+len(encoded) > len(expected):
                raise ValueError("Typed field crosses a native section boundary")
            expected[offset:offset+len(encoded)] = encoded
            fields += 1
        actual = rebuilt.get_data(mapped(section.VirtualAddress), len(expected))
        if actual != expected:
            offset = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
            raise ValueError(f"Unaccounted initialized native data change in {name} at {section.VirtualAddress+offset:x}")
        sections.append(dict(name=name, bytes=len(expected), typed_fields=fields))
    result = dict(sha256=digest, passed=True, retained_native_unwind_entries=retained,
                  runtime_function_entries=len(entries), retained_native_empty_records=len(native_empty), native_loader_pointers=loader_pointers,
                  total_loader_pointer_sites=len(new_relocations), native_exports=len(old_exports),
                  native_import_functions=import_functions, native_delay_import_functions=delay_functions,
                  native_tls_fields=4, pe_section_layout_checked=True,
                  direct_crt_destructor_registrations=len(crt_callbacks),
                  initialized_native_data=sections,
                  relative_table_elements=len(report["metadata"]["relative_tables"]),
                  relaxed_unwind_offset_fields=len(unwind_adjustments),
                  metadata_categories=report["metadata"]["counts"],
                  replaced_function_spans=report["replacements"], rva_map=report["rva_map"])
    (directory / "relocation-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    result = audit(parser.parse_args().build)
    print(json.dumps({k: result[k] for k in ("sha256", "passed", "retained_native_unwind_entries", "native_loader_pointers", "native_exports")}))
