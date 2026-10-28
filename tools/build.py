"""Compile recovered assembly and C++ objects and link a new Replay PE image.

This linker reads the source manifest, assembly objects and initialized-data
files. It does not open the original executable or embed original text bytes.
Native RVAs identify source symbols. In-place growth shifts their linked RVAs;
instructions, typed data references and PE metadata use one layout map.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import json
import re
from pathlib import Path
import struct
import subprocess
import sys
import time
import functools
import os
import shutil

from coff import align, read, select_comdats, allocate_common
import native_functions
import source_catalog
import recover
import native_unproven
import compiler_identity
import source_provenance
import mapped_cpp_aliases
import proxy_signature_registry
from layout import Layout, encode_relative_table
from native_linker import NativeLinker, NativeStages, NativeLayout

ROOT = Path(__file__).resolve().parents[1]


def _find_llvm_bin():
    configured = os.environ.get("REPLAY_LLVM_ROOT")
    candidates = []
    if configured:
        path = Path(configured).expanduser()
        candidates.extend((path, path / "bin"))
    for name in ("clang.exe", "clang"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found).parent)
    candidates.append(Path(r"C:\Program Files\LLVM\bin"))
    for candidate in candidates:
        if (candidate / "clang.exe").is_file() and (candidate / "clang++.exe").is_file():
            return candidate.resolve()
        if (candidate / "clang").is_file() and (candidate / "clang++").is_file():
            return candidate.resolve()
    raise FileNotFoundError("LLVM clang/clang++ not found; set REPLAY_LLVM_ROOT to its root or bin directory")


def _find_masm():
    configured = os.environ.get("REPLAY_MASM")
    candidates = []
    if configured:
        path = Path(configured).expanduser()
        candidates.append(path / "ml64.exe" if path.is_dir() else path)
    vswhere_roots = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]
    for root in filter(None, vswhere_roots):
        vswhere = Path(root) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if vswhere.is_file():
            result = subprocess.run([str(vswhere), "-latest", "-products", "*", "-find",
                                     r"VC\Tools\MSVC\**\bin\Hostx64\x64\ml64.exe"],
                                    capture_output=True, text=True)
            candidates.extend(Path(line.strip()) for line in result.stdout.splitlines() if line.strip())
    candidates.append(Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("MASM ml64.exe not found; set REPLAY_MASM to ml64.exe or its directory")


LLVM = _find_llvm_bin()
MASM = _find_masm()


def _reported_path(path):
    path = Path(path).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def build_output_directory(output_name, output_root=None):
    """Resolve build staging while retaining the historical project-root default."""
    root = Path(output_root).expanduser().resolve() if output_root else ROOT
    if not isinstance(output_name, str) or not output_name:
        raise ValueError("Build output name must be a non-empty relative path")
    relative = Path(output_name)
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        raise ValueError("Build output name must stay within the configured output root")
    output = (root / relative).resolve()
    if not output.is_relative_to(root):
        raise ValueError("Build output path escapes the configured output root")
    return output


def _resolve_build_record_path(value):
    """Resolve paths from both legacy root-relative and external-root build records."""
    path = Path(value)
    return (path if path.is_absolute() else ROOT / path).resolve()


def _source_path_key(path):
    """Return a stable key for source paths inside or outside the project root."""
    return _reported_path(path).replace("\\", "/")


@functools.lru_cache(maxsize=None)
def tool_digest(path, size, timestamp):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tool_identity(path):
    info = Path(path).stat()
    return dict(path=str(path), sha256=tool_digest(str(path), info.st_size, info.st_mtime_ns))


def assembly_cache_key(source):
    program = MASM if source.suffix == '.asm' else LLVM/'clang.exe'
    options = [str(program), '/nologo', '/c'] if source.suffix == '.asm' else [str(program), '--target=x86_64-pc-windows-msvc', '-c', '-o']
    return hashlib.sha256(json.dumps([hashlib.sha256(source.read_bytes()).hexdigest(), tool_identity(program), options]).encode()).hexdigest()


def compile_one(source, target, cpp=False, previous=None):
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    c_language = cpp and source.suffix.casefold() == '.c'
    arguments = [str(LLVM / ("clang++.exe" if cpp and not c_language else "clang.exe")),
                 "--target=x86_64-pc-windows-msvc", "-c", str(source), "-o", str(target)]
    if source.suffix == ".asm":
        arguments = [str(MASM), "/nologo", "/c", "/Fo"+str(target), str(source)]
    if cpp:
        if c_language:
            arguments[1:1] = ['-x', 'c']
        arguments.extend(["-ffreestanding", "-fno-stack-protector",
                          "-funwind-tables", "-ffunction-sections", "-fdata-sections",
                          "-O2", "-ffp-contract=off", "-std=c17" if c_language else "-std=c++20", "-Wall", "-Wextra", "-Werror"])
        if not c_language:
            arguments.extend(['-fno-exceptions', '-fno-rtti'])
    compiler = tool_identity(arguments[0])
    options = [arg for arg in arguments if arg not in (str(source), str(target), '/Fo'+str(target))]
    cache_key = hashlib.sha256(json.dumps([source_hash, compiler, options]).encode()).hexdigest()
    if previous and not cpp and previous.get('cache_key') == cache_key:
        cached = ROOT / previous['object']
        if cached.is_file() and hashlib.sha256(cached.read_bytes()).hexdigest() == previous['object_sha256']:
            return dict(previous, source=_reported_path(source))
    dependencies = None
    if cpp:
        dependency_file = target.with_suffix(".d")
        dependency_command = [arg for index, arg in enumerate(arguments)
                              if arg not in ("-c", "-o") and (index == 0 or arguments[index-1] != "-o")]
        dependency_command += ["-M", "-MT", "replay_deps", "-MF", str(dependency_file),
                               "-Wno-unused-command-line-argument"]
        result = subprocess.run(dependency_command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"Cannot discover source headers for {source.name}: {result.stderr}")
        dependencies = source_provenance.snapshots(source_provenance.parse_dependencies(dependency_file.read_text()))
        arguments += ["-MD", "-MT", "replay_deps", "-MF", str(dependency_file)]
    result = subprocess.run(arguments, capture_output=True, text=True)
    if result.returncode:
        (target.with_suffix(".errors.txt")).write_text(result.stdout+result.stderr)
        raise RuntimeError(f"Compilation failed: {source.name}; see {target.with_suffix('.errors.txt')}")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError(f"Source changed while compiling: {source.name}; rebuild from its new contents")
    if cpp:
        after = source_provenance.snapshots(source_provenance.parse_dependencies(dependency_file.read_text()))
        if after != dependencies:
            raise RuntimeError(f"C++ headers changed while compiling: {source.name}; rebuild")
    record = dict(source=_reported_path(source), source_sha256=source_hash,
                object=_reported_path(target), object_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                command=arguments, compiler=compiler, cache_key=cache_key)
    if cpp: record["dependencies"] = dependencies
    return record


def redirect_rva(rva, replacements, symbols):
    for item in replacements:
        if rva == item["begin"]:
            return symbols[item["symbol"]]
        if item["begin"] < rva < item["end"]:
            raise ValueError(f"Reference into replaced function interior: {rva:x}; recover a source symbol first")
    return rva


def relocate(obj, section, symbols, manifest, statistics, base_relocations, layout=None):
    data = bytearray(section["data"])
    for offset, index, kind in section["relocations"]:
        if kind == 0:
            continue
        if layout and 'original_rva' in section and layout.replaced(section['original_rva']+offset):
            continue
        symbol = obj["symbols"][index]
        visited = set()
        while 'weak' in symbol and symbol['name'] not in symbols:
            if index in visited:
                raise ValueError('Cyclic weak external fallback')
            visited.add(index)
            index = symbol['weak']['fallback']
            symbol = obj['symbols'][index]
        absolute = symbol["section"] == -1
        original_target = False
        if symbol["section"] > 0:
            defined = obj["sections"][symbol["section"]-1]
            if defined.get('discarded'):
                if 'selected' not in defined:
                    raise ValueError('Live relocation targets discarded associative metadata')
                defined = defined['selected']
            value = defined.get("original_rva", defined["rva"])+symbol["value"]
            original_target = "original_rva" in defined
        elif absolute:
            value = symbol["value"]
        else:
            name = symbol["name"]
            if name.startswith("replay_rva_"):
                value = int(name[11:], 16)
                original_target = True
                if not 0 <= value < manifest["optional"]["SizeOfImage"]:
                    raise ValueError(f"Recovered reference outside the native image: {name}")
            elif name in symbols:
                if name in manifest.get('native_symbol_rvas', {}):
                    value = manifest['native_symbol_rvas'][name]
                    original_target = True
                else:
                    value = symbols[name]
            else:
                raise ValueError(f"Unresolved symbol: {name} in {obj['path']}")
            if not layout:
                value = redirect_rva(value, manifest["replacements"], symbols)
        site = section["rva"]+offset
        if layout and "original_rva" in section:
            site = layout.map(section["original_rva"]+offset)
        if 4 <= kind <= 9:
            addend = struct.unpack_from("<i", data, offset)[0]
            value = layout.resolve(value+addend) if layout and original_target else value+addend
            result = value-(site+4+kind-4)
            if not -(1 << 31) <= result < (1 << 31):
                raise ValueError(f"REL32 cannot reach {symbol['name']}; use source that supports a wider reference")
            struct.pack_into("<i", data, offset, result)
        elif kind in (2, 3):  # ADDR32 / ADDR32NB
            addend = struct.unpack_from("<i", data, offset)[0]
            value = layout.resolve(value+addend) if layout and original_target else value+addend
            if kind == 2 and not absolute:
                value += manifest['image_base']
                if value < 1 << 32:
                    raise ValueError('ADDR32 image VA needs a HIGHLOW relocation; use a 64-bit pointer')
            if not 0 <= value < 1 << 32:
                raise ValueError(f'32-bit relocation overflow for {symbol["name"]}')
            struct.pack_into("<I", data, offset, value)
        elif kind == 1:  # IMAGE_REL_AMD64_ADDR64, including C++ function pointers
            addend = struct.unpack_from("<q", data, offset)[0]
            value = layout.resolve(value+addend) if layout and original_target else value+addend
            struct.pack_into("<Q", data, offset, value+(0 if absolute else manifest["image_base"]))
            if not absolute:
                base_relocations.add(site)
        elif kind in (10, 11):  # SECTION / SECREL refer to output sections.
            fmt = '<H' if kind == 10 else '<I'
            addend = struct.unpack_from('<H' if kind == 10 else '<i', data, offset)[0]
            anchor = layout.resolve(value) if layout and original_target else value
            if kind == 11:
                value = layout.resolve(value+addend) if layout and original_target else value+addend
            containing = [(i, s) for i, s in enumerate(manifest.get('linked_sections', []), 1)
                          if s['rva'] <= anchor < s['rva']+s['virtual_size']]
            if absolute or len(containing) != 1:
                raise ValueError('Section-relative relocation has no unique output section')
            number, target_section = containing[0]
            result = number+addend if kind == 10 else value-target_section['rva']
            if not 0 <= result < 1 << (16 if kind == 10 else 32):
                raise ValueError('Section-relative relocation overflow')
            struct.pack_into(fmt, data, offset, result)
        else:
            raise ValueError(f"Unsupported AMD64 relocation {kind} for {symbol['name']}")
        statistics[f"coff_type_{kind}"] += 1
    return data


def place_cpp(objects, native, manifest, layout, grow):
    symbols = {name: layout.map(value) for name,value in native.items()}
    replacements = {item["symbol"]: item for item in manifest["replacements"] if not item.get('retired')}
    text = manifest["sections"][0]
    tail = align(layout.map(text["rva"]+text["virtual_size"]), 16)
    tail_end = layout.map(manifest["sections"][1]["rva"])
    appended = layout.map(manifest["optional"]["SizeOfImage"])
    code_size = 0
    writable_size = 0
    data_alignment = manifest['optional']['SectionAlignment']
    native_data = next(s for s in manifest["sections"] if s["name"] == ".data")
    bss_tail = align(layout.map(native_data["rva"]+native_data["virtual_size"]), 8)
    bss_limit = layout.map(next(s["rva"] for s in manifest["sections"] if s["rva"] > native_data["rva"]))
    placements = []
    definitions = {}

    def allocate(size, alignment, writable, zero_initialized):
        nonlocal tail, code_size, writable_size, bss_tail, data_alignment
        if not writable:
            at = align(tail, alignment)
            if not grow and at+size <= tail_end:
                tail = at+size
                return at, "text_tail"
            at = align(appended+code_size, alignment)-appended
            code_size = at+size
            return appended+at, "new_code"
        at = align(bss_tail, alignment)
        if not grow and zero_initialized and at+size <= bss_limit:
            bss_tail = at+size
            return at, "native_bss_tail"
        at = align(writable_size, alignment)
        data_alignment = max(data_alignment, alignment)
        writable_size = at+size
        return at, "new_data"  # assigned after the complete code extent is known

    for obj in objects:
        for index, section in enumerate(obj["sections"], 1):
            if section.get('discarded'):
                continue
            if not section["data"] or section["name"].startswith((".debug", ".llvm")) or section["name"] == '.pdata':
                continue
            if section["name"].split("$")[0] not in (".text", ".rdata", ".xdata", ".data", ".bss"):
                raise ValueError(f"Unsupported C++ section: {section['name']}")
            names = [s for s in obj["symbols"].values() if s["section"] == index and s["storage"] == 2]
            aliases = [s["name"] for s in names]
            duplicate = next((definitions[n] for n in aliases if n in definitions), None)
            if duplicate is not None:
                raise ValueError(f"Duplicate strong definition: {aliases}")
            alignment = 1 << max(0, ((section["flags"] >> 20) & 15)-1)
            replacement = next((replacements[n] for n in aliases if n in replacements), None)
            if replacement:
                if len(names) != 1 or names[0]["value"]:
                    raise ValueError("A replacement must be compiled in its own function section")
                if not source_catalog.is_executable_function_definition(obj, names[0]):
                    raise ValueError("A replacement must be an external function in executable text")
                section["rva"], section["placement"] = layout.map(replacement["begin"]), "original_function"
                section["replacement_owner"] = replacement["symbol"]
                section["replacement_begin"] = replacement["begin"]
                section["replacement_end"] = replacement["end"]
                if section['rva'] % alignment:
                    raise ValueError(f'Replacement alignment {alignment} exceeds its original entry guarantee: {aliases}')
            else:
                section["rva"], section["placement"] = allocate(len(section["data"]), alignment,
                    bool(section["flags"] & 0x80000000), section["name"].split("$")[0] == ".bss")
            for name in aliases:
                if name in native and name not in replacements:
                    raise ValueError(f"Native symbol is not a replaceable function: {name}")
                definitions[name] = section

    data_rva = align(appended+code_size, data_alignment)
    for obj in objects:
        for section in obj["sections"]:
            if section.get("placement") == "new_data":
                section["rva"] += data_rva
        for symbol in obj["symbols"].values():
            if symbol["section"] > 0 and symbol["storage"] == 2:
                section = obj["sections"][symbol["section"]-1]
                if "rva" in section and not section.get('discarded'):
                    symbols[symbol["name"]] = section["rva"]+symbol["value"]
                    placements.append(dict(symbol=symbol["name"], rva=symbols[symbol["name"]],
                                           size=len(section["data"]), placement=section["placement"]))
    for name in replacements:
        if name not in definitions:
            raise ValueError(f"Replacement has no compiled definition: {name}")
    extra_sections = []
    if code_size:
        extra_sections.append(dict(name=".cpp", rva=appended, virtual_size=code_size,
                                   flags=0x60000020, data=bytearray(code_size)))
    if writable_size:
        extra_sections.append(dict(name=".rwcpp", rva=data_rva, virtual_size=writable_size,
                                   flags=0xC0000040, data=bytearray(writable_size)))
    return symbols, placements, extra_sections, tail, bss_tail


def write_rva(sections, rva, data):
    for section in sections:
        offset = rva-section["rva"]
        if 0 <= offset and offset+len(data) <= len(section["data"]):
            section["data"][offset:offset+len(data)] = data
            return
        if section["name"] == ".data" and len(section["data"]) <= offset and offset+len(data) <= section["virtual_size"] and not any(data):
            return  # loader-initialized BSS needs no initialized file bytes
    raise ValueError(f"No initialized section at RVA {rva:x} ({len(data)} bytes)")


def replace_directory(manifest, sections, index, data, name, flags):
    directory = manifest["directories"][index]
    for section in sections:
        offset = directory["rva"]-section["rva"]
        if 0 <= offset and offset+len(data) <= len(section["data"]):
            section["data"][offset:offset+len(data)] = data
            section["virtual_size"] = max(section["virtual_size"], offset+len(data))
            directory["size"] = len(data)
            return
    rva = align(max(s["rva"]+s["virtual_size"] for s in sections), manifest["optional"]["SectionAlignment"])
    sections.append(dict(name=name, rva=rva, virtual_size=len(data), flags=flags, data=bytearray(data)))
    directory.update(rva=rva, size=len(data))


def image_header(manifest, sections):
    old = manifest["optional"]
    file_alignment = old["FileAlignment"]
    header_size = align(0x80+24+240+40*len(sections), file_alignment)
    raw_at = header_size
    for section in sections:
        section["raw_at"] = raw_at
        section["raw_size"] = align(len(section["data"]), file_alignment)
        raw_at += section["raw_size"]
    header = bytearray(header_size)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3c, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, 0x8664, len(sections), manifest["timestamp"],
                     0, 0, 240, manifest["characteristics"])
    optional = 0x98
    struct.pack_into("<HBBIIIIIQII", header, optional, 0x20b, 22, 1,
                     sum(s["raw_size"] for s in sections if s["flags"] & 0x20),
                     sum(s["raw_size"] for s in sections if s["flags"] & 0x40),
                     old["SizeOfUninitializedData"], manifest.get("linked_entry_rva", old["AddressOfEntryPoint"]), old["BaseOfCode"],
                     old["ImageBase"], old["SectionAlignment"], file_alignment)
    for field, offset in (("MajorOperatingSystemVersion", 40), ("MinorOperatingSystemVersion", 42),
                          ("MajorImageVersion", 44), ("MinorImageVersion", 46),
                          ("MajorSubsystemVersion", 48), ("MinorSubsystemVersion", 50)):
        struct.pack_into("<H", header, optional+offset, old[field])
    image_size = align(max(s["rva"]+s["virtual_size"] for s in sections), old["SectionAlignment"])
    # Record the input image and linked layout in the rebuilt PE header.
    header[compiler_identity.OFFSET:compiler_identity.OFFSET+compiler_identity.SIZE] = compiler_identity.encode(manifest, image_size)
    struct.pack_into("<IIIIHHQQQQII", header, optional+52, old["Reserved1"], image_size,
                     header_size, 0, old["Subsystem"], old["DllCharacteristics"],
                     old["SizeOfStackReserve"], old["SizeOfStackCommit"], old["SizeOfHeapReserve"],
                     old["SizeOfHeapCommit"], old["LoaderFlags"], 16)
    for index, directory in enumerate(manifest["directories"]):
        struct.pack_into("<II", header, optional+112+index*8, directory["rva"], directory["size"])
    for index, section in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", header, optional+240+index*40,
                         section["name"].encode(), section["virtual_size"], section["rva"],
                         section["raw_size"], section["raw_at"], 0, 0, 0, 0, section["flags"])
    return header


def serialize_image(manifest, sections):
    """Build a PE byte image from the current in-memory linked sections."""
    header = image_header(manifest, sections)
    image = bytearray(header)
    for section in sections:
        if len(image) != section["raw_at"]:
            raise ValueError("Invalid fresh PE section layout")
        image.extend(section["data"])
        image.extend(b"\0"*(section["raw_size"]-len(section["data"])))
    return bytes(image)


def select_runtime_functions(data, replacements):
    """Python oracle retained for explicit backend comparisons."""
    retained, removed = [], 0
    for entry in struct.iter_unpack('<III', data):
        if any(entry[0] < item['end'] and entry[1] > item['begin'] for item in replacements):
            if not any(item['begin'] <= entry[0] and entry[1] <= item['end'] for item in replacements):
                raise ValueError('Replacement intersects a shared unwind range; recover the complete function')
            removed += 1
        else:
            retained.append(entry)
    return removed, retained


def python_loader_tables(manifest, sections, original_unwind, cpp_unwind, base_relocations, layout):
    """Explicit reference implementation for C++ PE-table reconstruction."""
    removed, retained_original = select_runtime_functions(original_unwind, manifest['replacements'])
    entries = sorted([tuple(layout.map(value) for value in entry) for entry in retained_original]
                     + list(struct.iter_unpack('<III', cpp_unwind)))
    for first, second in zip(entries, entries[1:]):
        if first[1] > second[0]:
            raise ValueError('Overlapping runtime function ranges')
    old_reloc_section = next(s for s in sections if s['name'] == '.reloc')
    directory = manifest['directories'][5]
    offset = layout.map(directory['rva']) - old_reloc_section['rva']
    old_reloc = old_reloc_section['data'][offset:offset + directory['size']]
    position = 0
    relocation_pages = collections.defaultdict(set)
    while position < len(old_reloc):
        page, size = struct.unpack_from('<II', old_reloc, position)
        if size < 8 or size % 2 or position + size > len(old_reloc):
            raise ValueError('Invalid original base relocation block')
        for (value,) in struct.iter_unpack('<H', old_reloc[position + 8:position + size]):
            at = page + (value & 0xfff)
            if value >> 12 and not layout.replaced(at):
                mapped = layout.map(at)
                relocation_pages[mapped & -4096].add((value & 0xf000) + (mapped & 4095))
        position += size
    for at in base_relocations:
        relocation_pages[at & -4096].add(0xa000 + (at & 4095))
    relocation_data = bytearray()
    for page, values in sorted(relocation_pages.items()):
        values = sorted(values)
        if len(values) % 2:
            values.append(0)
        relocation_data.extend(struct.pack('<II', page, 8 + len(values) * 2))
        relocation_data.extend(struct.pack(f'<{len(values)}H', *values))
    for directory in manifest['directories']:
        if directory['rva']:
            directory['rva'] = layout.map(directory['rva'])
    replace_directory(manifest, sections, 3, b''.join(struct.pack('<III', *entry) for entry in entries), '.pdata2', 0x40000040)
    replace_directory(manifest, sections, 5, relocation_data, '.reloc2', 0x42000040)
    manifest['directories'][6] = dict(rva=0, size=0)
    return removed, retained_original


def build(jobs, skip_assembly=False, grow=False, output_name="build",
          output_root=None, link_backend="native", compare_link_backends=False):
    backend_inputs = source_provenance.snapshots([ROOT/'tools'/name for name in (
        'build.py', 'coff.py', 'layout.py', 'native_functions.py', 'compiler_identity.py',
        'source_provenance.py', 'source_catalog.py', 'proxy_patterns.py', 'workstation_sources.py',
        'workstation_global_sources.py', 'proxy_signature_registry.py', 'mapped_cpp_aliases.py',
        'native_linker.py', 'cpp_symbol_preflight.py', 'recovered_cpp_names.py', 'native_unproven.py')]
        + [ROOT/'source-units.json', ROOT/'tools/native/replay_linker.cpp', ROOT/'tools/native/replay_link_stages.hpp'])
    workstation_units_path = ROOT / 'source-workstation' / 'units.json'
    if workstation_units_path.exists():
        backend_inputs += source_provenance.snapshots([workstation_units_path])
    workstation_users_path = ROOT / 'source-workstation' / 'user-functions.json'
    if workstation_users_path.exists():
        backend_inputs += source_provenance.snapshots([workstation_users_path])
    generated = ROOT / "generated"
    output = build_output_directory(output_name, output_root)
    output.mkdir(parents=True, exist_ok=True)
    if link_backend not in ('native', 'python'):
        raise ValueError('Unknown link backend')
    if compare_link_backends and link_backend != 'native':
        raise ValueError('Backend comparison requires the native linker')
    stages = NativeStages(output, LLVM, compare_link_backends) if link_backend == 'native' else None
    manifest = json.loads((generated / "manifest.json").read_text())
    if manifest.get('backend_version') != 2 or manifest.get('preparation_inputs') != recover.preparation_inputs(generated):
        print('Recovery inputs changed; regenerating assembly and metadata from the pinned image', flush=True)
        subprocess.run([sys.executable, str(ROOT/'tools/recover.py')], check=True)
        manifest = json.loads((generated / 'manifest.json').read_text())
    baseline_catalog_path = generated / 'function-catalog.json'
    baseline_catalog_sha256 = hashlib.sha256(baseline_catalog_path.read_bytes()).hexdigest() if baseline_catalog_path.exists() else None
    if baseline_catalog_sha256 and hashlib.sha256(baseline_catalog_path.read_bytes()).hexdigest() != baseline_catalog_sha256:
        raise ValueError('Baseline function catalog changed while preparing build inputs')
    recovered_names = json.loads((generated/manifest['symbols_file']).read_text())
    catalog_path = output / 'catalog-snapshot' / 'function-catalog.json'
    catalog_document, sqlite_provenance = source_catalog.refresh(
        generated, manifest['image_base'], manifest['input_sha256'], recovered_names,
        catalog_path, previous_catalog=json.loads(baseline_catalog_path.read_text()) if baseline_catalog_path.exists() else None)
    catalog_sha256 = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    backend_inputs += source_provenance.snapshots([catalog_path, Path(sqlite_provenance['catalog_rows_path'])])
    workstation_cache = os.environ.get("REPLAY_WORKSTATION_CACHE")
    import workstation_sources
    source_cache_root = (Path(workstation_cache).expanduser().resolve() / "sources"
                         if workstation_cache else ROOT / "cache" / "sources")
    source_workspace = workstation_sources.SourceWorkspace(ROOT, source_cache_root)
    baseline_units_doc = source_workspace.build_source_units(catalog_document)
    if baseline_catalog_sha256 and hashlib.sha256(baseline_catalog_path.read_bytes()).hexdigest() != baseline_catalog_sha256:
        raise ValueError('Baseline function catalog changed while composing source profile')
    global_overrides = []
    global_override_root = None
    if workstation_cache:
        global_override_root = Path(workstation_cache).expanduser().resolve() / "globals"
        if global_override_root.is_dir():
            import workstation_global_sources
            global_workspace = workstation_global_sources.GlobalSourceWorkspace(
                ROOT, Path(workstation_cache).expanduser().resolve(), verify_executable=False)
            global_overrides = global_workspace.load_build_overrides()
            backend_inputs += source_provenance.snapshots([Path(item["source"]) for item in global_overrides])
    recovery_inputs = source_provenance.snapshots(sorted(p for p in generated.iterdir()
        if p.is_file() and p.suffix in ('.json', '.bin', '.asm')))
    recovery_inputs += source_provenance.snapshots([catalog_path])
    forbidden = "game_dx12_ship_replay.exe"
    def source_only(event, arguments):
        if event == "open" and isinstance(arguments[0], (str, bytes)):
            path = Path(arguments[0])
            if path.name.lower() == forbidden:
                raise PermissionError("The build must not open the original Replay executable")
    sys.addaudithook(source_only)
    records = []
    sources_by_chunk = {chunk["file"]: generated / "asm" / chunk["file"]
                        for chunk in manifest["chunks"]}
    if not skip_assembly:
        cache_file = output / "assembly-build.json"
        cached = {Path(r["source"]).name:r for r in json.loads(cache_file.read_text())} if cache_file.exists() else {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as workers:
            tasks = {workers.submit(compile_one, sources_by_chunk[chunk["file"]],
                                    output/(Path(chunk["file"]).stem+".obj"),
                                    previous=cached.get(chunk["file"])): chunk for chunk in manifest["chunks"]}
            failures = []
            for number, future in enumerate(concurrent.futures.as_completed(tasks), 1):
                try:
                    records.append(future.result())
                    print(f"Assembled {number}/{len(tasks)}: {tasks[future]['file']}", flush=True)
                except RuntimeError as error:
                    failures.append(str(error))
            if failures:
                raise RuntimeError("\n".join(failures))
        (output / "assembly-build.json").write_text(json.dumps(records, indent=2)+"\n")
    else:
        # Layout variants can share objects: relocation happens at link time.
        # Accept a cache only after checking every source and object hash.
        for cache in dict.fromkeys((output / "assembly-build.json", ROOT / "build" / "assembly-build.json")):
            if not cache.exists():
                continue
            candidate = json.loads(cache.read_text())
            candidate_by_file = {Path(r["source"]).name: r for r in candidate}
            if len(candidate) == len(manifest["chunks"]) and set(candidate_by_file) == {c["file"] for c in manifest["chunks"]} and all(
                   _resolve_build_record_path(r["source"]) == sources_by_chunk[chunk["file"]].resolve() and
                   _resolve_build_record_path(r["source"]).is_file() and
                   _resolve_build_record_path(r["object"]).is_file() and
                   hashlib.sha256(_resolve_build_record_path(r["source"]).read_bytes()).hexdigest() == r["source_sha256"] and
                   r.get('compiler') == tool_identity(r['command'][0]) and
                   r.get('cache_key') == assembly_cache_key(sources_by_chunk[chunk['file']]) and
                   hashlib.sha256(_resolve_build_record_path(r["object"]).read_bytes()).hexdigest() == r["object_sha256"]
                   for chunk in manifest["chunks"] for r in (candidate_by_file[chunk["file"]],)):
                records = candidate
                break
        else:
            raise ValueError("No verified assembly cache matches the recovered source; reassemble it")
        (output / "assembly-build.json").write_text(json.dumps(records, indent=2)+"\n")
    cpp_records = []
    sources = sorted([*(ROOT / "src").glob("*.cpp"), *(ROOT / "src").glob("*.c")])
    source_stems = collections.Counter(path.stem.casefold() for path in sources)
    for source in sources:
        # Distinct nested overlay sources can share a filename. Never let the
        # second compile overwrite the first object's bytes or provenance.
        object_stem = source.stem
        if source_stems[source.stem.casefold()] > 1:
            object_stem += '-' + hashlib.sha256(_source_path_key(source).encode()).hexdigest()[:16]
        cpp_records.append(compile_one(source, output/(object_stem+".obj"), cpp=True))
    workstation_user_functions = []
    if workstation_users_path.exists():
        user_doc = json.loads(workstation_users_path.read_text(encoding='utf-8'))
        if user_doc.get('schema') != 1 or user_doc.get('image_sha256') != manifest['input_sha256']:
            raise ValueError('New workstation C++ functions belong to a different Replay image or schema')
        compiled_by_path = {Path(record['source']).as_posix(): record for record in cpp_records}
        for identity, user in sorted(user_doc.get('functions', {}).items()):
            source = (ROOT / user['path']).resolve()
            if not source.is_relative_to(ROOT / 'src') or not source.is_file():
                raise ValueError(f'New C++ function source path escapes src/: {identity}')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if digest != user.get('sha256') or digest != user.get('revision'):
                raise ValueError(f'New C++ source revision/hash mismatch: {identity}')
            record = compiled_by_path.get(Path(user['path']).as_posix())
            if record is None:
                raise ValueError(f'New C++ function was not compiled: {identity}')
            record['user_function_id'] = identity
            record['user_function_name'] = user['name']
            workstation_user_functions.append({"id": identity, "name": user["name"],
                                               "source": user["path"], "source_sha256": digest,
                                               "compiled_object_sha256": record["object_sha256"]})
    objects = []
    for record in cpp_records:
        obj = read(ROOT/record["object"])
        obj["source_path"] = str(_resolve_build_record_path(record["source"]).resolve())
        objects.append(obj)
    binding_units_doc = baseline_units_doc
    resolved_units_doc, cpp_native_aliases = mapped_cpp_aliases.resolve_units(
        binding_units_doc, cpp_records, objects, ROOT, catalog_document=catalog_document)
    alias_manifest = {"schema": "replay-mapped-cpp-link-aliases-v1",
                      "effective_source_units_canonical_sha256": hashlib.sha256(json.dumps(
                          binding_units_doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                      "aliases": cpp_native_aliases}
    alias_manifest_path = output / "cpp-native-link-aliases.json"
    alias_manifest_path.write_text(json.dumps(alias_manifest, indent=2) + "\n", encoding="utf-8")
    alias_manifest_sha256 = hashlib.sha256(alias_manifest_path.read_bytes()).hexdigest()
    workstation_assembly_records = []
    workstation_assembly_objects = {}
    if workstation_units_path.exists():
        workstation_units = json.loads(workstation_units_path.read_text(encoding='utf-8'))
        if workstation_units.get('schema') != 1 or workstation_units.get('image_sha256') != manifest['input_sha256']:
            raise ValueError('Workstation assembly units belong to a different Replay image or schema')
        seen_assembly_ids = set()
        for unit in workstation_units.get('units', []):
            if unit.get('kind') != 'assembly':
                continue
            identity = unit.get('function_id')
            if not isinstance(identity, str) or identity in seen_assembly_ids:
                raise ValueError('Duplicate or malformed workstation assembly identity')
            seen_assembly_ids.add(identity)
            catalog_row = next((r for r in catalog_document['functions']
                                if r['id'] == identity), None)
            if catalog_row is None:
                raise ValueError(f'Unknown workstation assembly function identity: {identity}')
            if catalog_row.get('quarantined'):
                raise ValueError(f'Workstation assembly function identity is retired by fresh analysis: {identity}')
            source = (ROOT / unit['source']).resolve()
            if not source.is_relative_to(ROOT / 'source-workstation' / 'assembly') or not source.is_file():
                raise ValueError(f'Workstation assembly path escapes its managed directory: {source}')
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if source_hash != unit.get('sha256') or source_hash != unit.get('revision'):
                raise ValueError(f'Workstation assembly revision/hash mismatch: {identity}')
            target = output / f'workstation-{identity}.obj'
            record = compile_one(source, target)
            record.update(function_id=identity, target_rva=catalog_row['rva'],
                          association='stable function catalog ID; native owner/extent derived by FunctionIndex')
            workstation_assembly_records.append(record)
            unit_object = read(ROOT / record['object'])
            objects.append(unit_object)
            workstation_assembly_objects[identity] = unit_object
            backend_inputs += source_provenance.snapshots([source])
    if stages:
        stages.select_comdats(objects)
    else:
        select_comdats(objects)
    native_record = compile_one(generated / manifest["native_assembly"]["file"], output / "native-encodings.obj")
    native_object = read(ROOT / native_record["object"])
    def checked_file(filename, digest):
        data = (generated / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Recovered source metadata changed: {filename}")
        return data
    native = json.loads(checked_file(manifest["symbols_file"], manifest["symbols_sha256"]))
    source_units = source_catalog.resolve(manifest, native, objects, catalog_path=catalog_path,
                                          document=resolved_units_doc)
    compiled_sources = {(ROOT/record['source']).resolve() for record in cpp_records}
    for unit in source_units:
        if (ROOT/unit['source']).resolve() not in compiled_sources:
            raise ValueError(f'Source identity does not match a compiled translation unit: {unit["source"]}')
    # Opaque catalog IDs are also valid C++ linkage names. Unnamed functions
    # can be called/replaced directly without addresses or an association file.
    catalog = catalog_document
    for alias, target_rva in source_catalog.unique_alias_targets(catalog).items():
        if alias in native and native[alias] != target_rva:
            raise ValueError(f'Current SQLite/recovered alias conflicts with linked native binding: {alias}')
        native[alias] = target_rva
    for row in catalog['functions']+catalog.get('symbols',[]):
        if row.get('quarantined'):
            continue
        if row['id'] in native and native[row['id']] != row['rva']:
            raise ValueError('Stable catalog identity conflicts with a native symbol')
        native[row['id']] = row['rva']
    if stages:
        stages.allocate_common(objects, native)
    else:
        allocate_common(objects, native)
    manifest['native_symbol_rvas'] = native
    data_fixups = checked_file(manifest["fixups_file"], manifest["fixups_sha256"])
    assembly_objects = {}
    native_text = bytearray(manifest["sections"][0]["raw_size"])
    for chunk in manifest["chunks"]:
        record = next(r for r in records if Path(r["source"]).name == chunk["file"])
        obj = read(ROOT / record["object"])
        code = next(s for s in obj["sections"] if s["name"] == ".text")
        if len(code["data"]) != chunk["size"]:
            raise ValueError(f"Assembler changed the chunk extent: {chunk['file']}")
        code["original_rva"] = code["rva"] = chunk["rva"]
        at = chunk["rva"]-manifest["sections"][0]["rva"]
        native_text[at:at+len(code["data"])] = code["data"]
        assembly_objects[chunk["file"]] = (obj, code)
    data_sources = [(s, checked_file(s['file'], s['sha256'])) for s in manifest['sections'] if 'file' in s]
    def read_native_data(rva, size):
        for s, data in data_sources:
            offset = rva-s['rva']
            if 0 <= offset and offset+size <= len(data):
                return data[offset:offset+size]
        raise ValueError(f'Native metadata outside initialized source at {rva:#x}')
    lengths = (generated/'instruction-lengths.bin').read_bytes()
    evidence = manifest.get('terminal_unowned_evidence')
    if evidence:
        checked_file(evidence['file'], evidence['sha256'])
    elif (generated / native_unproven.FILE).exists():
        raise ValueError('Terminal unowned evidence changed; regenerate native source before compiling')
    unproven = native_unproven.load(generated, manifest['input_sha256'],
        manifest.get('input_md5', ''), manifest['sections'][0]['rva'],
        manifest['sections'][0]['rva'] + manifest['sections'][0]['raw_size'])
    unproven.verify_bytes(native_text, manifest['sections'][0]['rva'])
    callback_thunks = unproven.prove_callback_thunks(
        manifest, assembly_objects, lengths,
        (generated / 'instruction-confidence.bin').read_bytes(), read_native_data)
    callback_objects = []
    callback_records = []
    for thunk in callback_thunks:
        source = output / f'native-callback-{thunk["rva"]:08x}.s'
        first, second = (row['target'] for row in thunk['references'])
        source.write_text('.intel_syntax noprefix\n.text\n'
                          'push r8\npush rdx\npush rcx\nsub rsp, 32\n'
                          f'call qword ptr [rip + replay_rva_{first:08x}]\n'
                          'add rsp, 32\npop rcx\npop rdx\npop r8\n'
                          f'jmp qword ptr [rip + replay_rva_{second:08x}]\n'
                          '.byte 0xcc, 0xcc, 0xcc, 0xcc\n')
        record = compile_one(source, source.with_suffix('.obj'))
        obj = read(ROOT / record['object'])
        code = next(row for row in obj['sections'] if row['name'] == '.text')
        raw = bytearray.fromhex(thunk['raw_hex'])
        for reference in thunk['references']:
            raw[reference['offset']:reference['offset'] + 4] = b'\0' * 4
        expected = {(ref['offset'], f'replay_rva_{ref["target"]:08x}', 4)
                    for ref in thunk['references']}
        actual = {(offset, obj['symbols'][symbol]['name'], kind)
                  for offset, symbol, kind in code['relocations']}
        if code['data'] != raw or actual != expected:
            raise ValueError('Assembler changed the independently proven callback thunk')
        code['original_rva'] = code['rva'] = thunk['rva']
        callback_objects.append((obj, code))
        callback_records.append(dict(**thunk, compilation=record))
    manifest['function_entries'] = sorted({row['rva'] for row in catalog['functions'] if not row.get('quarantined')})
    index = native_functions.FunctionIndex(manifest, read_native_data, lengths)
    targets = native_functions.branch_references(manifest, assembly_objects, lengths)
    # Hand-authored assembly must emit real COFF unwind metadata for every
    # replacement. Even a previously leaf function can acquire stack state in
    # an edit, so the workstation source always emits real COFF unwind data.
    # The PE-derived ownership and range stay authoritative; stack behavior is
    # represented by assembler .seh directives, never a guessed stub.
    import workstation_sources
    for identity, obj in workstation_assembly_objects.items():
        workstation_sources.verify_assembly_coff(identity, obj)
    manifest['replacements'] = index.replacements(objects, native, native_text, targets)
    catalog_ids = {row['id'] for row in catalog['functions']+catalog.get('symbols',[]) if not row.get('quarantined')}
    identities = {row['rva']: row['id'] for row in catalog['functions'] if not row.get('quarantined')}
    function_index = index.report({name: value for name, value in native.items() if name not in catalog_ids})
    for row in function_index['functions']:
        row['identity'] = identities.get(row['rva'], source_catalog.stable_id(manifest['input_sha256'], row['rva']))
    (output/'function-index.json').write_text(json.dumps(function_index, indent=2)+'\n')
    (output/'replacement-plan.json').write_text(json.dumps(manifest['replacements'], indent=2)+'\n')
    sizes = {}
    for obj in objects:
        for symbol in obj["symbols"].values():
            if symbol["name"] in {r["symbol"] for r in manifest["replacements"]} and symbol["section"] > 0 and not obj['sections'][symbol['section']-1].get('discarded'):
                sizes[symbol["name"]] = len(obj["sections"][symbol["section"]-1]["data"])
    layout = NativeLayout(manifest, sizes, native_text, stages) if stages else Layout(manifest, sizes, native_text)
    unproven.verify_layout(layout)
    native_linker = NativeLinker(layout, manifest, output, LLVM, compare_link_backends) if stages else None
    if native_linker:
        layout.engine = native_linker
        symbols, placements, extra_sections, tail, bss_tail = native_linker.place(objects, native, grow, place_cpp)
    else:
        symbols, placements, extra_sections, tail, bss_tail = place_cpp(objects, native, manifest, layout, grow)
    interior_mappings = []
    for obj in objects:
        for section_index, section in enumerate(obj["sections"], 1):
            owner = section.get("replacement_owner")
            if not owner:
                continue
            begin, end = section["replacement_begin"], section["replacement_end"]
            for symbol in obj["symbols"].values():
                if symbol["section"] != section_index:
                    continue
                match = re.fullmatch(r"L_([0-9a-fA-F]{8})", symbol["name"])
                if not match:
                    continue
                original_rva = int(match[1], 16)
                if original_rva == end:
                    continue
                if not begin < original_rva < end:
                    raise ValueError(f"Generated instruction label {symbol['name']} escapes replacement {owner}")
                offset = symbol["value"]
                if offset >= len(section["data"]):
                    raise ValueError(f"Generated instruction label {symbol['name']} is outside replacement code")
                text_rva = manifest["sections"][0]["rva"]
                instruction_offset = original_rva - text_rva
                if (instruction_offset < 0 or instruction_offset >= len(lengths) or
                        lengths[instruction_offset] in (0, 255)):
                    raise ValueError(f"Generated label {symbol['name']} is not a proven native instruction boundary")
                interior_mappings.append((original_rva, section["rva"] + offset, owner))
    layout.add_interior_rvas(interior_mappings)
    if native_linker:
        native_linker.update_sections([])
        backend_inputs += native_linker.identity['inputs'] + source_provenance.snapshots([Path(native_linker.identity['library'])])
        print('Using compiled C++ source linker' + (' with Python parity checks' if compare_link_backends else ''), flush=True)
    def link_relocate(obj, section, symbols, manifest, statistics, base_relocations, layout):
        if native_linker:
            return native_linker.relocate(obj, section, symbols, manifest, statistics, base_relocations, layout, reference=relocate)
        return relocate(obj, section, symbols, manifest, statistics, base_relocations, layout)
    text_section = manifest["sections"][0]
    original_text = bytearray(text_section["raw_size"])
    statistics = collections.Counter()
    base_relocations = set()
    for chunk in manifest["chunks"]:
        obj, code = assembly_objects[chunk["file"]]
        code_bytes = link_relocate(obj, code, symbols, manifest, statistics, base_relocations, layout)
        offset = chunk["rva"]-text_section["rva"]
        original_text[offset:offset+len(code_bytes)] = code_bytes
    text = layout.copy_text(original_text)
    for obj, code in callback_objects:
        code_bytes = link_relocate(obj, code, symbols, manifest, statistics, base_relocations, layout)
        offset = layout.map(code['original_rva']) - text_section['rva']
        text[offset:offset + len(code_bytes)] = code_bytes
    layout.branches(text, manifest)
    for item in manifest['replacements']:
        begin, end = layout.map(item['begin']), layout.map(item['end'])
        text[begin-text_section['rva']:end-text_section['rva']] = b'\xcc'*(end-begin)
    text.extend(b"\0"*max(0, tail-text_section["rva"]-len(text)))
    sections = []
    for original in manifest["sections"]:
        section = dict(original)
        section["rva"] = layout.map(original["rva"])
        if section["name"] == ".text":
            section["data"] = text
            section["virtual_size"] = max(section["virtual_size"], len(text))
        else:
            data = (generated/section["file"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != section["sha256"]:
                raise ValueError(f"Initialized data changed: {section['file']}")
            section["data"] = bytearray(data)
        if section["name"] == ".data":
            section["virtual_size"] = max(section["virtual_size"], bss_tail-section["rva"])
        sections.append(section)
    sections.extend(extra_sections)
    manifest['linked_sections'] = sections
    if native_linker:
        native_linker.update_sections(sections)
    native_labels = {s["name"]: s for s in native_object["symbols"].values()}
    for instruction in manifest["native_assembly"]["instructions"]:
        rva, size = instruction["rva"], instruction["size"]
        first, last = native_labels[f"native_{rva:08x}"], native_labels[f"native_end_{rva:08x}"]
        code = native_object["sections"][first["section"]-1]
        if first["section"] != last["section"] or last["value"]-first["value"] != size or code["relocations"]:
            raise ValueError(f"Native assembler changed a byte-sensitive instruction at {rva:x}")
        write_rva(sections, layout.map(rva), code["data"][first["value"]:last["value"]])
    cpp_unwind = bytearray()
    for obj in objects:
        for section in obj["sections"]:
            if section.get('discarded'):
                continue
            if section["name"] == ".pdata":
                section["rva"] = 0
                cpp_unwind.extend(link_relocate(obj, section, symbols, manifest, statistics, base_relocations, layout))
            elif "placement" in section and not section.get("duplicate"):
                write_rva(sections, section["rva"], link_relocate(obj, section, symbols, manifest, statistics, base_relocations, layout))

    # Every original image pointer, recognized RVA jump-table element and EAT
    # entry is resolved through the same replacement map as instruction calls.
    changed_data_references = 0
    if native_linker:
        va_count, rva_count, changed_data_references = native_linker.references(sections, data_fixups)
        statistics.update(native_va_references=va_count, native_rva_references=rva_count)
    else:
        for at, target, width in struct.iter_unpack("<III", data_fixups):
            if any(item["begin"] <= at < item["end"] for item in manifest["replacements"]):
                continue
            resolved = layout.resolve(target)
            write_rva(sections, layout.map(at), struct.pack("<Q" if width == 8 else "<I", resolved+(manifest["image_base"] if width == 8 else 0)))
            statistics["native_va_references" if width == 8 else "native_rva_references"] += 1
            changed_data_references += resolved != target

    original_pdata = next(s for s in sections if s["name"] == ".pdata")
    directory = manifest["directories"][3]
    offset = layout.map(directory["rva"])-original_pdata["rva"]
    original_unwind = bytes(original_pdata['data'][offset:offset + directory['size']])
    if native_linker:
        removed_count, retained_original = native_linker.retained_unwind(original_unwind)
        if compare_link_backends and (removed_count, retained_original) != select_runtime_functions(original_unwind, manifest['replacements']):
            raise ValueError('Native/Python unwind ownership parity failed')
    else:
        removed_count, retained_original = select_runtime_functions(original_unwind, manifest['replacements'])
    # The recovered metadata includes typed RVA fields, independently of the
    # loader's VA relocation table. Retired replacement unwind records are
    # excluded by recovery; references into live replacement interiors fail.
    metadata = manifest.get("metadata")
    if metadata and metadata.get("unrecovered_switch_targets"):
        raise ValueError("Recover missing native switch code before linking")
    if layout.events and not metadata:
        raise ValueError("Recover native RVA metadata before linking a shifted layout")
    retired_metadata_fields = set()
    if metadata:
        owners = collections.defaultdict(set)
        for root, fields in metadata.get('unwind_ownership', {}).items():
            for field in fields:
                owners[field].add(int(root))
        retired_metadata_fields = {at for at, roots in owners.items() if all(layout.replaced(root) for root in roots)}
        metadata_fixups = checked_file(metadata["file"], metadata["sha256"])
        if native_linker:
            va_count, rva_count, _changed = native_linker.references(sections, metadata_fixups, True, retired_metadata_fields)
            statistics['metadata_rva_references'] += va_count + rva_count
        else:
            for at,target,width in struct.iter_unpack("<III", metadata_fixups):
                if layout.replaced(at) or at in retired_metadata_fields:
                    continue
                resolved = layout.resolve(target)
                write_rva(sections, layout.map(at), resolved.to_bytes(width, "little"))
                statistics["metadata_rva_references"] += 1
        for item in metadata.get("relative_tables", []):
            if layout.replaced(item["at"]):
                continue
            encoded = native_linker.relative_table(item) if native_linker else encode_relative_table(item, layout.resolve(item['target']), layout.map(item['base']))
            write_rva(sections, layout.map(item['at']), encoded)
            statistics["switch_table_references"] += 1
    def original_metadata(rva,size):
        source = next(s for s in manifest["sections"] if s["rva"] <= rva < s["rva"]+s["raw_size"])
        data = (generated/source["file"]).read_bytes()
        return data[rva-source["rva"]:rva-source["rva"]+size]
    if layout.widened:
        for field,value in layout.unwind_offsets(retained_original,original_metadata).items():
            write_rva(sections,layout.map(field),bytes([value]))
    if native_linker:
        expected_sections = expected_manifest = None
        if compare_link_backends:
            import copy
            expected_sections = copy.deepcopy(sections)
            expected_manifest = dict(manifest, directories=copy.deepcopy(manifest['directories']))
            python_loader_tables(expected_manifest, expected_sections, original_unwind, cpp_unwind, base_relocations, layout)
        removed_final, retained_final, directories, linked = native_linker.tables(sections, original_unwind, cpp_unwind, base_relocations)
        if (removed_final, retained_final) != (removed_count, retained_original):
            raise ValueError('Native loader-table ownership changed during linking')
        if compare_link_backends and (directories != expected_manifest['directories'] or
                any({key: section[key] for key in ('name', 'rva', 'virtual_size', 'flags', 'data')} != result
                    for section, result in zip(expected_sections, linked)) or len(expected_sections) != len(linked)):
            raise ValueError('Native/Python PE loader-table parity failed')
        for index, section in enumerate(linked):
            if index < len(sections):
                sections[index].update(section)
            else:
                sections.append(section)
        manifest['directories'] = directories
    else:
        python_loader_tables(manifest, sections, original_unwind, cpp_unwind, base_relocations, layout)
    manifest["linked_entry_rva"] = layout.map(manifest["optional"]["AddressOfEntryPoint"])
    if native_linker:
        native_linker.sync_interior_uses()
    manifest["rva_map"] = layout.report(manifest)
    if layout.events:
        # A read-only, versioned map also lets external tooling resolve its
        # original Replay bindings. It never contains executable stubs.
        map_data = compiler_identity.encode_map(manifest, sections)
        map_at = align(max(s["rva"]+s["virtual_size"] for s in sections), 4096)
        sections.append(dict(name=".rplmap", rva=map_at, virtual_size=len(map_data), flags=0x40000040, data=bytearray(map_data)))
    global_initializer_reports = []
    if global_overrides:
        from workstation_global_sources import apply_global_overrides
        global_initializer_reports = apply_global_overrides(
            sections, global_overrides, layout, manifest["replacements"])
    for record in cpp_records + [row['compilation'] for row in callback_records]:
        source_provenance.validate_record(record)
    source_provenance.validate_inputs(backend_inputs + recovery_inputs)
    if hashlib.sha256(alias_manifest_path.read_bytes()).hexdigest() != alias_manifest_sha256:
        raise ValueError("Mapped C++ link-alias manifest changed during compilation")
    if hashlib.sha256(catalog_path.read_bytes()).hexdigest() != catalog_sha256:
        raise ValueError('Build-owned function catalog snapshot changed during compilation')
    source_catalog.validate_database_snapshot(sqlite_provenance)
    terminal_unowned_report = unproven.verify_bytes(
        next(section['data'] for section in sections if section['name'] == '.text'),
        manifest['sections'][0]['rva'], layout)
    # Derive linked signatures from the final in-memory PE, then append the
    # registry before recomputing the final section table and image identity.
    import proxy_patterns
    provisional = stages.serialize_image(manifest, sections, serialize_image) if stages else serialize_image(manifest, sections)
    provisional_pe = proxy_patterns.pefile.PE(data=provisional, fast_load=True)
    provisional_pe.parse_data_directories(directories=[5])
    pattern_report = {"rva_map": manifest["rva_map"]}
    embedded_pattern_entries = proxy_patterns.compiled_entries(provisional_pe, pattern_report)
    registry_bytes = proxy_signature_registry.encode(embedded_pattern_entries)
    registry_document = proxy_signature_registry.decode(registry_bytes)
    registry_rva = align(max(section["rva"]+section["virtual_size"] for section in sections),
                         manifest["optional"]["SectionAlignment"])
    if any(section["name"].rstrip("\0") == ".rplsig" for section in sections):
        raise ValueError("Duplicate embedded proxy signature section")
    sections.append(dict(name=".rplsig", rva=registry_rva,
                         virtual_size=len(registry_bytes),
                         flags=proxy_signature_registry.SECTION_CHARACTERISTICS,
                         data=bytearray(registry_bytes)))
    signature_registry_report = dict(section=".rplsig", rva=registry_rva,
                                     virtual_size=len(registry_bytes),
                                     count=len(registry_document["entries"]),
                                     identity=registry_document["identity"],
                                     sha256=hashlib.sha256(registry_bytes).hexdigest(),
                                     characteristics=proxy_signature_registry.SECTION_CHARACTERISTICS)
    image = stages.serialize_image(manifest, sections, serialize_image) if stages else serialize_image(manifest, sections)
    linker_report = dict(backend=link_backend)
    if native_linker:
        linker_report.update(identity=native_linker.identity, metrics=native_linker.metrics)
        linker_report['planning'] = stages.metrics
        linker_report['implementation'] = 'cpp-source-linker'
        native_linker.close()
    executable = output / "game_dx12_ship_replay_recompiled.exe"
    temporary_executable = executable.with_suffix('.exe.tmp')
    temporary_executable.write_bytes(image)
    temporary_executable.replace(executable)
    report = dict(executable=str(executable), sha256=hashlib.sha256(image).hexdigest(),
                  input_sha256=manifest["input_sha256"], original_executable_used_by_build=False,
                  original_executable_access_policy='Recovery reads the pinned original; the compile/link stage blocks original EXE reads',
                  original_executable_access_blocked=True, linker=linker_report,
                  symbols={name: symbols[name] for name in set(native) | {p["symbol"] for p in placements}},
                  placements=placements, replacements=manifest["replacements"],
                  cpp_region_rva=align(text_section["rva"]+text_section["virtual_size"], 16),
                  cpp_unwind_entries=len(cpp_unwind)//12, removed_unwind_entries=removed_count,
                  resolved_references=dict(statistics), unresolved_symbols=0,
                  changed_data_references=changed_data_references,
                  additional_base_relocations=sorted(base_relocations),
                  original_image_size=manifest["optional"]["SizeOfImage"],
                  image_size=align(max(s["rva"]+s["virtual_size"] for s in sections), manifest["optional"]["SectionAlignment"]),
                  grow=grow,
                  function_catalog_snapshot=dict(path=_reported_path(catalog_path), sha256=catalog_sha256,
                                                 sqlite=sqlite_provenance),
                  terminal_unowned_bytes=terminal_unowned_report,
                  proxy_signature_registry=signature_registry_report,
                  global_initializers=global_initializer_reports,
                  rva_map=manifest["rva_map"], entry_rva=manifest["linked_entry_rva"],
                  backend_version=2, source_units=source_units, backend_inputs=backend_inputs, recovery_inputs=recovery_inputs,
                  cpp_native_link_aliases=dict(path=_reported_path(alias_manifest_path),
                                               sha256=alias_manifest_sha256,
                                               count=len(cpp_native_aliases), records=cpp_native_aliases),
                  source_root=str(ROOT),
                  retired_metadata_fields=sorted(retired_metadata_fields), metadata=metadata,
                  build_time_utc=int(time.time()),
                  assembly=records, native_assembly=native_record, cpp=cpp_records, sources_recovery=manifest["recovery"])
    report['workstation_assembly'] = workstation_assembly_records
    report['workstation_user_functions'] = workstation_user_functions
    report['protected_callback_thunks'] = callback_records
    (output / "build-report.json").write_text(json.dumps(report, indent=2)+"\n")
    report["proxy_patterns"] = proxy_patterns.emit_compiled(
        executable, report, expected_entries=embedded_pattern_entries)
    (output / "build-report.json").write_text(json.dumps(report, indent=2)+"\n")
    print(f"Linked {executable}\nSHA256 {report['sha256']}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--skip-assembly", action="store_true")
    parser.add_argument("--grow", action="store_true")
    parser.add_argument("--link-backend", choices=("native", "python"), default="native")
    parser.add_argument("--compare-link-backends", action="store_true",
                        default=os.environ.get('REPLAY_COMPARE_LINK_BACKENDS') == '1')
    parser.add_argument("--output", default="build")
    parser.add_argument("--output-root", type=Path)
    arguments = parser.parse_args()
    build(arguments.jobs, arguments.skip_assembly, arguments.grow, arguments.output,
          arguments.output_root, arguments.link_backend, arguments.compare_link_backends)
