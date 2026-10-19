"""Resolve mapped C++ replacements to their exact compiler-emitted COFF names.

Authored C++ linkage stays intact. A source-unit mapping supplies the native
function identity; Clang's AST supplies the exact external definition name.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess


def _documents(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    rows = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            raise ValueError("Clang AST filter returned a non-object document")
        rows.append(value)
    return rows


def _rooted(value, root: Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def _normalize_record(record: dict, root: Path) -> dict:
    """Resolve every pinned input against the build root, never process cwd."""
    normalized = copy.deepcopy(record)
    normalized["source"] = str(_rooted(record["source"], root))
    normalized["object"] = str(_rooted(record["object"], root))
    compiler = normalized.get("compiler")
    if isinstance(compiler, dict) and compiler.get("path"):
        compiler["path"] = str(_rooted(compiler["path"], root))
    dependencies = normalized.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("Mapped C++ compile record dependencies must be a list")
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not dependency.get("path"):
            raise ValueError("Mapped C++ compile record has a malformed dependency")
        dependency["path"] = str(_rooted(dependency["path"], root))
    return normalized


def _filtered_ast(record: dict, function_name: str, root: Path | None = None) -> tuple[list[str], list[dict]]:
    root = Path(root or Path.cwd()).resolve()
    record = _normalize_record(record, root)
    _verify_record(record, "before AST extraction", root)
    command = ast_command(record["command"], function_name)
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f"Cannot inspect mapped C++ function {function_name}: {result.stderr.strip()}")
    documents = _documents(result.stdout)
    _verify_record(record, "after AST extraction", root)
    return command, documents


def ast_command(command: list[str], function_name: str) -> list[str]:
    """Reuse the compile command's target/defines/options for a filtered AST."""
    result = []
    skip = False
    for arg in command:
        if skip:
            skip = False
            continue
        if arg in ("-c", "-MD", "-MMD"):
            continue
        if arg == "-o":
            skip = True
            continue
        if arg in ("-MT", "-MF"):
            skip = True
            continue
        result.append(arg)
    if skip:
        raise ValueError("Malformed recorded C++ compile command")
    result.extend(("-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang",
                   f"-ast-dump-filter={function_name}"))
    return result


def resolve_definition(record: dict, function_name: str, obj: dict, root: Path | None = None) -> dict | None:
    """Return metadata for a C++-decorated definition, or None for C linkage.

    Overloaded names, templates, methods, internal definitions, and ambiguous
    declarations fail closed because a source-unit's bare symbol cannot choose
    among them safely.
    """
    root = Path(root or Path.cwd()).resolve()
    record = _normalize_record(record, root)
    source = Path(record["source"])
    object_definitions = [symbol for symbol in obj["symbols"].values()
                          if symbol["name"] == function_name and symbol["section"] > 0
                          and symbol["storage"] == 2]
    if len(object_definitions) == 1:
        from source_catalog import is_executable_function_definition
        if not is_executable_function_definition(obj, object_definitions[0]):
            raise ValueError(f"Mapped replacement is not an external function in executable text: {function_name}")
        return None
    if object_definitions:
        raise ValueError(f"Mapped C++ symbol has multiple exact COFF definitions: {function_name}")

    command, documents = _filtered_ast(record, function_name, root)
    active_file = None
    matching = []
    header_declarations = []
    unsupported_templates = []
    other_definition_kinds = []
    for node in documents:
        location = node.get("loc", {})
        if location.get("file"):
            active_file = _rooted(location["file"], root)
        if node.get("name") != function_name:
            continue
        kind = node.get("kind")
        if active_file != source:
            if kind in ("FunctionDecl", "FunctionTemplateDecl"):
                header_declarations.append(node)
            continue
        if kind == "FunctionTemplateDecl":
            unsupported_templates.append(node)
        elif kind in ("CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl"):
            other_definition_kinds.append(kind)
        elif kind == "FunctionDecl":
            matching.append(node)
    if unsupported_templates:
        raise ValueError(f"Mapped function is a template and cannot be safely aliased: {function_name}")
    if not matching:
        detail = "member function" if other_definition_kinds else "no external free-function definition"
        raise ValueError(f"Mapped symbol has {detail}: {function_name}")

    mangled_names = {node.get("mangledName") for node in matching}
    if None in mangled_names or len(mangled_names) != 1:
        raise ValueError(f"Mapped function is overloaded or has ambiguous compiler names: {function_name}")
    mangled_name = next(iter(mangled_names))
    definitions = [node for node in matching
                   if any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))]
    if len(definitions) != 1:
        raise ValueError(f"Mapped function must have exactly one source definition: {function_name}")
    if definitions[0].get("storageClass") == "static":
        raise ValueError(f"Mapped function has internal linkage: {function_name}")
    if mangled_name == function_name:
        raise ValueError(f"Clang reports C linkage but the exact COFF symbol is absent: {function_name}")
    for node in header_declarations:
        if node.get("kind") == "FunctionTemplateDecl" or node.get("mangledName") != mangled_name:
            raise ValueError(f"Header declaration makes mapped function name ambiguous: {function_name}")

    external_definitions = [symbol for symbol in obj["symbols"].values()
                            if symbol["name"] == mangled_name and symbol["section"] > 0
                            and symbol["storage"] == 2]
    if len(external_definitions) != 1:
        raise ValueError(f"AST definition does not have one external COFF definition: {mangled_name}")
    from source_catalog import is_executable_function_definition
    if not is_executable_function_definition(obj, external_definitions[0]):
        raise ValueError(f"Mapped replacement COFF symbol is not a function in executable text: {mangled_name}")
    return {"authored_symbol": function_name, "coff_symbol": mangled_name,
            "source": str(source), "source_sha256": record["source_sha256"],
            "object": record["object"], "object_sha256": record["object_sha256"],
            "compiler": record["compiler"], "ast_command": command,
            "dependencies": record.get("dependencies", [])}


def _ast_import_name(record: dict, name: str, obj: dict, root: Path | None = None,
                     classify_plain_c: bool = False) -> dict | None:
    """Resolve one used C++ import declaration to its exact undefined COFF name."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return None
    references = {symbol["name"] for symbol in obj["symbols"].values()
                  if symbol["section"] == 0 and symbol["storage"] == 2}
    related_references = {reference for reference in references if name in reference}
    if name in related_references and related_references == {name}:
        if not classify_plain_c:
            return None  # Existing C linkage is already exact; catalog resolution handles it.
        # The symbol name is already link-compatible, but still classify its
        # declaration when available. A plain C function import must not be
        # allowed to bind to a data-address identity (or vice versa).
        root = Path(root or Path.cwd()).resolve()
        record = _normalize_record(record, root)
        source = Path(record["source"])
        command, documents = _filtered_ast(record, name, root)
        exact_functions = [node for node in documents
                           if node.get("name") == name and node.get("kind") == "FunctionDecl"
                           and node.get("mangledName") == name]
        exact_variables = [node for node in documents
                           if node.get("name") == name and node.get("kind") == "VarDecl"
                           and node.get("mangledName") == name]
        if exact_functions and exact_variables:
            raise ValueError(f"Imported C name is both a function and a variable: {name}")
        if exact_functions:
            return {"authored_symbol": name, "coff_symbol": name,
                    "source": str(source), "source_sha256": record["source_sha256"],
                    "object": record["object"], "object_sha256": record["object_sha256"],
                    "compiler": record["compiler"], "ast_command": command,
                    "dependencies": record.get("dependencies", []), "entity_kind": "function"}
        if exact_variables:
            if any(node.get("tls") for node in exact_variables):
                raise ValueError(f"Imported C TLS variable requires an explicit TLS binding: {name}")
            return {"authored_symbol": name, "coff_symbol": name,
                    "source": str(source), "source_sha256": record["source_sha256"],
                    "object": record["object"], "object_sha256": record["object_sha256"],
                    "compiler": record["compiler"], "ast_command": command,
                    "dependencies": record.get("dependencies", []), "entity_kind": "variable"}
        return None  # No exact declaration: leave legacy C resolution unchanged.
    # This is only a cheap candidate filter, never a name binding: the exact
    # Clang AST declaration and exact undefined COFF symbol must still agree.
    # Filtering on emitted symbol bytes catches included-header and macro-built
    # names without invoking Clang for unrelated imports in every translation unit.
    if not related_references:
        return None
    root = Path(root or Path.cwd()).resolve()
    record = _normalize_record(record, root)
    source = Path(record["source"])
    command, documents = _filtered_ast(record, name, root)
    declarations = []
    variable_declarations = []
    templates = []
    for node in documents:
        if node.get("name") != name:
            continue
        kind = node.get("kind")
        if kind == "FunctionTemplateDecl":
            templates.append(node)
        elif kind == "FunctionDecl":
            declarations.append(node)
        elif kind == "VarDecl":
            mangled_name = node.get("mangledName")
            if mangled_name in references:
                variable_declarations.append(node)
    if templates:
        raise ValueError(f"Imported C++ function is a template and cannot be safely aliased: {name}")
    if declarations and variable_declarations:
        raise ValueError(f"Imported C++ name is both a function and a variable: {name}")
    if variable_declarations:
        variable_names = {node.get("mangledName") for node in variable_declarations}
        if len(variable_names) != 1 or None in variable_names:
            raise ValueError(f"Imported C++ variable is ambiguous: {name}")
        if any(node.get("tls") for node in variable_declarations):
            raise ValueError(f"Imported C++ TLS variable requires an explicit TLS binding: {name}")
        if any(node.get("storageClass") == "static" for node in variable_declarations):
            raise ValueError(f"Imported C++ variable lacks external compiler identity: {name}")
        coff_name = next(iter(variable_names))
        if coff_name == name or coff_name not in references:
            return None
        if not coff_name.startswith(f"?{name}@@"):
            raise ValueError(f"Namespace-scoped C++ data import lacks catalog namespace identity: {name}")
        return {"authored_symbol": name, "coff_symbol": coff_name,
                "source": str(source), "source_sha256": record["source_sha256"],
                "object": record["object"], "object_sha256": record["object_sha256"],
                "compiler": record["compiler"], "ast_command": command,
                "dependencies": record.get("dependencies", []), "entity_kind": "variable"}
    mangled = {node.get("mangledName") for node in declarations}
    if not declarations:
        return None
    if None in mangled or len(mangled) != 1:
        raise ValueError(f"Imported C++ function is overloaded or ambiguous: {name}")
    coff_name = next(iter(mangled))
    if coff_name == name:
        return None
    if coff_name not in references:
        return None
    if not coff_name.startswith(f"?{name}@@"):
        raise ValueError(f"Namespace-scoped C++ function import lacks catalog namespace identity: {name}")
    return {"authored_symbol": name, "coff_symbol": coff_name,
            "source": str(source), "source_sha256": record["source_sha256"],
            "object": record["object"], "object_sha256": record["object_sha256"],
            "compiler": record["compiler"], "ast_command": command,
            "dependencies": record.get("dependencies", []), "entity_kind": "function"}


def _verify_record(record: dict, stage: str, root: Path | None = None) -> None:
    root = Path(root or Path.cwd()).resolve()
    pins = [(record["source"], record["source_sha256"], "authored source"),
            (record["object"], record["object_sha256"], "compiled COFF object")]
    compiler = record.get("compiler", {})
    if not compiler.get("path") or not compiler.get("sha256"):
        raise ValueError("Mapped C++ compile record has no pinned compiler identity")
    pins.append((compiler["path"], compiler["sha256"], "compiler"))
    pins.extend((item["path"], item["sha256"], "header dependency")
                for item in record.get("dependencies", []))
    for path, expected, label in pins:
        actual = hashlib.sha256(_rooted(path, root).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Mapped C++ {label} changed {stage}: {path}")


def _catalog_alias_rows(catalog_document: dict) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    rows_by_alias: dict[str, list[dict]] = {}
    from recovered_cpp_names import function_name, global_name
    base = catalog_document.get('image_base')
    for group in ("functions", "symbols"):
        for row in catalog_document.get(group, []):
            if row.get('quarantined'):
                continue
            names = set(row.get("aliases", [])) | {row.get("name", ""), row.get("id", "")}
            if isinstance(base, int):
                names.add((function_name if group == 'functions' else global_name)(row['rva'], base))
            for name in names:
                if name:
                    rows_by_alias.setdefault(name, []).append(dict(row, catalog_kind=group[:-1]))
    from source_catalog import unique_alias_targets
    unique_targets = unique_alias_targets(catalog_document)
    unique = {}
    for name, rows in rows_by_alias.items():
        signatures = {(row["id"], row["catalog_kind"], int(row["rva"])) for row in rows}
        if any(name == row["id"] for row in rows):
            if len(signatures) == 1:
                unique[name] = rows[0]
            continue
        if name not in unique_targets:
            continue
        owners = {row["id"]: row for row in rows if int(row["rva"]) == unique_targets[name]}
        if len(owners) == 1:
            unique[name] = next(iter(owners.values()))
    return rows_by_alias, unique


def _catalog_entity_kind(row: dict, group: str) -> str:
    if group == "function" or (group == "symbol" and row.get("kind") == "code-label"):
        return "function"
    return "variable"


def _cpp_candidate_identifiers(objects: list[dict]) -> set[str]:
    """Extract only simple candidate tokens from unresolved MSVC COFF names.

    This is a coarse filter, not demangling. A later exact Clang AST name and
    exact undefined-symbol equality are required before any mapping is added.
    """
    names = set()
    for obj in objects:
        for symbol in obj["symbols"].values():
            if symbol["section"] != 0 or symbol["storage"] != 2:
                continue
            decorated = symbol["name"]
            token = (decorated[1:].split("@", 1)[0]
                     if decorated.startswith("?") else decorated)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                names.add(token)
    return names


def resolve_units(document: dict, records: list[dict], objects: list[dict], root: Path,
                  catalog_document: dict | None = None) -> tuple[dict, list[dict]]:
    """Clone the full mapping document and resolve C++ names for replacements."""
    if not isinstance(document, dict) or not isinstance(document.get("units"), list):
        raise ValueError("Mapped C++ source contract has no units list")
    root = Path(root).resolve()

    by_source = {}
    for record, obj in zip(records, objects, strict=True):
        normalized_record = _normalize_record(record, root)
        key = Path(normalized_record["source"])
        if key in by_source:
            raise ValueError(f"Multiple compiled translation units have one mapped source: {key}")
        by_source[key] = (normalized_record, obj)
    resolved = copy.deepcopy(document)
    aliases = []
    seen_coff = {}
    imports = resolved.setdefault("imports", [])
    if not isinstance(imports, list):
        raise ValueError("Mapped C++ source contract imports must be a list")
    for unit in resolved["units"]:
        if not isinstance(unit, dict) or not isinstance(unit.get("symbol"), str):
            raise ValueError("Mapped C++ source contract unit is malformed")
        authored_symbol = unit["symbol"]
        source = _rooted(unit["source"], root)
        pair = by_source.get(source)
        if pair is None:
            raise ValueError(f"Mapped C++ source was not compiled: {unit['source']}")
        record, obj = pair
        alias = resolve_definition(record, authored_symbol, obj, root)
        if alias is None:
            continue
        coff_symbol = alias["coff_symbol"]
        prior = seen_coff.get(coff_symbol)
        if prior is not None and prior != unit["function_id"]:
            raise ValueError(f"One COFF definition maps to multiple native functions: {coff_symbol}")
        seen_coff[coff_symbol] = unit["function_id"]
        function_id = unit["function_id"]
        existing_imports = [item for item in imports if isinstance(item, dict)
                            and item.get("symbol") == authored_symbol]
        if any(item.get("symbol_id") != function_id for item in existing_imports):
            raise ValueError(f"Mapped C alias conflicts with an existing source import: {authored_symbol}")
        if not existing_imports:
            imports.append({"symbol": authored_symbol, "symbol_id": function_id})
        unit["symbol"] = coff_symbol
        aliases.append(dict(alias, authored_symbol=authored_symbol,
                            function_id=function_id, native_alias=authored_symbol))

    catalog_rows_by_id = {}
    if catalog_document is not None:
        catalog_rows_by_id = {row["id"]: (row, "function")
                              for row in catalog_document.get("functions", []) if not row.get('quarantined')}
        catalog_rows_by_id.update({row["id"]: (row, "symbol")
                                   for row in catalog_document.get("symbols", [])})
    for item in list(imports):
        if not isinstance(item, dict) or not isinstance(item.get("symbol"), str):
            raise ValueError("Mapped C++ source import is malformed")
        authored_symbol, function_id = item["symbol"], item.get("symbol_id")
        candidates = []
        for record, obj in zip(records, objects, strict=True):
            alias = _ast_import_name(record, authored_symbol, obj, root, classify_plain_c=True)
            if alias is not None:
                candidates.append(alias)
        coff_names = {candidate["coff_symbol"] for candidate in candidates}
        if len(coff_names) > 1:
            raise ValueError(f"Imported C++ function has conflicting compiler names: {authored_symbol}")
        if not candidates:
            continue
        if catalog_document is not None:
            catalog_row = catalog_rows_by_id.get(function_id)
            if catalog_row and any(candidate.get("entity_kind") != _catalog_entity_kind(*catalog_row)
                                   for candidate in candidates):
                raise ValueError(f"C++ import AST kind conflicts with catalog identity: {authored_symbol}")
        coff_symbol = next(iter(coff_names))
        existing = [row for row in imports if isinstance(row, dict) and row.get("symbol") == coff_symbol]
        if any(row.get("symbol_id") != function_id for row in existing):
            raise ValueError(f"Imported C++ alias conflicts with another identity: {coff_symbol}")
        if not existing and coff_symbol != authored_symbol:
            imports.append({"symbol": coff_symbol, "symbol_id": function_id})
        if coff_symbol != authored_symbol:
            aliases.append(dict(candidates[0], function_id=function_id, native_alias=authored_symbol,
                                mapping_kind="cpp-import"))

    if catalog_document is not None:
        rows_by_alias, unique_aliases = _catalog_alias_rows(catalog_document)
        existing_ids = {item["symbol"]: item["symbol_id"] for item in imports}
        for candidate_name in sorted(_cpp_candidate_identifiers(objects) & rows_by_alias.keys()):
            if candidate_name in existing_ids:
                continue  # Explicit imports and replacement-unit bindings win.
            row = unique_aliases.get(candidate_name)
            candidates = []
            for record, obj in zip(records, objects, strict=True):
                alias = _ast_import_name(record, candidate_name, obj, root, classify_plain_c=True)
                if alias is not None:
                    candidates.append(alias)
            if row is None:
                if candidates:
                    raise ValueError(f"Ambiguous catalog alias for C++ import: {candidate_name}")
                if any(symbol["name"] == candidate_name and symbol["section"] == 0
                       and symbol["storage"] == 2
                       for obj in objects for symbol in obj["symbols"].values()):
                    raise ValueError(f"Ambiguous catalog alias for C import: {candidate_name}")
                continue
            identity = row["id"]
            expected_kind = _catalog_entity_kind(row, row["catalog_kind"])
            if any(candidate.get("entity_kind") != expected_kind for candidate in candidates):
                raise ValueError(f"C++ import AST kind conflicts with catalog identity: {candidate_name}")
            coff_names = {candidate["coff_symbol"] for candidate in candidates}
            if len(coff_names) > 1:
                raise ValueError(f"Catalog C++ import has conflicting exact COFF names: {candidate_name}")
            if not candidates:
                # A decorated name can contain the candidate token without an
                # AST declaration matching it; do not infer identity from bytes.
                continue
            if next(iter(coff_names)) == candidate_name:
                # Exact C linkage already uses the native catalog spelling.
                # Validate its AST/catalog kind, but leave the resolved input
                # document and alias receipt unchanged; build.py seeds this
                # unique alias from the same catalog row later.
                continue
            imports.append({"symbol": candidate_name, "symbol_id": identity})
            coff_symbol = next(iter(coff_names))
            existing = [item for item in imports if item.get("symbol") == coff_symbol]
            if any(item.get("symbol_id") != identity for item in existing):
                raise ValueError(f"Inferred C++ alias conflicts with another identity: {coff_symbol}")
            if not existing:
                imports.append({"symbol": coff_symbol, "symbol_id": identity})
            aliases.append(dict(candidates[0], function_id=identity, native_alias=candidate_name,
                                mapping_kind="catalog-cpp-import", catalog_kind=row["catalog_kind"]))
    return resolved, aliases
