"""Conservative COFF external-symbol preflight for the Replay source linker.

The native catalog is evidence for names and addresses, not C++ prototypes.
This module binds a catalog alias only when its identity and symbol kind are
unambiguous, then checks undefined COFF references using the same namespace
rules as the linker.  It deliberately does not synthesize CRT/IAT aliases.
"""

from collections import defaultdict


class SymbolPreflightError(ValueError):
    pass


def _catalog_candidates(catalog):
    candidates = defaultdict(dict)
    from recovered_cpp_names import function_name, global_name
    base = catalog.get('image_base')
    for row in catalog.get("functions", []):
        if row.get('quarantined'):
            continue
        candidate = ("function", row["id"], int(row["rva"]))
        aliases = set(row.get("aliases", [])) | {row["name"], row["id"]}
        if isinstance(base, int):
            aliases.add(function_name(row['rva'], base))
        for alias in aliases:
            if alias:
                candidates[alias][candidate] = candidate
    for row in catalog.get("symbols", []):
        kind = row.get("kind", "unknown")
        candidate = (kind, row["id"], int(row["rva"]))
        aliases = set(row.get("aliases", [])) | {row["name"], row["id"]}
        if isinstance(base, int):
            aliases.add(global_name(row['rva'], base))
        for alias in aliases:
            if alias:
                candidates[alias][candidate] = candidate
    return candidates


def unique_catalog_bindings(catalog, existing, explicit_aliases=()):
    """Return safely inferred aliases and ambiguity/conflict diagnostics.

    `existing` is the exact native/import alias namespace already assembled by
    source_catalog.resolve. Explicit aliases are preserved as exact bindings;
    their catalog identity validation remains source_catalog's responsibility.
    """
    explicit_aliases = set(explicit_aliases)
    bindings = {}
    problems = []
    for alias, values in sorted(_catalog_candidates(catalog).items()):
        entries = list(values)
        targets = {(kind, rva) for kind, _, rva in entries}
        if alias in explicit_aliases:
            continue
        if len(targets) != 1:
            kinds = {kind for kind, _ in targets}
            known_rvas = {rva for _, rva in targets}
            # The generated native-symbol map can disambiguate repeated
            # same-kind names when it explicitly points at one catalog row.
            # A function/data collision remains ambiguous even at one RVA.
            if alias in existing and int(existing[alias]) in known_rvas and len(kinds) == 1:
                continue
            problems.append({"symbol": alias, "reason": "catalog alias has multiple targets or kinds",
                             "candidates": [{"kind": kind, "id": identity, "rva": rva}
                                            for kind, identity, rva in sorted(entries)]})
            continue
        kind, rva = next(iter(targets))
        if kind not in ("function", "code-label", "data-address"):
            problems.append({"symbol": alias, "reason": f"catalog kind is not safely bindable: {kind}",
                             "candidates": [{"kind": k, "id": i, "rva": v} for k, i, v in entries]})
            continue
        if alias in existing and int(existing[alias]) != rva:
            problems.append({"symbol": alias, "reason": "catalog alias conflicts with an existing native/import binding",
                             "existing_rva": int(existing[alias]), "catalog_rva": rva,
                             "candidates": [{"kind": k, "id": i, "rva": v} for k, i, v in entries]})
            continue
        bindings[alias] = rva
    return bindings, problems


def _definition_namespace(objects):
    definitions = defaultdict(list)
    commons = defaultdict(list)
    weak_fallbacks = []
    for obj in objects:
        for index, symbol in obj["symbols"].items():
            if symbol["storage"] != 2:
                continue
            section = symbol["section"]
            if section > 0:
                if not obj["sections"][section - 1].get("discarded"):
                    definitions[symbol["name"]].append((obj, index, symbol))
            elif section == -1:
                definitions[symbol["name"]].append((obj, index, symbol))
            elif section == 0 and symbol["value"] > 0:
                commons[symbol["name"]].append((obj, index, symbol))
            if "weak" in symbol:
                weak_fallbacks.append((obj, index, symbol))
    return definitions, commons, weak_fallbacks


def _weak_target(obj, symbol, available, native, seen=()):
    """Mirror relocate()'s weak fallback walk without changing COFF objects."""
    index = next((i for i, value in obj["symbols"].items() if value is symbol), None)
    visited = set(seen)
    while index is not None:
        value = obj["symbols"][index]
        if "weak" not in value or value["name"] in available or value["name"] in native:
            return value["name"] if value["name"] in available or value["name"] in native else None
        if index in visited:
            return "<weak-cycle>"
        visited.add(index)
        index = value["weak"]["fallback"]
        value = obj["symbols"].get(index)
        if value is None:
            return "<missing-weak-fallback>"
        if value["section"] > 0 or value["section"] == -1:
            return value["name"] if value["name"] in available else None
    return None


def audit_objects(objects, native, catalog, image_size, explicit_aliases=()):
    """Return an auditable report or raise with actionable unresolved names."""
    bindings, alias_problems = unique_catalog_bindings(catalog, native, explicit_aliases)
    resolved_native = dict(native)
    resolved_native.update(bindings)
    definitions, commons, _ = _definition_namespace(objects)
    available = set(definitions)
    available.update(name for name in commons if name not in resolved_native)
    failures = defaultdict(list)
    problem_by_alias = {row["symbol"]: row for row in alias_problems}
    weak_uses = []
    common_uses = []
    relocations_checked = 0
    for obj in objects:
        for section in obj["sections"]:
            if section.get("discarded"):
                continue
            for offset, index, kind in section["relocations"]:
                if kind == 0:
                    continue
                relocations_checked += 1
                symbol = obj["symbols"][index]
                name = symbol["name"]
                if symbol["section"] > 0 or symbol["section"] == -1:
                    continue
                if symbol["section"] == 0 and symbol["storage"] == 2 and symbol["value"] > 0:
                    if name in resolved_native:
                        continue
                    common_uses.append({"symbol": name, "object": obj["path"], "section": section["name"],
                                        "offset": offset, "size": symbol["value"]})
                    continue
                if name.startswith("replay_rva_"):
                    try:
                        rva = int(name[len("replay_rva_"):], 16)
                    except ValueError:
                        rva = image_size
                    if 0 <= rva < image_size:
                        continue
                    failures[name].append({"object": obj["path"], "section": section["name"],
                                           "offset": offset, "relocation_type": kind,
                                           "reason": "raw recovered RVA is outside SizeOfImage"})
                    continue
                if name in problem_by_alias and name not in explicit_aliases:
                    issue = problem_by_alias[name]
                    failures[name].append({"object": obj["path"], "section": section["name"],
                                           "offset": offset, "relocation_type": kind,
                                           "reason": issue["reason"],
                                           "catalog_candidates": issue.get("candidates", [])})
                    continue
                if name in resolved_native or name in available:
                    continue
                if "weak" in symbol:
                    fallback = _weak_target(obj, symbol, available, resolved_native)
                    if fallback:
                        if fallback.startswith("<"):
                            failures[name].append({"object": obj["path"], "section": section["name"],
                                                   "offset": offset, "relocation_type": kind,
                                                   "reason": f"invalid weak fallback: {fallback}"})
                        else:
                            weak_uses.append({"symbol": name, "fallback": fallback, "object": obj["path"]})
                        continue
                detail = {"object": obj["path"], "section": section["name"],
                          "offset": offset, "relocation_type": kind,
                          "reason": "undefined COFF external has no native, catalog, or object definition"}
                if name in problem_by_alias:
                    detail["catalog_candidates"] = problem_by_alias[name]["candidates"]
                    detail["reason"] = "undefined external has an ambiguous catalog alias"
                failures[name].append(detail)

    report = {"relocations_checked": relocations_checked,
              "unique_catalog_bindings": len(bindings),
              "catalog_alias_problems": alias_problems,
              "weak_fallbacks_used": weak_uses,
              "common_symbols_used": common_uses,
              "unresolved": [{"symbol": name, "references": refs}
                             for name, refs in sorted(failures.items())]}
    if failures:
        lines = ["C++ symbol preflight failed before recovered assembly compilation:"]
        for name, refs in sorted(failures.items()):
            locations = ", ".join(f"{r['object']}:{r['section']}+{r['offset']:#x}" for r in refs[:4])
            candidates = refs[0].get("catalog_candidates", [])
            candidate_text = ""
            if candidates:
                candidate_text = "; catalog candidates: " + ", ".join(
                    f"{row['kind']} {row['id']}@{row['rva']:#x}" for row in candidates)
            lines.append(f"  {name}: {refs[0]['reason']} ({locations}){candidate_text}")
        raise SymbolPreflightError("\n".join(lines))
    return report
