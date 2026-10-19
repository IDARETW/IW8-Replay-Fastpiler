"""Read-only comparisons. Never substitute a saved edit for recovered original code."""
from __future__ import annotations

import difflib
import hashlib
import json
import re


def list_changes(app):
    sources = app.sources
    state = sources._state()
    items = {}

    def source_item(identity, variant="cpp", path=None):
        try:
            row = sources._by_identity(identity)
            name = sources._display_name(row)
        except KeyError:
            row = state.get("user_sources", {}).get(identity)
            if not row:
                raise
            name = row["name"]
        key = f"source:{identity}:{variant}"
        items[key] = dict(key=key, kind="source", id=identity, variant=variant,
                          name=name, path=path or row.get("path"),
                          category="New functions" if identity in state.get("user_sources", {}) else "Function overrides")

    for unit in sources._bound_cpp_units():
        source_item(unit["function_id"], path=unit["source"])
    for identity, variants in state.get("sources", {}).items():
        for variant, saved in variants.items():
            if variant == "cpp":
                source_item(identity, variant, saved.get("path"))
    for identity, saved in state.get("user_sources", {}).items():
        source_item(identity, path=saved.get("path"))
    bound_paths = {item["path"] for item in items.values() if item.get("path")}
    for file in app.project.authored_files():
        if file["path"] in bound_paths:
            continue
        key = "file:" + file["path"]
        items[key] = dict(key=key, kind="file", id=file["path"], name=file["name"],
                          path=file["path"], category="Authored files")
    # Discover only saved global overrides; do not generate the full global inventory here.
    for path in (app.project.cache / "globals").glob("sym_*.json"):
        saved = json.loads(path.read_text(encoding="utf-8"))
        identity = path.stem
        key = f"source:{identity}:global-initializer"
        items[key] = dict(key=key, kind="source", id=identity, variant="global-initializer",
                          name=saved.get("name", identity), category="Global initializers")
    return {"items": sorted(items.values(), key=lambda item: (item["category"], item["name"].casefold(), item["key"])),
            "note": "Overrides and authored inputs are review candidates. A candidate may have no textual changes. Recovered C++ follows the current reference database."}


def _insights(original, modified, language):
    before, after = original.splitlines(), modified.splitlines()
    # Bound the potentially quadratic diff work for large or repetitive files.
    if len(original) + len(modified) > 1_000_000 or len(before) + len(after) > 20_000:
        return {"changed": original != modified, "limited": True,
                "reason": "Line analysis is omitted for this large input; content and hashes remain available."}
    matcher = difflib.SequenceMatcher(None, before, after, autojunk=True)
    opcodes = matcher.get_opcodes()
    added = sum(j2 - j1 for tag, i1, i2, j1, j2 in opcodes if tag in ("insert", "replace"))
    removed = sum(i2 - i1 for tag, i1, i2, j1, j2 in opcodes if tag in ("delete", "replace"))
    groups = list(matcher.get_grouped_opcodes(3))
    result = dict(changed=original != modified, added=added, removed=removed, hunks=len(groups),
                  before_lines=len(before), after_lines=len(after), limited=False)
    if language in ("cpp", "c"):
        def mentions(content):
            return set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", content)) - {
                "if", "while", "for", "switch", "sizeof", "alignof", "decltype", "static_assert", "return"}
        old, new = mentions(original), mentions(modified)
        result["call_mentions_added"] = sorted(new - old)[:24]
        result["call_mentions_removed"] = sorted(old - new)[:24]
    return result


def get_change(app, kind, identity, variant="cpp"):
    original, basis, original_revision = None, None, None
    if kind == "source" and variant == "global-initializer":
        from workstation_global_sources import _decode_values
        globals = app.globals()
        current = globals.get_source(identity)
        native = globals._load()[identity]
        values = _decode_values(native)
        if native["encoding"] != "bytes":
            values = [str(value) for value in values]
        original = json.dumps({"type_name": native["type_name"], "values": values}, indent=2) + "\n"
        basis, original_revision = "Original typed initializer from the pinned Replay image", native["revision"]
    elif kind == "source":
        if variant != "cpp":
            raise ValueError("Source review supports C++ and typed global initializers")
        current = app.sources.get_source(identity, variant)
        try:
            row = app.sources._by_identity(identity, "function")
        except KeyError:
            if identity not in app.sources._state().get("user_sources", {}):
                raise
            original, basis = "", "New function; absent from the original game"
        else:
            recovered = app.sources.cpp_index().get(row)
            if recovered.get("content"):
                original = recovered["content"]
                original_revision = recovered.get("revision")
                basis = "Recovered original C++ from the current reference database"
            else:
                basis = "Original C++ is unavailable for this function"
    elif kind == "file":
        current = app.project.read_file(identity)
        basis = "No verified original baseline for this authored file"
        archive = app.project.cache / "file-revisions" / hashlib.sha256(identity.encode()).hexdigest()
        snapshots = sorted(archive.glob("*"), key=lambda path: (path.stat().st_mtime_ns, path.name)) if archive.is_dir() else []
        if snapshots:
            path = snapshots[0]
            if path.is_file() and re.fullmatch(r"[0-9a-f]{64}", path.stem):
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != path.stem:
                    raise ValueError("Archived source revision failed hash validation")
                original = data.decode("utf-8")
                original_revision = path.stem
                basis = "Earliest available archived file revision (not a verified game original)"
    else:
        raise ValueError("Unknown source review kind")
    content = current.get("content", "")
    return dict(kind=kind, id=identity, variant=variant, name=current.get("name", identity),
                path=current.get("source") or current.get("path"), language=current.get("language", "cpp"),
                original=original, modified=content, baseline=basis, baseline_revision=original_revision,
                revision=current.get("revision"), provenance=current.get("provenance", {}),
                compilable=current.get("compilable"),
                original_sha256=hashlib.sha256(original.encode()).hexdigest() if original is not None else None,
                modified_sha256=hashlib.sha256(content.encode()).hexdigest(),
                insights=_insights(original, content, current.get("language")) if original is not None else None)
