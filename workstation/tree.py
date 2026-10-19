"""Lazy, identity-preserving tree for the Replay Game Source workspace.

The tree is a view over existing source, authored-file, and decoded-zone APIs.
It never decodes an FF or starts ACTS while a folder is expanded.
"""
from __future__ import annotations

import base64
import hashlib
import heapq
import json
import re
from pathlib import Path, PurePosixPath


_PAGE_MAX = 1000
_UNKNOWN_DISPLAY = "Unknown"
_TYPED_ASSET_FAMILIES = {
    12: "shader", 14: "shader", 15: "shader", 16: "shader", 17: "shader",
    19: "image", 41: "localize", 51: "rawfile", 52: "scriptfile", 54: "stringtable",
    62: "luafile",
}


def _node_id(value: dict) -> str:
    raw = json.dumps({"v": 1, **value}, ensure_ascii=False,
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "n_" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_node(value: str | None) -> dict:
    if value in (None, "", "root"):
        return {"v": 1, "kind": "root"}
    if not isinstance(value, str) or not value.startswith("n_") or len(value) > 4096:
        raise ValueError("Unknown workspace tree node")
    token = value[2:]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise ValueError("Malformed workspace tree node")
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        node = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Malformed workspace tree node") from error
    if (not isinstance(node, dict) or type(node.get("v")) is not int or node.get("v") != 1 or
            node.get("kind") not in {"root", "code", "code-group", "code-prefix",
                                      "authored", "authored-dir", "assets", "zone-dir",
                                      "zone", "asset-type", "asset-dir"}):
        raise ValueError("Unknown workspace tree node")
    if _node_id({key: item for key, item in node.items() if key != "v"}) != value:
        raise ValueError("Workspace tree node is not canonical")
    return node


def _safe_relative(value: str, *, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Workspace tree path is invalid")
    parts = value.split("/")
    path = PurePosixPath(value)
    if ("\x00" in value or ":" in value or path.is_absolute() or
            any(part in ("", ".", "..") for part in parts)):
        raise ValueError("Workspace tree path is invalid")
    normalized = path.as_posix()
    if suffix is not None and not normalized.casefold().endswith(suffix.casefold()):
        raise ValueError("Workspace tree path has an unsupported file type")
    return normalized


def _page(items: list[dict], query: str, offset: int, limit: int) -> dict:
    if offset < 0 or not 1 <= limit <= _PAGE_MAX:
        raise ValueError("offset must be nonnegative and limit must be 1..1000")
    needle = query.casefold()
    if needle:
        items = [item for item in items
                 if needle in " ".join(str(item.get(key, ""))
                                        for key in ("name", "label", "kind", "type",
                                                    "type_id", "relative_path", "asset_id")).casefold()]
    total = len(items)
    return {"items": items[offset:offset + limit], "total": total,
            "offset": offset, "limit": limit}


class WorkspaceTree:
    """Build paged tree nodes from the app's existing, identity-bound APIs."""

    def __init__(self, app):
        self.app = app
        from workstation.search_index import SourceSearchIndex
        self._source_search = SourceSearchIndex()
        self.catalog = None
        if (hasattr(app, "project") and hasattr(app.project, "cache") and
                hasattr(app.project, "mutation_lock") and hasattr(app, "fastfile_lock")):
            from workstation.tree_catalog import WorkspaceTreeCatalog
            self.catalog = WorkspaceTreeCatalog(self)

    def get(self, node_id: str | None = None, query: str = "",
            offset: int = 0, limit: int = 100, *, _decoded_node: dict | None = None) -> dict:
        node = _decode_node(node_id) if _decoded_node is None else _decoded_node
        if offset < 0 or not 1 <= limit <= _PAGE_MAX:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        label, crumbs, page, extra = self._children(node, query, offset, limit)
        result = {"node": node_id or _node_id({"kind": "root"}), "label": label,
                  **page, "breadcrumbs": crumbs, **extra}
        result["catalog_status"] = (self.catalog.status() if self.catalog is not None else
            {"state": "unavailable", "generation": 0, "indexed_at": None,
             "family_counts": {}, "validation_scope": "display-only-metadata"})
        return result

    def search(self, query: str, offset: int = 0, limit: int = 100) -> dict:
        """Search workspace display metadata without changing folder paging state."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("Workspace search query is required")
        if offset < 0 or not 1 <= limit <= _PAGE_MAX:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        needle = query.strip().casefold()
        catalog_status = self.catalog.status() if self.catalog is not None else {}
        metadata_index = getattr(self.app, "asset_metadata", None)
        metadata_error = None
        try:
            metadata_snapshot = metadata_index.snapshot() if metadata_index is not None else None
        except Exception as error:
            metadata_snapshot = None
            metadata_error = str(error)[:240]
        asset_total = 0
        if metadata_index is not None:
            try:
                asset_total = metadata_index.search(needle, offset=0, limit=1).get("total", 0)
            except Exception as error:
                metadata_error = str(error)[:240]
        pending_assets = self._pending_search_assets(needle, metadata_snapshot, metadata_index)
        asset_total += len(pending_assets)

        authored = (self.catalog.family("authored")[0] if self.catalog is not None
                    else self.app.project.authored_files())
        authored_matches = []
        for row in authored:
            path = row.get("path", "")
            haystack = " ".join((path, PurePosixPath(path).name, row.get("language", ""))).casefold()
            if needle not in haystack:
                continue
            authored_matches.append({"id": _node_id({"kind": "authored-file", "path": path}),
                "node": _node_id({"kind": "authored-file", "path": path}),
                "area": "Authored files", "name": PurePosixPath(path).name,
                "kind": "file", "expandable": False, "path": path,
                "language": row.get("language"), "bytes": row.get("bytes"),
                "target": {"path": path}})
        authored_matches.sort(key=lambda item: (item["name"].casefold(), item["path"].casefold()))

        # Fastfile containers are searchable as soon as the shallow game-root
        # catalog is available. This keeps empty and not-yet-indexed zones
        # discoverable without waiting for native asset metadata indexing.
        fastfile_matches = []
        if self.catalog is not None:
            directories, _state = self.catalog.family("asset_directories")
            for rows in directories.values():
                for row in rows:
                    if row.get("kind") != "zone":
                        continue
                    relative = row.get("relative_path", "")
                    if needle not in relative.casefold():
                        continue
                    relative = _safe_relative(relative, suffix=".ff")
                    node = _node_id({"kind": "zone", "relative_path": relative})
                    fastfile_matches.append({"id": node, "node": node, "area": "Assets",
                        "name": PurePosixPath(relative).name, "kind": "zone",
                        "expandable": True, "relative_path": relative,
                        "bytes": row.get("bytes"), "status": row.get("status"),
                        "source_xfile_version": row.get("source_xfile_version"),
                        "transient_type": row.get("transient_type"),
                        "metadata_only": True,
                        "target": {"relative_path": relative, "metadata_only": True}})
        fastfile_matches.sort(key=lambda item: (item["relative_path"].casefold(),
                                                item["relative_path"]))

        # Keep only the lexically earliest source results needed for this page;
        # scanning aliases remains O(source rows), but node materialization is bounded.
        code_count = 0
        def code_matches():
            nonlocal code_count
            if self.catalog is None:
                function_rows = self._all_sources("function")
                symbol_rows = self._all_sources("symbol")
                global_rows = self.app.globals().list_editable()
            else:
                function_rows = self.catalog.family("functions")[0]
                symbol_rows = self.catalog.family("symbols")[0]
                global_rows = self.catalog.family("globals")[0]
            seen = set()
            for group, rows in (("function", function_rows), ("symbol", symbol_rows),
                                ("global", global_rows)):
                for row in self._source_search.matches(group, rows, needle):
                    # Older cached symbol families can also contain function rows.
                    # Merge by editor identity before counting and paginating.
                    identity = ("global" if group == "global" else "source", row["id"])
                    if identity in seen:
                        continue
                    seen.add(identity)
                    code_count += 1
                    yield ((str(row.get("name", "")).casefold(), str(row.get("id", "")), group),
                           group, row)

        code_rows = heapq.nsmallest(offset + limit, code_matches(), key=lambda value: value[0])
        asset_count = len(fastfile_matches) + asset_total
        total = code_count + asset_count + len(authored_matches)
        stop = offset + limit
        code_end = min(stop, code_count)
        code_start = min(offset, code_end)
        page = []
        for _sort, group, row in code_rows[code_start:code_end]:
            if group == "global":
                item = self._global(row)
            else:
                variant = "cpp"
                item = self._source(row, variant=variant)
            item["area"] = "Code"
            page.append(item)

        asset_start = max(offset, code_count)
        asset_end = min(stop, code_count + asset_count)
        fastfile_start = max(asset_start - code_count, 0)
        fastfile_end = min(asset_end - code_count, len(fastfile_matches))
        if fastfile_start < fastfile_end:
            page.extend(fastfile_matches[fastfile_start:fastfile_end])
        metadata_start = max(asset_start - code_count - len(fastfile_matches), 0)
        metadata_page_end = max(min(asset_end - code_count - len(fastfile_matches), asset_total), 0)
        stock_asset_total = asset_total - len(pending_assets)
        metadata_end = min(metadata_page_end, stock_asset_total)
        if metadata_index is not None and metadata_start < metadata_end:
            try:
                asset_page = metadata_index.search(needle, offset=metadata_start,
                                                   limit=metadata_end - metadata_start)
            except Exception as error:
                asset_page = {"items": []}
                metadata_error = str(error)[:240]
            for row in asset_page.get("items", []):
                relative = _safe_relative(row["relative_path"], suffix=".ff")
                zone_id, index, type_id = row["zone_id"], row["index"], row["type_id"]
                asset_id = f"{zone_id}:{index}"
                row = self._pending_display_overlay(relative, zone_id, [row])[0]
                name = row.get("name") or _UNKNOWN_DISPLAY
                type_name = row.get("type_name") or _UNKNOWN_DISPLAY
                page.append({"id": _node_id({"kind": "asset-target", "asset_id": asset_id}),
                    "node": _node_id({"kind": "zone", "relative_path": relative}),
                    "area": "Assets", "name": name, "kind": "asset", "expandable": False,
                    "relative_path": relative, "asset_id": asset_id, "zone_id": zone_id,
                    "index": index, "type_id": type_id, "type": type_name,
                    "type_name": type_name, "pointer_token": row.get("pointer_token"),
                    "reference_only": row.get("reference_only"),
                    "operation": row.get("operation"),
                    "identity_status": ("native-identity-verified" if row.get("name") else
                                        "xasset-index-only"),
                    "native_name_available": bool(row.get("name")),
                    "metadata_only": True, "status": row.get("status"),
                    "reader_scope": row.get("reader_scope", "native-walk"),
                    "editor_status": ("native-reader-unavailable" if row.get("reader_scope") ==
                                      "xasset-table-only" else self._editor_status(type_id)),
                    "target": {"asset_id": asset_id, "relative_path": relative,
                        "zone_id": zone_id, "type_id": type_id, "index": index,
                        "metadata_only": True}})
        pending_start = max(0, metadata_start - stock_asset_total)
        pending_end = min(len(pending_assets), max(0, metadata_page_end - stock_asset_total))
        for row in pending_assets[pending_start:pending_end]:
            page.append(row)

        authored_start = max(offset, code_count + asset_count)
        authored_end = min(stop, total)
        page.extend(authored_matches[authored_start - code_count - asset_count:
                                     authored_end - code_count - asset_count])
        asset_counts = metadata_snapshot.get("counts", {}) if metadata_snapshot else {}
        search_state = metadata_snapshot.get("state", "unavailable") if metadata_snapshot else "unavailable"
        family_states = catalog_status.get("family_states", {})
        source_families_ready = all(family_states.get(name) == "ready" for name in
                                    ("functions", "symbols", "globals", "authored"))
        complete = bool(metadata_snapshot and metadata_snapshot.get("complete") and
                        metadata_snapshot.get("native_names_complete", True) and
                        source_families_ready and metadata_error is None)
        if not source_families_ready and search_state == "ready":
            search_state = "stale" if any(value == "stale" for value in family_states.values()) else "partial"
        search_status = {"state": search_state,
            "complete": complete,
            "generation": metadata_snapshot.get("generation") if metadata_snapshot else None,
            "indexed_fastfiles": asset_counts.get("indexed_fastfiles", 0),
            "total_fastfiles": asset_counts.get("total_fastfiles", 0),
            "unavailable_fastfiles": asset_counts.get("unavailable_fastfiles", 0),
            "native_asset_rows": asset_counts.get("native_asset_rows", 0),
            "asset_rows": asset_counts.get("asset_rows", asset_counts.get("native_asset_rows", 0)),
            "table_only_fastfiles": asset_counts.get("table_only_fastfiles", 0),
            "validation_scope": "display-only-metadata",
            "error": metadata_error or (metadata_snapshot.get("error") if metadata_snapshot else
                     "Asset metadata index is not available")}
        return {"items": page, "total": total, "offset": offset, "limit": limit,
                "search_status": search_status,
                "catalog_status": catalog_status}

    @staticmethod
    def decode_node(node_id: str | None) -> dict:
        """Decode and validate a canonical request node before choosing its read lock."""
        return _decode_node(node_id)

    def _children(self, node: dict, query: str, offset: int, limit: int):
        kind = node["kind"]
        root = _node_id({"kind": "root"})
        if kind == "root":
            self._exact(node, {"kind"})
            items = [self._folder("Code", {"kind": "code"}),
                     self._folder("Assets", {"kind": "assets"})]
            return "IW8", self._crumbs((root, "IW8")), _page(items, query, offset, limit), {}
        if kind == "code":
            self._exact(node, {"kind"})
            items = [self._folder("Functions", {"kind": "code-group", "group": "functions"}),
                     self._folder("Globals", {"kind": "code-group", "group": "globals"}),
                     self._folder("Symbols", {"kind": "code-group", "group": "symbols"}),
                     self._folder("Authored files", {"kind": "authored"})]
            return "Code", self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code")), \
                   _page(items, query, offset, limit), {}
        if kind == "code-group":
            self._exact(node, {"kind", "group"})
            group = node.get("group")
            if group == "functions":
                groups = self._source_groups()
                items = [self._folder(label, {"kind": "code-prefix", "prefix": prefix}) | {
                    "source_count": count} for prefix, label, count in groups]
                return "Functions", self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                    (_node_id({"kind": "code-group", "group": "functions"}), "Functions")), \
                    _page(items, query, offset, limit), {}
            elif group == "symbols":
                if self.catalog is not None:
                    rows, _state = self.catalog.family("symbols")
                    rows, total = self._filter_page_rows(rows, query, offset, limit)
                else:
                    rows, total = self.app.sources.list_sources(query, offset, limit, "symbol")
                items = [self._source(row, variant="cpp") for row in rows]
                return "Symbols", self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                    (_node_id({"kind": "code-group", "group": "symbols"}), "Symbols")), \
                    {"items": items, "total": total, "offset": offset, "limit": limit}, {}
            elif group == "globals":
                rows = (self.catalog.family("globals")[0] if self.catalog is not None
                        else self.app.globals().list_editable())
                items = [self._global(row) for row in rows]
                return "Globals", self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                    (_node_id({"kind": "code-group", "group": "globals"}), "Globals")), \
                    _page(items, query, offset, limit), {}
            else:
                raise ValueError("Unknown code tree group")
        if kind == "code-prefix":
            self._exact(node, {"kind", "prefix"})
            prefix = node.get("prefix")
            if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9]+_|Other", prefix):
                raise ValueError("Invalid function prefix group")
            if self.catalog is not None:
                rows, _ = self.catalog.family("functions")
                indexes, _ = self.catalog.family("function_prefix_indexes")
                group_indexes = indexes.get(prefix, ())
                needle = query.casefold()
                if needle:
                    matching = [rows[index] for index in group_indexes if index < len(rows) and
                                needle in " ".join(str(rows[index].get(key, ""))
                                    for key in ("name", "id", "kind")).casefold() + " " +
                                " ".join(str(alias) for alias in rows[index].get("aliases", []))
                                    .casefold()]
                    total = len(matching)
                    selected = matching[offset:offset + limit]
                else:
                    total = len(group_indexes)
                    selected = [rows[index] for index in group_indexes[offset:offset + limit]
                                if index < len(rows)]
            else:
                rows = self._all_sources("function")
                selected = [row for row in rows if self._function_prefix(row.get("name", "")) == prefix]
                page = _page([self._source(row, variant="cpp")
                              for row in selected], query, offset, limit)
                function_id = _node_id({"kind": "code-group", "group": "functions"})
                prefix_id = _node_id({"kind": "code-prefix", "prefix": prefix})
                return prefix, self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                    (function_id, "Functions"), (prefix_id, prefix)), page, {}
            items = [self._source(row, variant="cpp")
                     for row in selected]
            function_id = _node_id({"kind": "code-group", "group": "functions"})
            prefix_id = _node_id({"kind": "code-prefix", "prefix": prefix})
            return prefix, self._crumbs((root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                (function_id, "Functions"), (prefix_id, prefix)), \
                {"items": items, "total": total, "offset": offset, "limit": limit}, {}
        if kind in ("authored", "authored-dir"):
            self._exact(node, {"kind"} if kind == "authored" else {"kind", "path"})
            prefix = "" if kind == "authored" else _safe_relative(node.get("path", ""))
            files = (self.catalog.family("authored")[0] if self.catalog is not None
                     else self.app.project.authored_files())
            allowed_roots = ("src", "source-workstation")
            tree_rows = self._authored_children(files, prefix, allowed_roots)
            label = "Authored files" if not prefix else PurePosixPath(prefix).name
            authored_id = _node_id({"kind": "authored"})
            entries = [(root, "IW8"), (_node_id({"kind": "code"}), "Code"),
                       (authored_id, "Authored files")]
            parts = prefix.split("/") if prefix else []
            for index, _part in enumerate(parts):
                parent = "/".join(parts[:index + 1])
                entries.append((_node_id({"kind": "authored-dir", "path": parent}), parent.rsplit("/", 1)[-1]))
            crumbs = self._crumbs(*entries)
            return label, crumbs, _page(tree_rows, query, offset, limit), {}
        if kind == "assets":
            self._exact(node, {"kind"})
            if self.catalog is not None:
                items, total = self._catalog_game_page("", query, offset, limit)
                page = {"items": items, "total": total, "offset": offset, "limit": limit}
            else:
                items = self._catalog_game_children("")
                page = _page(items, query, offset, limit)
            return "Assets", self._crumbs((root, "IW8"), (_node_id({"kind": "assets"}), "Assets")), \
                   page, {}
        if kind == "zone-dir":
            self._exact(node, {"kind", "relative_path"})
            relative_dir = _safe_relative(node.get("relative_path", ""))
            if self.catalog is not None:
                items, total = self._catalog_game_page(relative_dir, query, offset, limit)
                page = {"items": items, "total": total, "offset": offset, "limit": limit}
            else:
                items = self._catalog_game_children(relative_dir)
                page = _page(items, query, offset, limit)
            labels = relative_dir.split("/")
            entries = [(root, "IW8"), (_node_id({"kind": "assets"}), "Assets")]
            for index, _part in enumerate(labels):
                path = "/".join(labels[:index + 1])
                entries.append((_node_id({"kind": "zone-dir", "relative_path": path}), labels[index]))
            return labels[-1], self._crumbs(*entries), page, {}
        if kind == "zone":
            self._exact(node, {"kind", "relative_path"})
            relative = _safe_relative(node.get("relative_path", ""), suffix=".ff")
            inventory, inventory_state = self._catalog_inventory(relative)
            if inventory is None:
                extra = {"inventory_state": inventory_state,
                         "inventory_validation_scope": "display-only-metadata"}
                if self.catalog is not None:
                    entry, _state = self.catalog.entry("inventories", relative)
                    if entry and entry.get("error"):
                        extra["inventory_error"] = entry["error"]
                if inventory_state in ("uncached", "unavailable"):
                    extra.update(extract_required=True, extract_path=relative,
                        note="Extract this fastfile with the existing zone action to build a cached inventory.")
                return PurePosixPath(relative).name, self._zone_crumbs(root, relative), \
                    _page([], query, offset, limit), extra
            zone_id, rows = inventory
            type_rows = {}
            for row in rows:
                type_id = row["type_id"]
                type_rows.setdefault(type_id, []).append(row)
            items = [self._asset_type(zone_id, relative, type_id, rows_for_type)
                     for type_id, rows_for_type in sorted(type_rows.items())]
            return PurePosixPath(relative).name, self._zone_crumbs(root, relative), \
                   _page(items, query, offset, limit), {"zone_id": zone_id,
                       "inventory_cached": inventory_state == "ready",
                       "inventory_state": inventory_state,
                       "inventory_validation_scope": "display-only-metadata"}
        if kind in ("asset-type", "asset-dir"):
            self._exact(node, {"kind", "relative_path", "zone_id", "type_id", "type_name"}
                        if kind == "asset-type" else
                        {"kind", "relative_path", "zone_id", "type_id", "type_name", "prefix"})
            relative = _safe_relative(node.get("relative_path", ""), suffix=".ff")
            type_id = node.get("type_id")
            if type(type_id) is not int or not 0 <= type_id <= 255:
                raise ValueError("Invalid native asset type")
            if not isinstance(node.get("type_name"), str) or not node["type_name"]:
                raise ValueError("Invalid native asset type label")
            inventory, inventory_state = self._catalog_inventory(relative)
            if inventory is None or inventory[0] != node.get("zone_id"):
                raise ValueError("Cached zone inventory is missing or changed; extract again")
            rows = [row for row in inventory[1] if row["type_id"] == type_id]
            prefix = "" if kind == "asset-type" else _safe_relative(node.get("prefix", ""))
            items = self._asset_name_children(rows, relative, node["zone_id"], type_id, prefix)
            label = node.get("type_name") if kind == "asset-type" else PurePosixPath(prefix).name
            crumbs = self._asset_crumbs(root, relative, node["zone_id"], type_id,
                node.get("type_name", f"Type {type_id}"), prefix)
            return label, crumbs, _page(items, query, offset, limit), {
                "zone_id": node["zone_id"], "type_id": type_id,
                "inventory_state": inventory_state,
                "inventory_validation_scope": "display-only-metadata"}
        raise ValueError("Unsupported workspace tree node")

    @staticmethod
    def _exact(node: dict, allowed: set[str]):
        if set(node) - allowed - {"v"}:
            raise ValueError("Workspace tree node contains unsupported fields")

    @staticmethod
    def _folder(name: str, payload: dict) -> dict:
        return {"id": _node_id(payload), "name": name, "kind": "folder", "expandable": True}

    @staticmethod
    def _source(row: dict, variant: str) -> dict:
        kind = row.get("kind", "function")
        return {"id": _node_id({"kind": "source-target", "source_id": row["id"]}),
                "name": row["name"], "kind": "source", "expandable": False,
                "source_id": row["id"], "source_kind": kind,
                "rva": row.get("rva"), "aliases": row.get("aliases", []),
                "variants": row.get("variants", [variant]),
                "has_cpp": bool(row.get("has_cpp")),
                "has_assembly_edit": bool(row.get("has_assembly_edit")),
                "target": {"id": row["id"], "variant": variant}}

    @staticmethod
    def _function_prefix(name: str) -> str:
        match = re.match(r"^([A-Za-z0-9]+)_", name)
        return match.group(1) + "_" if match else "Other"

    def _all_sources(self, kind: str) -> list[dict]:
        rows, _total = self.app.sources.list_source_rows("", kind)
        return rows

    def _source_groups(self) -> list[tuple[str, str, int]]:
        if self.catalog is not None:
            groups, _state = self.catalog.family("function_groups")
            return [(prefix, prefix, count) for prefix, count in
                    sorted(groups.items(), key=lambda item: (item[0].casefold(), item[0]))]
        counts = {}
        for row in self._all_sources("function"):
            prefix = self._function_prefix(row.get("name", ""))
            counts[prefix] = counts.get(prefix, 0) + 1
        return [(prefix, prefix, count) for prefix, count in
                sorted(counts.items(), key=lambda item: (item[0].casefold(), item[0]))]

    @staticmethod
    def _filter_page_rows(rows, query, offset, limit):
        needle = query.casefold()
        if needle:
            rows = [row for row in rows if needle in " ".join(
                str(row.get(key, "")) for key in ("name", "id", "kind")).casefold() + " " +
                " ".join(str(alias) for alias in row.get("aliases", [])).casefold()]
        total = len(rows)
        return rows[offset:offset + limit], total

    def _catalog_game_children(self, relative_dir):
        if self.catalog is None:
            return self._game_children(relative_dir)
        relative_dir = _safe_relative(relative_dir) if relative_dir else ""
        directories, _state = self.catalog.family("asset_directories")
        rows = directories.get(relative_dir)
        if rows is None:
            return []
        return self._materialize_catalog_game_rows(rows)

    def _materialize_catalog_game_rows(self, rows, metadata_snapshot=None):
        result = []
        for row in rows:
            if row["kind"] == "directory":
                path = row["path"]
                result.append({"id": _node_id({"kind": "zone-dir", "relative_path": path}),
                    "name": row["name"], "kind": "folder", "expandable": True,
                    "relative_path": path})
            else:
                zone = self._zone(row, candidates=row.get("candidate_zone_ids", []))
                entry, family_state = self.catalog.entry("inventories", row["relative_path"])
                state = self._asset_inventory_state(entry, family_state, metadata_snapshot,
                                                    row["relative_path"])
                zone["inventory_state"] = state
                zone["inventory_validation_scope"] = "display-only-metadata"
                zone["inventory_cached"] = state == "ready"
                metadata_entry = (metadata_snapshot or {}).get("files", {}).get(
                    row["relative_path"], {})
                if metadata_entry.get("error"):
                    zone["inventory_error"] = metadata_entry["error"]
                if entry and (entry.get("error") or entry.get("refresh_error")):
                    zone["inventory_error"] = entry.get("error") or entry.get("refresh_error")
                zone["source_xfile_version"] = row.get("source_xfile_version")
                zone["transient_type"] = row.get("transient_type")
                result.append(zone)
        return result

    def _catalog_game_page(self, relative_dir, query, offset, limit):
        """Page/filter raw indexed rows before paying to materialize response IDs."""
        if offset < 0 or not 1 <= limit <= _PAGE_MAX:
            raise ValueError("offset must be nonnegative and limit must be 1..1000")
        relative_dir = _safe_relative(relative_dir) if relative_dir else ""
        directories, _state = self.catalog.family("asset_directories")
        rows = directories.get(relative_dir, ())
        metadata_index = getattr(self.app, "asset_metadata", None)
        metadata_snapshot = metadata_index.snapshot() if metadata_index is not None else None
        needle = query.casefold()
        if needle:
            selected = []
            for row in rows:
                name = (row.get("name") if row["kind"] == "directory" else
                        PurePosixPath(row["relative_path"]).name)
                relative = row.get("path", "") if row["kind"] == "directory" else row["relative_path"]
                if needle in " ".join((str(name), row["kind"], str(relative))).casefold():
                    selected.append(row)
            total = len(selected)
            selected = selected[offset:offset + limit]
        else:
            total = len(rows)
            selected = rows[offset:offset + limit]
        return self._materialize_catalog_game_rows(selected, metadata_snapshot), total

    def _asset_inventory_state(self, entry, family_state, metadata_snapshot, relative):
        state = entry.get("state", "uncached") if entry else (
            "building" if family_state == "building" else "uncached")
        if metadata_snapshot is not None:
            metadata_row = metadata_snapshot.get("files", {}).get(relative, {})
            metadata_state = metadata_row.get("state")
            if metadata_state == "ready":
                state = "ready"
            elif metadata_state == "indexing":
                state = "building"
            elif metadata_state == "unavailable" and not (entry and entry.get("zone_id")):
                state = "unavailable"
            elif metadata_state == "stale":
                state = "stale"
        if entry and family_state == "stale" and state == "ready":
            state = "stale"
        elif entry and family_state == "building" and state == "ready":
            state = "building"
        return state

    def _catalog_inventory(self, relative):
        if self.catalog is None:
            value = self._zone_inventory(relative)
            return value, "ready" if value is not None else "uncached"
        entry, family_state = self.catalog.entry("inventories", relative)
        metadata_index = getattr(self.app, "asset_metadata", None)
        metadata_state = None
        if metadata_index is not None:
            snapshot = metadata_index.snapshot()
            metadata_row = snapshot.get("files", {}).get(relative, {})
            metadata_state = metadata_row.get("state")
            if metadata_state == "ready":
                try:
                    shard = metadata_index.inventory(relative)
                except (OSError, ValueError, KeyError) as error:
                    shard = None
                    metadata_row = dict(metadata_row, error=str(error)[:240])
                if isinstance(shard, dict) and shard.get("complete") is True:
                    zone_id, rows = shard.get("zone_id"), shard.get("rows")
                    if isinstance(zone_id, str) and isinstance(rows, list):
                        rows = [dict(row, reader_scope=shard.get("reader_scope", "native-walk"))
                                for row in rows]
                        return (zone_id, self._pending_display_overlay(relative, zone_id, rows)), "ready"
                metadata_state = "unavailable"
        state_override = {"pending": "building", "indexing": "building",
                          "unavailable": "unavailable", "stale": "stale"}.get(metadata_state)
        if not entry:
            state = state_override or (family_state if family_state in
                ("building", "stale", "unavailable") else "uncached")
            return None, state
        value = (entry["zone_id"], entry["rows"]) if entry.get("zone_id") else None
        if value is not None:
            value = (value[0], self._pending_display_overlay(relative, value[0], value[1]))
        state = entry.get("state", "stale")
        if state_override:
            state = state_override
        if family_state == "stale" and state == "ready":
            state = "stale"
        elif family_state == "building" and state == "ready":
            state = "building"
        return value, state

    def _pending_display_overlay(self, relative, zone_id, base_rows):
        """Apply shallow pending row labels for display; readers revalidate them."""
        archives = self.app.archives()
        try:
            source = archives._zone_path(relative)
            cache_root = Path(archives.cache_root).resolve()
            cache = (cache_root / source.stem / zone_id).resolve()
            if not cache.is_relative_to(cache_root):
                return base_rows
            current_rows = []
            for current in sorted(cache.glob("pending-edits/op-*/current.json")):
                try:
                    resolved = current.resolve(strict=True)
                    if not resolved.is_relative_to(cache):
                        continue
                    row = json.loads(resolved.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if (not isinstance(row, dict) or row.get("zone_id") != zone_id or
                        row.get("operation") not in ("append", "remove") or
                        type(row.get("type_id")) is not int or
                        not isinstance(row.get("type"), str) or
                        not isinstance(row.get("name"), str) or
                        not isinstance(row.get("asset_id"), str)):
                    continue
                if row["operation"] == "append":
                    digest = hashlib.sha256(row['name'].encode('utf-8')).hexdigest()[:32]
                    typed = row["type_id"] in (12, 14, 15, 16, 17, 19)
                    expected_id = f"{zone_id}:new-{row['type_id']}-{digest}" if typed else f"{zone_id}:new-{digest}"
                    legacy_pixel_id = f"{zone_id}:new-{digest}" if row["type_id"] == 17 else None
                    if row["asset_id"] not in (expected_id, legacy_pixel_id):
                        continue
                    current_rows.append({"index": None, "type_id": row["type_id"],
                        "name": row["name"], "type_name": row["type"],
                        "reference_only": False, "asset_id": row["asset_id"],
                        "operation": "append"})
                elif (type(row.get("index")) is int and row["index"] >= 0 and
                      row["asset_id"] == f"{zone_id}:{row['index']}"):
                    current_rows.append({"index": row["index"], "type_id": row["type_id"],
                                         "name": row["name"], "operation": "remove"})
            if not current_rows:
                return base_rows
            removed = {row["index"]: row for row in current_rows if row["operation"] == "remove"}
            result = []
            for row in base_rows:
                removal = removed.get(row.get("index"))
                matches = (removal is not None and row.get("type_id") == removal["type_id"] and
                           (row.get("name") is None or row.get("name") == removal["name"]))
                result.append(dict(row, operation="remove") if matches else row)
            result.extend(row for row in current_rows if row["operation"] == "append")
            return result
        except (OSError, ValueError, AttributeError):
            return base_rows

    def _pending_search_assets(self, needle, metadata_snapshot, metadata_index):
        """Return pending append labels bound to indexed FF/zone identities only."""
        if metadata_index is None or not isinstance(metadata_snapshot, dict):
            return []
        files = metadata_snapshot.get("files")
        if not isinstance(files, dict):
            return []
        try:
            archives = self.app.archives()
            cache_root = Path(archives.cache_root).resolve()
            candidates = {}
            for path in cache_root.glob("*/*/pending-edits/op-*/current.json"):
                try:
                    current = path.resolve(strict=True)
                    if not current.is_relative_to(cache_root):
                        continue
                    zone_id, stem = current.parent.parent.parent.name, current.parent.parent.parent.parent.name
                except (OSError, RuntimeError):
                    continue
                if not re.fullmatch(r"[a-fA-F0-9]{16,128}", zone_id):
                    continue
                candidates.setdefault((stem.casefold(), zone_id), None)
            if not candidates:
                return []
            candidate_stems = {stem for stem, _zone_id in candidates}
            metadata_relatives = {}
            for relative in files:
                # Pending labels only need their candidate owners. Resolving
                # every shipped FF on every keystroke adds thousands of I/Os.
                if (not isinstance(relative, str) or
                        relative.rsplit('/', 1)[-1].rsplit('.', 1)[0].casefold()
                        not in candidate_stems):
                    continue
                try:
                    safe = _safe_relative(relative, suffix=".ff")
                    source = archives._zone_path(safe)
                    metadata_relatives.setdefault(source.stem.casefold(), []).append(safe)
                except (ValueError, OSError, AttributeError):
                    continue
            legacy_inventories = {}
            if self.catalog is not None:
                legacy_inventories = self.catalog.family("inventories")[0]
            results, seen = [], set()
            for stem, zone_id in candidates:
                bound_relatives = []
                for relative in metadata_relatives.get(stem, []):
                    try:
                        shard = metadata_index.inventory(relative)
                    except (OSError, ValueError, KeyError, TypeError):
                        continue
                    if (isinstance(shard, dict) and shard.get("complete") is True and
                            shard.get("zone_id") == zone_id):
                        bound_relatives.append(relative)
                if not bound_relatives:
                    for relative, entry in legacy_inventories.items():
                        if (not isinstance(relative, str) or not isinstance(entry, dict) or
                                entry.get("state") != "ready" or entry.get("zone_id") != zone_id):
                            continue
                        identity = entry.get("strong_identity")
                        if not isinstance(identity, dict) or identity.get("zone_id") != zone_id:
                            continue
                        try:
                            safe = _safe_relative(relative, suffix=".ff")
                            source = archives._zone_path(safe)
                        except (ValueError, OSError, AttributeError):
                            continue
                        if source.stem.casefold() == stem:
                            bound_relatives.append(safe)
                for relative in bound_relatives:
                    for row in self._pending_display_overlay(relative, zone_id, []):
                        if row.get("operation") != "append":
                            continue
                        searchable = " ".join(str(row.get(key, "")) for key in
                            ("name", "type_name", "type_id", "asset_id", "type")) + " " + relative
                        if needle not in searchable.casefold():
                            continue
                        asset_id = row.get("asset_id")
                        if not isinstance(asset_id, str) or asset_id in seen:
                            continue
                        seen.add(asset_id)
                        type_id = row.get("type_id")
                        target = {"asset_id": asset_id, "relative_path": relative,
                                  "zone_id": zone_id, "type_id": type_id,
                                  "index": None, "metadata_only": True}
                        results.append({"id": _node_id({"kind": "asset-target", "asset_id": asset_id}),
                            "node": _node_id({"kind": "zone", "relative_path": relative}),
                            "area": "Assets", "name": row.get("name") or _UNKNOWN_DISPLAY,
                            "kind": "asset", "expandable": False, "relative_path": relative,
                            "asset_id": asset_id, "zone_id": zone_id, "index": None,
                            "type_id": type_id, "type": row.get("type_name") or _UNKNOWN_DISPLAY,
                            "type_name": row.get("type_name") or _UNKNOWN_DISPLAY,
                            "operation": "append", "metadata_only": True,
                            "identity_status": "pending-display-metadata",
                            "target": target})
            return sorted(results, key=lambda item: (item["name"].casefold(),
                                                       item["relative_path"].casefold(),
                                                       item["asset_id"]))
        except (OSError, ValueError, AttributeError):
            return []

    @staticmethod
    def _global(row: dict) -> dict:
        return {"id": _node_id({"kind": "global-target", "source_id": row["id"]}),
                "name": row["name"], "kind": "source", "expandable": False,
                "source_id": row["id"], "source_kind": "global",
                "type_name": row.get("type_name"),
                "target": {"id": row["id"], "variant": "global-initializer"}}

    @staticmethod
    def _authored_children(files: list[dict], prefix: str,
                           allowed_roots: tuple[str, ...]) -> list[dict]:
        result = {}
        for row in files:
            path = _safe_relative(row.get("path", ""))
            if path.split("/", 1)[0] not in allowed_roots:
                continue
            if prefix and not path.startswith(prefix + "/"):
                continue
            remainder = path[len(prefix) + 1:] if prefix else path
            parts = remainder.split("/")
            if len(parts) > 1:
                name = parts[0]
                key = ("dir", prefix, name)
                result[key] = {"id": _node_id({"kind": "authored-dir",
                                               "path": f"{prefix}/{name}".strip("/")}),
                               "name": name, "kind": "folder", "expandable": True}
            else:
                relative = path
                result[("file", relative)] = {"id": _node_id({"kind": "authored-file", "path": relative}),
                    "name": parts[0], "kind": "file", "expandable": False,
                    "path": relative, "language": row.get("language"),
                    "bytes": row.get("bytes"), "target": {"path": relative}}
        if not prefix:
            for name in allowed_roots:
                if any(row.get("path", "").startswith(name + "/") for row in files):
                    result[("dir", "", name)] = {"id": _node_id({"kind": "authored-dir", "path": name}),
                        "name": name, "kind": "folder", "expandable": True}
        return sorted(result.values(), key=lambda item: (item["name"].casefold(), item["kind"]))

    @staticmethod
    def _crumbs(*entries: tuple[str, str]) -> list[dict]:
        result = []
        for identity, label in entries:
            crumb = dict(id=identity, name=label, label=label)
            try:
                payload = _decode_node(identity)
            except ValueError:
                payload = {}
            for key in ("kind", "relative_path", "zone_id", "type_id", "prefix", "group"):
                if key in payload:
                    crumb[key] = payload[key]
            result.append(crumb)
        return result

    @staticmethod
    def _zone_crumbs(root: str, relative: str) -> list[dict]:
        entries = [(root, "IW8"), (_node_id({"kind": "assets"}), "Assets")]
        parent = PurePosixPath(relative).parent
        if parent.as_posix() != ".":
            parts = parent.parts
            for index in range(len(parts)):
                path = "/".join(parts[:index + 1])
                entries.append((_node_id({"kind": "zone-dir", "relative_path": path}), parts[index]))
        entries.append((_node_id({"kind": "zone", "relative_path": relative}), PurePosixPath(relative).name))
        return WorkspaceTree._crumbs(*entries)

    @staticmethod
    def _asset_crumbs(root: str, relative: str, zone_id: str, type_id: int,
                      type_name: str, prefix: str) -> list[dict]:
        entries = [(crumb["id"], crumb["label"])
                   for crumb in WorkspaceTree._zone_crumbs(root, relative)[:-1]]
        entries.append((_node_id({"kind": "zone", "relative_path": relative}), PurePosixPath(relative).name))
        entries.append((_node_id({"kind": "asset-type", "relative_path": relative,
            "zone_id": zone_id, "type_id": type_id, "type_name": type_name}), type_name))
        if prefix:
            parts = prefix.split("/")
            for index in range(len(parts)):
                current = "/".join(parts[:index + 1])
                entries.append((_node_id({"kind": "asset-dir", "relative_path": relative,
                    "zone_id": zone_id, "type_id": type_id, "prefix": current,
                    "type_name": type_name}), parts[index]))
        return WorkspaceTree._crumbs(*entries)

    def _game_children(self, relative_dir: str) -> list[dict]:
        archives = self.app.archives()
        root = archives.game_root.resolve(strict=True)
        if relative_dir:
            relative_dir = _safe_relative(relative_dir)
        base = (root / relative_dir).resolve(strict=True) if relative_dir else root
        if not base.is_relative_to(root) or not base.is_dir():
            raise ValueError("Game tree directory is outside the configured IW8 root")
        items = []
        try:
            entries = sorted(base.iterdir(), key=lambda item: (item.name.casefold(), item.name))
        except OSError as error:
            raise ValueError("Game directory cannot be listed") from error
        from workstation_fastfiles import _source_header
        # Candidate discovery is metadata-only, but it must be performed once
        # for the directory. Scanning every cache receipt for every FF made a
        # large directory cost O(files * receipts) while holding the API locks.
        cached_zones = None
        for path in entries:
            try:
                if path.is_dir():
                    rel = path.relative_to(root).as_posix()
                    items.append({"id": _node_id({"kind": "zone-dir", "relative_path": rel}),
                                  "name": path.name, "kind": "folder", "expandable": True,
                                  "relative_path": rel})
                elif path.is_file() and path.suffix.casefold() == ".ff":
                    if cached_zones is None:
                        cached_zones = self._cached_zone_index()
                    rel = path.relative_to(root).as_posix()
                    try:
                        _source_header(path)
                        status = "source-header-checked"
                    except (OSError, ValueError) as error:
                        status = "unsupported-or-invalid"
                    source_key = str(path.resolve(strict=True))
                    items.append(self._zone({"relative_path": rel, "bytes": path.stat().st_size,
                                             "status": status},
                                            candidates=cached_zones.get(source_key, [])))
            except OSError:
                # A file disappearing during the shallow directory listing is
                # omitted; the subsequent ordinary FF action revalidates it.
                continue
        return items

    def _zone(self, row: dict, *, candidates: list[str] | None = None) -> dict:
        relative = _safe_relative(row.get("relative_path", ""), suffix=".ff")
        if candidates is None:
            candidates = self._cached_zone_candidates(relative)
        return {"id": _node_id({"kind": "zone", "relative_path": relative}),
                "name": PurePosixPath(relative).name, "kind": "zone", "expandable": True,
                "relative_path": relative, "bytes": row.get("bytes"),
                "source_status": row.get("status"),
                "zone_id": None, "inventory_cached": bool(candidates),
                "extract_target": relative}

    def _cached_zone_candidates(self, relative: str) -> list[str]:
        archives = self.app.archives()
        try:
            source = archives._zone_path(relative).resolve(strict=True)
        except (OSError, ValueError):
            return []
        return self._cached_zone_index().get(str(source), [])

    def _cached_zone_index(self) -> dict[str, list[str]]:
        """Index successful cache receipts by source path in one bounded pass."""
        archives = self.app.archives()
        matches: dict[str, set[str]] = {}
        for receipt_path in archives.cache_root.glob("*/*/decode-receipt.json"):
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                source_path = Path(receipt.get("source", {}).get("path", "")).resolve()
                cache_key = receipt.get("cache_key")
                if (receipt.get("status") == "decoded-and-validated" and
                        isinstance(cache_key, str) and receipt_path.parent.name == cache_key):
                    matches.setdefault(str(source_path), set()).add(cache_key)
            except (OSError, ValueError, TypeError):
                continue
        return {source: sorted(keys) for source, keys in matches.items()}

    def _zone_inventory(self, relative: str, *, candidates: list[str] | None = None,
                        include_pending: bool = True, return_identity: bool = False):
        candidates = self._cached_zone_candidates(relative) if candidates is None else candidates
        if not candidates:
            return None
        archives = self.app.archives()
        accepted = []
        for zone_id in candidates:
            try:
                snapshot = archives._validated_asset_snapshot(zone_id, require_trace=False,
                                                               validate_source=True)
            except (OSError, ValueError, KeyError, TypeError):
                continue
            decoded_source = snapshot.decode_receipt.get("source", {})
            current_profile = snapshot.source_profile or {}
            decoded_patches = [(row.get("extension"), row.get("sha256"))
                               for row in decoded_source.get("patches", [])]
            current_patches = [(row.get("extension"), row.get("sha256"))
                               for row in current_profile.get("patches", [])]
            if (decoded_source.get("sha256") == current_profile.get("sha256") and
                    decoded_patches == current_patches):
                accepted.append((zone_id, snapshot))
        if not accepted:
            return None
        if len(accepted) != 1:
            raise ValueError("Multiple cached zone inventories match the current FF/patch identity")
        zone_id, snapshot = accepted[0]
        native_rows = snapshot.native_rows or []
        rows = []
        for index, header in enumerate(snapshot.body.assets):
            native = native_rows[index] if index < len(native_rows) else {}
            name = native.get("name") if native.get("type_id") == header.type_id else None
            rows.append({"index": index, "type_id": header.type_id, "name": name,
                         "type_name": native.get("type") if name is not None else None,
                         "reference_only": native.get("status") == "reference"})
        # Keep staged append rows visible in the same tree as native rows.
        if include_pending and any(snapshot.cache_path.glob("pending-edits/op-*/current.json")):
            operations = []
            for module_name in ("workstation_localize_crud", "workstation_luafile_crud",
                                "workstation_rawfile_crud",
                                "workstation_scriptfile_crud", "workstation_shader_crud",
                                "workstation_image_crud"):
                module = __import__(module_name, fromlist=["operations"])
                operations.extend(module.operations(archives, zone_id, _snapshot=snapshot))
            removed = {item.get("index") for item in operations if item.get("operation") == "remove"}
            for row in rows:
                if row["index"] in removed:
                    row["operation"] = "remove"
            for operation in operations:
                if operation.get("operation") == "append":
                    rows.append({"index": None, "type_id": operation["type_id"],
                        "name": operation["name"], "type_name": operation["type"],
                        "reference_only": False, "asset_id": operation["asset_id"],
                        "operation": "append"})
        if return_identity:
            def sha_profile(profile):
                return {"sha256": profile.get("sha256") if isinstance(profile.get("sha256"), str) else None,
                    "patches": [{"extension": row.get("extension"), "sha256": row.get("sha256")}
                        for row in profile.get("patches", []) if isinstance(row, dict) and
                        isinstance(row.get("extension"), str) and isinstance(row.get("sha256"), str)]}
            native_walk = snapshot.native_walk or {}
            native_identity = {key: native_walk[key] for key in
                ("walk_key", "manifest_sha256", "stream_trace_sha256", "decoded_body_sha256")
                if isinstance(native_walk, dict) and isinstance(native_walk.get(key), str)}
            identity = {"zone_id": zone_id,
                "decode_source": sha_profile(decoded_source),
                "current_source_profile": sha_profile(current_profile),
                "native_walk": native_identity,
                "receipt_path": str((snapshot.cache_path / "decode-receipt.json").resolve())}
            return zone_id, rows, identity
        return zone_id, rows

    def _asset_type(self, zone_id: str, relative: str, type_id: int,
                    rows: list[dict]) -> dict:
        names = [row.get("type_name") for row in rows if row.get("type_name")]
        type_name = names[0] if names and len(set(names)) == 1 else _UNKNOWN_DISPLAY
        return {"id": _node_id({"kind": "asset-type", "relative_path": relative,
                                "zone_id": zone_id, "type_id": type_id,
                                "type_name": type_name}),
                "name": type_name, "kind": "folder", "expandable": True,
                "type_id": type_id, "count": len(rows), "zone_id": zone_id,
                "editor_status": ("native-reader-unavailable" if rows and all(
                    row.get("reader_scope") == "xasset-table-only" for row in rows)
                    else self._editor_status(type_id))}

    @staticmethod
    def _editor_status(type_id: int) -> str:
        if type_id in _TYPED_ASSET_FAMILIES:
            return f"{_TYPED_ASSET_FAMILIES[type_id]}-codec-validated-on-open"
        if type_id == 21:
            return "soundbank-metadata-and-resident-sab-editor-when-available"
        return "native-table-metadata-only"

    def _asset_name_children(self, rows: list[dict], relative: str,
                             zone_id: str, type_id: int, prefix: str) -> list[dict]:
        result = {}
        for row in rows:
            name = row.get("name")
            native_name_available = isinstance(name, str) and bool(name)
            if not isinstance(name, str) or not name:
                name = _UNKNOWN_DISPLAY
            if ("\\" in name or "\x00" in name or name.startswith("/") or
                    any(part in ("", ".", "..") for part in name.split("/")) or
                    any(":" in part for part in name.split("/"))):
                name = _UNKNOWN_DISPLAY
            parts = name.split("/")
            if not parts:
                parts = [_UNKNOWN_DISPLAY]
            if prefix:
                prefix_parts = prefix.split("/")
                if parts[:len(prefix_parts)] != prefix_parts or len(parts) <= len(prefix_parts):
                    continue
                parts = parts[len(prefix_parts):]
            if len(parts) > 1:
                folder = parts[0]
                next_prefix = f"{prefix}/{folder}".strip("/")
                key = ("dir", next_prefix)
                result[key] = {"id": _node_id({"kind": "asset-dir", "relative_path": relative,
                    "zone_id": zone_id, "type_id": type_id, "prefix": next_prefix,
                    "type_name": row.get("type_name") or _UNKNOWN_DISPLAY}),
                    "name": folder, "kind": "folder", "expandable": True,
                    "type_id": type_id, "zone_id": zone_id}
                continue
            asset_id = row.get("asset_id") or f"{zone_id}:{row['index']}"
            result[("asset", asset_id)] = {"id": _node_id({"kind": "asset-target", "asset_id": asset_id}),
                "name": parts[0], "kind": "asset", "expandable": False,
                "relative_path": relative,
                "asset_id": asset_id, "zone_id": zone_id, "index": row.get("index"),
                "type_id": type_id, "type": row.get("type_name") or _UNKNOWN_DISPLAY,
                "identity_status": ("native-identity-verified" if native_name_available else "xasset-index-only"),
                "native_name_available": native_name_available,
                "reader_scope": row.get("reader_scope", "native-walk"),
                "editor_status": ("native-reader-unavailable" if row.get("reader_scope") ==
                                  "xasset-table-only" else WorkspaceTree._editor_status(type_id)),
                "reference_only": row.get("reference_only"),
                "operation": row.get("operation"),
                "metadata_only": True,
                "target": {"asset_id": asset_id, "relative_path": relative,
                    "zone_id": zone_id, "type_id": type_id, "index": row.get("index"),
                    "metadata_only": True}}
        return sorted(result.values(), key=lambda item: (item["name"].casefold(), item["kind"], item.get("asset_id", "")))
