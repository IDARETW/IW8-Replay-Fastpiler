"""Persistent, display-only metadata catalog for the workspace tree.

Catalog rows improve tree loading only. They are never accepted as source or
asset freshness evidence by read, edit, packaging, or compile operations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import time
import uuid

_SCHEMA = 2
_VALIDATION_SCOPE = "display-only-metadata"
_FAMILIES = ("functions", "function_groups", "function_prefix_indexes", "symbols", "globals", "authored",
             "asset_directories", "inventories")


def _stat_fingerprint(path: Path):
    try:
        value = path.stat()
        return {"bytes": value.st_size, "mtime_ns": value.st_mtime_ns}
    except OSError:
        return None


def _safe_game_path(path: Path, game_root: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        if path.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return False
        return path.resolve(strict=True).is_relative_to(game_root)
    except (OSError, ValueError):
        return False


def _json_fingerprint(path: Path):
    stat = _stat_fingerprint(path)
    return None if stat is None else {"path": str(path.resolve()), **stat}


class WorkspaceTreeCatalog:
    """Background-built tree rows with atomic, identity-bound persistence."""

    def __init__(self, tree):
        self.tree = tree
        self.app = tree.app
        self.root = Path(self.app.project.cache) / "workspace-tree"
        self.path = self.root / "catalog.json"
        self._lock = threading.RLock()
        self._persist_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._generation = 0
        self._epochs = {name: 0 for name in _FAMILIES}
        self._indexed_at = None
        self._families = {name: [] if name in ("functions", "symbols", "globals", "authored") else {}
                          for name in _FAMILIES}
        self._states = {name: "building" for name in _FAMILIES}
        self._fingerprints = {}
        self._last_validation = 0.0
        self._errors = {}
        self._loaded_ready_snapshot = False
        self._counts = {name: 0 for name in _FAMILIES}
        self._counts.update(fastfiles=0, decoded_zones=0, native_asset_rows=0,
                            stale_inventory_zones=0)
        # Load the bounded local display snapshot before serving HTTP requests;
        # all strong refresh work remains in the daemon below.
        self._load()
        self._thread = threading.Thread(target=self._worker,
                                        name="workspace-tree-catalog", daemon=True)
        self._thread.start()
        self._wake.set()

    def _identity(self):
        project = self.app.project
        return {"project_root": str(Path(project.root).resolve()),
                "cache_root": str(Path(project.cache).resolve()),
                "game_root": str(Path(project.game).resolve()),
                "sqlite_path": str(Path(project.sqlite).resolve()),
                "backend_sha256": __import__("hashlib").sha256(json.dumps(
                    self.app.backend.files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "fastfile_inventory_schema": 1}

    def _load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("schema") != _SCHEMA or data.get("identity") != self._identity():
                return
            families = data.get("families")
            states = data.get("family_states")
            if not isinstance(families, dict) or not isinstance(states, dict):
                return
            if not self._valid_families(families):
                return
            if (any(name not in states or states[name] not in
                    ("building", "ready", "stale", "unavailable") for name in _FAMILIES) or
                    type(data.get("generation")) is not int or data["generation"] < 0 or
                    (data.get("indexed_at") is not None and not isinstance(data["indexed_at"], str)) or
                    not isinstance(data.get("fingerprints", {}), dict) or
                    not isinstance(data.get("errors", {}), dict)):
                return
            with self._lock:
                self._families = {name: families[name] for name in _FAMILIES}
                self._states = {name: states.get(name, "stale") for name in _FAMILIES}
                self._errors = data.get("errors", {})
                self._generation = int(data.get("generation", 0))
                self._indexed_at = data.get("indexed_at")
                self._fingerprints = data.get("fingerprints", {})
                self._loaded_ready_snapshot = (all(states.get(name) == "ready" for name in _FAMILIES)
                                               and not data.get("errors"))
                # Persisted rows are display-only until the background validator
                # checks their cheap fingerprints and rebuilds strong identities.
                self._states = {name: "stale" if self._families[name] else "building"
                                for name in _FAMILIES}
                self._recount_locked()
        except (OSError, ValueError, TypeError, AttributeError):
            return

    @staticmethod
    def _valid_families(families):
        def safe_relative(value):
            return (isinstance(value, str) and bool(value) and "\\" not in value and
                    not value.startswith("/") and ":" not in value and
                    all(part not in ("", ".", "..") for part in value.split("/")))

        if not isinstance(families, dict):
            return False
        for name in ("functions", "symbols", "globals", "authored"):
            rows = families.get(name)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                return False
        if any(not isinstance(row.get("id"), str) or not row["id"] or
               not isinstance(row.get("name"), str) for name in ("functions", "symbols", "globals")
               for row in families[name]):
            return False
        if any(not safe_relative(row.get("path")) or
               row["path"].split("/", 1)[0] not in ("src", "source-workstation")
               for row in families["authored"]):
            return False
        groups = families.get("function_groups")
        if (not isinstance(groups, dict) or any(not isinstance(key, str) or
                type(value) is not int or value < 0 for key, value in groups.items())):
            return False
        indexes = families.get("function_prefix_indexes")
        if (not isinstance(indexes, dict) or any(not isinstance(key, str) or
                not isinstance(value, list) or any(type(index) is not int or index < 0 or
                    index >= len(families["functions"]) for index in value)
                for key, value in indexes.items())):
            return False
        directories, inventories = families.get("asset_directories"), families.get("inventories")
        if not isinstance(directories, dict) or not isinstance(inventories, dict):
            return False
        if any(not isinstance(key, str) or not isinstance(rows, list) or
               any(not isinstance(row, dict) or row.get("kind") not in ("directory", "zone")
                   or (row.get("kind") == "directory" and
                       (not isinstance(row.get("name"), str) or not safe_relative(row.get("path"))))
                   or (row.get("kind") == "zone" and
                       (not safe_relative(row.get("relative_path")) or
                        type(row.get("bytes")) is not int or row["bytes"] < 0 or
                        not isinstance(row.get("status"), str) or
                        not isinstance(row.get("candidate_zone_ids", []), list) or
                        any(not isinstance(zone_id, str) for zone_id in row.get("candidate_zone_ids", []))))
                   for row in rows) for key, rows in directories.items()):
            return False
        if any(not isinstance(key, str) or not isinstance(row, dict) or
               not isinstance(row.get("rows", []), list) or
               not safe_relative(row.get("relative_path")) or
               any(not isinstance(asset, dict) for asset in row.get("rows", []))
               or (row.get("zone_id") is not None and not isinstance(row.get("zone_id"), str))
               or row.get("state") not in ("uncached", "building", "ready", "stale", "unavailable")
               or (row.get("strong_identity") is not None and not isinstance(row["strong_identity"], dict))
               or any(type(asset.get("type_id")) is not int or not 0 <= asset["type_id"] <= 255 or
                      (asset.get("index") is not None and type(asset.get("index")) is not int) or
                      (asset.get("name") is not None and not isinstance(asset.get("name"), str)) or
                      (asset.get("type_name") is not None and not isinstance(asset.get("type_name"), str))
                      for asset in row.get("rows", []))
               for key, row in inventories.items()):
            return False
        return all(name in families for name in _FAMILIES)

    def status(self):
        with self._lock:
            state = ("unavailable" if any(item == "unavailable" for item in self._states.values())
                     else "building" if any(item == "building" for item in self._states.values())
                     else "stale" if any(item == "stale" for item in self._states.values())
                     else "stale" if self._counts["stale_inventory_zones"]
                     else "ready")
            counts = {name: self._counts[name] for name in _FAMILIES if name != "inventories"}
            counts.update(fastfiles=self._counts["fastfiles"],
                          decoded_zones=self._counts["decoded_zones"],
                          native_asset_rows=self._counts["native_asset_rows"])
            return {"state": state, "generation": self._generation,
                    "indexed_at": self._indexed_at, "family_counts": counts,
                    "family_states": dict(self._states), "errors": dict(self._errors),
                    "validation_scope": _VALIDATION_SCOPE}

    def family(self, name):
        with self._lock:
            rows = self._families[name]
            # Published families are read-only snapshots; readers borrow the
            # immutable pointer. Inventory navigation uses entry() for O(1) lookup.
            return rows, self._states[name]

    def entry(self, name, key):
        with self._lock:
            return self._families[name].get(key), self._states[name]

    def _epoch(self, family):
        with self._lock:
            return self._epochs[family]

    def mark_dirty(self, *families):
        with self._lock:
            for family in families:
                if family in self._states:
                    self._epochs[family] += 1
                    self._states[family] = "stale"
                    if family == "functions":
                        self._epochs["function_groups"] += 1
                        self._epochs["function_prefix_indexes"] += 1
                        self._states["function_groups"] = "stale"
                        self._states["function_prefix_indexes"] = "stale"
                elif family.startswith("zone:"):
                    zones, state = self._families["inventories"], self._states["inventories"]
                    relative = family[5:]
                    if relative in zones:
                        copy_zones = dict(zones)
                        copy_zones[relative] = dict(zones[relative], state="stale")
                        self._families["inventories"] = copy_zones
                        self._epochs["inventories"] += 1
                        self._recount_locked()
                    self._states["inventories"] = "stale"
        self._wake.set()

    def _persist(self):
        # Inventory maps are updated with copy-on-write rows. Take a bounded
        # structural snapshot under the lock, then serialize/write outside it.
        with self._persist_lock:
            with self._lock:
                families = {}
                for name, rows in self._families.items():
                    if name == "inventories":
                        families[name] = {key: dict(row, rows=list(row.get("rows", [])))
                                          for key, row in rows.items()}
                    else:
                        families[name] = dict(rows) if isinstance(rows, dict) else list(rows)
                data = {"schema": _SCHEMA, "identity": self._identity(),
                        "generation": self._generation, "indexed_at": self._indexed_at,
                        "family_states": dict(self._states), "errors": dict(self._errors),
                        "families": families, "fingerprints": dict(self._fingerprints)}
            pending = self.path.with_name(self.path.name + "." + uuid.uuid4().hex + ".tmp")
            try:
                self.root.mkdir(parents=True, exist_ok=True)
                encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
                with pending.open("w", encoding="utf-8", newline="\n") as stream:
                    for chunk in encoder.iterencode(data):
                        stream.write(chunk)
                    stream.write("\n")
                os.replace(pending, self.path)
            except OSError:
                # The in-memory catalog remains useful when the cache volume is
                # temporarily unavailable; next startup rebuilds it.
                try:
                    pending.unlink(missing_ok=True)
                except OSError:
                    pass

    def _publish(self, family, rows, fingerprints=None, *, expected_epoch=None,
                 publish_state="ready"):
        inventory_counts = None
        if family == "inventories":
            inventory_counts = (len(rows),
                sum(bool(row.get("zone_id")) for row in rows.values()),
                sum(len(row.get("rows", [])) for row in rows.values()),
                sum(row.get("state") == "stale" for row in rows.values()))
        with self._lock:
            if expected_epoch is not None and self._epochs[family] != expected_epoch:
                self._wake.set()
                return False
            self._generation += 1
            self._indexed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._families[family] = rows
            self._states[family] = publish_state
            self._errors.pop(family, None)
            self._counts[family] = len(rows)
            if inventory_counts is not None:
                (self._counts["fastfiles"], self._counts["decoded_zones"],
                 self._counts["native_asset_rows"], self._counts["stale_inventory_zones"]) = inventory_counts
            if fingerprints is not None:
                self._fingerprints[family] = fingerprints
        if family in ("functions", "symbols", "globals"):
            self.tree._source_search.prepare({"functions": "function", "symbols": "symbol",
                                              "globals": "global"}[family], rows)
        self._persist()
        return True

    def close(self):
        self._stop.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1)

    def _recount_locked(self):
        for name in _FAMILIES:
            self._counts[name] = len(self._families[name])
        inventories = self._families["inventories"]
        self._counts["fastfiles"] = len(inventories)
        self._counts["decoded_zones"] = sum(bool(row.get("zone_id")) for row in inventories.values())
        self._counts["native_asset_rows"] = sum(len(row.get("rows", [])) for row in inventories.values())
        self._counts["stale_inventory_zones"] = sum(row.get("state") == "stale"
                                                      for row in inventories.values())

    def _worker(self):
        first = True
        # Warm persisted display rows in the background before the first
        # query. Asset-only catalog changes leave these indexes intact.
        for family, group in (("functions", "function"), ("symbols", "symbol"),
                              ("globals", "global")):
            self.tree._source_search.prepare(group, self.family(family)[0])
        while not self._stop.is_set():
            signaled = self._wake.wait(timeout=30)
            self._wake.clear()
            if self._stop.is_set():
                return
            if first and self._loaded_ready_snapshot:
                try:
                    changed = self._fingerprints_changed()
                except Exception:
                    changed = True
                if not changed:
                    # Persisted rows are display-only snapshots, not read/build
                    # proof. Reuse them when cheap identities match and defer
                    # strong rebuild to the regular validation interval.
                    with self._lock:
                        self._states = {name: "ready" for name in _FAMILIES}
                    self._last_validation = time.monotonic()
                    first = False
                    continue
                self._mark_stale()
            if not first and not signaled:
                try:
                    changed = self._fingerprints_changed()
                    if not changed and time.monotonic() - self._last_validation < 300:
                        continue
                    self._mark_stale()
                except Exception:
                    # A failed cheap probe is treated as a reason to rebuild.
                    pass
            try:
                self._build()
                first = False
                self._last_validation = time.monotonic()
            except Exception:
                with self._lock:
                    for family in _FAMILIES:
                        if self._states[family] != "ready":
                            self._states[family] = "stale"
                self._persist()

    def _fingerprints_changed(self):
        project = self.app.project
        source = self._source_fingerprints([])
        source["sqlite"] = _stat_fingerprint(Path(project.sqlite))
        if source != self._fingerprints.get("functions"):
            return True
        authored = self._source_fingerprints(project.authored_files())
        if authored != self._fingerprints.get("authored"):
            return True
        game_root = self.app.archives().game_root
        current_ff = {}
        for base, _dirs, files in os.walk(game_root):
            for name in files:
                path = Path(base) / name
                if path.suffix.casefold() == ".ff" and _safe_game_path(path, game_root):
                    rel = path.relative_to(game_root).as_posix()
                    current_ff[rel] = {"file": _stat_fingerprint(path),
                                       "fp": _stat_fingerprint(path.with_suffix(".fp")),
                                       "fc": _stat_fingerprint(path.with_suffix(".fc"))}
        previous_ff = self._fingerprints.get("asset_directories", {})
        prior_ff = {key: {"file": value.get("file"), "fp": value.get("fp"),
                          "fc": value.get("fc")}
                    for key, value in previous_ff.items()
                    if isinstance(value, dict) and "file" in value}
        if current_ff != prior_ff:
            return True
        current_cache = self._cache_fingerprints()
        return current_cache != previous_ff.get("_cache_metadata", {})

    def _cache_fingerprints(self):
        archives = self.app.archives()
        rows = {}
        for path in archives.cache_root.glob("*/*/decode-receipt.json"):
            rows[str(path.relative_to(archives.cache_root).as_posix())] = _stat_fingerprint(path)
        for path in archives.cache_root.glob("*/*/pending-edits/op-*/current.json"):
            rows[str(path.relative_to(archives.cache_root).as_posix())] = _stat_fingerprint(path)
        return rows

    def _build(self):
        project = self.app.project
        functions_epoch = self._epoch("functions")
        groups_epoch = self._epoch("function_groups")
        prefix_epoch = self._epoch("function_prefix_indexes")
        try:
            with project.mutation_lock:
                functions, _ = self.app.sources.list_source_rows("", "function")
                source_fingerprints = self._source_fingerprints([])
                source_fingerprints["sqlite"] = _stat_fingerprint(Path(project.sqlite))
            published = self._publish("functions", functions, source_fingerprints,
                                      expected_epoch=functions_epoch)
            groups = {}
            indexes = {}
            for row_index, row in enumerate(functions):
                prefix = self.tree._function_prefix(row.get("name", ""))
                groups[prefix] = groups.get(prefix, 0) + 1
                indexes.setdefault(prefix, []).append(row_index)
            if published:
                self._publish("function_groups", groups, expected_epoch=groups_epoch)
                self._publish("function_prefix_indexes", indexes, expected_epoch=prefix_epoch)
        except Exception as error:
            self._set_unavailable("functions", "function_groups", error=error)
        try:
            symbols_epoch = self._epoch("symbols")
            with project.mutation_lock:
                symbols, _ = self.app.sources.list_source_rows("", "symbol")
            self._publish("symbols", symbols, expected_epoch=symbols_epoch)
        except Exception as error:
            self._set_unavailable("symbols", error=error)
        try:
            globals_epoch = self._epoch("globals")
            with project.mutation_lock:
                globals_rows = self.app.globals().list_editable()
            self._publish("globals", globals_rows, expected_epoch=globals_epoch)
        except Exception as error:
            self._set_unavailable("globals", error=error)
        try:
            authored_epoch = self._epoch("authored")
            with project.mutation_lock:
                authored = project.authored_files()
                authored_fingerprints = self._source_fingerprints(authored)
            self._publish("authored", authored, authored_fingerprints,
                          expected_epoch=authored_epoch)
        except Exception as error:
            self._set_unavailable("authored", error=error)

        try:
            directories_epoch = self._epoch("asset_directories")
            directories, paths, ff_fingerprints = self._build_fastfiles()
            if not self._publish("asset_directories", directories, ff_fingerprints,
                                 expected_epoch=directories_epoch):
                return
        except Exception as error:
            self._set_unavailable("asset_directories", "inventories", error=error)
            return
        # Publish each zone as it completes: a large decoded-cache collection
        # must not delay already available Code and basic Assets rows.
        inventory_epoch = self._epoch("inventories")
        old_zones, _ = self.family("inventories")
        current_relatives = {relative for relative, _path, _stat in paths}
        stale_zones = {relative: dict(row, state="stale") for relative, row in old_zones.items()
                       if relative in current_relatives}
        if not self._publish("inventories", stale_zones, ff_fingerprints,
                              expected_epoch=inventory_epoch, publish_state="building"):
            return
        for relative, row in self._build_inventories(paths, directories):
            with self._lock:
                previous = self._families["inventories"].get(relative)
                self._families["inventories"][relative] = row
                self._generation += 1
                self._indexed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                if previous is None:
                    self._counts["fastfiles"] += 1
                if not previous or not previous.get("zone_id"):
                    if row.get("zone_id"):
                        self._counts["decoded_zones"] += 1
                elif not row.get("zone_id"):
                    self._counts["decoded_zones"] -= 1
                self._counts["native_asset_rows"] += len(row.get("rows", [])) - len((previous or {}).get("rows", []))
                self._counts["stale_inventory_zones"] += int(row.get("state") == "stale") - int(
                    (previous or {}).get("state") == "stale")
        with self._lock:
            if self._epochs["inventories"] == inventory_epoch:
                self._states["inventories"] = "ready"
            else:
                self._states["inventories"] = "stale"
                self._wake.set()
        self._persist()

    def _set_unavailable(self, *families, error=None):
        with self._lock:
            for family in families:
                has_rows = bool(self._families[family])
                self._states[family] = "stale" if has_rows else "unavailable"
                self._errors[family] = (str(error)[:240] if error is not None else
                    "Background catalog refresh failed")
        self._persist()

    def _mark_stale(self):
        with self._lock:
            for family in _FAMILIES:
                if self._states[family] in ("ready", "building"):
                    self._states[family] = "stale"
        self._persist()

    def _source_fingerprints(self, authored):
        import recovered_cpp_names
        policy = hashlib.sha256(Path(recovered_cpp_names.__file__).read_bytes()).hexdigest()
        root = Path(self.app.project.root)
        result = {}
        for row in authored:
            path = root / row["path"]
            result[row["path"]] = _stat_fingerprint(path)
        for name in ("source-units.json", "source-workstation/units.json",
                     "source-workstation/user-functions.json", "generated/function-catalog.json",
                     "generated/manifest.json"):
            result[name] = _stat_fingerprint(root / name)
        result["cpp_symbol_policy"] = policy
        result["sqlite"] = _stat_fingerprint(Path(self.app.project.sqlite))
        sources = getattr(self.app, "sources", None)
        if sources is not None:
            manifest = getattr(sources, "manifest_path", None)
            if manifest is not None:
                result["source_manifest"] = _stat_fingerprint(Path(manifest))
            try:
                state = sources._state()
                result["source_revisions"] = sorted(
                    (identity, variant, entry.get("revision"), entry.get("path"))
                    for identity, variants in state.get("sources", {}).items()
                    for variant, entry in variants.items())
            except Exception:
                result["source_revisions"] = None
        # GlobalSourceWorkspace.generated is deterministically project_root/generated.
        # Fingerprint it without calling Application.globals(), so cold and warm
        # Application instances produce the same authored-family fingerprint.
        generated = root / "generated"
        for name in ("function-catalog.json", "manifest.json"):
            result["globals/" + name] = _stat_fingerprint(generated / name)
        game = getattr(self.app.project, "game", None)
        if game is not None:
            result["replay_executable"] = _stat_fingerprint(Path(game) / "game_dx12_ship_replay.exe")
        return result

    def _build_fastfiles(self):
        archives = self.app.archives()
        game_root = archives.game_root.resolve(strict=True)
        from workstation_fastfiles import _source_header
        directories = {"": []}
        paths = []
        fingerprints = {}
        for base, dirs, files in os.walk(game_root):
            dirs[:] = sorted(name for name in dirs if _safe_game_path(Path(base) / name, game_root))
            base_path = Path(base)
            relative_dir = base_path.relative_to(game_root).as_posix()
            if relative_dir == ".":
                relative_dir = ""
            directories.setdefault(relative_dir, [])
            for name in dirs:
                child = (base_path / name).relative_to(game_root).as_posix()
                directories.setdefault(relative_dir, []).append({"kind": "directory", "path": child,
                    "name": name, "fingerprint": _stat_fingerprint(base_path / name)})
                directories.setdefault(child, [])
            for name in files:
                path = base_path / name
                if path.suffix.casefold() != ".ff" or not _safe_game_path(path, game_root):
                    continue
                relative = path.relative_to(game_root).as_posix()
                stat = _stat_fingerprint(path)
                if stat is None:
                    continue
                try:
                    header = _source_header(path)
                    row = {"relative_path": relative, "bytes": stat["bytes"],
                           "status": "source-header-checked",
                           "source_xfile_version": header.xfile_version,
                           "transient_type": header.transient_type}
                except (OSError, ValueError) as error:
                    row = {"relative_path": relative, "bytes": stat["bytes"],
                           "status": "unsupported-or-invalid", "error": str(error)}
                fingerprints[relative] = {"file": stat,
                    "fp": _stat_fingerprint(path.with_suffix(".fp")),
                    "fc": _stat_fingerprint(path.with_suffix(".fc")),
                    "header": {key: row.get(key) for key in ("status", "source_xfile_version", "transient_type")}}
                zone_row = {"kind": "zone", **row, "candidate_zone_ids": []}
                directories[relative_dir].append(zone_row)
                paths.append((relative, str(path.resolve()), stat))
        for rows in directories.values():
            rows.sort(key=lambda row: (row["name" if row["kind"] == "directory" else "relative_path"].casefold(),
                                       row["kind"]))
        return directories, paths, fingerprints

    def _build_inventories(self, paths, directories):
        archives = self.app.archives()
        old_zones, _old_state = self.family("inventories")
        directories = {key: [dict(row) for row in rows]
                       for key, rows in directories.items()}
        with self.app.fastfile_lock:
            candidates = self.tree._cached_zone_index()
        cache_metadata = self._cache_fingerprints()
        zone_rows = {row.get("relative_path"): row for rows in directories.values()
                     for row in rows if row.get("kind") == "zone"}
        for relative, absolute, _stat in paths:
            zone_rows[relative]["candidate_zone_ids"] = candidates.get(absolute, [])
        directory_fingerprints = dict(self._fingerprints.get("asset_directories", {}))
        directory_fingerprints["_cache_metadata"] = cache_metadata
        self._publish("asset_directories", directories, directory_fingerprints)
        for relative, absolute, stat in paths:
            keys = candidates.get(absolute, [])
            entry = {"relative_path": relative, "file_fingerprint": stat,
                     "candidate_zone_ids": keys, "zone_id": None, "rows": [],
                     "state": "uncached", "validation_scope": _VALIDATION_SCOPE}
            if keys:
                try:
                    with self.app.fastfile_lock:
                        inventory = self.tree._zone_inventory(relative, candidates=keys,
                                                               include_pending=False, return_identity=True)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    inventory = None
                    entry.update(state="unavailable", error=str(error)[:240])
                if inventory is not None:
                    zone_id, rows, strong_identity = inventory
                    entry.update(zone_id=zone_id, rows=rows, state="ready",
                                 strong_identity=strong_identity,
                                 receipt_fingerprint=_stat_fingerprint(
                                     archives.cache_root / Path(absolute).stem / zone_id / "decode-receipt.json"))
                elif entry["state"] != "unavailable":
                    entry.update(state="unavailable",
                        error="Cached candidate failed current source/profile validation")
            if entry["state"] != "ready" and relative in old_zones:
                previous = old_zones[relative]
                if previous.get("zone_id"):
                    entry.update(zone_id=previous["zone_id"], rows=previous.get("rows", []),
                                 state="stale", receipt_fingerprint=previous.get("receipt_fingerprint"))
                    if entry.get("error"):
                        entry["refresh_error"] = entry.pop("error")
            yield relative, entry
