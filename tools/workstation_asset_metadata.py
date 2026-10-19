"""Resumable native XAsset metadata index; payloads are acquired separately.

Every shard comes from the strict Replay source decoder. Complete native walks
supply names; when a native revision is unsupported, validated table-only rows
retain their identities with explicit reader limitations. Temporary decoded
bodies are released after indexing. Neither the shard nor this search database
can authorize an edit or a package write.
"""
from __future__ import annotations

import copy
from collections import OrderedDict
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import threading
import time

import workstation_fastfiles as fastfiles
import workstation_metadata_decode as table_decode
from workstation_reader_identity import reader_code_identity


_READER_BASELINE_PATH = Path(__file__).with_name("workstation_reader_identity_baseline.json")
_READER_BASELINE = json.loads(_READER_BASELINE_PATH.read_text(encoding="utf-8"))


class MetadataReaderDriftError(RuntimeError):
    """The metadata reader identity changed; abort rather than record a bad FF."""


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Metadata contains a non-JSON value: {type(value).__name__}")


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
            default=_json_default), encoding="utf-8")
        for attempt in range(6):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                # Windows readers can briefly hold a handle without delete
                # sharing. Keep the last good manifest visible while retrying
                # this worker's same atomic replacement, with a bounded wait.
                if attempt == 5:
                    raise
                time.sleep(0.02 * (2 ** attempt))
    finally:
        temporary.unlink(missing_ok=True)


def _confined_file(path, root):
    try:
        entry = path.lstat()
        return (stat.S_ISREG(entry.st_mode) and not path.is_symlink() and
                not getattr(entry, "st_file_attributes", 0) & 0x400 and
                path.resolve(strict=True).is_relative_to(root))
    except OSError:
        return False


def _fingerprint(source):
    def details(path):
        try:
            value = path.stat()
            return dict(bytes=value.st_size, mtime_ns=value.st_mtime_ns)
        except FileNotFoundError:
            return None
    return {"source": details(source), "companions": {
        suffix: details(source.with_suffix(suffix)) for suffix in (".fp", ".fc")}}


class AssetMetadataIndex:
    """One bounded indexing worker and a persistent substring search index."""

    def __init__(self, archives):
        self.archives = archives
        self.root = archives.cache_root.parent / "asset-metadata-v1"
        self.path = self.root / "manifest.json"
        self.database = self.root / "search.sqlite3"
        self._lock = threading.RLock()
        self._run_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._shards = OrderedDict()
        self._generation = 0
        self._files = {}
        self._error = None
        self._active = None
        self._indexing = False
        self._manifest_stamp = None
        self._reader_identity_stamp = None
        self._reader_identity_value = None
        self._identity_watch_paths = ()
        self.identity = self._reader_identity()
        self._reader_identity_aliases = []
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            saved_identity = saved.get("identity")
            aliases = saved.get("reader_identity_aliases", [])
            if saved.get("schema") == 1 and isinstance(aliases, list) and all(
                    self._legacy_identity_valid(alias) for alias in aliases):
                compatible = saved_identity == self.identity or self._legacy_identity_valid(saved_identity)
                if not compatible:
                    raise ValueError("metadata reader identity changed")
                self._reader_identity_aliases = list(aliases)
                if saved_identity != self.identity and saved_identity not in self._reader_identity_aliases:
                    self._reader_identity_aliases.append(saved_identity)
                rows = saved.get("files")
                if not isinstance(rows, dict):
                    raise ValueError("metadata manifest has no file map")
                for relative, row in rows.items():
                    self._source(relative)
                    if not isinstance(row, dict) or row.get("state") not in (
                            "pending", "indexing", "ready", "unavailable"):
                        raise ValueError("invalid metadata manifest entry")
                self._files = rows
                value = self.path.stat()
                self._manifest_stamp = (value.st_size, value.st_mtime_ns)
                self._generation = int(saved.get("generation", 0))
                for row in self._files.values():
                    if row["state"] == "indexing":
                        row["state"] = "pending"
                if saved_identity != self.identity:
                    self._persist()
        except (OSError, ValueError, TypeError):
            self._files = {}

    def _reader_identity(self):
        stamp = self._identity_stat_stamp()
        if stamp == self._reader_identity_stamp and self._reader_identity_value is not None:
            return self._reader_identity_value
        return self._compute_reader_identity(stamp)

    def _identity_stat_stamp(self):
        """Cheap change hints; never used as source freshness or edit proof."""
        paths = self._identity_watch_paths
        if not paths:
            paths = (Path(fastfiles.__file__), Path(table_decode.__file__), Path(__file__),
                     self.archives.replay_executable, self.archives.acts_path,
                     Path(self.archives.acts_path).parent,
                     Path(self.archives.acts_path).parent / "data")
        result = []
        for path in paths:
            try:
                value = path.stat()
                result.append((str(path), value.st_size, value.st_mtime_ns,
                               getattr(value, "st_file_attributes", 0)))
            except OSError:
                result.append((str(path), None, None, None))
        return tuple(result)

    def _compute_reader_identity(self, stamp=None):
        import inspect_frontend_asset_table
        import workstation_native_references
        import frontend_catalog
        modules = (Path(fastfiles.__file__), Path(table_decode.__file__), Path(inspect_frontend_asset_table.__file__),
                   Path(workstation_native_references.__file__), Path(frontend_catalog.__file__), Path(__file__),
                   Path(reader_code_identity.__code__.co_filename), _READER_BASELINE_PATH)
        code = reader_code_identity(fastfiles.__file__, _READER_BASELINE["reader_entrypoints"],
            Path(fastfiles.__file__).resolve().parent)
        module_hashes = {path.name: fastfiles.sha256_file(path) for path in modules
                         if path.resolve() != Path(fastfiles.__file__).resolve()}
        identity = dict(game_root=str(self.archives.game_root.resolve()),
                        acts_tool_identity=fastfiles.acts_tool_identity(self.archives.acts_path),
                        replay_executable_sha256=fastfiles.sha256_file(self.archives.replay_executable),
                        reader_code=code, reader_modules=module_hashes)
        # Monitor every dependency that contributed to the strong identity.
        acts_dir = Path(self.archives.acts_path).resolve().parent
        watched = {path.resolve() for path in modules}
        for name in code["local_dependencies"]:
            if name == "<local-source-inventory>":
                tools_root = Path(fastfiles.__file__).resolve().parent
                watched.update(path.resolve() for path in tools_root.rglob("*.py"))
                watched.update(path.resolve() for path in tools_root.rglob("*") if path.is_dir())
                continue
            dependency = Path(fastfiles.__file__).resolve().parent.joinpath(*name.split("."))
            dependency = dependency.with_suffix(".py")
            if dependency.exists():
                watched.add(dependency.resolve())
        watched.update((Path(self.archives.replay_executable).resolve(),
                        Path(self.archives.acts_path).resolve(), acts_dir, acts_dir / "data"))
        for binary in identity["acts_tool_identity"].get("binaries", []):
            watched.add(acts_dir / binary["name"])
        for item in identity["acts_tool_identity"].get("data_files", []):
            watched.add(acts_dir / "data" / item["path"])
        data_root = acts_dir / "data"
        if data_root.is_dir():
            watched.update(path.resolve() for path in data_root.rglob("*") if path.is_dir())
        self._identity_watch_paths = tuple(sorted(watched, key=lambda path: str(path).casefold()))
        self._reader_identity_value = identity
        self._reader_identity_stamp = self._identity_stat_stamp()
        return identity

    def _force_reader_identity(self):
        self._reader_identity_stamp = None
        return self._reader_identity()

    def _legacy_identity_valid(self, value):
        if not isinstance(value, dict) or value.get("game_root") != self.identity.get("game_root"):
            return False
        if (value.get("acts_tool_identity") != self.identity.get("acts_tool_identity") or
                value.get("replay_executable_sha256") != self.identity.get("replay_executable_sha256")):
            return False
        modules = value.get("reader_modules")
        if not isinstance(modules, dict):
            return False
        expected = _READER_BASELINE.get("legacy_reader_modules")
        baseline_reader = _READER_BASELINE.get("reader_code")
        if (not isinstance(expected, dict) or not isinstance(baseline_reader, dict) or
                _READER_BASELINE.get("schema") != 1 or
                expected.get("workstation_fastfiles.py") != _READER_BASELINE.get("baseline_source_sha256") or
                baseline_reader.get("entrypoints") != sorted(_READER_BASELINE.get("reader_entrypoints", []))):
            return False
        current_modules = self.identity.get("reader_modules", {})
        return (modules == expected and
                all(current_modules.get(name) == digest for name, digest in expected.items()
                    if name not in ("workstation_fastfiles.py", "workstation_asset_metadata.py")) and
                self.identity.get("reader_code", {}).get("sha256") == baseline_reader.get("sha256"))

    def _source(self, relative):
        if (not isinstance(relative, str) or not relative or "\\" in relative or
                ":" in relative or relative.startswith("/") or
                any(part in ("", ".", "..") for part in relative.split("/"))):
            raise ValueError("metadata source must be a confined relative fastfile")
        source = self.archives.game_root / relative
        if source.suffix.casefold() != ".ff":
            raise ValueError("metadata source must be a fastfile")
        return source

    def snapshot(self):
        self._refresh_manifest()
        with self._lock:
            files = copy.deepcopy(self._files)
            counts = dict(total_fastfiles=len(files), indexed_fastfiles=0,
                          unavailable_fastfiles=0, pending_fastfiles=0, asset_rows=0,
                          native_asset_rows=0, native_walk_fastfiles=0, table_only_fastfiles=0)
            for row in files.values():
                if row["state"] == "ready":
                    counts["indexed_fastfiles"] += 1
                    counts["asset_rows"] += row.get("asset_count", 0)
                    if row.get("reader_scope", "native-walk") == "xasset-table-only":
                        counts["table_only_fastfiles"] += 1
                    else:
                        counts["native_walk_fastfiles"] += 1
                        counts["native_asset_rows"] += row.get("asset_count", 0)
                elif row["state"] == "unavailable":
                    counts["unavailable_fastfiles"] += 1
                else:
                    counts["pending_fastfiles"] += 1
            complete = bool(files) and counts["indexed_fastfiles"] == len(files)
            native_names_complete = complete and not counts["table_only_fastfiles"]
            state = ("unavailable" if self._error else "ready" if native_names_complete else
                     "building" if counts["pending_fastfiles"] or not files else "partial")
            return dict(schema=1, identity=self.identity, files=files, counts=counts,
                        state=state, complete=complete, native_names_complete=native_names_complete,
                        generation=self._generation,
                        active_fastfile=self._active, error=self._error,
                        reader_identity_aliases=copy.deepcopy(self._reader_identity_aliases),
                        validation_scope="display-only-metadata")

    def _persist(self):
        _atomic_json(self.path, self.snapshot())
        value = self.path.stat()
        self._manifest_stamp = (value.st_size, value.st_mtime_ns)

    def _refresh_manifest(self, force=False):
        """Readers follow progress published by the single indexing process."""
        if self._indexing and not force:
            return
        try:
            value = self.path.stat()
            signature = (value.st_size, value.st_mtime_ns)
            if not force and signature == self._manifest_stamp:
                return
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            saved_identity = saved.get("identity")
            aliases = saved.get("reader_identity_aliases", [])
            if (saved.get("schema") != 1 or not isinstance(aliases, list) or
                    not all(self._legacy_identity_valid(alias) for alias in aliases) or
                    (saved_identity != self.identity and not self._legacy_identity_valid(saved_identity))):
                return
            rows = saved.get("files")
            if not isinstance(rows, dict):
                raise ValueError("metadata manifest has no file map")
            for relative, row in rows.items():
                self._source(relative)
                if not isinstance(row, dict) or row.get("state") not in (
                        "pending", "indexing", "ready", "unavailable"):
                    raise ValueError("invalid metadata manifest entry")
            with self._lock:
                self._files = rows
                self._reader_identity_aliases = list(aliases)
                if saved_identity != self.identity and saved_identity not in self._reader_identity_aliases:
                    self._reader_identity_aliases.append(saved_identity)
                self._generation = int(saved.get("generation", 0))
                self._manifest_stamp = signature
                self._active = saved.get("active_fastfile")
        except FileNotFoundError:
            return

        except (OSError, ValueError, TypeError) as error:
            with self._lock:
                if force:
                    # This manifest is a reproducible display cache, never
                    # an edit receipt. Recover from an interrupted/corrupt
                    # cache using current sources and strict native evidence.
                    self._files = {}
                    self._shards.clear()
                    self._manifest_stamp = None
                    self._error = None
                else:
                    self._error = f"Metadata cache needs rebuilding: {type(error).__name__}: {error}"

    def run_once(self, max_files=None, retry=False):
        from workstation.build_lock import compiler_lock
        entered = False
        try:
            with compiler_lock(self.root / "index.lock"):
                entered = True
                self._refresh_manifest(force=True)
                self._indexing = True
                try:
                    return self._run_batch(max_files, retry)
                finally:
                    self._indexing = False
        except ValueError:
            if entered:
                raise
            self._refresh_manifest(force=True)
            return self.snapshot()

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._worker, name="native-asset-metadata", daemon=True)
            self._thread.start()

    def close(self):
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)

    def _connect(self, writable=False):
        if writable:
            self.root.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database, timeout=30)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS zones(path TEXT PRIMARY KEY, shard_sha256 TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, path TEXT NOT NULL, asset_index INTEGER NOT NULL, row_json TEXT NOT NULL, terms TEXT NOT NULL)")
            connection.execute("CREATE INDEX IF NOT EXISTS asset_path ON assets(path,asset_index)")
            connection.execute("CREATE VIRTUAL TABLE IF NOT EXISTS asset_search USING fts5(terms,tokenize='trigram')")
            identity = json.dumps(self.identity, sort_keys=True, separators=(",", ":"))
            prior = connection.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if not prior or prior[0] != identity:
                with connection:
                    connection.execute("DELETE FROM asset_search")
                    connection.execute("DELETE FROM assets")
                    connection.execute("DELETE FROM zones")
                    connection.execute("INSERT OR REPLACE INTO metadata VALUES('identity',?)", (identity,))
        else:
            connection = sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=5)
        return connection

    def _update_database(self, relative, shard, digest):
        with closing(self._connect(True)) as connection, connection:
            connection.execute("DELETE FROM asset_search WHERE rowid IN (SELECT id FROM assets WHERE path=?)", (relative,))
            connection.execute("DELETE FROM assets WHERE path=?", (relative,))
            if shard is None:
                connection.execute("DELETE FROM zones WHERE path=?", (relative,))
                return
            for row in shard["rows"]:
                public = dict(row, relative_path=relative, zone_id=shard["zone_id"],
                              asset_id=f"{shard['zone_id']}:{row['index']}", metadata_only=True,
                              reader_scope=shard.get("reader_scope", "native-walk"))
                terms = " ".join(str(public.get(key, "")) for key in
                                 ("name", "type_name", "type_id", "index", "relative_path")).casefold()
                cursor = connection.execute("INSERT INTO assets(path,asset_index,row_json,terms) VALUES(?,?,?,?)",
                                            (relative, row["index"], json.dumps(public, ensure_ascii=False), terms))
                connection.execute("INSERT INTO asset_search(rowid,terms) VALUES(?,?)", (cursor.lastrowid, terms))
            connection.execute("INSERT OR REPLACE INTO zones VALUES(?,?)", (relative, digest))

    def _scan(self):
        found = {}
        root = self.archives.game_root.resolve(strict=True)
        for parent, directories, names in os.walk(root, followlinks=False):
            base = Path(parent)
            directories[:] = [name for name in directories
                               if not (base / name).is_symlink() and
                               not getattr((base / name).lstat(), "st_file_attributes", 0) & 0x400]
            for name in names:
                path = base / name
                if path.suffix.casefold() == ".ff" and _confined_file(path, root):
                    found[path.relative_to(root).as_posix()] = _fingerprint(path)
        with self._lock:
            removed = set(self._files).difference(found)
            changed = []
            for relative in removed:
                self._files.pop(relative)
                self._shards.pop(relative, None)
            for relative, fingerprint in found.items():
                old = self._files.get(relative)
                if not old or old.get("source_fingerprint") != fingerprint:
                    self._files[relative] = dict(state="pending", source_fingerprint=fingerprint)
                    self._shards.pop(relative, None)
                    changed.append(relative)
            self._generation += 1
        if self.database.is_file() and (removed or changed):
            with closing(self._connect(True)) as connection, connection:
                for relative in [*removed, *changed]:
                    connection.execute("DELETE FROM asset_search WHERE rowid IN (SELECT id FROM assets WHERE path=?)", (relative,))
                    connection.execute("DELETE FROM assets WHERE path=?", (relative,))
                    connection.execute("DELETE FROM zones WHERE path=?", (relative,))
        self._persist()

    def inventory(self, relative):
        self._refresh_manifest()
        source = self._source(relative)
        with self._lock:
            entry = copy.deepcopy(self._files.get(relative))
            memo = self._shards.get(relative)
        if not entry or entry["state"] != "ready" or entry.get("source_fingerprint") != _fingerprint(source):
            return None
        path = self.root / entry.get("shard_relative_path", "")
        if not _confined_file(path, self.root.resolve()) or not path.resolve().is_relative_to(self.root / "zones"):
            raise ValueError("metadata shard escapes its generated zone directory")
        value = path.stat()
        signature = (value.st_size, value.st_mtime_ns, entry.get("shard_sha256"))
        if memo and memo[0] == signature:
            return copy.deepcopy(memo[1])
        if fastfiles.sha256_file(path) != entry.get("shard_sha256"):
            raise ValueError("metadata shard failed its manifest hash")
        shard = json.loads(path.read_text(encoding="utf-8"))
        if (shard.get("schema") != 1 or shard.get("reader_identity") not in
                [self.identity, *self._reader_identity_aliases] or
                shard.get("relative_path") != relative or not shard.get("complete") or
                shard.get("zone_id") != entry.get("zone_id") or
                not isinstance(shard.get("rows"), list) or len(shard["rows"]) != entry.get("asset_count")):
            raise ValueError("metadata shard identity/coverage differs from its manifest")
        for index, row in enumerate(shard["rows"]):
            if (row.get("index") != index or type(row.get("type_id")) is not int or
                    not 0 <= row["type_id"] <= 255 or
                    (row.get("name") is not None and not isinstance(row["name"], str))):
                raise ValueError("metadata shard has malformed native asset rows")
        with self._lock:
            self._shards[relative] = (signature, shard)
            self._shards.move_to_end(relative)
            while len(self._shards) > 16:
                self._shards.popitem(last=False)
        return copy.deepcopy(shard)

    def read_only_asset(self, asset_id):
        """Open a fully cached table row when its native payload reader is absent.

        This path never supplies edit authority, native ownership, or guessed
        names. Full native-walk shards continue through the strict editor path.
        """
        match = re.fullmatch(r"([0-9a-f]{64}):(0|[1-9][0-9]*)", asset_id)
        if match is None:
            return None
        zone_id, index = match[1], int(match[2])
        snapshot = self.snapshot()
        matches = [relative for relative, entry in snapshot["files"].items()
                   if entry.get("state") == "ready" and entry.get("zone_id") == zone_id]
        if len(matches) > 1:
            raise ValueError("metadata asset identity matches more than one fastfile")
        if not matches:
            return None
        shard = self.inventory(matches[0])
        if shard is None or shard.get("reader_scope") != "xasset-table-only":
            return None
        if self._reader_identity() != self.identity:
            raise RuntimeError("metadata reader changed; use the current backend")
        if index >= len(shard["rows"]):
            raise ValueError("metadata asset index is outside its exact XAsset table")
        row = dict(shard["rows"][index], asset_id=asset_id, zone_id=zone_id,
                   relative_path=matches[0], reader_scope="xasset-table-only",
                   body_sha256=shard["body_sha256"], source_identity=shard["source_identity"],
                   native_reader_error=shard.get("native_reader_error"))
        return dict(row, name=row.get("name") or f"Asset {index}",
                    type=row.get("type_name") or f"type-{row['type_id']}",
                    content=json.dumps(row, ensure_ascii=False, indent=2), language="json",
                    editable=False, archive_writable=False, revision=None,
                    payload_format="Validated XAsset table metadata",
                    package_status=("The complete XAsset table is cached. Its native payload reader "
                                    "is unavailable for this source revision, so payload editing is disabled."))

    def search(self, query, offset=0, limit=100):
        if not isinstance(query, str) or len(query) > 4096 or offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("metadata search requires a text query and a bounded page")
        needle = query.casefold().strip()
        if not self.database.is_file():
            return dict(items=[], total=0, offset=offset, limit=limit)
        connection = self._connect()
        try:
            expected = json.dumps(self.identity, sort_keys=True, separators=(",", ":"))
            identity = connection.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if not identity or identity[0] != expected:
                return dict(items=[], total=0, offset=offset, limit=limit)
            where, parameters = "instr(a.terms,?)>0", [needle]
            if len(needle) >= 3:
                where = "a.id IN (SELECT rowid FROM asset_search WHERE asset_search MATCH ?) AND " + where
                parameters.insert(0, '"' + needle.replace('"', '""') + '"')
            total = connection.execute("SELECT count(*) FROM assets a WHERE " + where, parameters).fetchone()[0]
            items = [json.loads(row[0]) for row in connection.execute(
                "SELECT a.row_json FROM assets a WHERE " + where + " ORDER BY a.path COLLATE NOCASE,a.asset_index LIMIT ? OFFSET ?",
                [*parameters, limit, offset])]
            return dict(items=items, total=total, offset=offset, limit=limit)
        finally:
            connection.close()

    def _index_one(self, relative):
        source = self._source(relative)
        if not _confined_file(source, self.archives.game_root):
            raise ValueError("metadata source is not a confined regular file")
        before = _fingerprint(source)
        with self._lock:
            self._files[relative] = dict(state="indexing", source_fingerprint=before)
            self._active = relative
        self._persist()
        self.root.mkdir(parents=True, exist_ok=True)
        # This worker owns only these temporary directories. Existing payload
        # caches, pending drafts, game files, and failed edit evidence stay intact.
        with tempfile.TemporaryDirectory(prefix="ami-") as temporary:
            workspace = fastfiles.FastfileWorkspace(
                self.archives.root, Path(temporary) / "payloads", self.archives.game_root,
                acts_path=self.archives.acts_path, replay_executable=self.archives.replay_executable,
                lua_acts_path=self.archives.lua_acts_path)
            snapshot = None
            for candidate in sorted((self.archives.cache_root / source.stem).glob("*/decode-receipt.json")):
                try:
                    cached = json.loads(candidate.read_text(encoding="utf-8"))
                    if Path(cached.get("source", {}).get("path", "")).resolve() != source.resolve():
                        continue
                    snapshot = self.archives._validated_asset_snapshot(cached["cache_key"], require_trace=True)
                    break
                except (OSError, ValueError, RuntimeError, KeyError):
                    continue
            table_snapshot = None
            if snapshot is None:
                try:
                    receipt = workspace.extract(relative)
                    snapshot = workspace._validated_asset_snapshot(receipt["zone_id"], require_trace=True)
                except Exception as native_error:
                    logs = {}
                    for log in Path(temporary).rglob("*.log"):
                        with log.open("rb") as stream:
                            stream.seek(max(0, log.stat().st_size - 65536))
                            logs[log.relative_to(temporary).as_posix()] = stream.read().decode("utf-8", errors="replace")
                    key = hashlib.sha256(relative.encode("utf-8")).hexdigest()
                    _atomic_json(self.root / "errors" / f"{key}.json", dict(relative_path=relative,
                        reader_identity=self.identity, source_fingerprint=before,
                        native_reader_error=f"{type(native_error).__name__}: {native_error}", logs=logs))
                    try:
                        table_snapshot = table_decode.decode_table_only_metadata(workspace, relative,
                            native_reader_error=f"{type(native_error).__name__}: {native_error}",
                            decode_cache_root=workspace.cache_root)
                    except Exception as decode_error:
                        raise RuntimeError(f"{native_error}; table metadata decode: {decode_error}") from decode_error
            if table_snapshot is not None:
                shard = dict(table_snapshot, schema=1, relative_path=relative,
                             reader_identity=self.identity, complete=True)
                zone_id, rows = shard["zone_id"], shard["rows"]
            else:
                zone_id = snapshot.zone_id
                rows = [dict(index=header.index, type_id=header.type_id,
                             type_name=native.get("type"), name=native.get("name"),
                             pointer_token=f"0x{header.pointer_token:016x}",
                             reference_only=native.get("status") == "reference", status=native.get("status"))
                        for header, native in zip(snapshot.body.assets, snapshot.native_rows, strict=True)]
                shard = dict(schema=1, relative_path=relative, zone_id=zone_id,
                             source_identity=snapshot.source_profile, reader_identity=self.identity,
                             body_sha256=snapshot.body.source_sha256,
                             native_walk_key=snapshot.native_walk["walk_key"],
                             reader_scope="native-walk", complete=True, rows=rows)
            if self._reader_identity() != self.identity:
                raise MetadataReaderDriftError("metadata reader changed during indexing")
            if _fingerprint(source) != before:
                raise RuntimeError("metadata source changed during indexing")
            key = hashlib.sha256(relative.encode("utf-8")).hexdigest()
            path = self.root / "zones" / f"{key}.json"
            _atomic_json(path, shard)
            digest = fastfiles.sha256_file(path)
            self._update_database(relative, shard, digest)
            with self._lock:
                self._files[relative] = dict(state="ready", source_fingerprint=before,
                    shard_relative_path=path.relative_to(self.root).as_posix(), shard_sha256=digest,
                    zone_id=zone_id, asset_count=len(rows), reader_scope=shard["reader_scope"])
                self._generation += 1
            self._persist()

    def _run_batch(self, max_files=None, retry=False):
        """Index a bounded batch (or every pending FF) and retain failure details."""
        with self._run_lock:
            if self._force_reader_identity() != self.identity:
                raise RuntimeError("metadata reader changed; use the current backend")
            self._scan()
            with closing(self._connect(True)) as connection:
                db_rows = dict(connection.execute("SELECT path,shard_sha256 FROM zones"))
            with self._lock:
                candidates = sorted(self._files, key=lambda name: (
                    name not in ("code_post_gfx.ff", "common.ff", "mp_frontend3.ff", "ui.ff"), name.casefold()))
            completed = 0
            for relative in candidates:
                if self._stop.is_set() or (max_files is not None and completed >= max_files):
                    break
                try:
                    with self._lock:
                        entry = copy.deepcopy(self._files[relative])
                    if entry["state"] == "ready":
                        shard = self.inventory(relative)
                        if shard is not None:
                            if db_rows.get(relative) != entry.get("shard_sha256"):
                                self._update_database(relative, shard, entry["shard_sha256"])
                            continue
                    if entry["state"] == "unavailable" and not retry:
                        continue
                    self._index_one(relative)
                except MetadataReaderDriftError:
                    with self._lock:
                        if self._files.get(relative, {}).get("state") == "indexing":
                            self._files[relative]["state"] = "pending"
                        self._active = None
                    self._persist()
                    raise
                except Exception as error:
                    with self._lock:
                        self._files[relative] = dict(state="unavailable", source_fingerprint=_fingerprint(self._source(relative)),
                                                    error=f"{type(error).__name__}: {error}",
                                                    diagnostic_relative_path="errors/" + hashlib.sha256(relative.encode("utf-8")).hexdigest() + ".json")
                        self._generation += 1
                    self._update_database(relative, None, None)
                    self._persist()
                finally:
                    with self._lock:
                        self._active = None
                completed += 1
            self._persist()
            if self._force_reader_identity() != self.identity:
                raise RuntimeError("metadata reader changed during indexing; use the current backend")
            return self.snapshot()

    def _worker(self):
        while not self._stop.is_set():
            try:
                self.run_once()
                with self._lock:
                    self._error = None
            except Exception as error:
                with self._lock:
                    self._error = f"{type(error).__name__}: {error}"
            self._wake.wait(300)
            self._wake.clear()


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--acts", type=Path, required=True)
    parser.add_argument("--max-files", type=int)
    parser.add_argument("--retry", action="store_true")
    arguments = parser.parse_args()
    workspace = fastfiles.FastfileWorkspace(arguments.root, arguments.cache / "fastfiles",
        arguments.game / "zone", arguments.acts, arguments.game / "game_dx12_ship_replay.exe")
    index = AssetMetadataIndex(workspace)
    result = index.run_once(arguments.max_files, arguments.retry)
    print(json.dumps({key: value for key, value in result.items() if key not in ("files", "identity")}, indent=2))


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
