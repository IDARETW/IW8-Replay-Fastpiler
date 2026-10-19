import json
import hashlib
import tempfile
import threading
import time
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from types import SimpleNamespace
from unittest.mock import patch

from workstation.tree import WorkspaceTree, _node_id


class CatalogApp:
    def __init__(self, root):
        self.project = SimpleNamespace(root=root, cache=root / "machine-cache",
            game=root / "game", sqlite=root / "game" / "replay.sqlite",
            mutation_lock=threading.RLock(), authored_files=lambda: [
                {"path": "src/main.cpp", "name": "main.cpp", "bytes": 4, "language": "cpp"}])
        self.project.cache.mkdir()
        self.project.game.mkdir()
        (self.project.game / "mp.ff").write_bytes(b"not a Replay fastfile")
        self.sources = SimpleNamespace(
            list_source_rows=lambda _query, kind: (
                ([{"id": "fn-a", "name": "DB_Load", "kind": "function"}]
                 if kind == "function" else
                 [{"id": "sym-a", "name": "UnknownSymbol", "kind": "symbol"}]), 1),
            _state=lambda: {"sources": {}})
        self._archives = SimpleNamespace(game_root=self.project.game,
            cache_root=self.project.cache / "fastfiles")
        self._archives.cache_root.mkdir()
        self.fastfile_lock = threading.RLock()
        self.backend = SimpleNamespace(files={})
        self.global_sources = None

    def globals(self):
        raise RuntimeError("global inventory fixture intentionally unavailable")

    def archives(self):
        return self._archives


class FakeAssetMetadataIndex:
    def __init__(self, rows, *, complete=False):
        self.rows = rows
        self.complete = complete
        self.files = {row["relative_path"]: {"state": "ready"} for row in rows}

    def snapshot(self):
        return {"state": "ready" if self.complete else "building", "complete": self.complete,
            "files": self.files, "generation": 4,
            "counts": {"indexed_fastfiles": len(self.files), "total_fastfiles": 9441,
                       "unavailable_fastfiles": 0, "native_asset_rows": len(self.rows)}}

    def search(self, query, *, offset=0, limit=100):
        needle = query.casefold()
        rows = [row for row in self.rows if needle in " ".join(str(row.get(key, "")) for key in
            ("name", "type_name", "relative_path", "type_id", "index")).casefold()]
        rows.sort(key=lambda row: (row.get("name", "").casefold(), row["relative_path"], row["index"]))
        return {"items": rows[offset:offset + limit], "total": len(rows),
                "offset": offset, "limit": limit}

    def inventory(self, relative):
        row = next((item for item in self.rows if item["relative_path"] == relative), None)
        if row is None:
            return None
        return {"complete": True, "zone_id": row["zone_id"], "rows": [
            {"index": row["index"], "type_id": row["type_id"], "name": row["name"],
             "type_name": row["type_name"], "reference_only": row["reference_only"]}]}


class WorkspaceTreeCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = CatalogApp(self.root)
        self.tree = WorkspaceTree(self.app)

    def tearDown(self):
        if self.tree.catalog is not None:
            self.tree.catalog.close()
        self.temp.cleanup()

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("catalog family did not publish before timeout")

    def test_background_catalog_publishes_independent_families_and_persists_display_rows(self):
        catalog = self.tree.catalog
        self.wait_for(lambda: catalog.status()["family_states"].get("inventories") == "ready")
        functions, function_state = catalog.family("functions")
        symbols, symbol_state = catalog.family("symbols")
        authored, authored_state = catalog.family("authored")
        self.assertEqual(function_state, "ready")
        self.assertEqual(symbol_state, "ready")
        self.assertEqual(authored_state, "ready")
        self.assertEqual(functions[0]["id"], "fn-a")
        self.assertEqual(symbols[0]["name"], "UnknownSymbol")
        self.assertEqual(authored[0]["path"], "src/main.cpp")
        self.assertEqual(catalog.status()["family_states"]["globals"], "unavailable")

        status = catalog.status()
        self.assertEqual(status["validation_scope"], "display-only-metadata")
        self.assertEqual(status["family_counts"]["fastfiles"], 1)
        self.assertEqual(status["family_counts"]["decoded_zones"], 0)
        catalog._persist()
        with catalog._persist_lock:
            stored = json.loads((self.root / "machine-cache" / "workspace-tree" / "catalog.json").read_text())
        self.assertEqual(stored["schema"], 2)
        self.assertEqual(stored["families"]["symbols"][0]["id"], "sym-a")

    def test_function_groups_and_zone_basics_come_from_catalog(self):
        catalog = self.tree.catalog
        self.wait_for(lambda: catalog.status()["family_states"].get("inventories") == "ready")
        functions = self.tree.get(_node_id({"kind": "code-group", "group": "functions"}))
        self.assertEqual([(row["name"], row["source_count"]) for row in functions["items"]],
                         [("DB_", 1)])
        members = self.tree.get(functions["items"][0]["id"])
        self.assertEqual(members["items"][0]["target"], {"id": "fn-a", "variant": "cpp"})
        assets = self.tree.get(_node_id({"kind": "assets"}))
        zone = next(item for item in assets["items"] if item["kind"] == "zone")
        self.assertEqual(zone["relative_path"], "mp.ff")
        self.assertEqual(zone["source_status"], "unsupported-or-invalid")
        self.assertEqual(zone["inventory_validation_scope"], "display-only-metadata")
        self.assertEqual(zone["inventory_state"], "uncached")

    def test_real_path_shaped_source_profile_is_canonicalized_before_catalog_persist(self):
        cache_path = self.root / "zone-cache"
        cache_path.mkdir()
        source = {"sha256": "a" * 64, "patches": [{"extension": ".fp", "sha256": "b" * 64}]}
        snapshot = SimpleNamespace(
            decode_receipt={"source": source},
            source_profile={"path": self.root / "game" / "mp.ff", **source},
            native_walk={"walk_key": "walk-key", "manifest_sha256": "c" * 64,
                         "manifest_path": self.root / "manifest.json"},
            native_rows=[], body=SimpleNamespace(assets=[]), cache_path=cache_path)
        self.app._archives._validated_asset_snapshot = lambda *_args, **_kwargs: snapshot

        zone_id, rows, identity = self.tree._zone_inventory(
            "mp.ff", candidates=["zone-a"], include_pending=False, return_identity=True)
        self.assertEqual(zone_id, "zone-a")
        self.assertEqual(rows, [])
        self.assertNotIn("path", identity["current_source_profile"])
        self.assertEqual(identity["current_source_profile"]["sha256"], "a" * 64)
        self.assertEqual(identity["native_walk"], {"walk_key": "walk-key", "manifest_sha256": "c" * 64})
        with self.tree.catalog._lock:
            self.tree.catalog._families["inventories"]["mp.ff"] = {
                "relative_path": "mp.ff", "zone_id": zone_id, "rows": rows,
                "state": "ready", "strong_identity": identity}
        self.tree.catalog._persist()
        with self.tree.catalog._persist_lock:
            persisted = (self.root / "machine-cache" / "workspace-tree" / "catalog.json").read_text()
        self.assertNotIn("\\n  ", persisted)
        self.assertEqual(json.loads(persisted)["families"]["inventories"]["mp.ff"][
            "strong_identity"]["decode_source"]["sha256"], "a" * 64)

    def test_large_function_group_transforms_only_the_requested_page(self):
        self.tree.catalog.close()
        rows = [{"id": f"fn-{index}", "name": f"OtherFunction{index}", "kind": "function"}
                for index in range(12_000)]
        with self.tree.catalog._lock:
            self.tree.catalog._families["functions"] = rows
            self.tree.catalog._families["function_prefix_indexes"] = {"Other": list(range(len(rows)))}
            self.tree.catalog._states["functions"] = "ready"
            self.tree.catalog._states["function_prefix_indexes"] = "ready"
        calls = []
        original = WorkspaceTree._source

        def counted(row, variant):
            calls.append(row["id"])
            return original(row, variant)

        with patch.object(WorkspaceTree, "_source", staticmethod(counted)):
            page = self.tree.get(_node_id({"kind": "code-prefix", "prefix": "Other"}),
                                 offset=8000, limit=5)
        self.assertEqual(page["total"], 12_000)
        self.assertEqual(len(page["items"]), 5)
        self.assertEqual(len(calls), 5)

    def test_warm_matching_catalog_reuses_snapshot_without_rebuilding_source_families(self):
        warm_root = self.root / "warm"
        warm_root.mkdir()
        app = CatalogApp(warm_root)
        generated = warm_root / "generated"
        generated.mkdir()
        (generated / "function-catalog.json").write_text("{}", encoding="utf-8")
        (generated / "manifest.json").write_text("{}", encoding="utf-8")

        def initialize_globals():
            app.global_sources = SimpleNamespace(generated=generated)
            return SimpleNamespace(list_editable=lambda: [{"id": "global-a", "name": "g_test"}])

        app.globals = initialize_globals
        source_calls = []
        original_list = app.sources.list_source_rows

        def counted_list(query, kind):
            source_calls.append(kind)
            return original_list(query, kind)

        app.sources.list_source_rows = counted_list
        first_tree = WorkspaceTree(app)
        first_catalog = first_tree.catalog
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and first_catalog.status()["state"] != "ready":
            time.sleep(0.01)
        self.assertEqual(first_catalog.status()["state"], "ready")
        first_catalog.close()
        calls_before_warm = len(source_calls)
        # A fresh Application starts with its lazy GlobalSourceWorkspace unset.
        app.global_sources = None

        warm_tree = WorkspaceTree(app)
        warm_catalog = warm_tree.catalog
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and warm_catalog.status()["state"] != "ready":
                time.sleep(0.01)
            self.assertEqual(warm_catalog.status()["state"], "ready")
            self.assertEqual(len(source_calls), calls_before_warm)
            self.assertEqual(warm_catalog.family("functions")[0][0]["id"], "fn-a")
        finally:
            warm_catalog.close()

    def test_assets_pagination_materializes_only_requested_zone_nodes(self):
        self.tree.catalog.close()
        rows = [{"kind": "zone", "relative_path": f"zone-{index:05}.ff",
                 "bytes": 1, "status": "source-header-checked",
                 "candidate_zone_ids": []} for index in range(1000)]
        with self.tree.catalog._lock:
            self.tree.catalog._families["asset_directories"] = {"": rows}
            self.tree.catalog._states["asset_directories"] = "ready"
        calls = []
        original = WorkspaceTree._zone

        def counted(tree, row, *, candidates=None):
            calls.append(row["relative_path"])
            return original(tree, row, candidates=candidates)

        with patch.object(WorkspaceTree, "_zone", counted):
            page = self.tree.get(_node_id({"kind": "assets"}), limit=5)
        self.assertEqual(page["total"], 1000)
        self.assertEqual(len(page["items"]), 5)
        self.assertEqual(len(calls), 5)

    def test_cached_source_queries_match_aliases_without_renaming_or_regrouping(self):
        self.tree.catalog.close()
        row = {"id": "fn_5cce4fe86395c00e", "name": "Unnamed function fn_5cce4fe86395c00e",
               "kind": "function", "aliases": ["Sys_CheckCrashOrRerun", "sub_1413FF110"]}
        with self.tree.catalog._lock:
            self.tree.catalog._families["functions"] = [row]
            self.tree.catalog._families["function_prefix_indexes"] = {"Other": [0]}
            self.tree.catalog._families["symbols"] = [dict(row, kind="symbol")]
            for family in ("functions", "function_prefix_indexes", "symbols"):
                self.tree.catalog._states[family] = "ready"

        symbols = self.tree.get(_node_id({"kind": "code-group", "group": "symbols"}),
                                query="Sys_CheckCrashOrRerun")
        self.assertEqual(symbols["total"], 1)
        self.assertEqual(symbols["items"][0]["name"], "Unnamed function fn_5cce4fe86395c00e")
        self.assertEqual(symbols["items"][0]["aliases"], ["Sys_CheckCrashOrRerun", "sub_1413FF110"])

        functions = self.tree.get(_node_id({"kind": "code-prefix", "prefix": "Other"}),
                                  query="Sys_CheckCrashOrRerun")
        self.assertEqual(functions["total"], 1)
        self.assertEqual(functions["items"][0]["name"], "Unnamed function fn_5cce4fe86395c00e")
        self.assertEqual(functions["items"][0]["source_id"], "fn_5cce4fe86395c00e")

    def test_workspace_search_merges_areas_and_keeps_metadata_asset_target(self):
        self.tree.catalog.close()
        function = {"id": "fn-safe", "name": "safe_function", "kind": "function",
                    "aliases": ["needle"]}
        global_row = {"id": "global-safe", "name": "needle_global", "kind": "global",
                      "type_name": "unsigned int"}
        asset = {"relative_path": "mp.ff", "zone_id": "a" * 64, "index": 3,
                 "type_id": 14, "type_name": "material", "name": "needle_asset",
                 "pointer_token": "0xfffffffffffffffe", "reference_only": False,
                 "status": "native-read-spans-indexed", "metadata_only": True}
        with self.tree.catalog._lock:
            self.tree.catalog._families["functions"] = [function]
            self.tree.catalog._families["symbols"] = []
            self.tree.catalog._families["globals"] = [global_row]
            self.tree.catalog._families["authored"] = [
                {"path": "src/needle.cfg", "name": "needle.cfg", "language": "cfg", "bytes": 18}]
            for family in ("functions", "symbols", "globals", "authored"):
                self.tree.catalog._states[family] = "ready"
            self.tree.catalog._families["asset_directories"] = {"": [
                {"kind": "zone", "relative_path": "needle-empty.ff", "bytes": 4,
                 "status": "source-header-checked", "source_xfile_version": 1,
                 "transient_type": 0}]}
            self.tree.catalog._states["asset_directories"] = "ready"
        self.app.asset_metadata = FakeAssetMetadataIndex([asset], complete=False)

        type_page = self.tree.get(_node_id({"kind": "zone", "relative_path": "mp.ff"}))
        leaf_page = self.tree.get(type_page["items"][0]["id"])
        self.assertTrue(leaf_page["items"][0]["metadata_only"])
        self.assertTrue(leaf_page["items"][0]["target"]["metadata_only"])
        self.assertEqual(leaf_page["items"][0]["target"]["relative_path"], "mp.ff")

        code = self.tree.search("needle", offset=0, limit=2)
        self.assertEqual([item["area"] for item in code["items"]], ["Code", "Code"])
        self.assertEqual({item["target"]["id"] for item in code["items"]},
                         {"fn-safe", "global-safe"})
        empty_zone = self.tree.search("needle", offset=2, limit=1)
        self.assertEqual(empty_zone["items"][0]["kind"], "zone")
        self.assertEqual(empty_zone["items"][0]["relative_path"], "needle-empty.ff")
        self.assertTrue(empty_zone["items"][0]["expandable"])
        self.assertEqual(empty_zone["items"][0]["target"],
                         {"relative_path": "needle-empty.ff", "metadata_only": True})
        asset_result = self.tree.search("needle", offset=3, limit=1)
        self.assertEqual(asset_result["items"][0]["area"], "Assets")
        self.assertTrue(asset_result["items"][0]["metadata_only"])
        self.assertTrue(asset_result["items"][0]["target"]["metadata_only"])
        self.assertEqual(asset_result["items"][0]["target"]["asset_id"], "a" * 64 + ":3")
        self.assertEqual(asset_result["items"][0]["node"], _node_id({"kind": "zone", "relative_path": "mp.ff"}))
        self.assertEqual(asset_result["total"], 5)
        self.assertFalse(asset_result["search_status"]["complete"])
        authored = self.tree.search("needle", offset=4, limit=1)
        self.assertEqual(authored["items"][0]["area"], "Authored files")
        self.assertEqual(authored["items"][0]["target"], {"path": "src/needle.cfg"})
        past_end = self.tree.search("needle", offset=5, limit=1)
        self.assertEqual(past_end["items"], [])
        self.assertEqual(past_end["total"], 5)

    def test_missing_native_asset_names_and_types_use_unknown_display(self):
        asset = {"relative_path": "empty-name.ff", "zone_id": "b" * 64, "index": 9,
                 "type_id": 250, "type_name": None, "name": None,
                 "pointer_token": "0xfffffffffffffffe", "reference_only": False,
                 "status": "native-read-spans-indexed", "metadata_only": True}
        self.app.asset_metadata = FakeAssetMetadataIndex([asset], complete=False)
        zone = self.tree.get(_node_id({"kind": "zone", "relative_path": "empty-name.ff"}))
        self.assertEqual(zone["items"][0]["name"], "Unknown")
        leaves = self.tree.get(zone["items"][0]["id"])
        self.assertEqual(leaves["items"][0]["name"], "Unknown")
        self.assertEqual(leaves["items"][0]["type"], "Unknown")
        self.assertTrue(leaves["items"][0]["target"]["metadata_only"])

    def test_workspace_search_includes_shallow_pending_assets_and_marks_removals(self):
        self.tree.catalog.close()
        zone_id = "c" * 64
        stock = {"relative_path": "mp.ff", "zone_id": zone_id, "index": 3,
                 "type_id": 51, "type_name": "rawfile", "name": "needle_stock.cfg",
                 "pointer_token": "0xfffffffffffffffe", "reference_only": False,
                 "status": "native-read-spans-indexed", "metadata_only": True}
        self.app.asset_metadata = FakeAssetMetadataIndex([stock], complete=False)
        self.app.asset_metadata.files = {}
        self.app.asset_metadata.inventory = lambda relative: {
            "complete": True, "zone_id": zone_id, "rows": [
                {"index": 3, "type_id": 51, "name": "needle_stock.cfg", "type_name": "rawfile"}]}
        self.app._archives._zone_path = lambda relative: self.app.project.game / relative
        with self.tree.catalog._lock:
            self.tree.catalog._families["inventories"]["mp.ff"] = {
                "relative_path": "mp.ff", "zone_id": zone_id, "rows": [], "state": "ready",
                "strong_identity": {"zone_id": zone_id}}
        pending = self.app._archives.cache_root / "mp" / zone_id / "pending-edits"
        append_dir, remove_dir, forged_dir = (pending / "op-append", pending / "op-remove",
                                               pending / "op-forged")
        append_dir.mkdir(parents=True); remove_dir.mkdir(parents=True); forged_dir.mkdir(parents=True)
        append_name = "needle_new.cfg"
        append_asset_id = f"{zone_id}:new-{hashlib.sha256(append_name.encode('utf-8')).hexdigest()[:32]}"
        (append_dir / "current.json").write_text(json.dumps({
            "zone_id": zone_id, "operation": "append", "type_id": 51,
            "type": "rawfile", "name": append_name, "asset_id": append_asset_id}),
            encoding="utf-8")
        (remove_dir / "current.json").write_text(json.dumps({
            "zone_id": zone_id, "operation": "remove", "type_id": 51,
            "type": "rawfile", "name": "needle_stock.cfg", "asset_id": f"{zone_id}:3",
            "index": 3}), encoding="utf-8")
        forged_name = "needle_forged.cfg"
        (forged_dir / "current.json").write_text(json.dumps({
            "zone_id": zone_id, "operation": "append", "type_id": 51,
            "type": "rawfile", "name": forged_name,
            "asset_id": f"{zone_id}:new-{'0' * 32}"}), encoding="utf-8")

        first = self.tree.search("needle", offset=0, limit=100)
        assets = [row for row in first["items"] if row.get("kind") == "asset"]
        self.assertEqual(first["total"], 2, first)
        self.assertEqual([row["name"] for row in assets], ["needle_stock.cfg", "needle_new.cfg"])
        self.assertEqual(assets[0]["operation"], "remove")
        self.assertTrue(assets[0]["target"]["metadata_only"])
        self.assertEqual(assets[1]["operation"], "append")
        self.assertIsNone(assets[1]["index"])
        self.assertEqual(assets[1]["target"], {"asset_id": append_asset_id,
            "relative_path": "mp.ff", "zone_id": zone_id, "type_id": 51,
            "index": None, "metadata_only": True})
        tail = self.tree.search("needle", offset=1, limit=1)
        self.assertEqual(tail["items"][0]["asset_id"], append_asset_id)
        self.assertEqual(tail["total"], first["total"])
        path_match = self.tree.search("mp.ff", offset=0, limit=100)
        self.assertIn(append_asset_id, [row.get("asset_id") for row in path_match["items"]])

        # Native types may share names; their typed draft IDs must remain
        # distinct and searchable outside the current folder.
        shared_name = 'needle_shared'
        digest = hashlib.sha256(shared_name.encode('utf-8')).hexdigest()[:32]
        typed_ids = []
        for type_id, kind in ((19, 'image'), (12, 'computeshader'), (17, 'pixelshader')):
            folder = pending / f'op-a-type-{type_id}'
            folder.mkdir()
            identity = f'{zone_id}:new-{type_id}-{digest}'
            typed_ids.append(identity)
            (folder / 'current.json').write_text(json.dumps({
                'zone_id':zone_id, 'operation':'append', 'type_id':type_id,
                'type':kind, 'name':shared_name, 'asset_id':identity}), encoding='utf-8')
        typed_search = self.tree.search('needle_shared', offset=0, limit=100)
        self.assertEqual(typed_search['total'], 3)
        self.assertEqual({row['asset_id'] for row in typed_search['items']}, set(typed_ids))
        self.assertTrue(all(row['target']['metadata_only'] for row in typed_search['items']))


if __name__ == "__main__":
    unittest.main()
