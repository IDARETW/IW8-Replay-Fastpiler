import hashlib
"""Synthetic regressions for persistent workspace-tree catalog edge cases."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    from test_workstation_tree_catalog import CatalogApp
except ModuleNotFoundError:
    from tests.test_workstation_tree_catalog import CatalogApp
from workstation.tree import WorkspaceTree, _node_id

# Production installs the FF helpers beside workstation on its runtime path;
# the synthetic unittest runner needs to expose the source-tree helper module.
_TOOLS = str(Path(__file__).resolve().parents[1] / "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)
import workstation_fastfiles  # noqa: E402,F401


class WorkspaceTreeCatalogInvalidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = CatalogApp(self.root)
        self.trees = []
        self.gates = []
        self.tree = self.make_tree()

    def make_tree(self):
        tree = WorkspaceTree(self.app)
        self.trees.append(tree)
        return tree

    def gate(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        return entered, release

    def tearDown(self):
        for release in self.gates:
            release.set()
        for tree in self.trees:
            if tree.catalog is not None:
                tree.catalog.close()
                tree.catalog._thread.join(timeout=5)
                self.assertFalse(tree.catalog._thread.is_alive(), "catalog worker leaked")
        self.temp.cleanup()

    def wait_for(self, predicate, message="catalog condition not reached"):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(message)

    def warm(self):
        catalog = self.tree.catalog
        self.wait_for(lambda: catalog.status()["family_states"].get("functions") == "ready")
        self.wait_for(lambda: catalog.status()["family_states"].get("symbols") == "ready")
        self.wait_for(lambda: catalog.status()["family_states"].get("authored") == "ready")
        self.wait_for(lambda: catalog.status()["family_states"].get("asset_directories") == "ready")
        self.wait_for(lambda: catalog.status()["family_states"].get("inventories") == "ready")
        return catalog

    def test_persisted_warm_rows_remain_readable_while_refresh_is_blocked(self):
        catalog = self.warm()
        entered, release = self.gate()
        original = self.app.sources.list_source_rows

        def blocked(query, kind):
            if kind == "function":
                entered.set()
                release.wait(5)
            return original(query, kind)

        self.app.sources.list_source_rows = blocked
        catalog.mark_dirty("functions")
        self.assertTrue(entered.wait(3), "worker did not reach blocked source refresh")
        started = time.monotonic()
        try:
            page = self.tree.get(_node_id({"kind": "code-prefix", "prefix": "DB_"}))
        finally:
            release.set()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual([row["name"] for row in page["items"]], ["DB_Load"])
        self.assertEqual(page["catalog_status"]["family_states"]["functions"], "stale")

    def test_malformed_valid_json_is_discarded_then_rebuilt(self):
        catalog = self.warm()
        catalog.close()
        catalog._thread.join(timeout=5)
        self.assertFalse(catalog._thread.is_alive())
        payload = json.loads(catalog.path.read_text(encoding="utf-8"))
        payload["families"]["functions"][0].pop("name")
        catalog.path.write_text(json.dumps(payload), encoding="utf-8")

        entered, release = self.gate()
        original = self.app.sources.list_source_rows

        def blocked(query, kind):
            if kind == "function":
                entered.set()
                release.wait(5)
            return original(query, kind)

        self.app.sources.list_source_rows = blocked
        reloaded = self.make_tree()
        self.assertTrue(entered.wait(3), "reload worker did not start rebuilding")
        rows, _state = reloaded.catalog.family("functions")
        self.assertEqual(rows, [], "malformed persisted function row escaped validation")
        release.set()
        self.wait_for(lambda: reloaded.catalog.family("functions")[1] == "ready")
        self.assertEqual(reloaded.catalog.family("functions")[0][0]["id"], "fn-a")

    def test_mutation_during_blocked_refresh_does_not_publish_old_snapshot_ready(self):
        catalog = self.warm()
        entered_first, release_first = self.gate()
        entered_second, release_second = self.gate()
        calls = 0
        new_rows = [{"id": "fn-new", "name": "DB_Updated", "kind": "function"}]

        def refresh(_query, kind):
            nonlocal calls
            if kind == "function":
                calls += 1
                if calls == 1:
                    entered_first.set()
                    release_first.wait(5)
                    return [{"id": "fn-old-refresh", "name": "DB_Old", "kind": "function"}], 1
                entered_second.set()
                release_second.wait(5)
                return new_rows, len(new_rows)
            return ([{"id": "sym-a", "name": "UnknownSymbol", "kind": "symbol"}], 1)

        self.app.sources.list_source_rows = refresh
        catalog.mark_dirty("functions")
        self.assertTrue(entered_first.wait(3))
        catalog.mark_dirty("functions")
        release_first.set()
        self.assertTrue(entered_second.wait(3), "dirty epoch did not schedule a follow-up build")
        rows, state = catalog.family("functions")
        self.assertEqual(state, "stale")
        self.assertEqual([row["id"] for row in rows], ["fn-a"])
        release_second.set()
        self.wait_for(lambda: catalog.family("functions")[1] == "ready")
        self.assertEqual([row["id"] for row in catalog.family("functions")[0]], ["fn-new"])

    def test_fastfile_and_patch_sidecar_changes_are_detected(self):
        catalog = self.warm()
        catalog.close()
        catalog._thread.join(timeout=5)
        self.assertFalse(catalog._fingerprints_changed())
        zone = self.app.project.game / "mp.ff"
        fp, fc = zone.with_suffix(".fp"), zone.with_suffix(".fc")
        for path in (zone, fp, fc):
            with self.subTest(path=path.suffix):
                original = path.read_bytes() if path.exists() else None
                original_stat = path.stat() if path.exists() else None
                try:
                    path.write_bytes((original or b"synthetic") + b"changed")
                    self.assertTrue(catalog._fingerprints_changed(),
                                    f"{path.suffix} mutation was invisible")
                finally:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_bytes(original)
                        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                self.assertFalse(catalog._fingerprints_changed(),
                                 f"restoring {path.suffix} did not restore fingerprint")

    def test_cached_reads_use_snapshots_without_inventory_or_parser_locks(self):
        catalog = self.warm()
        catalog.close()
        catalog._thread.join(timeout=5)
        game = self.app.project.game
        (game / "mp.ff").write_bytes(b"synthetic-header")
        self.app.archives = lambda: SimpleNamespace(game_root=game, cache_root=self.app._archives.cache_root,
            _zone_path=lambda relative: game / relative)
        directories = {"": [{"kind": "zone", "relative_path": "mp.ff", "bytes": 15,
                             "status": "source-header-checked", "candidate_zone_ids": ["zone-cache"]}]}
        inventories = {"mp.ff": {"relative_path": "mp.ff", "zone_id": "zone-cache", "state": "ready",
            "rows": [{"index": 0, "type_id": 19, "name": "textures/wall", "type_name": "image"}]}}
        catalog._publish("asset_directories", directories)
        catalog._publish("inventories", inventories)
        self.app.sources.list_source_rows = lambda *_args: (_ for _ in ()).throw(
            AssertionError("cached read performed live source inventory"))
        self.tree._zone_inventory = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cached read invoked native inventory validation"))
        self.tree._cached_zone_index = lambda: (_ for _ in ()).throw(
            AssertionError("cached read scanned decode receipts"))

        locks = (self.app.project.mutation_lock, self.app.fastfile_lock)
        held, release = threading.Event(), threading.Event()
        owners = []
        for lock in locks:
            def hold(target=lock):
                with target:
                    held.set()
                    release.wait(5)
            thread = threading.Thread(target=hold, daemon=True)
            thread.start()
            owners.append(thread)
            self.assertTrue(held.wait(2))
            held.clear()
        future_result = []
        errors = []
        done = threading.Event()

        def read_cached():
            try:
                prefix = self.tree.get(_node_id({"kind": "code-prefix", "prefix": "DB_"}))
                symbols = self.tree.get(_node_id({"kind": "code-group", "group": "symbols"}))
                zone = self.tree.get(_node_id({"kind": "zone", "relative_path": "mp.ff"}))
                future_result.append((prefix, symbols, zone))
            except Exception as error:
                errors.append(error)
            finally:
                done.set()

        reader = threading.Thread(target=read_cached, daemon=True)
        reader.start()
        try:
            self.assertTrue(done.wait(1.5), "cached tree read waited for parser/source lock")
            self.assertFalse(errors, errors)
            self.assertEqual(future_result[0][0]["items"][0]["name"], "DB_Load")
            self.assertEqual(future_result[0][1]["items"][0]["name"], "UnknownSymbol")
            self.assertEqual(future_result[0][2]["items"][0]["name"], "image")
        finally:
            release.set()
            reader.join(timeout=3)
            for thread in owners:
                thread.join(timeout=3)
        self.assertTrue(all(not thread.is_alive() for thread in owners))

    def test_pending_append_remove_overlay_is_live_and_never_mutates_cached_rows(self):
        catalog = self.warm()
        catalog.close()
        catalog._thread.join(timeout=5)
        zone_id = "zone-cache"
        base = [{"index": 165, "type_id": 19, "name": "damage_feedback", "type_name": "image"},
                {"index": 166, "type_id": 19, "name": "other_image", "type_name": "image"}]
        catalog._publish("inventories", {"mp.ff": {"relative_path": "mp.ff", "zone_id": zone_id,
            "state": "ready", "rows": base}})
        game = self.app.project.game
        self.app.archives = lambda: SimpleNamespace(game_root=game, cache_root=self.app._archives.cache_root,
            _zone_path=lambda relative: game / relative)
        pending = self.app._archives.cache_root / "mp" / zone_id / "pending-edits"
        append = pending / "op-append" / "current.json"
        remove = pending / "op-remove" / "current.json"
        append.parent.mkdir(parents=True)
        remove.parent.mkdir(parents=True)
        new_id = f"{zone_id}:new-19-{hashlib.sha256(b'new_texture').hexdigest()[:32]}"
        append.write_text(json.dumps({"zone_id": zone_id, "operation": "append", "type_id": 19,
            "type": "image", "name": "new_texture", "asset_id": new_id}), encoding="utf-8")
        remove.write_text(json.dumps({"zone_id": zone_id, "operation": "remove", "type_id": 19,
            "type": "image", "name": "damage_feedback", "asset_id": f"{zone_id}:165", "index": 165}),
            encoding="utf-8")

        first, first_state = self.tree._catalog_inventory("mp.ff")
        second, second_state = self.tree._catalog_inventory("mp.ff")
        self.assertEqual((first_state, second_state), ("ready", "ready"))
        for _zone, rows in (first, second):
            self.assertEqual(sum(row.get("operation") == "append" and row.get("asset_id") == new_id
                                 for row in rows), 1)
            self.assertEqual(next(row for row in rows if row.get("index") == 165).get("operation"), "remove")
        self.assertNotIn("operation", base[0])
        self.assertEqual(len(catalog.entry("inventories", "mp.ff")[0]["rows"]), 2)

        new_id = f"{zone_id}:new-19-{hashlib.sha256(b'renamed_texture').hexdigest()[:32]}"
        append.write_text(json.dumps({"zone_id": zone_id, "operation": "append", "type_id": 19,
            "type": "image", "name": "renamed_texture", "asset_id": new_id}), encoding="utf-8")
        _zone, live_rows = self.tree._catalog_inventory("mp.ff")[0]
        added = [row for row in live_rows if row.get("asset_id") == new_id]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["name"], "renamed_texture")
        self.assertEqual(base[0]["name"], "damage_feedback")


if __name__ == "__main__":
    unittest.main()
