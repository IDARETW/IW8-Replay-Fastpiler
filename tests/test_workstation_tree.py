import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from threading import RLock
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from workstation.tree import WorkspaceTree, _decode_node, _node_id


class FakeSources:
    def __init__(self):
        self.full_list_calls = 0
        self.rows = [
            dict(id="fn-db-one", name="DB_LoadOne", kind="function", rva=0x100,
                 variants=["assembly", "cpp", "pseudocode"], has_cpp=True),
            dict(id="fn-db-two", name="DB_LoadTwo", kind="function", rva=0x200,
                 variants=["assembly", "cpp", "pseudocode"], has_cpp=False),
            dict(id="user-new", name="UserOverlay", kind="user-function", rva=None,
                 variants=["cpp"], has_cpp=True),
        ]

    def list_sources(self, query="", offset=0, limit=100, kind=None):
        rows = [row for row in self.rows if kind in (None, "all") or
                (kind in ("function", "functions") and row["kind"] in ("function", "user-function")) or
                (kind in ("symbol", "symbols") and row["kind"] != "function")]
        if query:
            rows = [row for row in rows if query.casefold() in row["name"].casefold()]
        return rows[offset:offset + limit], len(rows)

    def list_source_rows(self, query="", kind=None):
        self.full_list_calls += 1
        rows, total = self.list_sources(query, 0, max(1, len(self.rows)), kind)
        return rows, total


class FakeGlobals:
    def list_editable(self):
        return [dict(id="global-1", name="g_frontend", type_name="_QWORD")]


class FakeProject:
    def __init__(self, root):
        self.root = root

    def authored_files(self):
        return [dict(path="src/db/a.cpp", name="a.cpp", bytes=8, language="cpp"),
                dict(path="src/db/include/a.h", name="a.h", bytes=4, language="cpp"),
                dict(path="source-workstation/units.s", name="units.s", bytes=12,
                     language="assembly")]


class FakeArchives:
    def __init__(self, root):
        self.game_root = root / "game"
        self.cache_root = root / "cache"
        self.game_root.mkdir()
        self.cache_root.mkdir()
        self.snapshot = None
        self.extraction_calls = 0

    def _zone_path(self, relative):
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or "\\" in str(relative):
            raise ValueError("bad zone path")
        resolved = (self.game_root / candidate).resolve(strict=True)
        if not resolved.is_relative_to(self.game_root.resolve()) or resolved.suffix.casefold() != ".ff":
            raise ValueError("bad zone path")
        return resolved

    def _validated_asset_snapshot(self, zone_id, *, require_trace=False, validate_source=True):
        assert zone_id == "a" * 64
        return self.snapshot

    def extract(self, _path):
        self.extraction_calls += 1
        raise AssertionError("tree expansion must not start an FF decode")


class FakeApp:
    def __init__(self, root):
        self.sources = FakeSources()
        self.project = FakeProject(root)
        self._archives = FakeArchives(root)
        self._globals = FakeGlobals()

    def archives(self):
        return self._archives

    def globals(self):
        return self._globals


class WorkspaceTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = FakeApp(self.root)
        self.tree = WorkspaceTree(self.app)

    def tearDown(self):
        self.temp.cleanup()

    def expand(self, item):
        self.assertTrue(item["expandable"])
        return self.tree.get(item["id"])

    def test_root_and_code_prefix_groups_are_paged_and_navigable(self):
        root = self.tree.get()
        self.assertEqual(root["label"], "IW8")
        self.assertEqual([row["name"] for row in root["items"]], ["Code", "Assets"])
        self.assertEqual(_decode_node(root["items"][0]["id"])["kind"], "code")
        code = self.expand(root["items"][0])
        functions = next(row for row in code["items"] if row["name"] == "Functions")
        before = self.app.sources.full_list_calls
        groups = self.tree.get(functions["id"], offset=0, limit=1)
        self.assertEqual(self.app.sources.full_list_calls - before, 1)
        self.assertEqual(groups["total"], 2)
        self.assertEqual(groups["limit"], 1)
        second_page = self.tree.get(functions["id"], offset=1, limit=1)
        self.assertEqual(second_page["total"], 2)
        self.assertEqual(len(second_page["items"]), 1)
        groups = self.expand(functions)
        db = next(row for row in groups["items"] if row["name"] == "DB_")
        self.assertEqual(db["source_count"], 2)
        members = self.expand(db)
        self.assertEqual({row["source_id"] for row in members["items"]}, {"fn-db-one", "fn-db-two"})
        self.assertEqual(members["items"][0]["target"]["variant"], "cpp")
        self.assertEqual(members["breadcrumbs"][-1]["id"], db["id"])
        self.tree.get(members["breadcrumbs"][-1]["id"])

    def test_user_authored_function_opens_cpp_variant(self):
        functions = self.tree.get(_node_id({"kind": "code-group", "group": "functions"}))
        other = next(row for row in functions["items"] if row["name"] == "Other")
        members = self.expand(other)
        user = next(row for row in members["items"] if row["source_id"] == "user-new")
        self.assertEqual(user["target"], {"id": "user-new", "variant": "cpp"})

    def test_search_merges_cached_function_duplicates_before_paging(self):
        first = dict(self.app.sources.rows[0], aliases=["load_alias"])
        second = dict(first, id="fn-distinct", rva=0x300)
        symbol = dict(first, id="sym-distinct", kind="data-address", rva=0x400)
        # Simulate a persisted symbol family containing the same function IDs.
        self.tree.catalog = SimpleNamespace(
            status=lambda: {},
            family=lambda name: ({"functions": [first, second],
                                  "symbols": [first, second, symbol],
                                  "globals": [], "authored": [],
                                  "asset_directories": {}}[name], "ready"))
        for query in ("DB_LoadOne", "load_alias"):
            results = self.tree.search(query)
            self.assertEqual(results["total"], 3)
            self.assertEqual({row["source_id"] for row in results["items"]},
                             {"fn-db-one", "fn-distinct", "sym-distinct"})
            pages = [self.tree.search(query, offset=offset, limit=1)
                     for offset in range(3)]
            self.assertTrue(all(page["total"] == 3 for page in pages))
            self.assertEqual([page["items"][0]["id"] for page in pages],
                             [row["id"] for row in results["items"]])
            self.assertEqual(self.tree.search(query, offset=3, limit=1)["items"], [])

    def test_authored_files_keep_real_folder_structure_and_source_targets(self):
        authored = self.tree.get(_node_id({"kind": "authored"}))
        self.assertEqual({row["name"] for row in authored["items"]}, {"src", "source-workstation"})
        src = next(row for row in authored["items"] if row["name"] == "src")
        db = self.expand(src)
        db_folder = next(row for row in db["items"] if row["name"] == "db")
        db_items = self.expand(db_folder)
        a = next(row for row in db_items["items"] if row["name"] == "a.cpp")
        self.assertEqual(a["target"], {"path": "src/db/a.cpp"})
        include = next(row for row in db_items["items"] if row["name"] == "include")
        header = self.expand(include)["items"][0]
        self.assertEqual(header["target"]["path"], "src/db/include/a.h")

    def test_zone_directory_and_cached_type_name_tree_do_not_decode(self):
        ff_dir = self.app._archives.game_root / "zone" / "mp"
        ff_dir.mkdir(parents=True)
        ff = ff_dir / "sample.ff"
        ff.write_bytes(b"small fixture")
        zone_id = "a" * 64
        cache_dir = self.app._archives.cache_root / "sample" / zone_id
        cache_dir.mkdir(parents=True)
        (cache_dir / "decode-receipt.json").write_text(json.dumps({
            "status": "decoded-and-validated", "cache_key": zone_id,
            "source": {"path": str(ff.resolve()), "sha256": "body", "patches": []}}))
        self.app._archives.snapshot = SimpleNamespace(
            decode_receipt={"source": {"sha256": "body", "patches": []}},
            source_profile={"sha256": "body", "patches": []},
            cache_path=cache_dir,
            body=SimpleNamespace(assets=[SimpleNamespace(type_id=8) for _ in range(3)] +
                                        [SimpleNamespace(type_id=9)]),
            native_rows=[
                {"type_id": 8, "name": "models/thing", "type": "xmodel"},
                {"type_id": 8, "name": "models/thing", "type": "xmodel", "status": "reference"},
                {"type_id": 8, "name": "models/other", "type": "xmodel"},
                {"type_id": 9, "name": None, "type": None},
            ])
        with mock.patch("workstation_fastfiles._source_header", return_value=SimpleNamespace(xfile_version=0xFF7)):
            assets = self.tree.get(_node_id({"kind": "assets"}))
            zone_dir = next(row for row in assets["items"] if row["name"] == "zone")
            zone_mp = next(row for row in self.expand(zone_dir)["items"] if row["name"] == "mp")
            zone = self.expand(zone_mp)["items"][0]
            self.assertEqual(zone["relative_path"], "zone/mp/sample.ff")
            self.assertEqual(zone["source_status"], "source-header-checked")
            self.assertIsNone(zone["zone_id"])
            self.assertTrue(zone["inventory_cached"])
            type_result = self.expand(zone)
            self.assertEqual(type_result["zone_id"], zone_id)
            xmodel = next(row for row in type_result["items"] if row["type_id"] == 8)
            self.assertEqual(xmodel["count"], 3)
            children = self.expand(xmodel)
            models = next(row for row in children["items"] if row["name"] == "models")
            leaves = self.expand(models)["items"]
            thing = [row for row in leaves if row["name"] == "thing"]
            self.assertEqual(len(thing), 2)
            self.assertNotEqual(thing[0]["asset_id"], thing[1]["asset_id"])
            self.assertTrue(any(row["reference_only"] for row in thing))
            self.assertTrue(all(row["editor_status"] == "native-table-metadata-only" for row in thing))
            self.assertEqual(self.app._archives.extraction_calls, 0)
            self.assertEqual(zone["extract_target"], "zone/mp/sample.ff")
            self.assertTrue(all(crumb["id"] for crumb in children["breadcrumbs"]))

    def test_unextracted_zone_returns_existing_extract_target_without_decode(self):
        path = self.app._archives.game_root / "mp.ff"
        path.write_bytes(b"fixture")
        with mock.patch("workstation_fastfiles._source_header", return_value=SimpleNamespace(xfile_version=0xFF7)):
            item = self.tree._game_children("")[0]
            result = self.tree.get(item["id"])
        self.assertTrue(result["extract_required"])
        self.assertEqual(result["extract_path"], "mp.ff")
        self.assertEqual(result["items"], [])
        self.assertEqual(self.app._archives.extraction_calls, 0)

    def test_asset_directory_indexes_cache_receipts_once_for_many_fastfiles(self):
        cache = self.app._archives.cache_root
        sources = []
        for index in range(5):
            ff = self.app._archives.game_root / f"zone_{index}.ff"
            ff.write_bytes(b"fixture")
            sources.append(ff)
        for index, source in enumerate(sources[:2]):
            key = f"{index + 1:064x}"
            receipt_dir = cache / source.stem / key
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "decode-receipt.json").write_text(json.dumps({
                "status": "decoded-and-validated", "cache_key": key,
                "source": {"path": str(source.resolve())}}), encoding="utf-8")

        receipt_reads = []
        original_read_text = Path.read_text

        def counting_read_text(path, *args, **kwargs):
            if path.name == "decode-receipt.json":
                receipt_reads.append(path)
            return original_read_text(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", counting_read_text), \
                mock.patch("workstation_fastfiles._source_header",
                           return_value=SimpleNamespace(xfile_version=0xFF7)):
            items = self.tree._game_children("")
        self.assertEqual(len(items), 5)
        self.assertEqual(len(receipt_reads), 2)
        cached = [item for item in items if item["inventory_cached"]]
        self.assertEqual({item["relative_path"] for item in cached},
                         {"zone_0.ff", "zone_1.ff"})
        self.assertEqual(self.app._archives.extraction_calls, 0)

    def test_tree_rejects_noncanonical_or_traversal_ids_and_paths(self):
        for path in ("../outside.ff", "zone//mp.ff", "C:/outside.ff", "zone/./mp.ff"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.tree.get(_node_id({"kind": "zone", "relative_path": path}))
        with self.assertRaises(ValueError):
            _decode_node("n_eyJ2IjoxLCJraW5kIjoicm9vdCJ9.")
        with self.assertRaises(ValueError):
            self.tree.get(_node_id({"kind": "asset-type", "relative_path": "zone/a.ff",
                                    "zone_id": "a" * 64, "type_id": True,
                                    "type_name": "forged"}))
        self.assertEqual(self.app._archives.extraction_calls, 0)

    def test_http_route_returns_tree_contract_without_starting_extraction(self):
        from workstation.server import Handler

        route_app = SimpleNamespace(credentials=None, project=SimpleNamespace(mutation_lock=RLock()),
            fastfile_lock=RLock(), workspace_tree=lambda: self.tree)
        handler = object.__new__(Handler)
        handler.path = "/api/workspace/tree?limit=10"
        handler.headers = {}
        handler.client_address = ("127.0.0.1", 1000)
        handler.server = SimpleNamespace(app=route_app)
        handler.send_json = mock.Mock()
        Handler.do_GET(handler)
        payload = handler.send_json.call_args.args[0]
        self.assertEqual(payload["label"], "IW8")
        self.assertEqual(payload["total"], 2)

    def test_http_tree_lock_scope_follows_validated_node_family(self):
        from workstation.server import Handler

        fastfile_lock = RLock()
        app = SimpleNamespace(credentials=None,
            project=SimpleNamespace(mutation_lock=RLock()), fastfile_lock=fastfile_lock,
            workspace_tree=lambda: self.tree)
        ff_lock_acquired = threading.Event()
        fastfile_lock.acquire()
        ff_lock_acquired.set()

        def request(node_id):
            done = threading.Event()
            handler = object.__new__(Handler)
            handler.path = "/api/workspace/tree?node=" + quote(node_id, safe="")
            handler.headers = {}
            handler.client_address = ("127.0.0.1", 1000)
            handler.server = SimpleNamespace(app=app)
            handler.send_json = lambda _payload: done.set()
            thread = threading.Thread(target=Handler.do_GET, args=(handler,), daemon=True)
            thread.start()
            return done, thread

        try:
            for kind in ("root", "code"):
                done, thread = request(_node_id({"kind": kind}) if kind != "root" else "root")
                self.assertTrue(done.wait(1), f"{kind} node waited for fastfile lock")
                thread.join(1)

            done, thread = request(_node_id({"kind": "assets"}))
            time.sleep(0.05)
            self.assertFalse(done.is_set(), "asset node bypassed fastfile lock")
        finally:
            fastfile_lock.release()
        self.assertTrue(done.wait(1), "asset node did not resume after fastfile lock release")
        thread.join(1)

    def test_unsupported_native_asset_opens_as_read_only_only_for_exact_row(self):
        from workstation.server import Handler
        from workstation_fastfiles import UnsupportedAssetGraphError

        class Archives:
            row = dict(asset_id="b" * 64 + ":4", index=4, type_id=35,
                       name="sound/voice/test", native_type_name="soundcurve")

            def get_asset(self, _identity):
                raise UnsupportedAssetGraphError("no typed payload reader")

            def list_assets(self, _zone, offset=0, limit=100):
                return {"items": [self.row] if offset == 4 else [], "total": 1}

        class App:
            credentials = None
            fastfile_lock = RLock()

            def __init__(self):
                self._archives = Archives()

            def archives(self):
                return self._archives

        app = App()
        app._archives.cache_root = self.root / "asset-cache"
        receipt = app._archives.cache_root / "test" / ("b" * 64) / "decode-receipt.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("{}")

        def request(identity):
            handler = object.__new__(Handler)
            handler.path = "/api/asset?id=" + quote(identity, safe="")
            handler.headers = {}
            handler.client_address = ("127.0.0.1", 1000)
            handler.server = SimpleNamespace(app=app)
            handler.send_json = mock.Mock()
            Handler.do_GET(handler)
            return handler.send_json.call_args

        good = request("b" * 64 + ":4")
        payload, = good.args
        self.assertEqual(payload["asset_id"], "b" * 64 + ":4")
        self.assertFalse(payload["editable"])
        self.assertIsNone(payload["content"])
        self.assertEqual(payload["payload_format"], "Native XAsset table identity only")

        app._archives.row = dict(app._archives.row, asset_id="b" * 64 + ":5", index=5)
        wrong = request("b" * 64 + ":4")
        self.assertEqual(wrong.args[1], 400)

    def test_http_native_cache_missing_does_not_hide_ambiguity_or_validation_failure(self):
        from workstation.server import Handler

        cache = self.root / "asset-http-cache"
        cache.mkdir()
        archives = SimpleNamespace(cache_root=cache, get_asset=mock.Mock(side_effect=ValueError("native payload validation failed")))
        app = SimpleNamespace(credentials=None, fastfile_lock=RLock(), archives=lambda: archives)
        identity = "b" * 64 + ":4"

        def request():
            handler = object.__new__(Handler)
            handler.path = "/api/asset?id=" + quote(identity, safe="")
            handler.headers = {}
            handler.client_address = ("127.0.0.1", 1000)
            handler.server = SimpleNamespace(app=app)
            handler.send_json = mock.Mock()
            Handler.do_GET(handler)
            return handler.send_json.call_args.args

        missing, status = request()
        self.assertEqual(status, 400)
        self.assertEqual(missing["code"], "asset_payload_cache_missing")
        self.assertEqual(missing["asset_id"], identity)
        archives.get_asset.assert_not_called()

        receipt = cache / "first" / ("b" * 64) / "decode-receipt.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("{}")
        invalid, status = request()
        self.assertEqual(status, 400)
        self.assertNotIn("code", invalid)
        self.assertIn("native payload validation failed", invalid["error"])
        archives.get_asset.assert_called_once_with(identity)

        duplicate = cache / "second" / ("b" * 64) / "decode-receipt.json"
        duplicate.parent.mkdir(parents=True)
        duplicate.write_text("{}")
        ambiguous, status = request()
        self.assertEqual(status, 400)
        self.assertEqual(ambiguous["code"], "asset_payload_cache_ambiguous")
        self.assertEqual(archives.get_asset.call_count, 1)

    def test_table_only_metadata_opens_without_acquiring_payload_or_edit_authority(self):
        from workstation.server import Handler

        identity = "b" * 64 + ":4"
        metadata_row = dict(asset_id=identity, zone_id="b" * 64, index=4, type_id=255,
            name="Asset 4", type="type-255", content="{}", language="json",
            reader_scope="xasset-table-only", editable=False, archive_writable=False)
        archives = SimpleNamespace(cache_root=self.root / "absent-payload-cache", get_asset=mock.Mock())
        index = SimpleNamespace(read_only_asset=mock.Mock(return_value=metadata_row))
        app = SimpleNamespace(credentials=None, fastfile_lock=RLock(), archives=lambda: archives,
                              asset_metadata=index)
        handler = object.__new__(Handler)
        handler.path = "/api/asset?id=" + quote(identity, safe="")
        handler.headers = {}
        handler.client_address = ("127.0.0.1", 1000)
        handler.server = SimpleNamespace(app=app)
        handler.send_json = mock.Mock()
        Handler.do_GET(handler)
        self.assertEqual(handler.send_json.call_args.args, (metadata_row,))
        archives.get_asset.assert_not_called()
        index.read_only_asset.assert_called_once_with(identity)


if __name__ == "__main__":
    unittest.main()
