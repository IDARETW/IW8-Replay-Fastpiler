from __future__ import annotations

from pathlib import Path
import sys
import hashlib
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_luafile_crud import (_bind_native_manifest_to_trace, _plan,
                                      _pack_and_walk, create_luafile_asset, operations,
                                      plan_luafile_crud)  # noqa: E402
from workstation_fastfiles import FastfileWorkspace  # noqa: E402
from workstation_asset_codecs import capability_report  # noqa: E402
from roundtrip_replay_fastfile import ordered_asset_identity_sha256  # noqa: E402


class LuaFileCrudPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Authored tiny Lua compiler fixture, with a portable debug source name.
        # These CRUD tests validate chunk structure, not interpreter execution.
        label = b'@portable-crud.lua'
        cls.payload = b'\x1bLJ\x02\x08' + bytes([len(label)]) + label + bytes.fromhex(
            '1500000100000002030100290078004c00020000000068030003000200042a0002'
            '33000000360101003200008044010100277265706c61795f776f726b7374617469'
            '6f6e5f726f756e64747269705f70726f626500010202026c00540032004a007100'
            '5a0057004e0030004b004300520030006100430078006265000203000000')

    def test_removals_are_descending_and_recreation_appends_after_deletions(self):
        rows = [
            {"type_id": 62, "name": "ui/a.lua"},
            {"type_id": 20, "name": "material/a"},
            {"type_id": 62, "name": "ui/b.lua"},
            {"type_id": 62, "name": "ui/c.lua"},
        ]
        plan = _plan(rows, ["ui/a.lua", "ui/c.lua"],
                     [{"name": "ui/a.lua", "payload": self.payload}])
        self.assertEqual([(row["operation"], row["name"]) for row in plan], [
            ("remove", "ui/c.lua"), ("remove", "ui/a.lua"), ("append", "ui/a.lua")])
        self.assertEqual([row["source_index"] for row in plan[:2]], [3, 0])

    def test_rejects_ambiguous_removal_identity_and_existing_append_name(self):
        rows = [{"type_id": 62, "name": "ui/dup.lua"},
                {"type_id": 62, "name": "ui/dup.lua"}]
        with self.assertRaisesRegex(ValueError, "unique source row"):
            _plan(rows, ["ui/dup.lua"], [])
        with self.assertRaisesRegex(ValueError, "already exists"):
            _plan([{ "type_id": 62, "name": "ui/existing.lua" }], [],
                  [{"name": "ui/existing.lua", "payload": self.payload}])

    def test_rejects_invalid_appended_payload_or_path(self):
        with self.assertRaisesRegex(ValueError, "trailing NUL"):
            _plan([], [], [{"name": "ui/a.lua", "payload": b"no"}])
        with self.assertRaisesRegex(ValueError, "safe native path"):
            _plan([], [], [{"name": "../a.lua", "payload": self.payload}])

    def test_native_manifest_binding_preserves_raw_act_manifest_and_pins_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "stream-trace.jsonl"
            manifest = root / "manifest.json"
            bound = root / "manifest.transaction-bound.json"
            trace.write_bytes(b'{"sequence":0}\n')
            raw = {
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True, "tested": 1,
                "top_level_index": 1, "failed": 0, "unavailable": 0,
                "serialized_bytes_read": 123, "stream_trace": trace.name,
                "journal": "assets.jsonl",
            }
            manifest.write_text(json.dumps(raw), encoding="utf-8")
            original_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            binding = _bind_native_manifest_to_trace(manifest, trace, 123, bound)
            bound_json = json.loads(bound.read_text(encoding="utf-8"))
            self.assertEqual(bound_json["stream_trace_sha256"],
                             hashlib.sha256(trace.read_bytes()).hexdigest())
            self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), original_sha)
            self.assertEqual(binding["raw_manifest_sha256"], original_sha)
            self.assertEqual(binding["body_bytes"], 123)

    def test_native_manifest_binding_rejects_stale_embedded_trace_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "stream-trace.jsonl"
            manifest = root / "manifest.json"
            trace.write_bytes(b'{"sequence":0}\n')
            manifest.write_text(json.dumps({
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True, "tested": 1,
                "top_level_index": 1, "failed": 0, "unavailable": 0,
                "serialized_bytes_read": 123, "stream_trace": trace.name,
                "stream_trace_sha256": "0" * 64,
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "embedded stream-trace digest is stale"):
                _bind_native_manifest_to_trace(manifest, trace, 123,
                    root / "manifest.transaction-bound.json")

    def test_native_binding_preserves_raw_manifest_and_accounts_reference_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "stream-trace.jsonl"
            raw_path = root / "manifest.json"
            accounted_path = root / "manifest-reference-accounted.json"
            trace.write_bytes(b'{"sequence":0}\n')
            raw = {
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True, "tested": 2,
                "top_level_index": 3, "failed": 0, "unavailable": 0,
                "serialized_bytes_read": 123, "stream_trace": trace.name,
                "journal": "assets.jsonl",
            }
            reference = {"index": 0, "type_id": 19, "name": ",external", "pointer_token": 0xFFFFFFFFFFFFFFFD}
            accounted = dict(raw, reference_only_rows=[reference])
            raw_path.write_text(json.dumps(raw), encoding="utf-8")
            accounted_path.write_text(json.dumps(accounted), encoding="utf-8")
            original_sha = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            bound = root / "manifest.transaction-bound.json"
            binding = _bind_native_manifest_to_trace(
                raw_path, trace, 123, bound,
                accounted_manifest_path=accounted_path,
                normalized_inventory_sha256="b" * 64)
            bound_json = json.loads(bound.read_text(encoding="utf-8"))
            self.assertEqual(bound_json["reference_only_rows"], [reference])
            self.assertEqual(bound_json["normalized_inventory_sha256"], "b" * 64)
            self.assertEqual(hashlib.sha256(raw_path.read_bytes()).hexdigest(), original_sha)
            self.assertEqual(binding["raw_manifest_sha256"], original_sha)
            self.assertEqual(binding["accounted_manifest_sha256"],
                             hashlib.sha256(accounted_path.read_bytes()).hexdigest())

    def test_pack_and_walk_uses_full_normalized_indices_around_reference_before_lua(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_bytes = b"body"
            ref = {"index": 0, "type_id": 19, "name": ",external_image",
                   "pointer_token": 0xFFFFFFFFFFFFFFFD}
            normalized_rows = [
                dict(ref, status="reference"),
                {"index": 1, "type_id": 62, "name": "ui/after.lua", "status": "native-tested"},
                {"index": 2, "type_id": 19, "name": "$later", "status": "native-tested"},
            ]
            raw_rows = [
                {"type_id": 62, "name": "ui/after.lua"},
                {"type_id": 19, "name": "$later"},
            ]
            normalized_path = root / "normalized-inventory.json"
            normalized_path.write_text(json.dumps({"normalized_rows": normalized_rows}), encoding="utf-8")
            normalized_sha = hashlib.sha256(normalized_path.read_bytes()).hexdigest()
            raw_path = root / "native-reader" / "manifest.json"
            raw_path.parent.mkdir(parents=True)
            accounted_path = raw_path.with_name("manifest-reference-accounted.json")
            journal_path = raw_path.with_name("assets.jsonl")
            trace_path = raw_path.with_name("stream-trace.jsonl")
            journal_path.write_text("\n".join(json.dumps(row) for row in raw_rows) + "\n", encoding="utf-8")
            trace_path.write_text('{"sequence":0}\n', encoding="utf-8")
            raw = {"profile": "replay-1.20", "xfile_version": 0xFF7,
                   "complete": True, "success": True, "tested": 2,
                   "top_level_index": 3, "failed": 0, "unavailable": 0,
                   "serialized_bytes_read": len(body_bytes), "stream_trace": trace_path.name,
                   "journal": journal_path.name}
            raw_path.write_text(json.dumps(raw), encoding="utf-8")
            accounted = dict(raw, reference_only_rows=[ref])
            accounted_path.write_text(json.dumps(accounted), encoding="utf-8")
            assets = [SimpleNamespace(type_id=19), SimpleNamespace(type_id=62), SimpleNamespace(type_id=19)]
            fake_body = SimpleNamespace(assets=assets, data=body_bytes)
            index_asset = {"index": 1, "read_spans": []}
            def fake_index(_trace, _manifest, body_size, selected_assets):
                self.assertEqual(body_size, len(body_bytes))
                self.assertEqual(selected_assets, {1})
                return {"assets": [index_asset]}
            def fake_bytecodes(body, journal, spans):
                self.assertEqual(body, body_bytes)
                self.assertEqual(len(journal), 3)
                self.assertEqual(set(spans), {1})
                self.assertEqual(journal[1]["name"], "ui/after.lua")
                return {"ui/after.lua": "a" * 64}
            native = dict(manifest=accounted, manifest_path=str(accounted_path),
                raw_manifest_path=str(raw_path), raw_manifest_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                journal_sha256=hashlib.sha256(journal_path.read_bytes()).hexdigest(),
                normalized_asset_identity_sha256=ordered_asset_identity_sha256(normalized_rows),
                normalized_table_count=3, reference_only_rows=[ref],
                normalized_inventory_path=str(normalized_path), normalized_inventory_sha256=normalized_sha)
            profile = {"final_header": {"xfile_version": 0xFF7}, "header": {"transient_type": 0}, "patches": []}
            with patch("workstation_luafile_crud.pack_replay_uncompressed", return_value=b"package"), \
                 patch("workstation_luafile_crud.ZoneBody.parse", return_value=fake_body), \
                 patch("workstation_luafile_crud.verify_native", return_value=native), \
                 patch("workstation_luafile_crud.build_read_span_index", side_effect=fake_index), \
                 patch("workstation_luafile_crud._bytecodes", side_effect=fake_bytecodes):
                result = _pack_and_walk(body_bytes, [0] * 11, root / "source.ff", root / "acts.exe",
                    root / "replay.exe", root / "step", "reference-test", 30, profile)
            journal = result[2]
            self.assertEqual([row["index"] for row in journal], [0, 1, 2])
            self.assertEqual(journal[0]["status"], "reference")
            self.assertEqual(result[6], {"ui/after.lua": "a" * 64})
            bound = json.loads(result[4].read_text(encoding="utf-8"))
            self.assertEqual(bound["reference_only_rows"], [ref])
            self.assertEqual(bound["normalized_inventory_sha256"], normalized_sha)
            self.assertEqual(Path(result[1]["raw_manifest_path"]), raw_path)

    def test_workspace_preflight_rejects_existing_append_name_before_build(self):
        body = SimpleNamespace(source_sha256="a" * 64, assets=[object(), object(), object()])
        profile = {"sha256": "b" * 64}
        walk = {"walk_key": "walk", "stream_trace_enabled": True}
        native_rows = [
            {"type_id": 62, "name": "ui/existing.lua"},
            {"type_id": 20, "name": "material/other"},
            {"type_id": 1, "name": "tail"},
        ]
        staged = [{
            "operation": "append", "operation_id": "op-a-l-test", "asset_id": "zone:new-test",
            "revision": "c" * 64, "type": "luafile", "type_id": 62,
            "name": "ui/existing.lua", "index": None,
        }]
        stored = [dict(staged[0], _payload=self.payload)]
        with patch("workstation_luafile_crud.operations", return_value=stored), \
             patch("workstation_luafile_crud._workspace_inputs",
                   return_value=(Path("."), {}, body, Path("source.ff"), profile, walk,
                                 native_rows, {})):
            with self.assertRaisesRegex(ValueError, "already exists"):
                plan_luafile_crud(object(), "zone", staged)

    def test_workspace_preflight_requires_complete_operations_and_surviving_template(self):
        body = SimpleNamespace(source_sha256="a" * 64,
                               assets=[object(), object(), object(), object()])
        profile = {"sha256": "b" * 64}
        walk = {"walk_key": "walk", "stream_trace_enabled": True}
        native_rows = [
            {"type_id": 62, "name": "ui/remove.lua"},
            {"type_id": 20, "name": "material/other"},
            {"type_id": 62, "name": "ui/template.lua"},
            {"type_id": 1, "name": "tail"},
        ]
        remove = {"operation": "remove", "operation_id": "op-r-0", "asset_id": "zone:0",
                  "revision": "c" * 64, "type": "luafile", "type_id": 62,
                  "name": "ui/remove.lua", "index": 0}
        append = {"operation": "append", "operation_id": "op-a-l-test", "asset_id": "zone:new-test",
                  "revision": "d" * 64, "type": "luafile", "type_id": 62,
                  "name": "ui/new.lua", "index": None}
        stored = [dict(remove, _payload=self.payload), dict(append, _payload=self.payload)]
        context = (Path("."), {}, body, Path("source.ff"), profile, walk, native_rows, {})
        with patch("workstation_luafile_crud.operations", return_value=stored), \
             patch("workstation_luafile_crud._workspace_inputs", return_value=context):
            plan = plan_luafile_crud(object(), "zone", [remove, append])
            self.assertEqual(plan["final_xasset_count"], 4)
            with self.assertRaisesRegex(ValueError, "each current staged operation exactly once"):
                plan_luafile_crud(object(), "zone", [remove])

        no_template_rows = [native_rows[0], native_rows[1], native_rows[3]]
        body_no_template = SimpleNamespace(source_sha256="a" * 64,
                                           assets=[object(), object(), object()])
        context_no_template = (Path("."), {}, body_no_template, Path("source.ff"), profile,
                               walk, no_template_rows, {})
        only_remove = [dict(remove, name="ui/remove.lua")]
        remove_store = [dict(only_remove[0], _payload=self.payload),
                        dict(append, _payload=self.payload)]
        with patch("workstation_luafile_crud.operations", return_value=remove_store), \
             patch("workstation_luafile_crud._workspace_inputs", return_value=context_no_template):
            with self.assertRaisesRegex(ValueError, "surviving LuaFile"):
                plan_luafile_crud(object(), "zone", [only_remove[0], append])

    def test_workspace_preflight_allows_final_luafile_row_for_writer_eof_proof(self):
        body = SimpleNamespace(source_sha256="a" * 64,
                               assets=[object(), object()])
        profile = {"sha256": "b" * 64}
        walk = {"walk_key": "walk", "stream_trace_enabled": True}
        native_rows = [
            {"type_id": 20, "name": "material/retained"},
            {"type_id": 62, "name": "ui/final.lua"},
        ]
        remove = {"operation": "remove", "operation_id": "op-r-1",
                  "asset_id": "zone:1", "revision": "c" * 64,
                  "type": "luafile", "type_id": 62,
                  "name": "ui/final.lua", "index": 1}
        stored = [dict(remove, _payload=self.payload)]
        context = (Path("."), {}, body, Path("source.ff"), profile, walk,
                   native_rows, {})
        with patch("workstation_luafile_crud.operations", return_value=stored), \
             patch("workstation_luafile_crud._workspace_inputs", return_value=context):
            plan = plan_luafile_crud(object(), "zone", [remove])
        self.assertEqual(plan["final_xasset_count"], 1)
        self.assertEqual(plan["edits"][0]["index"], 1)
        self.assertIn("exact serialized EOF", plan["limits"])

    def test_staged_final_luafile_removal_survives_operations_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            current_path = cache / "pending-edits" / "op-r-1" / "current.json"
            current_path.parent.mkdir(parents=True)
            current_path.write_text('{"type_id":62}', encoding="utf-8")
            content = "return 1"
            content_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            payload = self.payload
            payload_sha = hashlib.sha256(payload).hexdigest()
            row = {
                "operation": "remove", "operation_id": "op-r-1",
                "asset_id": "zone:1", "zone_id": "zone", "revision": "c" * 64,
                "type": "luafile", "type_id": 62, "name": "ui/final.lua",
                "index": 1, "source_body_sha256": "a" * 64,
                "content": content, "content_sha256": content_sha,
                "payload_sha256": payload_sha,
                "compiler_receipt": {"asset_name": "ui/final.lua",
                    "source": {"sha256": content_sha},
                    "result": {"native_payload_sha256": payload_sha}},
            }
            body = SimpleNamespace(source_sha256="a" * 64,
                assets=[SimpleNamespace(type_id=20), SimpleNamespace(type_id=62)])
            workspace = SimpleNamespace(_compiler_identity_staleness=lambda *_: None)
            context = (cache, {}, body, Path("source.ff"), {"sha256": "b" * 64},
                       {"walk_key": "walk"},
                       [{"type_id": 20, "name": "material/retained"},
                        {"type_id": 62, "name": "ui/final.lua"}], {})
            with patch("workstation_luafile_crud._workspace_inputs", return_value=context), \
                 patch("workstation_asset_operations.validate_operation",
                       return_value=(row, payload)):
                rows = operations(workspace, "zone")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["index"], 1)
            self.assertEqual(rows[0]["name"], "ui/final.lua")

    def test_workspace_create_and_remove_dispatch_to_luafile_operations(self):
        workspace = object.__new__(FastfileWorkspace)
        snapshot = object()
        with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snapshot), \
             patch("workstation_luafile_crud.create_luafile_asset",
                   return_value={"status": "staged"}) as create, \
             patch("workstation_scriptfile_crud.operations", return_value=[]), \
             patch("workstation_localize_crud.operations", return_value=[]):
            result = workspace.create_asset("zone", "ui/new.lua", "return 1", type="luafile")
        self.assertEqual(result["status"], "staged")
        create.assert_called_once_with(workspace, "zone", "ui/new.lua", "return 1", None,
                                       _snapshot=snapshot)

        current = {"type": "luafile", "revision": "a" * 64}
        with patch.object(FastfileWorkspace, "get_asset", return_value=current), \
             patch("workstation_luafile_crud.remove_luafile_asset",
                   return_value={"status": "removed"}) as remove:
            result = workspace.remove_asset("zone:12", "a" * 64)
        self.assertEqual(result["status"], "removed")
        remove.assert_called_once_with(workspace, "zone:12", "a" * 64)

    def test_workspace_open_save_and_recompile_follow_operation_revisions(self):
        workspace = object.__new__(FastfileWorkspace)
        zone = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache" / zone
            (cache / "pending-edits" / ("op-a-l-" + "a" * 32)).mkdir(parents=True)
            (cache / "pending-edits" / ("op-a-l-" + "a" * 32) / "current.json").write_text("{}")
            snapshot = SimpleNamespace(cache_path=cache)
            appended = {"asset_id": zone + ":new-" + "a" * 32, "zone_id": zone,
                        "type": "luafile", "type_id": 62, "name": "ui/new.lua",
                        "operation": "append", "revision": "b" * 64,
                        "content": "return 1", "editable": True}
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snapshot), \
                 patch("workstation_luafile_crud.get_new_luafile_asset",
                       return_value=appended) as open_lua:
                self.assertEqual(workspace.get_asset(appended["asset_id"]), appended)
                open_lua.assert_called_once_with(workspace, appended["asset_id"], _snapshot=snapshot)
        with patch.object(FastfileWorkspace, "get_asset", return_value=appended), \
             patch.object(FastfileWorkspace, "create_asset",
                          return_value={"status": "updated"}) as create:
            self.assertEqual(workspace.save_asset(appended["asset_id"], "return 2",
                                                  appended["revision"])["status"], "updated")
            create.assert_called_once_with(zone, name="ui/new.lua", content="return 2",
                                           type="luafile", revision="b" * 64)
            with self.assertRaisesRegex(ValueError, "existing supported source edit"):
                workspace.recompile_asset(appended["asset_id"], appended["revision"])

    def test_native_capabilities_advertise_only_supported_row_mutations(self):
        report = capability_report()
        self.assertTrue(report["lua"]["row_create"] and report["lua"]["row_remove"])
        for family in ("gsc", "shader", "image", "stringtable", "localize", "omnvar", "sfx"):
            self.assertNotIn("row_create", report[family])
            self.assertNotIn("row_remove", report[family])

    def test_workspace_package_dispatches_exact_luafile_operation_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache, game = root / "cache", root / "game"
            cache.mkdir(); game.mkdir()
            (cache / "body.dec").write_bytes(b"body")
            source = game / "zone" / "source.ff"
            source.parent.mkdir(); source.write_bytes(b"source")
            output = root / "output" / "source.ff"
            workspace = object.__new__(FastfileWorkspace)
            workspace.game_root = game
            workspace._validated_zone_receipt = lambda _zone: (cache, {
                "final_body_relative_path": "body.dec",
                "source": {"path": str(source), "patches": []}})
            edit = {"asset_id": "zone:new-" + "a" * 32, "revision": "b" * 64}
            zone_plan = {"zone_id": "zone", "packageable": True,
                         "support": "luafile-sequential-native-row-operations",
                         "edits": [edit], "proof": {"operation_count": 1}}
            workspace.plan_pending_edits = lambda _zone: {"zones": [zone_plan]}
            expected = {"status": "native-pass"}
            with patch("workstation_fastfiles.ZoneBody.parse", return_value=SimpleNamespace()), \
                 patch("workstation_fastfiles.source_profile", return_value={"patches": []}), \
                 patch("workstation_luafile_crud.build_workspace_luafile_crud",
                       return_value=expected) as build:
                result = workspace.build_fastfile_with_pending_edits(
                    "zone", output, 120, expected_edits=[edit])
            self.assertEqual(result, expected)
            build.assert_called_once_with(workspace, "zone", zone_plan, output.resolve(), 120)
            with patch("workstation_fastfiles.ZoneBody.parse", return_value=SimpleNamespace()), \
                 patch("workstation_fastfiles.source_profile", return_value={"patches": []}), \
                 self.assertRaisesRegex(ValueError, "queued edit snapshot"):
                workspace.build_fastfile_with_pending_edits(
                    "zone", output, 120,
                    expected_edits=[{"asset_id": edit["asset_id"], "revision": "c" * 64}])

    def test_staged_luafile_append_updates_only_at_its_current_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            acts, replay = root / "acts.exe", root / "Replay.exe"
            profile = root / "replay120_lua_native.json"
            acts.write_bytes(b"acts fixture")
            replay.write_bytes(b"Replay fixture")
            profile.write_text("{}", encoding="utf-8")
            workspace = SimpleNamespace(
                acts_path=acts,
                replay_executable=replay,
                _lua_compiler_profile_path=lambda _acts, _name: profile)
            cache = root / "zone-cache"
            cache.mkdir()
            body = SimpleNamespace(source_sha256="a" * 64)
            identity = {"source_fastfile_sha256": "b" * 64}
            revision = "c" * 64
            stored = [{"type_id": 62, "operation": "append", "name": "ui/new.lua",
                       "revision": revision}]
            receipt = {"compiler": {}, "status": "target-lua-loadx-reload-pass"}
            with patch("workstation_luafile_crud._workspace_inputs",
                       return_value=(cache, {}, body, None, {}, {}, [], identity)), \
                 patch("workstation_luafile_crud.operations", return_value=stored), \
                 patch("workstation_fastfiles.acts_tool_identity", return_value={"sha256": "d" * 64}), \
                 patch("workstation_lua_compile.compile_luajit_source_with_receipt",
                       return_value=(self.payload, receipt)) as compile_source, \
                 patch("workstation_luafile_crud._stage_operation",
                       return_value={"status": "updated"}) as stage:
                result = create_luafile_asset(workspace, "zone", "ui/new.lua",
                                              "return 2", revision)
                self.assertEqual(result["status"], "updated")
                compile_source.assert_called_once()
                self.assertEqual(stage.call_args.args[-1], revision)
                with self.assertRaisesRegex(ValueError, "revision conflict"):
                    create_luafile_asset(workspace, "zone", "ui/new.lua",
                                         "return 3", "e" * 64)
                self.assertEqual(compile_source.call_count, 1)


if __name__ == "__main__":
    unittest.main()
