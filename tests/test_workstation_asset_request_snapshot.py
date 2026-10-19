from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_fastfiles import AssetRequestSnapshot, FastfileWorkspace


class AssetRequestSnapshotTests(unittest.TestCase):
    def workspace(self, root: Path):
        workspace_root = root / "workspace"
        cache_root = root / "cache"
        game_root = root / "game"
        workspace_root.mkdir(parents=True, exist_ok=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        game_root.mkdir(parents=True, exist_ok=True)
        acts = root / "acts.exe"
        lua_acts = root / "lua-acts.exe"
        replay = root / "replay.exe"
        for path in (acts, lua_acts, replay):
            path.write_bytes(b"tool")
        workspace = object.__new__(FastfileWorkspace)
        workspace.root = workspace_root.resolve()
        workspace.cache_root = cache_root.resolve()
        workspace.game_root = game_root.resolve()
        workspace.acts_path = acts.resolve()
        workspace.lua_acts_path = lua_acts.resolve()
        workspace.replay_executable = replay.resolve()
        return workspace

    def snapshot(self, workspace, zone, source, *, profile=None, cache=None):
        cache = cache or workspace.cache_root / "group" / zone
        cache.mkdir(parents=True, exist_ok=True)
        body_path = cache / "zone.dec"
        body_path.write_bytes(b"body")
        receipt = {"source": {"path": str(source.resolve()), "patches": []},
                   "final_body_relative_path": "zone.dec"}
        return AssetRequestSnapshot(
            zone, workspace._asset_workspace_identity(), cache.resolve(), receipt,
            SimpleNamespace(assets=[], source_sha256="body-hash"), body_path.resolve(),
            source.resolve(), profile or {"sha256": "source-hash", "patches": []},
            {"stream_trace_enabled": True, "walk_key": "walk",
             "manifest_sha256": "manifest", "stream_trace_sha256": "trace"}, [])

    def test_snapshot_is_bound_to_exact_workspace_and_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zone = "a" * 64
            workspace = self.workspace(root / "one")
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            workspace._require_asset_request_snapshot(snap, zone)
            with self.assertRaisesRegex(ValueError, "another zone"):
                workspace._require_asset_request_snapshot(snap, "b" * 64)
            other = self.workspace(root / "two")
            with self.assertRaisesRegex(ValueError, "another workspace"):
                other._require_asset_request_snapshot(snap, zone)

    def test_staging_rejects_snapshot_without_source_profile_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zone = "a" * 64
            workspace = self.workspace(root)
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            complete = self.snapshot(workspace, zone, source)
            incomplete = AssetRequestSnapshot(
                complete.zone_id, complete.workspace_identity, complete.cache_path,
                complete.decode_receipt, complete.body, complete.body_path,
                complete.source_path, None, complete.native_walk, complete.native_rows)
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot") as validate:
                with self.assertRaisesRegex(ValueError, "lacks the source profile"):
                    workspace._assert_asset_snapshot_current(incomplete)
            validate.assert_not_called()

    def test_request_cache_is_local_and_same_size_restored_mtime_change_is_seen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "c" * 64
            cache = workspace.cache_root / "group" / zone
            cache.mkdir(parents=True)
            (cache / "decode-receipt.json").write_text("{}", encoding="utf-8")
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"alpha!")
            original_stat = source.stat()
            body_path = cache / "zone.dec"
            body_path.write_bytes(b"body")
            body = SimpleNamespace(assets=[], source_sha256="body-hash")
            receipt = {"source": {"path": str(source), "patches": []},
                       "final_body_relative_path": "zone.dec"}
            def prof(path):
                return {"sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                        "patches": []}
            def rows(_cache, _body, *, require_trace):
                self.assertTrue(require_trace)
                return ({"stream_trace_enabled": True, "walk_key": "walk",
                         "manifest_sha256": "manifest", "stream_trace_sha256": "trace",
                         "status": "native-pass", "xasset_count": 0, "loaded_assets": 0,
                         "serialized_bytes_read": 0, "writer_ready": False,
                         "identity": {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                      "patch_sha256s": []}}, [])
            with patch("workstation_fastfiles._cache_receipt", return_value=(receipt, body)), \
                 patch("workstation_fastfiles._read_native_rows", side_effect=rows), \
                 patch("workstation_fastfiles.source_profile", side_effect=prof) as profile:
                first_request = workspace._request_asset_snapshot(zone, {})
                source.write_bytes(b"bravo!")
                os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                second_request = workspace._request_asset_snapshot(zone, {})
                self.assertNotEqual(first_request.source_profile["sha256"],
                                    second_request.source_profile["sha256"])
                self.assertEqual(source.stat().st_size, original_stat.st_size)
                self.assertEqual(source.stat().st_mtime_ns, original_stat.st_mtime_ns)
                self.assertEqual(profile.call_count, 2)
                self.assertIsNot(first_request, second_request)

    def test_list_create_get_and_preflight_share_one_snapshot_per_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "d" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source, cache=workspace.cache_root / "group" / zone)
            snap = AssetRequestSnapshot(snap.zone_id, snap.workspace_identity, snap.cache_path,
                snap.decode_receipt, snap.body, snap.body_path, snap.source_path,
                snap.source_profile, None, None)
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snap) as validate:
                listing = workspace.list_assets(zone)
            self.assertEqual(listing["total"], 0)
            validate.assert_called_once_with(zone, require_trace=False, validate_source=False)

            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snap) as validate, \
                 patch("workstation_localize_crud.operations", return_value=[]), \
                 patch("workstation_luafile_crud.operations", return_value=[]), \
                 patch("workstation_scriptfile_crud.operations", return_value=[]), \
                 patch("workstation_scriptfile_crud.create_scriptfile_asset",
                       return_value={"status": "staged"}) as create:
                self.assertEqual(workspace.create_asset(zone, "custom/test.gsc", "main() {}",
                                                        type="scriptfile")["status"], "staged")
            validate.assert_called_once_with(zone)
            self.assertIs(create.call_args.kwargs["_snapshot"], snap)

            op_id = "op-a-s-" + "e" * 32
            op_dir = snap.cache_path / "pending-edits" / op_id
            op_dir.mkdir(parents=True)
            (op_dir / "current.json").write_text("{}", encoding="utf-8")
            asset_id = zone + ":new-" + "e" * 32
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snap) as validate, \
                 patch("workstation_scriptfile_crud.get_new_scriptfile_asset",
                       return_value={"asset_id": asset_id}) as getter:
                self.assertEqual(workspace.get_asset(asset_id)["asset_id"], asset_id)
            validate.assert_called_once_with(zone)
            self.assertIs(getter.call_args.kwargs["_snapshot"], snap)

            snap = self.snapshot(workspace, zone, source, cache=snap.cache_path)
            snapshots = {}
            workspace.list_pending_edits = lambda *args, **kwargs: {
                "items": [], "total": 0,
                "snapshot": workspace._request_asset_snapshot(zone, kwargs["_snapshots"])}
            workspace._plan_pending_rows = lambda rows, *, _snapshots: {
                "snapshot": workspace._request_asset_snapshot(zone, _snapshots)}
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snap) as validate, \
                 patch.object(FastfileWorkspace, "_assert_asset_snapshot_current") as barrier:
                plan = workspace.plan_pending_edits(zone)
            validate.assert_called_once_with(zone, require_trace=True)
            barrier.assert_called_once_with(snap)
            self.assertIs(plan["snapshot"], snap)

    def test_new_localize_get_reuses_snapshot_cache_without_receipt_revalidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "6" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            asset_id = zone + ":new-" + "a" * 32
            operation = {"asset_id": asset_id, "operation_id": "op-a-" + "a" * 32,
                         "name": "NEW_KEY", "type": "localize", "operation": "append"}
            with patch("workstation_localize_crud.operations", return_value=[operation]), \
                 patch.object(FastfileWorkspace, "_validated_zone_receipt") as receipt:
                from workstation_localize_crud import get_new_localize_asset
                result = get_new_localize_asset(workspace, asset_id, _snapshot=snap)
            self.assertEqual(result["asset_id"], asset_id)
            self.assertTrue(result["pending_path"].startswith(str(snap.cache_path)))
            receipt.assert_not_called()

    def test_public_localize_create_uses_one_input_snapshot_then_final_recheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "9" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            identity = {"writer_module_path": "writer.py", "writer_module_sha256": "a" * 64}
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot",
                              side_effect=[snap, snap]) as validate, \
                 patch("workstation_scriptfile_crud.operations", return_value=[]), \
                 patch("workstation_luafile_crud.operations", return_value=[]), \
                 patch("workstation_localize_crud._inputs",
                       return_value=(snap.cache_path, snap.decode_receipt, snap.body,
                                     source, snap.source_profile, snap.native_walk, [], identity)) as inputs, \
                 patch("workstation_asset_operations.stage_operation",
                       return_value={"operation_id": "op-a-test", "revision": "b" * 64}) as stage:
                result = workspace.create_asset(zone, "NEW_KEY", "new text", type="localize")
            self.assertEqual(result["status"], "native-localize-append-staged")
            self.assertEqual(validate.call_count, 2)  # initial snapshot plus mandatory final fresh barrier
            self.assertEqual(inputs.call_count, 2)  # preflight and staging reuse identical row/body evidence
            for call in inputs.call_args_list:
                self.assertIs(call.kwargs["_snapshot"], snap)
            stage.assert_called_once()

    def test_public_scriptfile_create_shares_snapshot_across_family_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "8" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            tool = root / "gsc-tool.exe"
            tool.write_bytes(b"tool")
            identity = {"writer_module_path": "writer.py", "writer_module_sha256": "a" * 64}
            import workstation_asset_codecs
            inputs = (snap.cache_path, snap.cache_path, snap.decode_receipt, snap.body,
                      snap.body_path, source, snap.source_profile, snap.native_walk,
                      [], identity, workstation_asset_codecs)
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot",
                              side_effect=[snap, snap]) as validate, \
                 patch("workstation_fastfiles.DEFAULT_GSC_TOOL", tool), \
                 patch("workstation_fastfiles.acts_tool_identity", return_value={"tool": "pin"}), \
                 patch("workstation_scriptfile_crud._workspace_inputs", return_value=inputs) as family_inputs, \
                 patch("workstation_scriptfile_crud.operations", return_value=[]) as own_operations, \
                 patch("workstation_localize_crud.operations", return_value=[]), \
                 patch("workstation_luafile_crud.operations", return_value=[]), \
                 patch("workstation_asset_codecs.compile_scriptfile", return_value=b"GSCBIN"), \
                 patch("workstation_scriptfile_crud._validate_inline_script_strings",
                       return_value={"status": "inline-only"}), \
                 patch("workstation_asset_operations.stage_operation",
                       return_value={"operation_id": "op-a-s-test", "revision": "b" * 64}) as stage:
                result = workspace.create_asset(zone, "custom/test.gsc", "main() {}", type="scriptfile")
            self.assertEqual(result["status"], "native-scriptfile-append-staged")
            self.assertEqual(validate.call_count, 2)  # initial evidence and one fresh final barrier
            self.assertEqual(family_inputs.call_count, 1)
            self.assertIs(family_inputs.call_args.kwargs["_snapshot"], snap)
            self.assertEqual(own_operations.call_count, 1)
            self.assertIs(own_operations.call_args.kwargs["_snapshot"], snap)
            stage.assert_called_once()

    def test_empty_preflight_validates_receipt_once_without_reparsing_for_path_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "7" * 64
            cache = workspace.cache_root / "group" / zone
            (cache / "pending-edits").mkdir(parents=True)
            (cache / "decode-receipt.json").write_text("{}", encoding="utf-8")
            with patch.object(FastfileWorkspace, "_validated_zone_receipt",
                              return_value=(cache, {"ok": True})) as validate:
                plan = workspace.plan_pending_edits(zone)
            self.assertEqual(plan["status"], "empty")
            validate.assert_called_once_with(zone)

    def test_mixed_family_identity_collision_rejects_before_create_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "e" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            import hashlib
            identity = hashlib.sha256(b"DUPLICATE").hexdigest()[:32]
            conflict = {"operation": "append", "asset_id": zone + ":new-" + identity,
                        "type": "luafile", "name": "DUPLICATE"}
            with patch.object(FastfileWorkspace, "_validated_asset_snapshot", return_value=snap), \
                 patch("workstation_luafile_crud.operations", return_value=[conflict]), \
                 patch("workstation_scriptfile_crud.operations", return_value=[]), \
                 patch("workstation_localize_crud.create_localize_asset") as create:
                with self.assertRaisesRegex(ValueError, "luafile append already owns"):
                    workspace.create_asset(zone, "DUPLICATE", "value", type="localize")
            create.assert_not_called()

    def test_wrong_workspace_snapshot_and_source_drift_prevent_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self.workspace(root)
            zone = "f" * 64
            source = workspace.game_root / "zone.ff"
            source.write_bytes(b"source")
            snap = self.snapshot(workspace, zone, source)
            other = self.workspace(root / "other")
            with self.assertRaisesRegex(ValueError, "another workspace"):
                other._assert_asset_snapshot_current(snap)

            cache, receipt, body = snap.cache_path, snap.decode_receipt, snap.body
            (cache / "decode-receipt.json").write_text("{}", encoding="utf-8")
            original_stat = source.stat()
            def profile(path):
                return {"sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                        "patches": []}
            def rows(_cache, _body, *, require_trace):
                return ({"stream_trace_enabled": True, "walk_key": "walk",
                         "manifest_sha256": "manifest", "stream_trace_sha256": "trace",
                         "identity": {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                      "patch_sha256s": []}}, [])
            with patch("workstation_fastfiles._cache_receipt", return_value=(receipt, body)), \
                 patch("workstation_fastfiles._read_native_rows", side_effect=rows), \
                 patch("workstation_fastfiles.source_profile", side_effect=profile):
                snap = workspace._validated_asset_snapshot(zone)
                source.write_bytes(b"change")
                os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                self.assertEqual(source.stat().st_size, original_stat.st_size)
                self.assertEqual(source.stat().st_mtime_ns, original_stat.st_mtime_ns)
                identity = {"writer_module_path": "writer.py", "writer_module_sha256": "a" * 64}
                with patch("workstation_localize_crud._inputs",
                           return_value=(cache, receipt, body, source, snap.source_profile,
                                         snap.native_walk, [], identity)), \
                     patch("workstation_asset_operations.stage_operation") as stage:
                    from workstation_localize_crud import create_localize_asset
                    with self.assertRaisesRegex(RuntimeError, "source changed during the request"):
                        create_localize_asset(workspace, zone, "KEY", "value", _snapshot=snap)
                stage.assert_not_called()



if __name__ == "__main__":
    unittest.main()
