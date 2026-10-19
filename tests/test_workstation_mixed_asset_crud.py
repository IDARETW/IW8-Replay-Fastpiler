from __future__ import annotations

import sys
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_mixed_asset_crud import (
    _copy_verified_package, _publication_result, plan_mixed_asset_crud,
)
from workstation_asset_semantics import typed_semantics


class _Workspace:
    def _plan_pending_rows(self, rows):
        kind = rows[0]["type"]
        support = {"image": "same-extent-native-shader-image-batch",
                   "rawfile": "rawfile-full-trace-block5-relocation",
                   "soundbank": "same-extent-soundbank-alias-scalars",
                   "localize": "localize-sequential-native-row-operations",
                   "luafile": "luafile-sequential-native-row-operations"}[kind]
        return {"status": "ready", "invalid_edits": [], "zones": [dict(zone_id="zone-a", packageable=True,
            support=support, reason=None, edits=[dict(asset_id=row["asset_id"],
                revision=row["revision"], name=row["name"], type=row["type"])
                for row in rows], proof=dict(source_body_sha256="body", source_fastfile_sha256="ff",
                    edits=[dict(asset_id=row["asset_id"], revision=row["revision"],
                                typed_layout=dict(dimensions=[1, 1, 1, 1])) for row in rows]))]}

    def _validated_asset_snapshot(self, zone_id, **kwargs):
        return SimpleNamespace(body=SimpleNamespace(source_sha256="body"), source_profile={"sha256": "ff"})


class MixedAssetCrudPlanTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            dict(zone_id="zone-a", asset_id="zone-a:7", revision="r-image", type="image", name="$black"),
            dict(zone_id="zone-a", asset_id="zone-a:9", revision="r-rawfile", type="rawfile", name="config/test.cfg"),
            dict(zone_id="zone-a", asset_id="zone-a:new-loc", revision="r-loc", type="localize",
                 name="CODEX_TEST", operation="append", operation_id="op-loc"),
            dict(zone_id="zone-a", asset_id="zone-a:new-lua", revision="r-lua", type="luafile",
                 name="ui/test.lua", operation="append", operation_id="op-lua"),
        ]

    @patch("workstation_mixed_asset_crud.localize_operations")
    @patch("workstation_mixed_asset_crud.luafile_operations")
    def test_accepts_complete_proved_family_mix(self, lua_ops, localize_ops):
        lua_ops.return_value = [dict(operation_id="op-lua", revision="r-lua", operation="append")]
        localize_ops.return_value = [dict(operation_id="op-loc", revision="r-loc", operation="append")]
        plan = plan_mixed_asset_crud(_Workspace(), "zone-a", self.rows)
        self.assertEqual(plan["schema"], "replay120-mixed-asset-crud-plan-v1")
        self.assertEqual(set(plan["family_plans"]), {"image", "rawfile", "soundbank", "localize", "luafile"})
        self.assertEqual(plan["family_plans"]["rawfile"]["support"], "rawfile-full-trace-block5-relocation")
        self.assertEqual(len(plan["edits"]), 4)

    def test_rejects_removals_single_family_and_unknown_families_before_family_planning(self):
        invalid_sets = [
            [*self.rows[:1], {**self.rows[1], "operation": "remove"}, *self.rows[2:]],
            [*self.rows[:1], *self.rows[1:2], {**self.rows[2], "type": "scriptfile"}],
            self.rows[:1],
        ]
        for rows in invalid_sets:
            with self.subTest(rows=rows), patch.object(_Workspace, "_plan_pending_rows") as preflight:
                with self.assertRaisesRegex(ValueError, "supports resident|at least two|append-only"):
                    plan_mixed_asset_crud(_Workspace(), "zone-a", rows)
                preflight.assert_not_called()

    @patch("workstation_mixed_asset_crud.localize_operations")
    @patch("workstation_mixed_asset_crud.luafile_operations")
    def test_content_only_mix_needs_no_unrelated_row_creation(self, lua_ops, localize_ops):
        soundbank = dict(zone_id="zone-a", asset_id="zone-a:11", revision="r-bank",
                         type="soundbank", name="test.all")
        for rows in (self.rows[:2], [self.rows[1], soundbank]):
            plan = plan_mixed_asset_crud(_Workspace(), "zone-a", rows)
            self.assertIsNone(plan["localize_operation_id"])
            self.assertIsNone(plan["luafile_operation_id"])
            self.assertEqual(len(plan["edits"]), 2)
        lua_ops.assert_not_called()
        localize_ops.assert_not_called()

    def test_complex_dds_cannot_enter_an_unproved_mixed_route(self):
        workspace = _Workspace()
        original = workspace._plan_pending_rows
        for dimensions in ([32, 32, 32, 1], [256, 256, 1, 11]):
            def complex_image(rows):
                result = original(rows)
                if rows[0]["type"] == "image":
                    result["zones"][0]["proof"]["edits"][0]["typed_layout"]["dimensions"] = dimensions
                return result
            workspace._plan_pending_rows = complex_image
            with self.subTest(dimensions=dimensions), self.assertRaisesRegex(ValueError, "image/shader-only"):
                plan_mixed_asset_crud(workspace, "zone-a", self.rows[:2])

    def test_missing_image_shape_proof_cannot_claim_packageability(self):
        workspace = _Workspace()
        original = workspace._plan_pending_rows
        def missing_shape(rows):
            result = original(rows)
            result["zones"][0]["proof"]["edits"] = []
            return result
        workspace._plan_pending_rows = missing_shape
        with self.assertRaisesRegex(ValueError, "typed shape proof"):
            plan_mixed_asset_crud(workspace, "zone-a", self.rows[:2])

    @patch("workstation_mixed_asset_crud.localize_operations")
    @patch("workstation_mixed_asset_crud.luafile_operations")
    def test_rejects_stale_append_revisions(self, lua_ops, localize_ops):
        lua_ops.return_value = [dict(operation_id="op-lua", revision="old", operation="append")]
        localize_ops.return_value = [dict(operation_id="op-loc", revision="r-loc", operation="append")]
        with self.assertRaisesRegex(ValueError, "current Localize and LuaFile append revisions"):
            plan_mixed_asset_crud(_Workspace(), "zone-a", self.rows)

    def test_rejects_real_family_wrapper_when_blocked_or_invalid(self):
        workspace = _Workspace()
        original = workspace._plan_pending_rows
        def blocked(_rows):
            return {"status": "blocked", "invalid_edits": [], "zones": []}
        workspace._plan_pending_rows = blocked
        with patch("workstation_mixed_asset_crud.localize_operations",
                   return_value=[dict(operation_id="op-loc", revision="r-loc", operation="append")]), \
             patch("workstation_mixed_asset_crud.luafile_operations",
                   return_value=[dict(operation_id="op-lua", revision="r-lua", operation="append")]):
            with self.assertRaisesRegex(ValueError, "invalid pending rows"):
                plan_mixed_asset_crud(workspace, "zone-a", self.rows)
        workspace._plan_pending_rows = original

    def test_result_shape_is_accepted_by_replacement_packager(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ff, fp, receipt_path = root / "zone.ff", root / "zone.fp", root / "receipt.json"
            ff.write_bytes(b"native ff")
            fp.write_bytes(b"native fp")
            profile = {"patches": [{"path": str(root / "source.fp")}]} 
            result = _publication_result({"status": "native-mixed-asset-transaction-pass",
                                          "zone_id": "zone-a"},
                [{"asset_id": "zone-a:1", "revision": "r1"}], ff, fp, profile, receipt_path)
            self.assertEqual(result["output_fastfile"], str(ff))
            self.assertEqual(result["output_fastfile_sha256"], hashlib.sha256(ff.read_bytes()).hexdigest())
            self.assertEqual(result["sidecars"][0]["path"], str(fp))
            self.assertEqual(result["sidecars"][0]["sha256"], hashlib.sha256(fp.read_bytes()).hexdigest())

    def test_publication_rejects_post_reread_stage_mutation_and_cleans_partial_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.ff"
            staged_fp = root / "staged.fp"
            output = root / "out" / "zone.ff"
            staged.parent.mkdir(parents=True, exist_ok=True)
            output.parent.mkdir(parents=True)
            staged.write_bytes(b"native-reread ff")
            staged_fp.write_bytes(b"native-reread fp")
            expected_ff = hashlib.sha256(staged.read_bytes()).hexdigest()
            expected_fp = hashlib.sha256(staged_fp.read_bytes()).hexdigest()
            staged.write_bytes(b"changed after native reread")
            with self.assertRaisesRegex(ValueError, "changed after its native reread"):
                _copy_verified_package(staged, output, expected_ff, expected_fp)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix(".fp").exists())

    def test_publication_rechecks_copied_bytes_against_native_reread_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.ff"
            staged_fp = root / "staged.fp"
            output = root / "out" / "zone.ff"
            staged.parent.mkdir(parents=True, exist_ok=True)
            output.parent.mkdir(parents=True)
            staged.write_bytes(b"native-reread ff")
            staged_fp.write_bytes(b"native-reread fp")
            actual = _copy_verified_package(staged, output,
                hashlib.sha256(staged.read_bytes()).hexdigest(),
                hashlib.sha256(staged_fp.read_bytes()).hexdigest())
            self.assertEqual(actual[0], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(actual[1], hashlib.sha256(output.with_suffix(".fp").read_bytes()).hexdigest())

    def test_production_semantic_helpers_do_not_import_diagnostic_runner(self):
        bridge = (Path(__file__).resolve().parents[1] / "tools" / "workstation_mixed_asset_crud.py").read_text()
        semantics = (Path(__file__).resolve().parents[1] / "tools" / "workstation_asset_semantics.py").read_text()
        self.assertIn("workstation_asset_semantics", bridge)
        self.assertNotIn("workstation_mixed_asset_native", bridge)
        self.assertNotIn("SOURCE_CACHE_KEY", semantics)
        self.assertNotIn("replay-mixed-asset-native-v1", semantics)

    def test_reference_image_before_lua_keeps_table_indices_without_child_read(self):
        rows = [
            {"type_id": 19, "name": ",external_image", "status": "reference"},
            {"type_id": 19, "name": "$tested", "status": "native-tested"},
            {"type_id": 62, "name": "ui/after.lua", "status": "native-tested"},
        ]
        trace_assets = [{"index": 1, "read_spans": []}, {"index": 2, "read_spans": []}]
        fake_index = {"assets": trace_assets, "max_destination_offsets": {"5": 99}}
        def bytecodes(body, journal, spans):
            self.assertEqual(len(journal), 3)
            self.assertEqual(set(spans), {2})
            return {"ui/after.lua": "a" * 64}
        with patch("workstation_asset_semantics.build_read_span_index", return_value=fake_index) as indexer, \
             patch("workstation_asset_semantics._bytecodes", side_effect=bytecodes), \
             patch("workstation_asset_semantics.read_resident_image", return_value={
                 "payload_sha256": "b" * 64, "format": 7, "flags": 0,
                 "dimensions": (1, 1, 1, 1), "level_count": 1, "total_size": 16,
             }) as image_reader:
            semantics, index, by_index = typed_semantics(
                b"body", rows, Path("trace"), Path("manifest"))
        self.assertEqual(indexer.call_args.kwargs["selected_assets"], {1, 2})
        self.assertEqual(set(by_index), {1, 2})
        image_reader.assert_called_once()
        self.assertEqual(image_reader.call_args.args[1]["index"], 1)
        self.assertEqual(set(semantics), {(19, "$tested"), (62, "ui/after.lua")})


if __name__ == "__main__":
    unittest.main()
