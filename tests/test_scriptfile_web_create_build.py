from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
TOOLS = Path(os.environ.get("REPLAY_COMPILER_TOOLS", str(BASE / "tools"))).resolve()
sys.path.insert(0, str(BASE / "tools"))
sys.path.insert(1, str(TOOLS))

import roundtrip_replay_fastfile
from workstation_fastfiles import FastfileWorkspace, unpack_replay_uncompressed
from workstation_scriptfile_crud import (
    _compare_zero_root_sentinels, _native_scriptfile_name, _reject_cross_type_new_identity,
    _validate_active_removal_plan, _validate_inline_script_strings, _zero_root_sentinel,
)
from workstation_asset_codecs import GSCBIN_MAGIC
import workstation_scriptfile_crud as scriptfile_crud
from workstation_asset_operations import _revision, _validate_shape, stage_operation, validate_operation


PROOF_DIR = Path(os.environ.get("REPLAY_SCRIPTFILE_PROOF_DIR", str(BASE / "run")))
APPEND_PROOF = PROOF_DIR / "native-proof.json"
SOURCE_FIXTURE = (Path(os.environ["REPLAY_SCRIPTFILE_SOURCE_FIXTURE"]).resolve(strict=True)
                  if os.environ.get("REPLAY_SCRIPTFILE_SOURCE_FIXTURE") else None)
ZONE_ID = "f68e1d7599862fa0fa90489309b7313c6039a8bb8c1de19ab32c290857cee6bd"
NAME = "codex_scriptfile_append_probe_v1"
SOURCE = "workstation_codec_edit_probe()\n{\n    return;\n}\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ScriptFileWebCreateBuildTests(unittest.TestCase):
    def test_public_zone_plan_removal_proof_is_checked_from_nested_proof(self):
        staged = dict(operation_id="op-r-6012", revision="a" * 64, index=6012)
        zone_plan = dict(support="scriptfile-exclusive-final-row-removal-native-transaction",
            edits=[dict(operation="remove", operation_id=staged["operation_id"],
                        revision=staged["revision"])],
            proof=dict(source_body_sha256="b" * 64,
                       edits=[dict(operation="remove", operation_id=staged["operation_id"],
                                   revision=staged["revision"], index=staged["index"])]))
        _validate_active_removal_plan(zone_plan, staged, "b" * 64)
        with self.assertRaisesRegex(ValueError, "operation changed after preflight"):
            _validate_active_removal_plan(zone_plan, staged, "c" * 64)

    def test_scoped_pending_listing_uses_only_validated_zone_cache(self):
        with tempfile.TemporaryDirectory(prefix="scriptfile-scoped-pending-") as temp:
            root = Path(temp)
            cache_root = root / "cache"
            source_stem = cache_root / ("a" * 64)
            zones = ("b" * 64, "c" * 64)
            cache_paths = {zone: source_stem / zone for zone in zones}
            for zone, cache_path in cache_paths.items():
                pending = cache_path / "pending-edits" / ("op-a-s-" + "d" * 32) / "current.json"
                pending.parent.mkdir(parents=True)
                (cache_path / "body.dec").write_bytes(b"body")
                pending.write_text(json.dumps({"zone_id": zone, "type": "other", "schema": 99}),
                                   encoding="utf-8")
            workspace = FastfileWorkspace.__new__(FastfileWorkspace)
            workspace.cache_root = cache_root

            def validated_receipt(zone):
                return cache_paths[zone], {"final_body_relative_path": "body.dec"}

            with patch.object(workspace, "_validated_zone_receipt", side_effect=validated_receipt), \
                 patch("workstation_fastfiles.ZoneBody.parse", return_value=type("Body", (), {"assets": []})()):
                first = workspace.list_pending_edits(zones[0])
                second = workspace.list_pending_edits(zones[1])
                misfiled = cache_paths[zones[0]] / "pending-edits" / "op-misfiled" / "current.json"
                misfiled.parent.mkdir(parents=True)
                misfiled.write_text(json.dumps({"zone_id": zones[1], "type": "other", "schema": 99}),
                                    encoding="utf-8")
                rejected = workspace.list_pending_edits(zones[0])

            self.assertEqual([row["zone_id"] for row in first["items"]], [zones[0]])
            self.assertEqual([row["zone_id"] for row in second["items"]], [zones[1]])

            self.assertTrue(any(item.get("status") == "invalid" and
                                "differs from the requested zone" in item.get("error", "")
                                for item in rejected["items"]))

    def test_compiler_filename_preserves_native_path(self):
        self.assertEqual(_native_scriptfile_name("custom/frontend.gsc"), "custom/frontend.gsc")
        for invalid in ("../frontend.gsc", "custom\\frontend.gsc", "/frontend.gsc", "custom/../x.gsc"):
            with self.subTest(name=invalid), self.assertRaises(ValueError):
                _native_scriptfile_name(invalid)

    def test_existing_native_string_ids_fail_closed(self):
        payload = b"GSCBIN"
        fake_info = type("Info", (), {"bytecode": b"abcd"})()
        with patch("workstation_gsc_fields._strict_trace", return_value=(fake_info, [
                 {"next_pc": "0x4", "token": {"id": "0x1234"}}])):
            with self.assertRaisesRegex(ValueError, "source/function/import tokens"):
                _validate_inline_script_strings(payload)

    def test_canonical_token_ids_are_not_mistaken_for_inline_strings(self):
        payload = b"GSCBIN"
        fake_info = type("Info", (), {"bytecode": b"\x07\0\0\0\0"})()
        with patch("workstation_gsc_fields._strict_trace", return_value=(fake_info, [
                 {"pc": "0x0", "opcode": "0x07", "next_pc": "0x5",
                  "canonical_token": {"id": "0x2c5", "bytecode_offset": "0x1"}}])):
            with self.assertRaisesRegex(ValueError, "outside verified opcode 0x18"):
                _validate_inline_script_strings(payload)

    def test_incomplete_cursor_coverage_is_rejected(self):
        payload = b"GSCBIN"
        fake_info = type("Info", (), {"bytecode": b"abcd"})()
        with patch("workstation_asset_codecs.inspect_gscbin", return_value=fake_info), \
             patch("trace_gscbin_source_cursor.trace", return_value=[{"next_pc": "0x2"}]):
            with self.assertRaisesRegex(ValueError, "exact bytecode EOF"):
                _validate_inline_script_strings(payload)

    def test_operation_validation_rejects_scriptfile_remove_and_noncanonical_name(self):
        name, content = "custom/frontend", "main() {}"
        payload = b"gscbin-probe"
        content_sha, payload_sha = _sha(content.encode()), _sha(payload)
        receipt = dict(schema="replay120-gsc-compile-receipt-v1",
            status="gsc-tool-native-payload-pass", asset_name=name,
            source={"sha256": content_sha},
            compiler={"input_name": "script_" + _sha(name.encode())[:20]},
            result={"native_payload_sha256": payload_sha,
                    "payload_contract": "Replay ScriptFile GSCBIN after Replay local-reference scaling"},
            string_ownership={"policy": "typed-inline-only-v1", "complete_cursor": True,
                "nonzero_script_string_ids": 0, "cursor_event_count": 1, "bytecode_bytes": 1})
        zone = "a" * 64
        source_identity = dict(body_sha256="1" * 64, source_fastfile_sha256="2" * 64,
            patch_sha256s=["3" * 64], native_walk_key="walk-key",
            native_manifest_sha256="4" * 64, stream_trace_sha256="5" * 64,
            writer_module_path="writer.py", writer_module_sha256="6" * 64)
        row = dict(schema=4, operation="append", operation_id="op-a-s-" + _sha(name.encode())[:32],
            asset_id=zone + ":new-" + _sha(name.encode())[:32], zone_id=zone,
            type_id=52, type="scriptfile", name=name, index=None, xasset_index=None,
            content=content, content_sha256=content_sha, native_source_identity=source_identity,
            compiler_receipt=receipt,
            compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()),
            writer_identity={"path": "writer.py", "sha256": "6" * 64})
        row["payload_sha256"], row["payload_bytes"] = payload_sha, len(payload)
        row["payload_name"] = payload_sha + ".payload"
        row["revision"] = _revision(row)
        _validate_shape(row, payload)
        field_receipt = json.loads(json.dumps(receipt))
        field_receipt["string_ownership"] = {
            "policy": "typed-class0-op18-field-subset-v1",
            "complete_cursor": True,
            "nonzero_script_string_ids": 0,
            "cursor_event_count": 4,
            "bytecode_bytes": 8,
            "field_contract_sha256": "8" * 64,
            "original_replay_sha256": "9" * 64,
            "compiler_sha256": "a" * 64,
            "accepted_opcode_0x18_field_token_count": 1,
            "accepted_field_events": [{"pc": "0x0", "opcode": "0x18",
                "bytecode_offset": "0x1", "token": "0x2c5",
                "field_name": "origin", "descriptor_row_index": 2}],
        }
        row["compiler_receipt"] = field_receipt
        row["compiler_receipt_sha256"] = _sha(json.dumps(
            field_receipt, sort_keys=True, separators=(",", ":")).encode())
        row["revision"] = _revision(row)
        _validate_shape(row, payload)
        with tempfile.TemporaryDirectory(prefix="scriptfile-class0-operation-") as temp:
            operation_cache = Path(temp) / zone
            staged = stage_operation(operation_cache, row, payload)
            stored, stored_payload = validate_operation(
                operation_cache, operation_cache / "pending-edits" /
                staged["operation_id"] / "current.json")
            self.assertEqual(stored["compiler_receipt"]["string_ownership"]["policy"],
                             "typed-class0-op18-field-subset-v1")
            self.assertEqual(stored_payload, payload)
        malformed_field_receipt = json.loads(json.dumps(field_receipt))
        del malformed_field_receipt["string_ownership"]["compiler_sha256"]
        malformed = dict(row, compiler_receipt=malformed_field_receipt,
            compiler_receipt_sha256=_sha(json.dumps(malformed_field_receipt,
                sort_keys=True, separators=(",", ":")).encode()))
        malformed["revision"] = _revision(malformed)
        with self.assertRaisesRegex(ValueError, "class-0 field ownership identity"):
            _validate_shape(malformed, payload)
        removal = dict(row, operation="remove", index=1, xasset_index=1,
                       asset_id=zone + ":1", operation_id="op-r-1")
        removal["revision"] = _revision(removal)
        with self.assertRaisesRegex(ValueError, "existing-payload removal receipt"):
            _validate_shape(removal, payload)
        removal_receipt = dict(schema="replay120-gsc-existing-payload-remove-receipt-v1",
            status="gsc-existing-payload-preserved-pass", asset_name=name,
            source_index=1, source_body_sha256="7" * 64,
            native_payload_sha256=payload_sha, preservation="exact existing GSCBIN bytes")
        removal["compiler_receipt"] = removal_receipt
        removal["compiler_receipt_sha256"] = _sha(json.dumps(
            removal_receipt, sort_keys=True, separators=(",", ":")).encode())
        removal["revision"] = _revision(removal)
        _validate_shape(removal, payload)
        bad_name = "custom/../frontend.gsc"
        bad_receipt = json.loads(json.dumps(receipt))
        bad_receipt["asset_name"] = bad_name
        bad_receipt["compiler"]["input_name"] = "script_" + _sha(bad_name.encode())[:20]
        noncanonical = dict(row, name=bad_name,
            operation_id="op-a-s-" + _sha(bad_name.encode())[:32],
            asset_id=zone + ":new-" + _sha(bad_name.encode())[:32],
            compiler_receipt=bad_receipt,
            compiler_receipt_sha256=_sha(json.dumps(bad_receipt, sort_keys=True,
                separators=(",", ":")).encode()))
        noncanonical["revision"] = _revision(noncanonical)
        with self.assertRaisesRegex(ValueError, "invalid operation name"):
            _validate_shape(noncanonical, payload)

    def test_zero_root_sentinel_requires_exact_root_only_layout(self):
        import struct
        raw = struct.pack("<QiiiIQQ", (5 << 32) | 0x8481A9, 0, 0, 0, 0, 0, 0)
        body = b"prefix" + raw + b"suffix"
        row = dict(xasset_index=2, type_id=52, name="$default",
            root_stream_location={"stream": 1, "offset": 0},
            packed_pointer_events=[], physical_load_count_by_stream={1: 1},
            physical_load_bytes_by_stream={1: 40},
            read_spans=[dict(origin="load_stream_call", reader_start_arg=0,
                             archive_offset=6, size=40)])
        self.assertEqual(_zero_root_sentinel(body, row, 2)["status"], "zero-root-sentinel")
        malformed = bytearray(body)
        malformed[6 + 8] = 1
        with self.assertRaisesRegex(ValueError, "sentinel layout"):
            _zero_root_sentinel(bytes(malformed), row, 2)

    def test_removed_table_row_sentinel_maps_identity_and_name_target(self):
        source = dict(rows=[dict(index=8, type_id=52, name="$default",
            status="zero-root-sentinel", root_bytes_hex="00" * 8 + "11" * 32,
            packed_name_token="0x0000000500000101",
            root_stream_location={"stream": 1, "offset": 0x40})])
        output = dict(rows=[dict(index=7, type_id=52, name="$default",
            status="zero-root-sentinel", root_bytes_hex="00" * 8 + "11" * 32,
            packed_name_token="0x00000005000001f1",
            root_stream_location={"stream": 1, "offset": 0x40})])
        mapped = {(8, 1, 0x40): 0x1F0}
        result = _compare_zero_root_sentinels(source, output, mapped, removed_index=4,
                                               fallback_target_delta=0)
        self.assertEqual(result["compared"], 1)
        output["rows"][0]["packed_name_token"] = "0x00000005000001f0"
        with self.assertRaisesRegex(ValueError, "mapped name target"):
            _compare_zero_root_sentinels(source, output, mapped, removed_index=4,
                                          fallback_target_delta=0)

    def test_cross_type_pending_new_identity_is_rejected(self):
        asset_id = ZONE_ID + ":new-" + _sha(NAME.encode())[:32]
        for family in ("localize", "luafile"):
            with self.subTest(family=family), self.assertRaisesRegex(
                    ValueError, "another pending asset type"):
                _reject_cross_type_new_identity(ZONE_ID, NAME, [dict(
                    operation="append", type=family, asset_id=asset_id, name=NAME)])
        _reject_cross_type_new_identity(ZONE_ID, NAME, [])

    def test_public_create_rejects_cross_family_identity_in_both_orders(self):
        workspace = FastfileWorkspace.__new__(FastfileWorkspace)
        asset_id = ZONE_ID + ":new-" + _sha("custom/frontend.gsc".encode())[:32]
        modules = {
            "scriptfile": "workstation_scriptfile_crud",
            "luafile": "workstation_luafile_crud",
            "localize": "workstation_localize_crud",
        }
        for existing_type, requested_type in (
                ("localize", "scriptfile"), ("luafile", "scriptfile"),
                ("scriptfile", "localize"), ("scriptfile", "luafile"),
                ("localize", "luafile"), ("luafile", "localize")):
            row = dict(operation="append", type=existing_type,
                       asset_id=asset_id, name="custom/frontend.gsc")
            with self.subTest(existing=existing_type, requested=requested_type), \
                 patch(f"{modules['scriptfile']}.operations",
                       return_value=[row] if existing_type == "scriptfile" else []), \
                 patch(f"{modules['luafile']}.operations",
                       return_value=[row] if existing_type == "luafile" else []), \
                 patch(f"{modules['localize']}.operations",
                       return_value=[row] if existing_type == "localize" else []), \
                 patch.object(workspace, "_validated_asset_snapshot", return_value=object()):
                with self.assertRaisesRegex(ValueError, "pending .* append already owns"):
                    workspace.create_asset(ZONE_ID, "custom/frontend.gsc", "source",
                                           type=requested_type)

    def test_public_create_rejects_nontext_name_and_type(self):
        workspace = FastfileWorkspace.__new__(FastfileWorkspace)
        for name, asset_type in ((None, "scriptfile"), ("asset", [])):
            with self.subTest(name=name, asset_type=asset_type), self.assertRaisesRegex(
                    ValueError, "asset name and type must be text"):
                workspace.create_asset(ZONE_ID, name, "source", type=asset_type)

    def test_save_and_discard_routes_scriptfile_new_identity(self):
        workspace = FastfileWorkspace.__new__(FastfileWorkspace)
        asset_id = ZONE_ID + ":new-" + _sha(NAME.encode())[:32]
        current = dict(asset_id=asset_id, revision="1" * 64, editable=True,
                       stale=False, operation="append", zone_id=ZONE_ID,
                       name=NAME, type="scriptfile")
        with patch.object(workspace, "get_asset", return_value=current), \
             patch.object(workspace, "create_asset", return_value={"status": "restaged"}) as create:
            self.assertEqual(workspace.save_asset(asset_id, "updated", "1" * 64),
                             {"status": "restaged"})
        create.assert_called_once_with(ZONE_ID, name=NAME, content="updated",
                                       type="scriptfile", revision="1" * 64)

        with tempfile.TemporaryDirectory(prefix="scriptfile-discard-test-") as temp:
            cache = Path(temp)
            operation_id = "op-a-s-" + _sha(NAME.encode())[:32]
            operation_path = cache / "pending-edits" / operation_id / "current.json"
            operation_path.parent.mkdir(parents=True)
            operation_path.write_text("{}", encoding="utf-8")
            with patch.object(workspace, "_validated_zone_receipt", return_value=(cache, {})), \
                 patch("workstation_asset_operations.discard_operation",
                       return_value={"discarded_revision": "1" * 64}) as discard:
                result = workspace.discard_asset_edit(asset_id, "1" * 64)
            self.assertEqual(result["status"], "staged-operation-discarded")
            discard.assert_called_once_with(cache, operation_id, "1" * 64)

    def test_public_build_dispatches_final_row_removal_to_native_scriptfile_builder(self):
        workspace = FastfileWorkspace.__new__(FastfileWorkspace)
        marker = {"status": "builder-reached"}
        zone_plan = dict(zone_id=ZONE_ID, packageable=True,
            support="scriptfile-exclusive-final-row-removal-native-transaction",
            edits=[dict(asset_id=ZONE_ID + ":6012", revision="a" * 64)])
        with tempfile.TemporaryDirectory(prefix="scriptfile-remove-dispatch-") as temp:
            root = Path(temp)
            cache = root / "cache"
            cache.mkdir()
            source = root / "source.ff"
            source.write_bytes(b"pinned-source")
            (cache / "body.dec").write_bytes(b"test-body")
            decode_receipt = dict(final_body_relative_path="body.dec",
                                  source=dict(path=str(source), patches=[]))
            workspace.game_root = root / "game"
            with patch.object(workspace, "_validated_zone_receipt", return_value=(cache, decode_receipt)), \
                 patch.object(workspace, "plan_pending_edits", return_value={"zones": [zone_plan]}), \
                 patch.object(scriptfile_crud.ZoneBody, "parse", return_value=object()), \
                 patch.object(scriptfile_crud, "build_workspace_scriptfile_crud", return_value=marker) as build:
                result = workspace.build_fastfile_with_pending_edits(
                    ZONE_ID, root / "published" / "scriptfile-remove.ff", timeout=5,
                    expected_edits=zone_plan["edits"])
        self.assertEqual(result, marker)
        build.assert_called_once()

    @unittest.skipUnless(
        all(os.environ.get(key) for key in ("REPLAY_COMPILER_TOOLS",
            "REPLAY_SCRIPTFILE_SOURCE_FIXTURE", "REPLAY_GAME_ROOT", "REPLAY_ACTS")),
        "requires the pinned native fixture and external compiler tools")
    def test_public_create_plan_and_build_match_the_native_verified_transaction(self):
        proof = json.loads(APPEND_PROOF.read_text(encoding="utf-8"))
        self.assertEqual(proof["status"], "native-reread-identity-and-payload-pass")
        reader_manifest = next((PROOF_DIR / "native-reader").rglob("manifest.json"))
        game_root = Path(os.environ["REPLAY_GAME_ROOT"]).resolve(strict=True)
        acts_path = Path(os.environ["REPLAY_ACTS"]).resolve(strict=True)
        replay = game_root / "game_dx12_ship_replay.exe"
        gsc_tool = Path(os.environ.get(
            "REPLAY_GSC_TOOL", str(TOOLS / "bin" / "gsc-tool-1.5.1" / "gsc-tool.exe"))).resolve(strict=True)

        def link_or_copy(source_path, destination_path):
            try:
                os.link(source_path, destination_path)
            except OSError:
                shutil.copy2(source_path, destination_path)
            return destination_path

        with tempfile.TemporaryDirectory(prefix="scriptfile-web-create-") as temp:
            root = Path(temp)
            source_cache = SOURCE_FIXTURE / "cache"
            test_cache = root / "cache"
            shutil.copytree(source_cache, test_cache, copy_function=link_or_copy)
            workspace = FastfileWorkspace(TOOLS.parent, test_cache, game_root,
                                          acts_path, replay)
            with patch("workstation_localize_crud.operations", return_value=[dict(
                    operation="append", name=NAME,
                    asset_id=ZONE_ID + ":new-" + _sha(NAME.encode())[:32])]):
                with self.assertRaisesRegex(ValueError, "pending localize append.*identity"):
                    workspace.create_asset(ZONE_ID, NAME, SOURCE, type="scriptfile")

            staged = workspace.create_asset(ZONE_ID, NAME, SOURCE, type="scriptfile")
            self.assertEqual(staged["status"], "native-scriptfile-append-staged")
            self.assertEqual(staged["payload_sha256"], proof["appended_payload_sha256"])
            with self.assertRaisesRegex(ValueError, "pending scriptfile append"):
                workspace.create_asset(ZONE_ID, NAME, SOURCE, type="localize")
            with self.assertRaisesRegex(ValueError, "pending scriptfile append"):
                workspace.create_asset(ZONE_ID, NAME, SOURCE, type="luafile")
            reopened = workspace.get_asset(staged["asset_id"])
            self.assertEqual(reopened["revision"], staged["revision"])
            self.assertEqual(reopened["compiler_receipt"]["string_ownership"]["policy"],
                             "typed-inline-only-v1")

            pending = workspace.list_pending_edits(ZONE_ID)
            self.assertEqual(pending["total"], 1)
            visible = workspace.list_assets(ZONE_ID, query=NAME)
            visible_appends = [item for item in visible["items"] if item.get("asset_id") == staged["asset_id"]]
            self.assertEqual(len(visible_appends), 1)
            self.assertEqual(visible_appends[0]["type_id"], 52)
            self.assertEqual(visible_appends[0]["name"], NAME)
            plan = workspace.plan_pending_edits(ZONE_ID)
            zone = plan["zones"][0]
            self.assertTrue(zone["packageable"])
            self.assertEqual(zone["support"], "scriptfile-inline-row-append-native-transaction")
            self.assertIn("pinned class-0 opcode 0x18 field subset", zone["proof"]["limits"])
            self.assertIn("no general canonical-token or VM-execution claim", zone["proof"]["limits"])
            with self.assertRaisesRegex(Exception, "row removal has no complete retained-reference proof"):
                workspace.remove_asset(staged["asset_id"], staged["revision"])

            # The previously native-read output is reusable only because this
            # public route must recreate exactly the pinned FF and body bytes.
            def reuse_exact_native_proof(path, body, source, acts, replay, output_root,
                                         timeout, trace=False, reference_only_rows=None):
                self.assertTrue(trace)
                self.assertEqual(_sha(Path(path).read_bytes()), proof["candidate_ff_sha256"])
                self.assertEqual(_sha(body), proof["candidate_body_sha256"])
                return dict(manifest=json.loads(reader_manifest.read_text(encoding="utf-8")),
                            manifest_path=str(reader_manifest.resolve()), reference_only_rows=[])

            output = root / "published" / "web-created.ff"
            with patch.object(roundtrip_replay_fastfile, "verify_native", reuse_exact_native_proof):
                result = workspace.build_fastfile_with_pending_edits(
                    ZONE_ID, output, timeout=30, expected_edits=zone["edits"])

            self.assertEqual(result["status"], "scriptfile-append-native-transaction-pass")
            self.assertEqual(result["output_fastfile_sha256"], proof["candidate_ff_sha256"])
            self.assertEqual(result["output_body_sha256"], proof["candidate_body_sha256"])
            self.assertEqual(result["native_reader_tested"], proof["tested"])
            edited = workspace.save_asset(staged["asset_id"], SOURCE + "// saved revision\n",
                                          staged["revision"])
            self.assertNotEqual(edited["revision"], staged["revision"])
            reopened_edit = workspace.get_asset(staged["asset_id"])
            self.assertEqual(reopened_edit["content"], SOURCE + "// saved revision\n")
            discarded = workspace.discard_asset_edit(staged["asset_id"], edited["revision"])
            self.assertEqual(discarded["status"], "staged-operation-discarded")
            self.assertEqual(workspace.list_pending_edits(ZONE_ID)["total"], 0)
            with self.assertRaises(KeyError):
                workspace.get_asset(staged["asset_id"])
            aliases = result["retained_alias_verification"]
            self.assertEqual(aliases["status"], "retained-alias-targets-pass")
            self.assertEqual(aliases["compared"], proof["retained_alias_callbacks_compared"])
            self.assertTrue(output.is_file())
            self.assertTrue(output.with_suffix(".fp").is_file())
            packaged = unpack_replay_uncompressed(output.read_bytes())
            self.assertEqual(_sha(packaged), proof["candidate_body_sha256"])


if __name__ == "__main__":
    unittest.main()
