import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import workstation_asset_codecs as codecs
from workstation_fastfiles import FastfileWorkspace
import workstation_shader_crud as shader_crud
import workstation_shader_row_operations as shader_rows
from workstation_asset_operations import new_asset_identity, _operation_id, _revision, _validate_shape


class PixelShaderCreateTests(unittest.TestCase):
    def test_stage_new_asset_ids_are_type_qualified_and_repeatable(self):
        zone = "a" * 64
        name = "custom/probe.hlsl"
        ids = {type_id: new_asset_identity(zone, type_id, name) for type_id in (12, 14, 15, 16, 17)}
        self.assertEqual(len(set(ids.values())), 5)
        self.assertEqual(ids[14], new_asset_identity(zone, 14, name))
        self.assertTrue(ids[14].startswith(f"{zone}:new-14-"))

    def test_final_shader_removal_receipt_is_bound_to_exact_source_payload(self):
        zone = "b" * 64
        name = "custom/final.hlsl"
        payload = b"DXBC" + bytes(28)
        payload_hash = hashlib.sha256(payload).hexdigest()
        body_hash = "c" * 64
        receipt = {"schema":"replay120-native-shader-row-remove-receipt-v1",
            "status":"native-shader-row-removal-staged", "asset_name":name,
            "type_id":14,"source_index":0,"source_body_sha256":body_hash,
            "native_payload_sha256":payload_hash}
        receipt_hash=hashlib.sha256(json.dumps(receipt,sort_keys=True,separators=(",",":"),
            ensure_ascii=False).encode()).hexdigest()
        row={"schema":4,"operation":"remove","operation_id":_operation_id("remove",name,0,14),
            "asset_id":f"{zone}:0","zone_id":zone,"type_id":14,"type":"vertexshader",
            "name":name,"index":0,"xasset_index":0,"content":"vs_5_0\nret\n",
            "content_sha256":hashlib.sha256(b"vs_5_0\nret\n").hexdigest(),
            "source_body_sha256":body_hash,
            "native_source_identity":{"body_sha256":body_hash,"source_fastfile_sha256":"d"*64,
                "patch_sha256s":[],"native_walk_key":"walk","native_manifest_sha256":"e"*64,
                "stream_trace_sha256":"f"*64,"writer_module_path":"writer.py","writer_module_sha256":"1"*64},
            "compiler_receipt":receipt,"compiler_receipt_sha256":receipt_hash,
            "payload_sha256":payload_hash,"payload_bytes":len(payload),"payload_name":payload_hash+".payload",
            "writer_identity":{"path":"writer.py","sha256":"1"*64}}
        row["revision"]=_revision(row)
        _validate_shape(row,payload)
        changed=dict(row);changed["compiler_receipt"]=dict(receipt,native_payload_sha256="2"*64)
        changed["compiler_receipt_sha256"]=hashlib.sha256(json.dumps(changed["compiler_receipt"],
            sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        changed["revision"]=_revision(changed)
        with self.assertRaisesRegex(ValueError,"differs from its exact source row"):
            _validate_shape(changed,payload)

    def test_type_qualified_shader_ids_do_not_collide_with_legacy_name_only_pending_ids(self):
        zone_id = "z" * 64
        name = "custom/probe.hlsl"
        asset_id = f"{zone_id}:new-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:32]}"
        modules = {
            "workstation_scriptfile_crud": "scriptfile",
            "workstation_luafile_crud": "luafile",
            "workstation_localize_crud": "localize",
            "workstation_rawfile_crud": "rawfile",
            "workstation_stringtable_crud": "stringtable",
            "workstation_shader_crud": "pixelshader",
        }
        workspace = types.SimpleNamespace()
        for pending_kind, requested_kind in (("rawfile", "vertexshader"),
                                              ("localize", "computeshader"),
                                              ("luafile", "hullshader"),
                                              ("scriptfile", "domainshader"),
                                              ("pixelshader", "rawfile")):
            fake_modules = {}
            for module_name, operation_kind in modules.items():
                pending = ([dict(operation="append", asset_id=asset_id, name=name)]
                           if operation_kind == pending_kind else [])
                fake_modules[module_name] = types.SimpleNamespace(
                    operations=lambda _workspace, _zone, _snapshot=None, rows=pending: rows)
            with patch.dict(sys.modules, fake_modules):
                with self.subTest(pending=pending_kind, requested=requested_kind):
                    FastfileWorkspace._reject_cross_type_pending_new_identity(
                        workspace, zone_id, name, requested_kind, _snapshot=object())

    def test_exclusive_publication_hash_pins_receipt_and_preserves_racing_file(self):
        with tempfile.TemporaryDirectory(prefix="shader-publish-") as temporary:
            root = Path(temporary)
            output = root / "candidate.ff"
            sidecar = root / "candidate.fp"
            receipt_path = root / "candidate.ff.edit-receipt.json"
            semantics = {(19, "images/test"): "a" * 64}
            receipt = {"output": str(output), "retained_typed_semantics": [
                {"type_id": kind, "name": name, "sha256": digest}
                for (kind, name), digest in sorted(semantics.items())]}
            receipt_bytes = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
            blobs = [(output, b"verified ff", hashlib.sha256(b"verified ff").hexdigest()),
                     (sidecar, b"verified fp", hashlib.sha256(b"verified fp").hexdigest()),
                     (receipt_path, receipt_bytes, hashlib.sha256(receipt_bytes).hexdigest())]
            published = shader_crud._publish_verified_files(blobs)
            self.assertEqual(len(published), 3)
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), blobs[0][2])

            race_root = root / "race"
            race_root.mkdir()
            first, raced, last = (race_root / "first.ff", race_root / "raced.fp", race_root / "last.json")
            raced.write_bytes(b"preexisting racer")
            race_blobs = [(first, b"first", hashlib.sha256(b"first").hexdigest()),
                          (raced, b"ours", hashlib.sha256(b"ours").hexdigest()),
                          (last, b"receipt", hashlib.sha256(b"receipt").hexdigest())]
            with self.assertRaises(FileExistsError):
                shader_crud._publish_verified_files(race_blobs)
            self.assertFalse(first.exists(), "only paths created by this publication are rolled back")
            self.assertEqual(raced.read_bytes(), b"preexisting racer")
            self.assertFalse(last.exists())
            self.assertEqual(list(race_root.glob(".*.stage")), [])

    def test_type17_template_rejects_unproved_root_storage_children(self):
        root = bytearray(40)
        shader_rows._validate_pixel_shader_template_root(bytes(root))
        for offset in (16, 24):
            unsupported = bytearray(root)
            unsupported[offset] = 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, r"unsupported root\+16/root\+24"):
                shader_rows._validate_pixel_shader_template_root(bytes(unsupported))

    def test_public_create_stages_authored_type17_and_preflights_exact_operation(self):
        with tempfile.TemporaryDirectory(prefix="shader-crud-public-") as temporary:
            root = Path(temporary)
            zone_id = "a" * 64
            cache = root / zone_id
            cache.mkdir()
            walk_dir = root / "source-walk"
            walk_dir.mkdir()
            for filename in ("manifest.json", "stream-trace.jsonl", "assets.jsonl"):
                (walk_dir / filename).write_text("{}\n", encoding="utf-8")
            tool = root / "cmd_Decompiler.exe"
            tool.write_bytes(b"pinned-tool-fixture")
            body = types.SimpleNamespace(source_sha256="f" * 64, data=b"synthetic body",
                assets=[types.SimpleNamespace(type_id=17, index=0, pointer_token=0xFFFFFFFFFFFFFFFE)])
            snapshot = types.SimpleNamespace(zone_id=zone_id, cache_path=cache, body=body,
                source_path=root / "code_post_gfx.ff",
                decode_receipt={"final_body_relative_path": str(root / "unused-body")},
                source_profile={"sha256": "b" * 64, "patches": [],
                    "header": {"transient_type": 0},
                    "final_header": {"xfile_version": 4087, "block_sizes": [0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0]}},
                native_walk={"stream_trace_enabled": True,
                    "identity": {"body_sha256": body.source_sha256, "source_sha256": "b" * 64,
                                 "patch_sha256s": []},
                    "walk_key": "fixture-walk", "manifest_sha256": "c" * 64,
                    "stream_trace_sha256": "d" * 64, "cache_path": str(walk_dir),
                    "manifest_relative_path": "manifest.json",
                    "stream_trace_relative_path": "stream-trace.jsonl",
                    "journal_relative_path": "assets.jsonl"},
                native_rows=[{"type_id": 17, "name": "stock.hlsl"}])

            class Workspace:
                replay_executable = root / "game_dx12_ship_replay.exe"
                game_root = root / "game"
                acts_path = root / "acts.exe"
                cache_root = root
                def _validated_asset_snapshot(self, selected_zone, **_kwargs):
                    if selected_zone != zone_id:
                        raise AssertionError("wrong zone requested")
                    return snapshot
                def _validated_zone_receipt(self, selected_zone):
                    if selected_zone != zone_id:
                        raise AssertionError("wrong zone receipt requested")
                    return cache, {"final_body_relative_path": "unused-body"}
                def _request_asset_snapshot(self, selected_zone, snapshots, *, require_trace=True):
                    if selected_zone != zone_id or not require_trace:
                        raise AssertionError("pending shader rows require the expected native snapshot")
                    snapshots[selected_zone] = snapshot
                    return snapshot
                def _assert_asset_snapshot_current(self, selected):
                    self.assert_snapshot = selected
                def _reject_cross_type_pending_new_identity(self, *_args, **_kwargs):
                    pass

            workspace = Workspace()
            source = "ps_5_0\ndcl_output o0.xyzw\nmov o0, l(1, 0, 0, 1)\nret\n"
            payload = b"DXBC" + bytes(20) + (32).to_bytes(4, "little") + bytes(4)
            allocation = {"schema": "replay120-edited-shader-identity-v1", "type_id": 17,
                "name": "custom/probe.hlsl", "program_sha256": hashlib.sha256(payload).hexdigest(),
                "identity": 0x12345678, "identity_hex": "0x12345678", "nonce": 0,
                "digest_sha256": "e" * 64, "replay_executable_sha256": "1" * 64,
                "inventory_hashes": ["2" * 64], "allocation_rule": "test fixture"}
            with patch.object(shader_crud, "_tool", return_value=tool), \
                 patch.object(shader_crud, "_allocate", return_value=allocation), \
                 patch.object(codecs, "assemble_dxbc", return_value=payload), \
                 patch.object(codecs, "dxbc_native_shader_type", return_value=17):
                created = FastfileWorkspace.create_asset(workspace, zone_id,
                    "custom/probe.hlsl", source, type="pixelshader")
                self.assertEqual(created["type_id"], 17)
                self.assertEqual(created["status"], "native-pixelshader-append-staged")
                selected = FastfileWorkspace.get_asset(workspace, created["asset_id"])
                self.assertEqual(selected["content"], source)
                self.assertEqual(selected["compiler_receipt"]["identity_allocation"]["identity"],
                                 allocation["identity"])
                plan = shader_crud.plan_pixelshader_crud(workspace, zone_id,
                    [dict(operation_id=created["operation_id"], revision=created["revision"],
                          operation="append")], _snapshot=snapshot)
                self.assertEqual(plan["support"], "pixelshader-row-append-native-transaction")
                self.assertEqual(plan["final_xasset_count"], 2)
                journal = root / "native-journal.jsonl"
                journal.write_text('{"type_id":17,"type":"pixelshader","name":"custom/probe.hlsl"}\n',
                                   encoding="utf-8")
                native_manifest = root / "native-manifest.json"
                native_manifest.write_text("{}\n", encoding="utf-8")
                output = root / "built.ff"
                writer_proof = {"stream_reservation_highwaters": [0, 5, 0, 0, 0, 20, 0, 0, 0, 0, 0]}
                with patch("workstation_trace_index.build_read_span_index",
                           return_value={"assets": [{"index": 0, "read_spans": []}]}), \
                     patch.object(shader_rows, "append_native_shader_tail",
                                  return_value=(b"updated body", writer_proof)) as append, \
                     patch.object(shader_crud, "pack_replay_uncompressed", return_value=b"packed ff"), \
                     patch.object(shader_crud, "verify_native", return_value={
                         "manifest_path": str(native_manifest),
                         "manifest": {"complete": False, "loaded_assets": 2, "tested": 2, "failed": 0,
                                      "unavailable": 0, "journal": journal.name}}):
                    with self.assertRaises(ValueError):
                        shader_crud.build_workspace_pixelshader_crud(
                            workspace, zone_id, plan, output, timeout=30, _snapshot=snapshot)
                self.assertFalse(output.exists(), "unvalidated package must never be published")
                append.assert_called_once()

            # A vertex row with the same filename is a distinct typed native
            # identity and must coexist with the staged pixel row.
            vertex_payload = bytearray(payload)
            vertex_payload[4] = 1
            vertex_allocation = {**allocation, "type_id": 14, "identity": 0x87654321,
                                 "program_sha256": hashlib.sha256(vertex_payload).hexdigest()}
            with patch.object(shader_crud, "_tool", return_value=tool), \
                 patch.object(shader_crud, "_allocate", return_value=vertex_allocation), \
                 patch.object(codecs, "assemble_dxbc", return_value=bytes(vertex_payload)), \
                 patch.object(codecs, "dxbc_native_shader_type",
                    side_effect=lambda data: 17 if data == payload else 14):
                vertex = FastfileWorkspace.create_asset(workspace, zone_id,
                    "custom/probe.hlsl", "vs_5_0\ndcl_output o0.xyzw\nmov o0, l(0, 0, 0, 1)\nret\n",
                    type="vertexshader")
                self.assertEqual(vertex["type_id"], 14)
                self.assertTrue(vertex["asset_id"].startswith(f"{zone_id}:new-14-"))
                self.assertNotEqual(vertex["asset_id"], created["asset_id"])
                opened = FastfileWorkspace.get_asset(workspace, vertex["asset_id"])
                self.assertEqual(opened["type_id"], 14)
                rows = shader_crud.operations(workspace, zone_id, _snapshot=snapshot)
                self.assertEqual({(row["type_id"], row["name"]) for row in rows},
                                 {(17, "custom/probe.hlsl"), (14, "custom/probe.hlsl")})
                pending = FastfileWorkspace.list_pending_edits(workspace, zone_id)
                self.assertEqual({(row["type_id"], row["name"]) for row in pending["items"]},
                                 {(17, "custom/probe.hlsl"), (14, "custom/probe.hlsl")})


if __name__ == "__main__":
    unittest.main()
