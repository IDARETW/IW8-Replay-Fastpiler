"""Focused tests for immutable append/remove operation snapshots."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

from workstation_asset_operations import (  # noqa: E402
    discard_operation, stage_operation, validate_operation,
)
from workstation.asset_packaging import pending_snapshot  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_identity() -> dict:
    return {
        "body_sha256": "1" * 64,
        "source_fastfile_sha256": "2" * 64,
        "patch_sha256s": ["3" * 64],
        "native_walk_key": "walk-fixture-001",
        "native_manifest_sha256": "4" * 64,
        "stream_trace_sha256": "5" * 64,
        "writer_module_path": "tools/workstation_localize.py",
        "writer_module_sha256": "6" * 64,
    }


def make_row(operation="append", *, name="new/key", index=None, payload=b"encoded") -> dict:
    zone = "eng_code_post_gfx"
    if operation == "append":
        asset_id = zone + ":new-" + digest(name.encode())[:32]
    else:
        asset_id = f"{zone}:{index}"
    receipt = {"status": "encode-pass", "payload_sha256": digest(payload)}
    return {
        "operation": operation,
        "operation_id": None,
        "type_id": 41,
        "type": "localize",
        "name": name,
        "zone_id": zone,
        "asset_id": asset_id,
        "index": index,
        "xasset_index": index,
        "content": "authored text",
        "content_sha256": digest(b"authored text"),
        "native_source_identity": source_identity(),
        "compiler_receipt": receipt,
        "compiler_receipt_sha256": digest(json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()),
        "writer_identity": {"path": "tools/workstation_localize.py", "sha256": "6" * 64},
    }


def make_lua_row(operation="append", *, name="ui/new.lua", index=None, payload=b"luac\0") -> dict:
    row = make_row(operation, name=name, index=index, payload=payload)
    row.update(type_id=62, type="luafile")
    row["operation_id"] = None
    row["writer_identity"] = {"path": "tools/workstation_luafile_operations.py",
                              "sha256": "7" * 64}
    row["native_source_identity"] = {
        **source_identity(),
        "writer_module_path": "tools/workstation_luafile_operations.py",
        "writer_module_sha256": "7" * 64,
    }
    receipt = {"status": "target-lua-loadx-reload-pass",
               "asset_name": name,
               "source": {"sha256": digest(b"authored text")},
               "result": {"native_payload_sha256": digest(payload)}}
    row["compiler_receipt"] = receipt
    row["compiler_receipt_sha256"] = digest(json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    return row


class AssetOperationStoreTests(unittest.TestCase):
    def test_append_snapshot_is_discovered_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            machine_cache = Path(directory)
            cache = machine_cache / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            payload = b"native localize append packet"
            row = stage_operation(cache, make_row(payload=payload), payload)
            current = cache / "pending-edits" / row["operation_id"] / "current.json"
            loaded, loaded_payload = validate_operation(cache, current, source_identity())
            self.assertEqual(loaded, row)
            self.assertEqual(loaded_payload, payload)
            snapshot = pending_snapshot(machine_cache)
            self.assertIn(current.relative_to(machine_cache).as_posix(), snapshot)
            self.assertEqual(len(snapshot), 3)  # current, immutable revision, payload

    def test_remove_uses_stable_source_index_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            row = stage_operation(cache, make_row("remove", name="existing/key", index=321), b"remove request")
            self.assertEqual(row["operation_id"], "op-r-321")
            self.assertEqual(row["asset_id"], "eng_code_post_gfx:321")
            with self.assertRaisesRegex(ValueError, "escapes the cache"):
                validate_operation(cache, Path(directory) / "../outside/current.json")

    def test_luafile_append_and_remove_have_distinct_safe_operation_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            payload = b"\x1bLJ\x02\x08native\0"
            appended = stage_operation(cache, make_lua_row(payload=payload), payload)
            self.assertEqual(appended["operation_id"], "op-a-l-" + digest(b"ui/new.lua")[:32])
            self.assertEqual(appended["asset_id"], "eng_code_post_gfx:new-" + digest(b"ui/new.lua")[:32])
            current = cache / "pending-edits" / appended["operation_id"] / "current.json"
            loaded, loaded_payload = validate_operation(cache, current, appended["native_source_identity"])
            self.assertEqual(loaded, appended)
            self.assertEqual(loaded_payload, payload)

            removal = stage_operation(cache, make_lua_row("remove", name="ui/old.lua",
                                                          index=123, payload=payload), payload)
            self.assertEqual(removal["operation_id"], "op-r-123")
            self.assertEqual(removal["type_id"], 62)

    def test_revision_update_requires_exact_cas_and_retains_history(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            first = stage_operation(cache, make_row(), b"payload one")
            with self.assertRaisesRegex(ValueError, "stale operation revision"):
                stage_operation(cache, make_row(), b"payload two", expected_revision="0" * 64)
            updated_input = make_row(payload=b"payload two")
            updated_input["content"] = "edited text"
            updated_input["content_sha256"] = digest(b"edited text")
            updated_input["compiler_receipt"] = {"status": "encode-pass", "payload_sha256": digest(b"payload two")}
            updated_input["compiler_receipt_sha256"] = digest(json.dumps(
                updated_input["compiler_receipt"], sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode())
            second = stage_operation(cache, updated_input, b"payload two", expected_revision=first["revision"])
            self.assertNotEqual(first["revision"], second["revision"])
            folder = cache / "pending-edits" / first["operation_id"]
            self.assertTrue((folder / f"{first['revision']}.json").is_file())
            self.assertTrue((folder / f"{second['revision']}.json").is_file())
            current, payload = validate_operation(cache, folder / "current.json")
            self.assertEqual(current, second)
            self.assertEqual(payload, b"payload two")

    def test_payload_current_source_and_receipt_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            row = stage_operation(cache, make_row(), b"good")
            folder = cache / "pending-edits" / row["operation_id"]
            payload_path = folder / row["payload_name"]
            payload_path.write_bytes(b"evil")
            with self.assertRaisesRegex(ValueError, "payload bytes"):
                validate_operation(cache, folder / "current.json")
            payload_path.write_bytes(b"good")
            with self.assertRaisesRegex(ValueError, "source identity is stale"):
                validate_operation(cache, folder / "current.json", {**source_identity(), "body_sha256": "0" * 64})
            altered = json.loads((folder / "current.json").read_text())
            altered["compiler_receipt"]["status"] = "tampered"
            (folder / "current.json").write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "compiler receipt hash is invalid"):
                validate_operation(cache, folder / "current.json")

    def test_unsupported_schema_or_kind_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            row = make_row()
            row["operation"] = "replace"
            with self.assertRaisesRegex(ValueError, "unsupported asset operation"):
                stage_operation(cache, row, b"payload")
            row = make_row()
            row["schema"] = 99
            with self.assertRaisesRegex(ValueError, "unsupported asset operation schema"):
                stage_operation(cache, row, b"payload")

    def test_discard_requires_current_revision_and_keeps_history(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "fastfiles/source-stem/eng_code_post_gfx"
            cache.mkdir(parents=True)
            row = stage_operation(cache, make_row(), b"payload")
            with self.assertRaisesRegex(ValueError, "stale operation revision"):
                discard_operation(cache, row["operation_id"], "f" * 64)
            marker = discard_operation(cache, row["operation_id"], row["revision"])
            folder = cache / "pending-edits" / row["operation_id"]
            self.assertTrue(marker["discarded"])
            self.assertFalse((folder / "current.json").exists())
            self.assertTrue((folder / f"{row['revision']}.json").is_file())
            self.assertTrue((folder / row["payload_name"]).is_file())
            self.assertTrue((folder / f"{row['revision']}.discarded.json").is_file())

    def test_symlinked_operation_folder_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as elsewhere:
            cache = Path(directory) / "eng_code_post_gfx"
            cache.mkdir(parents=True)
            actual = Path(elsewhere) / "target"
            actual.mkdir()
            parent = cache / "pending-edits"
            parent.mkdir(parents=True)
            row = make_row()
            operation_id = "op-a-" + digest(row["name"].encode())[:32]
            link = parent / operation_id
            try:
                link.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable")
            with self.assertRaisesRegex(ValueError, "symlink or junction"):
                stage_operation(cache, row, b"payload")


if __name__ == "__main__":
    unittest.main()
