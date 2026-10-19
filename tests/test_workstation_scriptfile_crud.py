from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import workstation_scriptfile_crud as crud
import workstation_luafile_operations as luafile_ops
from workstation_asset_codecs import GSCBIN_MAGIC
from workstation_luafile_operations import INLINE_POINTER, XASSET_ROW_SIZE


def gscbin(source: bytes = b"return;\n", code: bytes = b"\x01\x02\x03\x04") -> bytes:
    compressed = zlib.compress(source)
    return struct.pack("<4I", GSCBIN_MAGIC, len(compressed), len(source), len(code)) + compressed + code


def receipt(name: str, source: str, payload: bytes) -> dict:
    return dict(schema="replay120-gsc-compile-receipt-v1", status="gsc-tool-native-payload-pass",
        asset_name=name,
        source=dict(sha256=hashlib.sha256(source.encode()).hexdigest()),
        compiler={"sha256": "0" * 64,
                  "input_name": "script_" + hashlib.sha256(name.encode()).hexdigest()[:20]},
        result=dict(native_payload_sha256=hashlib.sha256(payload).hexdigest(),
                    payload_contract="Replay ScriptFile GSCBIN after Replay local-reference scaling"),
        string_ownership={"policy": "typed-inline-only-v1", "cursor_event_count": 1,
            "bytecode_bytes": 4, "nonzero_script_string_ids": 0, "complete_cursor": True})


class ScriptFileAppendTests(unittest.TestCase):
    def _template(self, name="template"):
        source = b"return;\n"
        code = b"\x01\x02\x03\x04"
        compressed = zlib.compress(source)
        root = struct.pack("<QiiiIQQ", crud.SCRIPTFILE_NAME_INLINE,
            len(compressed), len(source), len(code), 0,
            crud.INLINE_CHILD_POINTER, crud.INLINE_CHILD_POINTER)
        encoded_name = name.encode() + b"\0"
        start = 48
        body = bytearray(16 + 2 * XASSET_ROW_SIZE)
        body.extend(root + encoded_name + compressed + code + b"TAIL")
        spans = [
            dict(origin="load_stream_call", reader_start_arg=0, archive_offset=start,
                 size=40, destination_stream_location=dict(stream=1, offset=0)),
            dict(origin="string_data", archive_offset=start + 40, size=len(encoded_name),
                 destination_stream_location=dict(stream=5, offset=10)),
            dict(origin="load_stream_call", reader_start_arg=0,
                 archive_offset=start + 40 + len(encoded_name), size=len(compressed),
                 destination_stream_location=dict(stream=6, offset=0)),
            dict(origin="load_stream_call", reader_start_arg=0,
                 archive_offset=start + 40 + len(encoded_name) + len(compressed), size=len(code),
                 destination_stream_location=dict(stream=6, offset=len(compressed))),
        ]
        return bytes(body), spans, source, code, compressed

    def test_payload_reader_selects_root_before_a_40_byte_child(self):
        source = bytes((i * 73 + 19) % 256 for i in range(31))
        compressed = zlib.compress(source)
        if len(compressed) != 40:
            self.skipTest("zlib build does not yield a 40-byte compressed source for this fixture")
        code = b"\x01\x02\x03\x04"
        name = "template"
        root = struct.pack("<QiiiIQQ", crud.SCRIPTFILE_NAME_INLINE,
            len(compressed), len(source), len(code), 0,
            crud.INLINE_CHILD_POINTER, crud.INLINE_CHILD_POINTER)
        encoded_name = name.encode() + b"\0"
        body = root + encoded_name + compressed + code
        spans = [
            dict(origin="load_stream_call", reader_start_arg=0, archive_offset=0,
                 size=40, destination_stream_location=dict(stream=1, offset=0)),
            dict(origin="string_data", archive_offset=40, size=len(encoded_name),
                 destination_stream_location=dict(stream=5, offset=0)),
            dict(origin="load_stream_call", reader_start_arg=0, archive_offset=40 + len(encoded_name),
                 size=40, destination_stream_location=dict(stream=6, offset=0)),
            dict(origin="load_stream_call", reader_start_arg=0, archive_offset=80 + len(encoded_name),
                 size=len(code), destination_stream_location=dict(stream=6, offset=40)),
        ]
        _, payload = crud._scriptfile_payload(body,
            dict(xasset_index=0, type_id=52, name=name, read_spans=spans), 0, name)
        self.assertEqual(payload, struct.pack("<4I", GSCBIN_MAGIC, 40, len(source), len(code)) + compressed + code)

    def test_payload_reader_rejects_noncontiguous_stream6_children(self):
        body, spans, _, _, _ = self._template()
        spans[-1]["destination_stream_location"]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "not contiguous"):
            crud._scriptfile_payload(body, dict(xasset_index=0, type_id=52,
                name="template", read_spans=spans), 0, "template")

    def test_compiler_receipt_binds_name_source_and_payload(self):
        source, payload = "main() {}", gscbin()
        valid = receipt("new/script", source, payload)
        with patch("workstation_gsc_fields.validate_ownership_receipt",
                   return_value=valid["string_ownership"]):
            self.assertEqual(crud._validate_compiler_receipt("new/script", source, payload, valid)["payload_sha256"],
                             hashlib.sha256(payload).hexdigest())
        with self.assertRaisesRegex(ValueError, "does not bind"):
            crud._validate_compiler_receipt("other", source, payload, valid)
        with self.assertRaisesRegex(ValueError, "does not bind"):
            crud._validate_compiler_receipt("new/script", source + " ", payload, valid)

    def test_append_writes_new_row_and_payload_after_trace_owned_exact_eof(self):
        body_data, template_spans, _, _, _ = self._template()
        source_text = "new_probe() {}"
        payload = gscbin()
        digest = hashlib.sha256(body_data).hexdigest()
        body = SimpleNamespace(source_sha256=digest,
            assets=[SimpleNamespace(type_id=52, pointer_token=INLINE_POINTER),
                    SimpleNamespace(type_id=20, pointer_token=INLINE_POINTER)],
            asset_table_offset=16, first_payload_offset=48)
        reparsed = SimpleNamespace(assets=[*body.assets,
            SimpleNamespace(type_id=52, pointer_token=INLINE_POINTER)])
        final_span = dict(archive_offset=len(body_data)-4, size=4)
        final = dict(xasset_index=1, type_id=20, end_cursor=len(body_data),
                     read_spans=[final_span])
        table = dict(size=2 * XASSET_ROW_SIZE, archive=16, end=48)
        contract = ({}, {}, [], [], table, {5: 20}, 0, {}, {}, {})
        with tempfile.TemporaryDirectory() as temp:
            trace, manifest = Path(temp)/"trace", Path(temp)/"manifest"
            trace.write_bytes(b"trace")
            manifest.write_bytes(b"manifest")
            with patch("workstation_gsc_fields.validate_ownership_receipt",
                       return_value=receipt("new/script", source_text, payload)["string_ownership"]), \
                 patch.object(crud.ZoneBody, "parse", side_effect=[body, reparsed]), \
                 patch.object(crud, "_trace_contract", return_value=contract), \
                 patch.object(crud, "_rebase_aliases", return_value=(body_data, {"packed_alias_fields_rebased": 0})):
                output, proof = crud.append_scriptfile_tail(bytes(body_data), "new/script", source_text,
                    payload, receipt("new/script", source_text, payload), {"template"}, 0, "template",
                    dict(xasset_index=0, type_id=52, name="template", read_spans=template_spans),
                    final, digest, trace, manifest)
        self.assertEqual(proof["status"], "trace-owned-scriptfile-append-candidate")
        self.assertEqual(proof["asset_index"], 2)
        self.assertEqual(len(output), len(body_data) + XASSET_ROW_SIZE + 40 + len("new/script") + 1 + len(payload) - 16)

    def test_name_rejects_path_escape_and_existing_identity(self):
        for name in ("", "../x", "x/../y", "/root", "a\\b", "a\0b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                crud._safe_name(name)


class ScriptFileRemovalWriterTests(unittest.TestCase):
    def test_transaction_helper_source_drift_is_rejected(self):
        before = {"writer": "1" * 64, "native_verifier": "2" * 64}
        crud._assert_helper_sources_unchanged(before, dict(before))
        changed = dict(before, native_verifier="3" * 64)
        with self.assertRaisesRegex(ValueError, "helper sources changed"):
            crud._assert_helper_sources_unchanged(before, changed)

    def _fixture(self, *, name="remove_me", index=0, following_asset=True):
        source = b"return;\n"
        code = b"\x01\x02\x03\x04"
        compressed = zlib.compress(source)
        encoded_name = name.encode() + b"\0"
        root = struct.pack("<QiiiIQQ", crud.SCRIPTFILE_NAME_INLINE,
            len(compressed), len(source), len(code), 0,
            crud.INLINE_CHILD_POINTER, crud.INLINE_CHILD_POINTER)
        asset_count = 2 if following_asset else 1
        table = bytearray(32 + asset_count * XASSET_ROW_SIZE)
        struct.pack_into("<I", table, 16, asset_count)
        struct.pack_into("<IIQ", table, 32, 52, 0, INLINE_POINTER)
        if following_asset:
            struct.pack_into("<IIQ", table, 32 + XASSET_ROW_SIZE, 20, 0, INLINE_POINTER)
        body_data = bytes(table) + root + encoded_name + compressed + code
        body_sha = hashlib.sha256(body_data).hexdigest()
        body_assets = [SimpleNamespace(type_id=52, pointer_token=INLINE_POINTER)]
        if following_asset:
            body_assets.append(SimpleNamespace(type_id=20, pointer_token=INLINE_POINTER))
        body = SimpleNamespace(source_sha256=body_sha, data=body_data, assets=body_assets,
            asset_table_offset=32, first_payload_offset=len(table))
        reparsed = SimpleNamespace(assets=body.assets[1:] if following_asset else [])
        start = len(table)
        spans = [
            dict(origin="load_stream_call", reader_start_arg=0, archive_offset=start,
                 size=40, destination_stream_location=dict(stream=1, offset=0)),
            dict(origin="string_data", archive_offset=start + 40, size=len(encoded_name),
                 destination_stream_location=dict(stream=5, offset=0)),
            dict(origin="load_stream_call", reader_start_arg=0,
                 archive_offset=start + 40 + len(encoded_name), size=len(compressed),
                 destination_stream_location=dict(stream=6, offset=0)),
            dict(origin="load_stream_call", reader_start_arg=0,
                 archive_offset=start + 40 + len(encoded_name) + len(compressed), size=len(code),
                 destination_stream_location=dict(stream=6, offset=len(compressed))),
        ]
        intervals = [dict(owner=0, archive=s["archive_offset"], size=s["size"])
                     for s in spans]
        table_alloc = dict(size=asset_count * XASSET_ROW_SIZE, archive=32, end=len(table))
        contract = ({}, {}, intervals, [], table_alloc, {1: 40, 5: len(encoded_name), 6: len(compressed)+len(code)},
                    0, {}, {}, {})
        trace_asset = dict(xasset_index=index, type_id=52, name=name, read_spans=spans)
        return body_data, body_sha, body, reparsed, contract, trace_asset, compressed, code

    def test_nonfinal_removal_is_outside_supported_scope(self):
        body_data, body_sha, body, _reparsed, _contract, trace_asset, _compressed, _code = self._fixture()
        with patch.object(crud.ZoneBody, "parse", return_value=body):
            with self.assertRaisesRegex(ValueError, "exact final XAsset row"):
                crud.remove_existing_scriptfile_row(body_data, 0, "remove_me", trace_asset,
                    body_sha, "unused-trace", "unused-manifest")

    def test_removes_final_row_and_exact_root_name_stream6_extent(self):
        body_data, body_sha, body, reparsed, contract, trace_asset, compressed, code = self._fixture(following_asset=False)
        with tempfile.TemporaryDirectory() as temp:
            trace, manifest = Path(temp) / "trace.jsonl", Path(temp) / "manifest.json"
            trace.write_text("trace", encoding="utf-8")
            manifest.write_text("manifest", encoding="utf-8")
            with patch.object(crud.ZoneBody, "parse", side_effect=[body, reparsed]), \
                 patch.object(luafile_ops, "_trace_contract", return_value=contract), \
                 patch.object(luafile_ops, "_rebase_aliases", return_value=(body_data, {"packed_alias_fields_rebased": 1})) as rebase:
                output, proof = crud.remove_existing_scriptfile_row(
                    body_data, 0, "remove_me", trace_asset, body_sha, trace, manifest)
        self.assertEqual(proof["operation"], "remove")
        self.assertEqual(proof["removed_root_bytes"], 40)
        self.assertEqual(proof["removed_name_bytes"], len(b"remove_me\0"))
        self.assertEqual(proof["removed_stream6_bytes"], len(compressed) + len(code))
        self.assertEqual(proof["output_asset_count"], 0)
        self.assertLess(len(output), len(body_data))
        self.assertEqual(rebase.call_args.kwargs["removed_stream_ranges"],
                         ((1, 0, 40), (5, 0, len(b"remove_me\0")),
                          (6, 0, len(compressed) + len(code))))

    def test_root_only_sentinel_is_never_removable(self):
        body_data, body_sha, body, _reparsed, _contract, trace_asset, *_ = self._fixture(
            name="$default", following_asset=False)
        trace_asset["name"] = "$default"
        with patch.object(crud.ZoneBody, "parse", return_value=body):
            with self.assertRaisesRegex(ValueError, "sentinel"):
                crud.remove_existing_scriptfile_row(body_data, 0, "$default", trace_asset,
                    body_sha, "unused-trace", "unused-manifest")

    def test_inbound_reference_into_name_or_stream6_fails_closed(self):
        body_data, body_sha, body, reparsed, contract, trace_asset, _compressed, _code = self._fixture(following_asset=False)
        with tempfile.TemporaryDirectory() as temp:
            trace, manifest = Path(temp) / "trace.jsonl", Path(temp) / "manifest.json"
            trace.write_text("trace", encoding="utf-8")
            manifest.write_text("manifest", encoding="utf-8")
            with patch.object(crud.ZoneBody, "parse", side_effect=[body]), \
                 patch.object(luafile_ops, "_trace_contract", return_value=contract), \
                 patch.object(luafile_ops, "_rebase_aliases", side_effect=ValueError("inbound alias targets removed extent")):
                with self.assertRaisesRegex(ValueError, "inbound alias"):
                    crud.remove_existing_scriptfile_row(body_data, 0, "remove_me", trace_asset,
                        body_sha, trace, manifest)


if __name__ == "__main__":
    unittest.main()
