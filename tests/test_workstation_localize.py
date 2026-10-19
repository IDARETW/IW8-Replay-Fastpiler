from __future__ import annotations

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_localize import (
    INLINE, SHARED_INLINE, LOCALIZE_TYPE_ID, LocalizeReadContext, append_localize_entry,
    _rebase_stream5_after_table_growth,
    remove_appended_localize_entry, remove_localize_entry,
    inspect_localize_entry, replace_localize_value_same_extent,
    replace_localize_values_same_extent, replace_localize_values_with_relocation,
)
from workstation_fastfiles import ZoneBody


def _tiny_body() -> bytes:
    # XAssetList root, one inline row and one 16-byte root + two strings.
    key, value = b"test/key\0", b"old\0"
    table_at = 32
    row_at = table_at
    payload_at = row_at + 16
    return (struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, INLINE) +
            struct.pack("<IIQ", LOCALIZE_TYPE_ID, 0, INLINE) +
            struct.pack("<QQ", INLINE, INLINE) + key + value)


def _native_trace_fixture(body: bytes, count: int, directory: Path) -> tuple[Path, Path]:
    events = []
    events.append({"kind": "stream_operation", "operation": "align",
                   "block_before": 5, "offset_before": 0,
                   "block_after": 5, "offset_after": 0})
    for index in range(count):
        events.append({"kind": "xasset_begin", "xasset_index": index,
                       "asset_type": LOCALIZE_TYPE_ID,
                       "table_entry_stream_location": {"stream": 5, "offset": index * 16}})
        events.append({"kind": "begin_asset_call", "xasset_index": index})
        events.append({"kind": "xasset_end", "xasset_index": index})
    trace_path = directory / "trace.jsonl"
    manifest_path = directory / "manifest.json"
    trace_path.write_text("".join(json.dumps({**event, "sequence": seq}) + "\n"
                                    for seq, event in enumerate(events)), encoding="utf-8")
    manifest_path.write_text(json.dumps({
        "profile": "replay-1.20", "complete": True, "success": True,
        "xfile_version": 0xFF7, "serialized_bytes_read": len(body),
        "tested": count, "top_level_index": count,
        "stream_trace_events": len(events),
    }), encoding="utf-8")
    return trace_path, manifest_path


def _two_localize_entries() -> tuple[bytes, list[dict]]:
    """Build two exact inline Localize records and matching native span rows."""
    rows = [("test/a", "oldA"), ("test/b", "oldB")]
    header = struct.pack("<IIQIIQ", 0, 0, 0, len(rows), 0, INLINE)
    table = b"".join(struct.pack("<IIQ", LOCALIZE_TYPE_ID, 0, INLINE) for _ in rows)
    cursor = len(header) + len(table)
    body_parts = [header, table]
    trace_rows = []
    stream5 = 0
    for index, (key, value) in enumerate(rows):
        root_at = cursor
        key_bytes, value_bytes = key.encode() + b"\0", value.encode() + b"\0"
        key_at = root_at + 16
        value_at = key_at + len(key_bytes)
        body_parts.extend((struct.pack("<QQ", INLINE, INLINE), key_bytes, value_bytes))
        end = value_at + len(value_bytes)
        trace_rows.append({
            "index": index, "type_id": LOCALIZE_TYPE_ID, "name": key,
            "end_cursor": end,
            "read_spans": [
                {"origin": "load_stream_call", "reader_start_arg": 0,
                 "size": 16, "caller_rva": 0xE047AD,
                 "archive_offset": root_at,
                 "destination_stream_location": {"stream": 1, "offset": 0}},
                {"origin": "string_data", "archive_offset": key_at,
                 "size": len(key_bytes),
                 "destination_stream_location": {"stream": 5, "offset": stream5}},
                {"origin": "string_data", "archive_offset": value_at,
                 "size": len(value_bytes),
                 "destination_stream_location": {"stream": 5, "offset": stream5 + len(key_bytes)}},
            ],
        })
        cursor = end
        stream5 += len(key_bytes) + len(value_bytes)
    return b"".join(body_parts), trace_rows


def _two_localize_native_trace(body: bytes, directory: Path,
                               alias_into_first: bool = False,
                               alias_target: tuple[int, int] = (5, 32)) -> tuple[Path, Path, list[dict]]:
    """Trace fixture with distinct table, stream-1 roots and stream-5 strings."""
    rows = [("test/a", "oldA"), ("test/b", "oldB")]
    table_start = 0
    stream5 = 32
    physical = 32 + 2 * 16
    events = [dict(kind="stream_operation", operation="load", block_before=5,
                   offset_before=0, input_before=32, block_after=5,
                   offset_after=32, size=32, physical_input_bytes=32)]
    trace_rows = []
    body_parts = [body[:32], body[32:64]]
    asset0_root = None
    for index, (key, value) in enumerate(rows):
        key_bytes, value_bytes = key.encode() + b"\0", value.encode() + b"\0"
        row_spans = []
        events.append(dict(kind="xasset_begin", xasset_index=index, asset_type=41,
                           table_entry_stream_location={"stream": 5, "offset": index * 16}))
        events.append(dict(kind="begin_asset_call", xasset_index=index))
        if index == 0:
            asset0_root = physical
        root_bytes = struct.pack("<QQ", INLINE, INLINE)
        if alias_into_first and index == 1:
            target_stream, target_offset = alias_target
            tag = 5 if target_stream == 5 else 0x15
            root_bytes = struct.pack("<QQ", (tag << 32) | (target_offset + 1), INLINE)
        root_at = physical
        body_parts.append(root_bytes)
        events.append(dict(kind="stream_operation", operation="load", block_before=1,
                           offset_before=0, input_before=physical, block_after=1,
                           offset_after=16, size=16, physical_input_bytes=16,
                           xasset_index=index))
        row_spans.append(dict(origin="load_stream_call", reader_start_arg=0,
                              size=16, caller_rva=0xE047AD, archive_offset=root_at,
                              destination_stream_location={"stream": 1, "offset": 0}))
        physical += 16
        for raw, content in ((key, key_bytes), (value, value_bytes)):
            events.append(dict(kind="stream_operation", operation="load", block_before=5,
                               offset_before=stream5, input_before=physical,
                               block_after=5, offset_after=stream5 + len(content),
                               size=len(content), physical_input_bytes=len(content),
                               xasset_index=index))
            row_spans.append(dict(origin="string_data", archive_offset=physical,
                                  size=len(content), destination_stream_location={
                                      "stream": 5, "offset": stream5}))
            body_parts.append(content)
            stream5 += len(content)
            physical += len(content)
        trace_rows.append(dict(index=index, type_id=41, name=key,
                               end_cursor=physical, read_spans=row_spans))
        if alias_into_first and index == 1:
            events.append(dict(kind="packed_alias", xasset_index=1,
                               raw_token=((5 if alias_target[0] == 5 else 0x15) << 32) |
                                         (alias_target[1] + 1),
                               field_stream_location={"stream": 1, "offset": 0},
                               resolved_target_stream_location={"stream": alias_target[0],
                                                                "offset": alias_target[1]}))
        events.append(dict(kind="xasset_end", xasset_index=index))
    trace_path, manifest_path = directory / "trace.jsonl", directory / "manifest.json"
    trace_path.write_text("".join(json.dumps({**event, "sequence": n}) + "\n"
                                               for n, event in enumerate(events)), encoding="utf-8")
    manifest_path.write_text(json.dumps(dict(profile="replay-1.20", complete=True,
        success=True, xfile_version=0xFF7, serialized_bytes_read=physical,
        tested=2, top_level_index=2, stream_trace_events=len(events),
        stream_trace_sha256=hashlib.sha256(trace_path.read_bytes()).hexdigest())), encoding="utf-8")
    return trace_path, manifest_path, trace_rows


def _shared_value_trace(directory: Path) -> tuple[bytes, list[dict], Path, Path]:
    """Three keys: owned shared text, its alias, and an alias past that text."""
    names = [b"test/a\0", b"test/b\0", b"test/c\0"]
    table = b"".join(struct.pack("<IIQ", 41, 0, INLINE) for _ in names)
    parts = [struct.pack("<IIQIIQ", 0, 0, 0, 3, 0, INLINE), table]
    physical, logical = 32 + len(table), len(table)
    target_value = logical + len(names[0])
    target_second_key = target_value + len(b"oldA\0")
    tokens = [SHARED_INLINE, (5 << 32) | (target_value + 1),
              (5 << 32) | (target_second_key + 1)]
    events = [dict(kind="stream_operation", operation="load", block_before=5,
                   offset_before=0, block_after=5, offset_after=logical,
                   input_before=32, size=len(table), physical_input_bytes=len(table))]
    rows = []
    for index, (name, token) in enumerate(zip(names, tokens)):
        events.extend([dict(kind="xasset_begin", xasset_index=index),
                       dict(kind="begin_asset_call", xasset_index=index)])
        root_at = physical
        events.extend([
            dict(kind="load_stream_call", xasset_index=index, loader_start_arg=0,
                 at_start=True, caller_rva=0xE047AD,
                 destination_stream_location=dict(stream=1, offset=0)),
            dict(kind="stream_operation", operation="load", xasset_index=index,
                 block_before=1, offset_before=0, block_after=1, offset_after=16,
                 input_before=physical, size=16, physical_input_bytes=16)])
        spans = [dict(origin="load_stream_call", reader_start_arg=0, size=16,
                      caller_rva=0xE047AD, archive_offset=physical,
                      destination_stream_location=dict(stream=1, offset=0))]
        parts.append(struct.pack("<QQ", INLINE, token))
        physical += 16
        strings = [name, b"oldA\0"] if index == 0 else [name]
        for text in strings:
            common = dict(kind="stream_operation", xasset_index=index,
                          block_before=5, offset_before=logical, block_after=5,
                          input_before=physical, size=len(text))
            events.extend([dict(**common, operation="string", offset_after=logical,
                                physical_input_bytes=0),
                           dict(**common, operation="load", offset_after=logical + len(text),
                                physical_input_bytes=len(text))])
            spans.append(dict(origin="string_data", size=len(text), archive_offset=physical,
                              destination_stream_location=dict(stream=5, offset=logical)))
            parts.append(text)
            physical += len(text)
            logical += len(text)
        if index:
            events.append(dict(kind="packed_resolve", xasset_index=index, type_id=41,
                               raw_token=token, root_stream_location=dict(stream=1, offset=0),
                               field_stream_location=dict(stream=1, offset=8),
                               resolved_target_stream_location=dict(stream=5, offset=(token & 0xFFFFFFFF) - 1),
                               stream_block=5, serialized_input_cursor=physical))
        events.append(dict(kind="xasset_end", xasset_index=index,
                           serialized_input_cursor=physical))
        rows.append(dict(index=index, name=name[:-1].decode(), type_id=41,
                         end_cursor=physical, read_spans=spans, root_at=root_at))
    body = b"".join(parts)
    trace, manifest = directory / "trace.jsonl", directory / "manifest.json"
    trace.write_text("".join(json.dumps(dict(event, sequence=i)) + "\n"
                              for i, event in enumerate(events)), encoding="utf-8")
    manifest.write_text(json.dumps(dict(profile="replay-1.20", xfile_version=0xFF7,
                                       complete=True, success=True, tested=3, top_level_index=3,
                                       serialized_bytes_read=len(body), stream_trace_events=len(events))),
                        encoding="utf-8")
    return body, rows, trace, manifest


class WorkstationLocalizeTests(unittest.TestCase):
    def test_shared_values_preserve_other_keys_for_equal_growing_and_shrinking_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            body, rows, trace, manifest = _shared_value_trace(Path(temporary))
            for text in ("newA", "a longer localized value", ""):
                with self.subTest(text=text):
                    updated, proof = replace_localize_values_with_relocation(
                        body, [dict(asset_index=0, asset_name="test/a", trace_asset=rows[0], value=text)],
                        hashlib.sha256(body).hexdigest(), trace, manifest)
                    delta = len(text.encode()) - len("oldA")
                    second_root = rows[1]["root_at"] + delta
                    third_root = rows[2]["root_at"] + delta + 5
                    self.assertEqual(struct.unpack_from("<Q", updated, second_root + 8)[0], INLINE)
                    self.assertEqual(updated[second_root + 16:third_root], b"test/b\0oldA\0")
                    # A packed target beyond the edited child also moves, even
                    # when its referring field follows an inserted inline copy.
                    self.assertEqual(struct.unpack_from("<Q", updated, third_root + 8)[0],
                                     (5 << 32) | (61 + delta))
                    self.assertEqual(proof["shared_localize_values_preserved"][0]["asset_index"], 1)
                    self.assertEqual(len(updated) - len(body), delta + 5)
                    self.assertEqual(ZoneBody.parse(updated).assets, ZoneBody.parse(body).assets)
            unchanged, proof = replace_localize_values_with_relocation(
                body, [dict(asset_index=0, asset_name="test/a", trace_asset=rows[0], value="oldA")],
                hashlib.sha256(body).hexdigest(), trace, manifest)
            self.assertEqual(unchanged, body)
            self.assertEqual(proof["status"], "semantic-noop-localize-batch")

    def test_shared_value_copy_rejects_substrings_untyped_fields_and_bad_end_cursors(self):
        with tempfile.TemporaryDirectory() as temporary:
            body, rows, trace, manifest = _shared_value_trace(Path(temporary))
            events = [json.loads(line) for line in trace.read_text().splitlines()]
            alias_at = next(i for i, event in enumerate(events)
                            if event["kind"] == "packed_resolve" and event["xasset_index"] == 1)
            for mutation in (dict(type_id=52), dict(field_stream_location=dict(stream=1, offset=0)),
                             dict(resolved_target_stream_location=dict(stream=5, offset=56)),
                             dict(serialized_input_cursor=0)):
                changed = [dict(event) for event in events]
                changed[alias_at].update(mutation)
                trace.write_text("".join(json.dumps(event) + "\n" for event in changed))
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "semantics are unproven"):
                    replace_localize_values_with_relocation(
                        body, [dict(asset_index=0, asset_name="test/a", trace_asset=rows[0], value="newA")],
                        hashlib.sha256(body).hexdigest(), trace, manifest)

    def test_read_context_rejects_another_body_and_mutable_bytes(self) -> None:
        body = _tiny_body()
        context = LocalizeReadContext(body)
        with self.assertRaisesRegex(ValueError, "not bound to this immutable body"):
            inspect_localize_entry(body + b"x", 0, "test/key", {}, context=context)
        with self.assertRaisesRegex(TypeError, "requires immutable bytes"):
            LocalizeReadContext(bytearray(body))
        with self.assertRaises(FrozenInstanceError):
            context.body_data = body + b"x"
        with self.assertRaises(FrozenInstanceError):
            context.body = ZoneBody.parse(body)

    def test_append_table_growth_absorbed_by_32_byte_stream_alignment(self):
        # The original table ends at stream-5 offset 16. Its next 32-byte
        # alignment moves the cursor to 32. Growing the table by one row moves
        # the pre-alignment cursor to 32, so the alignment absorbs the growth
        # and the later stream-5 target remains at offset 32.
        raw_target = (5 << 32) | 33
        header = struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, INLINE)
        table = struct.pack("<IIQ", LOCALIZE_TYPE_ID, 0, INLINE)
        root = struct.pack("<QQ", raw_target, INLINE)
        body = header + table + root + b"k\0v\0"
        events = [
            dict(kind="stream_operation", operation="load", block_before=5,
                 offset_before=0, block_after=5, offset_after=16, size=16,
                 physical_input_bytes=16, input_before=32),
            dict(kind="stream_operation", operation="align", block_before=5,
                 offset_before=16, block_after=5, offset_after=32, value=31),
            dict(kind="xasset_begin", xasset_index=0, asset_type=LOCALIZE_TYPE_ID),
            dict(kind="begin_asset_call", xasset_index=0),
            dict(kind="stream_operation", operation="load", block_before=1,
                 offset_before=0, block_after=1, offset_after=16, size=16,
                 physical_input_bytes=16, input_before=48, xasset_index=0),
            dict(kind="packed_alias", xasset_index=0, raw_token=raw_target,
                 field_stream_location={"stream": 1, "offset": 0},
                 resolved_target_stream_location={"stream": 5, "offset": 32}),
            dict(kind="stream_operation", operation="load", block_before=5,
                 offset_before=32, block_after=5, offset_after=34, size=2,
                 physical_input_bytes=2, input_before=64, xasset_index=0),
            dict(kind="stream_operation", operation="load", block_before=5,
                 offset_before=34, block_after=5, offset_after=36, size=2,
                 physical_input_bytes=2, input_before=66, xasset_index=0),
            dict(kind="xasset_end", xasset_index=0),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            trace = root_path / "trace.jsonl"
            manifest = root_path / "manifest.json"
            trace.write_text("".join(json.dumps(dict(event, sequence=seq)) + "\n"
                                          for seq, event in enumerate(events)), encoding="utf-8")
            manifest.write_text(json.dumps(dict(profile="replay-1.20", complete=True,
                success=True, xfile_version=0xFF7, serialized_bytes_read=len(body),
                tested=1, top_level_index=1, stream_trace_events=len(events),
                stream_trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())),
                encoding="utf-8")
            changed, proof = _rebase_stream5_after_table_growth(
                body, trace, manifest, table_growth=16, delta=16)
        self.assertEqual(changed, body)
        self.assertEqual(struct.unpack_from("<Q", changed, len(header) + len(table))[0],
                         raw_target)
        self.assertEqual(proof["aliases_rebased"], 0)
        self.assertEqual(proof["aliases_scanned"], 1)

    def test_production_table_splice_rejects_unbound_trace_and_unmapped_shrink(self):
        body = (struct.pack("<IIQIIQ", 0, 0, 0, 3, 0, INLINE) +
                b"".join(struct.pack("<IIQ", LOCALIZE_TYPE_ID, 0, INLINE)
                         for _ in range(3)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            trace.write_text("", encoding="utf-8")
            manifest = root / "manifest.json"
            document = dict(profile="replay-1.20", complete=True, success=True,
                            xfile_version=0xFF7, serialized_bytes_read=len(body),
                            tested=3, top_level_index=3, stream_trace_events=0)
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "trace-bound native manifest"):
                append_localize_entry(body, "test/new", "value",
                    [0, 0, 0, 0, 0, 48, 0, 0, 0, 0, 0], {1: 0, 5: 48},
                    hashlib.sha256(body).hexdigest(), trace, manifest)
            document["stream_trace_sha256"] = hashlib.sha256(b"").hexdigest()
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mapped-delete semantics"):
                _rebase_stream5_after_table_growth(body, trace, manifest, 48, -16)

    def test_append_rebases_the_owned_scratch_field_and_rejects_partial_overwrite(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous), tempfile.TemporaryDirectory() as temporary:
                original, _ = _two_localize_entries()
                trace, manifest, spans = _two_localize_native_trace(
                    original, Path(temporary), alias_into_first=True)
                field = spans[1]['read_spans'][0]['archive_offset']
                original = bytearray(original)
                struct.pack_into('<Q', original, field, (5 << 32) | 33)
                original = bytes(original)
                if ambiguous:
                    events = [json.loads(line) for line in trace.read_text().splitlines()]
                    position = next(i for i, event in enumerate(events)
                                    if event.get('operation') == 'load' and
                                    event.get('xasset_index') == 1 and event.get('block_before') == 1)
                    # The mapper follows the latest complete scratch load.
                    # A later partial overwrite of this eight-byte field has
                    # no single complete physical owner and must be rejected.
                    conflicting = dict(events[position])
                    conflicting.update(size=4, physical_input_bytes=4, offset_after=4)
                    events.insert(position + 1, conflicting)
                    trace.write_text(''.join(json.dumps(dict(event, sequence=i)) + '\n'
                                             for i, event in enumerate(events)))
                    document = json.loads(manifest.read_text())
                    document['stream_trace_events'] = len(events)
                    document['stream_trace_sha256'] = hashlib.sha256(trace.read_bytes()).hexdigest()
                    manifest.write_text(json.dumps(document))
                arguments = (original, 'test/new', 'new value',
                             [0, 16, 0, 0, 0, 56, 0, 0, 0, 0, 0],
                             {1: 16, 5: 56}, hashlib.sha256(original).hexdigest(), trace, manifest)
                if ambiguous:
                    with self.assertRaisesRegex(ValueError, 'partially overwritten'):
                        append_localize_entry(*arguments)
                else:
                    updated, _, proof = append_localize_entry(*arguments)
                    self.assertEqual(struct.unpack_from('<Q', updated, field + 16)[0], (5 << 32) | 49)
                    self.assertEqual(updated[64 + 16:64 + 32], original[64:80])
                    self.assertEqual(proof['stream5_pointer_relocation']['aliases_rebased'], 1)

    def test_append_rejects_incomplete_synthetic_table_trace(self) -> None:
        original = _tiny_body()
        reservations = [0, 16, 0, 0, 0, 32, 0, 0, 0, 0, 0]
        with tempfile.TemporaryDirectory() as temporary:
            trace, manifest = _native_trace_fixture(original, 1, Path(temporary))
            with self.assertRaisesRegex(ValueError, "trace-bound native manifest"):
                append_localize_entry(original, "test/new", "new value", reservations,
                    {1: 16, 5: 32}, hashlib.sha256(original).hexdigest(), trace, manifest)

    def test_same_extent_value_replacement_and_reject_extent_change(self) -> None:
        body = _tiny_body()
        root_at = 48
        key_at = root_at + 16
        value_at = key_at + len(b"test/key\0")
        body = bytearray(body)
        struct.pack_into("<QQ", body, root_at, INLINE, INLINE)
        body = bytes(body)
        trace = {
            "index": 0, "type_id": LOCALIZE_TYPE_ID, "name": "test/key",
            "end_cursor": len(body),
            "read_spans": [
                {"origin": "load_stream_call", "reader_start_arg": 0, "size": 16,
                 "caller_rva": 0xE047AD, "archive_offset": root_at,
                 "destination_stream_location": {"stream": 1, "offset": 0}},
                {"origin": "string_data", "archive_offset": key_at,
                 "size": len(b"test/key\0"),
                 "destination_stream_location": {"stream": 5, "offset": 0}},
                {"origin": "string_data", "archive_offset": value_at,
                 "size": len(b"old\0"),
                 "destination_stream_location": {"stream": 5, "offset": 9}},
            ],
        }
        result, proof = replace_localize_value_same_extent(
            body, 0, "test/key", trace, "new", hashlib.sha256(body).hexdigest(),
            expected_key="test/key", expected_value="old")
        self.assertEqual(result[value_at:value_at + 4], b"new\0")
        self.assertEqual(proof["body_extent_unchanged"], True)
        with self.assertRaisesRegex(ValueError, "changes its native stream-5 extent"):
            replace_localize_value_same_extent(
                body, 0, "test/key", trace, "longer", hashlib.sha256(body).hexdigest())

    def test_shared_inline_xstrings_are_owned_editable_and_preserved(self) -> None:
        original, traces = _two_localize_entries()
        root_at = traces[0]["read_spans"][0]["archive_offset"]
        for key_token in (INLINE, SHARED_INLINE):
            for value_token in (INLINE, SHARED_INLINE):
                with self.subTest(key=key_token, value=value_token):
                    body = bytearray(original)
                    struct.pack_into("<QQ", body, root_at, key_token, value_token)
                    body = bytes(body)
                    digest = hashlib.sha256(body).hexdigest()
                    layout, values = inspect_localize_entry(body, 0, "test/a", traces[0], digest)
                    self.assertEqual(values, {"key": "test/a", "value": "oldA"})
                    changed, _ = replace_localize_value_same_extent(
                        body, 0, "test/a", traces[0], "newA", digest)
                    self.assertEqual(changed[root_at:root_at + 16], body[root_at:root_at + 16])
                    self.assertEqual(changed[layout.value_archive_offset:layout.archive_end], b"newA\0")
                    self.assertEqual(changed[layout.archive_end:], body[layout.archive_end:])
        for token in (0, (5 << 32) | 1, 0xFFFFFFFFFFFFFFFD):
            with self.subTest(unsupported=token):
                body = bytearray(original)
                struct.pack_into("<Q", body, root_at + 8, token)
                with self.assertRaisesRegex(ValueError, "pointer form"):
                    inspect_localize_entry(bytes(body), 0, "test/a", traces[0])
        incomplete = dict(traces[0], read_spans=traces[0]["read_spans"][:2])
        with self.assertRaisesRegex(ValueError, "exactly two native string reads"):
            inspect_localize_entry(body_data=original, asset_index=0,
                                   asset_name="test/a", trace_asset=incomplete)

    def test_batch_same_extent_updates_multiple_trace_bound_entries_atomically(self) -> None:
        body, traces = _two_localize_entries()
        source_hash = hashlib.sha256(body).hexdigest()
        edits = [
            dict(asset_index=0, asset_name="test/a", trace_asset=traces[0],
                 expected_key="test/a", expected_value="oldA", value="newA"),
            dict(asset_index=1, asset_name="test/b", trace_asset=traces[1],
                 expected_key="test/b", expected_value="oldB", value="newB"),
        ]
        changed, receipt = replace_localize_values_same_extent(body, edits, source_hash)
        self.assertEqual(len(changed), len(body))
        self.assertEqual(ZoneBody.parse(changed).assets, ZoneBody.parse(body).assets)
        self.assertEqual(receipt["edit_count"], 2)
        self.assertEqual([row["new_value"] for row in receipt["edits"]], ["newA", "newB"])
        self.assertEqual(changed[-12:], b"test/b\0newB\0")
        self.assertEqual(body[-12:], b"test/b\0oldB\0")

    def test_batch_rejects_duplicate_and_extent_mismatch_without_partial_output(self) -> None:
        body, traces = _two_localize_entries()
        source_hash = hashlib.sha256(body).hexdigest()
        one = dict(asset_index=0, asset_name="test/a", trace_asset=traces[0], value="newA")
        with self.assertRaisesRegex(ValueError, "repeats XAsset index"):
            replace_localize_values_same_extent(
                body, [one, {**one, "value": "newA"}], source_hash)
        good = {**one, "expected_value": "oldA"}
        bad = dict(asset_index=1, asset_name="test/b", trace_asset=traces[1], value="too long")
        with self.assertRaisesRegex(ValueError, "changes its native stream-5 extent"):
            replace_localize_values_same_extent(body, [good, bad], source_hash)
        self.assertEqual(body[-12:], b"test/b\0oldB\0")

    def test_batch_rejects_overlapping_native_value_spans(self) -> None:
        body, traces = _two_localize_entries()
        source_hash = hashlib.sha256(body).hexdigest()
        first = SimpleNamespace(value_archive_offset=100, value_stream_offset=20,
                                 value_bytes=5, source_record_sha256="1" * 64)
        second = SimpleNamespace(value_archive_offset=103, value_stream_offset=23,
                                  value_bytes=5, source_record_sha256="2" * 64)
        edits = [
            dict(asset_index=0, asset_name="test/a", trace_asset=traces[0], value="newA"),
            dict(asset_index=1, asset_name="test/b", trace_asset=traces[1], value="newB"),
        ]
        with patch("workstation_localize.inspect_localize_entry",
                   side_effect=[(first, {"value": "oldA"}), (second, {"value": "oldB"})]):
            with self.assertRaisesRegex(ValueError, "overlapping native value spans"):
                replace_localize_values_same_extent(body, edits, source_hash)

    def test_remove_operation_rejects_existing_nonfinal_localize_row(self) -> None:
        body, traces = _two_localize_entries()
        with self.assertRaisesRegex(ValueError, "only the final XAsset"):
            remove_appended_localize_entry(
                body, 0, "test/a", traces[0], hashlib.sha256(body).hexdigest(), 0)

    def test_remove_existing_row_rebases_traced_aliases_and_preserves_order(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(body, Path(temporary))
            result, proof = remove_localize_entry(
                body, 0, "test/a", traces[0], hashlib.sha256(body).hexdigest(),
                "test/a", "oldA", trace_path, manifest_path)
        parsed = ZoneBody.parse(result)
        self.assertEqual(len(parsed.assets), 1)
        self.assertEqual(parsed.assets[0].type_id, LOCALIZE_TYPE_ID)
        self.assertEqual(proof["stream5_string_bytes_removed"], len(b"test/a\0oldA\0"))
        self.assertTrue(proof["retained_xasset_order_preserved"])
        self.assertEqual(proof["stream5_pointer_relocation"]["aliases_rebased"], 0)
        self.assertGreater(proof["stream5_pointer_relocation"]["full_trace_events"], 0)

    def test_remove_original_final_localize_row_when_trace_owns_exact_eof(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(body, Path(temporary))
            result, proof = remove_localize_entry(
                body, 1, "test/b", traces[1], hashlib.sha256(body).hexdigest(),
                "test/b", "oldB", trace_path, manifest_path)
        parsed = ZoneBody.parse(result)
        self.assertEqual(len(parsed.assets), 1)
        self.assertEqual(parsed.assets[0].type_id, LOCALIZE_TYPE_ID)
        self.assertTrue(proof["retained_xasset_order_preserved"])
        self.assertTrue(proof["final_row_tail_ownership_verified"])

    def test_final_localize_row_rejects_unowned_bytes_after_its_payload(self) -> None:
        body, _ = _two_localize_entries()
        extended = body + b"unowned"
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(
                extended, Path(temporary))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["serialized_bytes_read"] = len(extended)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact serialized EOF"):
                remove_localize_entry(
                    extended, 1, "test/b", traces[1], hashlib.sha256(extended).hexdigest(),
                    "test/b", "oldB", trace_path, manifest_path)

    def test_final_localize_tail_rejects_overlapping_native_owner(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(body, Path(temporary))
            events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
            duplicate = next(event for event in events if event.get("kind") == "stream_operation" and
                             event.get("operation") == "load" and event.get("xasset_index") == 1 and
                             event.get("block_before") == 5 and event.get("size") == len(b"oldB\0"))
            position = next(index for index, event in enumerate(events)
                            if event.get("kind") == "xasset_end" and event.get("xasset_index") == 1)
            events.insert(position, {**duplicate, "xasset_index": 0})
            trace_path.write_text("".join(json.dumps({**event, "sequence": index}) + "\n"
                                                     for index, event in enumerate(events)), encoding="utf-8")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["stream_trace_events"] = len(events)
            manifest["stream_trace_sha256"] = hashlib.sha256(trace_path.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "shared with another native XAsset"):
                remove_localize_entry(
                    body, 1, "test/b", traces[1], hashlib.sha256(body).hexdigest(),
                    "test/b", "oldB", trace_path, manifest_path)

    def test_remove_existing_row_fails_closed_on_inbound_string_alias(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(
                body, Path(temporary), alias_into_first=True)
            with self.assertRaisesRegex(ValueError, "targets deleted Localize key/value"):
                remove_localize_entry(
                    body, 0, "test/a", traces[0], hashlib.sha256(body).hexdigest(),
                    "test/a", "oldA", trace_path, manifest_path)

    def test_remove_existing_row_fails_closed_on_inbound_root_alias(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(
                body, Path(temporary), alias_into_first=True, alias_target=(1, 0))
            with self.assertRaisesRegex(ValueError, "unsupported packed target stream 1"):
                remove_localize_entry(
                    body, 0, "test/a", traces[0], hashlib.sha256(body).hexdigest(),
                    "test/a", "oldA", trace_path, manifest_path)

    def test_remove_existing_row_fails_closed_on_inbound_table_alias(self) -> None:
        body, _ = _two_localize_entries()
        with tempfile.TemporaryDirectory() as temporary:
            trace_path, manifest_path, traces = _two_localize_native_trace(
                body, Path(temporary), alias_into_first=True, alias_target=(5, 4))
            with self.assertRaisesRegex(ValueError, "targets the XAsset row"):
                remove_localize_entry(
                    body, 0, "test/a", traces[0], hashlib.sha256(body).hexdigest(),
                    "test/a", "oldA", trace_path, manifest_path)


if __name__ == "__main__":
    unittest.main()
