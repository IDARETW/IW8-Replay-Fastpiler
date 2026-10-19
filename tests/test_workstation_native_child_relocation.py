"""Exercise alignment, retained pointer fields, and rejected child ownership."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_native_child_relocation import InlineChildLayout, relocate_stream5_children

INLINE = 0xfffffffffffffffe


class ChildRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.trace, self.manifest = root / "trace.jsonl", root / "manifest.json"
        data = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, 2, 0, INLINE))
        data += struct.pack("<IIQ", 14, 0, INLINE) * 2
        first = bytearray(40)
        struct.pack_into("<I", first, 32, 4)
        second = bytearray(40)
        struct.pack_into("<Q", second, 0, (5 << 32) | 49)
        data += first + b"CODE" + b"END\0" + second
        self.body = bytes(data)
        self.layout = InlineChildLayout("first", 64, 104, 32, 4,
            hashlib.sha256(b"CODE").hexdigest(), 32, "<I")
        self.events = []

        def event(kind, owner=None, **values):
            self.events.append(dict(kind=kind, sequence=len(self.events), xasset_index=owner, **values))

        def operation(name, before, after, owner=None, **values):
            event("stream_operation", owner, operation=name,
                  block_before=before[0], offset_before=before[1],
                  block_after=after[0], offset_after=after[1], **values)

        operation("load", (5, 0), (5, 32), size=32, physical_input_bytes=32, input_before=32)
        event("xasset_begin", 0)
        event("begin_asset_call", 0)
        operation("push", (5, 32), (1, 0), 0)
        operation("load", (1, 0), (1, 40), 0, size=40, physical_input_bytes=40, input_before=64)
        operation("push", (1, 40), (5, 32), 0)
        event("load_stream_call", 0, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=5, offset=32))
        operation("load", (5, 32), (5, 36), 0, size=4, physical_input_bytes=4, input_before=104)
        operation("align", (5, 36), (5, 48), 0, value=15)
        operation("load", (5, 48), (5, 52), 0, size=4, physical_input_bytes=4, input_before=108)
        event("xasset_end", 0)
        event("xasset_begin", 1)
        event("begin_asset_call", 1)
        operation("push", (5, 52), (1, 0), 1)
        operation("load", (1, 0), (1, 40), 1, size=40, physical_input_bytes=40, input_before=112)
        event("packed_alias", 1, raw_token=(5 << 32) | 49,
              field_stream_location=dict(stream=1, offset=0),
              resolved_target_stream_location=dict(stream=5, offset=48))
        event("xasset_end", 1)
        self.write_trace()

    def write_trace(self):
        self.trace.write_text("".join(json.dumps(event) + "\n" for event in self.events))
        self.manifest.write_text(json.dumps(dict(profile="replay-1.20", xfile_version=0xff7,
            complete=True, success=True, failed=0, unavailable=0, tested=2, top_level_index=2,
            serialized_bytes_read=len(self.body), stream_trace_events=len(self.events),
            stream_trace_sha256=hashlib.sha256(self.trace.read_bytes()).hexdigest())))

    def rebuild(self, payload, layout=None):
        return relocate_stream5_children(self.body, {0: layout or self.layout}, {0: payload},
                                          self.trace, self.manifest)

    def test_growth_replays_alignment_and_moves_retained_pointer_field(self):
        updated, proof = self.rebuild(b"C" * 20)
        self.assertEqual(len(updated), len(self.body) + 16)
        self.assertEqual(struct.unpack_from("<I", updated, 96)[0], 20)
        self.assertEqual(updated[104:124], b"C" * 20)
        self.assertEqual(updated[124:128], b"END\0")
        self.assertEqual(struct.unpack_from("<Q", updated, 128)[0], (5 << 32) | 65)
        self.assertEqual(proof["packed_stream5_aliases_rebased"], 1)
        self.assertEqual(proof["stream5_extent_delta"], 16)

    def test_shrink_keeps_downstream_alignment_without_rebasing(self):
        updated, proof = self.rebuild(b"C")
        self.assertEqual(len(updated), len(self.body) - 3)
        self.assertEqual(struct.unpack_from("<Q", updated, 109)[0], (5 << 32) | 49)
        self.assertEqual(proof["packed_stream5_aliases_rebased"], 0)
        self.assertEqual(proof["stream5_extent_delta"], 0)

    def test_changed_child_digest_rejects_stale_layout(self):
        with self.assertRaisesRegex(ValueError, "trace-bound identity"):
            self.rebuild(b"changed", replace(self.layout, child_sha256="0" * 64))

    def test_root_length_must_match_owned_child(self):
        with self.assertRaisesRegex(ValueError, "length field"):
            self.rebuild(b"changed", replace(self.layout, length_field_offset=28))

    def test_changed_trace_digest_rejects_cached_receipt(self):
        self.trace.write_text(self.trace.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            self.rebuild(b"changed")

    def test_inbound_pointer_into_replaced_child_is_rejected(self):
        raw = (5 << 32) | 34
        body = bytearray(self.body)
        struct.pack_into("<Q", body, 112, raw)
        self.body = bytes(body)
        event = next(row for row in self.events if row["kind"] == "packed_alias")
        event["raw_token"] = raw
        event["resolved_target_stream_location"]["offset"] = 33
        self.write_trace()
        with self.assertRaisesRegex(ValueError, "targets bytes replaced"):
            self.rebuild(b"changed")

    def test_asset_relative_alias_tracks_growth_inside_its_owner(self):
        raw = (0x15 << 32) | 17
        data = bytearray(self.body)
        struct.pack_into("<Q", data, 64, raw)
        self.body = bytes(data)
        end = next(index for index, event in enumerate(self.events)
                   if event['kind'] == 'xasset_end' and event['xasset_index'] == 0)
        self.events.insert(end, dict(kind='packed_alias', xasset_index=0,
            raw_token=raw, field_stream_location=dict(stream=1, offset=0),
            resolved_target_stream_location=dict(stream=5, offset=48)))
        for sequence, event in enumerate(self.events):
            event['sequence'] = sequence
        self.write_trace()
        updated, proof = self.rebuild(b'C' * 20)
        self.assertEqual(struct.unpack_from('<Q', updated, 64)[0], (0x15 << 32) | 33)
        self.assertEqual(proof['packed_stream5_tag15_asset_relative_validated'], 1)
        self.assertEqual(proof['packed_stream5_aliases_rebased'], 2)

    def test_asset_relative_alias_must_agree_with_its_captured_base(self):
        alias = next(row for row in self.events if row['kind'] == 'packed_alias')
        alias['raw_token'] = (0x15 << 32) | 49
        self.write_trace()
        with self.assertRaisesRegex(ValueError, 'does not match asset-local base'):
            self.rebuild(b'C' * 20)

    def test_null_child_insertion_rebases_later_aligned_stream5_alias(self):
        data = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, 2, 0, INLINE))
        data += struct.pack("<IIQ", 51, 0, INLINE)
        data += struct.pack("<IIQ", 14, 0, INLINE)
        name = b"empty.cfg\0"
        root0 = struct.pack("<QiiQ", 0xFFFFFFFFFFFFFFFF, 0, 0, 0)
        root1 = bytearray(40)
        raw_token = (5 << 32) | 49
        struct.pack_into("<Q", root1, 0, raw_token)
        data += root0 + name + root1 + b"DATA"
        body = bytes(data)
        trace, manifest = Path(self.temp.name) / "empty-insert.jsonl", Path(self.temp.name) / "empty-insert-manifest.json"
        events = []

        def event(kind, owner=None, **values):
            events.append(dict(kind=kind, sequence=len(events), xasset_index=owner, **values))

        def op(name, before, after, owner=None, **values):
            event("stream_operation", owner, operation=name, block_before=before[0],
                offset_before=before[1], block_after=after[0], offset_after=after[1], **values)

        op("load", (5, 0), (5, 32), size=32, physical_input_bytes=32, input_before=32)
        event("xasset_begin", 0); event("begin_asset_call", 0)
        op("push", (5, 32), (1, 0), 0)
        event("load_stream_call", 0, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=1, offset=0))
        op("load", (1, 0), (1, 24), 0, size=24, physical_input_bytes=24, input_before=64)
        op("load", (5, 32), (5, 32 + len(name)), 0, size=len(name),
           physical_input_bytes=len(name), input_before=88)
        event("xasset_end", 0)
        event("xasset_begin", 1); event("begin_asset_call", 1)
        op("push", (5, 32 + len(name)), (1, 24), 1)
        event("load_stream_call", 1, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=1, offset=24))
        op("load", (1, 24), (1, 64), 1, size=40, physical_input_bytes=40,
           input_before=88 + len(name))
        event("packed_alias", 1, raw_token=raw_token,
              field_stream_location=dict(stream=1, offset=24),
              resolved_target_stream_location=dict(stream=5, offset=48))
        op("align", (5, 32 + len(name)), (5, 48), 1, value=15)
        event("load_stream_call", 1, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=5, offset=48))
        op("load", (5, 48), (5, 52), 1, size=4, physical_input_bytes=4,
           input_before=88 + len(name) + 40)
        event("xasset_end", 1)
        trace.write_text("".join(json.dumps(row) + "\n" for row in events))
        manifest.write_text(json.dumps(dict(profile="replay-1.20", xfile_version=0xff7,
            complete=True, success=True, failed=0, unavailable=0, tested=2, top_level_index=2,
            serialized_bytes_read=len(body), stream_trace_events=len(events),
            stream_trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())))
        layout = InlineChildLayout("empty.cfg", 64, 88 + len(name), 32 + len(name), 0,
            hashlib.sha256(b"").hexdigest(), 12, "<i", allow_empty_insert=True)
        grown, receipt = relocate_stream5_children(body, {0: layout}, {0: b"new text"}, trace, manifest)
        inserted_at = 88 + len(name)
        self.assertEqual(grown[inserted_at:inserted_at + 8], b"new text")
        self.assertEqual(grown[inserted_at + 8 + 8:inserted_at + 8 + 40], root1[8:])
        self.assertEqual(grown[inserted_at + 8 + 40:inserted_at + 8 + 44], b"DATA")
        self.assertEqual(struct.unpack_from("<Q", grown, inserted_at + 8)[0], (5 << 32) | 65)
        self.assertEqual(receipt["packed_stream5_aliases_rebased"], 1)
        self.assertEqual(receipt["stream5_extent_delta"], 16)

    def test_unrecognized_target_tag_fails_before_rewriting(self):
        alias = next(row for row in self.events if row['kind'] == 'packed_alias')
        alias['raw_token'] = (0x25 << 32) | 49
        self.write_trace()
        with self.assertRaisesRegex(ValueError, 'unsupported packed stream-5 token tag'):
            self.rebuild(b'C' * 20)


if __name__ == "__main__":
    unittest.main()
