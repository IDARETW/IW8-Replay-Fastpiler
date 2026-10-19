"""Trace-bound RawFile text/binary editing and native repack coverage."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_rawfile import (RawFileLayout, _replace_batch, read_rawfile,
                                 replace_rawfile_payload)

INLINE = 0xFFFFFFFFFFFFFFFE
PTR_FOLLOWS = 0xFFFFFFFFFFFFFFFF


class RawFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.trace_path = Path(self.temp.name) / "trace.jsonl"
        self.manifest_path = Path(self.temp.name) / "manifest.json"
        self._make_body(b"seta ui_test \"old\"\n", "config/test.cfg")

    def _make_body(self, raw, name, compressed_mode=True, name_token=PTR_FOLLOWS,
                   buffer_token=INLINE):
        compressed = zlib.compress(raw) if compressed_mode else raw
        name_data = name.encode() + b"\0"
        root_at = 48
        name_at = root_at + 24
        payload_at = name_at + len(name_data)
        body = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, INLINE))
        body += struct.pack("<IIQ", 51, 0, INLINE)
        body += struct.pack("<QiiQ", name_token,
                            len(compressed) if compressed_mode else 0, len(raw), buffer_token)
        body += name_data + compressed
        self.body = bytes(body)
        self.row = dict(index=0, type_id=51, name=name, pointer_token=INLINE)
        self.trace_asset = dict(index=0, type_id=51, name=name, end_cursor=len(body),
            begin_sequence=1, end_sequence=8,
            root_stream_location=dict(stream=1, offset=0),
            read_spans=[
                dict(origin="load_stream_call", reader_start_arg=0, size=24,
                     archive_offset=root_at, destination_stream_location=dict(stream=1, offset=0)),
                dict(origin="string_data", size=len(name_data), archive_offset=name_at,
                     destination_stream_location=dict(stream=5, offset=0)),
                dict(origin="load_stream_call", reader_start_arg=0, size=len(compressed),
                     archive_offset=payload_at,
                     destination_stream_location=dict(stream=5, offset=len(name_data)))])
        self.events = []

        def event(kind, owner=None, **values):
            self.events.append(dict(kind=kind, sequence=len(self.events), xasset_index=owner, **values))

        def operation(kind, before, after, owner=None, **values):
            event("stream_operation", owner, operation=kind,
                  block_before=before[0], offset_before=before[1],
                  block_after=after[0], offset_after=after[1], **values)

        operation("push", (5, 0), (5, 0))
        event("xasset_begin", 0)
        event("begin_asset_call", 0)
        operation("push", (5, 0), (1, 0), 0)
        event("load_stream_call", 0, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=1, offset=0))
        operation("load", (1, 0), (1, 24), 0, size=24,
                  physical_input_bytes=24, input_before=root_at)
        operation("load", (5, 0), (5, len(name_data)), 0, size=len(name_data),
                  physical_input_bytes=len(name_data), input_before=name_at)
        event("load_stream_call", 0, loader_start_arg=0, at_start=True,
              destination_stream_location=dict(stream=5, offset=len(name_data)))
        operation("load", (5, len(name_data)), (5, len(name_data) + len(compressed)), 0,
                  size=len(compressed), physical_input_bytes=len(compressed), input_before=payload_at)
        event("xasset_end", 0)
        self.trace_path.write_text("".join(json.dumps(row) + "\n" for row in self.events))
        trace_sha = hashlib.sha256(self.trace_path.read_bytes()).hexdigest()
        self.manifest_path.write_text(json.dumps(dict(
            profile="replay-1.20", xfile_version=0xff7, complete=True, success=True,
            failed=0, unavailable=0, tested=1, top_level_index=1,
            serialized_bytes_read=len(self.body), stream_trace_events=len(self.events),
            stream_trace_sha256=trace_sha)))

    def _corrupt_zlib_payload(self, payload, raw_len=None):
        layout, _ = read_rawfile(self.body, self.row, self.trace_asset)
        changed = bytearray(self.body[:layout.payload_archive_offset] + payload)
        struct.pack_into("<i", changed, layout.root_archive_offset + 8, len(payload))
        if raw_len is not None:
            struct.pack_into("<i", changed, layout.root_archive_offset + 12, raw_len)
        owner = copy.deepcopy(self.trace_asset)
        child = next(span for span in owner["read_spans"]
                     if span.get("archive_offset") == layout.payload_archive_offset)
        child["size"] = len(payload)
        owner["end_cursor"] = len(changed)
        return bytes(changed), owner

    def _make_packed_name_body(self, name="config/packed.cfg", name_token=None,
                               event_updates=None, span_updates=None):
        raw = b"seta packed yes\n"
        payload = zlib.compress(raw)
        name_data = name.encode() + b"\0"
        if name_token is None:
            name_token = (5 << 32) | 1
        body = bytearray(struct.pack("<IIQIIQ", 1, 0, INLINE, 1, 0, INLINE))
        body += struct.pack("<Q", INLINE)
        name_at = len(body)
        body += name_data
        table_at = len(body)
        body += struct.pack("<IIQ", 51, 0, INLINE)
        root_at = len(body)
        body += struct.pack("<QiiQ", name_token, len(payload), len(raw), INLINE)
        payload_at = len(body)
        body += payload
        body = bytes(body)
        name_span = dict(origin="string_data", archive_offset=name_at, size=len(name_data),
            destination_stream_location=dict(stream=5, offset=0), event_sequence=2)
        name_event = dict(sequence=6, kind="packed_resolve", xasset_index=0, type_id=51,
            raw_token=name_token, field_stream_location=dict(stream=1, offset=0),
            resolved_target_stream_location=dict(stream=5, offset=0))
        if event_updates:
            name_event.update(event_updates)
        if span_updates:
            name_span.update(span_updates)
        owner = dict(index=0, type_id=51, name=name, begin_sequence=4, end_sequence=9,
            end_cursor=len(body), root_stream_location=dict(stream=1, offset=0),
            packed_pointer_events=[name_event], _all_physical_spans=[name_span],
            read_spans=[
                dict(origin="load_stream_call", reader_start_arg=0, size=24,
                     archive_offset=root_at, destination_stream_location=dict(stream=1, offset=0),
                     event_sequence=5),
                dict(origin="load_stream_call", reader_start_arg=0, size=len(payload),
                     archive_offset=payload_at,
                     destination_stream_location=dict(stream=5, offset=len(name_data)),
                     event_sequence=8)])
        row = dict(index=0, type_id=51, name=name, pointer_token=INLINE)
        return body, row, owner, dict(name_at=name_at, table_at=table_at,
                                     root_at=root_at, payload_at=payload_at,
                                     payload=payload, raw=raw, name_data=name_data)

    def _make_two_owner_batch(self, alias_into_first=False, contents=None):
        names = ["config/a.cfg", "config/second.cfg"]
        if contents is None:
            contents = [b"alpha", b"second-source"]
        streams = [zlib.compress(value) if value else b"" for value in contents]
        data = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, 2, 0, INLINE))
        data += struct.pack("<IIQ", 51, 0, INLINE) * 2
        roots, payload_offsets = [], []
        for name, raw, payload in zip(names, contents, streams):
            root_at = len(data)
            roots.append(root_at)
            name_data = name.encode() + b"\0"
            data += struct.pack("<QiiQ", PTR_FOLLOWS, len(payload), len(raw), INLINE if payload else 0)
            data += name_data
            payload_offsets.append(len(data))
            data += payload
        body = bytes(data)
        layouts = []
        for index, (name, raw, payload, root_at, payload_at) in enumerate(
                zip(names, contents, streams, roots, payload_offsets)):
            layouts.append((RawFileLayout(index, name, root_at, index * 24,
                payload_at, sum(len(names[n].encode()) + 1 + len(streams[n])
                                for n in range(index)) + len(name.encode()) + 1,
                len(payload), len(raw), bool(payload), INLINE if payload else 0, hashlib.sha256(body).hexdigest(),
                hashlib.sha256(payload).hexdigest()), raw, payload, {}))

        events = []

        def event(kind, owner=None, **values):
            events.append(dict(kind=kind, sequence=len(events), xasset_index=owner, **values))

        def operation(kind, before, after, owner=None, **values):
            event("stream_operation", owner, operation=kind,
                  block_before=before[0], offset_before=before[1],
                  block_after=after[0], offset_after=after[1], **values)

        stream5 = 0
        operation("push", (5, 0), (5, 0))
        for index in range(2):
            name_data = names[index].encode() + b"\0"
            root_at = roots[index]
            root_stream = index * 24
            payload = streams[index]
            payload_at = payload_offsets[index]
            event("xasset_begin", index)
            event("begin_asset_call", index)
            operation("push", (5, stream5), (1, root_stream), index)
            event("load_stream_call", index, loader_start_arg=0, at_start=True,
                  destination_stream_location=dict(stream=1, offset=root_stream))
            operation("load", (1, root_stream), (1, root_stream + 24), index,
                      size=24, physical_input_bytes=24, input_before=root_at)
            operation("push", (1, root_stream + 24), (5, stream5), index)
            operation("load", (5, stream5), (5, stream5 + len(name_data)), index,
                      size=len(name_data), physical_input_bytes=len(name_data),
                      input_before=root_at + 24)
            stream5 += len(name_data)
            event("load_stream_call", index, loader_start_arg=0, at_start=True,
                  destination_stream_location=dict(stream=5, offset=stream5))
            operation("load", (5, stream5), (5, stream5 + len(payload)), index,
                      size=len(payload), physical_input_bytes=len(payload), input_before=payload_at)
            stream5 += len(payload)
            if alias_into_first and index == 1:
                target = len(names[0].encode()) + 1
                raw_token = (5 << 32) | (target + 1)
                struct.pack_into("<Q", data, roots[index] + 16, raw_token)
                event("packed_alias", index, type_id=51, raw_token=raw_token,
                      field_stream_location=dict(stream=1, offset=root_stream + 16),
                      resolved_target_stream_location=dict(stream=5, offset=target))
            event("xasset_end", index)
        trace_path = Path(self.temp.name) / "batch-trace.jsonl"
        manifest_path = Path(self.temp.name) / "batch-manifest.json"
        trace_path.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
        manifest_path.write_text(json.dumps(dict(profile="replay-1.20", xfile_version=0xff7,
            complete=True, success=True, failed=0, unavailable=0, tested=2, top_level_index=2,
            serialized_bytes_read=len(body), stream_trace_events=len(events),
            stream_trace_sha256=hashlib.sha256(trace_path.read_bytes()).hexdigest())))
        self.batch_trace, self.batch_manifest = trace_path, manifest_path
        return body, layouts, roots, payload_offsets, streams, names

    def test_cfg_is_read_as_text_and_growth_repackages_root_and_buffer(self):
        layout, edited = read_rawfile(self.body, self.row, self.trace_asset,
                                      hashlib.sha256(self.body).hexdigest())
        self.assertEqual(edited["mode"], "text")
        self.assertEqual(edited["content"], 'seta ui_test "old"\n')
        updated, proof = replace_rawfile_payload(
            self.body, self.row, self.trace_asset, 'seta ui_test "a much longer value"\n',
            "text", hashlib.sha256(self.body).hexdigest(), str(self.trace_path),
            str(self.manifest_path))
        compressed_len, raw_len = struct.unpack_from("<ii", updated, layout.root_archive_offset + 8)
        payload = updated[layout.payload_archive_offset:
                          layout.payload_archive_offset + compressed_len]
        self.assertEqual(zlib.decompress(payload), b'seta ui_test "a much longer value"\n')
        self.assertEqual(raw_len, len(zlib.decompress(payload)))
        self.assertGreater(compressed_len, layout.payload_bytes)
        self.assertEqual(proof["relocation"]["packed_stream5_aliases_scanned"], 0)

    def test_binary_rawfile_uses_lossless_base64_mode(self):
        self._make_body(b"\x00\xff\x81\x00", "ui/data/blob.bin")
        layout, data = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertEqual(data["mode"], "base64")
        self.assertEqual(data["content"], "AP+BAA==")
        updated, _ = replace_rawfile_payload(self.body, self.row, self.trace_asset,
            data["content"], "base64", hashlib.sha256(self.body).hexdigest(),
            str(self.trace_path), str(self.manifest_path))
        compressed_len, raw_len = struct.unpack_from("<ii", updated, layout.root_archive_offset + 8)
        raw = zlib.decompress(updated[layout.payload_archive_offset:
                                      layout.payload_archive_offset + compressed_len])
        self.assertEqual(raw, b"\x00\xff\x81\x00")
        self.assertEqual(raw_len, 4)
        self.assertEqual(layout.raw_bytes, 4)

    def test_binary_extension_with_valid_utf8_control_bytes_uses_base64(self):
        self._make_body(b"\x00\x01\x02", "ui/data/opaque.bin")
        _, data = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertEqual(data["mode"], "base64")
        self.assertEqual(data["content"], "AAEC")

    def test_rawfile_name_accepts_both_exact_pointer_follows_and_shared_tokens(self):
        for token in (PTR_FOLLOWS, INLINE):
            with self.subTest(token=hex(token)):
                self._make_body(b"seta x y\n", "config/name.cfg", name_token=token)
                _, result = read_rawfile(self.body, self.row, self.trace_asset)
                self.assertEqual(result["content"], "seta x y\n")

    def test_incomplete_oversized_and_trailing_zlib_payloads_are_rejected(self):
        original_layout, _ = read_rawfile(self.body, self.row, self.trace_asset)
        compressed = self.body[original_layout.payload_archive_offset:
                               original_layout.payload_archive_offset + original_layout.payload_bytes]
        incomplete_body, incomplete_trace = self._corrupt_zlib_payload(compressed[:-2])
        with self.assertRaisesRegex(ValueError, "incomplete|valid zlib"):
            read_rawfile(incomplete_body, self.row, incomplete_trace)
        oversized_body, oversized_trace = self._corrupt_zlib_payload(compressed,
                                                                      raw_len=original_layout.raw_bytes - 1)
        with self.assertRaisesRegex(ValueError, "length differs"):
            read_rawfile(oversized_body, self.row, oversized_trace)
        trailing_body, trailing_trace = self._corrupt_zlib_payload(compressed + b"tail")
        with self.assertRaisesRegex(ValueError, "trailing|valid zlib"):
            read_rawfile(trailing_body, self.row, trailing_trace)

    def test_24_byte_stream5_buffer_does_not_count_as_the_stream1_root(self):
        self._make_body(bytes((i * 37 + 11) % 256 for i in range(16)), "config/24.cfg")
        root_span, payload_span = self.trace_asset["read_spans"][0], self.trace_asset["read_spans"][2]
        self.assertEqual(root_span["size"], 24)
        self.assertEqual(payload_span["size"], 24)
        self.assertEqual(root_span["destination_stream_location"]["stream"], 1)
        self.assertEqual(payload_span["destination_stream_location"]["stream"], 5)
        _, result = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertEqual(result["mode"], "base64")
        self.assertEqual(result["content"], base64.b64encode(
            bytes((i * 37 + 11) % 256 for i in range(16))).decode("ascii"))

    def test_packed_rawfile_name_reads_exact_earlier_tag5_span(self):
        body, row, owner, fixture = self._make_packed_name_body()
        layout, result = read_rawfile(body, row, owner, hashlib.sha256(body).hexdigest())
        self.assertEqual(layout.asset_name, "config/packed.cfg")
        self.assertEqual(result["content"], "seta packed yes\n")
        self.assertEqual(fixture["name_at"] + len(fixture["name_data"]), fixture["table_at"])

    def test_packed_name_requires_exact_field_token_target_text_and_earlier_span(self):
        invalid_events = (
            {"field_stream_location": dict(stream=1, offset=8)},
            {"raw_token": (5 << 32) | 2},
            {"resolved_target_stream_location": dict(stream=5, offset=1)},
        )
        for changes in invalid_events:
            with self.subTest(changes=changes):
                body, row, owner, _ = self._make_packed_name_body(event_updates=changes)
                with self.assertRaises(ValueError):
                    read_rawfile(body, row, owner)
        body, row, owner, fixture = self._make_packed_name_body()
        wrong_text = bytearray(body)
        wrong_text[fixture["name_at"]] ^= 1
        with self.assertRaises(ValueError):
            read_rawfile(bytes(wrong_text), row, owner)
        _, row, owner, _ = self._make_packed_name_body(span_updates={"event_sequence": 7})
        with self.assertRaises(ValueError):
            read_rawfile(body, row, owner)

    def test_two_owner_batch_growth_and_shrink_moves_second_root_length(self):
        body, edits, roots, payload_offsets, old_payloads, _ = self._make_two_owner_batch()
        for first_raw, second_raw in ((b"first owner has grown substantially", b"second owner grew too"),
                                      (b"x", b"tiny")):
            with self.subTest(first_raw=first_raw):
                new_payloads = [zlib.compress(first_raw), zlib.compress(second_raw)]
                batch = [(layout, raw, payload, pending)
                         for (layout, _, _, pending), raw, payload in
                         zip(edits, (first_raw, second_raw), new_payloads)]
                updated, proof = _replace_batch(body, batch, self.batch_trace, self.batch_manifest)
                delta_first = len(new_payloads[0]) - len(old_payloads[0])
                shifted_second_root = roots[1] + delta_first
                shifted_second_payload = payload_offsets[1] + delta_first
                compressed_len, raw_len = struct.unpack_from("<ii", updated, shifted_second_root + 8)
                self.assertEqual(compressed_len, len(new_payloads[1]))
                self.assertEqual(raw_len, len(second_raw))
                self.assertEqual(zlib.decompress(updated[shifted_second_payload:
                    shifted_second_payload + compressed_len]), second_raw)
                self.assertEqual(len(updated), len(body) + sum(
                    len(new_payloads[i]) - len(old_payloads[i]) for i in range(2)))
                self.assertEqual(len(proof["edits"]), 2)

    def test_two_owner_noop_batch_preserves_compressed_payload_bytes_exactly(self):
        body, edits, roots, payload_offsets, payloads, _ = self._make_two_owner_batch()
        unchanged, proof = _replace_batch(body, edits, self.batch_trace, self.batch_manifest)
        self.assertEqual(unchanged, body)
        for index, payload in enumerate(payloads):
            length = struct.unpack_from("<i", unchanged, roots[index] + 8)[0]
            self.assertEqual(unchanged[payload_offsets[index]:payload_offsets[index] + length], payload)
        self.assertEqual(proof["status"], "semantic-noop-inline-child-batch")

    def test_batch_rejects_alias_input_that_targets_an_edited_buffer(self):
        body, edits, _, _, _, _ = self._make_two_owner_batch(alias_into_first=True)
        new_edits = [(layout, raw + b"changed", zlib.compress(raw + b"changed"), pending)
                     for layout, raw, _, pending in edits]
        with self.assertRaisesRegex(ValueError, "targets bytes replaced"):
            _replace_batch(body, new_edits, self.batch_trace, self.batch_manifest)

    def test_uncompressed_cfg_buffer_is_editable_with_compressed_len_zero(self):
        self._make_body(b"seta raw_mode old\n", "config/raw.cfg", compressed_mode=False)
        layout, result = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertFalse(layout.compressed)
        self.assertEqual(result["content"], "seta raw_mode old\n")
        updated, _ = replace_rawfile_payload(self.body, self.row, self.trace_asset,
            "seta raw_mode updated\n", "text", hashlib.sha256(self.body).hexdigest(),
            str(self.trace_path), str(self.manifest_path))
        compressed_len, raw_len = struct.unpack_from("<ii", updated, layout.root_archive_offset + 8)
        self.assertEqual(compressed_len, 0)
        self.assertEqual(raw_len, len(b"seta raw_mode updated\n"))
        self.assertEqual(updated[layout.payload_archive_offset:
                                layout.payload_archive_offset + raw_len],
                         b"seta raw_mode updated\n")

    def test_null_empty_buffer_grows_at_proven_inline_name_cursor(self):
        self._make_body(b"", "config/empty.cfg", compressed_mode=False, buffer_token=0)
        empty_layout, empty = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertEqual(empty["content"], "")
        self.assertEqual(empty_layout.payload_bytes, 0)
        grown, receipt = replace_rawfile_payload(self.body, self.row, self.trace_asset,
            "now nonempty", "text", hashlib.sha256(self.body).hexdigest(),
            str(self.trace_path), str(self.manifest_path))
        self.assertEqual(receipt["relocation"]["status"], "trace-relocated-inline-child-batch-ready")
        compressed_len, raw_len = struct.unpack_from("<ii", grown, empty_layout.root_archive_offset + 8)
        self.assertEqual(zlib.decompress(grown[empty_layout.payload_archive_offset:
                                                empty_layout.payload_archive_offset + compressed_len]),
                         b"now nonempty")
        self.assertEqual(raw_len, len(b"now nonempty"))
        self.assertEqual(struct.unpack_from("<Q", grown, empty_layout.root_archive_offset + 16)[0], INLINE)
        self.assertGreater(compressed_len, 0)

        self._make_body(b"", "config/zlib-empty.cfg", compressed_mode=True)
        zipped_layout, _ = read_rawfile(self.body, self.row, self.trace_asset)
        self.assertTrue(zipped_layout.compressed)
        self.assertGreater(zipped_layout.payload_bytes, 0)
        updated, _ = replace_rawfile_payload(self.body, self.row, self.trace_asset, "now nonempty",
            "text", hashlib.sha256(self.body).hexdigest(), str(self.trace_path), str(self.manifest_path))
        compressed_len, raw_len = struct.unpack_from("<ii", updated, zipped_layout.root_archive_offset + 8)
        self.assertEqual(zlib.decompress(updated[zipped_layout.payload_archive_offset:
                                                 zipped_layout.payload_archive_offset + compressed_len]),
                         b"now nonempty")
        self.assertEqual(raw_len, len(b"now nonempty"))

    def test_empty_growth_then_empty_noop_preserves_both_root_pointers(self):
        body, edits, roots, offsets, _, _ = self._make_two_owner_batch(contents=[b"", b""])
        text = b"seta native_empty grown\n"
        payload = zlib.compress(text)
        batch = [(edits[0][0], text, payload, {}), edits[1]]
        updated, proof = _replace_batch(body, batch, self.batch_trace, self.batch_manifest)
        self.assertEqual(proof["physical_extent_delta"], len(payload))
        self.assertEqual(struct.unpack_from("<iiQ", updated, roots[0] + 8),
                         (len(payload), len(text), INLINE))
        moved_second_root = roots[1] + len(payload)
        self.assertEqual(struct.unpack_from("<QiiQ", updated, moved_second_root),
                         (PTR_FOLLOWS, 0, 0, 0))
        self.assertEqual(zlib.decompress(updated[offsets[0]:offsets[0] + len(payload)]), text)

    def test_packed_buffer_pointer_fails_closed_without_owner_resolution(self):
        body = bytearray(self.body)
        struct.pack_into("<Q", body, 48 + 16, (5 << 32) | 1)
        with self.assertRaisesRegex(ValueError, "unsupported packed"):
            read_rawfile(bytes(body), self.row, self.trace_asset)

    def test_stale_body_and_untraced_payload_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "different decoded body"):
            read_rawfile(self.body, self.row, self.trace_asset, "0" * 64)
        with self.assertRaisesRegex(ValueError, "one exact traced"):
            read_rawfile(self.body, self.row,
                         dict(self.trace_asset, read_spans=self.trace_asset["read_spans"][:-1]))


if __name__ == "__main__":
    unittest.main()
