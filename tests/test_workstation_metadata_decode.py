"""Strict table-only metadata fallback tests; no native asset claims are made."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import workstation_fastfiles as fastfiles
from workstation_metadata_decode import (_validate_decode_receipt,
                                         decode_table_only_metadata)


INLINE = 0xFFFFFFFFFFFFFFFE


def xasset_list(type_ids=()):
    data = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, len(type_ids), 0, INLINE if type_ids else 0))
    for type_id in type_ids:
        data += struct.pack("<IIQ", type_id, 0, INLINE)
    return bytes(data)


class TableOnlyDecodeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace_root = self.root / "workspace"
        self.workspace_root.mkdir()
        self.game = self.root / "game" / "zone"
        self.game.mkdir(parents=True)
        self.cache = self.root / "cache" / "fastfiles"
        self.acts = self.root / "acts.exe"
        self.replay = self.root / "replay.exe"
        self.acts.write_bytes(b"fixture ACTS")
        self.replay.write_bytes(b"fixture Replay 1.20")
        self.acts_identity = dict(executable_sha256=hashlib.sha256(self.acts.read_bytes()).hexdigest(),
                                  binaries=[], data_files=[])
        self.workspace = fastfiles.FastfileWorkspace(
            self.workspace_root, self.cache, self.game, self.acts, self.replay)
        self.source = self.game / "synthetic.ff"
        self.write_source(xasset_list((51, 255, 0)))
        self.pinned = mock.patch.object(fastfiles, "REPLAY_EXECUTABLE_SHA256",
                                       hashlib.sha256(self.replay.read_bytes()).hexdigest())
        self.pinned.start()
        self.addCleanup(self.pinned.stop)
        self.acts_patch = mock.patch.object(fastfiles, "acts_tool_identity",
                                            return_value=self.acts_identity)
        self.acts_patch.start()
        self.addCleanup(self.acts_patch.stop)

    def write_source(self, body):
        raw = fastfiles.pack_replay_uncompressed(body, (0,) * 11, transient_type=1)
        self.source.write_bytes(raw)
        self.source.with_suffix(".fp").write_bytes(self.patch_for(raw))
        self.source.with_suffix(".fc").unlink(missing_ok=True)
        return raw

    def signed_header_only_profile(self):
        body = xasset_list((51,))
        raw = bytearray(0xA0)
        raw[:8] = b"IWffa100"
        struct.pack_into("<II", raw, 8, fastfiles.HEADER_VERSION_REPLAY, 4047)
        raw[0x10:0x13] = bytes((1, 0, 0))
        struct.pack_into("<I", raw, 0x14, len(raw) + len(body) - 0x88)
        struct.pack_into("<Q", raw, 0x20, len(body))
        struct.pack_into("<Q", raw, 0x30, len(body))
        raw[0x88:0x90] = b"IWffs100"
        source = self.game / "synthetic.ff"
        source.write_bytes(bytes(raw) + body)
        target = bytearray(raw[:0x88])
        struct.pack_into("<I", target, 0x0C, 4087)
        patch = bytearray(0x148)
        patch[:8] = b"IWffd100"
        struct.pack_into("<II", patch, 8, 6, 4)
        patch[0x38:0xC0] = raw[:0x88]
        patch[0xC0:0x148] = target
        source.with_suffix(".fp").write_bytes(patch)
        return source, body, fastfiles.source_profile(source)

    @staticmethod
    def patch_for(fastfile):
        template = bytearray(0x148)
        template[:8] = b"IWffd100"
        struct.pack_into("<II", template, 8, 6, 4)
        return fastfiles.make_replay_header_only_patch(bytes(template), fastfile)

    @staticmethod
    def patch_for_header(header):
        prefix = bytearray(b"IWffd100" + struct.pack("<II", 6, 4) + bytes(0x28))
        return bytes(prefix) + header[:0x88] + header[:0x88]

    @staticmethod
    def stored_frame(body):
        header = bytearray(0x88)
        header[:8] = b"IWffc100"
        struct.pack_into("<II", header, 8, fastfiles.HEADER_VERSION_REPLAY, 0xFF7)
        struct.pack_into("<I", header, 0x14, len(body) + 4)
        struct.pack_into("<I", header, 0x1C, len(body))
        struct.pack_into("<QQQ", header, 0x20, len(body), len(body), len(body))
        return bytes(header) + fastfiles.FRAME_MARKER + body

    def test_returns_every_table_row_with_unknown_native_fields_and_no_persistent_cache(self):
        temporary_calls = []
        original_temporary_directory = tempfile.TemporaryDirectory

        def temporary_directory(*args, **kwargs):
            temporary_calls.append(kwargs)
            return original_temporary_directory(*args, **kwargs)

        with mock.patch("workstation_metadata_decode.tempfile.TemporaryDirectory",
                        side_effect=temporary_directory):
            result = decode_table_only_metadata(self.workspace, "synthetic.ff",
                                                native_reader_error="native walker fixture failure")
        self.assertTrue(result["zone_id"])
        self.assertEqual(result["source_identity"]["source"], str(self.source.resolve()))
        self.assertEqual(result["source_identity"]["patches"][0]["sha256"],
                         hashlib.sha256(self.source.with_suffix(".fp").read_bytes()).hexdigest())
        self.assertEqual(result["body_sha256"], hashlib.sha256(xasset_list((51, 255, 0))).hexdigest())
        self.assertIsNone(result["native_walk_key"])
        self.assertEqual(result["reader_scope"], "xasset-table-only")
        self.assertEqual(result["native_reader_error"], "native walker fixture failure")
        self.assertEqual(result["rows"], [
            dict(index=0, type_id=51, pointer_token=f"0x{INLINE:016x}", name=None,
                 type_name=None, reference_only=None,
                 status="xasset-table-only-reader-unavailable"),
            dict(index=1, type_id=255, pointer_token=f"0x{INLINE:016x}", name=None,
                 type_name=None, reference_only=None,
                 status="xasset-table-only-reader-unavailable"),
            dict(index=2, type_id=0, pointer_token=f"0x{INLINE:016x}", name=None,
                 type_name=None, reference_only=None,
                 status="xasset-table-only-reader-unavailable"),
        ])
        self.assertFalse(self.cache.exists())
        self.assertEqual(list(self.workspace_root.glob("table-only-decode-*")), [])
        self.assertEqual(len(temporary_calls), 1)
        self.assertNotIn("dir", temporary_calls[0], "default decode temp must use system TEMP")

    def test_caller_may_reuse_only_the_workspace_cache_root(self):
        result = decode_table_only_metadata(self.workspace, "synthetic.ff",
                                            decode_cache_root=self.cache)
        cached_receipt = self.cache / "synthetic" / result["zone_id"] / "decode-receipt.json"
        self.assertTrue(cached_receipt.is_file())
        self.assertEqual(list(self.workspace_root.glob("table-only-decode-*")), [])
        with self.assertRaisesRegex(ValueError, "must equal the workspace cache root"):
            decode_table_only_metadata(self.workspace, "synthetic.ff",
                                       decode_cache_root=self.root / "unrelated")

    def test_stored_frame_with_exact_optional_header_only_fp_uses_strict_python_decode(self):
        body = xasset_list((51, 255))
        stored = self.stored_frame(body)
        self.source.write_bytes(stored)
        # Exact optional no-op FP: both headers and stream reservations match
        # the validated stored-frame FF. Its output is not decoded by ACTS.
        self.source.with_suffix(".fp").write_bytes(self.patch_for_header(bytes(stored)))
        result = decode_table_only_metadata(self.workspace, "synthetic.ff")
        profile = fastfiles.source_profile(self.source)
        self.assertEqual(profile["input_format"], "replay120-stored-frame-v1")
        self.assertEqual(profile["patches"][0]["bytes"], 0x148)
        self.assertEqual([row["type_id"] for row in result["rows"]], [51, 255])

    def test_stored_frame_nonmatching_patch_header_remains_rejected_by_source_profiler(self):
        body = xasset_list((51,))
        stored = self.stored_frame(body)
        self.source.write_bytes(stored)
        fp = bytearray(self.patch_for_header(bytes(stored)))
        fp[0xC0 + 0x20] ^= 1
        self.source.with_suffix(".fp").write_bytes(fp)
        with self.assertRaisesRegex(ValueError, "headers do not exactly match"):
            decode_table_only_metadata(self.workspace, "synthetic.ff")

    def test_empty_xasset_table_is_a_valid_zero_row_result(self):
        self.write_source(xasset_list())
        result = decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertEqual(result["rows"], [])
        self.assertIsNone(result["native_walk_key"])
        self.assertEqual(result["reader_scope"], "xasset-table-only")

    def test_invalid_source_framing_or_patch_chain_fails_without_persistent_cache(self):
        original = self.source.read_bytes()
        self.source.write_bytes(b"invalid" + original[7:])
        with self.assertRaises(ValueError):
            decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.source.write_bytes(original)
        self.source.with_suffix(".fc").write_bytes(b"unexpected FC")
        with self.assertRaises(ValueError):
            decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertFalse(self.cache.exists())

    def test_stale_decoded_receipt_output_is_rejected(self):
        original_decode = fastfiles.decode_source_fastfile

        def corrupt_output(source, cache_root, acts_path, replay_executable, *args, **kwargs):
            receipt = original_decode(source, cache_root, acts_path, replay_executable, *args, **kwargs)
            decoded = Path(cache_root) / source.stem / receipt["cache_key"] / receipt["final_body_relative_path"]
            decoded.write_bytes(decoded.read_bytes() + b"stale")
            return receipt

        with mock.patch.object(fastfiles, "decode_source_fastfile", side_effect=corrupt_output):
            with self.assertRaises(ValueError):
                decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertFalse(self.cache.exists())

    def test_receipt_cannot_omit_a_current_fp_patch_from_source_identity(self):
        original_decode = fastfiles.decode_source_fastfile

        def omit_patch(source, cache_root, acts_path, replay_executable, *args, **kwargs):
            receipt = original_decode(source, cache_root, acts_path, replay_executable, *args, **kwargs)
            receipt_path = Path(cache_root) / source.stem / receipt["cache_key"] / "decode-receipt.json"
            on_disk = json.loads(receipt_path.read_text(encoding="utf-8"))
            on_disk["source"]["patches"] = []
            receipt_path.write_text(json.dumps(on_disk), encoding="utf-8")
            return receipt

        with mock.patch.object(fastfiles, "decode_source_fastfile", side_effect=omit_patch):
            with self.assertRaisesRegex(ValueError, "source/FP/FC identity"):
                decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertFalse(self.cache.exists())

    def test_acts_or_replay_identity_change_during_decode_is_rejected(self):
        original_decode = fastfiles.decode_source_fastfile
        for changed in ("acts", "replay"):
            with self.subTest(changed=changed):
                state = {"acts": dict(self.acts_identity)}

                def mutate_reader(source, cache_root, acts_path, replay_executable, *args, **kwargs):
                    receipt = original_decode(source, cache_root, acts_path, replay_executable,
                                              *args, **kwargs)
                    if changed == "acts":
                        state["acts"] = dict(state["acts"], reader_dependency="changed")
                    else:
                        self.replay.write_bytes(b"Replay changed after decode")
                    return receipt

                replay_original = self.replay.read_bytes()
                try:
                    with mock.patch.object(fastfiles, "acts_tool_identity",
                                           side_effect=lambda _path: state["acts"]), \
                         mock.patch.object(fastfiles, "decode_source_fastfile",
                                           side_effect=mutate_reader):
                        with self.assertRaises((ValueError, RuntimeError)):
                            decode_table_only_metadata(self.workspace, "synthetic.ff")
                finally:
                    self.replay.write_bytes(replay_original)

    def test_receipt_with_source_patch_but_missing_patch_decode_is_rejected(self):
        profile = fastfiles.source_profile(self.source)
        profile["input_format"] = "signed-fixture"
        body = fastfiles.ZoneBody.parse(xasset_list((51,)))
        receipt = dict(status="decoded-and-validated", cache_key="fixture-key",
            final_body_sha256=body.source_sha256, final_body_bytes=len(body.data),
            source=profile, tools=dict(acts_tool_identity=self.acts_identity,
                acts_sha256=self.acts_identity["executable_sha256"],
                replay_executable_sha256=hashlib.sha256(self.replay.read_bytes()).hexdigest()),
            outputs=[dict(relative_path="decoded/synthetic.ff.dec")],
            final_body_relative_path="decoded/synthetic.ff.dec",
            xasset_table=dict(asset_count=len(body.assets),
                              first_payload_offset=body.first_payload_offset))
        with self.assertRaisesRegex(ValueError, "every decoded FP/FC patch output"):
            _validate_decode_receipt(receipt, body, "fixture-key", profile,
                self.acts_identity, hashlib.sha256(self.replay.read_bytes()).hexdigest(), self.source)

    def test_exact_signed_header_only_receipt_must_match_full_current_patch_proof(self):
        source, body_bytes, profile = self.signed_header_only_profile()
        body = fastfiles.ZoneBody.parse(body_bytes)
        patch = profile["patches"][0]
        patch_proof = dict(extension=patch["extension"], sha256=patch["sha256"],
                           previous_header_hex=patch["previous_header_hex"],
                           target_header_hex=patch["target_header_hex"],
                           previous_layout=patch["previous_layout"],
                           target_layout=patch["target_layout"])
        receipt = dict(status="decoded-and-validated", cache_key="fixture-key",
            final_body_sha256=body.source_sha256, final_body_bytes=len(body.data),
            source=profile, tools=dict(acts_tool_identity=self.acts_identity,
                acts_sha256=self.acts_identity["executable_sha256"],
                replay_executable_sha256=hashlib.sha256(self.replay.read_bytes()).hexdigest()),
            outputs=[dict(relative_path="decoded/synthetic.ff.dec")],
            final_body_relative_path="decoded/synthetic.ff.dec",
            xasset_table=dict(asset_count=len(body.assets),
                              first_payload_offset=body.first_payload_offset),
            patch_application=dict(mode="header-only-fp-no-body-change", patches=[patch_proof]))
        replay_sha = hashlib.sha256(self.replay.read_bytes()).hexdigest()
        _validate_decode_receipt(receipt, body, "fixture-key", profile,
                                 self.acts_identity, replay_sha, source)

        forged_cases = (
            ("wrong mode", dict(mode="acts-patch-outputs-required", patches=[patch_proof])),
            ("missing application", None),
            ("wrong full previous header", dict(mode="header-only-fp-no-body-change",
                patches=[dict(patch_proof, previous_header_hex="00" * 0x88)])),
            ("wrong full target header", dict(mode="header-only-fp-no-body-change",
                patches=[dict(patch_proof, target_header_hex="00" * 0x88)])),
            ("wrong layout", dict(mode="header-only-fp-no-body-change",
                patches=[dict(patch_proof, target_layout=dict(patch["target_layout"], decoded_size=1))])),
            ("wrong patch digest", dict(mode="header-only-fp-no-body-change",
                patches=[dict(patch_proof, sha256="0" * 64)])),
            ("omitted patch proof", dict(mode="header-only-fp-no-body-change", patches=[])),
        )
        for label, application in forged_cases:
            with self.subTest(label=label):
                forged = dict(receipt, patch_application=application)
                with self.assertRaises(ValueError):
                    _validate_decode_receipt(forged, body, "fixture-key", profile,
                        self.acts_identity, replay_sha, source)
        forged_source = json.loads(json.dumps(profile, default=str))
        forged_source["patches"][0]["previous_header_hex"] = "00" * 0x88
        forged_receipt = dict(receipt, source=forged_source)
        with self.assertRaisesRegex(ValueError, "full source/patch proof"):
            _validate_decode_receipt(forged_receipt, body, "fixture-key", profile,
                                     self.acts_identity, replay_sha, source)

    def test_source_change_during_decode_is_rejected(self):
        original_decode = fastfiles.decode_source_fastfile

        def change_source(source, cache_root, acts_path, replay_executable, *args, **kwargs):
            receipt = original_decode(source, cache_root, acts_path, replay_executable, *args, **kwargs)
            replacement = fastfiles.pack_replay_uncompressed(
                xasset_list((51, 254, 0)), (0,) * 11, transient_type=1)
            source.write_bytes(replacement)
            source.with_suffix(".fp").write_bytes(self.patch_for(replacement))
            return receipt

        with mock.patch.object(fastfiles, "decode_source_fastfile", side_effect=change_source):
            with self.assertRaises((ValueError, RuntimeError)):
                decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertFalse(self.cache.exists())

    def test_table_only_rows_never_claim_reference_or_asset_names(self):
        result = decode_table_only_metadata(self.workspace, "synthetic.ff")
        self.assertTrue(all(row["name"] is None and row["type_name"] is None and
                            row["reference_only"] is None for row in result["rows"]))
        self.assertTrue(all(row["status"] == "xasset-table-only-reader-unavailable"
                            for row in result["rows"]))


if __name__ == "__main__":
    unittest.main()
