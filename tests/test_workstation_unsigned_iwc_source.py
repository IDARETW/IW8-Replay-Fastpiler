import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workstation_fastfiles as fastfiles


def empty_xasset_list():
    # Empty Replay XAssetList root: no script strings and no asset rows.
    return struct.pack("<IIQIIQ", 0, 0, 0, 0, 0, 0)


def header_only_patch(ff: bytes) -> bytes:
    template = bytearray(0x148)
    template[:8] = b"IWffd100"
    struct.pack_into("<II", template, 8, 6, 4)
    return fastfiles.make_replay_header_only_patch(bytes(template), ff)


class UnsignedIwcSourceTests(unittest.TestCase):
    def write_pair(self, directory: Path, *, body: bytes | None = None,
                   stream_sizes=(0,) * 11, chunk_size=0x10000) -> tuple[Path, bytes]:
        path = directory / "generated.ff"
        ff = fastfiles.pack_replay_uncompressed(
            empty_xasset_list() if body is None else body, stream_sizes,
            transient_type=1, chunk_size=chunk_size)
        path.write_bytes(ff)
        path.with_suffix(".fp").write_bytes(header_only_patch(ff))
        return path, ff

    def rewrite_patch(self, path: Path, transform) -> None:
        raw = bytearray(path.with_suffix(".fp").read_bytes())
        transform(raw)
        path.with_suffix(".fp").write_bytes(raw)

    def test_roundtrip_writer_output_has_separate_unsigned_profile_and_exact_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path, ff = self.write_pair(Path(directory), stream_sizes=(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
            profile = fastfiles.source_profile(path)
            self.assertEqual(profile["input_format"], "replay120-iwc-uncompressed-v1")
            self.assertFalse(profile["signature_verified"])
            self.assertIsNone(profile["header_signature_marker"])
            self.assertEqual(profile["header"]["magic"], "IWffc100")
            self.assertEqual(profile["header"]["xfile_version"], 0xFF7)
            self.assertEqual(profile["final_header"]["decoded_size"], len(empty_xasset_list()))
            self.assertEqual(profile["final_header"]["block_sizes"], list(range(11)))
            self.assertEqual(len(profile["patches"]), 1)
            self.assertEqual(profile["patches"][0]["extension"], ".fp")
            self.assertEqual(profile["patches"][0]["previous_layout"],
                             profile["patches"][0]["target_layout"])
            self.assertEqual(fastfiles.unpack_replay_uncompressed(ff), empty_xasset_list())

    def test_decode_copies_unsigned_body_without_running_acts_and_marks_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "zone"
            source_dir.mkdir()
            path, ff = self.write_pair(source_dir)
            acts = root / "acts.exe"
            executable = root / "replay.exe"
            acts.write_bytes(b"fixture ACTS")
            executable.write_bytes(b"fixture Replay")
            exe_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            fake_acts_identity = dict(executable_sha256=hashlib.sha256(acts.read_bytes()).hexdigest(),
                                      binaries=[], data_files=[])
            with patch.object(fastfiles, "REPLAY_EXECUTABLE_SHA256", exe_sha), \
                 patch.object(fastfiles, "acts_tool_identity", return_value=fake_acts_identity), \
                 patch.object(fastfiles.subprocess, "run", side_effect=AssertionError("ACTS decode must not run")):
                receipt = fastfiles.decode_source_fastfile(
                    path, root / "cache", acts_path=acts, replay_executable=executable)
            self.assertEqual(receipt["decoder"], "strict-python-replay120-iwc-uncompressed-v1")
            self.assertEqual({row["path"] for row in receipt["decoder_sources"]}, {
                "tools/workstation_fastfiles.py", "tools/frontend_catalog.py",
                "tools/inspect_frontend_asset_table.py",
            })
            self.assertEqual(receipt["tools"]["command"], [])
            self.assertEqual(receipt["source"]["sha256"], hashlib.sha256(ff).hexdigest())
            self.assertFalse(receipt["authenticity"]["cryptographic_signature_verified"])
            self.assertIsNone(receipt["authenticity"]["signature_block_sha256"])
            body_path = root / "cache" / path.stem / receipt["cache_key"] / receipt["final_body_relative_path"]
            self.assertEqual(body_path.read_bytes(), empty_xasset_list())
            self.assertEqual(receipt["reader_graph"]["status"], "table-only")

    def test_changed_decoder_helper_identity_cannot_hit_an_old_unsigned_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "zone"
            source_dir.mkdir()
            path, _ = self.write_pair(source_dir)
            acts = root / "acts.exe"
            executable = root / "replay.exe"
            acts.write_bytes(b"fixture ACTS")
            executable.write_bytes(b"fixture Replay")
            replay_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            acts_identity = dict(executable_sha256=hashlib.sha256(acts.read_bytes()).hexdigest(),
                                 binaries=[], data_files=[])
            first = [dict(path="tools/workstation_fastfiles.py", sha256="1" * 64)]
            second = [dict(path="tools/workstation_fastfiles.py", sha256="2" * 64)]
            with patch.object(fastfiles, "REPLAY_EXECUTABLE_SHA256", replay_sha), \
                 patch.object(fastfiles, "acts_tool_identity", return_value=acts_identity), \
                 patch.object(fastfiles, "_unsigned_iwc_decoder_sources",
                              side_effect=[first, first, second, second]):
                first_receipt = fastfiles.decode_source_fastfile(
                    path, root / "cache", acts_path=acts, replay_executable=executable)
                second_receipt = fastfiles.decode_source_fastfile(
                    path, root / "cache", acts_path=acts, replay_executable=executable)
            self.assertNotEqual(first_receipt["cache_key"], second_receipt["cache_key"])
            self.assertEqual(first_receipt["decoder_sources"], first)
            self.assertEqual(second_receipt["decoder_sources"], second)

    def test_uncompressed_parser_rejects_header_version_and_reserved_field_drift(self):
        valid = bytearray(fastfiles.pack_replay_uncompressed(empty_xasset_list(), (0,) * 11))
        mutations = [
            (8, struct.pack("<I", 10)),
            (12, struct.pack("<I", 0xFF6)),
            (16, b"\x01"),
            (17, b"\x01"),
            (18, b"\x02"),
            (19, b"\x01"),
            (0x18, struct.pack("<I", 1)),
            (0x1C, struct.pack("<I", len(empty_xasset_list()) + 1)),
            (0x20, struct.pack("<Q", len(empty_xasset_list()) + 1)),
            (0x28, struct.pack("<Q", 1)),
            (0x88, struct.pack("<I", 0)),
            (0x90, struct.pack("<I", (2 << 24) | 0x10000)),
        ]
        for offset, replacement in mutations:
            with self.subTest(offset=hex(offset)):
                changed = bytearray(valid)
                changed[offset:offset + len(replacement)] = replacement
                with self.assertRaises(ValueError):
                    fastfiles.unpack_replay_uncompressed(bytes(changed))

    def test_uncompressed_parser_rejects_chunk_length_counter_alignment_and_tail_errors(self):
        valid = bytearray(fastfiles.pack_replay_uncompressed(empty_xasset_list(), (0,) * 11,
                                                             chunk_size=1))
        # With one-byte chunks the first chunk payload begins at 0xa0 and its
        # three alignment bytes begin at 0xa1.
        changed = bytearray(valid)
        changed[0xA1] = 1
        with self.assertRaisesRegex(ValueError, "alignment"):
            fastfiles.unpack_replay_uncompressed(bytes(changed))
        changed = bytearray(valid)
        struct.pack_into("<I", changed, 0x9C, 1)
        with self.assertRaisesRegex(ValueError, "chunk"):
            fastfiles.unpack_replay_uncompressed(bytes(changed))
        changed = bytearray(valid)
        struct.pack_into("<I", changed, 0x94, 0)
        with self.assertRaisesRegex(ValueError, "chunk"):
            fastfiles.unpack_replay_uncompressed(bytes(changed))
        changed = bytearray(valid)
        changed.extend(b"\0")
        struct.pack_into("<I", changed, 0x14, len(changed) - 0x88)
        with self.assertRaisesRegex(ValueError, "boundary"):
            fastfiles.unpack_replay_uncompressed(bytes(changed))

    def test_unsigned_source_requires_only_the_exact_writer_emitted_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            path, ff = self.write_pair(Path(directory))
            path.with_suffix(".fp").unlink()
            with self.assertRaisesRegex(ValueError, "requires exactly one"):
                fastfiles.source_profile(path)
            path.with_suffix(".fp").write_bytes(header_only_patch(ff))
            path.with_suffix(".fc").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "requires exactly one"):
                fastfiles.source_profile(path)

    def test_unsigned_source_rejects_malformed_patch_extent_version_flags_payload_and_headers(self):
        for label, mutate in (
            ("extent", lambda raw: raw.extend(b"x")),
            ("version", lambda raw: struct.pack_into("<I", raw, 8, 5)),
            ("flags", lambda raw: struct.pack_into("<I", raw, 0x0C, 5)),
            ("payload", lambda raw: raw.__setitem__(0x10, 1)),
            ("previous", lambda raw: raw.__setitem__(0x38, ord("X"))),
            ("target", lambda raw: raw.__setitem__(0xC0 + 0x10, 1)),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                path, ff = self.write_pair(Path(directory))
                self.rewrite_patch(path, mutate)
                with self.assertRaises(ValueError):
                    fastfiles.source_profile(path)

    def test_source_profile_does_not_route_stored_frame_or_signed_parser_through_iwc(self):
        ff = fastfiles.pack_replay_uncompressed(empty_xasset_list(), (0,) * 11)
        with self.assertRaisesRegex(ValueError, "signed IW Replay FFs"):
            fastfiles.SourceFastfileHeader.parse(ff)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "other.ff"
            bad = bytearray(ff)
            bad[:8] = b"IWffx100"
            path.write_bytes(bad)
            with self.assertRaises(ValueError):
                fastfiles.source_profile(path)


if __name__ == "__main__":
    unittest.main()
