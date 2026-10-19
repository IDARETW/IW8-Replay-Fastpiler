import hashlib
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workstation_fastfiles as fastfiles


def empty_xasset_list():
    return struct.pack("<IIQIIQ", 0, 0, 0, 0, 0, 0)


def signed_header(xfile_version: int, transient_type: int) -> bytes:
    raw = bytearray(0xA0)
    raw[:8] = b"IWffa100"
    struct.pack_into("<II", raw, 8, fastfiles.HEADER_VERSION_REPLAY, xfile_version)
    raw[0x10:0x13] = bytes((1, 0, transient_type))
    struct.pack_into("<I", raw, 0x14, len(raw) - 0x88)
    raw[0x88:0x90] = b"IWffs100"
    return bytes(raw)


def stored_frame(body: bytes) -> bytes:
    raw = bytearray(0x88)
    raw[:8] = b"IWffc100"
    struct.pack_into("<II", raw, 8, fastfiles.HEADER_VERSION_REPLAY, 0xFF7)
    raw[16:19] = b"\0\0\0"
    struct.pack_into("<I", raw, 0x14, len(body) + 4)
    struct.pack_into("<I", raw, 0x1C, len(body))
    struct.pack_into("<QQ", raw, 0x20, len(body), len(body))
    struct.pack_into("<Q", raw, 0x30, len(body))
    return bytes(raw) + fastfiles.FRAME_MARKER + body


def signed_source_with_header_only_fp(directory: Path) -> tuple[Path, bytes]:
    body = empty_xasset_list()
    directory = directory / "zone"
    directory.mkdir()
    raw = bytearray(0xA0)
    raw[:8] = b"IWffa100"
    struct.pack_into("<II", raw, 8, fastfiles.HEADER_VERSION_REPLAY, 4047)
    raw[0x10:0x13] = bytes((1, 0, 0))
    struct.pack_into("<I", raw, 0x14, len(raw) + len(body) - 0x88)
    struct.pack_into("<Q", raw, 0x20, len(body))
    struct.pack_into("<Q", raw, 0x30, len(body))
    raw[0x88:0x90] = b"IWffs100"
    source = directory / "signed-transition.ff"
    source.write_bytes(bytes(raw) + body)
    target = bytearray(raw[:0x88])
    struct.pack_into("<I", target, 0x0C, 4087)
    patch_bytes = bytearray(0x148)
    patch_bytes[:8] = b"IWffd100"
    struct.pack_into("<II", patch_bytes, 8, 6, 4)
    patch_bytes[0x38:0xC0] = raw[:0x88]
    patch_bytes[0xC0:0x148] = target
    source.with_suffix(".fp").write_bytes(patch_bytes)
    return source, body


class SourceReadAdmissionTests(unittest.TestCase):
    def test_signed_transient_13_is_admitted_only_for_observed_xfile_4045(self):
        accepted = fastfiles.SourceFastfileHeader.parse(signed_header(4045, 13))
        self.assertEqual((accepted.xfile_version, accepted.transient_type), (4045, 13))
        self.assertIn(4045, fastfiles.OBSERVED_REPLAY_SOURCE_REVISIONS)
        observed_nonstandard = {
            *((4045, transient) for transient in range(7, 14)),
            (4065, 5), (4083, 2), (4083, 3), (4083, 5),
        }
        self.assertEqual(observed_nonstandard,
                         fastfiles.OBSERVED_REPLAY_NONSTANDARD_TRANSIENT_PROFILES)
        for revision, transient in sorted(observed_nonstandard):
            parsed = fastfiles.SourceFastfileHeader.parse(signed_header(revision, transient))
            self.assertEqual((parsed.xfile_version, parsed.transient_type),
                             (revision, transient))
        for revision, transient in ((4046, 13), (4047, 13), (4045, 6),
                                    (4045, 14), (4065, 4), (4065, 6),
                                    (4083, 4), (4083, 6)):
            with self.subTest(revision=revision, transient=transient), \
                    self.assertRaises(ValueError):
                fastfiles.SourceFastfileHeader.parse(signed_header(revision, transient))

    def test_source_header_extent_and_marker_checks_still_apply_to_transient_13(self):
        valid = bytearray(signed_header(4045, 13))
        bad_marker = bytearray(valid)
        bad_marker[0x88] ^= 1
        with self.assertRaisesRegex(ValueError, "marker"):
            fastfiles.SourceFastfileHeader.parse(bytes(bad_marker))
        with self.assertRaisesRegex(ValueError, "extent"):
            fastfiles.SourceFastfileHeader.parse(bytes(valid), file_bytes=len(valid) + 1)

    def test_unsigned_writer_and_stored_reader_do_not_admit_transient_13(self):
        with self.assertRaisesRegex(ValueError, "transient"):
            fastfiles.pack_replay_uncompressed(empty_xasset_list(), (0,) * 11,
                                               transient_type=13)
        frame = bytearray(stored_frame(empty_xasset_list()))
        frame[0x12] = 13
        with self.assertRaisesRegex(ValueError, "transient"):
            fastfiles.StoredReplayFastfile.parse(bytes(frame))

    def test_stored_frame_source_profile_and_decode_use_strict_v1_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zone = root / "zone"
            zone.mkdir()
            source = zone / "sample.ff"
            source.write_bytes(stored_frame(empty_xasset_list()))
            profile = fastfiles.source_profile(source)
            self.assertEqual(profile["input_format"], "replay120-stored-frame-v1")
            self.assertEqual(profile["stored_xasset_count"], 0)
            self.assertEqual(profile["patches"], [])
            acts = root / "acts.exe"
            replay = root / "replay.exe"
            acts.write_bytes(b"acts fixture")
            replay.write_bytes(b"replay fixture")
            replay_sha = hashlib.sha256(replay.read_bytes()).hexdigest()
            acts_identity = dict(executable_sha256=hashlib.sha256(acts.read_bytes()).hexdigest(),
                                 binaries=[], data_files=[])
            with patch.object(fastfiles, "REPLAY_EXECUTABLE_SHA256", replay_sha), \
                 patch.object(fastfiles, "acts_tool_identity", return_value=acts_identity), \
                 patch.object(fastfiles.subprocess, "run",
                              side_effect=AssertionError("stored frame must not invoke ACTS")):
                receipt = fastfiles.decode_source_fastfile(
                    source, root / "cache", acts_path=acts, replay_executable=replay)
            self.assertEqual(receipt["decoder"],
                             "strict-python-replay120-stored-frame-v1")
            body = (root / "cache" / source.stem / receipt["cache_key"] /
                    receipt["final_body_relative_path"]).read_bytes()
            self.assertEqual(body, empty_xasset_list())

    def test_exact_zero_payload_signed_fp_uses_base_body_and_records_both_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, body = signed_source_with_header_only_fp(root)
            profile = fastfiles.source_profile(source)
            self.assertTrue(profile["header_only_zero_payload_chain"])
            patch_row = profile["patches"][0]
            self.assertEqual(patch_row["bytes"], 0x148)
            self.assertTrue(patch_row["header_only_zero_payload"])
            self.assertEqual(bytes.fromhex(patch_row["previous_header_hex"]),
                             source.read_bytes()[:0x88])
            self.assertEqual(struct.unpack_from("<I", bytes.fromhex(
                patch_row["target_header_hex"]), 0x0C)[0], 4087)

            acts = root / "acts.exe"
            replay = root / "replay.exe"
            acts.write_bytes(b"acts fixture")
            replay.write_bytes(b"replay fixture")
            replay_sha = hashlib.sha256(replay.read_bytes()).hexdigest()
            acts_identity = dict(executable_sha256=hashlib.sha256(acts.read_bytes()).hexdigest(),
                                 binaries=[], data_files=[])

            def fake_acts(command, *, stdout, stderr, check, timeout):
                decoded_dir = Path(command[7])
                decoded = decoded_dir / f"{source.name}.dec"
                decoded.write_bytes(body)
                stdout.write(f"Loading {source}... (IW)\nDump ff into {decoded}\n")
                return SimpleNamespace(returncode=0)

            with patch.object(fastfiles, "REPLAY_EXECUTABLE_SHA256", replay_sha), \
                 patch.object(fastfiles, "acts_tool_identity", return_value=acts_identity), \
                 patch.object(fastfiles.subprocess, "run", side_effect=fake_acts):
                receipt = fastfiles.decode_source_fastfile(
                    source, root / "cache", acts_path=acts, replay_executable=replay)
            self.assertEqual(receipt["patch_application"]["mode"],
                             "header-only-fp-no-body-change")
            self.assertEqual(receipt["final_body_sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(receipt["patch_application"]["patches"][0]["previous_header_hex"],
                             patch_row["previous_header_hex"])

    def test_signed_fp_with_any_payload_cannot_use_zero_payload_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, _ = signed_source_with_header_only_fp(root)
            with source.with_suffix(".fp").open("ab") as stream:
                stream.write(b"payload")
            profile = fastfiles.source_profile(source)
            self.assertFalse(profile["header_only_zero_payload_chain"])

    def test_signed_fp_fallback_rejects_changed_patch_fields_layout_and_fc(self):
        for label, mutate in (
            ("opaque patch data", lambda raw: raw.__setitem__(0x10, 1)),
            ("target stream layout", lambda raw: struct.pack_into("<Q", raw, 0xC0 + 0x30, 1)),
            ("target transient", lambda raw: raw.__setitem__(0xC0 + 0x12, 1)),
            ("other target header bytes", lambda raw: raw.__setitem__(0xC0 + 0x80, 1)),
            ("matching opaque previous and target bytes",
             lambda raw: (raw.__setitem__(0x38 + 0x18, 1),
                          raw.__setitem__(0xC0 + 0x18, 1))),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                source, _ = signed_source_with_header_only_fp(Path(directory))
                patch_bytes = bytearray(source.with_suffix(".fp").read_bytes())
                mutate(patch_bytes)
                source.with_suffix(".fp").write_bytes(patch_bytes)
                profile = fastfiles.source_profile(source)
                self.assertFalse(profile["header_only_zero_payload_chain"])
        with tempfile.TemporaryDirectory() as directory:
            source, _ = signed_source_with_header_only_fp(Path(directory))
            fp = source.with_suffix(".fp")
            fc = source.with_suffix(".fc")
            fc.write_bytes(fp.read_bytes())
            fp.unlink()
            profile = fastfiles.source_profile(source)
            self.assertFalse(profile["header_only_zero_payload_chain"])


if __name__ == "__main__":
    unittest.main()
