import hashlib
import json
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workstation_d3d12_checkpoints as checkpoints  # noqa: E402


class D3D12CheckpointTests(unittest.TestCase):
    def test_matches_program_in_any_graphics_stage(self):
        payload = b"DXBC" + bytes(range(64))
        desc = bytearray(0x58)
        struct.pack_into("<QQ", desc, 0x38, 0x12345000, len(payload))
        read = lambda address, size: payload if (address, size) == (0x12345000, len(payload)) else b""
        matches = checkpoints.matching_shader_stages(
            desc, read, hashlib.sha256(payload).hexdigest(), maximum_shader_bytes=4096)
        self.assertEqual([row["stage"] for row in matches], ["HS"])

    def test_shader_capture_rejects_unbounded_size(self):
        desc = bytearray(0x58)
        struct.pack_into("<QQ", desc, 0x18, 0x10000, 4097)
        with self.assertRaisesRegex(ValueError, "bounded"):
            checkpoints.matching_shader_stages(desc, lambda *_: b"", "0" * 64, 4096)

    def test_resource_desc_exact_4x4_texture(self):
        desc = bytearray(56)
        struct.pack_into("<I4xQQIHHIIIII", desc, 0, 3, 0, 4, 4, 1, 1, 28, 1, 0, 0, 0)
        self.assertTrue(checkpoints.is_target_texture(desc, width=4, height=4))
        parsed = checkpoints.parse_resource_desc(desc)
        self.assertEqual((parsed["format"], parsed["sample_count"]), (28, 1))
        self.assertFalse(checkpoints.is_target_texture(desc, width=1, height=1))

    def test_replay_format7_resource_contract_is_complete(self):
        def descriptor(*, fmt=28, mips=1, samples=1):
            value = bytearray(56)
            struct.pack_into("<I4xQQIHHIIIII", value, 0, 3, 0, 4, 4, 1, mips,
                             fmt, samples, 0, 0, 0)
            return value
        self.assertTrue(checkpoints.is_replay_format7_resident_texture(descriptor(fmt=27)))
        self.assertTrue(checkpoints.is_replay_format7_resident_texture(descriptor(fmt=28)))
        self.assertTrue(checkpoints.is_replay_format7_resident_texture(descriptor(fmt=29)))
        self.assertFalse(checkpoints.is_replay_format7_resident_texture(descriptor(fmt=30)))
        self.assertFalse(checkpoints.is_replay_format7_resident_texture(descriptor(mips=2)))
        self.assertFalse(checkpoints.is_replay_format7_resident_texture(descriptor(samples=4)))

    def test_resource_descriptor_comparison_ignores_only_tail_padding(self):
        left = bytearray(56)
        struct.pack_into("<I4xQQIHHIIIII", left, 0, 3, 4096, 4, 4, 1, 1, 29, 1, 0, 0, 0)
        right = bytearray(left)
        right[52:56] = b"\x01\x02\x03\x04"
        self.assertTrue(checkpoints.resource_desc_semantically_equal(left, right))
        right[48] = 1
        self.assertFalse(checkpoints.resource_desc_semantically_equal(left, right))

    def test_success_requires_hresult_and_output_pointer(self):
        self.assertTrue(checkpoints.successful_com_creation(0, 0x1234))
        self.assertFalse(checkpoints.successful_com_creation(0, 0))
        self.assertFalse(checkpoints.successful_com_creation(0x80004005, 0x1234))

    def test_sdk_resource_desc_contract(self):
        header = Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\d3d12.h")
        if not header.exists():
            self.skipTest("Pinned Windows SDK header is unavailable")
        evidence = checkpoints.validate_d3d12_resource_desc_header(header)
        self.assertEqual((evidence["vtable_slot"], evidence["x64_size"]), (10, 56))

    def test_supplied_build_report_rva_map_round_trips_every_range(self):
        report_path = Path(__file__).resolve().parents[1] / "build-frontend-workstation-15667b91a73b487e" / "build-report.json"
        if not report_path.exists():
            self.skipTest("Supplied frontend build report is unavailable")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        ranges = report["rva_map"]["ranges"]
        self.assertGreater(len(ranges), 1)
        for entry in ranges:
            self.assertEqual(set(entry), {"begin", "end", "mapped_begin"})
            if entry["end"] <= entry["begin"]:
                continue
            for original in (entry["begin"], entry["end"] - 1):
                mapped = checkpoints.map_original_rva(report, original)
                self.assertEqual(checkpoints.unmap_mapped_rva(report, mapped), original)

    def test_pinned_sqlite_device_anchor(self):
        database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
        if not database.exists():
            self.skipTest("Pinned Replay SQLite database is unavailable")
        evidence = checkpoints.validate_sqlite_device_evidence(database)
        self.assertEqual(evidence["verified_vtable_slot"], 38)
        self.assertEqual(evidence["device_global_original_rva"], 0x10C79C20)


if __name__ == "__main__":
    unittest.main()
