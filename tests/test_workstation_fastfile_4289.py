import struct
import sys
from unittest import mock
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workstation_fastfile_4289 as ff4289


def minimal_body():
    # Empty native XAssetList root: no ScriptStrings and no asset rows.
    return struct.pack("<IIQIIQ", 0, 0, 0, 0, 0, 0)


def target_header(body_size=32):
    header = bytearray(0x88)
    header[:8] = b"IWffa100"
    struct.pack_into("<II", header, 8, 11, 4289)
    header[0x10:0x13] = bytes((1, 0, 0))
    struct.pack_into("<I", header, 0x14, 0x1000)
    struct.pack_into("<I", header, 0x1C, body_size)
    struct.pack_into("<Q", header, 0x20, body_size)
    struct.pack_into("<Q", header, 0x28, 17)
    struct.pack_into("<11Q", header, 0x30, *([64] + [0] * 10))
    return bytes(header)


class WorkstationFastfile4289Tests(unittest.TestCase):
    def test_uncompressed_roundtrip_uses_4289_and_exact_iwc_boundary(self):
        body = minimal_body()
        packed = ff4289.pack_uncompressed_4289(body, target_header())
        self.assertEqual(packed[:8], b"IWffc100")
        self.assertEqual(struct.unpack_from("<II", packed, 8), (11, 4289))
        self.assertEqual(packed[0x88:0x8C], b"\x02IWC")
        self.assertEqual(ff4289.unpack_uncompressed_4289(packed), body)
        self.assertEqual(struct.unpack_from("<Q", packed, 0x20)[0], len(body))
        self.assertEqual(struct.unpack_from("<Q", packed, 0x28)[0], 17)
        self.assertEqual(struct.unpack_from("<11Q", packed, 0x30), (64,) + (0,) * 10)

    def test_rejects_4087_header_without_weakening_version_gate(self):
        header = bytearray(target_header())
        struct.pack_into("<I", header, 0x0C, 4087)
        with self.assertRaisesRegex(ValueError, "not XFile 4289"):
            ff4289.pack_uncompressed_4289(minimal_body(), bytes(header))

    def test_4289_stream_reservations_are_not_a_body_partition(self):
        packed = ff4289.pack_uncompressed_4289(
            minimal_body(), target_header(), stream_sizes=[0] * 11)
        self.assertEqual(ff4289.unpack_uncompressed_4289(packed), minimal_body())

    def test_rejects_corrupt_chunk_boundary(self):
        packed = bytearray(ff4289.pack_uncompressed_4289(minimal_body() + b"x", target_header()))
        packed[-1] ^= 0x20
        with self.assertRaises(ValueError):
            ff4289.unpack_uncompressed_4289(bytes(packed))

    def test_header_only_fp_pair_binds_both_headers_to_output(self):
        packed = ff4289.pack_uncompressed_4289(minimal_body(), target_header())
        template = bytearray(0x148)
        template[:8] = b"IWffd100"
        struct.pack_into("<II", template, 8, 6, 4)
        patch = ff4289.make_header_only_fp_4289(bytes(template), packed)
        self.assertEqual(len(patch), 0x148)
        self.assertEqual(patch[0x38:0xC0], packed[:0x88])
        self.assertEqual(patch[0xC0:0x148], packed[:0x88])

    def test_rejects_signed_template_with_compression_profile_drift(self):
        header = bytearray(target_header())
        header[0x10] = 0
        with self.assertRaisesRegex(ValueError, "signed 4289 source profile"):
            ff4289.pack_uncompressed_4289(minimal_body(), bytes(header))

    def test_changed_body_requires_final_reservations_and_walk_size(self):
        profile = {"final_header": {"decoded_size": len(minimal_body()) + 8}}
        with mock.patch.object(ff4289, "inspect_4289_source", return_value=profile):
            with self.assertRaisesRegex(ValueError, "requires explicit final stream reservations"):
                ff4289.write_4289_pair(minimal_body(), b"unused", b"unused", "unused.ff")


if __name__ == "__main__":
    unittest.main()
