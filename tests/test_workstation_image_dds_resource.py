import struct
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_asset_codecs import (
    export_replay_image_resource_to_dds,
    import_dds_to_replay_image_resource,
)


class ResidentDDSResourceTests(unittest.TestCase):
    def test_array_roundtrip_preserves_element_then_mip_order(self):
        # RGBA8: two 3x2 array elements, each with 3x2 then 1x1 mip data.
        resident = bytearray()
        for marker, raw in ((0x11, 24), (0x12, 4), (0x21, 24), (0x22, 4)):
            resident.extend(bytes([marker]) * raw)
            resident.extend(bytes((raw + 15) // 16 * 16 - raw))
        dds = export_replay_image_resource_to_dds(3, 2, 1, 2, 6, 2, bytes(resident))
        self.assertEqual(struct.unpack_from("<5I", dds, 128), (28, 3, 0, 2, 0))
        width, height, depth, elements, fmt, mips, rebuilt = import_dds_to_replay_image_resource(dds)
        self.assertEqual((width, height, depth, elements, fmt, mips), (3, 2, 1, 2, 6, 2))
        self.assertEqual(rebuilt, bytes(resident))

    def test_volume_roundtrip_preserves_depth_reduction_per_mip(self):
        # RGBA8 2x2x3 then 1x1x1; each 3D mip is one aligned subresource.
        resident = bytes(range(48)) + bytes(0) + bytes([0xA5]) * 4 + bytes(12)
        dds = export_replay_image_resource_to_dds(2, 2, 3, 1, 6, 2, resident)
        self.assertEqual(struct.unpack_from("<I", dds, 24)[0], 3)
        self.assertEqual(struct.unpack_from("<I", dds, 112)[0], 0x200000)
        self.assertEqual(struct.unpack_from("<5I", dds, 128), (28, 4, 0, 1, 0))
        self.assertEqual(import_dds_to_replay_image_resource(dds), (2, 2, 3, 1, 6, 2, resident))

    def test_import_rejects_shape_change_cube_and_trailing_bytes(self):
        resident = bytes(range(32))
        dds = export_replay_image_resource_to_dds(2, 2, 1, 2, 6, 1, resident)
        self.assertEqual(import_dds_to_replay_image_resource(dds)[3], 2)
        with self.assertRaisesRegex(ValueError, "cubemaps"):
            import_dds_to_replay_image_resource(dds[:136] + struct.pack("<I", 4) + dds[140:])
        with self.assertRaisesRegex(ValueError, "trailing"):
            import_dds_to_replay_image_resource(dds + b"x")
        with self.assertRaisesRegex(ValueError, "flag 0x40"):
            export_replay_image_resource_to_dds(2, 2, 1, 2, 6, 1, resident, flags=0x40)

    def test_nonzero_native_alignment_bytes_are_not_silently_discarded(self):
        with self.assertRaisesRegex(ValueError, "alignment bytes"):
            export_replay_image_resource_to_dds(1, 1, 1, 2, 6, 1, bytes(4) + b"x" + bytes(27))


if __name__ == "__main__":
    unittest.main()
