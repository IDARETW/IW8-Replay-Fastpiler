import struct
import unittest

from workstation_fastfiles import (
    _resident_image_typed_layout,
    _validate_resident_image_typed_layout,
)


def layout(dimensions):
    root = bytearray(232)
    struct.pack_into("<Q", root, 8, 0x1234)
    struct.pack_into("<Q", root, 0xD8, 0x5678)
    return dict(root_archive_offset=100, name_archive_offset=88,
                payload_archive_offset=120, payload=b"pixels", format=28,
                dimensions=dimensions, level_count=4, flags=9, root_bytes=bytes(root))


class ResidentImageTypedLayoutCompatibilityTests(unittest.TestCase):
    def test_2d_png_identity_keeps_the_legacy_schema_and_validates(self):
        current = layout((256, 128, 1, 1))
        identity = _resident_image_typed_layout(current)
        self.assertEqual(identity, dict(root_archive_offset=100, name_archive_offset=88,
                                        child_archive_offset=120, child_bytes=6, format=28,
                                        dimensions=[256, 128, 1, 1], level_count=4))
        _validate_resident_image_typed_layout(identity, current)

    def test_complex_dds_identity_requires_and_checks_every_extent_field(self):
        current = layout((64, 32, 8, 1))
        identity = _resident_image_typed_layout(current)
        self.assertEqual(identity["resource_kind"], "volume")
        self.assertEqual(identity["volume_depth"], 8)
        _validate_resident_image_typed_layout(identity, current)
        incomplete = {key: value for key, value in identity.items() if key != "flags"}
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            _validate_resident_image_typed_layout(incomplete, current)
        changed = dict(identity, volume_depth=7)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            _validate_resident_image_typed_layout(changed, current)

    def test_legacy_2d_identity_still_rejects_changed_native_core_geometry(self):
        current = layout((256, 128, 1, 1))
        identity = _resident_image_typed_layout(current)
        changed = dict(identity, child_archive_offset=121)
        with self.assertRaisesRegex(ValueError, "root/child layout changed"):
            _validate_resident_image_typed_layout(changed, current)

    def test_expanded_2d_draft_checks_optional_native_fields_without_changing_schema(self):
        current = layout((256, 128, 1, 1))
        identity = _resident_image_typed_layout(current)
        expanded_draft = dict(identity, flags=9, atlas_token=0x1234, fallback_token=0x5678)
        _validate_resident_image_typed_layout(expanded_draft, current)
        for key in ("flags", "atlas_token", "fallback_token"):
            changed = dict(expanded_draft, **{key: expanded_draft[key] + 1})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "root flags or child references"):
                _validate_resident_image_typed_layout(changed, current)
        self.assertEqual(set(identity), {"root_archive_offset", "name_archive_offset",
                                         "child_archive_offset", "child_bytes", "format",
                                         "dimensions", "level_count"})


if __name__ == "__main__":
    unittest.main()
