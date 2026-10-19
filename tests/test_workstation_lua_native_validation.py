import hashlib
import unittest
from pathlib import Path
from unittest import mock

from tools.verify_replay_lua_native_compile import (
    ALLOCATOR_GROWTH_REPRO_SHA256,
    BINDINGS,
    load_allocator_growth_repro,
    load_or_build_profile,
    validation_sources,
)


class ReplayLuaNativeValidationTests(unittest.TestCase):
    def test_allocator_growth_fixture_is_pinned_and_exercises_condition_dvar_path(self):
        source = load_allocator_growth_repro()
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self.assertEqual(digest, ALLOCATOR_GROWTH_REPRO_SHA256)
        self.assertIn("if not CONDITIONS.IsPC(self)", source)
        self.assertIn('Dvar.IBEGCHEFE("LKSTRMKTML")', source)

    def test_allocator_growth_case_is_mandatory_in_validation_plan(self):
        planned = validation_sources("stock", "edited", load_allocator_growth_repro())
        self.assertEqual(set(planned), {"stock_source", "edited_source", "allocator_growth_repro"})
        self.assertIn("CONDITIONS.IsPC", planned["allocator_growth_repro"])

    def test_existing_profile_is_bound_to_selected_image_and_stable_api_ids(self):
        with mock.patch("tools.verify_replay_lua_native_compile.sha256") as digest:
            digest.return_value = "target-image"
            with mock.patch("tools.verify_replay_lua_native_compile.build_profile") as build:
                # No regeneration should occur when setup already wrote the profile.
                import json
                import tempfile

                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    acts = root / "acts.exe"
                    replay = root / "replay.exe"
                    profile_path = root / "replay120_lua_native.json"
                    acts.write_bytes(b"acts")
                    replay.write_bytes(b"replay")
                    bindings = {
                        name: {"function_id": stable_id, "rva": index + 1}
                        for index, (name, stable_id) in enumerate(BINDINGS.items())
                    }
                    profile = {
                        "scans": {"lua": {
                            name: {"type": "Offset", "scan": f"0x{binding['rva']:x}"}
                            for name, binding in bindings.items()
                        }},
                        "__provenance": {"image_sha256": "target-image", "bindings": bindings},
                    }
                    profile_path.write_text(json.dumps(profile), encoding="utf-8")
                    result_path, result = load_or_build_profile(acts, replay, profile_path)
                    self.assertEqual(result_path, profile_path)
                    self.assertEqual(result, profile)
                    build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
