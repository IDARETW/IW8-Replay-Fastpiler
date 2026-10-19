import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "bootstrap_workstation_acts.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_workstation_acts", MODULE_PATH)
bootstrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrapper)


class ActsBootstrapTests(unittest.TestCase):
    def test_patch_matches_pinned_seven_file_manifest(self):
        manifest = bootstrapper.read_manifest()
        bootstrapper.verify_patch_paths(manifest)
        self.assertEqual(manifest["base_commit"], "6acfe4aeb3a122bc623c8f71971b2c2327f8d877")
        self.assertEqual(len(manifest["changed_paths"]), 7)
        self.assertEqual(manifest["build"]["cmake_target"], "AtianCodToolsCLI")
        self.assertFalse(manifest["build"]["gpl_build"])

    def test_build_job_limit_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 64"):
            bootstrapper.bootstrap(Path("unused"), jobs=0)


if __name__ == "__main__":
    unittest.main()
