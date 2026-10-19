import unittest

from tools.bootstrap_workstation_lua import (
    HEADLESS_CONSOLE, HEADLESS_MODE, ORIGINAL_CONSOLE, ORIGINAL_MODE, patch_headless,
)


class LuaBootstrapTests(unittest.TestCase):
    def test_unattended_console_patch_is_idempotent_and_rejects_source_drift(self):
        source = ORIGINAL_CONSOLE + "\n#ifdef _DEBUG\n#else\n" + ORIGINAL_MODE + "\n#endif\n"
        patched = patch_headless(source)
        self.assertIn(HEADLESS_CONSOLE, patched)
        self.assertIn(HEADLESS_MODE, patched)
        self.assertEqual(patch_headless(patched), patched)
        with self.assertRaises(ValueError):
            patch_headless("an incompatible console implementation")


if __name__ == '__main__':
    unittest.main()
