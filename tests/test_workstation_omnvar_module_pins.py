from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_fastfiles import (  # noqa: E402
    _omnvar_helper_module_identities,
    _omnvar_helper_modules_match,
)


class OmnvarModulePinTests(unittest.TestCase):
    def test_exact_current_helper_closure_matches(self):
        identity = _omnvar_helper_module_identities()
        self.assertEqual(set(identity), {
            "validator", "resolver", "stringtable", "asset_codecs", "trace_index",
            "semantic_export", "fastfiles"})
        self.assertTrue(_omnvar_helper_modules_match(identity))

    def test_changed_or_missing_helper_hash_fails_closed(self):
        identity = _omnvar_helper_module_identities()
        altered = {name: dict(value) for name, value in identity.items()}
        altered["stringtable"]["sha256"] = "0" * 64
        self.assertFalse(_omnvar_helper_modules_match(altered))
        self.assertFalse(_omnvar_helper_modules_match({name: value for name, value in identity.items()
                                                       if name != "resolver"}))

    def test_helper_path_cannot_be_repointed(self):
        identity = _omnvar_helper_module_identities()
        altered = {name: dict(value) for name, value in identity.items()}
        altered["validator"]["path"] = str(Path(identity["validator"]["path"]).with_name("other.py"))
        self.assertFalse(_omnvar_helper_modules_match(altered))


if __name__ == "__main__":
    unittest.main()
