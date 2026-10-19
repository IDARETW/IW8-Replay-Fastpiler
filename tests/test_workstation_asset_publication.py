"""Check that a package publication collision preserves existing outputs."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_mixed_asset_crud import _copy_verified_package
import workstation_mixed_asset_crud as writer


class PackagePublicationCollision(unittest.TestCase):
    def test_race_created_patch_is_preserved_and_only_owned_ff_is_rolled_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ff"
            source.write_bytes(b"verified-fastfile")
            source.with_suffix(".fp").write_bytes(b"verified-patch")
            output = root / "output.ff"
            external_patch = output.with_suffix(".fp")
            ff_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            fp_sha = hashlib.sha256(source.with_suffix(".fp").read_bytes()).hexdigest()
            digest = writer.sha256_file

            def collision_after_precheck(path):
                if path == source and not external_patch.exists():
                    external_patch.write_bytes(b"other-owner-patch")
                return digest(path)

            with patch.object(writer, "sha256_file", side_effect=collision_after_precheck):
                with self.assertRaises(FileExistsError):
                    _copy_verified_package(source, output, ff_sha, fp_sha)
            self.assertEqual(external_patch.read_bytes(), b"other-owner-patch")
            self.assertFalse(output.exists())
            # The same refusal applies to an FF that appeared independently.
            output.write_bytes(b"other-owner-fastfile")
            with self.assertRaises(FileExistsError):
                _copy_verified_package(source, output, ff_sha, fp_sha)
            self.assertEqual(output.read_bytes(), b"other-owner-fastfile")
            self.assertEqual(external_patch.read_bytes(), b"other-owner-patch")


if __name__ == "__main__":
    unittest.main()
