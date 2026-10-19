import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_sources import SourceWorkspace
import source_provenance


class CppBindingSnapshotAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cpp-binding-audit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.cache = Path(self.temp.name) / "cache"
        generated = self.root / "generated"
        generated.mkdir(parents=True)
        self.image = "a" * 64
        (generated / "manifest.json").write_text(json.dumps({
            "input_sha256": self.image, "image_base": 0x140000000}), encoding="utf-8")
        (generated / "function-catalog.json").write_text(json.dumps({
            "image_sha256": self.image,
            "functions": [{"id": "fn_0123456789abcdef", "name": "BoundFunction",
                           "rva": 0x1000, "aliases": ["BoundFunction"]}],
            "symbols": []}), encoding="utf-8")
        self.sqlite = Path(self.temp.name) / "analysis.sqlite"
        with closing(sqlite3.connect(self.sqlite)) as db:
            db.execute("CREATE TABLE functions (address TEXT, name TEXT)")
            db.execute("INSERT INTO functions VALUES (?, ?)", ("0x140001000", "BoundFunction"))
            db.commit()
        self.source = self.root / "src" / "bound.cpp"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"int BoundFunction() { return 1; }\n")
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def _write_persisted_binding(self, source_name):
        units_path = self.root / "source-workstation" / "units.json"
        units_path.parent.mkdir(parents=True, exist_ok=True)
        units_path.write_text(json.dumps({
            "schema": 1, "image_sha256": self.image,
            "units": [{"kind": "cpp", "function_id": "fn_0123456789abcdef",
                       "source": source_name, "symbol": "BoundFunction",
                       "sha256": self.digest, "revision": self.digest,
                       "language": "cpp"}]}), encoding="utf-8")
        return units_path

    def test_persisted_cpp_source_path_must_be_canonical_relative_src_path(self):
        invalid = [str(self.source.resolve()), "src/sub/../bound.cpp"]
        for source_name in invalid:
            with self.subTest(source=source_name):
                self._write_persisted_binding(source_name)
                workspace = SourceWorkspace(self.root, self.cache, self.sqlite)
                with self.assertRaisesRegex(ValueError, "Persisted catalog C\\+\\+ source path is invalid"):
                    workspace.build_source_units()
                with self.assertRaisesRegex(ValueError, "Persisted catalog C\\+\\+ source path is invalid"):
                    workspace.get_source("fn_0123456789abcdef", "cpp")

    def test_normalized_relative_cpp_binding_still_reopens_and_builds(self):
        self._write_persisted_binding("src/./bound.cpp")
        workspace = SourceWorkspace(self.root, self.cache, self.sqlite)
        unit = workspace.build_source_units()["units"][0]
        self.assertEqual(unit["source"], "src/bound.cpp")
        opened = workspace.get_source("fn_0123456789abcdef", "cpp")
        self.assertEqual(opened["content"].encode(), self.source.read_bytes())

    def test_same_size_mtime_restored_snapshot_rewrite_is_rejected(self):
        path = Path(self.temp.name) / "source-workstation-units.json"
        original = b'{"units": []}'
        changed = b'{"units" :[]}'
        self.assertEqual(len(original), len(changed))
        self.assertNotEqual(original, changed)
        path.write_bytes(original)
        pinned = {"path": str(path), "sha256": hashlib.sha256(original).hexdigest()}
        source_provenance.validate_inputs([pinned])

        before = path.stat()
        path.write_bytes(changed)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = path.stat()
        self.assertEqual(before.st_size, after.st_size)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pinned["sha256"])
        with self.assertRaisesRegex(ValueError, "Compilation input changed"):
            source_provenance.validate_inputs([pinned])

    def test_duplicate_input_is_hashed_once_per_validation_batch(self):
        path = Path(self.temp.name) / "shared-compiler.bin"
        path.write_bytes(b"compiler")
        pin = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        original_read = Path.read_bytes
        reads = []

        def counted_read(candidate):
            if candidate.resolve() == path.resolve():
                reads.append(candidate)
            return original_read(candidate)

        with patch.object(Path, "read_bytes", counted_read):
            source_provenance.validate_inputs([pin, dict(pin)])
        self.assertEqual(len(reads), 1)

    def test_duplicate_path_with_conflicting_expected_hash_fails_closed(self):
        path = Path(self.temp.name) / "shared-compiler.bin"
        path.write_bytes(b"compiler")
        good = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        conflicting = {"path": str(path), "sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "Compilation input changed"):
            source_provenance.validate_inputs([good, conflicting])

    def test_report_batches_repeated_compiler_identity(self):
        base = Path(self.temp.name) / "build"
        base.mkdir()
        compiler = base / "clang.exe"
        compiler.write_bytes(b"one compiler image")
        compiler_pin = {"path": str(compiler), "sha256": hashlib.sha256(compiler.read_bytes()).hexdigest()}
        backend = base / "backend.bin"
        recovery = base / "recovery.bin"
        backend.write_bytes(b"backend")
        recovery.write_bytes(b"recovery")
        snapshot = lambda path: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        records = []
        for index in range(2):
            source = base / f"unit{index}.s"
            obj = base / f"unit{index}.obj"
            source.write_bytes(f"asm {index}".encode())
            obj.write_bytes(f"object {index}".encode())
            records.append({
                "source": source.name,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "object": obj.name,
                "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(),
                "dependencies": [],
                "compiler": dict(compiler_pin),
            })
        report = {
            "backend_version": 2,
            "backend_inputs": [snapshot(backend)],
            "recovery_inputs": [snapshot(recovery)],
            "cpp": [], "assembly": records[:1], "native_assembly": records[1],
        }
        original_read = Path.read_bytes
        compiler_reads = []

        def counted_read(candidate):
            if candidate.resolve() == compiler.resolve():
                compiler_reads.append(candidate)
            return original_read(candidate)

        original_validate_record = source_provenance.validate_record
        validate_record_in_fixture = lambda record: original_validate_record(record, base)
        with patch.object(source_provenance, "validate_record", validate_record_in_fixture), \
             patch.object(Path, "read_bytes", counted_read):
            source_provenance.validate_report(report)
        self.assertEqual(len(compiler_reads), 1)


if __name__ == "__main__":
    unittest.main()
