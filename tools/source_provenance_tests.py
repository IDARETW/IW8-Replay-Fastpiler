"""Regression checks for transitive-header deployment guards."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from source_provenance import parse_dependencies, snapshots, validate_record, validate_inputs


class SourceProvenanceTests(unittest.TestCase):
    def test_compiler_dependency_escaping(self):
        result = parse_dependencies("replay_deps: C:/source/main.cpp \\\n  C:/a\\ folder/header\\#1.h C:/cash$$/other.h C:/source/main.cpp\n")
        self.assertEqual(result, sorted({Path("C:/source/main.cpp").resolve(),
            Path("C:/a folder/header#1.h").resolve(), Path("C:/cash$/other.h").resolve()}))

    def test_unexpected_dependency_target(self):
        with self.assertRaisesRegex(ValueError, "target"):
            parse_dependencies("other: source.cpp\n")

    def fixture(self, directory):
        source, header, obj = [directory / name for name in ("main.cpp", "layout.h", "main.obj")]
        source.write_text('#include "layout.h"\n')
        header.write_text("struct Layout { int count; };\n")
        obj.write_bytes(b"compiled-object-fixture")
        record = dict(source="main.cpp", source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                      object="main.obj", object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                      dependencies=snapshots(sorted([source, header])))
        return record, header, obj

    def test_layout_header_edit_rejects_unchanged_cpp_and_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record, header, _ = self.fixture(directory)
            validate_record(record, directory)
            header.write_text("struct Layout { long long count; };\n")
            with self.assertRaisesRegex(ValueError, "compilation input changed"):
                validate_record(record, directory)

    def test_old_cpp_record_requires_recompilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record, _, _ = self.fixture(directory)
            del record["dependencies"]
            with self.assertRaisesRegex(ValueError, "provenance missing"):
                validate_record(record, directory)

    def test_object_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record, _, obj = self.fixture(directory)
            obj.write_bytes(b"different-object")
            with self.assertRaisesRegex(ValueError, "source/object changed"):
                validate_record(record, directory)

    def test_backend_or_compiler_change_invalidates_prepared_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'compiler.exe';path.write_bytes(b'compiler-one')
            inputs=snapshots([path]);validate_inputs(inputs)
            path.write_bytes(b'compiler-two-with-different-size')
            with self.assertRaisesRegex(ValueError,'Compilation input changed'):
                validate_inputs(inputs)


if __name__ == "__main__":
    unittest.main()
