import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import workstation_shader_growth as growth  # noqa: E402
from workstation_shader_identity import allocate_identity_batch  # noqa: E402


def dxbc(size: int, marker: int, type_id: int = 14) -> bytes:
    if size < 56:
        raise ValueError("test DXBC must have a complete chunk directory and shader token")
    stage = {14: 1, 15: 3, 16: 4, 17: 0}[type_id]
    data = bytearray([marker] * size)
    data[:4] = b"DXBC"
    struct.pack_into("<II", data, 24, size, 1)
    struct.pack_into("<I", data, 32, 36)
    data[36:56] = b"SHEX" + struct.pack("<IIII", 12, (stage << 16) | 0x50, 3, 0)
    return bytes(data)


class ShaderGrowthTests(unittest.TestCase):
    EXE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"

    def fixture(self):
        body = bytearray(420)
        programs = {2: dxbc(64, 0x21, 14), 7: dxbc(64, 0x47, 17)}
        roots = {2: 80, 7: 220}
        children = {2: 140, 7: 300}
        identities = {2: 0x11111111, 7: 0x77777777}
        names = {2: "first_shader", 7: "later_shader"}
        for index in (2, 7):
            struct.pack_into("<QII", body, roots[index] + 24,
                             0xFFFFFFFFFFFFFFFE, len(programs[index]), identities[index])
            body[children[index]:children[index] + len(programs[index])] = programs[index]
        source = bytes(body)
        source_sha = hashlib.sha256(source).hexdigest()
        assets = [SimpleNamespace(type_id=0) for _ in range(8)]
        assets[2] = SimpleNamespace(type_id=14)
        assets[7] = SimpleNamespace(type_id=17)
        parsed = SimpleNamespace(source_sha256=source_sha, assets=assets)

        def read_inline(body_data, row, trace, expected_sha, *, trace_assets=None):
            index = row["index"]
            program = programs[index]
            return dict(asset_index=index, type_id=assets[index].type_id, name=names[index],
                        root_archive_offset=roots[index], root_bytes=body_data[roots[index]:roots[index] + 40],
                        program_archive_offset=children[index], program=program,
                        program_sha256=hashlib.sha256(program).hexdigest())

        traces = {index: {"read_spans": [dict(archive_offset=children[index], size=len(programs[index]),
                                               origin="load_stream_call", reader_start_arg=0,
                                               destination_stream_location={"stream": 5,
                                                                            "offset": 1000 + index * 100})]}
                  for index in (2, 7)}
        rows = {index: {"index": index} for index in (2, 7)}
        inventory_rows = [dict(asset_index=index, type_id=assets[index].type_id,
                               name=names[index], root_archive_offset=roots[index],
                               program_identity=identities[index],
                               inline_dxbc_sha256=hashlib.sha256(programs[index]).hexdigest())
                          for index in (2, 7)]
        inventory = dict(schema="replay120-shader-identity-inventory-v1",
                         status="complete-trace-proven-shader-root-inventory",
                         replay_executable_sha256=self.EXE_SHA, body_sha256=source_sha,
                         shader_count=len(inventory_rows), shaders=inventory_rows)
        inventory["inventory_sha256"] = hashlib.sha256(json.dumps(
            inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        def relocate(body_data, layouts, replacements, trace_path, manifest_path):
            result = bytearray(body_data)
            for index, layout in layouts.items():
                struct.pack_into("<I", result, layout.root_archive_offset + 32,
                                 len(replacements[index]))
            for index, layout in sorted(layouts.items(),
                                        key=lambda item: item[1].child_archive_offset,
                                        reverse=True):
                start = layout.child_archive_offset
                result[start:start + layout.child_bytes] = replacements[index]
            return bytes(result), {"status": "mock-trace-relocation"}

        return SimpleNamespace(body=source, source_sha=source_sha, parsed=parsed,
                               programs=programs, roots=roots, children=children,
                               identities=identities, names=names, traces=traces,
                               rows=rows, inventory=inventory, read_inline=read_inline,
                               relocate=relocate)

    def invoke(self, fixture, edits, inventories=None):
        with patch.object(growth.ZoneBody, "parse", return_value=fixture.parsed), \
                patch.object(growth, "read_inline_shader", side_effect=fixture.read_inline), \
                patch.object(growth, "_validate_dxbc", side_effect=lambda value: None), \
                patch.object(growth, "relocate_stream5_children", side_effect=fixture.relocate):
            return growth.replace_inline_shaders_with_relocation(
                fixture.body, edits, fixture.source_sha, "trace.jsonl", "manifest.json",
                identity_inventories=inventories or [fixture.inventory],
                replay_executable_sha256=self.EXE_SHA)

    def edit(self, fixture, index, payload):
        return dict(asset_row=fixture.rows[index], trace_asset=fixture.traces[index], payload=payload)

    def test_multiple_growth_edits_patch_shifted_later_root_identity(self):
        f = self.fixture()
        replacements = {2: dxbc(72, 0x62, 14), 7: dxbc(76, 0x73, 17)}
        output, receipt = self.invoke(f, [self.edit(f, 2, replacements[2]),
                                          self.edit(f, 7, replacements[7])])
        expected = allocate_identity_batch([
            dict(owner_key="asset:0000000002", type_id=14, name=f.names[2], program=replacements[2]),
            dict(owner_key="asset:0000000007", type_id=17, name=f.names[7], program=replacements[7]),
        ], [f.inventory], self.EXE_SHA)
        allocated = {int(row["owner_key"].split(":")[1]): row["identity"] for row in expected}
        self.assertEqual(struct.unpack_from("<I", output, f.roots[2] + 36)[0], allocated[2])
        shifted_later_root = f.roots[7] + (len(replacements[2]) - len(f.programs[2]))
        self.assertEqual(struct.unpack_from("<I", output, shifted_later_root + 36)[0], allocated[7])
        self.assertEqual({row["asset_index"]: row["new_program_identity"]
                          for row in receipt["assets"]}, allocated)

    def test_batch_identity_is_deterministic_when_input_edit_order_reverses(self):
        f = self.fixture()
        replacements = {2: dxbc(72, 0x62, 14), 7: dxbc(76, 0x73, 17)}
        forward, forward_receipt = self.invoke(
            f, [self.edit(f, 2, replacements[2]), self.edit(f, 7, replacements[7])])
        reverse, reverse_receipt = self.invoke(
            f, [self.edit(f, 7, replacements[7]), self.edit(f, 2, replacements[2])])
        self.assertEqual(forward, reverse)
        self.assertEqual({r["asset_index"]: r["new_program_identity"]
                          for r in forward_receipt["assets"]},
                         {r["asset_index"]: r["new_program_identity"]
                          for r in reverse_receipt["assets"]})

    def test_wrong_source_inventory_is_rejected_before_relocation(self):
        f = self.fixture()
        wrong = dict(f.inventory, body_sha256="0" * 64)
        hash_input = {key: value for key, value in wrong.items() if key != "inventory_sha256"}
        wrong["inventory_sha256"] = hashlib.sha256(json.dumps(
            hash_input, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "exact source body"):
            self.invoke(f, [self.edit(f, 2, dxbc(72, 0x62, 14))], [wrong])

    def test_semantic_noop_retains_exact_body_and_both_identities(self):
        f = self.fixture()
        output, receipt = self.invoke(
            f, [self.edit(f, 7, f.programs[7]), self.edit(f, 2, f.programs[2])])
        self.assertEqual(output, f.body)
        self.assertEqual(struct.unpack_from("<I", output, f.roots[2] + 36)[0], f.identities[2])
        self.assertEqual(struct.unpack_from("<I", output, f.roots[7] + 36)[0], f.identities[7])
        self.assertTrue(all("new_program_identity" not in row for row in receipt["assets"]))

    def test_semantic_noop_rejects_bad_inventory_schema(self):
        f = self.fixture()
        bad = dict(f.inventory, schema="unknown-inventory")
        with self.assertRaisesRegex(ValueError, "schema"):
            self.invoke(f, [self.edit(f, 2, f.programs[2])], [bad])

    def test_semantic_noop_rejects_bad_inventory_canonical_hash(self):
        f = self.fixture()
        bad = dict(f.inventory, inventory_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "receipt hash"):
            self.invoke(f, [self.edit(f, 2, f.programs[2])], [bad])

    def test_semantic_noop_rejects_wrong_replay_image(self):
        f = self.fixture()
        bad = dict(f.inventory, replay_executable_sha256="0" * 64)
        hash_input = {key: value for key, value in bad.items() if key != "inventory_sha256"}
        bad["inventory_sha256"] = hashlib.sha256(json.dumps(
            hash_input, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "another Replay image"):
            self.invoke(f, [self.edit(f, 2, f.programs[2])], [bad])


if __name__ == "__main__":
    unittest.main()
