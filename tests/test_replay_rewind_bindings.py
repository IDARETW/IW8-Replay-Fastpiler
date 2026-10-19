import sys
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from replay_rewind_bindings import (
    _derive_verified_pointer_prefix,
    _reachable_function_rows,
    _relative_stream_call_argument,
    _relative_stream_table_evidence,
    _state_displacements,
    discover_bindings,
)


def ins(rva, mnemonic, op_str="", memory=(), *, branches=(), rip=(), next_rva=None):
    return {
        "rva": rva,
        "next_rva": rva + 1 if next_rva is None else next_rva,
        "bytes": "90",
        "mnemonic": mnemonic,
        "op_str": op_str,
        "rip_targets": list(rip),
        "memory_operands": list(memory),
        "direct_call_rvas": [],
        "direct_branch_rvas": list(branches),
    }


def mem(base, displacement, *, index=None, scale=1, size=4, target=None):
    result = {"base": base, "index": index, "scale": scale,
              "disp": displacement, "size": size}
    if target is not None:
        result["target_rva"] = target
    return result


def rewind_rows(mode_branch="je"):
    flag = 0x9000
    return [
        ins(0x100, "cmp", "byte ptr [rip + 0x10], 0",
            [mem("rip", 0x10, size=1, target=flag)], rip=[flag], next_rva=0x107),
        ins(0x107, mode_branch, "0x110", branches=[0x110], next_rva=0x109),
        ins(0x109, "mov", "eax, dword ptr [r10 + 0x6008]",
            [mem("r10", 0x6008)], next_rva=0x10c),
        ins(0x10c, "jmp", "0x120", branches=[0x120], next_rva=0x10e),
        ins(0x110, "mov", "eax, dword ptr [r10 + 0x6000]",
            [mem("r10", 0x6000)], next_rva=0x113),
        ins(0x113, "test", "eax, eax", next_rva=0x120),
        ins(0x120, "cmp", "r11d, dword ptr [r10 + 0x600c]",
            [mem("r10", 0x600c)], next_rva=0x124),
        ins(0x124, "mov", "ebx, dword ptr [r10 + 0x6004]",
            [mem("r10", 0x6004)], next_rva=0x128),
        ins(0x128, "cmp", "r11d, dword ptr [r10 + r8*8]",
            [mem("r10", 0, index="r8", scale=8)], next_rva=0x12c),
        ins(0x12c, "mov", "ebx, dword ptr [r10 + rcx*8 + 4]",
            [mem("r10", 4, index="rcx", scale=8)], next_rva=0x130),
    ]


class ReplayRewindBindingTests(unittest.TestCase):
    def test_branch_dataflow_maps_count_and_walk_offsets(self):
        result = _state_displacements(rewind_rows(), "r10", 0x9000)
        self.assertEqual(result["history_count"]["offset"], 0x6000)
        self.assertEqual(result["history_walk_index"]["offset"], 0x6008)
        self.assertEqual(result["current_rewind"]["offset"], 0x6004)
        self.assertEqual(result["last_expected_offset"]["offset"], 0x600C)

    def test_inverted_zero_branch_still_maps_roles_from_control_flow(self):
        result = _state_displacements(rewind_rows("jne"), "r10", 0x9000)
        self.assertEqual(result["history_count"]["offset"], 0x6008)
        self.assertEqual(result["history_walk_index"]["offset"], 0x6000)

    def test_history_stride_and_fields_come_from_indexed_operands(self):
        result = _state_displacements(rewind_rows(), "r10", 0x9000)
        history = result["history_entries"]
        self.assertEqual(history["stride"], 8)
        self.assertEqual(history["start_expected_offset"]["offset"], 0)
        self.assertEqual(history["rewind_value"]["offset"], 4)
        self.assertEqual(history["start_expected_offset"]["evidence"][0]["stride"], 8)

    def test_rejects_ambiguous_indexed_history_layout(self):
        rows = rewind_rows()
        rows.append(ins(0x134, "mov", "eax, dword ptr [r10 + r8*4]",
                        [mem("r10", 0, index="r8", scale=4)], next_rva=0x138))
        with self.assertRaisesRegex(ValueError, "Indexed history row stride"):
            _state_displacements(rows, "r10", 0x9000)

    def test_rejects_missing_branch_role_evidence(self):
        rows = [row for row in rewind_rows() if row["rva"] != 0x109]
        with self.assertRaisesRegex(ValueError, "scalar loaded on one postload branch"):
            _state_displacements(rows, "r10", 0x9000)

    def test_reachable_decode_ignores_unreachable_adjacent_function(self):
        rows = [
            ins(0x10, "je", "0x20", branches=[0x20], next_rva=0x11),
            ins(0x11, "ret", next_rva=0x12),
            ins(0x20, "ret", next_rva=0x21),
            ins(0x30, "mov", "eax, 7", next_rva=0x33),
        ]
        reachable = _reachable_function_rows(rows, 0x10)
        self.assertEqual({row["rva"] for row in reachable}, {0x10, 0x11, 0x20})

    def test_relative_stream_table_requires_exact_four_byte_indexed_access(self):
        rows = [
            ins(0x100, "lea", "rcx, [rip + 0x100]",
                [mem("rip", 0x100, size=8, target=0x205)], rip=[0x205], next_rva=0x107),
            ins(0x107, "mov", "eax, dword ptr [rcx + rax*4]",
                [mem("rcx", 0, index="rax", scale=4, size=4)], next_rva=0x10d),
            ins(0x10d, "ret")]
        evidence = _relative_stream_table_evidence(rows)
        self.assertEqual(evidence["table_rva"], 0x205)
        self.assertEqual(evidence["stride"], 4)
        self.assertEqual(evidence["read_size"], 4)
        rows[1]["memory_operands"][0]["scale"] = 8
        with self.assertRaisesRegex(ValueError, "4-byte stream-indexed read"):
            _relative_stream_table_evidence(rows)

    def test_relative_stream_call_argument_tracks_stack_spill_and_rejects_wrong_value(self):
        rows = [
            ins(0x100, "mov", "r14, qword ptr [rcx]",
                [mem("rcx", 0, size=8)], next_rva=0x104),
            ins(0x104, "mov", "rax, r14", next_rva=0x107),
            ins(0x107, "shr", "rax, 0x20", next_rva=0x10b),
            ins(0x10b, "and", "eax, 0xf", next_rva=0x10e),
            ins(0x10e, "mov", "dword ptr [rsp + 0x40], eax",
                [mem("rsp", 0x40, size=4)], next_rva=0x113),
            ins(0x113, "mov", "ecx, dword ptr [rsp + 0x40]",
                [mem("rsp", 0x40, size=4)], next_rva=0x11a),
            ins(0x11a, "call", "0x200", next_rva=0x11f)]
        evidence = _relative_stream_call_argument(rows, rows[-1])
        self.assertEqual(evidence["value"], "(token >> 32) & 0xf")
        self.assertIn(0x10e, evidence["instruction_rvas"])
        rows[5]["op_str"] = "ecx, edx"
        with self.assertRaisesRegex(ValueError, "does not receive its token stream id"):
            _relative_stream_call_argument(rows, rows[-1])

    def _prefix_rows(self, *, stride=8, bound=8, branch_target=None, bypass_update=False):
        table_rva = 0x9000
        rows = [
            ins(0x100, "xor", "esi, esi", next_rva=0x102),
            ins(0x102, "lea", "r14, [rip + 0x100]",
                [mem("rip", 0x100, size=8, target=table_rva)], rip=[table_rva], next_rva=0x108),
            ins(0x108, "mov", "rax, qword ptr [r14]",
                [mem("r14", 0, size=8)], next_rva=0x10b),
        ]
        if bypass_update:
            rows.extend([
                ins(0x10b, "test", "eax, eax", next_rva=0x10d),
                ins(0x10d, "je", "0x118", branches=[0x118], next_rva=0x10f),
            ])
            increment_at, step_at, compare_at = 0x10f, 0x111, 0x118
            rows.extend([
                ins(increment_at, "inc", "esi", next_rva=step_at),
                ins(step_at, "add", f"r14, {stride}", next_rva=0x115),
                ins(0x115, "nop", next_rva=compare_at),
            ])
        else:
            increment_at, step_at, compare_at = 0x10b, 0x10d, 0x111
            rows.extend([
                ins(increment_at, "inc", "esi", next_rva=step_at),
                ins(step_at, "add", f"r14, {stride}", next_rva=compare_at),
            ])
        target = 0x108 if branch_target is None else branch_target
        rows.extend([
            ins(compare_at, "cmp", f"esi, {bound}", next_rva=compare_at + 3),
            ins(compare_at + 3, "jb", hex(target), branches=[target], next_rva=compare_at + 9),
            ins(compare_at + 9, "ret", next_rva=compare_at + 10),
        ])
        return rows

    def test_prefix_loop_proof_derives_counter_stride_and_bound(self):
        proof = _derive_verified_pointer_prefix(self._prefix_rows(), 0x9000)
        self.assertEqual(proof["verified_prefix_count"], 8)
        self.assertIsNone(proof["allocation_count"])
        self.assertTrue(proof["full_table_count_unknown"])
        evidence = proof["evidence"]
        self.assertEqual(evidence["counter_zero_init"]["op_str"], "esi, esi")
        self.assertEqual(evidence["pointer_increment"]["op_str"], "r14, 8")
        self.assertEqual(evidence["backedge"]["direct_branch_rvas"],
                         [evidence["loop_head_load"]["rva"]])

    def test_prefix_loop_rejects_bad_pointer_stride(self):
        with self.assertRaisesRegex(ValueError, "advance counter and pointer once"):
            _derive_verified_pointer_prefix(self._prefix_rows(stride=4), 0x9000)

    def test_prefix_loop_rejects_counter_initialization_not_dominating(self):
        rows = self._prefix_rows()
        rows[0]["mnemonic"] = "nop"
        rows[0]["op_str"] = ""
        with self.assertRaisesRegex(ValueError, "initialized to zero"):
            _derive_verified_pointer_prefix(rows, 0x9000)

    def test_prefix_loop_rejects_path_that_skips_an_increment(self):
        with self.assertRaisesRegex(ValueError, "bypasses a required increment"):
            _derive_verified_pointer_prefix(self._prefix_rows(bypass_update=True), 0x9000)

    def test_prefix_loop_rejects_path_that_skips_the_table_read(self):
        rows = self._prefix_rows()
        table_base = next(row for row in rows if row["mnemonic"] == "lea")
        table_base["next_rva"] = 0x10b
        with self.assertRaisesRegex(ValueError, "bypasses the table load"):
            _derive_verified_pointer_prefix(rows, 0x9000)

    def test_prefix_loop_rejects_wrong_backedge_target(self):
        with self.assertRaisesRegex(ValueError, "unique unsigned fixed-count backedge"):
            _derive_verified_pointer_prefix(self._prefix_rows(branch_target=0x110), 0x9000)

    def test_prefix_loop_rejects_signed_or_non_loop_branch(self):
        rows = self._prefix_rows()
        next(row for row in rows if row["mnemonic"] == "jb")["mnemonic"] = "jl"
        with self.assertRaisesRegex(ValueError, "unique unsigned fixed-count backedge"):
            _derive_verified_pointer_prefix(rows, 0x9000)

    def test_prefix_loop_rejects_nonunique_table_base(self):
        rows = self._prefix_rows()
        rows.append(ins(0x200, "lea", "r12, [rip + 0x100]",
                        [mem("rip", 0x100, size=8, target=0x9000)], rip=[0x9000],
                        next_rva=0x207))
        with self.assertRaisesRegex(ValueError, "uniquely establish"):
            _derive_verified_pointer_prefix(rows, 0x9000)

    def test_prefix_loop_rejects_multiple_counter_updates(self):
        rows = self._prefix_rows()
        inc = next(row for row in rows if row["mnemonic"] == "inc")
        inc["next_rva"] = 0x10c
        rows.append(ins(0x10c, "inc", "esi", next_rva=0x10d))
        with self.assertRaisesRegex(ValueError, "advance counter and pointer once"):
            _derive_verified_pointer_prefix(rows, 0x9000)

    def test_current_v8_build_proves_prefix_without_claiming_total_count(self):
        report_path = ROOT / "build-frontend-current-loader-trace-v8" / "build-report.json"
        if not report_path.is_file():
            self.skipTest("The exact v8 build report is not present in this checkout")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        executable = Path(report["executable"])
        if not executable.is_file():
            self.skipTest("The exact v8 executable is not present in this checkout")
        manifest = discover_bindings(executable, report_path, ROOT / "generated" / "function-catalog.json")
        layout = manifest["capture_layout"]
        proof = layout["pointer_table_proof"]
        self.assertEqual(layout["coverage"], "verified-prefix")
        self.assertEqual(layout["stream_count"], proof["verified_prefix_count"])
        self.assertIsNone(layout["allocation_count"])
        self.assertTrue(layout["full_table_count_unknown"])
        self.assertIsNone(layout["history"]["capacity"])
        first_scalar = min(field["offset"] for field in layout["scalars"].values())
        self.assertEqual(layout["history"]["max_capture_entries"],
                         first_scalar // layout["history"]["stride"])
        self.assertEqual(layout["history"]["bound_kind"], "non-overlap-read-bound")
        self.assertEqual(layout["history"]["bound_evidence"]["first_scalar_offset"], first_scalar)
        self.assertTrue(layout["history"]["bound_evidence"]["instruction_evidence"])
        self.assertEqual(set(layout["globals"]), {"postload"})
        evidence = proof["evidence"]
        self.assertEqual(evidence["loop_head_load"]["memory_operands"][0]["size"],
                         layout["pointer_stride"])
        self.assertEqual(evidence["pointer_increment"]["op_str"].split(",")[-1].strip(),
                         str(layout["pointer_stride"]))
        self.assertEqual(evidence["count_compare"]["op_str"].split(",")[-1].strip(),
                         str(layout["stream_count"]))
        self.assertEqual(evidence["backedge"]["direct_branch_rvas"],
                         [evidence["loop_head_load"]["rva"]])

    def test_current_v9_build_binds_relative_helper_by_profile_identity_and_reachable_call(self):
        report_path = ROOT / "build-frontend-current-loader-trace-v9" / "build-report.json"
        if not report_path.is_file():
            self.skipTest("The exact v9 build report is not present in this checkout")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        executable = Path(report["executable"])
        if not executable.is_file():
            self.skipTest("The exact v9 executable is not present in this checkout")
        manifest = discover_bindings(executable, report_path, ROOT / "generated" / "function-catalog.json")
        helper = manifest["relative_start_helper"]
        binding = manifest["functions"]["DB_OffsetAliasStreamDelta"]
        self.assertEqual(helper["compiled_rva"], binding["compiled_rva"])
        self.assertEqual(helper["profile_binding"]["symbol_id"], binding["symbol_id"])
        self.assertEqual(len(helper["call_edge_evidence"]), 1)
        call = helper["call_edge_evidence"][0]
        self.assertIn(helper["compiled_rva"], call["direct_call_rvas"])
        self.assertEqual(helper["call_argument_dataflow"]["value"], "(token >> 32) & 0xf")
        self.assertEqual(helper["stream_table_access"]["stride"], 4)
        self.assertEqual(helper["stream_table_access"]["read_size"], 4)


if __name__ == "__main__":
    unittest.main()
