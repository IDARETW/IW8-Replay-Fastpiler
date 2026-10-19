import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_seh import (ScopeRecord, compile_and_verify, render_cpp_funcinfo_handler,
                             render_rva_fields, render_scope_handler)


class WorkstationSehTests(unittest.TestCase):
    def test_scope_table_emits_compiler_handlerdata_and_addr32nb_relocations(self):
        labels = ["L_begin", "L_filter", "L_continue", "L_end"]
        scope = ScopeRecord("L_begin", "L_end", "fn_0123456789abcdef", "L_continue")
        handler = render_scope_handler("fn_0011223344556677", [scope], label_order=labels, flags=3)
        source = f""".intel_syntax noprefix
.text
.def fn_89abcdef01234567; .scl 2; .type 32; .endef
.globl fn_89abcdef01234567
.p2align 4
fn_89abcdef01234567:
.seh_proc fn_89abcdef01234567
push rbp
.seh_pushreg rbp
mov rbp, rsp
.seh_setframe rbp, 0
.seh_endprologue
L_begin:
nop
L_filter:
nop
L_continue:
nop
L_end:
{handler}
.seh_endproc
.def fn_0011223344556677; .scl 2; .type 32; .endef
fn_0011223344556677:
ret
.def fn_0123456789abcdef; .scl 2; .type 32; .endef
fn_0123456789abcdef:
ret
"""
        result = compile_and_verify(source)
        self.assertTrue(result["passed"])
        self.assertEqual(result["scope_count"], 1)
        self.assertEqual(result["handler_flags"], 3)
        self.assertGreaterEqual(result["addr32nb_relocations"], 5)

    def test_scope_labels_must_exist_and_be_ordered(self):
        record = ScopeRecord("L_after", "L_before", "fn_0123456789abcdef", None)
        with self.assertRaisesRegex(ValueError, "end label must follow"):
            render_scope_handler("fn_0011223344556677", [record],
                                 label_order=["L_before", "L_after"])
        with self.assertRaisesRegex(ValueError, "resolve to an emitted label"):
            render_scope_handler("fn_0011223344556677",
                                 [ScopeRecord("L_missing", "L_after", "fn_0123456789abcdef", None)],
                                 label_order=["L_after"])

    def test_raw_rva_is_not_accepted_as_handler_metadata(self):
        with self.assertRaisesRegex(ValueError, "stable function ID or emitted label"):
            render_scope_handler("0x1234", [], label_order=[])
        with self.assertRaisesRegex(ValueError, "outside uint32"):
            render_rva_fields([0x1_0000_0000])

    def test_cpp_funcinfo_pointer_uses_stable_data_id_and_both_handler_flags(self):
        handler_data = render_cpp_funcinfo_handler(
            "fn_0011223344556677", "sym_0123456789abcdef", flags=3)
        source = f""".intel_syntax noprefix
.text
.globl fn_89abcdef01234567
fn_89abcdef01234567:
.seh_proc fn_89abcdef01234567
push rbp
.seh_pushreg rbp
mov rbp, rsp
.seh_setframe rbp, 0
.seh_endprologue
{handler_data}
.seh_endproc
"""
        result = compile_and_verify(source)
        self.assertTrue(result["passed"])
        self.assertEqual(result["language_data"], "cpp-funcinfo")
        self.assertEqual(result["funcinfo_symbol"], "sym_0123456789abcdef")
        self.assertEqual(result["addr32nb_relocations"], 2)

    def test_funcinfo_renderer_rejects_rva_shaped_or_wrong_identity(self):
        with self.assertRaisesRegex(ValueError, "stable function ID or emitted label"):
            render_cpp_funcinfo_handler("fn_0011223344556677", "0x1234", flags=3)


if __name__ == "__main__":
    unittest.main()
