from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
TOOLS = os.environ.get("REPLAY_COMPILER_TOOLS")
if TOOLS:
    sys.path.append(str(Path(TOOLS).resolve()))

import workstation_gsc_fields as policy


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rewrite_operand(payload: bytes, new_opcode: int | None = None,
                     new_token: int | None = None) -> bytes:
    from workstation_asset_codecs import _script_instructions, inspect_gscbin
    info = inspect_gscbin(payload)
    code = bytearray(info.bytecode)
    match = next((start for start, opcode, _end in _script_instructions(code)
                 if opcode == 0x18), None)
    if match is None:
        raise AssertionError("probe payload lacks its opcode-0x18 field reference")
    if new_opcode is not None:
        code[match] = new_opcode
    if new_token is not None:
        struct.pack_into("<I", code, match + 1, new_token)
    return struct.pack("<4I", 0x435347, len(info.compressed_source), info.source_size, len(code)) + \
        info.compressed_source + bytes(code)


class Class0ScriptFilePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.replay = os.environ.get("REPLAY_SCRIPTFILE_TEST_REPLAY_EXE")
        cls.compiler = os.environ.get("REPLAY_SCRIPTFILE_TEST_GSC_TOOL")
        cls.contract, cls.contract_sha, cls.rows = policy._load_contract()

    def _payload(self, row):
        path = ROOT / "tests" / "fixtures" / "scriptfile-class0" / f"class0_probe_{row['descriptor_row_index'] + 1}.gscbin"
        payload = path.read_bytes()
        self.assertEqual(_sha(payload), row["compiled_payload_sha256"])
        return payload

    @unittest.skipUnless(os.environ.get("REPLAY_COMPILER_TOOLS") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_REPLAY_EXE") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_GSC_TOOL"),
                         "set configured Replay, GSC Tool and tools paths for real payload verification")
    def test_all_sixteen_real_compiler_payloads_pass_strict_trace_and_field_contract(self):
        for row in self.contract["verified_fields"]:
            with self.subTest(name=row["name"]):
                receipt = policy.validate_scriptfile_payload(
                    self._payload(row), replay_executable=self.replay,
                    compiler_executable=self.compiler)
                self.assertEqual(receipt["policy"], policy.FIELD_POLICY)
                self.assertEqual(receipt["accepted_opcode_0x18_field_token_count"], 1)
                self.assertEqual(receipt["accepted_field_events"][0]["token"],
                                 hex(row["compiled_bytecode_token"]))
                self.assertEqual(receipt["accepted_field_events"][0]["field_name"], row["name"])

    @unittest.skipUnless(os.environ.get("REPLAY_COMPILER_TOOLS") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_REPLAY_EXE") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_GSC_TOOL"),
                         "set configured Replay, GSC Tool and tools paths for real payload verification")
    def test_omitted_or_changed_configured_identities_fail_for_nonzero_fields(self):
        payload = self._payload(self.contract["verified_fields"][0])
        with self.assertRaisesRegex(ValueError, "explicit configured Replay and GSC Tool"):
            policy.validate_scriptfile_payload(payload)
        with self.assertRaisesRegex(ValueError, "Replay executable differs"):
            policy.validate_scriptfile_payload(payload, replay_executable=self.compiler,
                                               compiler_executable=self.compiler)
        with self.assertRaisesRegex(ValueError, "GSC Tool executable differs"):
            policy.validate_scriptfile_payload(payload, replay_executable=self.replay,
                                               compiler_executable=self.replay)
        with tempfile.TemporaryDirectory() as temp:
            changed_tool = Path(temp) / "changed-gsc-tool.exe"
            shutil.copyfile(self.compiler, changed_tool)
            with changed_tool.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                last = stream.read(1)
                stream.seek(-1, os.SEEK_END)
                stream.write(bytes([last[0] ^ 1]))
            with self.assertRaisesRegex(ValueError, "GSC Tool executable differs"):
                policy.validate_scriptfile_payload(payload, replay_executable=self.replay,
                                                   compiler_executable=changed_tool)

    def test_unknown_token_other_opcode_and_contract_tamper_are_rejected(self):
        payload = self._payload(self.contract["verified_fields"][0])
        with self.assertRaisesRegex(ValueError, "outside the verified class-0"):
            policy.validate_scriptfile_payload(_rewrite_operand(payload, new_token=0x8000))
        with self.assertRaisesRegex(ValueError, "outside verified opcode 0x18"):
            policy.validate_scriptfile_payload(_rewrite_operand(payload, new_opcode=0x07))
        changed = json.loads(policy.CONTRACT_PATH.read_text(encoding="utf-8"))
        changed["verified_fields"][0]["name"] = "forged_field"
        with tempfile.TemporaryDirectory() as temp:
            changed_path = Path(temp) / "contract.json"
            changed_path.write_text(json.dumps(changed), encoding="utf-8")
            with patch.object(policy, "CONTRACT_PATH", changed_path):
                with self.assertRaisesRegex(ValueError, "contract bytes differ"):
                    policy.validate_scriptfile_payload(payload)

    def test_inline_only_payload_keeps_legacy_receipt_shape(self):
        payload = self._payload(self.contract["verified_fields"][0])
        info, events = policy._strict_trace(_rewrite_operand(payload, new_token=0))
        expected = {"policy": "typed-inline-only-v1", "cursor_event_count": len(events),
                    "bytecode_bytes": len(info.bytecode), "nonzero_script_string_ids": 0,
                    "complete_cursor": True}
        inline = policy.validate_scriptfile_payload(_rewrite_operand(payload, new_token=0))
        self.assertEqual(inline, expected)

    @unittest.skipUnless(os.environ.get("REPLAY_COMPILER_TOOLS") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_REPLAY_EXE") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_GSC_TOOL"),
                         "set configured Replay, GSC Tool and tools paths for receipt revalidation")
    def test_receipt_revalidation_recomputes_exact_policy(self):
        payload = self._payload(self.contract["verified_fields"][0])
        kwargs = dict(replay_executable=self.replay, compiler_executable=self.compiler)
        receipt = policy.validate_scriptfile_payload(payload, **kwargs)
        self.assertEqual(policy.validate_ownership_receipt(receipt, payload, **kwargs), receipt)
        stale = dict(receipt, compiler_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "receipt is stale"):
            policy.validate_ownership_receipt(stale, payload, **kwargs)

    @unittest.skipUnless(os.environ.get("REPLAY_SCRIPTFILE_TEST_REPLAY_EXE") and
                         os.environ.get("REPLAY_SCRIPTFILE_TEST_GSC_TOOL"),
                         "set configured Replay and GSC Tool paths for writer integration")
    def test_scriptfile_writer_revalidates_field_receipt_against_configured_tools(self):
        import workstation_scriptfile_crud as writer

        row = self.contract["verified_fields"][2]
        name, source = "probe/class0_origin", "class0_probe_3() { self.origin = 1; return; }\n"
        payload = self._payload(row)
        ownership = policy.validate_scriptfile_payload(payload,
            replay_executable=self.replay, compiler_executable=self.compiler)
        receipt = {
            "schema": "replay120-gsc-compile-receipt-v1",
            "status": "gsc-tool-native-payload-pass",
            "asset_name": name,
            "source": {"sha256": _sha(source.encode("utf-8"))},
            "compiler": {"sha256": _sha(Path(self.compiler).read_bytes()),
                         "input_name": "script_" + _sha(name.encode("utf-8"))[:20]},
            "result": {"native_payload_sha256": _sha(payload),
                       "payload_contract": "Replay ScriptFile GSCBIN after Replay local-reference scaling"},
            "string_ownership": ownership,
        }
        checked = writer._validate_compiler_receipt(name, source, payload, receipt,
            replay_executable=self.replay, compiler_executable=self.compiler)
        self.assertEqual(checked["payload_sha256"], _sha(payload))


if __name__ == "__main__":
    unittest.main()
