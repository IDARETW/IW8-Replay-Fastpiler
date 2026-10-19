"""Bounded ScriptFile GSC token policy backed by a generated class-0 receipt.

The adjacent JSON is path-free evidence. Its bytes are pinned here, and runtime
validation hashes the caller's configured Replay and GSC Tool executables before
allowing the one verified opcode-0x18 field-token subset. This is not VM
getter/setter or general canonical-token proof.
"""
from __future__ import annotations

import hashlib
import json
import struct
import tempfile
from pathlib import Path


INLINE_POLICY = "typed-inline-only-v1"
FIELD_POLICY = "typed-class0-op18-field-subset-v1"
CONTRACT_PATH = Path(__file__).with_name("workstation_gsc_fields_class0.json")
CONTRACT_SHA256 = "d68b7e861a6baa3882d24b5b53b71980ea9aebf7d92ba88f1bc580ab3d125286"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_contract() -> tuple[dict, str, dict[int, dict]]:
    raw = CONTRACT_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CONTRACT_SHA256:
        raise ValueError("class-0 field contract bytes differ from the pinned proof")
    contract = json.loads(raw.decode("utf-8"))
    if (contract.get("schema") != "replay-scriptfile-class0-op18-field-contract-v1" or
            contract.get("status") != "verified-captured-class0-subset" or
            contract.get("class_id") != 0 or
            contract.get("descriptor_table_complete") is not True or
            contract.get("captured_descriptor_count") != 16 or
            contract.get("native_getter_setter_semantics_proven") is not False):
        raise ValueError("class-0 field contract has an unsupported or incomplete scope")
    inputs = contract.get("inputs")
    required_inputs = {
        "original_replay_sha256", "compiler_sha256", "capture_sha256",
        "fixed_token_proof_sha256", "dictionary_comparison_sha256",
        "compiler_probe_receipt_sha256", "compiled_operand_audit_sha256",
        "token_source_sha256", "cursor_proof_sha256", "candidate_executable_sha256",
    }
    if not isinstance(inputs, dict) or any(not isinstance(inputs.get(key), str) or
                                           len(inputs[key]) != 64 for key in required_inputs):
        raise ValueError("class-0 field contract provenance is incomplete")
    rows = contract.get("verified_fields")
    if not isinstance(rows, list) or len(rows) != 16:
        raise ValueError("class-0 field contract does not contain all 16 captured rows")
    by_token: dict[int, dict] = {}
    seen_names, seen_indexes = set(), set()
    for row in rows:
        if not isinstance(row, dict) or row.get("class_id") != 0:
            raise ValueError("class-0 field row has an invalid class")
        token = row.get("compiler_dictionary_token")
        if (type(token) is not int or not 0 <= token <= 0xFFFFFFFF or
                row.get("raw_registration_key_r9d") != token or
                row.get("compiled_bytecode_token") != token or
                not isinstance(row.get("name"), str) or not row["name"] or
                type(row.get("descriptor_row_index")) is not int or
                not isinstance(row.get("compiled_payload_sha256"), str) or
                len(row["compiled_payload_sha256"]) != 64 or
                row.get("exact_registration_pair") is not True or
                row.get("exact_dictionary_name_key_match") is not True or
                row.get("exact_compiled_operand_match") is not True):
            raise ValueError("class-0 row lacks exact native/dictionary/compiler identity")
        name, index = row["name"], row["descriptor_row_index"]
        if token in by_token or name in seen_names or index in seen_indexes:
            raise ValueError("class-0 field contract contains duplicate token, name, or row index")
        by_token[token] = row
        seen_names.add(name)
        seen_indexes.add(index)
    if seen_indexes != set(range(16)):
        raise ValueError("class-0 field contract row indices are not complete and contiguous")
    return contract, digest, by_token


def _parse_hex(value, label: str, *, maximum: int) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} is malformed")
    try:
        parsed = int(value, 16)
    except ValueError as error:
        raise ValueError(f"{label} is malformed") from error
    if not 0 <= parsed <= maximum:
        raise ValueError(f"{label} is outside its supported bounds")
    return parsed


def _strict_trace(payload: bytes):
    # These are the production GSCBIN parser and Replay cursor tracer. Strict
    # mode validates source consumption, instruction boundaries, and exact EOF.
    from workstation_asset_codecs import _script_instructions, inspect_gscbin
    from trace_gscbin_source_cursor import trace

    info = inspect_gscbin(payload)
    with tempfile.TemporaryDirectory(prefix="replay-class0-cursor-") as temp:
        path = Path(temp) / "payload.gscbin"
        path.write_bytes(payload)
        events = trace(path, limit=len(info.bytecode), strict=True)
    if not events or events[-1].get("next_pc") != hex(len(info.bytecode)):
        raise ValueError("strict GSC source cursor did not reach exact bytecode EOF")
    instructions = list(_script_instructions(info.bytecode))
    opcode_events = [event for event in events if "opcode" in event]
    if len(opcode_events) != len(instructions):
        raise ValueError("strict cursor opcode records do not cover every bytecode instruction")
    for event, (start, opcode, end) in zip(opcode_events, instructions, strict=True):
        if (event.get("pc") != hex(start) or event.get("opcode") != hex(opcode) or
                event.get("next_pc") != hex(end) or info.bytecode[start] != opcode):
            raise ValueError("strict cursor event does not match the payload instruction boundaries")
    return info, events


def validate_scriptfile_payload(payload: bytes, *, replay_executable: str | Path | None = None,
                                 compiler_executable: str | Path | None = None) -> dict:
    """Return the unchanged inline receipt, or a proof-bound opcode-0x18 receipt.

    Paths are mandatory whenever the payload has a nonzero canonical token.
    Missing path arguments never inherit a default target/compiler identity.
    """
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("ScriptFile GSCBIN payload must be nonempty bytes")
    info, events = _strict_trace(payload)
    token_rows = []
    nonzero_source = []
    for event in events:
        for key in ("name", "first", "second", "token"):
            value = event.get(key)
            if isinstance(value, dict) and "id" in value:
                source_id = _parse_hex(value["id"], f"source {key} ID", maximum=0xFFFFFFFF)
                if source_id:
                    nonzero_source.append({"pc": event.get("pc", event.get("function_at")),
                                           "field": key, "id": value["id"]})
        canonical = event.get("canonical_token")
        if canonical is None:
            continue
        if not isinstance(canonical, dict) or "id" not in canonical:
            raise ValueError("strict cursor returned a malformed canonical operand")
        token = _parse_hex(canonical["id"], "canonical token", maximum=0xFFFFFFFF)
        if not token:
            continue
        if event.get("opcode") != "0x18":
            raise ValueError("nonzero canonical token outside verified opcode 0x18 field-reference form")
        pc = _parse_hex(event.get("pc"), "canonical instruction offset", maximum=len(info.bytecode) - 1)
        operand_at = _parse_hex(canonical.get("bytecode_offset"), "canonical operand offset",
                                maximum=len(info.bytecode) - 4)
        if (info.bytecode[pc] != 0x18 or operand_at != pc + 1 or
                struct.unpack_from("<I", info.bytecode, operand_at)[0] != token):
            raise ValueError("canonical cursor event does not match its bounded opcode-0x18 operand bytes")
        token_rows.append((token, pc, operand_at))
    if nonzero_source:
        raise ValueError("GSC payload contains nonzero source/function/import tokens outside the field contract")
    if not token_rows:
        # Preserve exact legacy receipt shape for inline-only payloads.
        return dict(policy=INLINE_POLICY, cursor_event_count=len(events),
                    bytecode_bytes=len(info.bytecode), nonzero_script_string_ids=0,
                    complete_cursor=True)
    contract, contract_sha, by_token = _load_contract()
    accepted = []
    for token, pc, operand_at in token_rows:
        row = by_token.get(token)
        if row is None:
            raise ValueError(f"opcode 0x18 token {token:#x} is outside the verified class-0 field subset")
        accepted.append((token, pc, operand_at, row))
    if replay_executable is None or compiler_executable is None:
        raise ValueError("nonzero field tokens require explicit configured Replay and GSC Tool executables")
    replay_path = Path(replay_executable).resolve(strict=True)
    compiler_path = Path(compiler_executable).resolve(strict=True)
    replay_sha = _sha256_path(replay_path)
    compiler_sha = _sha256_path(compiler_path)
    if replay_sha != contract["inputs"]["original_replay_sha256"]:
        raise ValueError("configured Replay executable differs from the field contract target")
    if compiler_sha != contract["inputs"]["compiler_sha256"]:
        raise ValueError("configured GSC Tool executable differs from the compiled field probes")
    accepted_events = []
    for token, pc, operand_at, row in accepted:
        accepted_events.append({"pc": hex(pc), "opcode": "0x18", "bytecode_offset": hex(operand_at),
                                "token": hex(token), "field_name": row["name"],
                                "descriptor_row_index": row["descriptor_row_index"]})
    return {
        "policy": FIELD_POLICY,
        "cursor_event_count": len(events),
        "bytecode_bytes": len(info.bytecode),
        "nonzero_script_string_ids": 0,
        "complete_cursor": True,
        "field_contract_sha256": contract_sha,
        "original_replay_sha256": replay_sha,
        "compiler_sha256": compiler_sha,
        "accepted_opcode_0x18_field_token_count": len(accepted_events),
        "accepted_field_events": accepted_events,
        "scope_note": contract["scope"],
    }


def validate_ownership_receipt(receipt: dict, payload: bytes, *,
                               replay_executable: str | Path | None = None,
                               compiler_executable: str | Path | None = None) -> dict:
    """Recompute payload ownership and require exact receipt equality."""
    expected = validate_scriptfile_payload(payload, replay_executable=replay_executable,
                                           compiler_executable=compiler_executable)
    if receipt != expected:
        raise ValueError("ScriptFile ownership receipt is stale or bound to different configured tools")
    return expected
