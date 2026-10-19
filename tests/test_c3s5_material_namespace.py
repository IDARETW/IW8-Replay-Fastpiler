from __future__ import annotations

import hashlib
import unittest

from tools.c3s5_material_namespace import (
    NamespaceRewriteError,
    RenameRequest,
    deterministic_name,
    rewrite_material_names,
)


TRACE_SHA = "a" * 64


def fixture(name: bytes = b"mo/very_long_replay_material_name"):
    body = bytearray(8 + len(name) + 1 + 5)
    token = 0x5000000000000123
    body[:8] = token.to_bytes(8, "little")
    body[8:8 + len(name)] = name
    body[8 + len(name)] = 0
    return bytes(body), token, 8


def event(token: int, offset: int, *, role: str = "MaterialHandle", field: int = 0):
    return {
        "owner_type": role,
        "owner_name": "model/test",
        "owner_asset_index": 42,
        "owner_field_offset": field,
        "token": hex(token),
        "resolved_target_body_offset": offset,
    }


class MaterialNamespaceTests(unittest.TestCase):
    def test_exact_length_namespace_and_string_terminator_preserved(self):
        body, token, offset = fixture()
        result, receipt = rewrite_material_names(
            body,
            expected_body_sha256=hashlib.sha256(body).hexdigest(),
            rename_requests=[RenameRequest("mo/very_long_replay_material_name", offset)],
            typed_pointer_events=[event(token, offset)],
            expected_pointer_event_count=1,
            occupied_names=["mo/very_long_replay_material_name"],
            expected_trace_sha256=TRACE_SHA,
            supplied_trace_sha256=TRACE_SHA,
        )
        new_name = result[offset:result.index(b"\0", offset)].decode("ascii")
        self.assertEqual(len(new_name.encode()), len("mo/very_long_replay_material_name"))
        self.assertTrue(new_name.startswith("c3s5n/"))
        self.assertEqual(result[:8], body[:8])
        self.assertEqual(result[offset + len(new_name)], 0)
        self.assertEqual(len(result), len(body))
        self.assertTrue(receipt["body_length_preserved"])
        self.assertEqual(receipt["rewrites"][0]["owner_count"], 1)

    def test_leading_comma_is_preserved(self):
        original = ",mo/a_very_long_material_name"
        name = original.encode()
        body, token, offset = fixture(name)
        result, _ = rewrite_material_names(
            body,
            expected_body_sha256=hashlib.sha256(body).hexdigest(),
            rename_requests=[RenameRequest(original, offset)],
            typed_pointer_events=[event(token, offset)],
            expected_pointer_event_count=1,
            occupied_names=[original],
            expected_trace_sha256=TRACE_SHA,
            supplied_trace_sha256=TRACE_SHA,
        )
        actual = result[offset:result.index(b"\0", offset)].decode()
        self.assertTrue(actual.startswith(",c3s5n/"))
        self.assertEqual(len(actual.encode()), len(name))

    def test_rejects_pointer_into_string_interior(self):
        body, token, offset = fixture()
        with self.assertRaisesRegex(NamespaceRewriteError, "interior"):
            rewrite_material_names(
                body,
                expected_body_sha256=hashlib.sha256(body).hexdigest(),
                rename_requests=[RenameRequest("mo/very_long_replay_material_name", offset)],
                typed_pointer_events=[event(token, offset + 3)],
                expected_pointer_event_count=1,
                occupied_names=[],
                expected_trace_sha256=TRACE_SHA,
                supplied_trace_sha256=TRACE_SHA,
            )

    def test_rejects_unrelated_pointer_alias(self):
        body, token, offset = fixture()
        with self.assertRaisesRegex(NamespaceRewriteError, "unrelated"):
            rewrite_material_names(
                body,
                expected_body_sha256=hashlib.sha256(body).hexdigest(),
                rename_requests=[RenameRequest("mo/very_long_replay_material_name", offset)],
                typed_pointer_events=[event(token, offset, role="XString")],
                expected_pointer_event_count=1,
                occupied_names=[],
                expected_trace_sha256=TRACE_SHA,
                supplied_trace_sha256=TRACE_SHA,
            )

    def test_rejects_unproved_or_stale_token_and_trace(self):
        body, token, offset = fixture()
        base = dict(
            expected_body_sha256=hashlib.sha256(body).hexdigest(),
            rename_requests=[RenameRequest("mo/very_long_replay_material_name", offset)],
            occupied_names=[],
            expected_trace_sha256=TRACE_SHA,
            supplied_trace_sha256=TRACE_SHA,
            expected_pointer_event_count=1,
        )
        with self.assertRaisesRegex(NamespaceRewriteError, "token differs"):
            rewrite_material_names(body, typed_pointer_events=[event(token + 1, offset)], **base)
        with self.assertRaisesRegex(NamespaceRewriteError, "trace SHA"):
            rewrite_material_names(body, typed_pointer_events=[event(token, offset)],
                                   **{**base, "supplied_trace_sha256": "b" * 64})
        with self.assertRaisesRegex(NamespaceRewriteError, "source body SHA"):
            rewrite_material_names(body, typed_pointer_events=[event(token, offset)],
                                   **{**base, "expected_body_sha256": "b" * 64})

    def test_rejects_too_short_name_and_missing_owner(self):
        with self.assertRaises(NamespaceRewriteError):
            deterministic_name("abc", [])
        body, _, offset = fixture()
        with self.assertRaisesRegex(NamespaceRewriteError, "no typed incoming owner"):
            rewrite_material_names(
                body,
                expected_body_sha256=hashlib.sha256(body).hexdigest(),
                rename_requests=[RenameRequest("mo/very_long_replay_material_name", offset)],
                typed_pointer_events=[],
                expected_pointer_event_count=0,
                occupied_names=[],
                expected_trace_sha256=TRACE_SHA,
                supplied_trace_sha256=TRACE_SHA,
            )

    def test_reference_comma_and_definition_share_namespace_identity(self):
        plain = "mo/very_long_replay_material_name"
        ref = "," + plain
        plain_bytes = plain.encode()
        ref_bytes = ref.encode()
        body = bytearray(16 + len(plain_bytes) + 1 + len(ref_bytes) + 1)
        token_a, token_b = 0x5000000000000101, 0x5000000000000102
        body[0:8] = token_a.to_bytes(8, "little")
        body[8:16] = token_b.to_bytes(8, "little")
        plain_offset = 16
        ref_offset = plain_offset + len(plain_bytes) + 1
        body[plain_offset:plain_offset + len(plain_bytes)] = plain_bytes
        body[plain_offset + len(plain_bytes)] = 0
        body[ref_offset:ref_offset + len(ref_bytes)] = ref_bytes
        body[ref_offset + len(ref_bytes)] = 0
        events = [event(token_a, plain_offset, role="MaterialAssetName", field=0),
                  event(token_b, ref_offset, role="MaterialHandle", field=8)]
        result, receipt = rewrite_material_names(
            bytes(body),
            expected_body_sha256=hashlib.sha256(body).hexdigest(),
            rename_requests=[RenameRequest(plain, plain_offset), RenameRequest(ref, ref_offset)],
            typed_pointer_events=events,
            expected_pointer_event_count=2,
            occupied_names=[plain],
            expected_trace_sha256=TRACE_SHA,
            supplied_trace_sha256=TRACE_SHA,
        )
        new_plain = result[plain_offset:result.index(b"\0", plain_offset)].decode()
        new_ref = result[ref_offset:result.index(b"\0", ref_offset)].decode()
        self.assertEqual(new_ref, "," + new_plain)
        self.assertEqual(len(new_plain.encode()), len(plain_bytes))
        self.assertEqual(len(new_ref.encode()), len(ref_bytes))
        self.assertEqual(len(receipt["rewrites"]), 2)

    def test_rejects_overlapping_requested_strings(self):
        name = "mo/very_long_replay_material_name"
        body = (name + "\0x\0").encode()
        first = 0
        second = 3
        token_a, token_b = 0x5000000000000101, 0x5000000000000102
        tokens = token_a.to_bytes(8, "little") + token_b.to_bytes(8, "little")
        body = tokens + body
        first += 16
        second += 16
        suffix = body[second:body.index(0, second)].decode()
        with self.assertRaisesRegex(NamespaceRewriteError, "overlap"):
            rewrite_material_names(
                body,
                expected_body_sha256=hashlib.sha256(body).hexdigest(),
                rename_requests=[RenameRequest(name, first), RenameRequest(suffix, second)],
                typed_pointer_events=[event(token_a, first, field=0), event(token_b, second, field=8)],
                expected_pointer_event_count=2,
                occupied_names=[],
                expected_trace_sha256=TRACE_SHA,
                supplied_trace_sha256=TRACE_SHA,
            )


if __name__ == "__main__":
    unittest.main()
