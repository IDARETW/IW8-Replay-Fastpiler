import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_asset_transaction import execute_transaction


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


class MixedAssetTransactionTests(unittest.TestCase):
    def test_rawfile_content_edit_resolves_original_identity_and_checks_bytes(self):
        rows = [dict(type_id=51, name="config/test.cfg", payload_sha256=sha("original")),
                dict(type_id=19, name="$black", payload_sha256=sha("image"))]
        resolved = []
        def rawfile(mutation, index, _snapshot):
            resolved.append((mutation["identity"], index))
            self.assertEqual(index, 0)
            rows[index]["payload_sha256"] = mutation["output_payload_sha256"]
            return {"rawfile_replaced": True}
        mutation = dict(kind="rawfile_replace",
            identity=dict(type_id=51, name="config/test.cfg", occurrence=0),
            output_payload_sha256=sha("edited"))
        receipt = execute_transaction([mutation], lambda: [dict(row) for row in rows],
                                      {"rawfile_replace": rawfile})
        self.assertEqual(resolved, [(mutation["identity"], 0)])
        self.assertEqual(receipt["steps"][0]["kind"], "rawfile_replace")
        self.assertTrue(receipt["full_native_reread_after_each_mutation"])

    def test_mixed_route_remaps_current_rows_and_checks_every_payload(self):
        rows = [dict(type_id=62, name="ui/existing.lua", payload_sha256=sha("lua")),
                dict(type_id=19, name="$black", payload_sha256=sha("old-image"))]
        rereads = 0
        resolved = []
        def reread():
            nonlocal rereads
            rereads += 1
            return [dict(row) for row in rows]
        def update(mutation, index, _snapshot):
            resolved.append((mutation["kind"], index))
            rows[index]["payload_sha256"] = mutation["output_payload_sha256"]
            return {"native": True}
        def append(mutation, index, _snapshot):
            self.assertIsNone(index)
            rows.append(dict(type_id=mutation["type_id"], name=mutation["name"],
                             payload_sha256=mutation["output_payload_sha256"]))
            return {"native": True}
        mutations = [
            dict(kind="luafile_append", type_id=62, name="ui/new.lua", output_payload_sha256=sha("new-lua")),
            dict(kind="resident_image", identity=dict(type_id=19, name="$black"), output_payload_sha256=sha("new-image")),
            dict(kind="localize_append", type_id=41, name="CODEX_MIXED_PROOF", output_payload_sha256=sha("new-localize")),
        ]
        receipt = execute_transaction(mutations, reread,
            {"localize_append": append, "resident_image": update, "luafile_append": append})
        self.assertEqual([step["kind"] for step in receipt["steps"]],
                         ["resident_image", "localize_append", "luafile_append"])
        self.assertEqual(resolved, [("resident_image", 1)])
        self.assertEqual(rereads, 1 + 2 * len(mutations))
        self.assertTrue(receipt["full_native_reread_after_each_mutation"])
        self.assertEqual([step["resolved_current_index"] for step in receipt["steps"]], [1, None, None])

    def test_rejects_unexpected_payload_change_and_unsupported_mutation(self):
        rows = [dict(type_id=41, name="A", payload_sha256=sha("a")),
                dict(type_id=19, name="B", payload_sha256=sha("b"))]
        def corrupt(mutation, index, snapshot):
            rows[index]["payload_sha256"] = mutation["output_payload_sha256"]
            rows[1]["payload_sha256"] = sha("silent corruption")
            return {}
        mutation = dict(kind="resident_image", identity=dict(type_id=19, name="B"),
                        output_payload_sha256=sha("new-a"))
        with self.assertRaisesRegex(ValueError, "payload digests differ"):
            execute_transaction([mutation], lambda: rows, {"resident_image": corrupt})
        with self.assertRaisesRegex(ValueError, "unsupported mutations"):
            execute_transaction([dict(kind="delete")], lambda: rows, {})
        wrong = dict(kind="resident_image", identity=dict(type_id=41, name="A"),
                     output_payload_sha256=sha("x"))
        with self.assertRaisesRegex(ValueError, "wrong native asset type"):
            execute_transaction([wrong], lambda: rows, {"resident_image": corrupt})
        with self.assertRaisesRegex(ValueError, "malformed payload digest"):
            execute_transaction([mutation], lambda: [dict(type_id=41, name="A", payload_sha256="z" * 64)],
                                {"resident_image": corrupt})
        with self.assertRaisesRegex(ValueError, "invalid asset identity"):
            execute_transaction([mutation], lambda: [dict(type_id=True, name="A", payload_sha256=sha("a"))],
                                {"resident_image": corrupt})

    def test_rejects_missing_retained_asset_with_inbound_reference(self):
        rows = [dict(type_id=41, name="A", payload_sha256=sha("a")),
                dict(type_id=19, name="B", payload_sha256=sha("b"),
                     inbound=[dict(type_id=41, name="A")])]
        def delete_target(mutation, index, snapshot):
            rows.pop(index)
            return {}
        mutation = dict(kind="resident_image", identity=dict(type_id=19, name="B"),
                        output_payload_sha256=sha("new-a"))
        with self.assertRaisesRegex(ValueError, "deleted retained assets"):
            execute_transaction([mutation], lambda: rows, {"resident_image": delete_target})

    def test_invalid_mutation_is_rejected_before_reread_or_writer(self):
        calls = []
        def reread():
            calls.append("reread")
            return []
        def writer(*_args):
            calls.append("writer")
            return {}
        invalid = [
            (dict(kind="resident_image", identity=dict(type_id=19, name="$black"),
                  output_payload_sha256="z" * 64), "output payload digest"),
            (dict(kind="resident_image", identity=dict(type_id=True, name="$black"),
                  output_payload_sha256=sha("x")), "invalid immutable"),
            (dict(kind="resident_image", identity=dict(type_id=19, name="$black", occurrence=-1),
                  output_payload_sha256=sha("x")), "invalid immutable"),
            (dict(kind="resident_image", identity=dict(type_id=19, name="$black", occurrence=True),
                  output_payload_sha256=sha("x")), "invalid immutable"),
            (dict(kind="resident_image", identity=dict(type_id=19, name="$black", occurrence="0"),
                  output_payload_sha256=sha("x")), "invalid immutable"),
            (dict(kind="localize_append", type_id=41, name="bad\0name",
                  output_payload_sha256=sha("x")), "valid native asset name"),
            (dict(kind="luafile_append", type_id=62, name="../escape.lua",
                  output_payload_sha256=sha("x")), "valid native asset name"),
            (dict(kind="localize_append", type_id=True, name="valid_name",
                  output_payload_sha256=sha("x")), "wrong native asset type"),
            (dict(kind="localize_append", type_id=41, name="valid_name",
                  output_payload_sha256="A" * 64), "output payload digest"),
        ]
        for mutation, message in invalid:
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, message):
                    execute_transaction([mutation], reread, {mutation["kind"]: writer})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
