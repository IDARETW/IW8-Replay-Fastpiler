import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_shader_identity import allocate_identity, allocate_identity_batch, identity_digest  # noqa: E402


class ShaderIdentityTests(unittest.TestCase):
    EXE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    SYNTHETIC_DXBC = (b"DXBC" + bytes(20) + struct.pack("<I", 32) + bytes(4))

    @classmethod
    def setUpClass(cls):
        body_path = ROOT / "assets/replay120-code-shaders-decoded/code_post_gfx.ff.dec"
        cls.body = body_path.read_bytes() if body_path.is_file() else None
        if cls.body is not None and hashlib.sha256(cls.body).hexdigest() != (
                "71bce18e9c11d3bcdeb75b8e6583b0ff730e15e066a88b27c4bde6b32b9b7ac7"):
            raise RuntimeError("pinned Replay shader body changed")
        cls.exe_sha = cls.EXE_SHA

    @staticmethod
    def inventory(exe_sha, identities):
        records = [dict(program_identity=value) for value in identities]
        result = dict(schema="replay120-shader-identity-inventory-v1",
                      status="complete-trace-proven-shader-root-inventory",
                      replay_executable_sha256=exe_sha, shader_count=len(records), shaders=records)
        result["inventory_sha256"] = hashlib.sha256(json.dumps(
            result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return result

    def test_stock_identity_is_not_common_crc_of_microcode_chunk(self):
        if self.body is None:
            self.skipTest("private stock shader body is unavailable")
        samples = ((6394730, 6394815, 2148), (6845758, 6845831, 1152))
        for root_at, program_at, size in samples:
            expected = struct.unpack_from("<I", self.body, root_at + 36)[0]
            program = self.body[program_at:program_at + size]
            chunk_count = struct.unpack_from("<I", program, 28)[0]
            shader_chunks = []
            for i in range(chunk_count):
                at = struct.unpack_from("<I", program, 32 + 4 * i)[0]
                count = struct.unpack_from("<I", program, at + 4)[0]
                if program[at:at + 4] in (b"SHDR", b"SHEX"):
                    shader_chunks.append((program[at:at + 8 + count], program[at + 8:at + 8 + count],
                                          program[at + 16:at + 8 + count]))
            self.assertEqual(len(shader_chunks), 1)
            for data in shader_chunks[0]:
                candidates = (zlib.crc32(data) & 0xFFFFFFFF,
                              zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF,
                              (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF,
                              (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF)
                self.assertNotIn(expected, candidates)

    def test_allocation_retries_an_occupied_identity_across_inventories(self):
        program = self.SYNTHETIC_DXBC
        first = struct.unpack_from("<I", identity_digest(14, "edited", program, 0))[0]
        result = allocate_identity(14, "edited", program,
                                   [self.inventory(self.exe_sha, [first]),
                                    self.inventory(self.exe_sha, [0x12345678])], self.exe_sha)
        self.assertEqual(result["nonce"], 1)
        self.assertNotIn(result["identity"], (0, first, 0x12345678))

    def test_allocation_is_bound_to_the_replay_image(self):
        program = self.SYNTHETIC_DXBC
        with self.assertRaisesRegex(ValueError, "another Replay image"):
            allocate_identity(14, "edited", program,
                              [self.inventory("0" * 64, [])], self.exe_sha)

    def test_batch_allocation_is_owner_sorted_and_reserves_prior_results(self):
        program = self.SYNTHETIC_DXBC
        inventory = self.inventory(self.exe_sha, [])
        receipts = allocate_identity_batch([
            dict(owner_key="zone:9", type_id=14, name="same", program=program),
            dict(owner_key="zone:2", type_id=14, name="same", program=program),
        ], [inventory], self.exe_sha)
        self.assertEqual([r["owner_key"] for r in receipts], ["zone:2", "zone:9"])
        self.assertEqual(receipts[0]["nonce"], 0)
        self.assertEqual(receipts[1]["nonce"], 1)
        self.assertNotEqual(receipts[0]["identity"], receipts[1]["identity"])

    def test_extra_occupied_id_must_be_uint32(self):
        program = self.SYNTHETIC_DXBC
        with self.assertRaisesRegex(ValueError, "uint32"):
            allocate_identity(14, "edited", program, [self.inventory(self.exe_sha, [])],
                              self.exe_sha, occupied_extra=[True])

    def test_identical_stock_programs_can_have_distinct_authored_identities(self):
        if self.body is None:
            inventory = self.inventory(self.exe_sha, [0x4760A65F, 0x885C9E64])
            self.assertEqual([row["program_identity"] for row in inventory["shaders"]],
                             [0x4760A65F, 0x885C9E64])
            return
        root_a, program_a, root_b, program_b, size = 6586431, 6586530, 6774675, 6774732, 392
        self.assertEqual(self.body[program_a:program_a + size],
                         self.body[program_b:program_b + size])
        id_a = struct.unpack_from("<I", self.body, root_a + 36)[0]
        id_b = struct.unpack_from("<I", self.body, root_b + 36)[0]
        self.assertEqual((id_a, id_b), (0x4760A65F, 0x885C9E64))
        self.assertNotEqual(id_a, id_b)

    def test_synthetic_allocation_is_deterministic_without_private_fixtures(self):
        inventory = self.inventory(self.exe_sha, [0x12345678])
        first = allocate_identity(14, "portable", self.SYNTHETIC_DXBC,
                                  [inventory], self.exe_sha)
        second = allocate_identity(14, "portable", self.SYNTHETIC_DXBC,
                                   [inventory], self.exe_sha)
        self.assertEqual(first, second)
        self.assertNotIn(first["identity"], (0, 0x12345678))
        self.assertEqual(first["replay_executable_sha256"], self.EXE_SHA)


if __name__ == "__main__":
    unittest.main()
