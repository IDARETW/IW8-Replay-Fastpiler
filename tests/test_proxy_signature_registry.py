import hashlib
import struct
import unittest
from types import SimpleNamespace

from tools.proxy_signature_registry import (HEADER_SIZE, MAGIC, RECORD_SIZE, SECTION_CHARACTERISTICS,
                                            decode, encode, verify_pe)


def entry(name="Target", rva=0x1000):
    return {"name": name, "rva": rva,
            "native": {"bytes": "4883ec28", "mask": "ffffffff"},
            "compiled": {"bytes": "4883ec30", "mask": "ffffffff"}}


class ProxySignatureRegistryTests(unittest.TestCase):
    def test_round_trip_contract_and_body_hash(self):
        encoded = encode([entry("Second", 0x2000), entry("First", 0x1000)])
        self.assertEqual(len(encoded[:HEADER_SIZE]), HEADER_SIZE)
        header = struct.unpack_from("<8s7I32sI", encoded)
        self.assertEqual(header[0:2], (MAGIC, 1))
        self.assertEqual(header[2:8], (2, HEADER_SIZE, HEADER_SIZE + 2 * RECORD_SIZE,
                                       len(b"FirstSecond"), HEADER_SIZE + 2 * RECORD_SIZE + len(b"FirstSecond"),
                                       len(encoded) - (HEADER_SIZE + 2 * RECORD_SIZE + len(b"FirstSecond"))))
        self.assertEqual(header[8], hashlib.sha256(encoded[HEADER_SIZE:]).digest())
        decoded = decode(encoded)
        self.assertEqual([row["rva"] for row in decoded["entries"]], [0x1000, 0x2000])
        self.assertEqual(decoded["entries"][0]["name"], "First")
        self.assertEqual(decoded["identity"], header[8].hex())
        self.assertEqual(SECTION_CHARACTERISTICS, 0x40000040)

    def test_rejects_duplicate_and_unsorted_rvas(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            encode([entry("A", 1), entry("B", 1)])

    def test_rejects_invalid_masks_and_non_ascii_names(self):
        broken = entry()
        broken["compiled"]["mask"] = "00000000"
        with self.assertRaisesRegex(ValueError, "fixed byte"):
            encode([broken])
        with self.assertRaisesRegex(ValueError, "ASCII"):
            encode([entry("λ")])

    def test_detects_body_tampering(self):
        encoded = bytearray(encode([entry()]))
        encoded[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            decode(encoded)

    def test_rejects_bad_offsets_and_delimited_name(self):
        encoded = bytearray(encode([entry("Target")]))
        struct.pack_into("<I", encoded, 20, 0xFFFFFFFF)
        struct.pack_into("<I", encoded, 36, 0)
        encoded[36:68] = hashlib.sha256(encoded[HEADER_SIZE:]).digest()
        with self.assertRaisesRegex(ValueError, "string table offset"):
            decode(encoded)

    def test_verifies_native_identity_and_linked_bytes(self):
        native = entry()
        registry = decode(encode([native]))
        section_data = encode([native])
        section = SimpleNamespace(Name=b".rplsig\0", Characteristics=SECTION_CHARACTERISTICS,
                                  Misc_VirtualSize=len(section_data), VirtualAddress=0x9000,
                                  get_data=lambda: section_data)
        linked = bytes.fromhex(native["compiled"]["bytes"])
        class FakePe:
            sections = [section]
            def get_data(self, rva, size):
                return linked if rva == 0x2000 and size == len(linked) else b""
        expected = {"name": "Target", "rva": 0x1000, "native": native["native"]}
        result = verify_pe(FakePe(), {}, [expected], lambda rva, _report: 0x2000)
        self.assertEqual(result["identity"], registry["identity"])
        self.assertEqual(result["count"], 1)


if __name__ == "__main__":
    unittest.main()
