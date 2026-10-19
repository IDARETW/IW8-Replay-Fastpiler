"""Regression tests for recovered image-base operands."""
import struct
import unittest

import capstone
import image_references


def references(code):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lengths = bytearray(len(code))
    for i in decoder.disasm(code, 0x1000):
        lengths[i.address-0x1000] = i.size
        lengths[i.address-0x1000+1:i.address-0x1000+i.size] = b"\xff"*(i.size-1)
    return image_references.recover(code, 0x1000, lengths, 0x1000000)[0]


class ImageReferences(unittest.TestCase):
    def test_unannotated_virtual_base_table(self):
        code = b"\x48\x8d\x1d"+struct.pack("<i",-0x1007)+bytes.fromhex("488d8360984d00c3")
        self.assertEqual(references(code)[0]["target"],0x4d9860)

    def test_call_register_preservation(self):
        for rex, preserved in ((b"\x1d",True),(b"\x05",False)):
            code = b"\x48\x8d"+rex+struct.pack("<i",-0x1007)+bytes.fromhex("e800000000")
            code += bytes.fromhex("488d")+(b"\x83" if preserved else b"\x80")+struct.pack("<I",0x4d9860)+b"\xc3"
            self.assertEqual(bool(references(code)),preserved)

    def test_register_overwrite_ends_provenance(self):
        code = b"\x48\x8d\x1d"+struct.pack("<i",-0x1007)+bytes.fromhex("31db488d8360984d00c3")
        self.assertEqual(references(code),[])

    def test_image_base_in_index_register(self):
        # The real thread-creation routine uses [rdi+rsi+RVA], with RSI
        # containing the image base and RDI containing a thread-array offset.
        code = b"\x48\x8d\x35"+struct.pack("<i",-0x1007)+bytes.fromhex("48898c37e0341200c3")
        self.assertEqual(references(code)[0]["target"],0x1234e0)

    def test_indexed_image_base_keeps_table_rva(self):
        # Native Dvar_RegisterVariant adds the bucket offset before reading
        # and writing its hash table, so the later displacement still moves.
        code = b"\x4c\x8d\x05"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4d8d0440410fb780f0e943004d8d80f0e94300c3")
        self.assertEqual([r["target"] for r in references(code)],[0x43e9f0,0x43e9f0])

    def test_indexed_base_copy_and_call_preservation(self):
        code = b"\x48\x8d\x1d"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("488d1c434889dee800000000488d8ef0e94300c3")
        self.assertEqual(references(code)[0]["target"],0x43e9f0)

    def test_scaled_image_base_is_not_an_rva_base(self):
        code = b"\x48\x8d\x1d"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("488d1c5b488d8bf0e94300c3")
        self.assertEqual(references(code),[])

    def test_split_indexed_rva_and_image_base(self):
        code = b"\x4c\x8d\x0d"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("488d14cd087412004c01cac3")
        self.assertEqual(references(code)[0]["target"],0x127408)

    def test_split_rva_does_not_rebase_structure_fields(self):
        code = b"\x4c\x8d\x0d"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("488d14cd087412004c01ca488d8260984d00c3")
        self.assertEqual([r["target"] for r in references(code)],[0x127408])

    def test_split_rva_requires_proven_image_base(self):
        code = b"\x4c\x8d\x0d"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4d31c9488d14cd087412004c01cac3")
        self.assertEqual(references(code),[])

    def test_spatial_initializer_temporary_precedes_image_base(self):
        # Replay 0x12ec78e: the indexed destination is formed before its base
        # seed. A later allocator call preserves R12 before writing the field.
        code = bytes.fromhex("4d8da424a8516500")
        code += b"\x48\x8d\x05"+struct.pack("<i",-0x100f)
        code += bytes.fromhex("4901c4e80000000049890424c3")
        found = references(code)
        self.assertEqual([(r["rva"],r["target"]) for r in found],[(0x1000,0x6551a8)])

    def test_temporary_without_image_base_remains_an_integer(self):
        code = bytes.fromhex("4d8da424a85165004901c449890424c3")
        self.assertEqual(references(code),[])

    def test_allocator_rva_temporary_consumed_by_memory(self):
        # MT_Alloc forms a bitmap RVA in R11, then supplies its proven R14
        # image base in both the load and the atomic update.
        code = b"\x4c\x8d\x35"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4c8d1c8580e84300478b143341b900000000f0470fb10c33c3")
        self.assertEqual([r["target"] for r in references(code)],[0x43e880])

    def test_rva_temporary_register_copy_survives_call(self):
        code = b"\x4c\x8d\x35"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4c8d1c8580e843004c89dbe800000000428b0433c3")
        self.assertEqual([r["target"] for r in references(code)],[0x43e880])

    def test_overwritten_rva_temporary_is_not_relocated(self):
        code = b"\x4c\x8d\x35"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4c8d1c8580e843004531db478b1413c3")
        self.assertEqual(references(code),[])

    def test_scaled_rva_temporary_is_not_an_image_address(self):
        code = b"\x4c\x8d\x35"+struct.pack("<i",-0x1007)
        code += bytes.fromhex("4c8d1c8580e843004b8b045ec3")
        self.assertEqual(references(code),[])

    def test_image_base_survives_switch_into_another_switch(self):
        code = bytearray(0x140)
        first = b"\x48\x8d\x1d"+struct.pack("<i",-0x1007)
        first += bytes.fromhex("8b8483001100004801d8ffe0")
        second = bytes.fromhex("8b8c8b201100004801d9ffe1")
        code[:len(first)] = first
        code[0x20:0x20+len(second)] = second
        code[0x40] = 0xc3
        struct.pack_into("<I",code,0x100,0x1020)
        struct.pack_into("<I",code,0x120,0x1040)
        lengths = bytearray(len(code))
        decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        for start,body in ((0,first),(0x20,second),(0x40,b"\xc3")):
            for instruction in decoder.disasm(body,0x1000+start):
                at = instruction.address-0x1000
                lengths[at] = instruction.size
                lengths[at+1:at+instruction.size] = b"\xff"*(instruction.size-1)
        found,stats = image_references.recover(bytes(code),0x1000,lengths,0x1000000)
        self.assertEqual({i["target"] for i in found},{0x1100,0x1120})
        self.assertEqual(stats["image_base_dispatch_edges"],2)


if __name__ == "__main__":
    unittest.main()
