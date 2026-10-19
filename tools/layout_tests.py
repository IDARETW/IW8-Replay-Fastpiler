"""Small executable checks for layout growth, COFF sites, and branch relaxation."""
import collections
import struct
import unittest

import unicorn
import unicorn.x86_const as x86

from build import relocate
from layout import Layout, encode_relative_table, from_report


def fixture(opcode=None, prefix=b"", growth=80):
    manifest = dict(image_base=0x140000000, optional=dict(SizeOfImage=0x8000),
        sections=[dict(rva=0x1000,raw_size=0x400,virtual_size=0x400),dict(rva=0x2000)],
        replacements=[dict(symbol="first",begin=0x1040,end=0x1050),dict(symbol="second",begin=0x10c0,end=0x10d0)],
        short_references=[])
    text = bytearray(b"\x90"*0x400)
    if opcode is not None:
        size = len(prefix)+2
        text[0x80:0x80+size] = prefix+bytes([opcode])+struct.pack("<b",0x1040-(0x1080+size))
        manifest["short_references"].append([0x1080,0x1040])
    return manifest,text,Layout(manifest,dict(first=growth,second=16),text)


class LayoutTests(unittest.TestCase):
    def test_relative_table_signed_unsigned_and_scaled_limits(self):
        for width in (1, 2, 4, 8):
            for signed in (False, True):
                bits = width * 8
                minimum = -(1 << (bits-1)) if signed else 0
                maximum = (1 << (bits-1)) - 1 if signed else (1 << bits) - 1
                for subtract in (False, True):
                    item = dict(width=width, signed=signed, shift=2, subtract=subtract)
                    for value in (minimum, 0, maximum):
                        target = 0x1000 - value*4 if subtract else 0x1000 + value*4
                        encoded = encode_relative_table(item, target, 0x1000)
                        decoded = int.from_bytes(encoded, "little", signed=signed)
                        self.assertEqual(0x1000 - decoded*4 if subtract else 0x1000 + decoded*4, target)
                    for value in (minimum-1, maximum+1):
                        target = 0x1000 - value*4 if subtract else 0x1000 + value*4
                        with self.assertRaisesRegex(ValueError, "out of range"):
                            encode_relative_table(item, target, 0x1000)
                    with self.assertRaisesRegex(ValueError, "representable"):
                        encode_relative_table(item, 0x1001, 0x1000)

    def test_invalid_replacement_layout_is_rejected(self):
        for change in ("overlap", "duplicate", "outside", "empty"):
            manifest, text, _ = fixture()
            sizes = dict(first=16, second=16)
            if change == "overlap": manifest["replacements"][1]["begin"] = 0x1048
            elif change == "duplicate": manifest["replacements"][1]["symbol"] = "first"
            elif change == "outside": manifest["replacements"][1]["end"] = 0x2001
            else: sizes["first"] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                Layout(manifest, sizes, text)

    def test_growth_at_adjacent_slot_boundaries(self):
        manifest, text, _ = fixture()
        manifest["replacements"][1].update(begin=0x1050, end=0x1060)
        for first, second in ((16,16),(17,16),(16,17),(4112,4113)):
            with self.subTest(first=first,second=second):
                layout = Layout(manifest, dict(first=first,second=second), text)
                a = ((max(0,first-16)+15)//16)*16
                b = ((max(0,second-16)+15)//16)*16
                self.assertEqual(layout.map(0x1040),0x1040)
                self.assertEqual(layout.map(0x1050),0x1050+a)
                self.assertEqual(layout.map(0x1060),0x1060+a+b)
                self.assertEqual(len(layout.copy_text(text)),len(text)+a+b)

    def test_fit_growth_and_data_alignment(self):
        manifest,text,layout = fixture(growth=16)
        self.assertEqual(layout.map(0x1040),0x1040)
        self.assertEqual(layout.map(0x10c0),0x10c0)
        manifest,text,layout = fixture()
        self.assertEqual(layout.map(0x1040),0x1040)
        self.assertEqual(layout.map(0x10c0),0x1100)
        self.assertEqual(layout.map(0x2030),0x2030)
        manifest,text,layout = fixture(growth=4112)
        self.assertEqual(layout.map(0x2030),0x3030)
        self.assertEqual(len(layout.copy_text(text)),len(text)+4096)

    def test_rel32_addr32nb_and_addr64_sites(self):
        manifest,_,layout = fixture(growth=4112)
        obj=dict(path="fixture.obj",symbols={0:dict(name="replay_rva_00002030",section=0,value=0)})
        for kind in (1,3,4,5,6,7,8,9):
            with self.subTest(kind=kind):
                section=dict(rva=0x1080,original_rva=0x1080,data=bytes(8),relocations=[(0,0,kind)])
                bases=set()
                data=relocate(obj,section,{},manifest,collections.Counter(),bases,layout)
                if kind==1:
                    self.assertEqual(struct.unpack_from("<Q",data)[0],manifest["image_base"]+0x3030)
                    self.assertEqual(bases,{0x2080})
                elif kind==3:
                    self.assertEqual(struct.unpack_from("<I",data)[0],0x3030)
                else:
                    self.assertEqual(struct.unpack_from("<i",data)[0],0x3030-(0x2080+4+kind-4))

    def test_replacement_interior_is_rejected(self):
        _,_,layout=fixture()
        with self.assertRaisesRegex(ValueError,"interior"):
            layout.resolve(0x1041)

    def test_signed_coff_addends_cross_shift_boundaries(self):
        manifest, _, layout = fixture(growth=4112)
        obj = dict(path="negative-addend.obj", symbols={0:dict(name="replay_rva_00002030",section=0,value=0)})
        for kind in (1,3,4,5,6,7,8,9):
            for addend in (-0x10, -0x1030):
                with self.subTest(kind=kind,addend=addend):
                    data = struct.pack("<q" if kind == 1 else "<i", addend)
                    section = dict(rva=0x1080, original_rva=0x1080, data=data, relocations=[(0,0,kind)])
                    result = relocate(obj, section, {}, manifest, collections.Counter(), set(), layout)
                    target = layout.resolve(0x2030+addend)
                    expected = manifest["image_base"]+target if kind == 1 else target if kind == 3 else target-(layout.map(0x1080)+kind)
                    self.assertEqual(struct.unpack_from("<Q" if kind == 1 else "<I" if kind == 3 else "<i",result)[0], expected)

    def test_serialized_map_matches_half_open_boundaries_and_image_end(self):
        manifest, _, layout = fixture(growth=4112)
        report = dict(rva_map=layout.report(manifest))
        for rva in (0x103f,0x1040,0x104f,0x1050,0x1051,0x1fff,0x2000,0x2030,0x7fff,0x8000):
            self.assertEqual(from_report(rva,report),layout.map(rva))

    def test_relaxed_branches_execute_both_successors(self):
        cases=[(0xeb,b"",1,0,True),(0x74,b"",1,0x40,True),(0x74,b"",1,0,False),
               (0xe0,b"",2,0,True),(0xe0,b"",2,0x40,False),
               (0xe1,b"",2,0x40,True),(0xe1,b"",2,0,False),
               (0xe2,b"",2,0,True),(0xe2,b"",1,0,False),
               (0xe3,b"",0,0,True),(0xe3,b"",1,0,False),
               (0xe3,b"\x67",0x100000000,0,True),(0xe3,b"\x67",1,0,False)]
        for opcode,prefix,rcx,flags,taken in cases:
            with self.subTest(opcode=opcode,prefix=prefix,rcx=rcx,flags=flags):
                manifest,text,layout=fixture(opcode,prefix)
                self.assertIn(0x1080,layout.widened)
                code=layout.copy_text(text)
                layout.branches(code,manifest)
                target=layout.map(0x1040)-0x1000
                fallthrough=layout.map(0x1080+len(prefix)+2)-0x1000
                code[target:target+6]=b"\xb8\x2a\0\0\0\xc3"
                code[fallthrough:fallthrough+6]=b"\xb8\x18\0\0\0\xc3"
                machine=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
                machine.mem_map(0x1000,0x1000)
                machine.mem_write(0x1000,bytes(code))
                machine.mem_map(0x10000,0x1000)
                machine.mem_write(0x10800,struct.pack("<Q",0x10900))
                machine.reg_write(x86.UC_X86_REG_RSP,0x10800)
                machine.reg_write(x86.UC_X86_REG_RCX,rcx)
                machine.reg_write(x86.UC_X86_REG_EFLAGS,flags|2)
                machine.emu_start(layout.map(0x1080),0x10900,count=100)
                self.assertEqual(machine.reg_read(x86.UC_X86_REG_EAX),42 if taken else 24)
                self.assertEqual(machine.reg_read(x86.UC_X86_REG_EFLAGS),flags|2)

    def test_native_unwind_offsets_follow_relaxation(self):
        _,_,layout=fixture(0x74)
        header=bytes([1,0x30,1,0])
        codes=bytes([0x28,0x32])
        def read(at,size):return (header if at==0x2200 else codes)[:size]
        changes=layout.unwind_offsets([(0x1060,0x10c0,0x2200)],read)
        self.assertEqual(changes[0x2201],0x40)
        self.assertEqual(changes[0x2204],0x38)


if __name__=="__main__":unittest.main()
