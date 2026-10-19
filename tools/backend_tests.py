"""Backend contracts tested with real Clang COFF plus malformed/family cases."""
import collections
import copy
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from coff import read, select_comdats, allocate_common, align, BIGOBJ_CLASS
from native_functions import FunctionIndex, original_rva
from build import place_cpp, relocate, LLVM
from layout import Layout
from recover import retire_weak_overlaps

ROOT=Path(__file__).resolve().parents[1]


def manifest():
    return dict(image_base=0x140000000, optional=dict(SizeOfImage=0x10000, SectionAlignment=0x1000),
        sections=[dict(name='.text',rva=0x1000,raw_size=0x1000,virtual_size=0x1000),
                  dict(name='.rdata',rva=0x2000,raw_size=0x1000,virtual_size=0x1000),
                  dict(name='.data',rva=0x3000,raw_size=0x1000,virtual_size=0x1000),
                  dict(name='.pdata',rva=0x5000,raw_size=0x1000,virtual_size=0x1000)],
        replacements=[],short_references=[],directories=[{}, {}, {},dict(rva=0x5000,size=36)])


def family_fixture(cycle=False):
    m=manifest(); data=bytearray(0x10000)
    rows=[(0x1100,0x1120,0x2100),(0x1200,0x1210,0x2120),(0x1300,0x1320,0x2140)]
    for i,row in enumerate(rows): struct.pack_into('<III',data,0x5000+12*i,*row)
    data[0x2100:0x2104]=bytes([1,0,0,0]);data[0x2140:0x2144]=bytes([1,0,0,0])
    data[0x2120:0x2124]=bytes([33,0,0,0])
    struct.pack_into('<III',data,0x2124,*(rows[1] if cycle else rows[0]))
    lengths=bytearray([1]*0x1000)
    return m,data,lengths


class BackendTests(unittest.TestCase):
    def test_empty_source_project_keeps_native_layout_and_definitions(self):
        m = manifest()
        original = copy.deepcopy(m)
        native = {'NativeEntry': 0x1700}
        layout = Layout(m, {}, bytes(0x1000))
        symbols, placements, extras, text_end, data_end = place_cpp([], native, m, layout, False)
        self.assertEqual(symbols, native)
        self.assertEqual(placements, [])
        self.assertEqual(extras, [])
        self.assertEqual(text_end, 0x2000)
        self.assertEqual(data_end, 0x4000)
        self.assertEqual(m, original)

    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='replay-coff-')
        cls.path=Path(cls.temp.name)
        (cls.path/'shared.h').write_text('''
extern "C" int helper(int);
template<class T> __declspec(noinline) int shared(T v) { volatile int a[12]; a[0]=v; return helper(a[0])+7; }
extern "C" { __declspec(selectany) int (*pointer)(int)=shared<int>; }
''')
        cls.objects=[]
        for name in ('a','b'):
            p=cls.path/(name+'.cpp')
            p.write_text('#include "shared.h"\nextern "C" int '+name+'(int v) { return pointer(v); }\n')
            subprocess.run([str(LLVM/'clang++.exe'),'--target=x86_64-pc-windows-msvc','-c',str(p),'-o',str(p.with_suffix('.obj')),
                            '-ffreestanding','-fno-exceptions','-fno-rtti','-ffunction-sections','-fdata-sections','-funwind-tables','-O2'],check=True,capture_output=True)
            cls.objects.append(read(p.with_suffix('.obj')))

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def test_real_relocation_bearing_comdat_and_associated_unwind(self):
        objects=copy.deepcopy(self.objects);select_comdats(objects)
        selected=[(o,s) for o in objects for s in o['sections'] if s.get('discarded')]
        self.assertTrue(any(s['name']=='.text' for _,s in selected))
        self.assertTrue(any(s['name']=='.pdata' for _,s in selected))
        self.assertTrue(any(s['name']=='.xdata' for _,s in selected))
        m=manifest();m['replacements']=[]
        layout=Layout(m,{},bytes(0x1000))
        symbols,placements,extra,_,_=place_cpp(objects,{'helper':0x1700},m,layout,True)
        self.assertEqual(len([p for p in placements if p['symbol']=='pointer']),1)
        m['linked_sections']=m['sections']+extra
        for o in objects:
            for s in o['sections']:
                if s.get('discarded'):continue
                if s['name']=='.pdata':s['rva']=0
                if 'rva' in s:relocate(o,s,symbols,m,collections.Counter(),set(),layout)

    def test_duplicate_strong_definition_fails(self):
        objects=copy.deepcopy([self.objects[0],self.objects[0]])
        with self.assertRaisesRegex(ValueError,'NODUPLICATES'):
            select_comdats(objects)

    def test_truncated_object_and_invalid_symbol_index_fail(self):
        raw=Path(self.objects[0]['path']).read_bytes()
        p=self.path/'broken.obj'
        for n in (0,4,19,39,len(raw)-2):
            p.write_bytes(raw[:n])
            with self.subTest(n=n),self.assertRaises((ValueError,UnicodeDecodeError)):read(p)
        bad=bytearray(raw);sec=self.objects[0]['sections']
        for i,s in enumerate(sec):
            if s['relocations']:
                rel_at=struct.unpack_from('<I',bad,20+i*40+24)[0]
                struct.pack_into('<I',bad,rel_at+4,0x7fffffff);break
        p.write_bytes(bad)
        with self.assertRaisesRegex(ValueError,'symbol index'):read(p)

    def test_unnamed_split_family_replaces_all_owned_chunks(self):
        m,data,lengths=family_fixture();index=FunctionIndex(m,lambda a,n:data[a:a+n],lengths)
        obj=dict(path='anonymous.obj',sections=[dict(name='.text',flags=0x20,data=b'\xc3')],
                 symbols={0:dict(name='replay_rva_00001100',value=0,section=1,storage=2)})
        rows=index.replacements([obj],{},bytes(0x1000),{})
        self.assertEqual([(r['begin'],r['end'],r['retired']) for r in rows],[(0x1100,0x1120,False),(0x1200,0x1210,True)])
        m['replacements']=rows;layout=Layout(m,{'replay_rva_00001100':64},bytes(0x1000))
        self.assertEqual(layout.map(0x1300),0x2300)
        with self.assertRaisesRegex(ValueError,'retired function code'):layout.resolve(0x1200)

    def test_chain_cycle_rejected(self):
        m,data,lengths=family_fixture(True)
        with self.assertRaisesRegex(ValueError,'Cyclic'):FunctionIndex(m,lambda a,n:data[a:a+n],lengths)

    def test_missing_unwind_is_allowed_only_for_proven_leaf(self):
        from verify import verify_frameless_leaf
        self.assertEqual(verify_frameless_leaf(b'\x89\xc8\xc3',0x1000),2)
        for code in (b'\x48\x83\xec\x28\xc3',b'\x53\xc3',b'\xe8\x00\x00\x00\x00\xc3'):
            with self.subTest(code=code),self.assertRaises(ValueError):verify_frameless_leaf(code,0x1000)

    def test_frameless_tail_jump_requires_exact_unwind_entry_and_unchanged_frame(self):
        from verify import verify_frameless_leaf
        target, rva = 0x2000, 0x1000
        jump = b'\xe9' + struct.pack('<i', target-rva-5)
        self.assertEqual(verify_frameless_leaf(jump,rva,{target}),1)
        for entries in (set(), {target+1}):
            with self.assertRaisesRegex(ValueError,'external transfer'):
                verify_frameless_leaf(jump,rva,entries)
        conditional = b'\x0f\x84' + struct.pack('<i',target-rva-6) + b'\xc3'
        with self.assertRaisesRegex(ValueError,'external transfer'):
            verify_frameless_leaf(conditional,rva,{target})
        for prefix in (b'\x53', b'\x48\x83\xec\x28'):
            code = prefix + b'\xe9' + struct.pack('<i',target-rva-len(prefix)-5)
            with self.assertRaisesRegex(ValueError,'preserved register'):
                verify_frameless_leaf(code,rva,{target})

    def test_leaf_tailcall_does_not_retire_separate_unframed_function(self):
        m,data,lengths=family_fixture();m['function_entries']=[0x1400,0x1500]
        code=bytearray(0x1000)
        code[0x400:0x405]=b'\xe9\0\0\0\0';lengths[0x400:0x405]=bytes([5,255,255,255,255])
        code[0x500]=0xc3
        index=FunctionIndex(m,lambda a,n:data[a:a+n],lengths)
        self.assertEqual(index.leaf(0x1400,code,{0x1400:0x1500}),[[0x1400,0x1405]])
        code[0x500:0x505]=b'\xe9\0\0\0\0';lengths[0x500:0x505]=bytes([5,255,255,255,255])
        self.assertEqual(index.leaf(0x1500,code,{0x1500:0x1400}),[[0x1500,0x1505]])

    def test_interior_entry_rejected(self):
        m,data,lengths=family_fixture();index=FunctionIndex(m,lambda a,n:data[a:a+n],lengths)
        obj=dict(path='tail.obj',sections=[dict(name='.text',flags=0x20,data=b'\xc3')],
                 symbols={0:dict(name='replay_rva_00001200',value=0,section=1,storage=2)})
        with self.assertRaisesRegex(ValueError,'interior/shared'):index.replacements([obj],{},bytes(0x1000),{})

    def test_page_alignment_preserved_through_growth(self):
        m=manifest();m['replacements']=[dict(symbol='f',begin=0x1100,end=0x1120)]
        layout=Layout(m,{'f':33},bytes(0x1000))
        for alignment in (16,32,64,128,256,512,1024,4096):
            for rva in (0x1800,0x2000,0x3040):
                self.assertEqual(layout.map(rva)%alignment,rva%alignment)

    def test_native_named_addend_maps_before_addition(self):
        m=manifest();m['replacements']=[dict(symbol='f',begin=0x1100,end=0x1120)]
        m['native_symbol_rvas']={'alias':0x1180}
        layout=Layout(m,{'f':64},bytes(0x1000))
        obj=dict(path='alias.obj',symbols={0:dict(name='alias',section=0,value=0)})
        s=dict(rva=0x1800,data=struct.pack('<i',-0x100),relocations=[(0,0,3)])
        result=relocate(obj,s,{'alias':layout.map(0x1180)},m,collections.Counter(),set(),layout)
        self.assertEqual(struct.unpack('<I',result)[0],0x1080)

    def test_weak_fallback_and_cycle(self):
        m=manifest();obj=dict(path='weak.obj',symbols={0:dict(name='weak',section=0,value=0,weak=dict(fallback=1,search=3)),1:dict(name='actual',section=0,value=0)})
        s=dict(rva=0x1800,data=bytes(8),relocations=[(0,0,1)])
        self.assertEqual(struct.unpack('<Q',relocate(obj,s,{'actual':0x1200},m,collections.Counter(),set()))[0],m['image_base']+0x1200)
        obj['symbols'][1]['weak']=dict(fallback=0,search=3)
        with self.assertRaisesRegex(ValueError,'Cyclic'):relocate(obj,s,{},m,collections.Counter(),set())

    def test_section_and_secrel_use_output_section(self):
        m=manifest();m['linked_sections']=m['sections'];obj=dict(path='sec.obj',symbols={0:dict(name='global',section=0,value=0)})
        for kind,expected,fmt in ((10,3,'<H'),(11,0x34,'<I')):
            s=dict(rva=0x1800,data=bytes(struct.calcsize(fmt)),relocations=[(0,0,kind)])
            result=relocate(obj,s,{'global':0x3034},m,collections.Counter(),set())
            self.assertEqual(struct.unpack(fmt,result)[0],expected)

    def test_native_secrel_addend_crossing_growth_uses_original_identity(self):
        m=manifest();m['replacements']=[dict(symbol='f',begin=0x1100,end=0x1120)]
        m['linked_sections']=[dict(rva=0x1000,virtual_size=0x2000)]
        layout=Layout(m,{'f':64},bytes(0x1000))
        for rva,addend,expected in ((0x1180,-0x100,0x80),(0x10f0,0x50,0x1140)):
            m['native_symbol_rvas']={'alias':rva}
            obj=dict(path='secrel.obj',symbols={0:dict(name='alias',section=0,value=0)})
            section=dict(rva=0x1800,data=struct.pack('<i',addend),relocations=[(0,0,11)])
            actual=relocate(obj,section,{'alias':layout.map(rva)},m,collections.Counter(),set(),layout)
            self.assertEqual(struct.unpack('<I',actual)[0],expected)

    def test_anonymous_identity_and_alignment_reject_invalid_input(self):
        self.assertEqual(original_rva('replay_rva_00001000',{}),0x1000)
        self.assertIsNone(original_rva('replay_rva_NOTHEX',{}))
        for value in (0,3,-1):
            with self.assertRaises(ValueError):align(5,value)

    def test_common_coalesces_largest_and_strong_wins(self):
        objects=[dict(path=str(n),sections=[],symbols={0:dict(name='buffer',section=0,value=n,storage=2)}) for n in (4,32)]
        allocate_common(objects,{})
        self.assertEqual(sum(len(s['data']) for o in objects for s in o['sections']),32)
        self.assertEqual(sum(s['section']>0 for o in objects for s in o['symbols'].values()),1)
        objects=[dict(path='common',sections=[],symbols={0:dict(name='native',section=0,value=16,storage=2)})]
        allocate_common(objects,{'native':0x3000})
        self.assertEqual(objects[0]['sections'],[])
        self.assertEqual(objects[0]['symbols'][0]['value'],0)

    def test_bigobj_symbol_and_auxiliary_width(self):
        header=bytearray(56)
        struct.pack_into('<HHHHI',header,0,0,0xffff,2,0x8664,0)
        header[12:28]=BIGOBJ_CLASS
        struct.pack_into('<III',header,44,1,97,1)
        section=struct.pack('<8sIIIIIIHHI',b'.text',0,0,1,96,0,0,0,0,0x60000020)
        symbol=struct.pack('<8sIiHBB',b'leaf',0,1,0x20,2,0)
        p=self.path/'big.obj';p.write_bytes(header+section+b'\xc3'+symbol+struct.pack('<I',4))
        result=read(p)
        self.assertTrue(result['bigobj']);self.assertEqual(result['symbols'][0]['name'],'leaf')

    def test_bigobj_associative_metadata_from_real_compiler_object(self):
        raw=Path(self.objects[0]['path']).read_bytes()
        machine,count,timestamp,at,n,_,_=struct.unpack_from('<HHIIIHH',raw)
        header=bytearray(56)
        struct.pack_into('<HHHHI',header,0,0,0xffff,2,machine,timestamp)
        header[12:28]=BIGOBJ_CLASS;struct.pack_into('<III',header,44,count,at+36,n)
        body=bytearray(raw[20:at])
        for i in range(count):
            for field in (20,24,28):
                value=struct.unpack_from('<I',body,i*40+field)[0]
                if value:struct.pack_into('<I',body,i*40+field,value+36)
        symbols=bytearray();index=0
        while index<n:
            fields=struct.unpack_from('<8sIhHBB',raw,at+index*18)
            symbols.extend(struct.pack('<8sIiHBB',*fields));index+=1
            for _ in range(fields[-1]):
                symbols.extend(raw[at+index*18:at+(index+1)*18]+bytes(2));index+=1
        p=self.path/'real-big.obj';p.write_bytes(header+body+symbols+raw[at+n*18:])
        big=read(p);normal=self.objects[0]
        self.assertTrue(big['bigobj'])
        self.assertEqual(big['symbols'],normal['symbols'])
        self.assertEqual(big['sections'],normal['sections'])
        select_comdats([big,copy.deepcopy(self.objects[1])])

    def test_absolute_padding_relocation_does_not_lookup_symbol(self):
        result=relocate(dict(path='padding',symbols={}),dict(rva=0x1000,data=b'1234',relocations=[(0,0xffffffff,0)]),{},manifest(),collections.Counter(),set())
        self.assertEqual(result,b'1234')

    def test_addr32_overflow_stops_link(self):
        m=manifest();o=dict(path='narrow',symbols={0:dict(name='target',section=0,value=0)})
        s=dict(rva=0x1100,data=bytes(4),relocations=[(0,0,2)])
        with self.assertRaisesRegex(ValueError,'overflow'):relocate(o,s,{'target':0x1400},m,collections.Counter(),set())

    def test_overaligned_data_uses_absolute_output_alignment(self):
        m=manifest();m['optional']['SizeOfImage']=0x11000
        section=dict(name='.data',data=bytearray(64),flags=0xc0e00040,relocations=[])
        obj=dict(path='aligned',sections=[section],symbols={0:dict(name='wideData',section=1,value=0,storage=2)})
        layout=Layout(m,{},bytes(0x1000))
        symbols,_,_,_,_=place_cpp([obj],{},m,layout,True)
        self.assertEqual(symbols['wideData']%8192,0)

    def test_switch_proof_retires_whole_overlapping_weak_instructions(self):
        lengths=bytearray([0,0,0,2,255,3,255,255,1])
        seen=bytearray([0,0,0,1,0,1,0,0,1]);confidence=bytearray([0,0,0,1,1,1,1,1,2])
        self.assertEqual(retire_weak_overlaps(lengths,seen,confidence,0,4,True),[(3,5)])
        lengths[:4]=bytes([4,255,255,255]);confidence[:4]=bytes([2]*4)
        self.assertEqual(retire_weak_overlaps(lengths,seen,confidence,4,4,True),[(5,8)])
        self.assertEqual(lengths[8],1)

    def test_competing_proven_decode_is_rejected(self):
        for strong in (False,True):
            with self.assertRaisesRegex(ValueError,'Conflicting proven'):
                retire_weak_overlaps(bytearray([3,255,255,0]),bytearray(4),bytearray([2,2,2,0]),1,2,strong)

    def test_generated_function_id_needs_no_address_in_source(self):
        m,data,lengths=family_fixture();index=FunctionIndex(m,lambda a,n:data[a:a+n],lengths)
        name='fn_a4d9247fe3b651c0'
        obj=dict(path='generated-name.obj',sections=[dict(name='.text',flags=0x20,data=b'\xc3')],
                 symbols={0:dict(name=name,value=0,section=1,storage=2)})
        rows=index.replacements([obj],{name:0x1100},bytes(0x1000),{})
        self.assertEqual(rows[0]['begin'],0x1100)
        self.assertEqual(rows[0]['symbol'],name)

    def test_standard_coff_high_section_number(self):
        count=32769;at=20+40*count
        header=struct.pack('<HHIIIHH',0x8664,count,0,at,1,0,0)
        sections=struct.pack('<8sIIIIIIHHI',b'.bss',0,0,0,0,0,0,0,0,0xc0000080)*count
        symbol=struct.pack('<8sIHHBB',b'high',0,count,0,2,0)
        p=self.path/'high-section.obj';p.write_bytes(header+sections+symbol+struct.pack('<I',4))
        self.assertEqual(read(p)['symbols'][0]['section'],count)



if __name__=='__main__':unittest.main()
