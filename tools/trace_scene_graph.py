"""Execute the analysis-only 1.31 scene reader against serialized source data.

The VM follows database reader calls, not external engine/rendering services.
It is a source-layout investigation, not a runnable game or a build input.
"""
import argparse
import bisect
import hashlib
import json
import struct
import re
import functools
import uuid
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP
from analyze_frontend_loaders import ROOT, REFERENCE
from analyze_frontend_loaders import ORIGINAL, ORIGINAL_SHA

BLOCK = 0x2000000
BLOCK_BASE = 0x30000000
STACK, DONE, DUMMY = 0x70000000, 0x71000000, 0x72000000
POS = 0x140bd9d0
GLOBALS = dict(GfxWorld=0x997d3b0, GfxWorldSurfaces=0x99825f8, MapEnts=0x99811e8)
PROFILES = dict(GfxWorld=(0x1d35c30,17872), MapEnts=(0x1daefe0,1072))


def reserve_insert_pointer(positions, active_stream, active_position):
    """Advance Replay's saved block-5 cursor for DB_InsertPointer.

    The helper intentionally does not touch archive bytes. When another stream
    is active, only the saved stream-5 position changes; when stream 5 is
    active, the caller must also install the returned position as its cursor.
    """
    before = active_position if active_stream == 5 else positions[5]
    slot = (before + 7) & ~7
    after = slot + 8
    if slot < BLOCK_BASE + 5 * BLOCK or after > BLOCK_BASE + 6 * BLOCK:
        raise ValueError(f'Inserted-pointer slot outside stream 5: {slot:#x}')
    updated = dict(positions)
    updated[5] = after
    next_active = after if active_stream == 5 else active_position
    return slot, before, after, updated, next_active


def local_archive_reference(service, token, base, loaded_end, read_pointer):
    """Replay resolve returns an address; alias reads the fixed-up pointer there.

    Original Replay d90530 ends with base+offset; d904c0 instead reads
    qword ptr [base+offset]. Neither permits a read beyond the loaded span.
    This helper covers unshifted local stream storage in the diagnostic VM;
    it does not model the native patch-memory offset-adjustment tables.
    """
    relative = (token & 0xffffffff) - 1
    destination = base + relative
    if service not in ('resolve', 'alias'):
        raise ValueError('Unknown archive reference service')
    size = 8 if service == 'alias' else 1
    if relative < 0 or not base <= destination or destination + size > loaded_end:
        raise ValueError(f'Local archive reference outside loaded source: {token:#x}')
    return destination, read_pointer(destination) if service == 'alias' else destination


@functools.lru_cache(maxsize=None)
def compiled_inputs(frontend, frontend_placeholders=False):
    """One immutable compiler/input snapshot for a batch of offline probes."""
    from build import compile_one
    from coff import read
    assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == ORIGINAL_SHA
    objects = []
    # Independent layout workers may compile different source profiles at the
    # same time. Never share writable .obj paths between those compilations.
    object_dir = ROOT/'evidence/scene-objects'/f'{frontend}-{uuid.uuid4().hex}'
    object_dir.mkdir(parents=True)
    inputs = sorted((ROOT/'src').rglob('*.cpp')) + sorted((ROOT/'src').rglob('*.h'))
    inputs += [ROOT/'source-units.json', ROOT/'tools/build.py', ROOT/'tools/coff.py',
               ROOT/'generated/native-symbols.json', ROOT/'generated/function-catalog.json']
    receipt = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in inputs}
    for label in ('DB_ArchiveFieldPlan', 'DB_ArchiveScene', 'Load_GfxWorld',
                  'Load_GfxWorldSurfaces', 'DB_ReleaseGfxWorld', 'Load_MapEnts',
                  'Load_ClientTriggers', 'Load_XAnimParts', 'Load_ScriptableDefPtr',
                  'Load_SndAlias', 'Load_SndAliasList', 'Load_SndAliasListArray', 'Load_SndDuckArray', 'DB_ReleaseSndBankResident',
                  'Load_ParticleSystemDefPtr', 'Load_MaterialHandle', 'Load_GfxImage',
                  'Load_GfxImageRawGpuTempArray', 'Load_RawFile',
                  'DB_ArchiveMesh', 'Load_XModelSurfs', 'Load_XSurfaceSharedData'):
        path = object_dir/(label+'.obj')
        compile_one(ROOT/'src'/(label+'.cpp'), path, cpp=True, frontend_probe=frontend,
                    frontend_placeholders=frontend_placeholders)
        objects.append(read(path))
    native = json.loads((ROOT/'generated/native-symbols.json').read_text())
    catalog = json.loads((ROOT/'generated/function-catalog.json').read_text())
    by_id = {r['id']: r['rva'] for r in catalog['functions']+catalog['symbols']}
    source_units = json.loads((ROOT/'source-units.json').read_text())
    for item in source_units.get('imports', []):
        native[item['symbol']] = by_id[item['symbol_id']]
    units = {u['symbol']:by_id[u['function_id']] for u in source_units['units']}
    if any(hashlib.sha256((ROOT/path).read_bytes()).hexdigest() != digest
           for path, digest in receipt.items()):
        raise ValueError('Reader inputs changed during compilation; rerun the offline probe')
    (object_dir/'inputs.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return pefile.PE(str(ORIGINAL), fast_load=True), objects, native, units, dict(
        source_sha256=receipt, object_directory=str(object_dir),
        object_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in object_dir.glob('*.obj')})


def run(name, source, file_offset, compiled=False, frontend='7b', output_prefix=None, source_version=None,
        asset_type=None, asset_size=None, expected_reads=None, instruction_limit=8000000,
        local_asset_offsets=False, stream_base_alignment=None, frontend_placeholders=False,
        root_reader=None, linked_weapon_placeholders=False, external_root_asset_name=None,
        initial_stream_positions=None):
    # A nested source record can be tested before its parent adapter exists.
    # Resolve both its reader and transfer global through the same catalog as
    # a normal compilation. No alternate native-body emulator is required.
    # Contract: (compiled entry symbol, native transfer-global symbol, size).
    if root_reader is not None and (not compiled or asset_type is not None or
            len(root_reader) != 3 or not 0 < root_reader[2] <= BLOCK):
        raise ValueError('Invalid standalone compiled reader contract')
    source_version = source_version or (4118 if frontend == '6' else 4136)
    if compiled:
        pe, objects, native, unit_entries, compiled_receipt = compiled_inputs(frontend, frontend_placeholders)
        meta = {'dump_sha256': ORIGINAL_SHA, 'missing_pages': []}
    else:
        meta=json.loads((ROOT/'evidence/mw131-reference-dump.json').read_text())
        assert meta['analysis_only'] and hashlib.sha256(REFERENCE.read_bytes()).hexdigest()==meta['dump_sha256']
        pe=pefile.PE(str(REFERENCE),fast_load=True)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    machine=Uc(UC_ARCH_X86,UC_MODE_64);pages=set();events=[];external={};stream=0;cursor=file_offset
    positions={index:BLOCK_BASE+index*BLOCK for index in range(11)};stack=[]
    for index,alignment in (stream_base_alignment or {}).items():
        if index not in positions or not 0<=alignment<16:raise ValueError("Invalid archive base alignment")
        positions[index]+=alignment
    if initial_stream_positions is not None:
        for raw_index, value in initial_stream_positions.items():
            index = int(raw_index)
            if index not in positions or not isinstance(value, int):
                raise ValueError(f"Invalid initial archive stream position: {raw_index!r}={value!r}")
            base = BLOCK_BASE + index * BLOCK
            if not base <= value <= base + BLOCK:
                raise ValueError(f"Initial stream {index} position is outside its block: {value:#x}")
            positions[index] = value
    asset_bases=dict(positions)
    asset_depth = 0
    expected_reads = None if expected_reads is None else [(r['size'], r['offset']) for r in expected_reads if r['size']]
    physical_index = 0
    def map_(at,size):
        for page in range(at&~4095,(at+size+4095)&~4095,4096):
            if page not in pages:machine.mem_map(page,4096);pages.add(page)
    def put(at,raw):map_(at,len(raw));machine.mem_write(at,bytes(raw))
    def qput(at,value):put(at,struct.pack('<Q',value))
    def qget(at):return struct.unpack('<Q',machine.mem_read(at,8))[0]
    def read_pe_page(at):
        page=at&~4095
        if not compiled and any(page==p for p in meta['missing_pages']):raise ValueError(f'Unreadable reference page: {page:#x}')
        map_(page,4096)
        section=pe.get_section_by_rva(page)
        if section:
            raw=pe.get_data(page,4096)
            if raw:machine.mem_write(page,raw)
    def unmapped(_,access,at,size,value,opaque):
        if 0<=at<pe.OPTIONAL_HEADER.SizeOfImage:
            read_pe_page(at);return True
        if BLOCK_BASE<=at<BLOCK_BASE+11*BLOCK:
            map_(at,size);return True
        return False
    machine.hook_add(UC_HOOK_MEM_UNMAPPED,unmapped)
    # Database namespace is code under investigation. The caller below never
    # runs the native reference entry point or any operating-system import.
    namespace=(0xd80000,0xe50000) if compiled else (0x1d30000,0x1df0000)
    pos=0xd120c00 if compiled else POS
    globals_={'GfxWorld':0x5d40d00,'GfxWorldSurfaces':0x5d45338,'MapEnts':0x5d443b8,
              'XAnimParts':native['varXAnimParts']} if compiled else GLOBALS
    if root_reader is not None:
        globals_[name] = native[root_reader[1]]
    for page in range(*namespace,4096):
        if compiled or page not in meta['missing_pages']:read_pe_page(page)
    for at in globals_.values():read_pe_page(at)
    read_pe_page(pos);qput(pos,positions[0])
    if asset_type is None: qput(globals_[name],positions[0])
    for other,at in globals_.items():
        if other!=name:qput(at,DUMMY)
    map_(DUMMY,65536);map_(STACK,0x20000);map_(DONE,4096)
    sp=STACK+0x18008;qput(sp,DONE);machine.reg_write(UC_X86_REG_RSP,sp);machine.reg_write(UC_X86_REG_RCX,0)
    if asset_type is not None:
        assert compiled and asset_size
        entry,size=native['Load_XAssetHeader'],asset_size
        put(positions[0],struct.pack('<IIQ',asset_type,0,0xfffffffffffffffe))
        qput(0x5d414b0,positions[0]);qput(0x5d414d0,positions[0]+8)
        qput(pos,positions[0]+16)
        machine.reg_write(UC_X86_REG_RCX,1)
    elif root_reader is not None:
        entry, size = unit_entries[root_reader[0]], root_reader[2]
    else:
        entry,size=(native['Load_XAnimParts'],160) if compiled and name=='XAnimParts' else PROFILES[name]
    if compiled and source_version == 4289 and asset_type is None and root_reader is None:
        size = {'GfxWorld':17936, 'MapEnts':1136, 'XAnimParts':168}[name]
    put(entry,pe.get_data(entry,15))
    globals_seen=set(globals_.values());executed=set();last=[]
    services={0x23c8750:'stream',0x1d30210:'align',0x23c8340:'push',0x23c8290:'pop',
              0x1d310a0:'shared',0x1d30dd0:'unshared',0x1d30810:'asset_push',0x1d305e0:'asset_pop',
              0x1d332e0:'resolve',0x1d33270:'alias',0x23c8830:'string'}
    if compiled:
        services={0x11b2a20:'stream',0xd8d480:'align',0x11b2570:'push',0x11b24c0:'pop',
                  0xd8e5b0:'shared',0xd8e2e0:'unshared',0xd8da80:'asset_push',0xd8d850:'asset_pop',
                  0xd90530:'resolve',0xd904c0:'alias',0x11b2b00:'string'}
        if 'DB_InsertPointer' in native:
            services[native['DB_InsertPointer']] = 'insert_pointer'
        services[native['sub_1411B29B0']] = 'prefix'
    compiled_code=[];public={};allocation_cursor=0x60000000;allocations={};api_calls=[]
    archive_references=[]
    compiled_functions=[]
    mesh_context = None
    if compiled:
        section_locations={};symbols={};next_section=0x50000000
        for index,obj in enumerate(objects):
            for section_index,section in enumerate(obj['sections'],1):
                section_locations[index,section_index]=next_section;next_section+=0x10000
                if section['name']=='.text' and section['data']:compiled_code.append((section_locations[index,section_index],len(section['data'])))
            for number,symbol in obj['symbols'].items():
                if symbol['section']>0:
                    symbols[index,number]=section_locations[index,symbol['section']]+symbol['value']
                    if symbol['storage']==2:public[symbol['name']]=symbols[index,number]
            # Derive diagnostic caller identities from this compilation's COFF
            # symbols. A recorded return RVA is not stable when C++ grows.
            for section_index,section in enumerate(obj['sections'],1):
                if not section['flags'] & 0x20000000:continue
                functions=sorted((s['value'],s['name']) for s in obj['symbols'].values()
                    if s['section']==section_index and s['kind'] & 0x20)
                for position,(offset,label) in enumerate(functions):
                    end=next((other for other,_ in functions[position+1:] if other>offset),len(section['data']))
                    if offset<end:
                        begin=section_locations[index,section_index]
                        compiled_functions.append((begin+offset,begin+end,label))
        public.update(s_dbLastXFileVersion=0x71200000,s_dbFrontendProbeAccepted=0x71200004,
                      _fltused=0x71200008,
                      s_dbFrontendAssetType=0x7120000c,
                      s_dbFrontendArchiveTraceCount=0x71200010,
                      s_dbFrontendAssetsRead=0x71200014,
                      memmove=0x71100100,memcpy=0x71100200,memset=0x71100300,__chkstk=0x71100400,
                      DB_RebaseWeaponArchiveAlias=0x71100500, DB_GetFrontendSourceXFileVersion=0x71100600)
        # A standalone typed-reader probe has no top-level Load_XAsset loop.
        # Its live-only diagnostic ordinals start at zero; they do not provide
        # archive ownership or alias-resolution evidence in this VM.
        put(0x71200000,struct.pack('<IIIIII',source_version,4,0,asset_type or 0,0,0))
        put(DUMMY,f'mp_frontend{frontend}\0'.encode())
        for number,(label,api) in enumerate((('__imp_VirtualAlloc',0x71101000),('__imp_VirtualFree',0x71101100),
                                           ('__imp_VirtualQuery',0x71101200))):
            public[label]=0x71201000+number*8;qput(public[label],api);put(api,b'\xc3')
        # Mesh file IO is independently exercised with the actual compiled
        # helper on Windows. This graph loads its verified cache into VM memory.
        for number,label in enumerate(('GetModuleFileNameW','CreateFileW','GetFileSizeEx','ReadFile','CloseHandle')):
            public['__imp_'+label]=0x71201100+number*8
            qput(public['__imp_'+label],0x71102000+number*16)
        for api in public.values():
            if 0x71100000<=api<0x71200000:put(api,b'\xc3')
        for index,obj in enumerate(objects):
            for number,symbol in obj['symbols'].items():
                if symbol['section']!=0:continue
                label=symbol['name']
                if re.fullmatch(r'replay_rva_[0-9a-f]{8}',label):
                    target=int(label[-8:],16)
                    if target==0xe305d0:target=public['Load_GfxWorldSurfaces']
                    if target==0xe09d20:target=public['Load_ClientTriggers']
                    if target==0xf60170:target=public['DB_ReleaseGfxWorld']
                    symbols[index,number]=target
                    if target in native.values() and target>0x2300000:
                        read_pe_page(target);globals_seen.add(target)
                else:symbols[index,number]=public.get(label,native.get(label))
                if symbols[index,number] is None:raise ValueError(f'Unresolved scene COFF symbol {label}')
            for section_index,section in enumerate(obj['sections'],1):
                if section['name'] not in ('.text','.data','.bss','.rdata'):continue
                raw=bytearray(section['data']);at=section_locations[index,section_index]
                for offset,symbol,kind in section['relocations']:
                    target=symbols[index,symbol]
                    if kind==1:struct.pack_into('<Q',raw,offset,target+struct.unpack_from('<Q',raw,offset)[0])
                    elif 4<=kind<=9:struct.pack_into('<i',raw,offset,target+struct.unpack_from('<i',raw,offset)[0]-(at+offset+4+kind-4))
                    else:raise ValueError(kind)
                if raw:put(at,raw)
        if asset_type is None: entry=public[root_reader[0] if root_reader is not None else 'Load_'+name]
        redirects={rva:public[label] for label,rva in unit_entries.items() if label in public}
    def return_(value=0):
        sp=machine.reg_read(UC_X86_REG_RSP);target=qget(sp)
        machine.reg_write(UC_X86_REG_RAX,value);machine.reg_write(UC_X86_REG_RSP,sp+8);machine.reg_write(UC_X86_REG_RIP,target)
    def hook(_,at,ins_size,opaque):
        nonlocal cursor,stream,allocation_cursor,physical_index,mesh_context,asset_depth
        if at==DONE:machine.emu_stop();return
        if compiled and at == native.get('SND_RemoveBank'):
            api_calls.append(dict(api='SND_RemoveBank', live_allocations=len(allocations)))
            return_();return
        if compiled and at == public.get('DB_LoadArchiveMesh'):
            cx=machine.reg_read(UC_X86_REG_RCX);dx=machine.reg_read(UC_X86_REG_RDX);count=machine.reg_read(UC_X86_REG_R8)
            def hash_bytes(raw, value=0xcbf29ce484222325):
                for byte in raw:value=((value^byte)*0x100000001b3)&0xffffffffffffffff
                return value
            name=bytearray()
            while len(name)<4096:
                byte=machine.mem_read(cx+len(name),1)[0]
                if not byte:break
                name.append(byte)
            else:raise ValueError('Unterminated mesh name')
            cache=ROOT/f'assets/mw169-frontend-mesh-cache/{hash_bytes(name):016x}.rmesh'
            raw=cache.read_bytes()
            magic,version,n,source_size,resident_size,surface_hash,data_hash=struct.unpack_from('<QIIIIQQ',raw)
            data=raw[40+4*n:]
            if (magic!=0x3248534d594c5052 or version!=4289 or n!=count or
                surface_hash!=hash_bytes(machine.mem_read(dx,count*208),
                    hash_bytes(machine.mem_read(machine.reg_read(UC_X86_REG_R9),32))) or
                len(data)!=resident_size or data_hash!=hash_bytes(data)):
                raise ValueError('Mesh cache does not match native graph input')
            allocation_cursor=(allocation_cursor+4095)&~4095
            mesh=allocation_cursor; data_at=mesh+((64+4*n+15)&~15)
            allocation_cursor=data_at+resident_size
            put(mesh,struct.pack('<Q',0)+raw[:40]+struct.pack('<QQ',data_at,0)+raw[40:40+4*n])
            put(data_at,data)
            root=qget(native['varXModelSurfs'])
            mesh_context=dict(mesh=mesh,shared_token=qget(root+48))
            api_calls.append(dict(api='offline_verified_mesh_cache',name=name.decode(),size=resident_size))
            return_(mesh);return
        if compiled and at in redirects:
            machine.reg_write(UC_X86_REG_RIP,redirects[at]);return
        if compiled and at in (0x71100100,0x71100200,0x71100300,0x71100400,
                                0x71100500,0x71100600,0x71101000,0x71101100,0xf66a30):
            cx=machine.reg_read(UC_X86_REG_RCX);dx=machine.reg_read(UC_X86_REG_RDX);r8=machine.reg_read(UC_X86_REG_R8)
            if at in (0x71100100,0x71100200):put(cx,machine.mem_read(dx,r8));return_(cx)
            elif at==0x71100300:put(cx,bytes([dx&255])*r8);return_(cx)
            elif at==0x71100400:return_(machine.reg_read(UC_X86_REG_RAX))
            elif at==0x71100500:return_(0) # Scene graph has no converted weapon roots.
            elif at==0x71100600:return_(source_version)
            elif at==0xf66a30:return_(DUMMY)
            elif at==0x71101000:
                allocation_cursor=(allocation_cursor+4095)&~4095;allocated=allocation_cursor;allocation_cursor+=dx
                put(allocated,bytes(dx));allocations[allocated]=dx;api_calls.append(dict(api='VirtualAlloc',address=hex(allocated),size=dx));return_(allocated)
            else:
                assert cx in allocations;del allocations[cx];api_calls.append(dict(api='VirtualFree',address=hex(cx)));return_(1)
            return
        if at in services:
            label=services[at];cx=machine.reg_read(UC_X86_REG_RCX);dx=machine.reg_read(UC_X86_REG_RDX);r8=machine.reg_read(UC_X86_REG_R8)
            if label=='stream':
                start=cx&0xffffffff
                if r8>BLOCK or not (BLOCK_BASE<=dx<BLOCK_BASE+11*BLOCK or
                        (start==1 and STACK<=dx and dx+r8<=STACK+0x20000)):
                    raise ValueError(f'Invalid native read: {dx:#x} {r8:#x} at file {cursor:#x}')
                if start==0:
                    assert dx==qget(pos),f'Unexpected stream destination {dx:#x} != {qget(pos):#x}'
                    if stream==4:put(dx,bytes(r8))
                    else:
                        if r8 and expected_reads is not None:
                            actual=(r8,cursor)
                            expected=expected_reads[physical_index] if physical_index<len(expected_reads) else None
                            if actual!=expected:
                                raise ValueError(f'Physical read {physical_index} differs: {actual} != {expected}')
                            physical_index+=1
                        if cursor+r8>len(source):raise ValueError(f'Source overrun at {cursor:#x} + {r8:#x}')
                        put(dx,source[cursor:cursor+r8]);cursor+=r8
                    qput(pos,dx+r8)
                events.append(dict(op=label,start=start,size=r8,address=hex(dx),stream=stream,file_end=hex(cursor),
                                   bindings={hex(g):hex(qget(g)) for g in globals_seen if BLOCK_BASE<=qget(g)<BLOCK_BASE+11*BLOCK}))
            elif label=='prefix':
                # Native temporary stream-1 allocation/read used for count
                # prefixes (for example GfxCellTree). This is a real file read,
                # not an external GPU/registration stub returning null.
                if not 0 < cx <= BLOCK or not 0 < dx <= 4096 or dx & (dx-1):
                    raise ValueError('Invalid native prefix length/alignment')
                destination = ((qget(pos) if stream == 1 else positions[1]) + dx-1) & ~(dx-1)
                if expected_reads is not None:
                    expected = expected_reads[physical_index] if physical_index < len(expected_reads) else None
                    if (cx,cursor) != expected:
                        raise ValueError(f'Prefix read {physical_index} differs: {(cx,cursor)} != {expected}')
                    physical_index += 1
                if cursor + cx > len(source): raise ValueError('Prefix exceeds decoded source')
                put(destination,source[cursor:cursor+cx]);cursor += cx
                positions[1] = destination + cx
                if stream == 1: qput(pos,positions[1])
                events.append(dict(op='stream',start=0,size=cx,address=hex(destination),stream=1,
                                   file_end=hex(cursor),direct_prefix=True))
                return_(destination);return
            elif label=='string':
                logical_start=qget(pos)
                destination=qget(cx);end=source.index(b'\0',cursor)+1
                length=end-cursor
                assert length<65536 and destination==qget(pos)
                put(destination,source[cursor:end]);qput(pos,destination+length);cursor=end
                events.append(dict(op=label,size=length,address=hex(destination),stream=stream,
                                   logical_start=hex(logical_start),logical_end=hex(logical_start+length),
                                   file_end=hex(cursor)))
            elif label=='insert_pointer':
                # Replay reserves an aligned pointer-sized slot from block 5
                # even when a nested reader currently has another stream active.
                # Keep the saved block-5 cursor current so PopStreamPos restores
                # the reservation; do not advance the active stream's cursor.
                slot,before,after,updated_positions,next_active=reserve_insert_pointer(
                    positions,stream,qget(pos))
                put(slot,bytes(8))
                positions.clear();positions.update(updated_positions)
                if stream==5:qput(pos,next_active)
                events.append(dict(op=label,address=hex(slot),size=8,stream=5,
                                   active_stream=stream,alignment_padding=slot-before,
                                   stream5_before=hex(before),stream5_after=hex(after),
                                   file_end=hex(cursor),physical_read=False))
                return_(slot);return
            elif label=='align':qput(pos,(qget(pos)+cx)&~cx)
            elif label=='push':positions[stream]=qget(pos);stack.append(stream);stream=cx;qput(pos,positions[stream])
            elif label=='pop':positions[stream]=qget(pos);stream=stack.pop();qput(pos,positions[stream])
            elif label=='asset_push':
                # Replay's DB_GetAssetOffset reads the first PushAsset record,
                # not the currently nested asset. Capture actual cursors so
                # probes with nonzero entry alignment exercise the same base.
                if asset_depth == 0:
                    asset_bases.update(positions)
                    asset_bases[stream] = qget(pos)
                asset_depth += 1
            elif label=='asset_pop':
                if not asset_depth: raise ValueError('Unbalanced asset stack')
                asset_depth -= 1
            elif label in ('resolve','alias'):
                token=qget(cx)
                # Preserve incoming serialized references before the analysis
                # stub substitutes a resident address. Reader traversal alone
                # does not prove dependency closure. The native return site
                # lets a separate audit classify the actual pointer reader.
                field_source = None
                for event in reversed(events):
                    if event['op'] != 'stream' or event['start'] != 0 or event['stream'] == 4:
                        continue
                    begin = int(event['address'],16)
                    if begin <= cx and cx+8 <= begin+event['size']:
                        field_source = int(event['file_end'],16)-event['size']+cx-begin
                        break
                return_site=qget(machine.reg_read(UC_X86_REG_RSP))
                callers={name for begin,end,name in compiled_functions if begin<=return_site-1<end}
                if len(callers)>1:raise ValueError('Ambiguous compiled reference caller')
                reference = dict(service=label,token=hex(token),field_address=hex(cx),
                    native_return_site=hex(return_site),
                    compiled_caller=next(iter(callers),None),
                    source_field_offset=field_source,
                    source_field_offset_matches_raw_token=field_source is not None and
                        source[field_source:field_source+8] == struct.pack('<Q', token))
                archive_references.append(reference)
                if mesh_context and token == mesh_context['shared_token']:
                    descriptor=qget(mesh_context['mesh']+56)
                    if not descriptor:raise ValueError('Mesh shared alias precedes its descriptor')
                    qput(cx,descriptor)
                elif local_asset_offsets and token>>32 in range(0x10,0x1b):
                    block=(token>>32)-0x10
                    loaded_end=qget(pos) if stream==block else positions[block]
                    destination, value = local_archive_reference(label, token,
                        asset_bases[block], loaded_end, qget)
                    # Packed field references retain the actual loaded/fixed-up
                    # source object instead of the unrelated external stub.
                    qput(cx,value)
                    api_calls.append(dict(api='local_asset_alias',service=label,
                        token=hex(token),target=hex(destination),value=hex(value)))
                elif external_root_asset_name is not None and field_source == file_offset and label == 'resolve':
                    # A per-asset VM starts after the zone's global name table.
                    # Supply that external string explicitly from the pinned
                    # asset manifest, without claiming a real global fixup.
                    encoded_name = external_root_asset_name.encode('ascii')
                    if not encoded_name or len(encoded_name) >= 256:
                        raise ValueError('Invalid external root-name fixture')
                    put(DUMMY+0x3000, encoded_name+b'\0')
                    qput(cx,DUMMY+0x3000)
                    api_calls.append(dict(api='external_root_asset_name', name=external_root_asset_name,
                                          field_address=hex(cx), token=hex(token), external_stub=True))
                else:qput(cx,DUMMY)
                reference['resolved_address']=hex(qget(cx))
                reference['external_stub']=qget(cx) in (DUMMY,DUMMY+0x3000)
            return_();return
        if not namespace[0]<=at<namespace[1] and not any(start<=at<start+length for start,length in compiled_code):
            if compiled and at==native['Sys_Error']:
                message = bytearray()
                message_at = machine.reg_read(UC_X86_REG_RCX)
                for index in range(512):
                    value = bytes(machine.mem_read(message_at + index, 1))[0]
                    if not value: break
                    message.append(value)
                raise ValueError('Compiled scene reader called Sys_Error: ' +
                                 message.decode('utf-8', 'replace') +
                                 f' [arg1={machine.reg_read(UC_X86_REG_RDX):#x}]')
            if compiled and at == native['Load_MaterialAsset']:
                cx = machine.reg_read(UC_X86_REG_RCX)
                material = qget(cx)
                string_at = qget(material)
                name_bytes = bytearray()
                for index in range(1024):
                    value = bytes(machine.mem_read(string_at + index, 1))[0]
                    if not value: break
                    name_bytes.append(value)
                else: raise ValueError('Material registration name exceeds diagnostic bound')
                api_calls.append(dict(api='register_material', field_address=hex(cx),
                                      name=name_bytes.decode('ascii'), external_stub=True))
            if compiled and at == native.get('Load_ParticleSystemDefAsset'):
                # Diagnostic snapshot of the native particle header handed to
                # Replay registration. This allows offline archive probes to
                # distinguish a complete empty fallback shell from a merely
                # incremented placeholder counter; the service remains stubbed.
                field = machine.reg_read(UC_X86_REG_RCX)
                particle = qget(field)
                raw = bytes(machine.mem_read(particle, 128))
                empty_shell = (raw[8:92] == bytes(84) and raw[92:96] == b'\x00\x00\x80\x3f'
                               and raw[96:124] == bytes(28) and raw[124:128] == b'\x00\x00\x80\x3f')
                api_calls.append(dict(api='register_particle_system', field_address=hex(field),
                                      particle_address=hex(particle), header_bytes=raw.hex(),
                                      empty_shell=empty_shell, external_stub=True))
            if compiled and at == native.get('sub_1419388B0'):
                # Snapshot the raw image handed to native GPU creation. The
                # real graphics call remains stubbed in this offline reader VM.
                field = machine.reg_read(UC_X86_REG_RCX)
                raw_image = machine.reg_read(UC_X86_REG_RDX)
                raw = bytes(machine.mem_read(raw_image, 40))
                payload_size = struct.unpack_from('<I', raw, 8)[0]
                payload = struct.unpack_from('<Q', raw, 32)[0]
                api_calls.append(dict(api='create_raw_gpu_image', field_address=hex(field),
                                      image_address=hex(raw_image), header_bytes=raw.hex(),
                                      payload_sha256=hashlib.sha256(bytes(machine.mem_read(payload, payload_size))).hexdigest(),
                                      external_stub=True))
            if compiled and linked_weapon_placeholders and at == native.get('Load_WeaponCompleteDefAsset'):
                field = machine.reg_read(UC_X86_REG_RCX)
                reference = qget(field)
                string_at = qget(reference)
                name = bytearray()
                for index in range(256):
                    value = bytes(machine.mem_read(string_at + index, 1))[0]
                    if not value: break
                    name.append(value)
                else: raise ValueError('Weapon reference name exceeds diagnostic bound')
                if not name.startswith(b','):
                    raise ValueError('Foreign source weapon reached native registration without a named placeholder')
                # Explicit registration stub, separate from source storage.
                # Live native dependency residency is verified by the runtime
                # canary; this VM checks the adapter's publication boundary.
                resident, resident_name = DUMMY + 0x1000, DUMMY + 0x2000
                put(resident, struct.pack('<Q', resident_name) + bytes(616))
                put(resident_name, bytes(name[1:]) + b'\0')
                qput(field, resident)
                api_calls.append(dict(api='link_weapon_placeholder', field_address=hex(field),
                                      name=name.decode('ascii'), reference=hex(reference),
                                      resident=hex(resident), external_stub=True))
            external[hex(at)]=external.get(hex(at),0)+1
            return_(0);return
        ins=next(decoder.disasm(bytes(machine.mem_read(at,ins_size)),at),None)
        assert ins is not None
        executed.add(at);last.append(f'{at:#x} {ins.mnemonic} {ins.op_str}')
        if len(last)>30:last.pop(0)
        for operand in ins.operands:
            if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                target=at+ins.size+operand.mem.disp
                if target&~4095 not in pages:read_pe_page(target)
                if operand.size==8 and ins.mnemonic=='mov':globals_seen.add(target)
        if ins.mnemonic=='call' and ins.operands[0].type==X86_OP_IMM:
            target=ins.operands[0].imm
            if target&~4095 not in pages:
                if target<pe.OPTIONAL_HEADER.SizeOfImage:read_pe_page(target)
                else:raise ValueError(f'Call outside reference image: {target:#x}')
    machine.hook_add(UC_HOOK_CODE,hook)
    passed=False;error=None
    try:
        machine.emu_start(entry,DONE+1,count=instruction_limit)
        passed=machine.reg_read(UC_X86_REG_RIP)==DONE and not stack
        if not passed:error='Instruction limit or unbalanced stream stack'
        if passed and expected_reads is not None and physical_index!=len(expected_reads):
            passed=False;error=f'Only consumed {physical_index}/{len(expected_reads)} expected physical reads'
    except Exception as exc:error=repr(exc)
    root=BLOCK_BASE + (BLOCK if asset_type is not None else 0)
    result=dict(name=name,passed=passed,error=error,entry=hex(entry),root_size=size,file_start=hex(file_offset),file_end=hex(cursor),
                expected_physical_read_count=None if expected_reads is None else len(expected_reads),
                consumed_physical_read_count=physical_index,
                stream_positions={str(index):hex(value) for index,value in positions.items()},
                active_stream=stream,active_stream_position=hex(qget(pos)),
                native_instructions=len(executed),events=events,external_calls=external,last_instructions=last,
                archive_references=archive_references,
                reference_sha256=meta['dump_sha256'],source_sha256=hashlib.sha256(source).hexdigest(),
                coverage='Analysis-only native database-reader graph with external engine/rendering services stubbed. Not runtime, renderer, or gameplay proof.')
    if compiled:
        result['compiled_input_receipt'] = compiled_receipt
        for label in ('s_dbFrontendWorldMaterialPlaceholders',
                      's_dbFrontendModelMaterialPlaceholders',
                      's_dbFrontendParticleSystemsConverted',
                      's_dbFrontendParticleSystemsPlaceholdered',
                      's_dbFrontendWeaponPlaceholders',
                      's_dbScriptSourcesConverted', 's_dbScriptSourcesRejected'):
            if label in public:
                result.setdefault('compiled_diagnostics', {})[label] = struct.unpack(
                    '<I', machine.mem_read(public[label], 4))[0]
    prefix=output_prefix or (('compiled-mw131' if compiled else 'mw131') + ('-frontend6' if frontend == '6' else ''))
    if not (ROOT/'evidence'/prefix).resolve().is_relative_to((ROOT/'evidence').resolve()):
        raise ValueError('Scene evidence prefix must stay inside evidence')
    result['api_calls']=api_calls
    result['compiled_cpp']=compiled
    if compiled:
        result['resident_size']={'GfxWorld':17808,'MapEnts':1032,'XAnimParts':160}.get(name,size)
        result['coverage']='Actual compiled C++ scene readers and retained native Replay database-reader graph; external GPU, registration and OS services stubbed. Not live rendering proof.'
    root_path = ROOT/f'evidence/{prefix}-{name}-graph-root.bin'
    if all(page in pages for page in range(root & ~4095, (root+size+4095)&~4095, 4096)):
        root_path.write_bytes(bytes(machine.mem_read(root,size)))
    else:
        # An early contract rejection may occur before the root is allocated.
        # Keep its original failure instead of masking it with a dump exception.
        result['root_capture_error'] = 'Root was not fully mapped before reader stopped'
        if root_path.exists(): root_path.unlink()
    if name=='GfxWorld':
        for field in ((0x28,0x30,0x38,0x40) if compiled else (0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,0x80)):
            pointer=qget(root+0xc8+field)
            event=next((e for e in events if e['op']=='stream' and e['start']==0 and int(e['address'],16)==pointer),None)
            if event and event['size']:
                (ROOT/f'evidence/{prefix}-GfxWorld-surfaces-{field:x}.bin').write_bytes(bytes(machine.mem_read(pointer,event['size'])))
        if compiled:
            pointer=qget(root+0xf8)
            if pointer in {base+16 for base in allocations}:
                count=struct.unpack('<I',machine.mem_read(root+0xc8,4))[0]
                (ROOT/f'evidence/{prefix}-GfxWorld-expanded-bounds.bin').write_bytes(bytes(machine.mem_read(pointer,count*56)))
    if compiled and passed:
        result['counters']={label:struct.unpack('<I',machine.mem_read(address,4))[0]
                            for label,address in public.items() if label.startswith('s_dbFrontend') and label!='s_dbFrontendProbeAccepted'}
    if compiled and passed and name=='GfxWorld':
        # Native pool headers may be copied. Release by bounds ownership, and
        # check non-owning, owning, repeated and ordinary/native release paths.
        clone=root+0x100000
        put(clone,machine.mem_read(root,17808))
        result['release_cases']=[]
        for label,header,kind in (('non-owning',root,1),('owning-moved-header',clone,0),
                                  ('duplicate',clone,0),('native-untracked',root,0)):
            if label=='native-untracked':qput(root+0xf8,DUMMY)
            before=len(api_calls)
            qput(sp,DONE);machine.reg_write(UC_X86_REG_RSP,sp)
            machine.reg_write(UC_X86_REG_RCX,header);machine.reg_write(UC_X86_REG_RDX,kind)
            machine.emu_start(public['DB_ReleaseGfxWorld'],DONE+1,count=100000)
            assert machine.reg_read(UC_X86_REG_RIP)==DONE
            result['release_cases'].append(dict(case=label,api_calls=api_calls[before:]))
        assert not allocations,'Expanded scene allocation leaked in ownership tests'
        assert sum(call['api']=='VirtualFree' for call in api_calls)==1
        result['release_counter']=struct.unpack('<I',machine.mem_read(public['s_dbFrontendSurfaceBoundsReleased'],4))[0]
        assert result['release_counter']==1
    if compiled and passed and name=='soundbank':
        # Registration/GPU services remain stubbed, but run the actual compiled
        # owner wrappers against the bank produced by the complete reader graph.
        clone=root+0x100000
        put(clone,machine.mem_read(root,512))
        allocation_count=len(allocations)
        result['release_cases']=[]
        for label,header,kind,wrapper in (
                ('non-owning',root,1,'DB_ReleaseSndBankResident'),
                ('owning-moved-header',clone,0,'DB_ReleaseSndBankTransient'),
                ('duplicate',clone,0,'DB_ReleaseSndBankResident')):
            before=len(api_calls)
            qput(sp,DONE);machine.reg_write(UC_X86_REG_RSP,sp)
            machine.reg_write(UC_X86_REG_RCX,header);machine.reg_write(UC_X86_REG_RDX,kind)
            machine.emu_start(public[wrapper],DONE+1,count=1000000)
            assert machine.reg_read(UC_X86_REG_RIP)==DONE
            calls=api_calls[before:]
            if kind:
                assert not calls and len(allocations)==allocation_count
            else:
                assert calls and calls[0]['api']=='SND_RemoveBank'
                assert calls[0]['live_allocations']==(allocation_count if label=='owning-moved-header' else 0)
                assert not allocations,'Expanded sound arrays leaked on bank release'
            result['release_cases'].append(dict(case=label,api_calls=calls))
        result['expanded_alias_allocations']=allocation_count
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('name',choices=PROFILES);parser.add_argument('--offset',type=lambda s:int(s,0),required=True)
    parser.add_argument('--source',type=Path,default=ROOT/'assets/mw131-decoded/mp_frontend7b.fp.patched.dec')
    parser.add_argument('--compiled',action='store_true');args=parser.parse_args()
    result=run(args.name,args.source.read_bytes(),args.offset,args.compiled)
    prefix='compiled-mw131' if args.compiled else 'mw131'
    (ROOT/f'evidence/{prefix}-{args.name}-graph-trace.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('events','last_instructions')},indent=2))
    if not result['passed']:
        print('\n'.join(result['last_instructions']))
        raise SystemExit(1)


if __name__=='__main__':main()
