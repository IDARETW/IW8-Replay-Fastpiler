"""Verify an exact edited shader with WARP and Replay's native comparators."""
import argparse, ctypes as c, hashlib, json, struct
from pathlib import Path

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_R8, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RIP

EXE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
FUNCTIONS = {"pixel": (0x194D3F0, 0x70), "vertex": (0x194D480, 0x58)}

def sha(data): return hashlib.sha256(data).hexdigest()

def warp_vertex_shader(code):
    lib=c.WinDLL("d3d11.dll"); create=lib.D3D11CreateDevice
    create.argtypes=[c.c_void_p,c.c_uint,c.c_void_p,c.c_uint,c.c_void_p,c.c_uint,c.c_uint,c.POINTER(c.c_void_p),c.POINTER(c.c_uint),c.POINTER(c.c_void_p)]
    create.restype=c.c_long; dev,ctx,level=c.c_void_p(),c.c_void_p(),c.c_uint()
    status=create(None,5,None,0,None,0,7,c.byref(dev),c.byref(level),c.byref(ctx))
    if status < 0: raise OSError(f"WARP device creation failed: {status & 0xffffffff:#x}")
    def release(p):
        if p: c.WINFUNCTYPE(c.c_uint,c.c_void_p)(c.cast(p,c.POINTER(c.POINTER(c.c_void_p))).contents[2])(p)
    shader=c.c_void_p()
    try:
        table=c.cast(dev,c.POINTER(c.POINTER(c.c_void_p))).contents
        buf=c.create_string_buffer(code)
        status=c.WINFUNCTYPE(c.c_long,c.c_void_p,c.c_void_p,c.c_size_t,c.c_void_p,c.POINTER(c.c_void_p))(table[12])(dev,buf,len(code),None,c.byref(shader))
        return {"device":"D3D11 WARP","feature_level":hex(level.value),"hresult":f"0x{status & 0xffffffff:08x}","accepted":status >= 0}
    finally: release(shader); release(ctx); release(dev)

def comparator_case(pe, rva, slot, left_id, right_id, left_code, right_code):
    base=pe.OPTIONAL_HEADER.ImageBase; start=base+rva; done=0x71000000; memcmp=base+0x21F6920
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for at,size in ((start&-4096,4096),(memcmp&-4096,4096),(0x60000000,0x10000),(0x70000000,0x10000),(done,4096)):
        try: uc.mem_map(at,size)
        except: pass
    raw=pe.get_data(rva,0x90); uc.mem_write(start,raw); uc.mem_write(memcmp,b"\xc3"); uc.mem_write(done,b"\xf4")
    left,right,ls,rs,lc,rc=0x70000000,0x70000100,0x70001000,0x70001100,0x70002000,0x70003000
    uc.mem_write(lc,left_code); uc.mem_write(rc,right_code)
    for root,shader,ident,code in ((left,ls,left_id,lc),(right,rs,right_id,rc)):
        uc.mem_write(root+slot,struct.pack("<Q",shader)); uc.mem_write(shader+0x18,struct.pack("<QII",code,len(left_code if root==left else right_code),ident))
    def hook(cpu,at,size,_):
        if at==done: cpu.emu_stop()
        elif at==memcmp:
            a=cpu.reg_read(UC_X86_REG_RCX); b=cpu.reg_read(UC_X86_REG_RDX); n=cpu.reg_read(UC_X86_REG_R8)
            av=bytes(cpu.mem_read(a,n)); bv=bytes(cpu.mem_read(b,n)); result=(av>bv)-(av<bv)
            cpu.reg_write(UC_X86_REG_RAX,result & 0xffffffff)
    def unmapped(cpu,access,at,size,value,_): raise RuntimeError(f"unmapped {at:#x} size={size} rip={cpu.reg_read(UC_X86_REG_RIP):#x}")
    uc.hook_add(UC_HOOK_CODE,hook); uc.hook_add(UC_HOOK_MEM_UNMAPPED,unmapped); sp=0x60008000; uc.mem_write(sp,struct.pack("<Q",done)); uc.reg_write(UC_X86_REG_RSP,sp); uc.reg_write(UC_X86_REG_RCX,left); uc.reg_write(UC_X86_REG_RDX,right)
    uc.emu_start(start,done,count=1000); return uc.reg_read(UC_X86_REG_RAX)&0xffffffff

def verify(exe, proof_path, dxbc_path, catalog_path):
    exe_bytes=exe.read_bytes(); assert sha(exe_bytes)==EXE_SHA
    proof=json.loads(proof_path.read_text()); asset=proof["writer"]["assets"][0]; code=dxbc_path.read_bytes()
    assert asset["type_id"]==14 and asset["new_program_identity"]==0xB3F88526
    assert sha(code)==asset["identity_allocation"]["program_sha256"] and len(code)==proof["new_program_bytes"]
    catalog=json.loads(catalog_path.read_text()); entries={e["name"]:e for e in catalog["functions"] if e.get("name") in ("Material_ComparePixelShader","Material_CompareVertexShader")}
    assert entries["Material_ComparePixelShader"]["rva"]==FUNCTIONS["pixel"][0]
    assert entries["Material_CompareVertexShader"]["rva"]==FUNCTIONS["vertex"][0]
    pe=pefile.PE(str(exe),fast_load=True); old_id=asset["old_program_identity"]; new_id=asset["new_program_identity"]
    cases={}; function_bytes={}
    for name,(rva,slot) in FUNCTIONS.items():
        raw=pe.get_data(rva,0x90); function_bytes[name]={"rva":hex(rva),"bytes":len(raw),"sha256":sha(raw),"hex":raw.hex()}
        cases[name]={
            "equal_old_ids_different_code": comparator_case(pe,rva,slot,old_id,old_id,b"AAAA",b"BBBB"),
            "fresh_edited_id_different_code": comparator_case(pe,rva,slot,old_id,new_id,b"AAAA",b"BBBB"),
            "equal_program_distinct_ids": comparator_case(pe,rva,slot,old_id,new_id,b"AAAA",b"AAAA")}
        assert cases[name]["equal_old_ids_different_code"]==0
        assert cases[name]["fresh_edited_id_different_code"]!=0
        assert cases[name]["equal_program_distinct_ids"]!=0
    warp=warp_vertex_shader(code); assert warp["accepted"]
    return {"schema":"replay120-shader-candidate-contract-v1","passed":True,"executable":{"path":str(exe),"sha256":EXE_SHA},"candidate":{"path":str(dxbc_path),"sha256":sha(code),"bytes":len(code),"type_id":14,"old_identity":old_id,"new_identity":new_id},"catalog":{"path":str(catalog_path),"sha256":sha(catalog_path.read_bytes())},"warp":warp,"function_bytes":function_bytes,"native_comparator_cases":cases,"limitations":"D3D11 WARP validates exact DXBC creation; Replay live DX12/GPU execution remains a separate runtime gate."}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--exe",type=Path,required=True); ap.add_argument("--proof",type=Path,required=True); ap.add_argument("--dxbc",type=Path,required=True); ap.add_argument("--catalog",type=Path,required=True); ap.add_argument("--output",type=Path,required=True); a=ap.parse_args()
    result=verify(a.exe,a.proof,a.dxbc,a.catalog); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2)+"\n"); print(json.dumps({"passed":True,"warp":result["warp"],"cases":result["native_comparator_cases"]}))
if __name__=="__main__": main()
