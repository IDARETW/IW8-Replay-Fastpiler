"""Evaluate pinned Striga IR on Replay; never installs an engine replacement.

Requires the isolated striga-py314 packages and pinned striga-source checkout
under .toolchains. All compilation in this experiment runs on Windows.
"""
import ast
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
COMMIT='f2fbb7d15cb32f6d3571b4fc41a27d62ee2bc819'


def main():
    source=ROOT/'.toolchains/striga-source'
    if json.loads((source/'source-receipt.json').read_text())['commit']!=COMMIT:
        raise ValueError('Striga source revision differs from the evaluated pin')
    sys.path[:0]=[str(ROOT/'.toolchains/striga-py314'),str(source),str(ROOT/'tools'),str(ROOT)]
    from llvm import global_context, Linkage
    from bfs import lift_bfs
    from container import PEContainer
    from cpp_recovery import Recovery,atomic_json,sha,run,windows_compiler
    from test_cpp_recovery_pilot import Machine,cases
    # The upstream example executes demonstrations at import time. Load only
    # its declarations so this experiment controls every input and output.
    tree=ast.parse((source/'brighten.py').read_text())
    tree.body=[node for node in tree.body if isinstance(node,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.Assign,ast.AnnAssign))]
    helpers={};exec(compile(tree,str(source/'brighten.py'),'exec'),helpers)
    recovery=Recovery();recovery.verify_image()
    pe=PEContainer(str(recovery.image));directory=recovery.directory/'striga-evaluation';directory.mkdir(exist_ok=True)
    results=[]
    for name,identity in [('I_stricmp','fn_2a385ed3a736c866'),('I_stristr','fn_98e4a70bc4c66c13'),('Vec3Normalize','fn_62b1f5ea433e8291')]:
        row=recovery.resolve(identity);spans=recovery.spans(row)
        class Bounded:
            def get_data(self,address,size):
                rva=address-pe.image_base
                span=next((s for s in spans if s[0]<=rva<s[1]),None)
                if span is None:raise ValueError('Branch leaves proven native ownership')
                return pe.get_data(address,min(size,span[1]-rva))
        record=dict(name=name,function_id=identity,lifted=False,cpp_recovered=False,installed=False)
        try:
            with global_context().create_module(name) as module:
                sem=lift_bfs(module,Bounded(),pe.image_base+row['rva'],verbose=False)
                module.verify_or_raise();(directory/(name+'.lifted.ll')).write_text(str(module),encoding='utf-8')
                record['lifted']=True
                if name=='I_stricmp':
                    # The real loop is larger than the upstream demo. Force
                    # its state-based body into the ABI wrapper before RAM
                    # rewriting; ordinary O1 heuristics may leave the call.
                    sem.function.attributes.add('alwaysinline')
                    sem.function.linkage=Linkage.Internal
                    types=module.context.types
                    ram=module.add_global(types.array(types.i8,0),'RAM')
                    wrapper=module.add_function('Striga_I_stricmp',types.function(types.i32,[types.i64,types.i64]))
                    with wrapper.append_basic_block('entry').create_builder() as ir:
                        state=ir.alloca(sem.state_ty,'state')
                        def reg(register):return ir.struct_gep(sem.state_ty,state,sem.reg_indices[register],register)
                        ir.store(wrapper.get_param(0),reg('rcx'));ir.store(wrapper.get_param(1),reg('rdx'))
                        stack=ir.alloca(types.i8,types.i64.constant(4096),'stack')
                        top=ir.gep(types.i8,stack,[types.i64.constant(4088)])
                        ir.store(ir.ptrtoint(top,types.i64),reg('rsp'))
                        stored=ir.store(types.i64.constant(0xdeadbeef),top);stored.inst_alignment=1
                        ir.call(sem.function,[state,ram])
                        ir.ret(ir.trunc(ir.load(types.i64,reg('rax')),types.i32))
                    module.optimize('always-inline,default<O1>')
                    helpers['rewrite_ram_geps'](module,ram)
                    helpers['define_ret_stub'](module)
                module.optimize('default<O1>');module.verify_or_raise()
                path=directory/(name+'.optimized.ll');path.write_text(str(module),encoding='utf-8')
            if name=='I_stricmp':
                obj=directory/(name+'.obj')
                checked=run([windows_compiler(),'--target=x86_64-pc-windows-msvc','-O2','-c',path,'-o',obj],ROOT,60)
                record['windows_compilation']=checked
                if checked['returncode']==0:
                    native,candidate=Machine(pe.pe),Machine(pe.pe,obj)
                    count=0
                    for left,right in cases()[0]:
                        expected=native.execute(pe.image_base+row['rva'],left,right)
                        actual=candidate.execute(candidate.symbols['Striga_I_stricmp'],left,right)
                        if expected!=actual:raise ValueError('Striga differential mismatch for '+left.hex()+':'+right.hex())
                        count+=1
                    record['differential']=dict(passed=True,cases=count)
        except Exception as error:
            record['error']=type(error).__name__+': '+str(error)
        results.append(record);print(json.dumps(record),flush=True)
    inputs=[source/'bfs.py',source/'brighten.py',source/'container.py',*(source/'src/striga').rglob('*.py')]
    report=dict(schema=1,image_sha256=recovery.catalog['image_sha256'],striga_commit=COMMIT,
                host='Windows',results=results,source_inputs={str(p):sha(p) for p in inputs})
    atomic_json(directory/'report.json',report)
    return report


if __name__=='__main__':
    main()
