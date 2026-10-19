"""Repair instruction gaps in a disposable IDB and export real C++ continuations.

Invocation: idat -A -S"script.py request.json output.jsonl" disposable.i64
The source IDB, SQLite database, and executable are never written.
"""
import json
from pathlib import Path
import time
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_segment
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_typeinf
import ida_ua
import idc
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from recovered_cpp_names import count_jumpouts


def reference_names(cfunc, base):
    """Record native object identities from this ctree's own IDB generation."""
    class References(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.names = {}

        def remember(self, ea):
            name = ida_name.get_name(ea)
            if not name or ea < base:
                return
            function = ida_funcs.get_func(ea)
            kind = 'function' if function and function.start_ea == ea else 'data-global'
            value = dict(rva=ea - base, kind=kind)
            if name in self.names and self.names[name] != value:
                raise ValueError('Recovered object name has multiple native owners: ' + name)
            self.names[name] = value

        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_obj:
                self.remember(expr.obj_ea)
            return 0

    visitor = References()
    visitor.remember(cfunc.entry_ea)
    visitor.apply_to(cfunc.body, None)
    return visitor.names


def repair(row, base, clear_inferred_types=True):
    if row.get('ownership_error'):
        raise ValueError(row['ownership_error'])
    entry = base + row['rva']
    function = ida_funcs.get_func(entry)
    if (function is None or function.start_ea != entry) and not row['spans']:
        raise ValueError('Native catalog entry has no exact IDB function')
    details = {'old_function_end': function.end_ea - base if function else None}
    if not row['spans']:
        return details
    previous_type = ida_typeinf.tinfo_t()
    retain_type = not clear_inferred_types and ida_nalt.get_tinfo(previous_type, entry)
    if function is not None and function.start_ea == entry:
        ida_funcs.del_func(entry)
    for begin, end in row['spans']:
        ida_bytes.del_items(base + begin, ida_bytes.DELIT_SIMPLE, end - begin)
    patched = 0
    for rva, size, hex_bytes in row['instructions']:
        expected = bytes.fromhex(hex_bytes)
        if ida_bytes.get_bytes(base + rva, size) != expected:
            ida_bytes.patch_bytes(base + rva, expected)
            patched += 1
        actual = ida_ua.create_insn(base + rva)
        if actual != size:
            raise ValueError(f'IDA instruction decoder disagrees at {rva:#x}: '
                             f'created={actual}, expected={size}, native={hex_bytes}')
    details['restored_instruction_bytes'] = patched
    primary = next((span for span in row['spans'] if span[0] == row['rva']), None)
    if primary is None or not ida_funcs.add_func(entry, base + primary[1]):
        raise ValueError('Cannot adopt complete native function extent')
    function = ida_funcs.get_func(entry)
    for begin, end in row['spans']:
        if begin != row['rva'] and not ida_funcs.append_func_tail(function, base + begin, base + end):
            tail = ida_funcs.get_fchunk(base + begin)
            if tail is None or tail.start_ea != base + begin or tail.end_ea != base + end:
                raise ValueError('Cannot adopt native chained-unwind tail')
            parents = ida_funcs.func_parent_iterator_t(tail)
            attached = parents.first()
            while attached and parents.parent() != entry:
                attached = parents.next()
            if not attached:
                raise ValueError('Native chained-unwind tail is not attached to the requested function')
    if clear_inferred_types:
        idc.SetType(entry, '')
    elif retain_type and not ida_typeinf.apply_tinfo(entry, previous_type, ida_typeinf.TINFO_DEFINITE):
        raise ValueError('Cannot retain the fresh baseline function type after extent repair')
    return details


def main():
    request_path, output_path = map(Path, idc.ARGV[1:3])
    request = json.loads(request_path.read_text(encoding='utf-8'))
    if ida_nalt.retrieve_input_file_md5().hex() != request['database_program_md5']:
        raise ValueError('Disposable recovery IDB belongs to another image')
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError('The native C++ decompiler is unavailable')
    base = ida_nalt.get_imagebase()
    if base != request['image_base']:
        raise ValueError('Recovery IDB image base mismatch')
    progress_path = Path(request['progress_path']) if request.get('progress_path') else None

    def progress(row, phase):
        if progress_path is None:
            return
        record = dict(rva=row['rva'], source_hash=row['source_hash'], phase=phase)
        # Append complete lines: the external watchdog never needs to hold an
        # atomic-replacement file open while IDA publishes progress.
        with progress_path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record) + '\n')
            stream.flush()

    print('REPLAY_CPP_PROCESSOR', ida_ida.inf_get_procname(),
          ida_segment.getseg(base + request['requests'][0]['rva']).bitness, flush=True)
    ida_idp.set_processor_type('metapc', ida_idp.SETPROC_USER)
    # Repair all callees before decompiling their callers. Otherwise the first
    # functions would inherit stale argument lists from still-broken callees.
    repaired = {}
    ida_auto.enable_auto(False)
    for position, row in enumerate(request['requests']):
        try:
            progress(row, 'repair_start')
            repaired[row['rva']] = repair(row, base, request.get('clear_inferred_types', True))
            progress(row, 'repair_complete')
        except Exception:
            repaired[row['rva']] = {'repair_error': traceback.format_exc()}
        if position % 100 == 0:
            print('REPLAY_CPP_REPAIR', position + 1, len(request['requests']), flush=True)
    ida_auto.enable_auto(True)
    # Analyze the repaired ranges rather than draining unrelated IDB work.
    for row in request['requests']:
        for begin, end in row['spans']:
            progress(row, 'analysis_start')
            ida_auto.auto_wait_range(base + begin, base + end)
            progress(row, 'analysis_complete')
    hints = {}
    for group in [request.get('type_hints', [])] + [row.get('type_hints', []) for row in request['requests']]:
        for hint in group:
            key = hint['rva']
            if key in hints and hints[key]['prototype'] != hint['prototype']:
                raise ValueError('Conflicting recovery types for one native function entry')
            hints[key] = hint
    for hint in hints.values():
        target = base + hint['rva']
        function = ida_funcs.get_func(target)
        if hint['rva'] < 0 or function is None or function.start_ea != target:
            raise ValueError('Recovery type hint is not a mapped native function entry')
        if not idc.SetType(target, hint['prototype']):
            raise ValueError(f'Cannot apply verified recovery type: {hint["prototype"]}')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w', encoding='utf-8') as output:
        for position, row in enumerate(request['requests']):
            start = time.monotonic()
            result = dict(rva=row['rva'], name=row['name'], image_sha256=request['image_sha256'],
                          decoder_sha256=request.get('decoder_sha256'),
                          recovery_generation=request.get('recovery_generation'),
                          baseline_idb_sha256=request.get('baseline_idb_sha256'),
                          source_idb_sha256=request.get('source_idb_sha256'),
                          private_idb_input_sha256=request.get('private_idb_input_sha256'),
                          source_hash=row.get('source_hash'), ownership_error=row.get('ownership_error'))
            try:
                entry = base + row['rva']
                result.update(repaired[row['rva']])
                if 'repair_error' in result:
                    raise ValueError(result['repair_error'])
                function = ida_funcs.get_func(entry)
                if (function is None or function.start_ea != entry) and not row['spans']:
                    raise ValueError('Native catalog entry has no exact IDB function')
                ida_hexrays.mark_cfunc_dirty(entry, False)
                failure = ida_hexrays.hexrays_failure_t()
                progress(row, 'decompile_start')
                cfunc = ida_hexrays.decompile(entry, failure)
                if cfunc is None:
                    raise ValueError(str(failure))
                pseudo = '\n'.join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())
                result.update(status='recovered' if not count_jumpouts(pseudo) else 'continuation-required',
                              pseudocode=pseudo, prototype=str(cfunc.type),
                              reference_names=reference_names(cfunc, base),
                              remaining_jumpouts=count_jumpouts(pseudo),
                              function_end=ida_funcs.get_func(entry).end_ea - base,
                              repaired_native_spans=row['spans'])
                result['type_hints'] = request.get('type_hints', []) + row.get('type_hints', [])
                definitions = {}
                for name in dict.fromkeys(request.get('export_types', []) + row.get('export_types', [])):
                    tif = ida_typeinf.tinfo_t()
                    if tif.get_named_type(None, name):
                        definitions[name] = {'size': tif.get_size(),
                            'declaration': ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF, tif, name, '')}
                result['types'] = definitions
                result['unclassified_ranges'] = row.get('unclassified_ranges', [])
            except Exception:
                result.update(status='error', error=traceback.format_exc())
                ida_auto.enable_auto(True)
            result['seconds'] = time.monotonic() - start
            output.write(json.dumps(result, ensure_ascii=False) + '\n')
            output.flush()
            progress(row, 'record_complete')
            print('REPLAY_CPP_FLOW', position + 1, len(request['requests']),
                  result['name'], result['status'], flush=True)


try:
    main()
except Exception:
    print(traceback.format_exc(), flush=True)
finally:
    ida_pro.qexit(0)
