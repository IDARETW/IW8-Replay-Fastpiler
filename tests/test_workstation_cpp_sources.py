import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from workstation_sources import SourceWorkspace
from workstation_cpp_sources import compile_check, render_cpp
import source_catalog


class CppRecoveryTests(unittest.TestCase):
    def test_declaration_binding_preserves_literals_and_self_references(self):
        body = ('int Old() { const char *name = R"tag(Old())tag"; '
                '/* Old(); */ return (&Old)(); }')
        content, _, _, accepted = render_cpp('fn_id', 'Old', 'int Old()', body, symbol='Current')
        self.assertIn('int Current()', content)
        self.assertIn('(&Current)()', content)
        self.assertIn('R"tag(Old())tag"', content)
        self.assertIn('/* Old(); */', content)
        self.assertFalse(accepted)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        generated = self.root / 'generated'
        generated.mkdir()
        # Minimal PE fixture containing one complete native xor-eax/ret leaf.
        raw = bytearray(0x220)
        struct.pack_into('<I', raw, 0x3c, 0x80)
        raw[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<H', raw, 0x86, 1)
        struct.pack_into('<IIII', raw, 0x98 + 8, 0x20, 0x1000, 0x20, 0x200)
        raw[0x200:0x203] = b'\x33\xc0\xc3'
        (self.root / 'game_dx12_ship_replay.exe').write_bytes(raw)
        image = hashlib.sha256(raw).hexdigest()
        self.identity = source_catalog.stable_id(image, 0x1000)
        (generated / 'manifest.json').write_text(json.dumps({'input_sha256': image, 'image_base': 0x140000000,
            'sections': [{'rva': 0x1000, 'virtual_size': 0x20, 'flags': 0x20}]}), encoding='utf-8')
        (generated / 'function-catalog.json').write_text(json.dumps({'schema': 3, 'image_sha256': image,
            'functions': [{'id': self.identity, 'name': 'Leaf', 'rva': 0x1000, 'aliases': []}], 'symbols': []}), encoding='utf-8')
        self.database = self.root / 'analysis.sqlite'
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE functions(address TEXT UNIQUE,name TEXT,prototype TEXT,pseudocode TEXT,clean_pseudo TEXT,size INTEGER)')
            db.execute('INSERT INTO functions VALUES (?,?,?,?,?,?)',
                       (str(0x140001000), 'Leaf', '__int64 Leaf()', '{\n return 0;\n}', '{ invalid vXXX; }', 3))
            db.commit()
        self.sources = SourceWorkspace(self.root, self.root / 'cache', self.database)

    def test_export_counter_map_refreshes_without_catalog_rebuild(self):
        # The generated catalog still contains historical aliases. Source opens
        # must consume the fresh live export ownership in one SQLite snapshot.
        image = self.sources._load_catalog()['image_sha256']
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('CREATE TABLE replay_ida_export_function_names('
                       'function_rva INTEGER PRIMARY KEY,name TEXT,input_md5 TEXT,image_sha256 TEXT,'
                       'idb_sha256 TEXT,idb_path TEXT)')
            db.execute('INSERT INTO replay_ida_export_function_names VALUES(?,?,?,?,?,?)',
                       (0x1000, 'nullsub_62', '11' * 16, image, 'b' * 64, 'fresh.i64'))
            db.execute('UPDATE functions SET prototype=?,pseudocode=?,size=?',
                       ('void Leaf()', 'void Leaf() { nullsub_62(); }', 10))
            db.commit()
        self.sources._catalog['database_program_md5'] = '11' * 16
        row = self.sources._by_identity(self.identity)
        self.assertEqual(row['decompiler_name'], 'nullsub_62')
        value = self.sources.cpp_index().get(row)
        self.assertIn('Leaf();', value['content'])
        self.assertNotIn('nullsub_62', value['content'])

    def test_live_counter_references_use_their_own_atomic_text_event(self):
        image = self.sources._load_catalog()['image_sha256']
        self.sources._catalog['database_program_md5'] = '11' * 16
        body, proto = 'void Leaf() { nullsub_62(); }', 'void Leaf()'
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE functions SET prototype=?,pseudocode=?,size=10', (proto, body))
            db.execute('CREATE TABLE replay_ida_export_function_names('
                       'function_rva INTEGER PRIMARY KEY,name TEXT,input_md5 TEXT,image_sha256 TEXT,'
                       'idb_sha256 TEXT,idb_path TEXT)')
            db.execute('INSERT INTO replay_ida_export_function_names VALUES(?,?,?,?,?,?)',
                       (0x1000, 'nullsub_62', '11' * 16, image, 'b' * 64, 'fresh.i64'))
            db.execute('CREATE TABLE replay_ida_function_text(function_rva INTEGER PRIMARY KEY,'
                       'pseudocode TEXT,prototype TEXT,event_id TEXT)')
            db.execute('CREATE TABLE replay_ida_events(event_id TEXT PRIMARY KEY,payload TEXT)')
            db.execute('INSERT INTO replay_ida_function_text VALUES(?,?,?,?)', (0x1000, body, proto, 'live'))
            db.commit()
        index = self.sources.cpp_index()
        value = self.sources.get_source(self.identity, 'cpp')
        self.assertIn('func_unresolved_nullsub_62();', value['content'])
        event = dict(kind='text', rva=0x1000, input_md5='11' * 16, pseudocode=body, prototype=proto,
                     reference_names={'nullsub_62': dict(rva=0x1010, kind='function')})
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO replay_ida_events VALUES(?,?)', ('live', json.dumps(event)))
            db.commit()
        value = self.sources.get_source(self.identity, 'cpp')
        self.assertIn('func_140001010();', value['content'])
        self.assertNotIn('func_unresolved_', value['content'])
        index.refresh()
        self.assertEqual(self.sources.get_source(self.identity, 'cpp')['content'], value['content'])
        # A newer declaration retaining older text has no matching body event.
        event.update(kind='prototype', prototype='void Leaf(int arg)')
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE replay_ida_events SET payload=?', (json.dumps(event),))
            db.commit()
        self.assertIn('func_unresolved_nullsub_62();', self.sources.get_source(self.identity, 'cpp')['content'])

    def test_private_recovery_never_borrows_legacy_counter_ownership(self):
        from recovered_cpp_flow import source_hash
        catalog = self.sources._load_catalog()
        catalog['functions'][0]['aliases'].append('nullsub_62')
        data = dict(prototype='void Leaf()', pseudocode='void Leaf() { JUMPOUT(0x140001001); }')
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE functions SET prototype=?,pseudocode=?,size=10',
                       (data['prototype'], data['pseudocode']))
            db.commit()
        index = self.sources.cpp_index()
        index.flow.directory.mkdir(parents=True, exist_ok=True)
        record = dict(image_sha256=index.image, rva=0x1000, source_hash=source_hash(data),
                      pseudocode='void Leaf() { nullsub_62(); }', status='recovered')
        path = index.flow.directory / 'counter-result.jsonl'
        path.write_text(json.dumps(record) + '\n', encoding='utf8')
        source = self.sources.get_source(self.identity, 'cpp')
        self.assertIn('func_unresolved_nullsub_62();', source['content'])
        record['reference_names'] = {'nullsub_62': dict(rva=0x1010, kind='function')}
        with path.open('a', encoding='utf8') as stream:
            stream.write(json.dumps(record) + '\n')
        source = self.sources.get_source(self.identity, 'cpp')
        self.assertIn('func_140001010();', source['content'])
        self.assertNotIn('func_unresolved_', source['content'])

    def tearDown(self):
        if self.sources._cpp_index:
            self.sources._cpp_index.close()
        self.temp.cleanup()

    def test_real_object_and_native_leaf_bytes(self):
        source = self.sources.get_source(self.identity, 'c')
        self.assertEqual(source['language'], 'cpp')
        self.assertIn(source['recovery']['status'], ('byte-equivalent-leaf', 'instruction-equivalent-leaf'))
        self.assertTrue(source['compilable'])
        checked = compile_check(self.root, source['content'], source['symbol'])
        self.assertTrue(checked['compiled'])
        self.assertIn(checked['code_hex'], ('33c0c3', '31c0c3'))

    def test_deferred_native_function_is_visible_with_its_recovery_reason(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE functions SET prototype=NULL,pseudocode=NULL,size=1048577')
            db.execute('CREATE TABLE replay_function_export_queue(function_rva INTEGER PRIMARY KEY,reason TEXT,status TEXT,body_sha256 TEXT)')
            db.execute('INSERT INTO replay_function_export_queue VALUES(?,?,?,?)',
                       (0x1000, 'Oversized native body needs isolated recovery', 'queued_for_isolated_recovery', 'b' * 64))
            db.commit()
        source = self.sources.get_source(self.identity, 'cpp')
        self.assertFalse(source['compilable'])
        self.assertIn('Oversized native body needs isolated recovery', '\n'.join(source['recovery']['diagnostics']))
        self.assertEqual(source['provenance']['export_queue']['body_sha256'], 'b' * 64)
        self.assertEqual('recovery-required', source['recovery']['status'])
        self.sources.cpp_index().refresh()
        refreshed = self.sources.get_source(self.identity, 'cpp')
        self.assertEqual(refreshed['content'], source['content'])

    def test_wal_refresh_and_user_revision_preservation(self):
        baseline = self.sources.get_source(self.identity, 'c')
        changed = baseline['content'].replace('return 0u', 'return 7u')
        saved = self.sources.save_source(self.identity, changed, baseline['revision'], 'c')
        self.assertEqual(saved['language'], 'cpp')
        self.assertTrue((self.root / 'src' / f'workstation_{self.identity}.cpp').is_file())
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE functions SET name='RenamedLeaf'")
            db.commit()
        self.sources.cpp_index().refresh()
        self.assertEqual(self.sources.get_source(self.identity, 'c')['content'], changed)
        unit = self.sources.build_source_units(self.sources._catalog)['units'][0]
        self.assertEqual(unit['symbol'], 'Leaf')
        self.assertEqual(unit['function_id'], self.identity)
        self.assertTrue(unit['source'].endswith('.cpp'))
        # Exercise the production compiler command and dependency discovery.
        import build
        record = build.compile_one(self.root / unit['source'], self.root / 'edited.obj', cpp=True)
        self.assertIn('-std=c++20', record['command'])
        self.assertIn('-fno-exceptions', record['command'])

    def test_failed_compilation_never_installs_source(self):
        baseline = self.sources.get_source(self.identity, 'c')
        with self.assertRaisesRegex(ValueError, 'did not compile'):
            self.sources.save_source(self.identity, f'int {baseline["symbol"]}() {{ unknown_variable; }}', baseline['revision'], 'c')
        self.assertFalse(self.sources.units_path.exists())
        self.assertFalse((self.root / 'src').exists())

    def test_new_sqlite_function_is_indexed_and_incomplete_body_is_blocked(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO functions VALUES (?,?,?,?,?,?)',
                       ('0x140001010', 'NewFunction', '__int64 NewFunction()', '{ return missing_call(); }', '{ vXXX; }', 10))
            db.commit()
        self.sources.cpp_index().refresh()
        new_id = source_catalog.stable_id(self.sources._catalog['image_sha256'], 0x1010)
        result = self.sources.get_source(new_id, 'c')
        self.assertIn('missing_call()', result['content'])
        self.assertNotIn('vXXX', result['content'])
        self.assertNotIn('#error', result['content'])
        self.assertEqual(result['recovery']['status'], 'recovery-required')
        self.assertTrue(result['recovery']['diagnostics'])
        self.assertFalse(result['compilable'])
        self.assertEqual(self.sources.cpp_index().status()['indexed'], 2)

    def test_native_flow_updates_generated_cpp_but_stale_recovery_is_rejected(self):
        from recovered_cpp_flow import source_hash
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE functions SET prototype='void Leaf()',pseudocode='{ JUMPOUT(0x140001001); }',size=10")
            db.commit()
        index = self.sources.cpp_index()
        original = self.sources.get_source(self.identity, 'cpp')
        index.flow.directory.mkdir(parents=True, exist_ok=True)
        data = {'prototype': 'void Leaf()', 'pseudocode': '{ JUMPOUT(0x140001001); }'}
        record = dict(image_sha256=index.image,rva=0x1000,source_hash=source_hash(data),
                      pseudocode='void Leaf()\n{ if (vXXX) return; }',status='recovered')
        (index.flow.directory / 'batch-result.jsonl').write_text(json.dumps(record)+'\n', encoding='utf-8')
        recovered = self.sources.get_source(self.identity, 'cpp')
        self.assertNotEqual(original['revision'], recovered['revision'])
        self.assertNotIn('JUMPOUT', recovered['content'])
        self.assertIn('if (vXXX)', recovered['content'])
        self.assertFalse(recovered['compilable'])  # CFG recovery does not prove types/ABI.
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE functions SET prototype='int Leaf()'")
            db.commit()
        stale = self.sources.get_source(self.identity, 'cpp')
        self.assertIn('JUMPOUT', stale['content'])

    def test_unresolved_jump_is_never_claimed_compilable(self):
        code, status, diagnostics, eligible = render_cpp('fn_123', 'Bad', 'void Bad()', '{ JUMPOUT(0x123); }')
        self.assertFalse(eligible)
        self.assertEqual(status, 'recovery-required')
        self.assertNotIn('#error', code)
        self.assertTrue(any('unresolved jump' in reason for reason in diagnostics))

    def test_recovery_status_does_not_create_a_cpp_error(self):
        code, status, diagnostics, eligible = render_cpp('fn_123', 'Renderable',
            'int Renderable(void)', '{ return 2; }', symbol='Renderable')
        self.assertEqual(status, 'recovery-required')
        self.assertFalse(eligible)
        self.assertTrue(diagnostics)
        checked = compile_check(self.root, code, 'Renderable')
        self.assertTrue(checked['compiled'], checked['diagnostics'])

    def test_complete_recovered_definition_has_one_signature(self):
        code, status, diagnostics, eligible = render_cpp('fn_123', 'Find', '__int64 __fastcall Find(int a1)',
            '__int64 __fastcall Find(int a1)\n{\n int vXXX = a1;\n return vXXX;\n}')
        self.assertEqual(code.count('__int64 __fastcall fn_123(int a1)'), 1)
        self.assertIn('int vXXX = a1', code)
        self.assertFalse(eligible)
        self.assertNotIn('#error', code)
        self.assertEqual(status, 'recovery-required')
        changed, _, errors, _ = render_cpp('fn_123', 'Find', '__int64 __fastcall Find(void)',
            '__int64 __fastcall Find(int a1)\n{ return a1; }')
        self.assertNotIn('fn_123(void)', changed)
        self.assertTrue(any('disagree' in reason for reason in errors))

    def test_identifierless_ida_type_does_not_become_function_named_fastcall(self):
        code, _, errors, _ = render_cpp('fn_123', 'Find', 'void __fastcall(int a1)',
                                     'void __fastcall Find(int a1) { if (a1) return; }', symbol='Find')
        self.assertEqual(code.count('void __fastcall Find(int a1)'), 1)
        self.assertFalse(any('disagree' in error for error in errors))

    def test_toolchain_change_invalidates_unchanged_database_cache(self):
        index = self.sources.cpp_index()
        index.refresh()
        original = index.get(self.sources._by_identity(self.identity))['recovery']['input_hash']
        with patch('workstation_cpp_sources.compiler_identity', return_value={'path': 'fixture', 'sha256': 'new'}):
            with patch('workstation_cpp_sources.compile_check', return_value={'compiled': False, 'diagnostics': 'changed compiler fixture'}):
                index.refresh()
                source = index.get(self.sources._by_identity(self.identity))
        self.assertNotEqual(original, source['recovery']['input_hash'])
        self.assertFalse(source['compilable'])
        self.assertNotIn('#error', source['content'])
        self.assertEqual(source['recovery']['status'], 'recovery-required')
        self.assertIn('changed compiler fixture', source['recovery']['diagnostics'])

    def test_new_cpp_function_survives_cache_recreation(self):
        saved = self.sources.create_source('Com_CustomCpp', 'cpp', 'int Com_CustomCpp() { return 2; }\n')
        self.assertEqual(saved['language'], 'cpp')
        with self.assertRaisesRegex(ValueError, 'did not compile'):
            self.sources.save_source(saved['id'], 'int Com_CustomCpp() { return missing; }', saved['revision'], 'cpp')
        self.assertEqual(self.sources.get_source(saved['id'], 'cpp')['content'], saved['content'])
        self.sources.manifest_path.unlink()
        reopened = SourceWorkspace(self.root, self.root / 'other-cache', self.database).get_source(saved['id'], 'c')
        self.assertEqual(reopened['language'], 'cpp')
        self.assertEqual(reopened['content'], saved['content'])

    def test_friendly_names_and_ambiguous_aliases(self):
        named = self.sources.get_source(self.identity, 'cpp')
        self.assertEqual(named['symbol'], 'Leaf')
        self.assertIn('extern "C" __int64 Leaf()', named['content'])
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO functions VALUES (?,?,?,?,?,?)',
                ('0x140001010', 'Leaf', 'int Leaf(void)', '{ return unknown(); }', '', 10))
            db.commit()
        ambiguous = self.sources.get_source(self.identity, 'cpp')
        self.assertEqual(ambiguous['symbol'], 'func_140001000')
        self.assertIn('__int64 func_140001000()', ambiguous['content'])

    def test_cpp_name_mangling_is_resolved_and_overloads_rejected(self):
        checked = compile_check(self.root, 'int Com_CustomCpp(int n) { return n + 1; }', 'Com_CustomCpp')
        self.assertTrue(checked['compiled'], checked['diagnostics'])
        self.assertNotEqual(checked['coff_symbol'], 'Com_CustomCpp')
        ambiguous = compile_check(self.root,
            'int Com_CustomCpp(int n) { return n; }\nint Com_CustomCpp(float n) { return (int)n; }', 'Com_CustomCpp')
        self.assertFalse(ambiguous['compiled'])
        self.assertIn('overloaded', ambiguous['diagnostics'])

    def test_existing_stable_definition_keeps_its_compiled_binding(self):
        baseline = self.sources.get_source(self.identity, 'cpp')
        old_style = baseline['content'].replace('Leaf()', self.identity + '()')
        saved = self.sources.save_source(self.identity, old_style, baseline['revision'], 'cpp')
        self.assertEqual(saved['symbol'], self.identity)
        unit = self.sources.build_source_units(self.sources._catalog)['units'][0]
        self.assertEqual(unit['symbol'], self.identity)

    def test_cached_open_does_not_wait_for_background_compiler(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO functions VALUES (?,?,?,?,?,?)',
                ('0x140001010', 'Other', 'int Other(void)', '{ return unknown(); }', '', 10))
            db.commit()
        index = self.sources.cpp_index()
        other = self.sources._by_identity(source_catalog.stable_id(index.image, 0x1010))
        index.get(self.sources._by_identity(self.identity))
        index.get(other)
        index.leaf_checks.clear()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE functions SET name='Changed' WHERE name='Leaf'")
            db.commit()
        compiling, release, opened = threading.Event(), threading.Event(), threading.Event()
        def slow_compile(*args, **kwargs):
            compiling.set()
            release.wait(5)
            return {'compiled': False, 'diagnostics': 'background fixture'}
        worker = threading.Thread(target=index.refresh)
        reader = threading.Thread(target=lambda: (index.get(other), opened.set()))
        with patch('workstation_cpp_sources.compile_check', side_effect=slow_compile):
            try:
                worker.start()
                self.assertTrue(compiling.wait(2))
                reader.start()
                self.assertTrue(opened.wait(1), 'A cached open waited for an unrelated background compilation')
            finally:
                release.set()
                worker.join(5)
                if reader.ident:
                    reader.join(5)


if __name__ == '__main__':
    unittest.main()
