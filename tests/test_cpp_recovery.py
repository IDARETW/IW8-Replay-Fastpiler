import hashlib
import json
import os
import sqlite3
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tools'), str(ROOT/'tests')]
import cpp_recovery
import test_workstation_sources as fixtures
from workstation_cpp_sources import compile_check
from workstation.build_lock import compiler_lock


class ExternalEditTests(unittest.TestCase):
    def setUp(self):
        fixtures.SourceWorkspaceTests.setUp(self)
        self.identity = 'fn_0123456789abcdef'
        self.source = self.root/'src/External.cpp'
        self.source.parent.mkdir()
        self.original = 'extern "C" int External() { return 3; }\n'
        self.source.write_text(self.original, newline='\n')
        (self.root/'source-units.json').write_text(json.dumps({'schema':1,'units':[
            {'function_id':self.identity,'source':'src/External.cpp','symbol':'External'}]}))

    def tearDown(self):
        fixtures.SourceWorkspaceTests.tearDown(self)

    def checkout(self):
        return Path(self.workspace.checkout_external(self.identity)['ticket'])

    def test_native_windows_external_edit_registers_and_preserves_original(self):
        ticket = self.checkout()
        edited = 'extern "C" int External() { return 7; }\n'
        self.source.write_text(edited, newline='\n')
        result = self.workspace.reconcile_external(ticket)
        self.assertTrue(result['compiled'])
        self.assertEqual(result['revision'],hashlib.sha256(edited.encode()).hexdigest())
        history=self.cache/'history'/self.identity/'cpp'/(hashlib.sha256(self.original.encode()).hexdigest()+'.txt')
        self.assertEqual(history.read_text(),self.original)
        self.assertEqual(self.source.read_text(),edited)
        with self.assertRaisesRegex(ValueError,'consumed'):
            self.workspace.reconcile_external(ticket)

    def test_failed_compile_preserves_metadata_and_edit(self):
        ticket = self.checkout()
        before=ticket.read_bytes()
        self.source.write_text('broken C++')
        with self.assertRaisesRegex(ValueError,'did not compile'):
            self.workspace.reconcile_external(ticket)
        self.assertEqual(ticket.read_bytes(),before)
        self.assertEqual(self.source.read_text(),'broken C++')

    def test_concurrent_metadata_change_rejects_without_overwriting_either_version(self):
        ticket=self.checkout()
        self.source.write_text('extern "C" int External() { return 9; }\n')
        (self.root/'source-units.json').write_text('{"units":[]}')
        with self.assertRaisesRegex(ValueError,'Revision conflict'):
            self.workspace.reconcile_external(ticket)
        self.assertEqual(json.loads(ticket.read_text())['base_content'],self.original)
        self.assertIn('return 9',self.source.read_text())

    def test_active_build_prevents_reconciliation(self):
        ticket=self.checkout()
        with compiler_lock(self.root/'.workstation-compiler.lock'):
            with self.assertRaisesRegex(ValueError,'Another compiler'):
                self.workspace.reconcile_external(ticket)

    def test_tampered_source_path_is_rejected(self):
        ticket=self.checkout(); data=json.loads(ticket.read_text())
        data['source']='../outside.cpp'; ticket.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'escapes'):
            self.workspace.reconcile_external(ticket)

    def test_header_in_parent_directory_is_compiled_and_hashed(self):
        folder=self.root/'src/nested';folder.mkdir()
        header=folder/'Value.h';header.write_text('constexpr int value = 5;\n')
        source=folder/'Check.cpp';source.write_text('#include "Value.h"\nextern "C" int Check(){ return value; }\n')
        result=compile_check(self.root,source.read_text(),'Check',source_path=source)
        self.assertTrue(result['compiled'],result['diagnostics'])
        self.assertIn(str(header),[d['path'] for d in result['dependencies']])

    def test_registered_units_advance_with_cached_revisions(self):
        digest=hashlib.sha256(self.original.encode()).hexdigest()
        self.workspace._write_cpp_unit(self.identity,'External',Path('src/External.cpp'),digest,'cpp')
        state=self.workspace._state()
        self.workspace.manifest_path.parent.mkdir(parents=True,exist_ok=True)
        self.workspace.manifest_path.write_text(json.dumps(state))
        ticket=self.checkout()
        edited='extern "C" int External() { return 11; }\n'
        self.source.write_text(edited, newline='\n')
        result=self.workspace.reconcile_external(ticket)
        self.assertEqual(json.loads(self.workspace.units_path.read_text())['units'][0]['sha256'],result['revision'])
        self.assertEqual(self.workspace.get_source(self.identity,'cpp')['content'],edited)

    def test_edit_during_compilation_is_rejected(self):
        ticket=self.checkout()
        def compile_and_edit(*args,**kwargs):
            self.source.write_text('second edit')
            return {'compiled':True}
        with patch('workstation_cpp_sources.compile_check',side_effect=compile_and_edit):
            with self.assertRaisesRegex(ValueError,'changed during'):
                self.workspace.reconcile_external(ticket)
        self.assertFalse(json.loads(ticket.read_text())['consumed'])

    def test_crlf_external_revision_remains_readable_by_managed_editor(self):
        digest=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.workspace._write_cpp_unit(self.identity,'External',Path('src/External.cpp'),digest,'cpp')
        ticket=self.checkout()
        content='extern "C" int External() { return 12; }\r\n'
        self.source.write_bytes(content.encode())
        result=self.workspace.reconcile_external(ticket)
        self.assertEqual(result['revision'],hashlib.sha256(content.encode()).hexdigest())
        self.assertEqual(self.workspace.get_source(self.identity,'cpp')['content'],content)

    def test_metadata_publication_failure_restores_all_previous_metadata(self):
        import workstation_sources
        digest=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.workspace._write_cpp_unit(self.identity,'External',Path('src/External.cpp'),digest,'cpp')
        ticket=self.checkout()
        before=self.workspace.units_path.read_bytes()
        self.source.write_text('extern "C" int External() { return 14; }',newline='\n')
        original=workstation_sources._atomic_json
        def fail_ticket(path,data):
            if Path(path)==ticket:
                raise OSError('publication failed')
            return original(path,data)
        with patch.object(workstation_sources,'_atomic_json',side_effect=fail_ticket):
            with self.assertRaisesRegex(OSError,'publication failed'):
                self.workspace.reconcile_external(ticket)
        self.assertEqual(self.workspace.units_path.read_bytes(),before)
        self.assertIn('return 14',self.source.read_text())
        self.assertFalse(json.loads(ticket.read_text())['consumed'])

    def test_validation_cannot_run_on_linux(self):
        with patch.object(cpp_recovery.os,'name','posix'):
            with self.assertRaisesRegex(ValueError,'Windows'):
                cpp_recovery.windows_compiler()

    def test_backend_timeout_is_reported_as_failure(self):
        import subprocess
        with patch.object(cpp_recovery.subprocess,'run',side_effect=subprocess.TimeoutExpired(['tool'],1)):
            result=cpp_recovery.run(['tool'],self.root,1)
        self.assertIsNone(result['returncode'])
        self.assertTrue(result['timeout'])

    def test_primary_key_recovery_avoids_full_database_scans(self):
        from workstation_cpp_sources import CppSourceIndex
        index=object.__new__(CppSourceIndex)
        index.manifest={'image_base':0x140000000};index.addresses=None
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE functions(id INTEGER PRIMARY KEY,address TEXT,name TEXT,prototype TEXT,pseudocode TEXT)')
            db.execute("INSERT INTO functions VALUES(7,'0x140001000','Correct','int Correct()','{return 4;}')")
            statements=[];db.set_trace_callback(statements.append)
            result=index._read(db,{'rva':0x1000,'database_id':7},set())
        self.assertEqual(result['name'],'Correct')
        self.assertFalse(any(s=='SELECT address FROM functions' for s in statements))

    def test_stale_database_primary_key_cannot_borrow_another_function(self):
        from workstation_cpp_sources import CppSourceIndex
        index=object.__new__(CppSourceIndex)
        index.manifest={'image_base':0x140000000};index.addresses=None
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE functions(id INTEGER PRIMARY KEY,address TEXT,name TEXT,prototype TEXT,pseudocode TEXT)')
            db.executemany('INSERT INTO functions VALUES(?,?,?,?,?)',[
                (7,'0x140002000','Wrong','int Wrong()','{return 8;}'),
                (9,'0x140001000','Correct','int Correct()','{return 4;}')])
            result=index._read(db,{'rva':0x1000,'database_id':7},set())
        self.assertEqual(result['name'],'Correct')

    def test_promotion_rejects_stale_behavior_evidence(self):
        evidence={'image_sha256':'a'*64,'function_id':self.identity,'source_sha256':'b'*64,
                  'abi_review':True,'differential':{'passed':True,'cases':1}}
        with self.assertRaisesRegex(ValueError,'passing differential'):
            cpp_recovery.require_promotion_evidence(self.root,{'id':self.identity},'a'*64,self.source,evidence)

    def test_promotion_rejects_compiler_change(self):
        evidence={'image_sha256':'a'*64,'function_id':self.identity,'source_sha256':cpp_recovery.sha(self.source),
                  'abi_review':True,'differential':{'passed':True,'cases':1},'compiler':{'sha256':'b'*64}}
        with self.assertRaisesRegex(ValueError,'another compiler'):
            cpp_recovery.require_promotion_evidence(self.root,{'id':self.identity},'a'*64,self.source,evidence)


if __name__=='__main__':
    unittest.main()
