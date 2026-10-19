from contextlib import closing
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from recovered_cpp_flow import FlowRecovery, source_hash
from recovered_cpp_names import CppNames, automatic_aliases, count_jumpouts
import source_catalog
from prepare_cpp_flow_recovery import recovery_reason, pending_recovery
from run_cpp_flow_recovery import read_progress, interrupted_record, preserve_unpacked_snapshot


class RecoveryTests(unittest.TestCase):
    def test_new_baseline_rejects_old_recovery_even_for_identical_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flow = FlowRecovery(root, 'image')
            flow.directory.mkdir(parents=True)
            data = dict(prototype='void f()', pseudocode='JUMPOUT(1);')
            old = dict(image_sha256='image', rva=1, source_hash=source_hash(data),
                       status='recovered', pseudocode='void f() {}', baseline_idb_sha256='old',
                       type_hints=[dict(rva=1, prototype='void f();')])
            path = flow.directory / 'batch-result.jsonl'
            path.write_text(json.dumps(old) + '\n', encoding='utf-8')
            flow.sync()
            self.assertIsNotNone(flow.get(1, data))
            (root / 'replay-project.local.json').write_text(json.dumps(
                dict(cpp_recovery=dict(baseline_idb_sha256='fresh'))), encoding='utf-8')
            flow = FlowRecovery(root, 'image')
            flow.sync()
            self.assertIsNone(flow.get(1, data))
            fresh = dict(old, baseline_idb_sha256='fresh', reference_names={}, type_hints=[])
            with path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(fresh) + '\n' + json.dumps(old) + '\n')
            flow.sync()
            self.assertEqual(flow.get(1, data)['baseline_idb_sha256'], 'fresh')

    def test_interrupted_native_recovery_keeps_partial_progress_and_closed_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = dict(rva=1, name='f', source_hash='body', recovery_reason='missing-body')
            request = dict(image_sha256='image', decoder_sha256='native', requests=[owner])
            path = root / 'progress.jsonl'
            event = dict(rva=1, source_hash='body', phase='decompile_start')
            path.write_text(json.dumps(event), encoding='utf-8')
            offset, progress = read_progress(path, 0, {1: owner})
            self.assertEqual((offset, progress), (0, None))
            with path.open('a', encoding='utf-8') as stream:
                stream.write('\n')
            offset, progress = read_progress(path, offset, {1: owner})
            failure = interrupted_record(request, progress, 'timeout')
            self.assertEqual((failure['status'], failure['source_hash'], failure['decoder_sha256']),
                             ('error', 'body', 'native'))
            self.assertIsNone(interrupted_record(request, dict(event, phase='record_complete'), 'exit'))
            self.assertIsNone(interrupted_record(request, dict(event, phase='repair_complete'), 'exit'))
            with self.assertRaisesRegex(ValueError, 'pinned native request'):
                read_progress(path, 0, {})
            copy = root / 'private.i64'
            copy.write_bytes(b'closed baseline')
            copy.with_suffix('.id0').write_bytes(b'unpacked evidence')
            evidence = preserve_unpacked_snapshot(copy, root, 123)
            self.assertEqual(copy.read_bytes(), b'closed baseline')
            self.assertFalse(copy.with_suffix('.id0').exists())
            self.assertEqual((Path(evidence) / 'private.id0').read_bytes(), b'unpacked evidence')

    def test_pending_recovery_includes_missing_bodies_and_unscoped_legacy_output(self):
        self.assertEqual(recovery_reason('  '), 'missing-body')
        self.assertEqual(recovery_reason('void f() { JUMPOUT(1); }'), 'native-continuation')
        self.assertIsNone(recovery_reason('void f() { /* JUMPOUT(1); */ }'))
        legacy = dict(status='recovered', decoder_sha256='native', pseudocode='void f() {}')
        self.assertEqual(recovery_reason('void f() {}', legacy), 'reference-provenance')
        self.assertTrue(pending_recovery(legacy, 'native'))
        self.assertFalse(pending_recovery(dict(legacy, reference_names={}), 'native'))
        failed = dict(status='error', decoder_sha256='native')
        self.assertFalse(pending_recovery(failed, 'native'))
        self.assertTrue(pending_recovery(failed, 'improved-native'))
        self.assertTrue(pending_recovery(failed, 'native', 'new-baseline'))
        self.assertFalse(pending_recovery(dict(failed, recovery_generation='new-baseline'),
                                          'native', 'new-baseline'))
        residual = dict(legacy, pseudocode='void f() { JUMPOUT(2); }', reference_names={})
        self.assertFalse(pending_recovery(residual, 'native'))
        self.assertTrue(pending_recovery(residual, 'improved-native'))

    def test_only_jumpout_calls_require_native_continuation_recovery(self):
        self.assertEqual(count_jumpouts('// JUMPOUT(1)\n"JUMPOUT(2)"; /* JUMPOUT(3) */'), 0)
        self.assertEqual(count_jumpouts('JUMPOUT /* target */ (4); JUMPOUT(5);'), 2)
        self.assertEqual(count_jumpouts('NotJUMPOUT(1); JUMPOUT_count = 2;'), 0)

    def test_cpp_literals_and_continued_comments_are_not_symbol_references(self):
        names = CppNames([], {}, 0x140000000)
        source = ('u8R"diag(sub_140001000(); "quoted" JUMPOUT(1);)diag";\n'
                  'LR"(dword_140002000; JUMPOUT(2);)";\n'
                  'L"sub_140003000"; u\'x\';\n'
                  '// continued comment \\\nJUMPOUT(3); sub_140004000();\n'
                  'sub_140005000(); JUMPOUT(4);')
        expected = source.replace('sub_140005000();', 'func_140005000();')
        self.assertEqual(names.rewrite(source), expected)
        self.assertEqual(count_jumpouts(source), 1)

    def test_fresh_counter_ownership_precedes_legacy_aliases(self):
        rows = [dict(id='fn_old', rva=0x1000, name='OldOwner', aliases=['nullsub_62'],
                     decompiler_name='nullsub_1'),
                dict(id='fn_new', rva=0x2000, name='NewOwner', aliases=[],
                     decompiler_name='nullsub_62')]
        names = CppNames(rows, {'fn_old': 'OldOwner', 'fn_new': 'NewOwner'}, 0x140000000)
        self.assertEqual(names.rewrite('nullsub_62();', use_export_names=True), 'NewOwner();')
        self.assertEqual(names.rewrite('nullsub_62();'), 'OldOwner();')
        self.assertEqual(names.rewrite('nullsub_900();', use_export_names=True),
                         'func_unresolved_nullsub_900();')
        self.assertEqual(names.rewrite('nullsub_62();', reference_names={
            'nullsub_62': dict(rva=0x1000, kind='function')}), 'OldOwner();')

    def test_counter_nullsubs_and_thunks_use_their_catalog_address(self):
        rows = [dict(id='fn_first', rva=0x1000, name='nullsub_62', aliases=[]),
                dict(id='fn_thunk', rva=0x2000, name='j_nullsub_62', aliases=[])]
        names = CppNames(rows, {'fn_first': 'nullsub_62', 'fn_thunk': 'j_nullsub_62'}, 0x140000000)
        self.assertEqual(names.rewrite('nullsub_62(); j_nullsub_62();'),
                         'func_140001000(); func_140002000();')
        self.assertTrue(source_catalog._is_opaque_name('nullsub_62'))
        self.assertTrue(source_catalog._is_opaque_name('j_nullsub_62'))
        self.assertEqual(names.rewrite('j_sub_140003000_0();'), 'func_140003000_0();')

    def test_reference_names_preserve_known_functions_and_literals(self):
        rows = [dict(id='fn_aa', rva=0x1000, name='Live_Check', aliases=['sub_140001000']),
                dict(id='fn_bb', rva=0x2000, name='sub_140002000', aliases=[]),
                dict(id='sym_cc', rva=0x3000, kind='data-global', name='dword_140003000', aliases=[])]
        names = CppNames(rows, {'fn_aa': 'Live_Check', 'fn_bb': 'func_140002000'}, 0x140000000)
        self.assertEqual(names.rewrite('sub_140001000(); fn_bb(); dword_140003000++; sub_140004000();'),
                         'Live_Check(); func_140002000(); gl_140003000++; func_140004000();')
        self.assertEqual(names.rewrite('// sub_140002000\n"sub_140002000"; /* dword_140003000 */'),
                         '// sub_140002000\n"sub_140002000"; /* dword_140003000 */')
        raw_names = CppNames(rows, {'fn_aa': 'Live_Check', 'fn_bb': 'sub_140002000'}, 0x140000000)
        self.assertEqual(raw_names.rewrite('sub_140002000();'), 'func_140002000();')

    def test_automatic_aliases_have_separate_function_and_data_identities(self):
        catalog = dict(image_base=0x140000000,
                       functions=[dict(id='fn_a', rva=0x1000, name='sub_140001000', aliases=[])],
                       symbols=[dict(id='sym_b', rva=0x2000, kind='data-global', name='dword_140002000', aliases=[])])
        self.assertEqual(automatic_aliases(catalog), {'func_140001000': 0x1000, 'gl_140002000': 0x2000})
        targets = source_catalog.unique_alias_targets(catalog)
        self.assertEqual(targets['func_140001000'], 0x1000)
        self.assertEqual(targets['gl_140002000'], 0x2000)
        catalog['functions'][0]['aliases'].append('gl_140002000')
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            source_catalog.unique_alias_targets(catalog)

    def test_recovery_is_pinned_to_source_and_image_and_waits_for_complete_row(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flow = FlowRecovery(root, 'image')
            flow.directory.mkdir(parents=True)
            data = {'prototype': 'void Bad()', 'pseudocode': '{ JUMPOUT(0x123); }'}
            record = dict(image_sha256='image', rva=0x1000, source_hash=source_hash(data),
                          pseudocode='void Bad() { return; }', status='recovered')
            output = flow.directory / 'batch-result.jsonl'
            output.write_text(json.dumps(record), encoding='utf-8')
            flow.sync()
            self.assertIsNone(flow.get(0x1000, data))
            with output.open('a', encoding='utf-8') as stream:
                stream.write('\n')
            flow.sync()
            self.assertEqual(flow.get(0x1000, data)['pseudocode'], record['pseudocode'])
            self.assertIsNone(flow.get(0x1000, dict(data, prototype='int Bad()')))
            other_image = FlowRecovery(root, 'other')
            other_image.sync()
            self.assertIsNone(other_image.get(0x1000, data))
            # A new process reloads durable recovery even after no JSONL changes.
            fresh = FlowRecovery(root, 'image')
            fresh.sync()
            self.assertIsNotNone(fresh.get(0x1000, data))

    def test_residual_jump_or_failed_recovery_is_never_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            flow = FlowRecovery(directory, 'image')
            data = {'prototype': None, 'pseudocode': 'JUMPOUT(1);'}
            record = dict(status='recovered', pseudocode='JUMPOUT(2);')
            flow.rows[(1, source_hash(data))] = record
            self.assertIsNone(flow.get(1, data))
            record.update(status='error', pseudocode='void f() {}')
            self.assertIsNone(flow.get(1, data))
            record.update(status='recovered', pseudocode='  ')
            self.assertIsNone(flow.get(1, data))

    def test_bulk_and_failed_retries_preserve_complete_typed_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            flow = FlowRecovery(directory, 'image')
            flow.directory.mkdir(parents=True)
            data = {'prototype': None, 'pseudocode': 'JUMPOUT(1);'}
            record = dict(image_sha256='image', rva=1, source_hash=source_hash(data),
                          status='recovered', pseudocode='void f(int controller) {}',
                          reference_names={'nullsub_62': dict(rva=2, kind='function')},
                          type_hints=[{'rva': 1, 'prototype': 'void f(int);'}])
            path = flow.directory / 'batch-result.jsonl'
            path.write_text(json.dumps(record) + '\n', encoding='utf-8')
            flow.sync()
            for retry in (dict(record, status='error', pseudocode='', type_hints=[]),
                          dict(record, pseudocode='char f() {}', type_hints=[])):
                with path.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(retry) + '\n')
                flow.sync()
                self.assertEqual(flow.get(1, data)['pseudocode'], record['pseudocode'])
            legacy = dict(record)
            legacy.pop('reference_names')
            with path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(legacy) + '\n')
            flow.sync()
            self.assertEqual(flow.get(1, data)['reference_names'], record['reference_names'])


if __name__ == '__main__':
    unittest.main()
