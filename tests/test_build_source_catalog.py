import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import source_catalog


class FreshCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / 'analysis.sqlite'
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('CREATE TABLE program (processor TEXT, md5sum BLOB)')
            db.execute('INSERT INTO program VALUES (?, ?)', ('pc64', bytes.fromhex('11' * 16)))
            db.execute('CREATE TABLE functions (id INTEGER, name TEXT, address TEXT, mangled_function TEXT, rva TEXT)')
            db.execute('INSERT INTO functions VALUES (1, ?, ?, ?, ?)',
                       ('CurrentDescriptiveName', str(0x140001000), '?CurrentDescriptiveName@@YAXXZ', '0x1000'))
            db.commit()

    def tearDown(self):
        self.temp.cleanup()

    def test_current_sqlite_name_and_mangled_alias_join_stable_identity(self):
        fresh, ids, _ = source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)
        self.assertEqual(ids, {1: 0x1000})
        row = fresh[0]
        self.assertEqual(row['id'], source_catalog.stable_id('a' * 64, 0x1000))
        self.assertEqual(row['sqlite_name'], 'CurrentDescriptiveName')
        self.assertEqual(set(row['aliases']), {'CurrentDescriptiveName', '?CurrentDescriptiveName@@YAXXZ'})

    def test_decompiler_token_provenance_is_separate_and_image_scoped(self):
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('CREATE TABLE replay_ida_export_function_names('
                       'function_rva INTEGER PRIMARY KEY,name TEXT,input_md5 TEXT,image_sha256 TEXT,'
                       'idb_sha256 TEXT,idb_path TEXT)')
            db.execute('INSERT INTO replay_ida_export_function_names VALUES(?,?,?,?,?,?)',
                       (0x1000, 'nullsub_62', '11' * 16, 'a' * 64, 'b' * 64, 'fresh.i64'))
            db.commit()
        rows, _, snapshot = source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)
        self.assertEqual(rows[0]['name'], 'CurrentDescriptiveName')
        self.assertEqual(rows[0]['decompiler_name'], 'nullsub_62')
        self.assertEqual(snapshot[0]['decompiler_idb_sha256'], 'b' * 64)
        self.assertNotIn('nullsub_62', rows[0]['aliases'])
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('UPDATE replay_ida_export_function_names SET image_sha256=?', ('c' * 64,))
            db.commit()
        with self.assertRaisesRegex(ValueError, 'another executable'):
            source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)

    def test_quarantine_preserves_identity_without_creating_callable_aliases(self):
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('CREATE TABLE replay_function_quarantine(function_id INTEGER PRIMARY KEY,address TEXT,reason TEXT,evidence_json TEXT)')
            db.execute('INSERT INTO replay_function_quarantine VALUES(1,?,?,?)',
                       (str(0x140001000), 'native interior label', '{}'))
            db.commit()
        rows, identities, snapshot = source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)
        self.assertEqual(identities, {1: 0x1000})
        self.assertTrue(rows[0]['quarantined'])
        self.assertTrue(snapshot[0]['quarantined'])
        self.assertEqual(source_catalog.unique_alias_targets(dict(image_base=0x140000000, functions=rows)), {})
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('UPDATE replay_function_quarantine SET address=?', (str(0x140002000),))
            db.commit()
        with self.assertRaisesRegex(ValueError, 'Quarantine address'):
            source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)

    def test_name_refresh_preserves_old_verified_aliases_but_keeps_stable_id(self):
        fresh, _, _ = source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)
        fresh, symbols = source_catalog.merge_catalog_rows({
            'functions': [{'id': fresh[0]['id'], 'database_id': 1, 'name': 'OlderVerifiedName',
                           'rva': 0x1000, 'aliases': ['OlderVerifiedName', 'sub_140001000']}],
            'symbols': []}, fresh)
        self.assertEqual(fresh[0]['id'], source_catalog.stable_id('a' * 64, 0x1000))
        self.assertEqual(fresh[0]['name'], 'CurrentDescriptiveName')
        self.assertEqual(set(fresh[0]['aliases']), {
            'CurrentDescriptiveName', '?CurrentDescriptiveName@@YAXXZ', 'OlderVerifiedName', 'sub_140001000'})
        self.assertEqual(symbols, [])

    def test_database_identity_and_row_address_movement_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'MD5'):
            source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '22' * 16)
        fresh, _, _ = source_catalog._read_sqlite_catalog(self.db, 0x140000000, 'a' * 64, '11' * 16)
        moved = [dict(fresh[0], rva=0x2000, id=source_catalog.stable_id('a' * 64, 0x2000))]
        with self.assertRaisesRegex(ValueError, 'moved'):
            source_catalog.merge_catalog_rows({'functions': [fresh[0]], 'symbols': []}, moved)

    def test_logical_snapshot_hash_is_location_independent_and_content_sensitive(self):
        rows = [dict(database_id=1, name='Name', address=0x140001000,
                     mangled_function='?Name@@', rva=0x1000)]
        first, digest = source_catalog.logical_snapshot_document('a' * 64, 0x140000000,
                                                                  '11' * 16, rows)
        second, relocated_digest = source_catalog.logical_snapshot_document('a' * 64, 0x140000000,
                                                                             '11' * 16, rows)
        changed, changed_digest = source_catalog.logical_snapshot_document(
            'a' * 64, 0x140000000, '11' * 16, [dict(rows[0], name='Changed')])
        self.assertEqual(first['snapshot_kind'], 'sqlite-logical-catalog-v1')
        self.assertEqual(digest, relocated_digest)
        self.assertNotEqual(digest, changed_digest)
        self.assertEqual(changed['functions'][0]['name'], 'Changed')

    def test_catalog_reader_keeps_one_wal_snapshot_during_progress_callbacks(self):
        database = self.root / 'wal-functions.sqlite'
        with closing(sqlite3.connect(database)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE program (processor TEXT, md5sum BLOB)')
            db.execute('INSERT INTO program VALUES (?, ?)', ('pc64', bytes.fromhex('11' * 16)))
            db.execute('CREATE TABLE functions (id INTEGER, name TEXT, address TEXT, mangled_function TEXT, rva TEXT)')
            base = 0x140000000
            db.executemany('INSERT INTO functions VALUES (?, ?, ?, ?, ?)', (
                (i, f'F{i}', str(base + i * 16), f'?F{i}@@', hex(i * 16))
                for i in range(1, 100002)))
            db.commit()

        writes = []
        def concurrent_write(count, elapsed):
            if not writes:
                with closing(sqlite3.connect(database)) as writer:
                    writer.execute('UPDATE functions SET name=? WHERE id=100001', ('ChangedDuringRead',))
                    writer.commit()
                writes.append(count)

        _, _, rows = source_catalog._read_sqlite_catalog(
            database, 0x140000000, 'a' * 64, '11' * 16, 0x200000, progress=concurrent_write)
        self.assertTrue(writes)
        self.assertEqual(rows[-1]['database_id'], 100001)
        self.assertEqual(rows[-1]['name'], 'F100001')

    def test_sqlite_backup_is_immutable_after_live_names_change(self):
        backup = self.root / 'build-input.sqlite'
        digest = source_catalog.backup_readonly_database(self.db, backup)
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('UPDATE functions SET name=? WHERE id=1', ('RenamedAfterSnapshot',))
            db.commit()
        rows, _, _ = source_catalog._read_sqlite_catalog(backup, 0x140000000, 'a' * 64, '11' * 16)
        self.assertEqual(rows[0]['name'], 'CurrentDescriptiveName')
        with backup.open('rb') as stream:
            self.assertEqual(hashlib.file_digest(stream, 'sha256').hexdigest(), digest)

    def test_opaque_stable_name_does_not_replace_a_recovered_name(self):
        fresh = [dict(id='fn_opaque', database_id=1, name='sub_140001000', rva=0x1000,
                      aliases=['sub_140001000'])]
        merged, _ = source_catalog.merge_catalog_rows({'functions': [
            dict(id='fn_opaque', database_id=1, name='RecoveredMeaning', rva=0x1000,
                 aliases=['RecoveredMeaning'])], 'symbols': []}, fresh)
        self.assertEqual(merged[0]['name'], 'RecoveredMeaning')
        self.assertIn('sub_140001000', merged[0]['aliases'])

    def test_decoder_reclassification_retains_aliases_and_history(self):
        old = dict(id='sym_a', rva=0x1000, kind='data-address', aliases=['OldAddress'])
        new = dict(old, kind='code-label', aliases=['NewLabel'])
        merged = source_catalog.merge_catalog_symbols([], [new], [old], 0x140000000)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['kind'], 'code-label')
        self.assertEqual(merged[0]['classification_history'], ['data-address', 'code-label'])
        self.assertEqual(merged[0]['aliases'], ['NewLabel', 'OldAddress'])
        with self.assertRaisesRegex(ValueError, 'Typed symbol kind changed'):
            source_catalog.merge_catalog_symbols([], [new], [dict(old, kind='data-global')], 0x140000000)

    def test_new_function_absorbs_previous_address_symbol_without_duplicate(self):
        function = dict(id='fn_a', database_id=1, rva=0x1000, name='RecoveredFunction', aliases=[])
        old = dict(id='sym_a', rva=0x1000, kind='code-label', name='OldAddress', aliases=[])
        self.assertEqual(source_catalog.merge_catalog_symbols([function], [], [old], 0x140000000), [])
        self.assertIn('OldAddress', function['aliases'])
        self.assertIn('gl_140001000', function['aliases'])
        aliases = source_catalog.unique_alias_targets(dict(image_base=0x140000000, functions=[function], symbols=[]))
        self.assertEqual(aliases['gl_140001000'], 0x1000)
        self.assertEqual(aliases['sym_a'], 0x1000)
        refreshed, _ = source_catalog.merge_catalog_rows(dict(functions=[function], symbols=[]),
            [dict(id='fn_a', database_id=1, rva=0x1000, name='RecoveredFunction', aliases=[])])
        self.assertEqual(refreshed[0]['symbol_history'], function['symbol_history'])
        self.assertEqual(len(refreshed[0]['symbol_history']), 1)

    def test_quarantined_function_does_not_absorb_address_symbol(self):
        function = dict(id='fn_a', rva=0x1000, quarantined=True, aliases=[])
        address = dict(id='sym_a', rva=0x1000, kind='code-label', aliases=[])
        self.assertEqual(source_catalog.merge_catalog_symbols([function], [], [address], 0x140000000), [address])

    def _resolve_fixture(self, units, objects, add_coff_sections=True):
        image = 'a' * 64
        catalog_path = self.root / 'resolve-catalog.json'
        rows = []
        for obj in objects:
            if add_coff_sections and 'sections' not in obj:
                obj['sections'] = [{'name': '.text', 'flags': 0x60000020 | 0x20000000,
                                    'data': bytearray(0x100)}]
            for symbol in obj.get('symbols', {}).values():
                symbol.setdefault('kind', 0x20)
        for index, unit in enumerate(units, 1):
            rva = 0x1000 * index
            rows.append({'id': source_catalog.stable_id(image, rva), 'rva': rva,
                         'aliases': []})
            unit['function_id'] = rows[-1]['id']
        catalog_path.write_text(json.dumps({'image_sha256': image,
                                            'functions': rows, 'symbols': []}))
        manifest = {'input_sha256': image}
        native = {}
        resolved = source_catalog.resolve(manifest, native, objects,
                                          catalog_path=catalog_path,
                                          document={'units': units, 'imports': []})
        return resolved, native

    def test_resolve_rejects_missing_coff_section_metadata(self):
        source = (self.root / 'src' / 'base.cpp').resolve()
        units = [{'source': str(source), 'symbol': 'Base'}]
        objects = [{'path': 'obj/base.obj', 'source_path': str(source),
                    'symbols': {'base': {'name': 'Base', 'section': 1,
                                         'storage': 2, 'kind': 0x20}}}]
        with self.assertRaisesRegex(ValueError, 'does not define an executable function'):
            self._resolve_fixture(units, objects, add_coff_sections=False)

    def test_resolve_rejects_nonexecutable_text_function(self):
        source = (self.root / 'src' / 'base.cpp').resolve()
        units = [{'source': str(source), 'symbol': 'Base'}]
        objects = [{'path': 'obj/base.obj', 'source_path': str(source),
                    'symbols': {'base': {'name': 'Base', 'section': 1,
                                         'storage': 2, 'kind': 0x20}},
                    'sections': [{'name': '.text', 'flags': 0x40000020,
                                  'data': bytearray(0x100)}]}]
        with self.assertRaisesRegex(ValueError, 'does not define an executable function'):
            self._resolve_fixture(units, objects)

    def test_resolve_uses_exact_source_path_for_same_basename_hashed_objects(self):
        alpha = (self.root / 'src' / 'alpha' / 'same.cpp').resolve()
        beta = (self.root / 'src' / 'beta' / 'same.cpp').resolve()
        units = [{'source': str(alpha), 'symbol': 'Alpha'},
                 {'source': str(beta), 'symbol': 'Beta'}]
        # Object names are deliberately hashed like build.py's duplicate-stem
        # outputs. The correct source ownership must not depend on list order.
        objects = [
            {'path': 'obj/same-bbbbbbbbbbbbbbbb.obj', 'source_path': str(beta),
             'symbols': {'beta': {'name': 'Beta', 'section': 1, 'storage': 2}}},
            {'path': 'obj/same-aaaaaaaaaaaaaaaa.obj', 'source_path': str(alpha),
             'symbols': {'alpha': {'name': 'Alpha', 'section': 1, 'storage': 2}}},
        ]
        resolved, native = self._resolve_fixture(units, objects)
        self.assertEqual([unit['symbol'] for unit in resolved], ['Alpha', 'Beta'])
        self.assertEqual(native, {'Alpha': 0x1000, 'Beta': 0x2000})

    def test_resolve_rejects_wrong_source_owner_even_when_symbol_matches(self):
        alpha = (self.root / 'src' / 'alpha' / 'same.cpp').resolve()
        beta = (self.root / 'src' / 'beta' / 'same.cpp').resolve()
        units = [{'source': str(alpha), 'symbol': 'Alpha'}]
        objects = [{'path': 'obj/same-bbbbbbbbbbbbbbbb.obj', 'source_path': str(beta),
                    'symbols': {'alpha': {'name': 'Alpha', 'section': 1, 'storage': 2}}}]
        with self.assertRaisesRegex(ValueError, 'Missing compiled source unit'):
            self._resolve_fixture(units, objects)

    def test_resolve_keeps_unique_legacy_stem_fallback(self):
        source = (self.root / 'src' / 'base.cpp').resolve()
        units = [{'source': str(source), 'symbol': 'Base'}]
        objects = [{'path': 'obj/base.obj',
                    'symbols': {'base': {'name': 'Base', 'section': 1, 'storage': 2}}}]
        resolved, native = self._resolve_fixture(units, objects)
        self.assertEqual(resolved[0]['symbol'], 'Base')
        self.assertEqual(native, {'Base': 0x1000})

    def test_resolve_rejects_ambiguous_legacy_stem_fallback(self):
        source = (self.root / 'src' / 'base.cpp').resolve()
        units = [{'source': str(source), 'symbol': 'Base'}]
        symbol = {'name': 'Base', 'section': 1, 'storage': 2}
        objects = [{'path': 'obj/a/base.obj', 'symbols': {'base-a': symbol}},
                   {'path': 'obj/b/base.obj', 'symbols': {'base-b': symbol}}]
        with self.assertRaisesRegex(ValueError, 'Ambiguous compiled source unit basename'):
            self._resolve_fixture(units, objects)

    def test_resolve_rejects_duplicate_exact_source_provenance(self):
        source = (self.root / 'src' / 'base.cpp').resolve()
        units = [{'source': str(source), 'symbol': 'Base'}]
        symbol = {'name': 'Base', 'section': 1, 'storage': 2}
        objects = [{'path': 'obj/base-a.obj', 'source_path': str(source),
                    'symbols': {'base': symbol}},
                   {'path': 'obj/base-b.obj', 'source_path': str(source),
                    'symbols': {'base': symbol}}]
        with self.assertRaisesRegex(ValueError, 'Duplicate compiled objects claim source unit'):
            self._resolve_fixture(units, objects)

    def test_ambiguous_alias_is_not_exported_as_a_linker_name(self):
        catalog = {'functions': [
            {'id': 'fn_a', 'name': 'SharedName', 'aliases': ['SharedName'], 'rva': 0x1000},
            {'id': 'fn_b', 'name': 'SharedName', 'aliases': ['SharedName'], 'rva': 0x2000}], 'symbols': []}
        aliases = source_catalog.unique_alias_targets(catalog)
        self.assertNotIn('SharedName', aliases)
        self.assertEqual(aliases['fn_a'] if 'fn_a' in aliases else None, None)

    def test_legacy_alias_collision_binds_only_to_unique_current_sqlite_name_owner(self):
        catalog = {'functions': [
            {'id': 'fn_legacy', 'database_id': 10, 'name': 'OldOwnerName',
             'sqlite_name': 'RenamedOwner', 'aliases': ['OldOwnerName', 'CurrentName'], 'rva': 0x1000},
            {'id': 'fn_current', 'database_id': 20, 'name': 'CurrentName',
             'sqlite_name': 'CurrentName', 'aliases': ['CurrentName', 'OldCurrentName'], 'rva': 0x2000}],
            'symbols': []}
        aliases = source_catalog.unique_alias_targets(catalog)
        self.assertEqual(aliases['CurrentName'], 0x2000)
        self.assertEqual(aliases['OldOwnerName'], 0x1000)

    def test_ambiguous_alias_with_multiple_sqlite_owners_or_no_owner_fails_closed(self):
        multiple_owners = {'functions': [
            {'id': 'fn_a', 'name': 'SharedName', 'sqlite_name': 'SharedName',
             'aliases': ['SharedName'], 'rva': 0x1000},
            {'id': 'fn_b', 'name': 'SharedName', 'sqlite_name': 'SharedName',
             'aliases': ['SharedName'], 'rva': 0x2000}], 'symbols': []}
        ownerless_legacy = {'functions': [
            {'id': 'fn_a', 'name': 'OldNameA', 'aliases': ['OldNameA', 'SharedName'], 'rva': 0x1000},
            {'id': 'fn_b', 'name': 'OldNameB', 'aliases': ['OldNameB', 'SharedName'], 'rva': 0x2000}],
            'symbols': []}
        self.assertNotIn('SharedName', source_catalog.unique_alias_targets(multiple_owners))
        self.assertNotIn('SharedName', source_catalog.unique_alias_targets(ownerless_legacy))

    def test_ambiguous_function_and_data_alias_does_not_choose_sqlite_owner(self):
        catalog = {'functions': [
            {'id': 'fn_owner', 'name': 'SharedName', 'sqlite_name': 'SharedName',
             'aliases': ['SharedName'], 'rva': 0x1000}],
            'symbols': [
            {'id': 'sym_legacy', 'name': 'legacy', 'aliases': ['SharedName'],
             'kind': 'data-address', 'rva': 0x2000}]}
        self.assertNotIn('SharedName', source_catalog.unique_alias_targets(catalog))


class SourceProfileCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'generated').mkdir()
        (self.root / 'src').mkdir()
        (self.root / 'scratch').mkdir()
        self.image = 'ab' * 32
        self.catalog_path = self.root / 'generated' / 'function-catalog.json'
        unit_source = self.root / 'src' / 'base.cpp'
        unit_source.write_text('extern "C" void Base() {}\n')
        self.base = {'schema': 1, 'image_sha256': self.image,
                     'units': [{'source': 'src/base.cpp', 'symbol': 'Base',
                                'function_id': source_catalog.stable_id(self.image, 0x1000)}],
                     'imports': [{'symbol': 'BaseImport', 'symbol_id': source_catalog.stable_id(self.image, 0x2000)}]}
        (self.root / 'source-units.json').write_text(json.dumps(self.base))
        (self.root / 'src' / 'Load_XAsset.cpp').write_text('base loader')
        catalog = {'image_sha256': self.image, 'functions': [
            {'id': source_catalog.stable_id(self.image, 0x1000), 'rva': 0x1000, 'aliases': []},
            {'id': source_catalog.stable_id(self.image, 0x2000), 'rva': 0x2000, 'aliases': []},
            {'id': source_catalog.stable_id(self.image, 0x3000), 'rva': 0x3000, 'aliases': []}], 'symbols': []}
        self.catalog_path.write_text(json.dumps(catalog))
        overlay = self.root / 'scratch' / 'trace.cpp'
        overlay.write_text('extern "C" void Trace() {}\n')
        support = self.root / 'scratch' / 'trace.h'
        support.write_text('struct TraceRecord {};\n')
        self.profile_path = self.root / 'scratch' / 'profile.json'
        self.profile = {
            'schema': 1, 'profile_id': 'test-trace', 'source_image_sha256': self.image,
            'image_base': 0x140000000,
            'function_catalog_sha256': hashlib.sha256(self.catalog_path.read_bytes()).hexdigest(),
            'base_source_units_sha256': hashlib.sha256((self.root / 'source-units.json').read_bytes()).hexdigest(),
            'base_loader_source_sha256': hashlib.sha256((self.root / 'src' / 'Load_XAsset.cpp').read_bytes()).hexdigest(),
            'replacement_units': [{'source': 'scratch/trace.cpp', 'symbol': 'Trace',
                                   'function_id': source_catalog.stable_id(self.image, 0x3000)}],
            'imports': [{'symbol': 'BaseImport', 'symbol_id': source_catalog.stable_id(self.image, 0x2000)}],
            'source_sha256': {'scratch/trace.cpp': hashlib.sha256(overlay.read_bytes()).hexdigest(),
                              'scratch/trace.h': hashlib.sha256(support.read_bytes()).hexdigest()},
            'required_defines': ['REPLAY_COMPILER_FRONTEND_PROBE'],
            'required_linked_globals': ['TraceCount']}
        self.profile_path.write_text(json.dumps(self.profile))

    def tearDown(self):
        self.temp.cleanup()

    def test_profile_composes_without_mutating_baseline(self):
        baseline_bytes = (self.root / 'source-units.json').read_bytes()
        composed, report = source_catalog.compose_source_profile(
            self.profile_path, {'input_sha256': self.image, 'image_base': 0x140000000},
            self.base, self.catalog_path, self.root)
        self.assertEqual(len(composed['units']), 2)
        self.assertEqual(composed['units'][0], self.base['units'][0])
        self.assertEqual(composed['units'][1]['symbol'], 'Trace')
        self.assertEqual(composed['imports'], self.base['imports'])
        self.assertEqual((self.root / 'source-units.json').read_bytes(), baseline_bytes)
        self.assertEqual(report['profile_id'], 'test-trace')
        self.assertEqual(report['superseded_sources'], [])

    def test_profile_replaces_baseline_translation_unit_in_compile_plan(self):
        self.profile['replacement_units'][0]['function_id'] = self.base['units'][0]['function_id']
        self.profile_path.write_text(json.dumps(self.profile))
        composed, report = source_catalog.compose_source_profile(
            self.profile_path, {'input_sha256': self.image, 'image_base': 0x140000000},
            self.base, self.catalog_path, self.root)
        self.assertEqual(len(composed['units']), 1)
        self.assertEqual(composed['units'][0]['source'], 'scratch/trace.cpp')
        self.assertEqual(report['superseded_sources'], [str((self.root / 'src/base.cpp').resolve())])

    def test_profile_cannot_drop_unreplaced_function_in_same_translation_unit(self):
        other_id = source_catalog.stable_id(self.image, 0x2000)
        self.base['units'].append(dict(source='src/base.cpp', symbol='Other', function_id=other_id))
        (self.root / 'source-units.json').write_text(json.dumps(self.base))
        self.profile['base_source_units_sha256'] = hashlib.sha256((self.root / 'source-units.json').read_bytes()).hexdigest()
        self.profile['replacement_units'][0]['function_id'] = self.base['units'][0]['function_id']
        self.profile_path.write_text(json.dumps(self.profile))
        with self.assertRaisesRegex(ValueError, 'only part of a baseline translation unit'):
            source_catalog.compose_source_profile(
                self.profile_path, {'input_sha256': self.image, 'image_base': 0x140000000},
                self.base, self.catalog_path, self.root)

    def test_stale_image_or_overlay_source_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'different Replay'):
            source_catalog.compose_source_profile(self.profile_path,
                {'input_sha256': 'cd' * 32, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)
        source = self.root / 'scratch' / 'trace.cpp'
        source.write_text(source.read_text() + '// changed\n')
        with self.assertRaisesRegex(ValueError, 'source hash mismatch'):
            source_catalog.compose_source_profile(self.profile_path,
                {'input_sha256': self.image, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)

    def test_name_only_catalog_refresh_keeps_profile_ids_but_rva_drift_fails(self):
        catalog = json.loads(self.catalog_path.read_text())
        catalog['functions'][0]['aliases'] = ['CurrentSQLiteName']
        self.catalog_path.write_text(json.dumps(catalog))
        composed, report = source_catalog.compose_source_profile(self.profile_path,
            {'input_sha256': self.image, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)
        self.assertFalse(report['catalog_digest_matches_profile'])
        self.assertEqual(composed['units'][0]['function_id'], self.base['units'][0]['function_id'])
        catalog['functions'][0]['rva'] = 0x1100
        self.catalog_path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, 'identity/RVA mismatch'):
            source_catalog.compose_source_profile(self.profile_path,
                {'input_sha256': self.image, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)

    def test_crlf_loader_uses_normalized_profile_baseline(self):
        loader = self.root / 'src' / 'Load_XAsset.cpp'
        loader.write_bytes(b'line one\r\nline two\r\n')
        self.profile['base_loader_source_sha256'] = hashlib.sha256(
            loader.read_text(encoding='utf-8').encode('utf-8')).hexdigest()
        self.profile_path.write_text(json.dumps(self.profile))
        composed, report = source_catalog.compose_source_profile(
            self.profile_path, {'input_sha256': self.image, 'image_base': 0x140000000},
            self.base, self.catalog_path, self.root)
        self.assertEqual(report['profile_id'], 'test-trace')
        self.assertEqual(len(composed['units']), 2)

    def test_conflicting_profile_import_and_unaccounted_define_fail(self):
        self.profile['imports'] = [{'symbol': 'BaseImport', 'symbol_id': source_catalog.stable_id(self.image, 0x3000)}]
        self.profile_path.write_text(json.dumps(self.profile))
        with self.assertRaisesRegex(ValueError, 'conflicts with baseline'):
            source_catalog.compose_source_profile(self.profile_path,
                {'input_sha256': self.image, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)

        self.profile['imports'] = [{'symbol': 'BaseImport', 'symbol_id': source_catalog.stable_id(self.image, 0x2000)}]
        self.profile['required_defines'] = ['UNSUPPORTED_DEFINE']
        self.profile_path.write_text(json.dumps(self.profile))
        with self.assertRaisesRegex(ValueError, 'unsupported compiler defines'):
            source_catalog.compose_source_profile(self.profile_path,
                {'input_sha256': self.image, 'image_base': 0x140000000}, self.base, self.catalog_path, self.root)


if __name__ == '__main__':
    unittest.main()
