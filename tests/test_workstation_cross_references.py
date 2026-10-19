"""Small read-only catalog/SQLite reference fixture; no game or asset writes."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from workstation.cross_references import inspect_symbol


class CrossReferencesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / 'generated').mkdir()
        (root / 'generated' / 'manifest.json').write_text(json.dumps({'image_base': 0x140000000}))
        (root / 'source-units.json').write_text(json.dumps({'image_sha256': 'image',
            'imports': [{'symbol': 'Engine_GetState', 'symbol_id': 'fn_target'}]}))
        rows = [{'id': 'fn_target', 'name': 'Unnamed function', 'rva': 0x1000, 'aliases': []},
                {'id': 'fn_caller', 'name': 'Com_Frame', 'rva': 0x2000, 'aliases': ['Com_FrameAlias']},
                {'id': 'sym_state', 'name': 's_state', 'rva': 0x3000, 'kind': 'data', 'aliases': []}]
        self.sources = Mock(root=root, generated=root/'generated', sqlite_path=root/'analysis.sqlite',
                            _catalog={'image_sha256': 'image'})
        self.sources._rows.return_value = rows
        self.sources._state.return_value = {'sources': {}}
        self.sources._display_name.side_effect = lambda row: row['name']
        with closing(sqlite3.connect(self.sources.sqlite_path)) as db:
            db.executescript('''CREATE TABLE functions(id INTEGER, address TEXT, prototype TEXT, prototype2 TEXT, comment TEXT, size INTEGER);
                CREATE TABLE callgraph(func_id INTEGER, address TEXT, type TEXT);
                CREATE TABLE replay_crossref_function_references(owner_rva INTEGER,site_rva INTEGER,target_rva INTEGER,kind TEXT,decoded TEXT);''')
            db.execute('INSERT INTO functions VALUES(1,?,?,?,?,?)', (str(0x140001000), 'int Engine_GetState()', '', '', 32))
            db.executemany('INSERT INTO callgraph VALUES(?,?,?)', [(1,str(0x140002000),'caller'),
                (1,str(0x140002000),'caller'), (1,str(0x140003000),'callee'),(1,str(0x140009000),'callee')])
            db.execute('INSERT INTO replay_crossref_function_references VALUES(?,?,?,?,?)', (0x2000,0x2008,0x1000,'call','call Engine_GetState'))
            db.commit()

    def test_binding_and_recorded_references(self):
        before = self.sources.sqlite_path.read_bytes()
        result = inspect_symbol(self.sources, query='Engine_GetState')
        self.assertEqual(result['subject']['id'], 'fn_target')
        self.assertEqual(result['subject']['prototype'], 'int Engine_GetState()')
        self.assertEqual(result['groups']['caller']['total'], 1)
        self.assertEqual(result['groups']['caller']['items'][0]['id'], 'fn_caller')
        self.assertEqual(result['groups']['inbound']['items'][0]['site_rva'], 0x2008)
        self.assertEqual(self.sources.sqlite_path.read_bytes(), before)

    def test_unmapped_and_pagination(self):
        result = inspect_symbol(self.sources, identity='fn_target', limit=1, offset=1)
        self.assertEqual(result['groups']['callee']['total'], 2)
        self.assertIsNone(result['groups']['callee']['items'][0]['id'])

    def test_alias_and_unknown(self):
        self.assertEqual(inspect_symbol(self.sources, query='Com_FrameAlias')['subject']['id'], 'fn_caller')
        self.assertIsNone(inspect_symbol(self.sources, query='unresolved')['subject'])
        with self.assertRaises(ValueError):
            inspect_symbol(self.sources, limit=10000)

    def test_generated_cpp_alias_opens_the_same_function_context(self):
        result = inspect_symbol(self.sources, query='func_140001000')
        self.assertEqual(result['subject']['id'], 'fn_target')
        self.assertEqual(result['subject']['variant'], 'cpp')
        self.assertEqual(inspect_symbol(self.sources, query='gl_140003000')['subject']['id'], 'sym_state')

    def test_ambiguous_name_keeps_all_identities(self):
        self.sources._rows.return_value.append({'id':'fn_other','name':'Unnamed function','rva':0x4000,'aliases':[]})
        result=inspect_symbol(self.sources,query='Unnamed function')
        self.assertEqual(result['match_count'],2)
        self.assertIsNone(result['subject'])

    def test_catalog_name_refresh_invalidates_context_index(self):
        inspect_symbol(self.sources, query='Com_FrameAlias')
        rows = [dict(row) for row in self.sources._rows.return_value]
        rows[1].update(name='Com_FrameRenamed', aliases=[])
        self.sources._rows.return_value = rows
        self.assertIsNone(inspect_symbol(self.sources, query='Com_FrameAlias')['subject'])
        self.assertEqual(inspect_symbol(self.sources, query='Com_FrameRenamed')['subject']['id'], 'fn_caller')


if __name__ == '__main__':
    unittest.main()
