import json
from contextlib import closing
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest

from workstation.code_search import CodeSearchIndex
from workstation_cpp_sources import GENERATOR


class CodeSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.cpp = SimpleNamespace(path=self.cache / 'generated-cpp.sqlite', image='image',
                                   rows={}, progress={'state': 'ready'})
        with closing(sqlite3.connect(self.cpp.path)) as db, db:
            db.execute('CREATE TABLE recovered_cpp(id TEXT PRIMARY KEY,input_hash TEXT,image_hash TEXT,generation INTEGER,content TEXT)')
        self.sources = SimpleNamespace(root=self.root, cache_root=self.cache,
                                       cpp_index=lambda: self.cpp, _display_name=lambda row: row['name'])
        self.index = CodeSearchIndex(self.sources)

    def tearDown(self):
        self.index.close()
        self.temp.cleanup()

    def put(self, identity, content):
        self.cpp.rows[identity] = {'id': identity, 'name': 'Com_' + identity}
        with closing(sqlite3.connect(self.cpp.path)) as db, db:
            db.execute('INSERT OR REPLACE INTO recovered_cpp VALUES(?,?,?,?,?)',
                       (identity, content, self.cpp.image, GENERATOR, content))

    def test_literal_quotes_wildcards_unicode_and_trigram_false_positives(self):
        self.put('one', 'void x() {\n  print("100%_done Straße");\n  abcXYZbcd;\n}')
        self.put('two', 'void y() { print("abcd"); }')
        self.index.refresh()
        for query in ('100%_done', 'STRASSE', '"100%_', 'print("'):
            result = self.index.search(query)
            self.assertEqual(result['items'][0]['id'], 'one')
            self.assertEqual(result['items'][0]['match']['line'], 2)
        self.assertEqual([row['id'] for row in self.index.search('abcd')['items']], ['two'])
        self.assertEqual(self.index.search('absent')['items'], [])

    def test_authored_override_update_retirement_and_persistent_cache(self):
        self.put('one', 'recovered old body')
        source = self.root / 'src/Com_One.cpp'
        source.write_text('authored literal body', encoding='utf-8')
        (self.root / 'source-units.json').write_text(json.dumps({'units': [
            {'source': 'src/Com_One.cpp', 'function_id': 'one'}]}))
        self.index.refresh()
        self.assertEqual(self.index.search('recovered')['items'], [])
        self.assertEqual(self.index.search('authored')['items'][0]['target']['id'], 'one')
        source.write_text('newly saved content', encoding='utf-8')
        self.index.refresh()
        self.assertEqual(self.index.search('authored')['items'], [])
        self.assertEqual(self.index.search('newly')['items'][0]['id'], 'one')
        other = CodeSearchIndex(self.sources)
        self.assertEqual(other.search('newly')['items'][0]['id'], 'one')
        other.close()
        source.unlink()
        self.cpp.rows.clear()
        self.index.refresh()
        self.assertEqual(self.index.search('newly')['items'], [])

    def test_page_bounds_more_results_and_short_query_guard(self):
        for number in range(5):
            self.put(str(number), 'same literal twice: same literal')
        self.index.refresh()
        first = self.index.search('same literal', limit=2)
        second = self.index.search('same literal', offset=2, limit=2)
        final = self.index.search('same literal', offset=4, limit=2)
        self.assertTrue(first['has_more'])
        self.assertTrue(second['has_more'])
        self.assertFalse(final['has_more'])
        self.assertEqual(len({row['id'] for page in (first, second, final) for row in page['items']}), 5)
        for query in ('a', 'ab', 'abc\0d', 'a' * 257):
            with self.assertRaises(ValueError):
                self.index.search(query)


if __name__ == '__main__':
    unittest.main()
