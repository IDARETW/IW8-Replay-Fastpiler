import unittest

from workstation.search_index import SourceSearchIndex


class SourceSearchIndexTests(unittest.TestCase):
    def test_substrings_aliases_unicode_and_multiple_hits_per_row(self):
        rows = [dict(id='fn-one', name='DB_Load', kind='function',
                     aliases=['scripts/test.gsc', 'another.gsc']),
                dict(id='fn-two', name='Straße', aliases=['mixed.CFG']),
                dict(id='tail', name='Boundary')]
        index = SourceSearchIndex()
        for query in ('.gsc', 'STRASSE', '.cfg', 'fn-', 'missing', 'Boundary'):
            needle = query.casefold()
            expected = [row for row in rows if needle in (
                ' '.join(str(row.get(k, '')) for k in ('id', 'name', 'kind', 'type_name')) +
                ' ' + ' '.join(row.get('aliases', []))).casefold()]
            self.assertEqual(list(index.matches('functions', rows, needle)), expected)

    def test_cache_reuses_snapshot_and_refreshes_replaced_family(self):
        index = SourceSearchIndex()
        old = [dict(id='fn-one', name='OldName')]
        cached = index.prepare('functions', old)
        self.assertIs(index.prepare('functions', old), cached)
        new = [dict(id='fn-one', name='NewName')]
        self.assertEqual(list(index.matches('functions', new, 'oldname')), [])
        self.assertEqual(list(index.matches('functions', new, 'newname')), new)

    def test_query_cannot_join_neighbor_rows(self):
        index = SourceSearchIndex()
        rows = [dict(id='first', aliases=['tail']), dict(id='second', name='head')]
        self.assertEqual(list(index.matches('functions', rows, 'tail\0second')), [])
        self.assertEqual(list(index.matches('functions', rows, 'tail')), [rows[0]])
        self.assertEqual(list(index.matches('empty', [], '.gsc')), [])


if __name__ == '__main__':
    unittest.main()
