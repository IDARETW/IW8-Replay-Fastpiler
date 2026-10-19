"""Substring search over immutable display rows; never edit or build authority."""
from array import array
from bisect import bisect_right
import threading


class SourceSearchIndex:
    def __init__(self):
        self._lock = threading.RLock()
        self._families = {}

    def prepare(self, family, rows):
        with self._lock:
            existing = self._families.get(family)
            if existing is not None and existing[0] is rows:
                return existing
            starts = array('Q')
            pieces = []
            position = 0
            for row in rows:
                text = (' '.join(str(row.get(key, '')) for key in
                                 ('id', 'name', 'kind', 'type_name')) + ' ' +
                        ' '.join(str(alias) for alias in row.get('aliases', []))).casefold()
                starts.append(position)
                pieces.append(text + '\0')
                position += len(text) + 1
            starts.append(position)
            result = (rows, ''.join(pieces), starts)
            self._families[family] = result
            return result

    def matches(self, family, rows, needle):
        rows, text, starts = self.prepare(family, rows)
        position = 0
        while position < len(text):
            found = text.find(needle, position)
            if found < 0:
                break
            index = bisect_right(starts, found) - 1
            stop = starts[index + 1]
            # A query spanning the separator must not match adjacent rows.
            if found + len(needle) < stop:
                yield rows[index]
                position = stop
            else:
                position = found + 1
