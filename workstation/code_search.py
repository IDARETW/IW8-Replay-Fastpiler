"""Persistent, incremental substring index for the C++ editor's code bodies.

This disposable display cache never writes the recovery database or compiler
inputs. FTS trigrams narrow candidates; an exact literal check rejects matches
whose trigrams occur in different places. Queries read only one bounded page.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time


def _digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _expression(needle):
    # detail=none stores document postings rather than every token position.
    # Three-character terms work with that compact format. Cap term count;
    # instr() still verifies the entire query, including punctuation/newlines.
    terms = list(dict.fromkeys(needle[i:i + 3] for i in range(len(needle) - 2)))
    return ' AND '.join('"' + term.replace('"', '""') + '"' for term in terms[:64])


def _preview(content, needle):
    folded = content.casefold()
    at = folded.find(needle)
    # Unicode folding can expand characters (ß -> ss). Recover the original
    # character offset only for those bodies; the ordinary ASCII path is O(1).
    if len(folded) != len(content):
        position = 0
        for at_original, char in enumerate(content):
            position += len(char.casefold())
            if position > at:
                at = at_original
                break
    line = content.count('\n', 0, at) + 1
    start = content.rfind('\n', 0, at) + 1
    end = content.find('\n', at)
    if end < 0:
        end = len(content)
    start = max(start, at - 80)
    return dict(line=line, column=at - (content.rfind('\n', 0, at) + 1) + 1,
                snippet=content[start:min(end, start + 240)].strip(), query=needle)


class CodeSearchIndex:
    def __init__(self, sources):
        self.sources = sources
        self.cpp = sources.cpp_index()
        self.path = sources.cache_root / 'code-search.sqlite'
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.progress = {'state': 'building', 'indexed': 0, 'total': 0, 'error': None}
        self.file_cache = {}
        self.worker = None
        with closing(self.connect()) as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS documents (
                    rowid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL, path TEXT, kind TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, content TEXT NOT NULL,
                    folded TEXT NOT NULL);
                CREATE VIRTUAL TABLE IF NOT EXISTS code_fts USING fts5(
                    folded, content='documents', content_rowid='rowid',
                    tokenize='trigram', detail='none');
                CREATE TRIGGER IF NOT EXISTS code_insert AFTER INSERT ON documents BEGIN
                    INSERT INTO code_fts(rowid,folded) VALUES(new.rowid,new.folded);
                END;
                CREATE TRIGGER IF NOT EXISTS code_delete AFTER DELETE ON documents BEGIN
                    INSERT INTO code_fts(code_fts,rowid,folded) VALUES('delete',old.rowid,old.folded);
                END;
                CREATE TRIGGER IF NOT EXISTS code_update AFTER UPDATE ON documents BEGIN
                    INSERT INTO code_fts(code_fts,rowid,folded) VALUES('delete',old.rowid,old.folded);
                    INSERT INTO code_fts(rowid,folded) VALUES(new.rowid,new.folded);
                END;
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            ''')
            identity = self.cpp.image + ':trigram-v1'
            old = db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if not old or old[0] != identity:
                db.execute('DELETE FROM documents')
                db.execute("INSERT OR REPLACE INTO meta VALUES('identity',?)", (identity,))
            self.progress['indexed'] = db.execute('SELECT count(*) FROM documents').fetchone()[0]

    def connect(self):
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=NORMAL')
        return db

    def _authored(self, rows):
        root = self.sources.root
        bindings = {}
        for relative in ('source-units.json', 'source-workstation/units.json'):
            path = root / relative
            if not path.is_file():
                continue
            for unit in json.loads(path.read_text(encoding='utf-8')).get('units', []):
                if unit.get('kind', 'cpp') != 'cpp':
                    continue
                identity = unit.get('function_id')
                if identity in rows:
                    source = (root / unit['source']).resolve()
                    bindings.setdefault(source, []).append(identity)
        users = root / 'source-workstation/user-functions.json'
        user_rows = json.loads(users.read_text(encoding='utf-8')).get('functions', {}) if users.is_file() else {}
        for identity, unit in user_rows.items():
            source = (root / unit['path']).resolve()
            bindings.setdefault(source, []).append(identity)
        result = {}
        active_paths = set()
        for directory in ('src', 'source-workstation'):
            base = root / directory
            for path in base.rglob('*') if base.is_dir() else ():
                if self.stop.is_set():
                    return result
                if not path.is_file() or path.suffix.lower() not in ('.cpp', '.c', '.h', '.hpp'):
                    continue
                resolved = path.resolve()
                if not resolved.is_relative_to(base.resolve()):
                    continue
                active_paths.add(resolved)
                stat = path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
                cached = self.file_cache.get(resolved)
                if not cached or cached[0] != signature:
                    content = path.read_text(encoding='utf-8')
                    cached = (signature, content, _digest(content))
                    self.file_cache[resolved] = cached
                _, content, content_hash = cached
                relative = path.relative_to(root).as_posix()
                ids = bindings.get(resolved)
                if ids:
                    for identity in ids:
                        row = rows.get(identity) or user_rows[identity]
                        name = self.sources._display_name(row) if identity in rows else row['name']
                        result[identity] = (name, relative, 'function', content_hash, content)
                else:
                    identity = 'file:' + relative
                    result[identity] = (path.name, relative, 'file', content_hash, content)
        self.file_cache = {path: value for path, value in self.file_cache.items() if path in active_paths}
        return result

    def refresh(self):
        from workstation_cpp_sources import GENERATOR
        rows = dict(self.cpp.rows)
        authored = self._authored(rows)
        with closing(sqlite3.connect(self.cpp.path.as_uri() + '?mode=ro', uri=True, timeout=3)) as source, \
                closing(self.connect()) as target:
            source.execute('BEGIN')
            headers = source.execute('SELECT id,input_hash FROM recovered_cpp WHERE image_hash=? AND generation=?',
                                     (self.cpp.image, GENERATOR)).fetchall()
            existing = {row['id']: row['fingerprint'] for row in target.execute('SELECT id,fingerprint FROM documents')}
            active = set()
            changed = 0
            self.progress.update(state='building' if not existing else 'updating', total=len(rows) + len(authored), error=None)

            def publish(identity, name, path, kind, content_hash, content_reader):
                nonlocal changed
                active.add(identity)
                fingerprint = _digest(json.dumps((content_hash, name, path, kind)))
                if existing.get(identity) == fingerprint:
                    return
                content = content_reader()
                target.execute('''INSERT INTO documents(id,name,path,kind,fingerprint,content,folded)
                    VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                    path=excluded.path,kind=excluded.kind,fingerprint=excluded.fingerprint,
                    content=excluded.content,folded=excluded.folded''',
                    (identity, name, path, kind, fingerprint, content, content.casefold()))
                changed += 1
                self.progress['indexed'] = len(active)
                if changed % 250 == 0:
                    target.commit()
                    target.execute('BEGIN')

            target.execute('BEGIN')
            try:
                for identity, content_hash in headers:
                    if self.stop.is_set():
                        target.rollback()
                        return
                    row = rows.get(identity)
                    if row is None or identity in authored:
                        continue
                    publish(identity, self.sources._display_name(row), None, 'function', content_hash,
                            lambda identity=identity: source.execute('SELECT content FROM recovered_cpp WHERE id=?', (identity,)).fetchone()[0])
                for identity, (name, path, kind, content_hash, content) in authored.items():
                    publish(identity, name, path, kind, content_hash, lambda content=content: content)
                for identity in existing.keys() - active:
                    target.execute('DELETE FROM documents WHERE id=?', (identity,))
                target.commit()
            except Exception:
                target.rollback()
                raise
        self.progress.update(state='ready' if self.cpp.progress.get('state') == 'ready' else 'building',
                             indexed=len(active), total=len(active), updated_at=time.time(), error=None)

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        def run():
            while not self.stop.is_set():
                self.wake.clear()
                try:
                    self.refresh()
                except Exception as error:
                    self.progress.update(state='error', error=str(error))
                self.wake.wait(10)
        self.worker = threading.Thread(target=run, name='Replay-code-search', daemon=True)
        self.worker.start()

    def search(self, query, offset=0, limit=100):
        if not isinstance(query, str) or '\0' in query or not 3 <= len(query) <= 256:
            raise ValueError('Code text search needs 3..256 characters; it treats punctuation literally.')
        if not 0 <= offset <= 10000 or not 1 <= limit <= 1000:
            raise ValueError('Invalid code search page')
        needle = query.casefold()
        started = time.perf_counter()
        with closing(self.connect()) as db:
            records = db.execute('''SELECT d.id,d.name,d.path,d.kind,d.content FROM code_fts
                JOIN documents d ON d.rowid=code_fts.rowid
                WHERE code_fts MATCH ? AND instr(d.folded,?)>0 ORDER BY code_fts.rowid LIMIT ? OFFSET ?''',
                (_expression(needle), needle, limit + 1, offset)).fetchall()
        more = len(records) > limit
        items = []
        for row in records[:limit]:
            match = _preview(row['content'], needle)
            kind = 'file' if row['kind'] == 'file' else 'source'
            target = {'path': row['path']} if kind == 'file' else {'id': row['id'], 'variant': 'cpp'}
            items.append(dict(id=row['id'], name=row['name'], kind=kind, area='Code',
                              source_kind='function' if kind == 'source' else None,
                              path=row['path'], target=target, expandable=False, match=match))
        status = dict(self.progress)
        status['complete'] = status['state'] == 'ready'
        return dict(items=items, offset=offset, limit=limit,
                    total=offset + len(items) + int(more), has_more=more, total_is_exact=not more,
                    search_status=status, elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
                    search_mode='code', query=query)

    def close(self):
        self.stop.set()
        self.wake.set()
        if self.worker:
            self.worker.join(timeout=3)
