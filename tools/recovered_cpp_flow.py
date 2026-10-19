"""Publish image- and source-scoped native control-flow recovery atomically.

The growing analysis SQLite remains read-only. A recovery is usable only for
the exact decompiler input it repaired and the executable it was decoded from.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from recovered_cpp_names import count_jumpouts

IMPLEMENTATION = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def source_hash(data):
    return hashlib.sha256(json.dumps([data.get('prototype'), data.get('pseudocode') or ''],
                                    ensure_ascii=False).encode()).hexdigest()


class FlowRecovery:
    def __init__(self, root, image):
        self.directory = Path(root) / 'analysis' / 'cpp-flow'
        self.path = self.directory / 'recovered.sqlite'
        self.image = image
        config = Path(root) / 'replay-project.local.json'
        settings = json.loads(config.read_text()).get('cpp_recovery', {}) if config.is_file() else {}
        self.baseline = settings.get('baseline_idb_sha256')
        self.offsets = {}
        self.signature = None
        self.rows = {}
        self.lock = threading.RLock()

    def connect(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS flows (
                image TEXT NOT NULL,rva INTEGER NOT NULL,source_hash TEXT NOT NULL,
                record TEXT NOT NULL,updated REAL NOT NULL,
                PRIMARY KEY(image,rva,source_hash));
            CREATE TABLE IF NOT EXISTS imports (
                path TEXT PRIMARY KEY,offset INTEGER NOT NULL,prefix TEXT NOT NULL);
        ''')
        return db

    def sync(self):
        # Foreground opens and background indexing share this publisher. Keep
        # the imported offsets, durable transaction and in-memory snapshot in
        # the same order, including while IDA appends another batch record.
        with self.lock:
            self._sync()

    def _sync(self):
        files = sorted(self.directory.glob('*-result*.jsonl')) if self.directory.exists() else []
        signature = [(str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in files]
        if signature == self.signature:
            return
        with closing(self.connect()) as db:
            for path in files:
                with path.open('rb') as stream:
                    prefix = hashlib.sha256(stream.read(256)).hexdigest()
                    previous = db.execute('SELECT offset,prefix FROM imports WHERE path=?', (str(path),)).fetchone()
                    offset = previous['offset'] if previous and previous['prefix'] == prefix and previous['offset'] <= path.stat().st_size else 0
                    stream.seek(offset)
                    while True:
                        line_start = stream.tell()
                        line = stream.readline()
                        if not line or not line.endswith(b'\n'):
                            stream.seek(line_start)
                            break  # A writer may still be publishing this record.
                        record = json.loads(line)
                        if record.get('image_sha256') != self.image or not record.get('source_hash'):
                            continue
                        if self.baseline and record.get('baseline_idb_sha256') != self.baseline:
                            continue  # Earlier IDB decoding/types cannot overwrite the adopted baseline.
                        existing = db.execute('SELECT record FROM flows WHERE image=? AND rva=? AND source_hash=?',
                                              (self.image, record['rva'], record['source_hash'])).fetchone()
                        if existing:
                            prior = json.loads(existing['record'])
                            # A failed retry cannot invalidate a successfully
                            # recovered body for the same pinned native input.
                            prior_complete = (prior.get('status') == 'recovered' and
                                              (not self.baseline or prior.get('baseline_idb_sha256') == self.baseline) and
                                              bool(str(prior.get('pseudocode') or '').strip()) and
                                              not count_jumpouts(prior.get('pseudocode', '')))
                            next_complete = (record.get('status') == 'recovered' and
                                             bool(str(record.get('pseudocode') or '').strip()) and
                                             not count_jumpouts(record.get('pseudocode', '')))
                            if prior_complete and not next_complete:
                                continue
                            # A generic bulk pass must not erase a reviewed,
                            # typed recovery for the same exact source input.
                            if prior_complete and prior.get('type_hints') and not record.get('type_hints'):
                                continue
                            if (prior_complete and next_complete and prior.get('reference_names')
                                    and not record.get('reference_names')
                                    and prior.get('pseudocode') == record.get('pseudocode')
                                    and prior.get('type_hints') == record.get('type_hints')):
                                continue  # Keep exact reference provenance on equivalent older records.
                        db.execute('INSERT OR REPLACE INTO flows VALUES (?,?,?,?,?)',
                                   (self.image, record['rva'], record['source_hash'],
                                    json.dumps(record, ensure_ascii=False), time.time()))
                    db.execute('INSERT OR REPLACE INTO imports VALUES (?,?,?)', (str(path), stream.tell(), prefix))
            db.commit()
            self.rows = {(row['rva'], row['source_hash']): json.loads(row['record'])
                         for row in db.execute('SELECT * FROM flows WHERE image=?', (self.image,))}
        self.signature = signature

    def get(self, rva, data):
        record = self.rows.get((rva, source_hash(data)))
        if (not record or (self.baseline and record.get('baseline_idb_sha256') != self.baseline) or
                record.get('status') != 'recovered' or not str(record.get('pseudocode') or '').strip() or
                count_jumpouts(record.get('pseudocode', ''))):
            return None
        return record

    def status(self):
        counts = {}
        active = [record for record in self.rows.values()
                  if not self.baseline or record.get('baseline_idb_sha256') == self.baseline]
        for record in active:
            counts[record['status']] = counts.get(record['status'], 0) + 1
        return {'counts': counts, 'records': len(active), 'historical_records': len(self.rows),
                'baseline_idb_sha256': self.baseline,
                'scope': 'Recovery inputs for this image and analysis baseline. Only exact current source matches are applied.'}
