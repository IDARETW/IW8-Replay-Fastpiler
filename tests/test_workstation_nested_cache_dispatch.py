import json
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from tools.workstation_fastfiles import _read_native_rows, _native_walk_artifact


class NestedCacheDispatchTests(unittest.TestCase):
    def test_dispatch_retains_validated_receipt_artifact_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            walk = root / 'native-walk/hash'
            (walk / 'native').mkdir(parents=True)
            trace = walk / 'native/stream-trace.jsonl'
            trace.write_text('')
            journal = walk / 'native/assets.jsonl'
            journal.write_text('{"type_id":14,"name":"test"}\n')
            receipt = dict(decoded_body_sha256='body-hash', stream_trace_enabled=True,
                           stream_trace_relative_path='native/stream-trace.jsonl',
                           journal_relative_path='native/assets.jsonl', walk_key='hash')
            (walk / 'native-walk-receipt.json').write_text(json.dumps(receipt))
            body = SimpleNamespace(source_sha256='body-hash')
            with patch('tools.workstation_fastfiles._validate_native_walk_receipt',
                       return_value=dict(receipt, cache_path=str(walk))):
                validated, rows = _read_native_rows(root, body, require_trace=True)
            self.assertEqual(_native_walk_artifact(validated, 'stream_trace_relative_path'), trace)
            self.assertEqual(rows, [dict(type_id=14,name='test')])


if __name__ == '__main__':
    unittest.main()
