"""Durable compiler implementation identity shared by dispatch and publication."""
from __future__ import annotations

from workstation.backend_identity import BackendSnapshot


def compiler_snapshot(root):
    # Dynamic imports and subprocess entry points make a hand-maintained helper
    # list incomplete. Pin the authored backend tree, including nested codecs
    # and the C++ relocation implementation.
    # UI, generated data and installed tools have independent lifetimes/checks.
    return {'schema': 1, 'files': BackendSnapshot(root).files}


def require_compiler_snapshot(root, expected):
    if (not isinstance(expected, dict) or type(expected.get('schema')) is not int or
            expected['schema'] != 1 or not isinstance(expected.get('files'), dict)):
        raise ValueError('Compiler implementation snapshot is missing or invalid; start a fresh build')
    actual = compiler_snapshot(root)['files']
    wanted = expected['files']
    changed = sorted(name for name in wanted.keys() | actual.keys()
                     if wanted.get(name) != actual.get(name))
    if changed:
        raise RuntimeError('Compiler implementation changed after dispatch; rebuild before publication: '
                           + ', '.join(changed[:12]))
