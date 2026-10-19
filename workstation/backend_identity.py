"""Pin the server and C++ compiler backend before importing local modules."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class BackendChangedError(ValueError):
    pass


class BackendSnapshot:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.files = self._snapshot()

    def _snapshot(self):
        # Include nested authored modules, including the DXBC translators.
        # Installed tools and third-party trees have their own pinned identities.
        result = {}
        for folder in ('workstation', 'tools'):
            for directory, children, files in os.walk(self.root / folder, followlinks=False):
                children[:] = sorted(name for name in children if name not in {
                    '__pycache__', 'bin', 'vendor', 'renderdoc', 'node_modules', '.venv',
                    'generated', 'build', 'web'})
                for name in sorted(files):
                    if not name.endswith(('.py', '.cpp', '.h', '.hpp')):
                        continue
                    path = Path(directory) / name
                    try:
                        result[path.relative_to(self.root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
                    except FileNotFoundError:
                        # A concurrent rename must compare as a missing input.
                        continue
        return result

    def status(self):
        current = self._snapshot()
        changed = sorted(name for name in self.files.keys() | current.keys()
                         if self.files.get(name) != current.get(name))
        return {'restart_required': bool(changed), 'changed_files': changed}

    def require_current(self):
        changed = self.status()['changed_files']
        if changed:
            raise BackendChangedError('Workstation backend source changed after startup; '
                                      'restart the server before saving or compiling: ' + ', '.join(changed[:8]))
