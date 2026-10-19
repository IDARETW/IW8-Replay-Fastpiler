"""A stopped HTTP process must not unlock a surviving compiler child."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from workstation.build_lock import ensure_compiler_idle


class CompilerLockTests(unittest.TestCase):
    def test_lock_survives_launcher_exit_and_blocks_competing_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            lock, ready, release, attempted = [folder / name for name in ('compiler.lock', 'ready', 'release', 'attempted')]
            child = folder / 'child.py'
            child.write_text('from pathlib import Path\nimport time\n'
                             f'Path({str(ready)!r}).touch()\n'
                             f'while not Path({str(release)!r}).exists(): time.sleep(0.02)\n')
            command = [sys.executable, str(ROOT / 'tools/run_compiler_locked.py'), '--lock', str(lock), '--', sys.executable, str(child)]
            launcher = folder / 'launcher.py'
            launcher.write_text('import subprocess,time\n'
                                f'subprocess.Popen({command!r}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n'
                                'time.sleep(30)\n')
            process = subprocess.Popen([sys.executable, str(launcher)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), 'Compiler child failed to acquire its lock')
                process.kill()
                process.wait(timeout=5)
                with self.assertRaisesRegex(ValueError, 'Another compiler process'):
                    ensure_compiler_idle(lock)
                competitor = command[:-1] + ['-c', f'from pathlib import Path; Path({str(attempted)!r}).touch()']
                result = subprocess.run(competitor, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(attempted.exists(), 'Conflicting command was allowed to run')
            finally:
                release.touch()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        ensure_compiler_idle(lock)
                        break
                    except ValueError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)


if __name__ == '__main__':
    unittest.main()
