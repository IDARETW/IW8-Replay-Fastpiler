"""Keep compiler ownership until the child exits, even after server interruption."""
from pathlib import Path
import argparse
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workstation.build_lock import compiler_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('A compiler command is required')
    try:
        with compiler_lock(args.lock):
            return subprocess.call(command)
    except ValueError as error:
        print(str(error), file=sys.stderr, flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
