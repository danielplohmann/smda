"""Replay crash artifacts against a fuzz target without atheris.

atheris publishes no arm64/macOS wheels, so a crash found in CI would otherwise
be undebuggable on a developer machine. This runs the identical target body over
files on disk:

    python fuzzing/replay.py loaders artifacts/crash-*

Files whose name ends in ``_xored`` are decoded with the repository fixture XOR
scheme first, which is how a reproducer is committed under
tests/fuzz_regressions/ (raw samples are never stored in the tree).
"""

import argparse
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from targets import TARGETS  # noqa: E402


def decode(path):
    data = path.read_bytes()
    if path.name.endswith("_xored"):
        return bytes(byte ^ (index % 256) for index, byte in enumerate(data))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    target = TARGETS[args.target]
    failures = 0
    for path in args.paths:
        if not path.is_file():
            print(f"SKIP {path} (not a file)")
            continue
        try:
            target(decode(path))
        except Exception:
            failures += 1
            print(f"FAIL {path}")
            traceback.print_exc()
        else:
            print(f"OK   {path}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
