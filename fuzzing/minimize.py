"""Shrink a crashing input to a smaller input that fails the same way.

libFuzzer's ``-minimize_crash=1`` is unusable with atheris (it re-executes
argv[0], which is the interpreter rather than the harness), and it would only
work on Linux CI anyway. This is a plain delta-debugging loop over the target
bodies in targets.py, so it runs anywhere and produces the small reproducer that
gets pinned under tests/fuzz_regressions/.

    python fuzzing/minimize.py loaders artifacts/crash-abc -o crash-min

"Fails the same way" means the same exception type, deliberately ignoring the
message and traceback: a shrunken input often reports different offsets while
hitting the identical defect.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from targets import TARGETS  # noqa: E402


def failure_type(target, data):
    """Return the exception type a target raises for data, or None if it passes."""
    try:
        target(data)
    except BaseException as exc:  # noqa: BLE001 - classifying, not handling
        return type(exc)
    return None


def shrink(data, predicate, max_rounds=64):
    """Delta-debug data down while predicate(candidate) stays True.

    Removes shrinking-sized chunks, then trims single bytes from both ends, and
    repeats until a full round makes no progress.
    """
    best = data
    for _ in range(max_rounds):
        progressed = False
        chunk = max(len(best) // 2, 1)
        while chunk >= 1:
            offset = 0
            while offset < len(best):
                candidate = best[:offset] + best[offset + chunk :]
                if candidate != best and predicate(candidate):
                    best = candidate
                    progressed = True
                else:
                    offset += chunk
            chunk //= 2
        if not progressed:
            break
    return best


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("artifact", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="defaults to <artifact>.min")
    args = parser.parse_args()

    target = TARGETS[args.target]
    data = args.artifact.read_bytes()
    expected = failure_type(target, data)
    if expected is None:
        print(f"{args.artifact} does not fail the {args.target} target; nothing to minimize")
        return 1

    minimized = shrink(data, lambda candidate: failure_type(target, candidate) is expected)
    output = args.output or args.artifact.with_suffix(args.artifact.suffix + ".min")
    output.write_bytes(minimized)
    print(f"{expected.__name__}: {len(data)} -> {len(minimized)} bytes, wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
