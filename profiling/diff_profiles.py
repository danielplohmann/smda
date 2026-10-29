"""Compare two cProfile dumps of the same workload function by function.

The profile job used to profile the PR only, which shows where the time goes but not
what changed. Given the base and the PR profile of one target, this lists the
functions whose own time moved most, with their call counts. Call counts are exact
for a given input, so a changed count is a real change in the work done; own-time
deltas are wall time and carry the runner's noise.

    python -m profiling.diff_profiles base.cpu.prof pr.cpu.prof --top 20

Functions are matched by file and name, with the checkout path and line numbers
left out, so two checkouts of different versions line up.
"""

import argparse
import pstats
import re
import sys

_ANCHORS = ("/site-packages/", "/smda/", "/profiling/")
# builtins and C-level functions are named with their address, e.g.
# "<built-in method __new__ of type object at 0x7f1e604496e0>", which differs per process
_ADDRESS = re.compile(r" at 0x[0-9a-f]+")


def _normalize(key):
    """Key a function by file and name, without the checkout path or line number.

    Lines move whenever code above a function changes, which would split one function
    into a removed and an added row; two functions of one name in one file are merged.
    The path is cut at the anchor that occurs last, so a base tree checked out inside
    the PR tree (smda/base-repo/profiling/...) lines up with the PR's profiling/...
    """
    filename, _line, name = key
    position = max(filename.rfind(anchor) for anchor in _ANCHORS)
    if position >= 0:
        filename = filename[position + 1 :]
    return filename, _ADDRESS.sub("", name)


def load(path):
    """Return {(file, function): (calls, own seconds)} for a cProfile dump."""
    # pstats.Stats carries the raw table at runtime; typeshed does not declare it
    stats = pstats.Stats(path).stats  # ty: ignore[unresolved-attribute]
    merged = {}
    for key, (_, calls, own, _cumulative, _callers) in stats.items():
        norm = _normalize(key)
        previous_calls, previous_own = merged.get(norm, (0, 0.0))
        merged[norm] = (previous_calls + calls, previous_own + own)
    return merged


def diff(base, pr, top):
    """Return markdown rows for the `top` functions by absolute own-time change."""
    rows = []
    for key in base.keys() | pr.keys():
        base_calls, base_own = base.get(key, (0, 0.0))
        pr_calls, pr_own = pr.get(key, (0, 0.0))
        rows.append((pr_own - base_own, key, base_calls, pr_calls, base_own, pr_own))
    rows.sort(key=lambda row: abs(row[0]), reverse=True)

    base_total = sum(own for _, own in base.values())
    pr_total = sum(own for _, own in pr.values())
    changed_calls = sum(1 for row in rows if row[2] != row[3])
    lines = [
        f"Total own time: base {base_total:.3f}s, PR {pr_total:.3f}s ({pr_total - base_total:+.3f}s). "
        f"{changed_calls} function(s) changed call count.",
        "",
        "| Function | Calls base | Calls PR | Own base (s) | Own PR (s) | Change (s) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for delta, (filename, name), base_calls, pr_calls, base_own, pr_own in rows[:top]:
        calls = f"**{pr_calls}**" if pr_calls != base_calls else str(pr_calls)
        lines.append(f"| `{name}` {filename} | {base_calls} | {calls} | {base_own:.4f} | {pr_own:.4f} | {delta:+.4f} |")
    lines.append("")
    lines.append("Bold call counts differ from base; those changes are exact, own-time changes are not.")

    by_calls = sorted((row for row in rows if row[2] != row[3]), key=lambda row: abs(row[3] - row[2]), reverse=True)
    if by_calls:
        lines += [
            "",
            "Largest call-count changes:",
            "",
            "| Function | Calls base | Calls PR | Change |",
            "| --- | ---: | ---: | ---: |",
        ]
        for _, (filename, name), base_calls, pr_calls, _, _ in by_calls[:top]:
            lines.append(f"| `{name}` {filename} | {base_calls} | {pr_calls} | {pr_calls - base_calls:+d} |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("base", help="cProfile dump of the base tree")
    parser.add_argument("pr", help="cProfile dump of the PR tree")
    parser.add_argument("--top", type=int, default=20, help="how many functions to list")
    args = parser.parse_args(argv)
    print(diff(load(args.base), load(args.pr), args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
