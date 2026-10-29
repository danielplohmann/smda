#!/usr/bin/env python3
"""Instruction-count benchmark for SMDA, measured under callgrind.

Wall time on a shared runner moves by tens of percent between identical runs, which is
why the fixture gate cannot fail below 30%. The number of instructions executed does
not depend on the runner: with hash randomization pinned and a warm-up pass run first, the
same tree repeats to within a few parts per million, and the same code checked out at
two different paths agrees to within about a million instructions, a fraction of a
percent on every fixture but the smallest. So it can flag a regression of a couple of
percent that timing never would.

``measure`` runs each fixture once under ``valgrind --tool=callgrind`` from a given source
tree, plus one import-only run of the same tree, and writes the totals as JSON. The
fixture cost is the run minus the import baseline, so a change to import time shows up
on its own row instead of inflating every fixture. ``compare`` reads a base and a PR
result and fails when a fixture or the total grows past the threshold.

Callgrind attributes cost to the interpreter's C frames rather than Python functions, so
the count says whether a change got slower; the cProfile toolkit in profiling/ says where.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

DEFAULT_TARGETS = [
    "asprox",
    "cutwail",
    "bashlite",
    "blockblast",
    "komplex",
    "njrat",
    "pe_export",
    "aarch64_static",
    "arm_mixed",
    "arm_thumb",
]
IMPORT_ROW = "(import)"
TOTAL_ROW = "TOTAL"

_TOTALS_RE = re.compile(rb"^(?:summary|totals):\s*(\d+)", re.MULTILINE)


def read_total(callgrind_out):
    """Return the Ir total from a callgrind output file."""
    with open(callgrind_out, "rb") as f:
        match = _TOTALS_RE.search(f.read())
    if match is None:
        raise ValueError(f"no summary line in {callgrind_out}")
    return int(match.group(1))


def _run_env():
    env = dict(os.environ, PYTHONHASHSEED="0")
    # the tree's own profiling/_target.py puts its src/ first on sys.path, but an
    # inherited PYTHONPATH would still be searched ahead of the editable install
    env.pop("PYTHONPATH", None)
    return env


def _callgrind(tree, out_file, python_args):
    env = _run_env()
    command = ["valgrind", "--tool=callgrind", f"--callgrind-out-file={out_file}", sys.executable, *python_args]
    result = subprocess.run(command, cwd=tree, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        tail = "\n".join(result.stderr.splitlines()[-20:])
        raise RuntimeError(f"{' '.join(python_args)} failed in {tree} (exit {result.returncode}):\n{tail}")
    return read_total(out_file)


def measure(tree, targets, out_dir, jobs):
    """Measure the import baseline and each target from `tree`; return the result dict."""
    tree = os.path.abspath(tree)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    # The first process to import a module without a bytecode cache also compiles it.
    # That covers the tree and any installed module no earlier run has imported, so
    # whichever measured run got there first, on whichever side, paid for it. One
    # unmeasured pass over every target leaves nothing to compile.
    env = _run_env()
    known_targets = json.loads(
        subprocess.check_output(
            [
                sys.executable,
                "-c",
                "import json; from profiling._target import FIXTURES; print(json.dumps(list(FIXTURES)))",
            ],
            cwd=tree,
            env=env,
            text=True,
        )
    )
    available = [target for target in targets if target in known_targets or os.path.isfile(os.path.join(tree, target))]
    warmups = [
        subprocess.Popen(
            [sys.executable, "-m", "profiling.profile_smda", "run", "--target", target],
            cwd=tree,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for target in available
    ]
    warmup_statuses = [warmup.wait() for warmup in warmups]
    for target, status in zip(available, warmup_statuses, strict=True):
        if status:
            raise RuntimeError(f"warm-up failed for {target} in {tree} (exit {status})")

    def run_one(target):
        out_file = os.path.join(out_dir, f"callgrind.{target}.out")
        if target == IMPORT_ROW:
            out_file = os.path.join(out_dir, "callgrind.import.out")
            return target, _callgrind(tree, out_file, ["-c", "import profiling._target"])
        return target, _callgrind(tree, out_file, ["-m", "profiling.profile_smda", "run", "--target", target])

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        raw = dict(pool.map(run_one, [IMPORT_ROW, *available]))

    baseline = raw[IMPORT_ROW]
    if baseline is None:
        raise RuntimeError(f"import baseline failed in {tree}")
    fixtures = {}
    for target in targets:
        total = raw.get(target)
        fixtures[target] = None if total is None else {"total": total, "net": total - baseline}
    return {"python": sys.version.split()[0], "import": baseline, "fixtures": fixtures}


def compare(base, pr, threshold_warn, threshold_fail, min_absolute=0):
    """Return (markdown, failed) for a base and a PR result.

    A row other than TOTAL also has to grow by `min_absolute` instructions before its
    percentage counts: allocator state differs slightly between two checkouts, which
    moves every run by around a million instructions, and on the smallest fixture
    that alone is a few percent.
    """
    rows = [(IMPORT_ROW, base["import"], pr["import"])]
    base_sum = pr_sum = 0
    for target in sorted(set(base["fixtures"]) | set(pr["fixtures"])):
        b = base["fixtures"].get(target)
        p = pr["fixtures"].get(target)
        b_net = b["net"] if b else None
        p_net = p["net"] if p else None
        if b_net is not None and p_net is not None:
            base_sum += b_net
            pr_sum += p_net
        rows.append((target, b_net, p_net))
    rows.append((TOTAL_ROW, base_sum, pr_sum))

    lines = [
        "## Instruction counts (callgrind)",
        "",
        "Fixture rows are net of the import baseline; TOTAL sums the fixtures present on both sides.",
        "",
        "| Target | Base Ir | PR Ir | Change | Status |",
        "|---|---:|---:|---:|---|",
    ]
    failed = False
    for target, b, p in rows:
        if b is None or p is None:
            lines.append(f"| {target} | {_fmt(b)} | {_fmt(p)} | n/a | only on one side |")
            continue
        change = (p - b) / b if b else 0.0
        significant = target == TOTAL_ROW or p - b > min_absolute
        if significant and change > threshold_fail:
            status = "FAIL"
            failed = True
        elif significant and change > threshold_warn:
            status = "warn"
        else:
            status = "ok"
        lines.append(f"| {target} | {_fmt(b)} | {_fmt(p)} | {change:+.2%} | {status} |")
    lines.append("")
    return "\n".join(lines), failed


def _fmt(value):
    return "-" if value is None else f"{value:,}"


def main():
    parser = argparse.ArgumentParser(description="Instruction-count benchmark for SMDA under callgrind")
    sub = parser.add_subparsers(dest="command", required=True)

    p_measure = sub.add_parser("measure", help="measure one source tree")
    p_measure.add_argument("tree", help="repository root to measure (must contain profiling/ and src/)")
    p_measure.add_argument("--output", required=True, help="path of the JSON result")
    p_measure.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS, help="fixture names")
    p_measure.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="parallel callgrind runs")

    p_compare = sub.add_parser("compare", help="compare a PR result against a base result")
    p_compare.add_argument("pr_results")
    p_compare.add_argument("base_results")
    p_compare.add_argument("--threshold-warn", type=float, default=0.01, help="growth that warns (0.01 = 1%%)")
    p_compare.add_argument("--threshold-fail", type=float, default=0.02, help="growth that fails (0.02 = 2%%)")
    p_compare.add_argument(
        "--min-absolute",
        type=int,
        default=5_000_000,
        help="instructions a row other than TOTAL must also grow by before its percentage counts",
    )

    args = parser.parse_args()

    if args.command == "measure":
        out_dir = os.path.dirname(os.path.abspath(args.output))
        result = measure(args.tree, args.targets, out_dir, args.jobs)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(json.dumps(result, indent=2))
        return 0

    with open(args.pr_results) as f:
        pr = json.load(f)
    with open(args.base_results) as f:
        base = json.load(f)
    markdown, failed = compare(base, pr, args.threshold_warn, args.threshold_fail, args.min_absolute)
    print(markdown)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(markdown + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
