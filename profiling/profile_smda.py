#!/usr/bin/env python3
"""Unified SMDA profiling CLI (profiling layer only).

Subcommands
-----------
  run   Execute the workload once with no profiling. This is the unit that
        external samplers wrap, e.g.:
            py-spy record --native -o out.svg -- \
                python -m profiling.profile_smda run --target asprox
            memray run --native -o out.bin -- \
                python -m profiling.profile_smda run --target asprox
  cpu   cProfile the workload (dumps a .prof, prints top cumulative functions).
        --line additionally runs line_profiler over SMDA's hot functions.
  mem   memray-track the workload (dumps a .bin), plus a tracemalloc top-allocator
        diff and a psutil USS delta.

Outputs land in profiling/output/. See profiling/README.md for platform notes
(py-spy --native is Linux-only; cProfile/line_profiler/memray work locally).
"""

import argparse
import cProfile
import os
import pstats
import sys
import tracemalloc
from pstats import SortKey

from profiling._target import build_workload, resolve_label, run_workload

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _print_report_summary(report):
    if report is None:
        print("  (no report produced)")
        return
    status = getattr(report, "status", "ok")
    print(
        f"  status={status} "
        f"functions={report.num_functions} "
        f"blocks={report.num_blocks} "
        f"instructions={report.num_instructions}"
    )


def _hot_functions():
    """SMDA functions worth a line-by-line view. Resolved lazily and defensively
    so a future rename degrades to 'skipped', not a crash."""
    funcs = []
    try:
        from smda.intel.IntelDisassembler import IntelDisassembler

        funcs += [IntelDisassembler.analyzeFunction, IntelDisassembler.analyzeBuffer]
    except (ImportError, AttributeError) as exc:
        print(f"  [line] skipped IntelDisassembler hot functions: {exc}", file=sys.stderr)
    try:
        from smda.intel.FunctionCandidateManager import FunctionCandidateManager

        funcs += [
            FunctionCandidateManager.isFunctionCandidate,
            FunctionCandidateManager.getNextFunctionStartCandidate,
            FunctionCandidateManager.locateCandidates,
        ]
    except (ImportError, AttributeError) as exc:
        print(f"  [line] skipped FunctionCandidateManager hot functions: {exc}", file=sys.stderr)
    try:
        from smda.utility import StringExtractor

        funcs += [StringExtractor.extract_strings, StringExtractor.read_string]
    except (ImportError, AttributeError) as exc:
        print(f"  [line] skipped StringExtractor hot functions: {exc}", file=sys.stderr)
    return funcs


def cmd_run(args):
    print(f"Running SMDA on '{args.target}' x{args.iterations} (no profiling)...")
    report = run_workload(args.target, iterations=args.iterations, with_strings=args.strings)
    _print_report_summary(report)
    if report is not None and getattr(report, "status", "ok") not in ("ok", None):
        return 1
    return 0


def cmd_cpu(args):
    _ensure_output_dir()
    label = resolve_label(args.target)
    workload = build_workload(args.target, with_strings=args.strings)

    print(f"cProfile: '{args.target}' x{args.iterations}...")
    report = None
    with cProfile.Profile() as profiler:
        for _ in range(max(1, args.iterations)):
            report = workload()
    _print_report_summary(report)

    prof_path = os.path.join(OUTPUT_DIR, f"{label}.cpu.prof")
    stats = pstats.Stats(profiler).sort_stats(SortKey.CUMULATIVE)
    stats.dump_stats(prof_path)
    print(f"\nTop {args.top} functions by cumulative time:")
    stats.print_stats(args.top)
    print(f"Saved: {prof_path}")
    print(f"View interactively: snakeviz {prof_path}")

    if args.line:
        _run_line_profiler(args, workload)
    return 0


def _run_line_profiler(args, workload):
    try:
        from line_profiler import LineProfiler
    except ImportError:
        print(
            "\n[line] line_profiler not installed. Install with: pip install -e '.[profile]'",
            file=sys.stderr,
        )
        return
    hot = _hot_functions()
    if not hot:
        print("[line] no hot functions could be registered; skipping.", file=sys.stderr)
        return
    print(f"\nline_profiler over {len(hot)} hot function(s)...")
    lp = LineProfiler()
    for fn in hot:
        lp.add_function(fn)
    lp_wrapper = lp(workload)
    lp_wrapper()
    lp.print_stats(output_unit=1e-3)


def cmd_mem(args):
    _ensure_output_dir()
    label = resolve_label(args.target)
    workload = build_workload(args.target, with_strings=args.strings)

    try:
        import memray
    except ImportError:
        print(
            "memray not installed. Install with: pip install -e '.[profile]'",
            file=sys.stderr,
        )
        return 1

    bin_path = os.path.join(OUTPUT_DIR, f"{label}.mem.bin")
    if os.path.exists(bin_path):
        os.remove(bin_path)  # memray refuses to overwrite an existing capture

    uss_before = _uss()
    tracemalloc.start()
    try:
        snap_before = tracemalloc.take_snapshot()

        print(f"memray (native_traces={args.native}): '{args.target}' x{args.iterations}...")
        report = None
        with memray.Tracker(bin_path, native_traces=args.native):
            for _ in range(max(1, args.iterations)):
                report = workload()

        snap_after = tracemalloc.take_snapshot()
    finally:
        tracemalloc.stop()
    uss_after = _uss()
    _print_report_summary(report)

    print(f"\nTop {args.top} Python allocators (tracemalloc, by line):")
    for stat in snap_after.compare_to(snap_before, "lineno")[: args.top]:
        print(f"  {stat}")

    if uss_before is not None and uss_after is not None:
        print(f"\nUSS delta: {(uss_after - uss_before) / 1024 / 1024:+.2f} MiB (peak private memory growth)")

    print(f"\nSaved: {bin_path}")
    print(f"Generate flamegraph: memray flamegraph {bin_path}")
    print(f"Allocation table:    memray table {bin_path}")
    return 0


def _uss():
    """Private (USS) memory in bytes, or None if psutil is unavailable.

    USS is preferred over RSS here: LIEF's memory-mapped files and shared
    libraries inflate RSS, while USS reflects this process's own footprint.
    """
    try:
        import psutil
    except ImportError:
        print("[mem] psutil not installed; skipping USS delta.", file=sys.stderr)
        return None
    return psutil.Process().memory_full_info().uss


def build_parser():
    parser = argparse.ArgumentParser(
        prog="profile_smda",
        description="Profile SMDA disassembly (CPU/memory). Reuses the existing benchmark fixtures.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument(
            "--target",
            default="asprox",
            help="Fixture name (asprox, cutwail, bashlite, blockblast, komplex, njrat, pe_export) "
            "or a path to a binary.",
        )
        p.add_argument("--iterations", type=int, default=1, help="Number of disassembly passes.")
        p.add_argument("--strings", action="store_true", help="Enable string extraction (config.WITH_STRINGS).")

    p_run = sub.add_parser("run", help="Run the workload with no profiling (wrap with py-spy/memray).")
    add_common(p_run)
    p_run.set_defaults(func=cmd_run)

    p_cpu = sub.add_parser("cpu", help="cProfile the workload (+ optional line_profiler).")
    add_common(p_cpu)
    p_cpu.add_argument("--top", type=int, default=25, help="How many top functions to print.")
    p_cpu.add_argument("--line", action="store_true", help="Also run line_profiler over SMDA hot functions.")
    p_cpu.set_defaults(func=cmd_cpu)

    p_mem = sub.add_parser("mem", help="memray + tracemalloc + USS for the workload.")
    add_common(p_mem)
    p_mem.add_argument("--top", type=int, default=25, help="How many top allocators to print.")
    p_mem.add_argument(
        "--native",
        action="store_true",
        help="Capture native (C/C++) frames into Capstone/LIEF. Best on Linux.",
    )
    p_mem.set_defaults(func=cmd_mem)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
