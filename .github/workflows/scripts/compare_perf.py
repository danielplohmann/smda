#!/usr/bin/env python3
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Compare SMDA performance and correctness results")
    parser.add_argument("pr_results", type=str, help="Path to PR results JSON")
    parser.add_argument("base_results", type=str, help="Path to base results JSON")
    parser.add_argument(
        "--threshold-warn", type=float, default=0.20, help="Slowdown warning threshold (e.g. 0.20 for 20%%)"
    )
    parser.add_argument(
        "--threshold-fail", type=float, default=0.30, help="Slowdown failure threshold (e.g. 0.30 for 30%%)"
    )
    parser.add_argument(
        "--min-absolute-regression",
        type=float,
        default=0.15,
        help="Seconds a single fixture must also lose before its percentage counts as a "
        "failure. The counterbalanced passes cancel drift but not per-sample variance, so "
        "a sub-second fixture can swing tens of percent on a shared runner without doing "
        "any more work. The OVERALL row carries no such floor.",
    )
    parser.add_argument(
        "--memory-threshold-fail",
        type=float,
        default=0.10,
        help="Peak-memory growth failure threshold (e.g. 0.10 for 10%%). Tighter than the time "
        "threshold because allocation totals barely vary between runs on a shared runner.",
    )
    parser.add_argument(
        "--fail-on-call-count-change",
        action="store_true",
        help="Treat any call-count delta as a failure (useful when bisecting, off by default because "
        "a legitimate optimization changes it on purpose)",
    )
    args = parser.parse_args()

    try:
        with open(args.pr_results, encoding="utf-8") as f:
            pr_data = json.load(f)
    except Exception as e:
        print(f"Error reading PR results JSON: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.base_results, encoding="utf-8") as f:
            base_data = json.load(f)
    except Exception as e:
        print(f"Error reading Base results JSON: {e}", file=sys.stderr)
        sys.exit(1)

    correctness_failed = False
    perf_failed = False
    memory_failed = False
    memory_rows = []
    skipped_memory = []

    print("\n=== SMDA BENCHMARK COMPARISON ===")
    print(f"Comparing PR results ({args.pr_results}) with Base results ({args.base_results})\n")

    headers = ["Fixture", "Base Median", "PR Median", "Diff (s)", "Change (%)", "Perf Status", "Correctness"]
    row_fmt = "{:<12} | {:<11} | {:<11} | {:<10} | {:<10} | {:<13} | {:<12}"
    print(row_fmt.format(*headers))
    print("-" * 90)

    overall_base_time = 0.0
    overall_pr_time = 0.0
    call_count_rows = []
    call_count_changed = False
    skipped_call_counts = []

    all_fixtures = set(base_data.keys()).union(pr_data.keys())
    for name in sorted(all_fixtures):
        if name not in base_data:
            print(f"Warning: Fixture '{name}' is present in PR results but missing from Base results.", file=sys.stderr)
            continue
        if name not in pr_data:
            print(f"Error: Fixture '{name}' is missing from PR results!", file=sys.stderr)
            correctness_failed = True
            continue

        base = base_data[name]
        pr = pr_data[name]

        base_med = base["median_time"]
        pr_med = pr["median_time"]

        overall_base_time += base_med
        overall_pr_time += pr_med

        diff = pr_med - base_med
        pct_change = (diff / base_med) * 100 if base_med > 0 else 0

        # Check performance status
        if pct_change > (args.threshold_fail * 100) and diff >= args.min_absolute_regression:
            perf_status = "FAIL (REGRESS)"
            perf_failed = True
        elif pct_change > (args.threshold_fail * 100):
            perf_status = "WARN (NOISE?)"
        elif pct_change > (args.threshold_warn * 100):
            perf_status = "WARN"
        elif pct_change < -5:
            perf_status = "OK (IMPROVED)"
        else:
            perf_status = "OK"

        # Peak memory is the resource most likely to break a downstream batch consumer,
        # which sizes its worker count by per-file peak, so it gets its own gate.
        base_mem = base.get("median_peak_memory")
        pr_mem = pr.get("median_peak_memory")
        if base_mem and pr_mem:
            mem_change = ((pr_mem - base_mem) / base_mem) * 100
            memory_rows.append((name, base_mem, pr_mem, pr_mem - base_mem, mem_change))
            if mem_change > (args.memory_threshold_fail * 100):
                memory_failed = True
        elif base_mem or pr_mem:
            skipped_memory.append(name)

        # Check correctness
        corr_status = "MATCH"
        mismatches = []

        base_hash = base.get("report_hash", "")
        pr_hash = pr.get("report_hash", "")
        if base_hash and pr_hash and base_hash != pr_hash:
            mismatches.append(f"Report identity hash mismatch: base={base_hash[:16]}, pr={pr_hash[:16]}")

        if base["num_functions"] != pr["num_functions"]:
            mismatches.append(f"Function count mismatch: base={base['num_functions']}, pr={pr['num_functions']}")
        if base["num_instructions"] != pr["num_instructions"]:
            mismatches.append(
                f"Instruction count mismatch: base={base['num_instructions']}, pr={pr['num_instructions']}"
            )
        if base["num_blocks"] != pr["num_blocks"]:
            mismatches.append(f"Block count mismatch: base={base['num_blocks']}, pr={pr['num_blocks']}")

        # Deep check functions
        base_funcs = base.get("functions", {})
        pr_funcs = pr.get("functions", {})

        for addr in base_funcs:
            if addr not in pr_funcs:
                mismatches.append(f"Function {addr} in base, but missing from PR")
            else:
                bf = base_funcs[addr]
                pf = pr_funcs[addr]
                if bf["num_blocks"] != pf["num_blocks"]:
                    mismatches.append(
                        f"Function {addr} block count mismatch: base={bf['num_blocks']}, pr={pf['num_blocks']}"
                    )
                if bf["num_instructions"] != pf["num_instructions"]:
                    mismatches.append(
                        f"Function {addr} instruction count mismatch: base={bf['num_instructions']}, pr={pf['num_instructions']}"
                    )

        for addr in pr_funcs:
            if addr not in base_funcs:
                mismatches.append(f"Function {addr} in PR, but missing from base")

        if mismatches:
            corr_status = "MISMATCH"
            correctness_failed = True
            print(f"\n[CORRECTNESS MISMATCH] in '{name}':")
            for m in mismatches[:10]:
                print(f"  - {m}")
            if len(mismatches) > 10:
                print(f"  - ... and {len(mismatches) - 10} more mismatches")

        base_calls = base.get("total_calls")
        pr_calls = pr.get("total_calls")
        if base_calls is not None and pr_calls is not None:
            if base.get("python_version") != pr.get("python_version"):
                # call counts are only comparable within one interpreter version
                skipped_call_counts.append(name)
            else:
                delta = pr_calls - base_calls
                pct = (delta / base_calls) * 100 if base_calls else 0
                call_count_rows.append((name, base_calls, pr_calls, delta, pct))
                if delta:
                    call_count_changed = True

        print(
            row_fmt.format(
                name,
                f"{base_med:.4f}s",
                f"{pr_med:.4f}s",
                f"{diff:+.4f}s",
                f"{pct_change:+.1f}%",
                perf_status,
                corr_status,
            )
        )

    print("-" * 90)
    # Overall summary
    overall_diff = overall_pr_time - overall_base_time
    overall_change = (overall_diff / overall_base_time) * 100 if overall_base_time > 0 else 0
    overall_perf = "OK"
    if overall_change > (args.threshold_fail * 100):
        overall_perf = "FAIL (REGRESS)"
        perf_failed = True
    elif overall_change > (args.threshold_warn * 100):
        overall_perf = "WARN"

    print(
        row_fmt.format(
            "OVERALL",
            f"{overall_base_time:.4f}s",
            f"{overall_pr_time:.4f}s",
            f"{overall_diff:+.4f}s",
            f"{overall_change:+.1f}%",
            overall_perf,
            "MATCH" if not correctness_failed else "MISMATCH",
        )
    )
    print()

    if memory_rows:
        status = "FAIL" if memory_failed else "OK"
        print(f"=== PEAK MEMORY (gated at {args.memory_threshold_fail * 100:.0f}%: {status}) ===")
        mem_fmt = "{:<12} | {:>14} | {:>14} | {:>14} | {:>9}"
        print(mem_fmt.format("Fixture", "Base Peak", "PR Peak", "Delta", "Change"))
        print("-" * 74)
        for mem_name, base_mem, pr_mem, delta, pct in memory_rows:
            print(
                mem_fmt.format(
                    mem_name,
                    f"{base_mem / 1048576:.1f} MiB",
                    f"{pr_mem / 1048576:.1f} MiB",
                    f"{delta / 1048576:+.1f} MiB",
                    f"{pct:+.2f}%",
                )
            )
        print()
    if skipped_memory:
        print(f"Memory comparison skipped (one side lacks the channel): {', '.join(skipped_memory)}\n")

    if call_count_rows:
        print("=== PYTHON CALL COUNTS (informational) ===")
        cc_fmt = "{:<12} | {:>14} | {:>14} | {:>14} | {:>9}"
        print(cc_fmt.format("Fixture", "Base Calls", "PR Calls", "Delta", "Change"))
        print("-" * 74)
        for cc_name, base_calls, pr_calls, delta, pct in call_count_rows:
            print(cc_fmt.format(cc_name, base_calls, pr_calls, f"{delta:+d}", f"{pct:+.2f}%"))
        print()
    if skipped_call_counts:
        print(f"Call-count comparison skipped (python version differs): {', '.join(skipped_call_counts)}\n")

    # Exit codes
    if correctness_failed:
        print("FAIL: correctness checks failed; output results do not match.", file=sys.stderr)
        sys.exit(1)
    if call_count_changed and args.fail_on_call_count_change:
        print("FAIL: call counts changed and --fail-on-call-count-change was requested.", file=sys.stderr)
        sys.exit(1)
    if perf_failed:
        print("FAIL: performance checks failed; severe performance regression detected.", file=sys.stderr)
        sys.exit(2)
    if memory_failed:
        print("FAIL: peak memory grew beyond the configured threshold.", file=sys.stderr)
        sys.exit(3)

    print("PASS: all checks passed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
