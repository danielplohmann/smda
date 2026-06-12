#!/usr/bin/env python3
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Compare SMDA performance and correctness results")
    parser.add_argument("pr_results", type=str, help="Path to PR results JSON")
    parser.add_argument("base_results", type=str, help="Path to base results JSON")
    parser.add_argument(
        "--threshold-warn", type=float, default=0.20, help="Slowdown warning threshold (e.g. 0.20 for 20%)"
    )
    parser.add_argument(
        "--threshold-fail", type=float, default=0.50, help="Slowdown failure threshold (e.g. 0.50 for 50%)"
    )
    args = parser.parse_args()

    try:
        with open(args.pr_results) as f:
            pr_data = json.load(f)
    except Exception as e:
        print(f"Error reading PR results JSON: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.base_results) as f:
            base_data = json.load(f)
    except Exception as e:
        print(f"Error reading Base results JSON: {e}", file=sys.stderr)
        sys.exit(1)

    correctness_failed = False
    perf_failed = False

    print("\n=== SMDA BENCHMARK COMPARISON ===")
    print(f"Comparing PR results ({args.pr_results}) with Base results ({args.base_results})\n")

    headers = ["Fixture", "Base Median", "PR Median", "Diff (s)", "Change (%)", "Perf Status", "Correctness"]
    row_fmt = "{:<12} | {:<11} | {:<11} | {:<10} | {:<10} | {:<13} | {:<12}"
    print(row_fmt.format(*headers))
    print("-" * 90)

    overall_base_time = 0
    overall_pr_time = 0

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
        if pct_change > (args.threshold_fail * 100):
            perf_status = "FAIL (REGRESS)"
            perf_failed = True
        elif pct_change > (args.threshold_warn * 100):
            perf_status = "WARN"
        elif pct_change < -5:
            perf_status = "OK (IMPROVED)"
        else:
            perf_status = "OK"

        # Check correctness
        corr_status = "MATCH"
        mismatches = []

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

    # Exit codes
    if correctness_failed:
        print("❌ Correctness checks failed! Output results do not match.", file=sys.stderr)
        sys.exit(1)
    if perf_failed:
        print("❌ Performance checks failed! Severe performance regression detected.", file=sys.stderr)
        sys.exit(2)

    print("✅ All checks passed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
