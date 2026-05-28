#!/usr/bin/env python3
"""Compare base/head pyperf runs and write a concise PR comment body."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

import pyperf

MARKER = "<!-- smda-performance-gate -->"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pyperf_mean(path: Path) -> tuple[float, float]:
    suite = pyperf.BenchmarkSuite.load(str(path))
    benchmarks = suite.get_benchmarks()
    if len(benchmarks) != 1:
        raise ValueError(f"{path} should contain exactly one benchmark, found {len(benchmarks)}")
    benchmark = benchmarks[0]
    try:
        stdev = benchmark.stdev()
    except statistics.StatisticsError:
        stdev = 0.0
    return benchmark.mean(), stdev


def percent_delta(base_value: float, head_value: float) -> float:
    if base_value == 0:
        return 0.0
    return ((head_value - base_value) / base_value) * 100.0


def format_seconds(value: float) -> str:
    return f"{value:.3f}s"


def format_seconds_with_stdev(mean: float, stdev: float) -> str:
    return f"{mean:.3f}s +/- {stdev:.3f}s"


def format_percent(value: float) -> str:
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.2f}%"


def format_int_delta(base_value: int, head_value: int) -> str:
    delta = head_value - base_value
    sign = "+" if delta > 0 else ""
    return f"{sign}{delta}"


def status_text(summary: dict[str, Any]) -> str:
    counts = summary.get("status_counts") or {}
    if not counts:
        return "none"
    return ", ".join(f"{key}:{counts[key]}" for key in sorted(counts))


def build_result(args: argparse.Namespace) -> dict[str, Any]:
    base_mean, base_stdev = load_pyperf_mean(args.base_pyperf)
    head_mean, head_stdev = load_pyperf_mean(args.head_pyperf)
    base_summary = read_json(args.base_summary)
    head_summary = read_json(args.head_summary)
    runtime_delta_percent = percent_delta(base_mean, head_mean)
    execution_delta_percent = percent_delta(
        float(base_summary.get("total_report_execution_time") or 0.0),
        float(head_summary.get("total_report_execution_time") or 0.0),
    )
    threshold_percent = float(args.threshold_percent)
    status_mismatch = (base_summary.get("status_counts") or {}) != (head_summary.get("status_counts") or {})
    target_mismatch = int(base_summary.get("target_count") or 0) != int(head_summary.get("target_count") or 0)
    exception_count = int(base_summary.get("exception_count") or 0) + int(head_summary.get("exception_count") or 0)
    performance_degraded = runtime_delta_percent > threshold_percent
    failed = performance_degraded or status_mismatch or target_mismatch or exception_count > 0
    reasons = []
    if performance_degraded:
        reasons.append(f"pyperf mean regressed by {format_percent(runtime_delta_percent)}")
    if status_mismatch:
        reasons.append("base/head status counts differ")
    if target_mismatch:
        reasons.append("base/head target counts differ")
    if exception_count:
        reasons.append(f"{exception_count} runner exceptions were recorded")
    return {
        "failed": failed,
        "result": "FAIL" if failed else "PASS",
        "reasons": reasons,
        "threshold_percent": threshold_percent,
        "pyperf": {
            "base_mean": base_mean,
            "base_stdev": base_stdev,
            "head_mean": head_mean,
            "head_stdev": head_stdev,
            "delta_percent": runtime_delta_percent,
        },
        "smda_execution": {
            "base_total": float(base_summary.get("total_report_execution_time") or 0.0),
            "head_total": float(head_summary.get("total_report_execution_time") or 0.0),
            "delta_percent": execution_delta_percent,
        },
        "corpus": {
            "base_targets": int(base_summary.get("target_count") or 0),
            "head_targets": int(head_summary.get("target_count") or 0),
            "base_status": status_text(base_summary),
            "head_status": status_text(head_summary),
            "exceptions": exception_count,
        },
        "output_shape": {
            "base_functions": int(base_summary.get("total_functions") or 0),
            "head_functions": int(head_summary.get("total_functions") or 0),
            "base_instructions": int(base_summary.get("total_instructions") or 0),
            "head_instructions": int(head_summary.get("total_instructions") or 0),
        },
        "memory": {
            "base_max_rss_kb": int(base_summary.get("max_rss_kb") or 0),
            "head_max_rss_kb": int(head_summary.get("max_rss_kb") or 0),
        },
    }


def build_comment(result: dict[str, Any]) -> str:
    pyperf_result = result["pyperf"]
    execution = result["smda_execution"]
    corpus = result["corpus"]
    shape = result["output_shape"]
    memory = result["memory"]
    reasons = "; ".join(result["reasons"]) if result["reasons"] else "within threshold"
    function_delta = format_int_delta(shape["base_functions"], shape["head_functions"])
    instruction_delta = format_int_delta(shape["base_instructions"], shape["head_instructions"])
    rss_delta = format_int_delta(memory["base_max_rss_kb"], memory["head_max_rss_kb"])
    return "\n".join(
        [
            MARKER,
            "### SMDA Performance Gate",
            "",
            f"Result: **{result['result']}** ({reasons})",
            "",
            "| Metric | Base | PR | Delta |",
            "| --- | ---: | ---: | ---: |",
            (
                "| pyperf mean | "
                f"{format_seconds_with_stdev(pyperf_result['base_mean'], pyperf_result['base_stdev'])} | "
                f"{format_seconds_with_stdev(pyperf_result['head_mean'], pyperf_result['head_stdev'])} | "
                f"{format_percent(pyperf_result['delta_percent'])} |"
            ),
            (
                f"| SMDA reported execution | {format_seconds(execution['base_total'])} | "
                f"{format_seconds(execution['head_total'])} | "
                f"{format_percent(execution['delta_percent'])} |"
            ),
            f"| targets | {corpus['base_targets']} | {corpus['head_targets']} | |",
            f"| functions | {shape['base_functions']} | {shape['head_functions']} | {function_delta} |",
            f"| instructions | {shape['base_instructions']} | {shape['head_instructions']} | {instruction_delta} |",
            f"| max RSS | {memory['base_max_rss_kb']} KB | {memory['head_max_rss_kb']} KB | {rss_delta} KB |",
            "",
            f"Statuses: base `{corpus['base_status']}`, PR `{corpus['head_status']}`.",
            "Artifacts include raw pyperf JSON, per-target metrics, summaries, and comparison JSON.",
            (
                f"Gate fails when pyperf mean is more than "
                f"{result['threshold_percent']:.1f}% slower, or when target/status counts make the "
                "comparison unsafe."
            ),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-pyperf", type=Path, required=True)
    parser.add_argument("--head-pyperf", type=Path, required=True)
    parser.add_argument("--base-summary", type=Path, required=True)
    parser.add_argument("--head-summary", type=Path, required=True)
    parser.add_argument("--threshold-percent", type=float, default=5.0)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--comment-md", type=Path, required=True)
    args = parser.parse_args()

    result = build_result(args)
    args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.comment_md.write_text(build_comment(result) + "\n", encoding="utf-8")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
