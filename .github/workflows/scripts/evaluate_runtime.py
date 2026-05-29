#!/usr/bin/env python3
"""
Runtime efficiency evaluation script for SMDA.

Compares SMDA reports generated on the base branch vs the PR branch over the
same set of samples, each disassembled several times (``base_0..N`` / ``pr_0..N``
folders under ``runtime_measurements/``). It then:

  * verifies each side is internally deterministic (function-address sets agree
    across repeated runs of the same code),
  * compares correctness between base and PR (function-address sets), and
  * compares performance with a PAIRED, per-file design using min-of-runs as a
    low-noise estimator, reporting a bootstrap confidence interval and a
    Wilcoxon signed-rank test.

Outputs (under ``runtime_measurements/cache/``): ``evaluation.{json,html,md}``.

Exit codes (gating can be disabled with ``--no-gate`` or ``SMDA_BENCH_GATE=0``):
  0  ok                       1  PR correctness regression vs base
  2  non-determinism          3  no comparable data (only with ``--require-data``)

All statistics are pure-Python (``statistics`` + ``random``); no third-party deps.
"""

import argparse
import hashlib
import json
import math
import os
import random
import re
import statistics
import sys
from datetime import datetime
from pathlib import Path

BASE_PATH = Path(__file__).resolve().parent.parent.parent.parent
RUNTIME_PATH = BASE_PATH / "runtime_measurements"
CACHE_PATH = RUNTIME_PATH / "cache"

SCHEMA_VERSION = 2


# Version name mapping - rename pr_* and base_* for stability
def get_version_name(folder_name):
    """Map folder names to stable version identifiers."""
    if folder_name.startswith("pr_"):
        return "pr"
    elif folder_name.startswith("base_"):
        return "base"
    return folder_name


def compute_file_hash(filepath):
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_five_num_summary(values):
    """Compute 5-number summary (min, Q1, median, Q3, max)."""
    if not values:
        return {"min": 0, "q1": 0, "median": 0, "q3": 0, "max": 0}
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    return {
        "min": sorted_vals[0],
        "q1": statistics.median(sorted_vals[: n // 2]) if n > 1 else sorted_vals[0],
        "median": statistics.median(sorted_vals),
        "q3": statistics.median(sorted_vals[(n + 1) // 2 :]) if n > 1 else sorted_vals[0],
        "max": sorted_vals[-1],
    }


def parse_report(filepath):
    """Parse a single SMDA JSON report and extract precomputed values.

    Note: ``xcfg[addr]["blocks"]`` is serialized by ``SmdaFunction.toDict()`` as a
    dict ``{block_offset: [instructions]}``, so ``len(blocks)`` is the number of
    basic blocks. We keep that count for throughput context, but correctness is
    compared via the set of function addresses (the keys of ``block_counts``).
    """
    with open(filepath) as f:
        data = json.load(f)

    xcfg = data.get("xcfg", {})
    total_blocks = 0
    block_counts = {}
    for addr, func_data in xcfg.items():
        blocks = func_data.get("blocks", [])
        num_blocks = len(blocks)
        block_counts[addr] = num_blocks
        total_blocks += num_blocks

    exec_time = data.get("execution_time", 0)

    return {
        "function_count": len(block_counts),
        "block_counts": block_counts,
        "total_blocks": total_blocks,
        "execution_time": exec_time,
        "file_hash": compute_file_hash(filepath),
    }


def get_cache_key(folder_name):
    """Generate cache file path for a folder."""
    return CACHE_PATH / folder_name / "cache.json"


def load_from_cache(folder_name):
    """Load precomputed data from cache if valid (local-iteration speedup; inert in CI)."""
    cache_file = get_cache_key(folder_name)
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return None


_RUN_DIR_RE = re.compile(r"^(base|pr)_\d+$")


def discover_run_folders(runtime_path):
    """Find ``base_N`` / ``pr_N`` run folders under ``runtime_path``.

    Searches recursively (the shallowest match per name wins) so it is robust to
    however the CI artifact download nests the directories. The ``cache`` folder
    is skipped so our own evaluation cache is never mistaken for a run.
    """
    found = {}
    for path in runtime_path.rglob("*"):
        if not path.is_dir() or "cache" in path.parts:
            continue
        if _RUN_DIR_RE.match(path.name):
            current = found.get(path.name)
            if current is None or len(path.parts) < len(current.parts):
                found[path.name] = path
    return found


def cache_reports(folder_path):
    """Parse (and cache) all .smda reports for a folder.

    Returns ``{filename: parsed_report}``. The on-disk cache is keyed on file
    hashes; it speeds up local re-runs but is inert in ephemeral CI (fresh tree
    each run).
    """
    folder_name = folder_path.name
    cache_file = get_cache_key(folder_name)

    cached = load_from_cache(folder_name)
    if cached is not None:
        all_valid = True
        for filename, cached_info in cached.items():
            filepath = folder_path / filename
            if not filepath.exists() or compute_file_hash(filepath) != cached_info.get("file_hash", ""):
                all_valid = False
                break
        if all_valid:
            return cached

    cache_data = {}
    for json_file in folder_path.glob("*.smda"):
        cache_data[json_file.name] = parse_report(json_file)

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w") as f:
        json.dump(cache_data, f, indent=2)

    return cache_data


# --------------------------------------------------------------------------- #
# Aggregation, determinism, pairing and statistics
# --------------------------------------------------------------------------- #


def aggregate_runs(side_caches):
    """Collapse the repeated runs of one side into a single record per file.

    ``side_caches`` is ``{folder_name: {filename: parsed_report}}`` (e.g. the
    three ``base_*`` runs). Only files present in *every* run are kept (others are
    reported as ``dropped``). Timing uses min-of-runs (the minimum is the
    least-noise estimate of true compute cost; wall-time noise is positive-only).

    Returns ``(aggregated, meta)`` where ``aggregated`` is
    ``{filename: {time_min, time_median, times_all, function_addrs, function_count,
    addr_sets}}``.
    """
    folders = sorted(side_caches.keys())
    if not folders:
        return {}, {"folders": [], "dropped": [], "files": 0}

    file_sets = [set(side_caches[f].keys()) for f in folders]
    common = set.intersection(*file_sets) if file_sets else set()
    dropped = sorted(set.union(*file_sets) - common) if file_sets else []

    aggregated = {}
    for filename in sorted(common):
        reps = [side_caches[f][filename] for f in folders]
        times = [float(r.get("execution_time", 0) or 0) for r in reps]
        addr_sets = [frozenset(r.get("block_counts", {}).keys()) for r in reps]
        aggregated[filename] = {
            "time_min": min(times),
            "time_median": statistics.median(times),
            "times_all": times,
            "function_addrs": addr_sets[0],
            "function_count": reps[0].get("function_count", len(addr_sets[0])),
            "addr_sets": addr_sets,
        }
    meta = {"folders": folders, "dropped": dropped, "files": len(aggregated)}
    return aggregated, meta


def check_determinism(aggregated):
    """Self-check: do repeated runs of the same code agree on the function set?

    Returns a dict with ``is_deterministic``, the list of disagreeing files, and
    an informational median timing coefficient of variation (timing is expected
    to vary and never marks the side non-deterministic).
    """
    disagreeing = []
    cvs = []
    for filename, agg in aggregated.items():
        addr_sets = agg["addr_sets"]
        if any(s != addr_sets[0] for s in addr_sets[1:]):
            disagreeing.append(
                {
                    "file": filename,
                    "function_counts": [len(s) for s in addr_sets],
                }
            )
        times = agg["times_all"]
        if len(times) > 1:
            mean_t = statistics.fmean(times)
            if mean_t > 0:
                cvs.append(statistics.pstdev(times) / mean_t)

    return {
        "files_checked": len(aggregated),
        "runs": len(next(iter(aggregated.values()))["addr_sets"]) if aggregated else 0,
        "is_deterministic": not disagreeing,
        "files_disagreeing": disagreeing,
        "median_timing_cv": statistics.median(cvs) if cvs else 0.0,
    }


def build_paired(base_agg, pr_agg):
    """Pair base vs PR on common files. Correctness uses function-address sets;
    timing uses per-file min-of-runs. Returns parallel lists + mismatch records."""
    common = sorted(set(base_agg) & set(pr_agg))
    only_in_base = sorted(set(base_agg) - set(pr_agg))
    only_in_pr = sorted(set(pr_agg) - set(base_agg))

    base_times, pr_times, speedups, timed_files = [], [], [], []
    regressions, degenerate = [], []

    for filename in common:
        b = base_agg[filename]
        p = pr_agg[filename]

        if b["function_addrs"] != p["function_addrs"]:
            regressions.append(
                {
                    "file": filename,
                    "base_count": b["function_count"],
                    "pr_count": p["function_count"],
                    "only_in_base": sorted(b["function_addrs"] - p["function_addrs"]),
                    "only_in_pr": sorted(p["function_addrs"] - b["function_addrs"]),
                }
            )

        bt, pt = b["time_min"], p["time_min"]
        if bt > 0 and pt >= 0:
            base_times.append(bt)
            pr_times.append(pt)
            speedups.append((bt - pt) / bt * 100.0)
            timed_files.append(filename)
        else:
            degenerate.append(filename)

    return {
        "common_files": common,
        "only_in_base": only_in_base,
        "only_in_pr": only_in_pr,
        "timed_files": timed_files,
        "base_times": base_times,
        "pr_times": pr_times,
        "speedups": speedups,
        "regressions": regressions,
        "degenerate": degenerate,
    }


def bootstrap_ci(values, statistic, n_resamples=10000, confidence=0.95, seed=12345):
    """Percentile bootstrap CI for ``statistic`` over ``values``.

    Deterministic via a fixed seed so the report is reproducible. Returns
    ``(lo, hi)``; degenerate inputs return ``(point, point)`` or ``(0, 0)``.
    """
    n = len(values)
    if n == 0:
        return (0.0, 0.0)
    if n == 1:
        return (float(values[0]), float(values[0]))

    rng = random.Random(seed)
    stats = []
    for _ in range(n_resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        stats.append(statistic(sample))
    stats.sort()
    alpha = 1.0 - confidence
    lo_idx = int((alpha / 2.0) * n_resamples)
    hi_idx = min(int((1.0 - alpha / 2.0) * n_resamples), n_resamples - 1)
    return (stats[lo_idx], stats[hi_idx])


def _normal_cdf(x):
    """Standard normal CDF via the error function."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def wilcoxon_signed_rank(base_times, pr_times, min_n=10):
    """Paired Wilcoxon signed-rank test on per-file differences (base - pr).

    Pure-Python normal approximation with average-rank tie handling, zero-diff
    dropping, and continuity + tie correction. Returns ``p_value=None`` (with a
    note) when fewer than ``min_n`` non-zero differences exist, where the
    approximation is unreliable.
    """
    diffs = [b - p for b, p in zip(base_times, pr_times, strict=False)]
    nonzero = [d for d in diffs if d != 0]
    n = len(nonzero)
    n_zero = len(diffs) - n
    if n < min_n:
        return {
            "statistic": None,
            "z": None,
            "p_value": None,
            "n_nonzero": n,
            "n_zero": n_zero,
            "note": f"insufficient samples (n={n} < {min_n}) for normal approximation",
        }

    order = sorted(range(n), key=lambda i: abs(nonzero[i]))
    abs_sorted = [abs(nonzero[i]) for i in order]

    # Average ranks, tracking tie-group sizes for the variance correction.
    ranks = [0.0] * n
    tie_term = 0.0
    i = 0
    while i < n:
        j = i
        while j < n and abs_sorted[j] == abs_sorted[i]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        t = j - i
        tie_term += t**3 - t
        i = j

    w_plus = sum(ranks[k] for k in range(n) if nonzero[order[k]] > 0)
    mu = n * (n + 1) / 4.0
    var = n * (n + 1) * (2 * n + 1) / 24.0 - tie_term / 48.0
    if var <= 0:
        return {
            "statistic": w_plus,
            "z": None,
            "p_value": None,
            "n_nonzero": n,
            "n_zero": n_zero,
            "note": "degenerate variance (all differences tied)",
        }

    sigma = math.sqrt(var)
    # Continuity correction toward the mean.
    cc = 0.5 if w_plus > mu else (-0.5 if w_plus < mu else 0.0)
    z = (w_plus - mu - cc) / sigma
    p_value = 2.0 * (1.0 - _normal_cdf(abs(z)))
    return {
        "statistic": w_plus,
        "z": z,
        "p_value": max(0.0, min(1.0, p_value)),
        "n_nonzero": n,
        "n_zero": n_zero,
        "note": "",
    }


def compute_paired_stats(paired, noise_floor_pct=0.0):
    """Headline timing statistics for the paired comparison.

    ``noise_floor_pct`` is the cross-runner/run-to-run timing noise band (derived
    from the per-side timing CV). Because base and PR are timed on separate CI
    runners, a systematic per-runner speed offset can make a tiny difference look
    statistically "significant"; so a median speedup whose magnitude is within the
    noise floor is reported as inconclusive regardless of the CI/p-value.
    """
    speedups = paired["speedups"]
    m = len(speedups)
    if m == 0:
        return {
            "n": 0,
            "median_speedup": 0.0,
            "mean_speedup": 0.0,
            "stdev_speedup": 0.0,
            "iqr_speedup": 0.0,
            "ci_median": (0.0, 0.0),
            "ci_mean": (0.0, 0.0),
            "noise_floor_pct": noise_floor_pct,
            "wilcoxon": {"p_value": None, "n_nonzero": 0, "note": "no paired samples"},
            "verdict": "no comparable timing data",
        }

    median_speedup = statistics.median(speedups)
    mean_speedup = statistics.fmean(speedups)
    stdev_speedup = statistics.pstdev(speedups) if m > 1 else 0.0
    five = compute_five_num_summary(speedups)
    iqr = five["q3"] - five["q1"]
    ci_median = bootstrap_ci(speedups, statistics.median)
    ci_mean = bootstrap_ci(speedups, statistics.fmean)
    wilcoxon = wilcoxon_signed_rank(paired["base_times"], paired["pr_times"])

    lo, hi = ci_median
    if abs(median_speedup) <= noise_floor_pct:
        verdict = f"inconclusive — within cross-runner noise (±{noise_floor_pct:.1f}%)"
    elif lo > 0:
        verdict = "PR is faster"
    elif hi < 0:
        verdict = "PR is slower"
    else:
        verdict = "indistinguishable from base"

    return {
        "n": m,
        "median_speedup": median_speedup,
        "mean_speedup": mean_speedup,
        "stdev_speedup": stdev_speedup,
        "iqr_speedup": iqr,
        "ci_median": ci_median,
        "ci_mean": ci_mean,
        "noise_floor_pct": noise_floor_pct,
        "wilcoxon": wilcoxon,
        "verdict": verdict,
    }


def side_summary(aggregated):
    """Per-side aggregate timing/throughput summary (uses min-of-runs times)."""
    times = [v["time_min"] for v in aggregated.values()]
    total_funcs = sum(v["function_count"] for v in aggregated.values())
    total_time = sum(times)
    return {
        "files": len(aggregated),
        "median_time": statistics.median(times) if times else 0.0,
        "total_functions": total_funcs,
        "total_time": total_time,
        "functions_per_sec": (total_funcs / total_time) if total_time > 0 else 0.0,
    }


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #


def _fmt_p(wilcoxon):
    p = wilcoxon.get("p_value")
    if p is None:
        return f"n/a ({wilcoxon.get('note', 'insufficient data')})"
    return f"{p:.4f} (n={wilcoxon.get('n_nonzero', 0)})"


def generate_markdown_report(model, output_path):
    """Render the PR-comment Markdown. Tables are kept contiguous; long lists go
    into collapsible <details> blocks."""
    perf = model["performance"]
    paired = perf["paired"]
    corr = model["correctness"]
    det = model["determinism"]
    base_s = perf["base_summary"]
    pr_s = perf["pr_summary"]
    wil = paired["wilcoxon"]

    lines = [
        "### 📊 SMDA Performance Evaluation Benchmark Results",
        f"*Generated on: {model['generated']}*",
        "",
    ]

    nondet_sides = [s for s in ("base", "pr") if not det[s]["is_deterministic"]]
    if nondet_sides:
        lines += [
            f"> ⚠️ **Non-determinism detected** on: {', '.join(nondet_sides)}. "
            "Repeated runs of the same code disagree on the recovered function set, "
            "so the comparison below may be unreliable. See the Determinism section.",
            "",
        ]

    corr_icon = "✅ PASS" if corr["pass"] else "❌ FAIL"
    lines += [
        "#### Correctness",
        f"**{corr_icon}** — {len(corr['regressions'])} of {corr['n_common']} common file(s) "
        "differ in function-address set between base and PR.",
        "",
    ]

    lines += [
        f"#### Performance (paired per file, min of {model['runs']['base']}/{model['runs']['pr']} runs)",
        "| Side | Files | Median time (s) | Throughput (func/s) |",
        "| --- | --- | --- | --- |",
        f"| base | {base_s['files']} | {base_s['median_time']:.4f} | ~{base_s['functions_per_sec']:.0f} |",
        f"| pr | {pr_s['files']} | {pr_s['median_time']:.4f} | ~{pr_s['functions_per_sec']:.0f} |",
        "",
        "**Paired per-file speedup (positive = PR faster):**",
        "| Statistic | Value |",
        "| --- | --- |",
        f"| Files compared | {paired['n']} |",
        f"| Median speedup | {paired['median_speedup']:+.2f}% "
        f"(95% CI [{paired['ci_median'][0]:+.2f}%, {paired['ci_median'][1]:+.2f}%]) |",
        f"| Mean speedup | {paired['mean_speedup']:+.2f}% "
        f"(95% CI [{paired['ci_mean'][0]:+.2f}%, {paired['ci_mean'][1]:+.2f}%]) |",
        f"| Std dev / IQR | {paired['stdev_speedup']:.2f}% / {paired['iqr_speedup']:.2f}% |",
        f"| Wilcoxon signed-rank p | {_fmt_p(wil)} |",
        f"| Cross-runner noise floor | ±{paired.get('noise_floor_pct', 0.0):.1f}% |",
        f"| **Verdict** | **{paired['verdict']}** |",
        "",
        "> ℹ️ base and PR are timed on **separate** CI runners, so a small median "
        "difference can reflect per-runner hardware variance rather than code. "
        "Differences within the noise floor above are reported as inconclusive; "
        "correctness and determinism are unaffected (they are not timing-based).",
        "",
        "#### Determinism (self-check across repeated runs)",
        "| Side | Runs | Files | Deterministic | Median timing CV |",
        "| --- | --- | --- | --- | --- |",
        f"| base | {det['base']['runs']} | {det['base']['files_checked']} | "
        f"{'✅' if det['base']['is_deterministic'] else '❌'} | {det['base']['median_timing_cv'] * 100:.1f}% |",
        f"| pr | {det['pr']['runs']} | {det['pr']['files_checked']} | "
        f"{'✅' if det['pr']['is_deterministic'] else '❌'} | {det['pr']['median_timing_cv'] * 100:.1f}% |",
        "",
    ]

    if corr["regressions"]:
        lines.append("#### ⚠️ Correctness Regressions (PR vs base)")
        lines.append("")
        lines.append(f"<details>\n<summary>{len(corr['regressions'])} file(s) with differing function sets</summary>")
        lines.append("")
        for m in corr["regressions"][:25]:
            lines.append(
                f"- `{m['file']}`: base {m['base_count']} funcs, PR {m['pr_count']} funcs "
                f"(+{len(m['only_in_pr'])} only in PR, -{len(m['only_in_base'])} only in base)"
            )
        if len(corr["regressions"]) > 25:
            lines.append(f"- ... and {len(corr['regressions']) - 25} more")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    for side in ("base", "pr"):
        disagreeing = det[side]["files_disagreeing"]
        if disagreeing:
            lines.append(f"<details>\n<summary>{side}: {len(disagreeing)} non-deterministic file(s)</summary>")
            lines.append("")
            for d in disagreeing[:25]:
                lines.append(f"- `{d['file']}`: function counts across runs = {d['function_counts']}")
            if len(disagreeing) > 25:
                lines.append(f"- ... and {len(disagreeing) - 25} more")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return output_path


def generate_html_report(model, output_path):
    """Render a styled standalone HTML report (uploaded as an artifact)."""
    perf = model["performance"]
    paired = perf["paired"]
    corr = model["correctness"]
    det = model["determinism"]
    base_s = perf["base_summary"]
    pr_s = perf["pr_summary"]
    wil = paired["wilcoxon"]

    def card(title, value):
        return (
            f'            <div class="stat-card">\n'
            f"                <h4>{title}</h4>\n"
            f'                <div class="stat-value">{value}</div>\n'
            f"            </div>\n"
        )

    corr_ok = corr["pass"]
    p_text = "n/a" if wil.get("p_value") is None else f"{wil['p_value']:.4f}"

    html = (
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMDA Runtime Efficiency Evaluation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .summary h3 { margin-top: 0; color: #4CAF50; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 200px; }
        .stat-card h4 { margin: 0 0 10px 0; color: #666; font-size: 14px; text-transform: uppercase; }
        .stat-value { font-size: 24px; font-weight: bold; color: #333; }
        .pass { color: #2e7d32; } .fail { color: #d32f2f; }
        .footer { margin-top: 40px; color: #888; font-size: 14px; text-align: center; }
    </style>
</head>
<body>
    <h1>SMDA Runtime Efficiency Evaluation</h1>
    <p>Generated: """
        + model["generated"]
        + """</p>
"""
    )

    if not corr_ok or not det["base"]["is_deterministic"] or not det["pr"]["is_deterministic"]:
        issues = []
        if not corr_ok:
            issues.append(f"{len(corr['regressions'])} correctness regression(s)")
        for side in ("base", "pr"):
            if not det[side]["is_deterministic"]:
                issues.append(f"{side} non-determinism ({len(det[side]['files_disagreeing'])} files)")
        html += f'    <div class="summary"><h3 class="fail">⚠️ Issues: {"; ".join(issues)}</h3></div>\n'

    html += '    <div class="summary">\n        <h3>Correctness & Performance</h3>\n        <div class="stats">\n'
    html += card("Correctness", '<span class="pass">PASS</span>' if corr_ok else '<span class="fail">FAIL</span>')
    html += card("Common Files", corr["n_common"])
    html += card("Regressions", len(corr["regressions"]))
    html += card("Median Speedup", f"{paired['median_speedup']:+.2f}%")
    html += card("Median Speedup 95% CI", f"[{paired['ci_median'][0]:+.2f}%, {paired['ci_median'][1]:+.2f}%]")
    html += card("Wilcoxon p", p_text)
    html += card("Cross-runner noise floor", f"±{paired.get('noise_floor_pct', 0.0):.1f}%")
    html += card("Verdict", paired["verdict"])
    html += "        </div>\n    </div>\n"

    html += '    <div class="summary">\n        <h3>Per-side Summary (min-of-runs)</h3>\n        <div class="stats">\n'
    html += card("base Files", base_s["files"])
    html += card("pr Files", pr_s["files"])
    html += card("Med base Time", f"{base_s['median_time']:.4f}s")
    html += card("Med pr Time", f"{pr_s['median_time']:.4f}s")
    html += card("base Func/s", f"~{base_s['functions_per_sec']:.0f}")
    html += card("pr Func/s", f"~{pr_s['functions_per_sec']:.0f}")
    html += "        </div>\n    </div>\n"

    html += '    <div class="summary">\n        <h3>Determinism</h3>\n        <div class="stats">\n'
    for side in ("base", "pr"):
        d = det[side]
        ok = "✅" if d["is_deterministic"] else "❌"
        html += card(f"{side} ({d['runs']} runs)", f"{ok} CV {d['median_timing_cv'] * 100:.1f}%")
    html += "        </div>\n    </div>\n"

    html += (
        '    <p class="footer">Evaluation script: evaluate_runtime.py | Runtime measurements: '
        + str(RUNTIME_PATH)
        + "</p>\n</body>\n</html>\n"
    )

    with open(output_path, "w") as f:
        f.write(html)
    return output_path


def write_json_report(model, output_path):
    """Machine-readable report (schema-versioned)."""
    with open(output_path, "w") as f:
        json.dump(model, f, indent=2, default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o))
    return output_path


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def evaluate(runtime_path):
    """Parse folders under ``runtime_path`` and build the full report model.

    Returns ``(model, status)`` where ``status`` is one of ``"ok"``,
    ``"no_data"``. Does not decide exit codes (see ``main``).
    """
    global RUNTIME_PATH, CACHE_PATH
    RUNTIME_PATH = runtime_path
    CACHE_PATH = runtime_path / "cache"

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not runtime_path.exists():
        return {"generated": generated, "status": "no_data", "reason": f"{runtime_path} does not exist"}, "no_data"

    run_folders = discover_run_folders(runtime_path)
    base_folders = sorted(n for n in run_folders if n.startswith("base_"))
    pr_folders = sorted(n for n in run_folders if n.startswith("pr_"))
    print(f"Found base runs: {base_folders or '(none)'}")
    print(f"Found pr runs:   {pr_folders or '(none)'}")

    if not base_folders or not pr_folders:
        return (
            {
                "generated": generated,
                "status": "no_data",
                "reason": "missing base_* or pr_* run folders",
                "runs": {"base": len(base_folders), "pr": len(pr_folders)},
            },
            "no_data",
        )

    base_caches = {n: cache_reports(run_folders[n]) for n in base_folders}
    pr_caches = {n: cache_reports(run_folders[n]) for n in pr_folders}

    base_agg, base_meta = aggregate_runs(base_caches)
    pr_agg, pr_meta = aggregate_runs(pr_caches)

    base_det = check_determinism(base_agg)
    pr_det = check_determinism(pr_agg)

    paired = build_paired(base_agg, pr_agg)
    # Cross-runner/run-to-run noise band: base and PR are timed on separate CI
    # runners, so treat a median speedup within the per-side timing CV as noise.
    noise_floor_pct = max(base_det["median_timing_cv"], pr_det["median_timing_cv"]) * 100.0
    paired_stats = compute_paired_stats(paired, noise_floor_pct=noise_floor_pct)

    model = {
        "schema_version": SCHEMA_VERSION,
        "generated": generated,
        "status": "ok",
        "runs": {"base": len(base_folders), "pr": len(pr_folders)},
        "determinism": {"base": base_det, "pr": pr_det},
        "correctness": {
            "pass": len(paired["regressions"]) == 0,
            "n_common": len(paired["common_files"]),
            "regressions": paired["regressions"],
            "only_in_base": paired["only_in_base"],
            "only_in_pr": paired["only_in_pr"],
        },
        "performance": {
            "base_summary": side_summary(base_agg),
            "pr_summary": side_summary(pr_agg),
            "paired": paired_stats,
            "degenerate_files": paired["degenerate"],
        },
        "meta": {"base": base_meta, "pr": pr_meta},
    }
    return model, "ok"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate SMDA base-vs-PR benchmark runs")
    parser.add_argument("--runtime-path", type=Path, default=RUNTIME_PATH, help="Folder containing base_*/pr_* runs")
    parser.add_argument("--no-gate", action="store_true", help="Report only; never exit non-zero")
    parser.add_argument(
        "--no-fail-on-nondeterminism",
        action="store_true",
        help="Do not fail CI when a side's repeated runs disagree (still reported)",
    )
    parser.add_argument("--require-data", action="store_true", help="Exit non-zero when there is no comparable data")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    gate = not (args.no_gate or os.environ.get("SMDA_BENCH_GATE") == "0")

    print("=" * 80)
    print("SMDA Runtime Efficiency Evaluation")
    print("=" * 80)

    model, status = evaluate(args.runtime_path)

    cache_path = args.runtime_path / "cache"
    cache_path.mkdir(parents=True, exist_ok=True)

    reasons = []
    exit_code = 0

    if status == "no_data":
        print(f"No comparable data: {model.get('reason')}")
        model.setdefault("gate", {"enabled": gate, "failed": False, "exit_code": 0, "reasons": ["no comparable data"]})
        # Still emit minimal reports so artifacts exist.
        with open(cache_path / "evaluation.json", "w") as f:
            json.dump(model, f, indent=2)
        with open(cache_path / "evaluation.md", "w") as f:
            f.write(
                "### 📊 SMDA Performance Evaluation Benchmark Results\n\n"
                f"_No comparable data: {model.get('reason')}._\n"
            )
        with open(cache_path / "evaluation.html", "w") as f:
            f.write(
                f"<html><body><h1>SMDA Evaluation</h1><p>No comparable data: {model.get('reason')}</p></body></html>"
            )
        if gate and args.require_data:
            print("FAIL: no comparable data (--require-data)")
            return 3
        return 0

    nondet_sides = [s for s in ("base", "pr") if not model["determinism"][s]["is_deterministic"]]
    correctness_failed = not model["correctness"]["pass"]

    if nondet_sides:
        reasons.append(f"non-determinism on: {', '.join(nondet_sides)}")
    if correctness_failed:
        n = len(model["correctness"]["regressions"])
        reasons.append(f"{n} correctness regression(s) vs base")

    if gate:
        if nondet_sides and not args.no_fail_on_nondeterminism:
            exit_code = 2
        elif correctness_failed:
            exit_code = 1

    model["gate"] = {"enabled": gate, "failed": exit_code != 0, "exit_code": exit_code, "reasons": reasons}

    write_json_report(model, cache_path / "evaluation.json")
    generate_html_report(model, cache_path / "evaluation.html")
    generate_markdown_report(model, cache_path / "evaluation.md")
    print(f"Reports written to {cache_path}")

    paired = model["performance"]["paired"]
    print(
        f"Correctness: {'PASS' if model['correctness']['pass'] else 'FAIL'} "
        f"({len(model['correctness']['regressions'])} regressions); "
        f"median speedup {paired['median_speedup']:+.2f}% "
        f"CI[{paired['ci_median'][0]:+.2f}%,{paired['ci_median'][1]:+.2f}%]; verdict: {paired['verdict']}"
    )
    if reasons:
        print("Gate reasons: " + "; ".join(reasons))
    print(f"Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
