#!/usr/bin/env python3
"""Collect focused profiler artifacts for a failed SMDA performance gate.

This is the CI-safe subset of the deeper research-vault profiler workflow. It
keeps PR comments concise while uploading actionable artifacts for investigation.
"""

from __future__ import annotations

import argparse
import json
import pstats
import shutil
import statistics
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any

import psutil
import smda_perf_runner


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_capture(args: list[str], cwd: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        return {
            "args": args,
            "status": "skipped",
            "returncode": None,
            "elapsed": time.perf_counter() - started,
            "stdout_tail": "",
            "stderr_tail": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "args": args,
            "status": "failed",
            "returncode": 124,
            "elapsed": time.perf_counter() - started,
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else f"timeout after {timeout}s",
        }
    return {
        "args": args,
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "elapsed": time.perf_counter() - started,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }


def runner_args(args: argparse.Namespace, output_dir: Path) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("smda_perf_runner.py")),
        "--repo",
        str(args.repo),
        "--corpus-root",
        str(args.corpus_root),
        "--output-dir",
        str(output_dir),
        "--limit",
        str(args.limit),
    ]
    if args.manifest:
        command.extend(["--manifest", str(args.manifest)])
    return command


def sample_memory(stop: threading.Event, interval: float, samples: list[dict[str, Any]]) -> None:
    proc = psutil.Process()
    started = time.perf_counter()
    while not stop.is_set():
        info = proc.memory_full_info()
        samples.append(
            {
                "elapsed": time.perf_counter() - started,
                "rss": int(info.rss),
                "uss": int(getattr(info, "uss", 0)),
                "pss": int(getattr(info, "pss", 0)),
            }
        )
        stop.wait(interval)


def numeric_summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"count": 0, "min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0}
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
    }


def memory_baseline(args: argparse.Namespace, output: Path) -> dict[str, Any]:
    targets = (
        smda_perf_runner.load_manifest_targets(args.corpus_root, args.manifest)
        if args.manifest
        else smda_perf_runner.discover_targets(args.corpus_root)
    )
    targets = targets[: args.limit]
    samples: list[dict[str, Any]] = []
    stop = threading.Event()
    sampler = threading.Thread(target=sample_memory, args=(stop, 0.05, samples), daemon=True)

    disassembler = smda_perf_runner.import_disassembler(args.repo)
    tracemalloc.start(25)
    sampler.start()
    started = time.perf_counter()
    results = []
    try:
        for target in targets:
            results.append(smda_perf_runner.disassemble_target(disassembler, target))
    finally:
        stop.set()
        sampler.join(timeout=2.0)
        current, peak = tracemalloc.get_traced_memory()
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()

    top_allocations = []
    for stat in snapshot.statistics("lineno")[:25]:
        frame = stat.traceback[0]
        top_allocations.append(
            {
                "file": frame.filename,
                "line": frame.lineno,
                "size_bytes": stat.size,
                "count": stat.count,
            }
        )

    rss_values = [float(item["rss"]) for item in samples]
    uss_values = [float(item["uss"]) for item in samples if item.get("uss")]
    value = {
        "elapsed": time.perf_counter() - started,
        "target_count": len(targets),
        "status_counts": {
            status: sum(1 for item in results if item["status"] == status)
            for status in sorted({item["status"] for item in results})
        },
        "psutil": {
            "rss": numeric_summary(rss_values),
            "uss": numeric_summary(uss_values),
            "sample_count": len(samples),
        },
        "tracemalloc": {
            "current_bytes": current,
            "peak_bytes": peak,
            "top_allocations": top_allocations,
        },
    }
    write_json(output, value)
    return {"status": "ok", "artifacts": [str(output)]}


def cprofile_lane(args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    profile = output_dir / "cprofile" / "profile.prof"
    pstats_txt = output_dir / "cprofile" / "pstats.txt"
    profile.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "cProfile",
        "-o",
        str(profile),
        *runner_args(args, output_dir / "cprofile-run")[1:],
    ]
    result = run_capture(command, timeout=args.timeout)
    if profile.exists():
        with pstats_txt.open("w", encoding="utf-8") as fout:
            stats = pstats.Stats(str(profile), stream=fout)
            stats.strip_dirs().sort_stats("cumulative").print_stats(80)
    result["artifacts"] = [str(profile), str(pstats_txt)]
    return result


def pyinstrument_lane(args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    if shutil.which("pyinstrument") is None:
        return {"status": "skipped", "reason": "pyinstrument executable not found", "artifacts": []}
    output = output_dir / "pyinstrument" / "profile.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "pyinstrument",
        "-r",
        "html",
        "-o",
        str(output),
        *runner_args(args, output_dir / "pyinstrument-run")[1:],
    ]
    result = run_capture(command, timeout=args.timeout)
    result["artifacts"] = [str(output)]
    return result


def memray_lane(args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    if shutil.which("memray") is None:
        return {"status": "skipped", "reason": "memray executable not found", "artifacts": []}
    capture = output_dir / "memray" / "capture.bin"
    stats = output_dir / "memray" / "stats.json"
    flame = output_dir / "memray" / "flamegraph.html"
    capture.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "memray",
        "run",
        "--native",
        "--force",
        "--output",
        str(capture),
        *runner_args(args, output_dir / "memray-run")[1:],
    ]
    result = run_capture(command, timeout=args.timeout)
    if result["status"] == "ok" and capture.exists():
        run_capture(
            [sys.executable, "-m", "memray", "stats", "--json", "--output", str(stats), "--force", str(capture)]
        )
        run_capture([sys.executable, "-m", "memray", "flamegraph", "--output", str(flame), "--force", str(capture)])
    result["artifacts"] = [str(capture), str(stats), str(flame)]
    return result


def write_summary(output_dir: Path, lanes: dict[str, Any]) -> None:
    write_json(output_dir / "diagnostics-summary.json", lanes)
    lines = [
        "",
        "Failure diagnostics captured in artifacts:",
        "- cProfile cumulative stats",
        "- Pyinstrument timeline HTML when available",
        "- Memray native allocation capture/stats/flamegraph when available",
        "- tracemalloc and psutil memory baseline",
    ]
    (output_dir / "diagnostics-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    lanes = {
        "cprofile": cprofile_lane(args, args.output_dir),
        "pyinstrument": pyinstrument_lane(args, args.output_dir),
        "memray": memray_lane(args, args.output_dir),
        "memory-baseline": memory_baseline(args, args.output_dir / "memory-baseline.json"),
    }
    write_summary(args.output_dir, lanes)
    hard_failures = [name for name, item in lanes.items() if item.get("status") == "failed"]
    return 1 if hard_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
