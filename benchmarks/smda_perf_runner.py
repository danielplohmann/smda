#!/usr/bin/env python3
"""Run SMDA over a corpus and emit compact benchmark metrics.

The runner is intended to be timed by ``python -m pyperf command``. It statically
disassembles files and memory dumps; it never executes corpus contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DUMP_PATTERN = re.compile(r"dump7?_0x[0-9a-fA-F]{8,16}")
UNPACKED_PATTERN = re.compile(r"_unpacked(_x64)?$")


@dataclass(frozen=True)
class Target:
    path: Path
    relative_path: str
    filename: str
    mode: str
    family: str = ""
    version: str = ""
    sha256: str = ""
    size_bytes: int = 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fin:
        for chunk in iter(lambda: fin.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_base_addr(filename: str) -> int:
    match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})", filename)
    return int(match.group("base_addr"), 16) if match else 0


def get_bitness_from_filename(filename: str) -> int:
    match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})", filename)
    if not match:
        return 0
    return 32 if len(match.group("base_addr")) == 8 else 64


def infer_mode(filename: str, requested_mode: str | None = None) -> str:
    if requested_mode in {"dump", "file"}:
        return requested_mode
    return "dump" if DUMP_PATTERN.search(filename) else "file"


def resolve_manifest_path(corpus_root: Path, item: dict[str, Any], manifest_path: Path) -> Path:
    candidates = []
    for key in ("relative_path", "path"):
        value = item.get(key)
        if not value:
            continue
        path = Path(str(value))
        candidates.append(path if path.is_absolute() else corpus_root / path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    line_hint = item.get("relative_path") or item.get("path") or "<missing path>"
    raise FileNotFoundError(f"{manifest_path}: cannot resolve corpus target {line_hint!r}")


def load_manifest_targets(corpus_root: Path, manifest_path: Path) -> list[Target]:
    targets = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        path = resolve_manifest_path(corpus_root, item, manifest_path)
        relative_path = item.get("relative_path")
        if not relative_path:
            try:
                relative_path = str(path.relative_to(corpus_root))
            except ValueError:
                relative_path = path.name
        targets.append(
            Target(
                path=path,
                relative_path=str(relative_path),
                filename=str(item.get("filename") or path.name),
                mode=infer_mode(path.name, item.get("mode")),
                family=str(item.get("family") or ""),
                version=str(item.get("version") or ""),
                sha256=str(item.get("sha256") or sha256_file(path)),
                size_bytes=int(item.get("size_bytes") or path.stat().st_size),
            )
        )
    return targets


def discover_targets(corpus_root: Path) -> list[Target]:
    targets = []
    for root, dirs, files in os.walk(corpus_root):
        dirs[:] = [item for item in dirs if item not in {".git", "__MACOSX"}]
        root_path = Path(root)
        for filename in sorted(files):
            if filename.startswith("."):
                continue
            if not (DUMP_PATTERN.search(filename) or UNPACKED_PATTERN.search(filename)):
                continue
            path = root_path / filename
            rel = path.relative_to(corpus_root)
            parts = rel.parts
            targets.append(
                Target(
                    path=path,
                    relative_path=str(rel),
                    filename=filename,
                    mode=infer_mode(filename),
                    family=parts[0] if parts else "",
                    version=parts[1] if len(parts) > 2 else "",
                    sha256=sha256_file(path),
                    size_bytes=path.stat().st_size,
                )
            )
    return sorted(targets, key=lambda item: item.relative_path)


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fout:
        fout.write(json.dumps(item, sort_keys=True) + "\n")


def write_json(path: Path, item: dict[str, Any]) -> None:
    path.write_text(json.dumps(item, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def import_disassembler(repo: Path) -> Any:
    src = repo / "src"
    if src.exists():
        sys.path.insert(0, str(src))
    else:
        sys.path.insert(0, str(repo))
    from smda.Disassembler import Disassembler

    return Disassembler()


def report_statistics(report: Any) -> dict[str, int]:
    report_dict = report.toDict()
    statistics = report_dict.get("statistics") or {}
    xcfg = report_dict.get("xcfg") or {}
    return {
        "num_functions": int(statistics.get("num_functions") or len(xcfg)),
        "num_instructions": int(statistics.get("num_instructions") or 0),
        "num_basic_blocks": int(statistics.get("num_basic_blocks") or 0),
    }


def disassemble_target(disassembler: Any, target: Target) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    report = None
    try:
        if target.mode == "dump":
            report = disassembler.disassembleBuffer(
                target.path.read_bytes(),
                parse_base_addr(target.filename),
                get_bitness_from_filename(target.filename),
            )
        else:
            report = disassembler.disassembleFile(str(target.path))
    except Exception as exc:
        error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(limit=12),
        }
    wall_time = time.perf_counter() - started
    result: dict[str, Any] = {
        "filename": target.filename,
        "relative_path": target.relative_path,
        "mode": target.mode,
        "size_bytes": target.size_bytes,
        "sha256": target.sha256,
        "wall_time": wall_time,
        "status": "exception" if error else "ok",
    }
    if error:
        result["error"] = error
    if report is not None:
        stats = report_statistics(report)
        result.update(
            {
                "status": getattr(report, "status", result["status"]),
                "execution_time": float(getattr(report, "execution_time", 0.0) or 0.0),
                "num_functions": stats["num_functions"],
                "num_instructions": stats["num_instructions"],
                "num_basic_blocks": stats["num_basic_blocks"],
            }
        )
    return result


def summarize_results(results: list[dict[str, Any]], started: float, repo: Path) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for result in results:
        status = str(result.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    total_exec = sum(float(item.get("execution_time") or 0.0) for item in results)
    total_functions = sum(int(item.get("num_functions") or 0) for item in results)
    total_instructions = sum(int(item.get("num_instructions") or 0) for item in results)
    total_bytes = sum(int(item.get("size_bytes") or 0) for item in results)
    max_rss_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return {
        "repo": str(repo),
        "target_count": len(results),
        "status_counts": status_counts,
        "exception_count": int(status_counts.get("exception", 0)),
        "total_wall_time": time.perf_counter() - started,
        "total_report_execution_time": total_exec,
        "total_functions": total_functions,
        "total_instructions": total_instructions,
        "total_input_bytes": total_bytes,
        "functions_per_second": total_functions / total_exec if total_exec > 0 else 0.0,
        "instructions_per_second": total_instructions / total_exec if total_exec > 0 else 0.0,
        "max_rss_kb": max_rss_kb,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = args.output_dir / "metrics.jsonl"
    if metrics_path.exists():
        metrics_path.unlink()

    targets = (
        load_manifest_targets(args.corpus_root, args.manifest) if args.manifest else discover_targets(args.corpus_root)
    )
    if args.limit > 0:
        targets = targets[: args.limit]
    if not targets:
        raise SystemExit("No benchmark targets found in the corpus")

    disassembler = import_disassembler(args.repo)
    started = time.perf_counter()
    results = []
    for index, target in enumerate(targets, start=1):
        result = disassemble_target(disassembler, target)
        result["index"] = index
        result["total"] = len(targets)
        append_jsonl(metrics_path, result)
        results.append(result)
        print(
            f"[{index}/{len(targets)}] {target.filename} "
            f"status={result['status']} exec={float(result.get('execution_time') or 0):.4f}s",
            flush=True,
        )

    summary = summarize_results(results, started, args.repo)
    write_json(args.output_dir / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
