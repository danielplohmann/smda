#!/usr/bin/python

import argparse
import logging
import os
import sys
import time

from smda.SmdaConfig import SmdaConfig
from smda.utility.BatchProcessor import collectInputFiles, disassembleParallel, getDefaultWorkerCount

try:
    import tqdm

    HAVE_TQDM = True
except ImportError:
    HAVE_TQDM = False

LOGGER = logging.getLogger("batch_analyze")


def _iterateWithProgress(results, total):
    if HAVE_TQDM:
        yield from tqdm.tqdm(results, total=total, unit="file")
        return
    last_report = 0.0
    for index, result in enumerate(results, start=1):
        now = time.time()
        if now - last_report > 2.0 or index == total:
            print(f"  {index}/{total} files processed", file=sys.stderr)
            last_report = now
        yield result


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        description="Disassemble many files in parallel, writing one SMDA report per input file."
    )
    PARSER.add_argument("input_paths", type=str, nargs="+", help="Files and/or directories to disassemble.")
    PARSER.add_argument(
        "-o",
        "--output_path",
        type=str,
        required=True,
        help="Directory to write reports to. Created if it does not exist.",
    )
    PARSER.add_argument(
        "-w",
        "--workers",
        type=int,
        default=0,
        help="Number of worker processes (default: all usable cores).",
    )
    PARSER.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Per-file analysis timeout in seconds; 0 disables it. A nonzero timeout is wall-clock, "
        "so under oversubscription it makes output load-dependent (default: SmdaConfig.TIMEOUT).",
    )
    PARSER.add_argument(
        "-c",
        "--resume",
        action="store_true",
        default=False,
        help="Skip inputs whose report already exists in the output directory.",
    )
    PARSER.add_argument(
        "-m",
        "--max_tasks_per_child",
        type=int,
        default=None,
        help="Recycle each worker after this many files, bounding per-worker memory growth "
        "at the cost of re-paying ~175ms of warm-up per recycle.",
    )
    PARSER.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable debug logging.")
    ARGS = PARSER.parse_args()

    logging.basicConfig(
        format="%(asctime)-15s %(message)s",
        level=logging.DEBUG if ARGS.verbose else logging.WARNING,
    )

    if ARGS.workers < 0:
        PARSER.error("--workers must be >= 0")
    if ARGS.timeout is not None and ARGS.timeout < 0:
        PARSER.error("--timeout must be >= 0")
    if ARGS.max_tasks_per_child is not None and ARGS.max_tasks_per_child < 1:
        PARSER.error("--max_tasks_per_child must be >= 1")
    for input_path in ARGS.input_paths:
        if not os.path.exists(input_path):
            PARSER.error(f"input path does not exist: {input_path}")

    os.makedirs(ARGS.output_path, exist_ok=True)

    COLLECTED = collectInputFiles(ARGS.input_paths)
    TOTAL = len(COLLECTED)
    WORKERS = ARGS.workers if ARGS.workers > 0 else getDefaultWorkerCount()
    print(f"Disassembling {TOTAL} file(s) with {WORKERS} worker(s) into {ARGS.output_path}")
    if ARGS.timeout is None:
        print(f"Per-file timeout: {SmdaConfig.TIMEOUT}s (wall-clock; pass --timeout 0 to disable)")

    RESULTS = disassembleParallel(
        ARGS.input_paths,
        output_dir=ARGS.output_path,
        workers=ARGS.workers,
        timeout=ARGS.timeout,
        resume=ARGS.resume,
        max_tasks_per_child=ARGS.max_tasks_per_child,
        collected=COLLECTED,
    )

    START = time.time()
    COUNTS = {"ok": 0, "timeout": 0, "error": 0, "other": 0}
    FAILURES = []
    for RESULT in _iterateWithProgress(RESULTS, TOTAL):
        status = RESULT["status"]
        COUNTS[status if status in COUNTS else "other"] += 1
        if RESULT["error"]:
            FAILURES.append((RESULT["path"], RESULT["error"]))

    DURATION = time.time() - START
    print(
        f"\nDone in {DURATION:.2f}s - ok: {COUNTS['ok']}, timeout: {COUNTS['timeout']}, "
        f"error: {COUNTS['error']}, other: {COUNTS['other']}"
    )
    for path, error in FAILURES[:20]:
        print(f"  FAILED {path}: {error}")
    if len(FAILURES) > 20:
        print(f"  ... and {len(FAILURES) - 20} more failures")
    sys.exit(1 if FAILURES else 0)
