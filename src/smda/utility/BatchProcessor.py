import json
import logging
import os
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import get_context

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.common import computeReportIdentityHash

LOGGER = logging.getLogger(__name__)


def getDefaultWorkerCount():
    """Number of usable cores, honouring CPU affinity where the platform exposes it."""
    process_cpu_count = getattr(os, "process_cpu_count", None)
    if process_cpu_count is not None:
        return max(1, process_cpu_count())
    sched_getaffinity = getattr(os, "sched_getaffinity", None)
    if sched_getaffinity is not None:
        return max(1, len(sched_getaffinity(0)))
    return max(1, os.cpu_count() or 1)


def deriveReportStem(path, input_root):
    """Path-relative stem, so same-named samples in different folders cannot collide."""
    relative = os.path.relpath(os.path.abspath(path), os.path.abspath(input_root))
    return relative.replace(os.sep, "_")


def _initWorker(log_level):
    logging.getLogger().setLevel(log_level)


def _analyzeOneFile(task):
    """Runs in a worker process. Writes the report and returns a small summary.

    The Disassembler is constructed here rather than in a pool initializer: reusing one
    instance across files would reintroduce instance-scoped id()-keyed caches and per-call
    scratch state that are only valid for a single binary.
    """
    path = task["path"]
    summary = {
        "path": path,
        "report_stem": task["report_stem"],
        "status": "error",
        "output_path": None,
        "num_functions": 0,
        "num_instructions": 0,
        "report_hash": "",
        "execution_time": 0.0,
        "error": None,
        "report": None,
    }
    try:
        config = SmdaConfig()
        if task["timeout"] is not None:
            config.TIMEOUT = task["timeout"]
        disassembler = Disassembler(config)
        report = disassembler.disassembleFile(path)
        summary["status"] = report.status
        summary["num_functions"] = report.num_functions
        summary["num_instructions"] = report.num_instructions
        summary["execution_time"] = report.execution_time
        summary["report_hash"] = computeReportIdentityHash(report)
        if task["output_dir"]:
            output_path = os.path.join(task["output_dir"], task["report_stem"] + ".smda")
            with open(output_path, "w", encoding="utf-8") as f_out:
                json.dump(report.toDict(), f_out, indent=1, sort_keys=True)
            summary["output_path"] = output_path
        if task["return_reports"]:
            summary["report"] = report
    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        summary["traceback"] = traceback.format_exc()
    return summary


def collectInputFiles(paths, input_root=None):
    """Expand files and directories into a sorted list of (path, report_stem) pairs."""
    collected = []
    for path in paths:
        if os.path.isdir(path):
            root = input_root or path
            for dirpath, _, filenames in os.walk(path):
                for filename in sorted(filenames):
                    file_path = os.path.join(dirpath, filename)
                    collected.append((file_path, deriveReportStem(file_path, root)))
        elif os.path.isfile(path):
            root = input_root or os.path.dirname(os.path.abspath(path)) or os.sep
            collected.append((path, deriveReportStem(path, root)))
        else:
            raise FileNotFoundError(path)
    return sorted(collected)


def disassembleParallel(
    paths,
    output_dir=None,
    workers=0,
    timeout=None,
    resume=False,
    max_tasks_per_child=None,
    return_reports=False,
    input_root=None,
):
    """Disassemble many files across processes, yielding one summary dict per completed file.

    Each binary is independent, so results do not depend on the number of workers, with one
    exception: a nonzero SmdaConfig.TIMEOUT is wall-clock, so under oversubscription a slow
    sample can time out where a serial run finished. Pass timeout=0 for load-independent
    output.

    Reports are written in the worker and only a small summary is returned, because shipping
    whole reports back through the parent makes deserialization the bottleneck. Pass
    return_reports=True to receive the report objects as well.

    This is a library helper: it never configures logging and never adds a handler.
    """
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    collected = collectInputFiles(paths, input_root=input_root)
    tasks = []
    for path, report_stem in collected:
        # resume is decided here, in the parent, so the set of finished reports is never
        # embedded into every task payload
        if resume and output_dir and os.path.exists(os.path.join(output_dir, report_stem + ".smda")):
            LOGGER.debug("Skipping %s, report already exists", path)
            continue
        tasks.append(
            {
                "path": path,
                "report_stem": report_stem,
                "output_dir": output_dir,
                "timeout": timeout,
                "return_reports": return_reports,
            }
        )

    if not tasks:
        return

    worker_count = workers if workers > 0 else getDefaultWorkerCount()
    worker_count = max(1, min(worker_count, len(tasks)))

    with ProcessPoolExecutor(
        max_workers=worker_count,
        # spawn is the strictest context: it re-imports, which proves the task function is
        # importable and the payload picklable instead of relying on a forked address space
        mp_context=get_context("spawn"),
        initializer=_initWorker,
        initargs=(logging.getLogger().level,),
        # None is the ProcessPoolExecutor default: a worker lives as long as the executor
        max_tasks_per_child=max_tasks_per_child,
    ) as executor:
        futures = {executor.submit(_analyzeOneFile, task): task for task in tasks}
        for future in as_completed(futures):
            task = futures[future]
            try:
                yield future.result()
            except Exception as exc:
                # a worker that was OOM-killed or died inside capstone/LIEF surfaces here as
                # BrokenProcessPool instead of hanging the run
                LOGGER.error("Worker failed for %s: %r", task["path"], exc)
                yield {
                    "path": task["path"],
                    "report_stem": task["report_stem"],
                    "status": "error",
                    "output_path": None,
                    "num_functions": 0,
                    "num_instructions": 0,
                    "report_hash": "",
                    "execution_time": 0.0,
                    "error": f"{type(exc).__name__}: {exc}",
                    "report": None,
                }
