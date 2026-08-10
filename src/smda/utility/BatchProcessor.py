import json
import logging
import os
import traceback
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from contextlib import ExitStack
from multiprocessing import get_context

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.common import computeReportDictIdentityHash

LOGGER = logging.getLogger(__name__)

DEFAULT_LARGE_INPUT_BYTES = 1 << 20
# peak worker RSS observed for an analysis, expressed per byte of input
LARGE_INPUT_RSS_FACTOR = 500
MEMORY_BUDGET_FRACTION = 0.5


def getMemoryBudget():
    """Bytes of RSS the large-input partition may occupy, or None where the platform hides RAM size."""
    sysconf = getattr(os, "sysconf", None)
    if sysconf is None:
        return None
    try:
        return int(sysconf("SC_PAGE_SIZE") * sysconf("SC_PHYS_PAGES") * MEMORY_BUDGET_FRACTION)
    except (ValueError, OSError):
        return None


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
        # one toDict() serves both the identity hash and the file, instead of building the
        # whole report dict twice
        as_dict = report.toDict()
        summary["report_hash"] = computeReportDictIdentityHash(as_dict)
        if task["output_dir"]:
            output_path = os.path.join(task["output_dir"], task["report_stem"] + ".smda")
            with open(output_path, "w", encoding="utf-8") as f_out:
                f_out.write(json.dumps(as_dict, indent=1, sort_keys=True))
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
    # with several inputs, each path's own directory is not a usable root: two of them can
    # relativize distinct samples to the same stem and overwrite each other's report
    shared_root = input_root
    if shared_root is None and len(paths) > 1:
        shared_root = os.path.commonpath([os.path.abspath(path) for path in paths])
    for path in paths:
        if os.path.isdir(path):
            root = shared_root or path
            for dirpath, _, filenames in os.walk(path):
                for filename in sorted(filenames):
                    file_path = os.path.join(dirpath, filename)
                    collected.append((file_path, deriveReportStem(file_path, root)))
        elif os.path.isfile(path):
            root = shared_root or os.path.dirname(os.path.abspath(path)) or os.sep
            collected.append((path, deriveReportStem(path, root)))
        else:
            raise FileNotFoundError(path)
    return sorted(collected)


def _inputSize(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _largeWorkerCount(largest_input_bytes, task_count, worker_count, memory_budget):
    budget = getMemoryBudget() if memory_budget is None else memory_budget
    capacity = task_count
    if budget:
        capacity = budget // max(1, largest_input_bytes * LARGE_INPUT_RSS_FACTOR)
    return max(1, min(worker_count, task_count, capacity))


def _runPartitions(partitions):
    """Drive the given (tasks, workers, max_tasks_per_child) pools, yielding summaries as they land.

    Each pool holds at most twice its worker count of tasks in flight, so the parent's own
    memory stays proportional to the workers rather than to the size of the corpus.
    """
    with ExitStack() as stack:
        streams = []
        for tasks, worker_count, max_tasks_per_child in partitions:
            executor = stack.enter_context(
                ProcessPoolExecutor(
                    max_workers=worker_count,
                    # spawn is the strictest context: it re-imports, which proves the task function is
                    # importable and the payload picklable instead of relying on a forked address space
                    mp_context=get_context("spawn"),
                    initializer=_initWorker,
                    initargs=(logging.getLogger().level,),
                    max_tasks_per_child=max_tasks_per_child,
                )
            )
            streams.append((executor, iter(tasks), set(), 2 * worker_count))

        owners = {}
        while True:
            for executor, pending_tasks, in_flight, limit in streams:
                while len(in_flight) < limit:
                    task = next(pending_tasks, None)
                    if task is None:
                        break
                    future = executor.submit(_analyzeOneFile, task)
                    in_flight.add(future)
                    owners[future] = (task, in_flight)
            if not owners:
                return
            done, _ = wait(list(owners), return_when=FIRST_COMPLETED)
            # wait() returns a set; order the batch by path so a rerun yields summaries identically
            for future in sorted(done, key=lambda finished: owners[finished][0]["path"]):
                task, in_flight = owners.pop(future)
                in_flight.discard(future)
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


def disassembleParallel(
    paths,
    output_dir=None,
    workers=0,
    timeout=None,
    resume=False,
    max_tasks_per_child=None,
    return_reports=False,
    input_root=None,
    collected=None,
    large_input_bytes=DEFAULT_LARGE_INPUT_BYTES,
    memory_budget=None,
):
    """Disassemble many files across processes, yielding one summary dict per completed file.

    Each binary is independent, so results do not depend on the number of workers, with one
    exception: a nonzero SmdaConfig.TIMEOUT is wall-clock, so under oversubscription a slow
    sample can time out where a serial run finished. Pass timeout=0 for load-independent
    output.

    Peak worker RSS scales with input size, so inputs of at least large_input_bytes are run on
    a separate pool whose concurrency is capped by memory_budget (bytes, defaulting to a
    fraction of physical RAM) and whose workers are recycled after every file. Pass an already
    collected list of (path, report_stem) pairs to avoid walking the input tree twice.

    Reports are written in the worker and only a small summary is returned, because shipping
    whole reports back through the parent makes deserialization the bottleneck. Pass
    return_reports=True to receive the report objects as well.

    This is a library helper: it never configures logging and never adds a handler.
    """
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if collected is None:
        collected = collectInputFiles(paths, input_root=input_root)
    small_tasks = []
    large_tasks = []
    largest_input_bytes = 0
    for path, report_stem in collected:
        # resume is decided here, in the parent, so the set of finished reports is never
        # embedded into every task payload
        if resume and output_dir and os.path.exists(os.path.join(output_dir, report_stem + ".smda")):
            LOGGER.debug("Skipping %s, report already exists", path)
            continue
        task = {
            "path": path,
            "report_stem": report_stem,
            "output_dir": output_dir,
            "timeout": timeout,
            "return_reports": return_reports,
        }
        size = _inputSize(path)
        if size >= large_input_bytes:
            large_tasks.append(task)
            largest_input_bytes = max(largest_input_bytes, size)
        else:
            small_tasks.append(task)

    if not small_tasks and not large_tasks:
        return

    worker_count = workers if workers > 0 else getDefaultWorkerCount()
    worker_count = max(1, min(worker_count, len(small_tasks) + len(large_tasks)))

    partitions = []
    large_workers = 0
    if large_tasks and worker_count > 1:
        # the second pool must not push total concurrency past the requested worker count
        reserved = 1 if small_tasks else 0
        large_workers = _largeWorkerCount(largest_input_bytes, len(large_tasks), worker_count - reserved, memory_budget)
        partitions.append((large_tasks, large_workers, 1))
    else:
        small_tasks = large_tasks + small_tasks
    if small_tasks:
        small_workers = max(1, min(worker_count - large_workers, len(small_tasks)))
        # None is the ProcessPoolExecutor default: a worker lives as long as the executor
        partitions.append((small_tasks, small_workers, max_tasks_per_child))
    yield from _runPartitions(partitions)
