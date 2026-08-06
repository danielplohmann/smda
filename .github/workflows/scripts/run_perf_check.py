#!/usr/bin/env python3
import argparse
import cProfile
import json
import logging
import os
import platform
import pstats
import statistics
import sys
import time
import tracemalloc

# Setup python path so we can run the script directly from the repo root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src")))

try:
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig
    from smda.utility.common import computeReportIdentityHash
except ImportError as e:
    print(f"Error importing SMDA. Make sure you run this script from the repository root: {e}", file=sys.stderr)
    sys.exit(1)


def decrypt_binary(filepath):
    """Decrypts a XOR-obfuscated test fixture binary."""
    with open(filepath, "rb") as f:
        binary = f.read()
    decrypted = bytearray()
    for index, byte in enumerate(binary):
        if isinstance(byte, str):
            byte = ord(byte)
        decrypted.append(byte ^ (index % 256))
    return bytes(decrypted)


# sample list -> the median key derived from it; both accumulate across counterbalanced passes
SAMPLE_CHANNELS = {
    "execution_times": "median_time",
    "peak_memories": "median_peak_memory",
}


def merge_results(existing_results, new_results):
    """Merge a fresh pass into accumulated results without dropping pass-specific metrics.

    Timing and memory samples accumulate across passes; every other key is carried forward
    from the existing entry unless the new pass actually produced it.
    """
    merged_results = dict(existing_results)
    for name, new_result in new_results.items():
        if name not in merged_results:
            merged_results[name] = dict(new_result)
            continue
        merged = dict(merged_results[name])
        merged.update(new_result)
        for samples_key, median_key in SAMPLE_CHANNELS.items():
            existing_samples = merged_results[name].get(samples_key)
            new_samples = new_result.get(samples_key)
            if not existing_samples or not new_samples:
                continue
            samples = existing_samples + new_samples
            merged[samples_key] = samples
            merged[median_key] = statistics.median(samples)
        merged_results[name] = merged
    return merged_results


def disassemble_fixture(config, fixture, binary_bytes):
    disasm = Disassembler(config, backend=fixture["backend"])
    if fixture["backend"] in ("dalvik", "cil"):
        return disasm.disassembleUnmappedBuffer(binary_bytes)
    if fixture["base_addr"] != 0:
        return disasm.disassembleBuffer(binary_bytes, fixture["base_addr"])
    return disasm.disassembleUnmappedBuffer(binary_bytes)


def count_calls(config, fixture, binary_bytes):
    """Total/primitive call counts from a dedicated pass, strictly outside the timed loop.

    The first pass of a process carries ~200k one-time calls (ApiScout DB parse, regex
    compilation, demangler caches), so it is discarded: only the warm pass is reported. Two
    separate processes then agree to the digit, which is what makes this metric usable at all.
    """
    disassemble_fixture(config, fixture, binary_bytes)
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        disassemble_fixture(config, fixture, binary_bytes)
    finally:
        profiler.disable()
    stats = pstats.Stats(profiler)
    return stats.total_calls, stats.prim_calls


def run_benchmark(iterations, output_file, append=False, with_call_counts=False):
    # Disable logging during benchmark to avoid stdout/file write overhead in the timed region
    logging.disable(logging.CRITICAL)
    config = SmdaConfig()
    config.PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    config.API_COLLECTION_FILES = {"winxp": os.path.join(config.PROJECT_ROOT, "data", "apiscout_winxp_prof_sp3.json")}

    fixtures = [
        {"name": "asprox", "filename": "asprox_0x008D0000_xored", "base_addr": 0x8D0000, "backend": "intel"},
        {"name": "cutwail", "filename": "cutwail_xored", "base_addr": 0x4000000, "backend": "intel"},
        {"name": "bashlite", "filename": "bashlite_xored", "base_addr": 0, "backend": "intel"},
        {"name": "blockblast", "filename": "blockblast_classes_xored", "base_addr": 0, "backend": "dalvik"},
        {"name": "komplex", "filename": "komplex_xored", "base_addr": 0, "backend": "intel"},
        {"name": "njrat", "filename": "njrat_xored", "base_addr": 0, "backend": "cil"},
        {"name": "pe_export", "filename": "pe_export_label_test_xored", "base_addr": 0, "backend": "intel"},
        {"name": "aarch64_static", "filename": "aarch64_static_xored", "base_addr": 0, "backend": "aarch64"},
    ]

    results = {}
    tests_dir = os.path.join(config.PROJECT_ROOT, "tests")

    for fixture in fixtures:
        filepath = os.path.join(tests_dir, fixture["filename"])
        if not os.path.exists(filepath):
            print(f"Skipping {fixture['name']} - file not found: {filepath}", file=sys.stderr)
            continue

        print(f"Benchmarking {fixture['name']} ({fixture['backend']})...")
        binary_bytes = decrypt_binary(filepath)

        times = []
        report = None
        report_hashes = set()
        for _ in range(iterations):
            start = time.perf_counter()
            report = disassemble_fixture(config, fixture, binary_bytes)
            end = time.perf_counter()
            times.append(end - start)
            # hashed outside the timed region: identical input must yield an identical report,
            # and a side that disagrees with itself makes any cross-side comparison meaningless
            report_hashes.add(computeReportIdentityHash(report))

        if len(report_hashes) > 1:
            print(
                f"Error: '{fixture['name']}' produced {len(report_hashes)} different report hashes "
                f"across {iterations} iterations of the same input - the output is non-deterministic.",
                file=sys.stderr,
            )
            sys.exit(1)

        # measured in its own pass: tracemalloc materially slows allocation, so tracing
        # inside the timed loop would corrupt the channel it sits beside
        tracemalloc.start()
        try:
            disassemble_fixture(config, fixture, binary_bytes)
            peak_memory = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        num_functions = report.num_functions if report else 0
        num_instructions = report.num_instructions if report else 0
        num_blocks = report.num_blocks if report else 0

        # Extract function level details for correctness validation
        functions_meta = {}
        if report:
            for fn in report.getFunctions():
                functions_meta[hex(fn.offset)] = {
                    "num_blocks": len(list(fn.getBlocks())),
                    "num_instructions": len(list(fn.getInstructions())),
                }

        results[fixture["name"]] = {
            "backend": fixture["backend"],
            "execution_times": times,
            "median_time": statistics.median(times),
            "peak_memories": [peak_memory],
            "median_peak_memory": peak_memory,
            "num_functions": num_functions,
            "num_instructions": num_instructions,
            "num_blocks": num_blocks,
            "functions": functions_meta,
            "report_hash": report_hashes.pop() if report_hashes else "",
            "python_version": platform.python_version(),
        }

        if with_call_counts:
            total_calls, prim_calls = count_calls(config, fixture, binary_bytes)
            results[fixture["name"]]["total_calls"] = total_calls
            results[fixture["name"]]["prim_calls"] = prim_calls

    if output_file:
        if append and os.path.exists(output_file):
            with open(output_file, encoding="utf-8") as f:
                results = merge_results(json.load(f), results)
        # Create output directory if it doesn't exist
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, sort_keys=True)
        print(f"Benchmark results successfully written to {output_file}")
    else:
        print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SMDA performance and correctness checks on test fixtures")
    parser.add_argument("--iterations", type=int, default=3, help="Number of benchmark iterations")
    parser.add_argument("--output", type=str, default="", help="Path to write output JSON results")
    parser.add_argument(
        "--append",
        action="store_true",
        help="Merge this pass's timing samples into an existing output file instead of replacing it",
    )
    parser.add_argument(
        "--call-counts",
        action="store_true",
        help="Also record cProfile call counts (two extra untimed passes per fixture)",
    )
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    run_benchmark(args.iterations, args.output, append=args.append, with_call_counts=args.call_counts)
