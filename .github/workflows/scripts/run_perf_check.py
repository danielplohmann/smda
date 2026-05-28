#!/usr/bin/env python3
import argparse
import json
import os
import statistics
import sys
import time

# Setup python path so we can run the script directly from the repo root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src")))

try:
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig
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


def run_benchmark(iterations, output_file):
    config = SmdaConfig()
    config.PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    # Disable logging during benchmark to avoid stdout/file write overhead
    config.API_COLLECTION_FILES = {"winxp": os.path.join(config.PROJECT_ROOT, "data", "apiscout_winxp_prof_sp3.json")}

    fixtures = [
        {"name": "asprox", "filename": "asprox_0x008D0000_xored", "base_addr": 0x8D0000, "backend": "intel"},
        {"name": "cutwail", "filename": "cutwail_xored", "base_addr": 0x4000000, "backend": "intel"},
        {"name": "bashlite", "filename": "bashlite_xored", "base_addr": 0, "backend": "intel"},
        {"name": "blockblast", "filename": "blockblast_classes_xored", "base_addr": 0, "backend": "dalvik"},
        {"name": "komplex", "filename": "komplex_xored", "base_addr": 0, "backend": "intel"},
        {"name": "njrat", "filename": "njrat_xored", "base_addr": 0, "backend": "cil"},
        {"name": "pe_export", "filename": "pe_export_label_test_xored", "base_addr": 0, "backend": "intel"},
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
        for _ in range(iterations):
            disasm = Disassembler(config, backend=fixture["backend"])
            start = time.perf_counter()
            if fixture["backend"] in ("dalvik", "cil"):
                report = disasm.disassembleUnmappedBuffer(binary_bytes)
            else:
                if fixture["base_addr"] != 0:
                    report = disasm.disassembleBuffer(binary_bytes, fixture["base_addr"])
                else:
                    report = disasm.disassembleUnmappedBuffer(binary_bytes)
            end = time.perf_counter()
            times.append(end - start)

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
            "num_functions": num_functions,
            "num_instructions": num_instructions,
            "num_blocks": num_blocks,
            "functions": functions_meta,
        }

    if output_file:
        # Create output directory if it doesn't exist
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, sort_keys=True)
        print(f"Benchmark results successfully written to {output_file}")
    else:
        print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SMDA performance and correctness checks on test fixtures")
    parser.add_argument("--iterations", type=int, default=3, help="Number of benchmark iterations")
    parser.add_argument("--output", type=str, default="", help="Path to write output JSON results")
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    run_benchmark(args.iterations, args.output)
