"""Shared, profiler-agnostic SMDA workload.

Every profiler (cProfile, line_profiler, memray, py-spy) wraps the *same* unit of
work so their results are comparable: a single disassembly of one target. The
fixture catalog, the XOR decrypt, and the backend dispatch mirror the existing
benchmark harness in .github/workflows/scripts/run_perf_check.py — kept here as a
small, self-contained copy rather than importing across the dashed
".github/workflows/scripts" path (not an importable package). If these ever
drift, consider promoting a single shared module.

Guardrail: fixtures are XOR-decrypted into an in-memory buffer and handed to the
SMDA analyzer. They are never executed as programs.
"""

import os
import sys

# Allow running straight from a source checkout (mirrors run_perf_check.py).
# Harmless when smda is already importable via an editable install.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from smda.Disassembler import Disassembler  # noqa: E402
from smda.SmdaConfig import SmdaConfig  # noqa: E402

# name -> fixture spec. Same set the benchmark gate uses.
FIXTURES = {
    "asprox": {"filename": "asprox_0x008D0000_xored", "base_addr": 0x8D0000, "backend": "intel"},
    "cutwail": {"filename": "cutwail_xored", "base_addr": 0x4000000, "backend": "intel"},
    "bashlite": {"filename": "bashlite_xored", "base_addr": 0, "backend": "intel"},
    "blockblast": {"filename": "blockblast_classes_xored", "base_addr": 0, "backend": "dalvik"},
    "komplex": {"filename": "komplex_xored", "base_addr": 0, "backend": "intel"},
    "njrat": {"filename": "njrat_xored", "base_addr": 0, "backend": "cil"},
    "pe_export": {"filename": "pe_export_label_test_xored", "base_addr": 0, "backend": "intel"},
}


def decrypt_binary(filepath):
    """Decrypt an XOR-obfuscated test fixture (byte ^ (index % 256))."""
    with open(filepath, "rb") as f:
        binary = f.read()
    decrypted = bytearray()
    for index, byte in enumerate(binary):
        if isinstance(byte, str):
            byte = ord(byte)
        decrypted.append(byte ^ (index % 256))
    return bytes(decrypted)


def _make_config():
    config = SmdaConfig()
    config.PROJECT_ROOT = _REPO_ROOT
    config.API_COLLECTION_FILES = {"winxp": os.path.join(_REPO_ROOT, "data", "apiscout_winxp_prof_sp3.json")}
    return config


def _disassemble_fixture(config, spec):
    filepath = os.path.join(_REPO_ROOT, "tests", spec["filename"])
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fixture not found: {filepath}")
    binary_bytes = decrypt_binary(filepath)
    disasm = Disassembler(config, backend=spec["backend"])
    if spec["backend"] in ("dalvik", "cil") or spec["base_addr"] == 0:
        return disasm.disassembleUnmappedBuffer(binary_bytes)
    return disasm.disassembleBuffer(binary_bytes, spec["base_addr"])


def _disassemble_file(config, path):
    disasm = Disassembler(config)
    return disasm.disassembleFile(path)


def resolve_label(target):
    """Short, filesystem-safe label used for output filenames."""
    if target in FIXTURES:
        return target
    return os.path.splitext(os.path.basename(target))[0] or "target"


def build_workload(target, with_strings=False):
    """Return a zero-arg callable that performs ONE disassembly of `target`.

    `target` is either a fixture name (see FIXTURES) or a path to a real binary.
    The returned report exposes num_functions / num_instructions / num_blocks.
    """
    config = _make_config()
    config.WITH_STRINGS = with_strings

    if target in FIXTURES:
        spec = FIXTURES[target]

        def _run():
            return _disassemble_fixture(config, spec)

        return _run

    if os.path.exists(target):

        def _run():
            return _disassemble_file(config, target)

        return _run

    raise ValueError(
        f"Unknown target '{target}'. Use a fixture name ({', '.join(sorted(FIXTURES))}) "
        f"or a path to an existing binary."
    )


def run_workload(target, iterations=1, with_strings=False):
    """Run the workload `iterations` times; return the last SmdaReport."""
    workload = build_workload(target, with_strings=with_strings)
    report = None
    for _ in range(max(1, iterations)):
        report = workload()
    return report
