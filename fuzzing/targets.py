"""Fuzz target bodies, free of any atheris dependency.

Every function here takes a single ``bytes`` input and returns None, raising only
when the input revealed a genuine defect. Keeping the bodies importable without
atheris is what allows crash artifacts to be replayed (``replay.py``) and pinned
as regression tests on platforms where no atheris wheel exists.

Parameter-carrying targets consume a small fixed-size header from the front of
the input to pick their arguments instead of using a fuzzer-provided data
provider; the mutation engine explores those bytes like any other, and replay
stays byte-exact.
"""

import json

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader
from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.PeFileLoader import PeFileLoader

# Exceptions that the public contract treats as operational (i.e. any malformed
# input may legitimately produce them) but which still indicate a real defect
# when a fuzzer triggers them: unbounded recursion is a crash on CPython builds
# with a raised recursion limit and a latent stack overflow either way.
FATAL_EXCEPTION_TYPES = (RecursionError,)

VALID_STATUS = frozenset({"ok", "timeout", "error"})

ARCHITECTURES = ("intel", "aarch64", "cil", "dalvik", "unsupported")
BITNESSES = (None, 16, 32, 64)

FORMAT_LOADERS = (
    PeFileLoader,
    ElfFileLoader,
    MachoFileLoader,
    DelphiKbFileLoader,
    DexFileLoader,
)

# Analysis budget per input. The engine's own -timeout is the backstop for hangs
# inside native code; this keeps the cooperative timeout well below it.
ANALYSIS_TIMEOUT = 5


def _config():
    config = SmdaConfig()
    config.TIMEOUT = ANALYSIS_TIMEOUT
    return config


def _reraise_real_defect(exception):
    """Swallow operational exceptions, propagate everything that is a defect."""
    if isinstance(exception, FATAL_EXCEPTION_TYPES):
        raise
    reraise_non_operational_exception(exception)


def _check_report(report):
    if report is None:
        raise AssertionError("disassembly returned None instead of a report")
    if report.status not in VALID_STATUS:
        raise AssertionError(f"invalid report status: {report.status}")


def loaders(data):
    """MemoryFileLoader mapping path, mirroring the public loader contract."""
    try:
        loader = MemoryFileLoader(data, map_file=True)
        loader.getData()
        loader.getRawData()
        loader.getBaseAddress()
        loader.getBitness()
        loader.getArchitecture()
        loader.getAbi()
        loader.getCodeAreas()
        loader.getHasBackend()
    except Exception as exc:
        _reraise_real_defect(exc)


def formats(data):
    """A single format loader, invoked with isCompatible() deliberately bypassed.

    Mutation rarely preserves a magic header, so the generic path above spends
    most of its budget in the unrecognized-format branch. Pinning one loader per
    input reaches the header-parsing code of every format instead.
    """
    if not data:
        return
    loader = FORMAT_LOADERS[data[0] % len(FORMAT_LOADERS)]
    payload = data[1:]
    try:
        kw = {"parsed": loader.parseBinary(payload)} if hasattr(loader, "parseBinary") else {}
        loader.mapBinary(payload, **kw)
        loader.getBaseAddress(payload, **kw)
        loader.getBitness(payload, **kw)
        loader.getCodeAreas(payload, **kw)
        loader.getArchitecture(payload, **kw)
        loader.getAbi(payload, **kw)
        if hasattr(loader, "getHasBackend"):
            loader.getHasBackend(payload, **kw)
    except Exception as exc:
        _reraise_real_defect(exc)


def disassembler(data):
    """Full unmapped-buffer pipeline: detection, mapping, CFG recovery, report.

    A fresh Disassembler per input: the instance caches a backend and the last
    DisassemblyResult, so reusing one would make a crash depend on the preceding
    input and defeat replay of the artifact on its own.
    """
    report = Disassembler(_config()).disassembleUnmappedBuffer(data)
    _check_report(report)


def buffer(data):
    """disassembleBuffer() with caller-supplied architecture/bitness/addresses.

    This is the API path that skips format detection, so the fuzzer — not a
    header — chooses the backend. It is also the only way to feed foreign-ISA
    bytes to a pinned backend, which is what exercises the instruction escapers
    and candidate filters of each architecture directly.
    """
    if len(data) < 4:
        return
    architecture = ARCHITECTURES[data[0] % len(ARCHITECTURES)]
    bitness = BITNESSES[data[1] % len(BITNESSES)]
    base_addr = int.from_bytes(data[2:4], "little") << 12
    payload = data[4:]
    try:
        report = Disassembler(_config()).disassembleBuffer(
            payload,
            base_addr,
            bitness=bitness,
            architecture=architecture,
        )
    except Exception as exc:
        _reraise_real_defect(exc)
        return
    _check_report(report)


def report(data):
    """SmdaReport JSON deserialization, the surface consumers ingest reports on."""
    try:
        parsed = json.loads(data)
    except Exception:
        return
    if not isinstance(parsed, dict):
        return
    try:
        smda_report = SmdaReport.fromDict(parsed)
        if smda_report is not None:
            smda_report.toDict()
    except Exception as exc:
        _reraise_real_defect(exc)


TARGETS = {
    "loaders": loaders,
    "formats": formats,
    "disassembler": disassembler,
    "buffer": buffer,
    "report": report,
}
