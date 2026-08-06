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
import struct

import lief

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.synthesis import FORMAT_ELF, FORMAT_MACHO, FORMAT_PE
from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader
from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.lief_helper import safe_lief_parse
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.PeFileLoader import PeFileLoader

# The library deliberately turns malformed-input failures into error reports for
# callers. The fuzzing oracle is stricter: these exception classes indicate a
# programming defect when crafted input reaches them, except for the
# loader-specific struct.error carve-out below.
FUZZING_DEFECT_EXCEPTION_TYPES = (
    AssertionError,
    AttributeError,
    ImportError,
    IndexError,
    KeyError,
    MemoryError,
    NameError,
    RecursionError,
    ReferenceError,
    SyntaxError,
    TypeError,
    UnboundLocalError,
    ZeroDivisionError,
    struct.error,
)

# These are documented malformed-input outcomes across the parser targets.
FUZZING_ALLOWED_OPERATIONAL_EXCEPTION_TYPES = (ValueError, UnicodeDecodeError)

# struct.error is documented for truncated Mach-O structures and is also
# reachable through the generic MemoryFileLoader dispatch path. Format-target
# carve-outs are narrowed to MachoFileLoader below.
FUZZING_LOADER_EXCEPTION_TYPES = (struct.error,)

VALID_STATUS = frozenset({"ok", "timeout", "error"})

SYNTHESIS_FORMATS = (FORMAT_PE, FORMAT_ELF, FORMAT_MACHO)

ARCHITECTURES = ("intel", "aarch64", "cil", "dalvik", "unsupported")
BITNESSES = (None, 16, 32, 64)

FORMAT_LOADERS = (
    PeFileLoader,
    ElfFileLoader,
    MachoFileLoader,
    DelphiKbFileLoader,
    DexFileLoader,
)

FORMAT_PARSED_TYPES = {
    PeFileLoader: lief.PE.Binary,
    ElfFileLoader: lief.ELF.Binary,
    MachoFileLoader: (lief.MachO.Binary, lief.MachO.FatBinary),
}

# Analysis budget per input. The engine's own -timeout is the backstop for hangs
# inside native code; this keeps the cooperative timeout well below it.
ANALYSIS_TIMEOUT = 5


def _config():
    config = SmdaConfig()
    config.TIMEOUT = ANALYSIS_TIMEOUT
    return config


def _reraise_real_defect(exception, *, allow_struct_error=False):
    """Apply the stricter fuzzing oracle without changing the library contract."""
    if allow_struct_error and isinstance(exception, FUZZING_LOADER_EXCEPTION_TYPES):
        return
    if isinstance(exception, FUZZING_DEFECT_EXCEPTION_TYPES):
        raise
    if isinstance(exception, FUZZING_ALLOWED_OPERATIONAL_EXCEPTION_TYPES):
        return
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
        # the dispatch can land on MachoFileLoader but does not report which, so the
        # documented truncated-Mach-O struct.error has to be allowed for every loader
        _reraise_real_defect(exc, allow_struct_error=True)


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
        if hasattr(loader, "parseBinary"):
            parsed = loader.parseBinary(payload)
            expected_type = FORMAT_PARSED_TYPES.get(loader)
            if expected_type and not isinstance(parsed, expected_type):
                parsed = None
            kw = {"parsed": parsed}
        else:
            kw = {}
        loader.mapBinary(payload, **kw)
        loader.getBaseAddress(payload, **kw)
        loader.getBitness(payload, **kw)
        loader.getCodeAreas(payload, **kw)
        loader.getArchitecture(payload, **kw)
        loader.getAbi(payload, **kw)
        if hasattr(loader, "getHasBackend"):
            loader.getHasBackend(payload, **kw)
    except Exception as exc:
        _reraise_real_defect(exc, allow_struct_error=loader is MachoFileLoader)


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
    except Exception as exc:
        _reraise_real_defect(exc)
        return
    if not isinstance(parsed, dict):
        return
    try:
        smda_report = SmdaReport.fromDict(parsed)
        if smda_report is not None:
            smda_report.toDict()
    except Exception as exc:
        _reraise_real_defect(exc)


def synthesis(data):
    """Binary synthesis: rebuild a fictive file from a report and re-parse it.

    src/smda/synthesis/ writes binary headers from report-derived integers and is
    documented as not hardened against adversarial input, which makes it the one
    place where a crafted report reaches struct packing and offset arithmetic.
    """
    if not data:
        return
    output_format = SYNTHESIS_FORMATS[data[0] % len(SYNTHESIS_FORMATS)]
    try:
        parsed = json.loads(data[1:])
    except Exception as exc:
        _reraise_real_defect(exc)
        return
    if not isinstance(parsed, dict):
        return
    try:
        smda_report = SmdaReport.fromDict(parsed)
        if smda_report is None:
            return
        synthesized = smda_report.synthesizeBinary(output_format=output_format)
    except Exception as exc:
        _reraise_real_defect(exc)
        return
    # the point of synthesis is a loadable file, so bytes that no longer parse are
    # a defect in the synthesizer rather than a legitimate response to odd input
    if synthesized and safe_lief_parse(bytes(synthesized)) is None:
        raise AssertionError(f"synthesized {output_format} image does not parse")


TARGETS = {
    "loaders": loaders,
    "formats": formats,
    "disassembler": disassembler,
    "synthesis": synthesis,
    "buffer": buffer,
    "report": report,
}
