import datetime
import hashlib
import logging
import traceback
from typing import Any, List, Optional

from smda.aarch64.AArch64Disassembler import AArch64Disassembler
from smda.aarch64.definitions import looksLikeAArch64
from smda.cil.CilDisassembler import CilDisassembler
from smda.common.BinaryInfo import BinaryInfo
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.SmdaReport import SmdaReport
from smda.dalvik.DalvikDisassembler import DalvikDisassembler
from smda.ida.IdaExporter import IdaExporter
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.StringExtractor import extract_strings

LOGGER = logging.getLogger(__name__)


class Disassembler:
    def __init__(self, config: Optional[SmdaConfig] = None, backend: Optional[str] = None) -> None:
        if config is None:
            config = SmdaConfig()
        self.config = config
        self.disassembler = None
        self._explicit_backend = bool(backend)
        self._active_architecture = backend if backend in ("intel", "aarch64", "cil", "dalvik") else None
        if backend == "intel":
            self.disassembler = IntelDisassembler(self.config)
        elif backend == "aarch64":
            self.disassembler = AArch64Disassembler(self.config)
        elif backend == "cil":
            self.disassembler = CilDisassembler(self.config)
        elif backend == "dalvik":
            self.disassembler = DalvikDisassembler(self.config)
        elif backend == "IDA":
            self.disassembler = IdaExporter(self.config)
        self._start_time = None
        self._timeout = 0
        self._last_timeout_log_second = -1
        # cache the last DisassemblyResult
        self.disassembly = None

    def initDisassembler(self, architecture: str = "intel") -> None:
        """Initialize disassembler backend to given architecture, default: intel.
        Re-creates the backend if a differing architecture is requested later, unless a
        backend was explicitly pinned at construction time (self._explicit_backend)."""
        if self.disassembler is not None and (self._explicit_backend or self._active_architecture == architecture):
            return
        if architecture == "intel":
            self.disassembler = IntelDisassembler(self.config)
        elif architecture == "aarch64":
            self.disassembler = AArch64Disassembler(self.config)
        elif architecture == "cil":
            self.disassembler = CilDisassembler(self.config)
        elif architecture == "dalvik":
            self.disassembler = DalvikDisassembler(self.config)
        else:
            # Unsupported architecture: do not keep a stale backend from a previous
            # analyze call on a reused instance, or it would silently disassemble
            # foreign-ISA bytes and stamp the report with the wrong architecture.
            self.disassembler = None
            self._active_architecture = None
            return
        self._active_architecture = architecture

    def _getDurationInSeconds(self, start_ts, end_ts):
        return (end_ts - start_ts).seconds + ((end_ts - start_ts).microseconds / 1000000.0)

    def _callbackAnalysisTimeout(self):
        if not self._timeout:
            return False
        start_time = self._start_time
        if start_time is None:
            return False
        time_diff = datetime.datetime.now(datetime.timezone.utc) - start_time
        elapsed_seconds = int(time_diff.total_seconds())
        if elapsed_seconds >= self._timeout:
            LOGGER.debug("Current analysis callback time %s", time_diff)
            return True
        # Log on 30s bucket transitions (not exact-second boundaries) so the message
        # still fires when callback timing skips past 30/60/... whole seconds.
        current_bucket = elapsed_seconds // 30
        if current_bucket >= 1 and current_bucket != self._last_timeout_log_second:
            self._last_timeout_log_second = current_bucket
            LOGGER.debug("Current analysis callback time %s", time_diff)
        return False

    def _addStringsToReport(self, smda_report, buffer, mode=None):
        # StringExtractor reads the buffer off the report, so set it only for the duration of
        # extraction and then restore the previous value. This keeps a buffer captured purely for
        # string extraction from being serialized later (persisting it is gated by STORE_BUFFER,
        # which assigns smda_report.buffer after this call).
        previous_buffer = smda_report.buffer
        smda_report.buffer = buffer
        try:
            self._extractStrings(smda_report, mode=mode)
        finally:
            smda_report.buffer = previous_buffer

    #: backends that record non-buffer-backed strings via disassembly.addStringRef
    #: (the string only exists as a runtime/decode-time side effect, e.g. CIL's
    #: ldstr token or an AArch64 stack-built string — there are no corresponding
    #: bytes anywhere in the file for the generic StringExtractor to find).
    _ANALYZER_STRINGREF_TYPES = {"dalvik": "dex", "cil": "cil", "aarch64": "stack"}

    def _extractStrings(self, smda_report, mode=None):
        architecture = smda_report.architecture
        analyzer_type = self._ANALYZER_STRINGREF_TYPES.get(architecture, "analyzer")
        for smda_function in smda_report.getFunctions():
            # SmdaFunction.__init__ sets stringrefs to the raw addStringRef dict
            # (ref_addr -> string) for every architecture when WITH_STRINGS is set;
            # normalize it into the same shape the generic extractor below produces.
            analyzer_provided = []
            if isinstance(smda_function.stringrefs, dict):
                analyzer_provided = [
                    {
                        "string": string_value,
                        "ins_addr": referencing_addr,
                        "data_addr": None,
                        "type": analyzer_type,
                    }
                    for referencing_addr, string_value in sorted(smda_function.stringrefs.items())
                ]
            if architecture == "dalvik":
                # DEX strings are part of the parsed file structure, not the raw
                # buffer bytes: the generic StringExtractor cannot see them either.
                continue
            function_strings = analyzer_provided
            for string_result in extract_strings(smda_function, mode=mode):
                string, referencing_addr, string_addr, string_type = string_result
                function_strings.append(
                    {
                        "string": string,
                        "ins_addr": referencing_addr,
                        "data_addr": string_addr,
                        "type": string_type,
                    }
                )
            smda_function.stringrefs = function_strings

    def _populateBinaryInfo(self, loader, file_path=""):
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        # we want the SHA256/SHA1/MD5 of the unmapped file not how we mapped it to memory
        binary_info.sha256 = hashlib.sha256(binary_info.raw_data).hexdigest()
        binary_info.sha1 = hashlib.sha1(binary_info.raw_data).hexdigest()
        binary_info.md5 = hashlib.md5(binary_info.raw_data).hexdigest()
        binary_info.file_path = file_path
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.architecture = loader.getArchitecture()
        binary_info.abi = loader.getAbi()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.has_backend = loader.getHasBackend()
        binary_info.format_recognized = loader.getFormatRecognized()
        return binary_info

    def _ensureHashes(self, binary_info):
        if binary_info.sha256 and binary_info.sha1 and binary_info.md5:
            return
        data = binary_info.raw_data if binary_info.raw_data else binary_info.binary
        if data is None:
            return
        if not binary_info.sha256:
            binary_info.sha256 = hashlib.sha256(data).hexdigest()
        if not binary_info.sha1:
            binary_info.sha1 = hashlib.sha1(data).hexdigest()
        if not binary_info.md5:
            binary_info.md5 = hashlib.md5(data).hexdigest()

    def disassembleFile(self, file_path: str, pdb_path: str = "") -> SmdaReport:
        start = datetime.datetime.now(datetime.timezone.utc)
        try:
            loader = FileLoader(file_path, map_file=True)
            binary_info = self._populateBinaryInfo(loader, file_path)
            self.initDisassembler(binary_info.architecture)
            if self.disassembler:
                self.disassembler.addPdbFile(binary_info, pdb_path)
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                go_pclntab_offset = GoSymbolProvider(None).getPcLntabOffset(binary_info)
                string_mode = "go" if go_pclntab_offset is not None else None
                self._addStringsToReport(smda_report, binary_info.binary, mode=string_mode)
            if self.config.STORE_BUFFER:
                smda_report.buffer = binary_info.binary
        except Exception as exc:
            smda_report = self._handleDisassemblyException(
                start,
                exc,
                "An error occurred while disassembling file.",
            )
        return smda_report

    def disassembleUnmappedBuffer(self, file_content: bytes) -> SmdaReport:
        start = datetime.datetime.now(datetime.timezone.utc)
        try:
            loader = MemoryFileLoader(file_content, map_file=True)
            binary_info = self._populateBinaryInfo(loader)
            self.initDisassembler(binary_info.architecture)
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                go_pclntab_offset = GoSymbolProvider(None).getPcLntabOffset(binary_info)
                string_mode = "go" if go_pclntab_offset is not None else None
                self._addStringsToReport(smda_report, binary_info.binary, mode=string_mode)
            if self.config.STORE_BUFFER:
                smda_report.buffer = binary_info.binary
        except Exception as exc:
            smda_report = self._handleDisassemblyException(
                start,
                exc,
                "An error occurred while disassembling unmapped buffer.",
            )
        return smda_report

    def disassembleBuffer(
        self,
        file_content: bytes,
        base_addr: int,
        bitness: Optional[int] = None,
        code_areas: Optional[List[Any]] = None,
        oep: Optional[int] = None,
        architecture: str = "",
    ) -> SmdaReport:
        """
        Disassemble a given buffer (file_content), with given base_addr.
        Optionally specify bitness, the areas to which disassembly should be limited to (code_areas), an entry point (oep)
        and the architecture. Leaving the architecture empty asks for auto-detection and falls back to intel;
        naming one is honoured as given, so a caller can hand foreign bytes to a specific backend deliberately.
        """
        # disassembleUnmappedBuffer / disassembleFile detect the architecture through
        # FileLoader; this path bypasses it, so an unspecified architecture is decided
        # from the bytes here.
        if not self._explicit_backend and not architecture:
            if DexFileLoader.isCompatible(file_content):
                architecture = "dalvik"
                if bitness is None:
                    bitness = DexFileLoader.getBitness(file_content)
            elif looksLikeAArch64(file_content):
                # A dump carries no container header to read the instruction set from, and
                # decoding AArch64 as x86 produces a full report whose every block is wrong.
                LOGGER.warning("Buffer contains AArch64 machine code; disassembling as aarch64 rather than intel.")
                architecture = "aarch64"
                if bitness is None:
                    bitness = 64
        architecture = architecture or "intel"
        binary_info = BinaryInfo(file_content)
        binary_info.base_addr = base_addr
        binary_info.bitness = bitness
        binary_info.is_buffer = True
        binary_info.code_areas = code_areas
        binary_info.architecture = architecture
        binary_info.oep = oep
        self.initDisassembler(binary_info.architecture)
        start = datetime.datetime.now(datetime.timezone.utc)
        try:
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                go_pclntab_offset = GoSymbolProvider(None).getPcLntabOffset(binary_info)
                string_mode = "go" if go_pclntab_offset is not None else None
                self._addStringsToReport(smda_report, binary_info.binary, mode=string_mode)
            if self.config.STORE_BUFFER:
                smda_report.buffer = binary_info.binary
        except Exception as exc:
            smda_report = self._handleDisassemblyException(
                start,
                exc,
                "An error occurred while disassembling buffer.",
            )
        return smda_report

    def _disassemble(self, binary_info, timeout=0):
        self._start_time = datetime.datetime.now(datetime.timezone.utc)
        self._timeout = timeout
        self._last_timeout_log_second = -1
        self._ensureHashes(binary_info)
        if self.disassembler:
            self.disassembly = self.disassembler.analyzeBuffer(binary_info, self._callbackAnalysisTimeout)
            return SmdaReport(self.disassembly, config=self.config)
        if not binary_info.has_backend:
            if not binary_info.architecture:
                if binary_info.format_recognized:
                    raise RuntimeError(
                        "The container was recognized but names an instruction set SMDA has no "
                        "backend for, so there is nothing to disassemble it with."
                    )
                raise RuntimeError(
                    "Input is not a PE, ELF, Mach-O, DEX or Delphi knowledge base, so neither its "
                    "instruction set nor its load address can be read from it. A memory dump has to "
                    "be passed to disassembleBuffer() with its base address."
                )
            raise RuntimeError(f"No disassembly backend available for architecture '{binary_info.architecture}'.")
        raise RuntimeError("Disassembler backend not initialized.")

    def _createErrorReport(self, start, exception):
        report = SmdaReport(config=self.config)
        report.smda_version = self.config.VERSION
        report.status = "error"
        report.execution_time = self._getDurationInSeconds(start, datetime.datetime.now(datetime.timezone.utc))
        report.message = traceback.format_exc()
        # stamp the report like the regular path so error reports (e.g. for
        # unsupported architectures) survive toDict()/toFile() serialization
        report.timestamp = datetime.datetime.now(datetime.timezone.utc)
        return report

    def _handleDisassemblyException(self, start, exception, log_message):
        reraise_non_operational_exception(exception)
        LOGGER.error(log_message)
        return self._createErrorReport(start, exception)
