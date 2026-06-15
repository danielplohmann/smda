import base64
import datetime
import io
import json
import logging
import os
import zipfile
from typing import Iterator, Optional

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.BlockLocator import BlockLocator
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.DisassemblyStatistics import DisassemblyStatistics

from .BinaryInfo import BinaryInfo
from .SmdaBasicBlock import SmdaBasicBlock
from .SmdaFunction import SmdaFunction

LOGGER = logging.getLogger(__name__)


class SmdaReport:
    architecture = None
    abi = None
    base_addr = None
    binary_size = None
    binweight = None
    bitness = None
    block_locator = None
    buffer = None
    code_areas = None
    code_sections = None
    component = None
    confidence_threshold = None
    disassembly_errors = None
    execution_time = None
    family = None
    filename = None
    identified_alignment = None
    is_library = None
    is_buffer = None
    message = None
    oep = None
    sha256 = None
    sha1 = None
    md5 = None
    smda_version = None
    statistics = None
    # status can be "ok", "timeout", "error"
    status = None
    timestamp = None
    version = None
    xcfg = None
    xheader = None
    data_refs_from = None
    data_refs_to = None

    # on first usage, initialize codexrefs objects for all functions based on inrefs/outrefs (requires knowledge about all functions)
    _has_codexrefs = False
    # in case we need to re-disassemble with more detail, we hold an initialized capstone instance as singleton
    capstone = None

    def __init__(self, disassembly=None, config=None, buffer=None):
        # caches owned by SmdaReport but populated lazily by StringExtractor; declared here so
        # their lifecycle is explicit and every construction path (incl. fromDict via cls(None))
        # starts with empty caches rather than relying on monkey-patched attributes.
        self._string_cache = {}
        self._derefs_cache = {}
        # start every construction path with an empty CFG so accessors like
        # num_functions/getFunction work on reports without a disassembly
        # (e.g. controlled error reports for unsupported architectures);
        # the regular path and fromDict overwrite this with the real CFG.
        self.xcfg = {}
        # likewise keep xmetadata serializable on reports without a disassembly
        # (it has no class-level default), so toDict()/toFile() never raise.
        self.xmetadata = {}
        if disassembly is not None:
            self.architecture = disassembly.binary_info.architecture
            self.abi = disassembly.binary_info.abi
            self.base_addr = disassembly.binary_info.base_addr
            self.binary_size = disassembly.binary_info.binary_size
            self.binweight = 0
            self.bitness = disassembly.binary_info.bitness
            self.buffer = buffer
            self.code_areas = disassembly.binary_info.code_areas
            self.code_sections = list(disassembly.binary_info.getSections())
            if self.code_sections is None:
                self.code_sections = []
            self.component = disassembly.binary_info.component
            self.confidence_threshold = disassembly.getConfidenceThreshold()
            self.disassembly_errors = disassembly.errors
            self.execution_time = disassembly.getAnalysisDuration()
            self.family = disassembly.binary_info.family
            self.filename = os.path.basename(disassembly.binary_info.file_path)
            self.identified_alignment = disassembly.identified_alignment
            self.is_library = disassembly.binary_info.is_library
            self.is_buffer = disassembly.binary_info.is_buffer
            self.message = "Analysis finished regularly."
            self.oep = disassembly.binary_info.getOep()
            self.sha256 = disassembly.binary_info.sha256
            self.sha1 = disassembly.binary_info.sha1
            self.md5 = disassembly.binary_info.md5
            self.smda_version = disassembly.smda_version
            self.statistics = DisassemblyStatistics(disassembly)
            self.status = disassembly.getAnalysisOutcome()
            if self.status == "timeout":
                self.message = "Analysis was stopped when running into the timeout."
            self.timestamp = datetime.datetime.now(datetime.timezone.utc)
            self.version = disassembly.binary_info.version
            self.xcfg = self._convertCfg(disassembly, config=config)
            self._num_blocks = sum(f.num_blocks for f in self.xcfg.values())
            self._num_instructions = sum(f.num_instructions for f in self.xcfg.values())
            self.xheader = disassembly.binary_info.getHeaderBytes()
            pairs = sorted((s, d) for s, ds in disassembly.data_refs_from.items() for d in ds)
            self.data_refs_from = {}
            self.data_refs_to = {}
            for src, dst in pairs:
                self.data_refs_from.setdefault(src, []).append(dst)
                self.data_refs_to.setdefault(dst, []).append(src)
            self.xmetadata = {
                "exported_functions": disassembly.binary_info.getExportedFunctions(),
                "imported_functions": disassembly.binary_info.getImportedFunctions(),
                "symbols": disassembly.binary_info.getSymbols(),
            }

    def _convertCfg(self, disassembly, config=None):
        function_results = {}
        for function_offset in disassembly.functions:
            if (
                self.confidence_threshold
                and function_offset in disassembly.candidates
                and disassembly.candidates[function_offset].getConfidence() < self.confidence_threshold
            ):
                continue
            smda_function = SmdaFunction(disassembly, function_offset, config=config, smda_report=self)
            function_results[function_offset] = smda_function
            self.binweight += smda_function.binweight
        return function_results

    @property
    def num_functions(self):
        return len(self.xcfg)

    @property
    def num_blocks(self):
        if getattr(self, "_num_blocks", None) is None:
            self._num_blocks = sum(function.num_blocks for function in self.getFunctions())
        return self._num_blocks

    @property
    def num_instructions(self):
        if getattr(self, "_num_instructions", None) is None:
            self._num_instructions = sum(function.num_instructions for function in self.getFunctions())
        return self._num_instructions

    def getBuffer(self) -> bytes:
        return self.buffer

    def getFunction(self, function_addr) -> Optional["SmdaFunction"]:
        return self.xcfg.get(function_addr, None)

    def getFunctions(self) -> Iterator["SmdaFunction"]:
        if getattr(self, "_sorted_functions", None) is None:
            self._sorted_functions = []
            if self.xcfg:
                self._sorted_functions = [smda_function for _, smda_function in sorted(self.xcfg.items())]
        yield from self._sorted_functions

    def getExportedFunctions(self):
        if getattr(self, "_sorted_exported_functions", None) is None:
            self._sorted_exported_functions = [
                smda_function for smda_function in self.getFunctions() if smda_function.isExported()
            ]
        yield from self._sorted_exported_functions

    def findFunctionByContainedAddress(self, inner_address) -> Optional["SmdaFunction"]:
        block = self.findBlockByContainedAddress(inner_address)
        if block is None:
            return None
        return block.smda_function

    def findBlockByContainedAddress(self, inner_address) -> Optional["SmdaBasicBlock"]:
        # init the block locator if it hasn't been used yet.
        if self.block_locator is None:
            self.block_locator = BlockLocator(self.getFunctions())

        block = self.block_locator.findBlockByContainedAddress(inner_address)
        return block

    def getCapstone(self):
        if self.capstone is None:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64) if self.bitness == 64 else Cs(CS_ARCH_X86, CS_MODE_32)
            self.capstone.detail = True
        return self.capstone

    def getSection(self, offset):
        for section in self.code_sections:
            if section[1] <= offset < section[2]:
                return section

    def isAddrWithinMemoryImage(self, offset):
        return self.base_addr <= offset < self.base_addr + self.binary_size

    def initCodeXrefs(self):
        if not self._has_codexrefs:
            # create offset to SmdaInstruction map
            self._offset2ins = {}
            for function in self.getFunctions():
                for instruction in function.getInstructions():
                    self._offset2ins[instruction.offset] = instruction
            self._has_codexrefs = True

    @staticmethod
    def _packBuffer(buffer: bytes) -> str:
        """Deflate-compress raw buffer bytes and base85-encode them into a JSON-safe string.

        Mirrors the scheme used by MCRIT so reports can optionally carry a recoverable
        copy of the analyzed buffer at a fraction of its on-disk footprint.
        """
        zip_buffer = io.BytesIO()
        # write via a ZipInfo with its default fixed timestamp so packing the same bytes is
        # reproducible across runs; writestr() with a plain str name would stamp the current
        # time into the entry header and make the output non-deterministic.
        entry = zipfile.ZipInfo("buffer")
        entry.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(zip_buffer, "w") as zip_file:
            zip_file.writestr(entry, buffer)
        return base64.b85encode(zip_buffer.getvalue()).decode("ascii")

    @staticmethod
    def _unpackBuffer(packed: str) -> bytes:
        """Inverse of :meth:`_packBuffer`: decode base85 and inflate the stored buffer bytes."""
        zip_buffer = io.BytesIO(base64.b85decode(packed))
        with zipfile.ZipFile(zip_buffer, "r") as zip_file:
            return zip_file.read("buffer")

    @classmethod
    def fromFile(cls, file_path):
        smda_json = {}
        if os.path.isfile(file_path):
            with open(file_path) as fjson:
                smda_json = json.load(fjson)
        else:
            raise FileNotFoundError
        return SmdaReport.fromDict(smda_json)

    @classmethod
    def fromDict(cls, report_dict) -> Optional["SmdaReport"]:
        smda_report = cls(None)
        smda_report.architecture = report_dict["architecture"]
        smda_report.abi = report_dict.get("abi", "")
        smda_report.base_addr = report_dict["base_addr"]
        smda_report.binary_size = report_dict["binary_size"]
        smda_report.bitness = report_dict["bitness"]
        smda_report.code_areas = report_dict["code_areas"] if report_dict["code_areas"] is not None else []
        smda_report.code_sections = (
            [("", section[1], section[2]) for section in report_dict["code_sections"]]
            if "code_sections" in report_dict
            else []
        )
        smda_report.confidence_threshold = report_dict["confidence_threshold"]
        smda_report.disassembly_errors = report_dict["disassembly_errors"]
        smda_report.execution_time = report_dict["execution_time"]
        smda_report.identified_alignment = report_dict["identified_alignment"]
        if "metadata" in report_dict:
            if "binweight" in report_dict["metadata"]:
                smda_report.binweight = report_dict["metadata"]["binweight"]
            if "component" in report_dict["metadata"]:
                smda_report.component = report_dict["metadata"]["component"]
            if "family" in report_dict["metadata"]:
                smda_report.family = report_dict["metadata"]["family"]
            if "filename" in report_dict["metadata"]:
                smda_report.filename = report_dict["metadata"]["filename"]
            if "is_library" in report_dict["metadata"]:
                smda_report.is_library = report_dict["metadata"]["is_library"]
            if "version" in report_dict["metadata"]:
                smda_report.version = report_dict["metadata"]["version"]
            smda_report.is_buffer = report_dict["metadata"].get("is_buffer", False)
        smda_report.message = report_dict["message"]
        smda_report.oep = report_dict.get("oep", None)
        smda_report.sha256 = report_dict["sha256"]
        smda_report.sha1 = report_dict.get("sha1", None)
        smda_report.md5 = report_dict.get("md5", None)
        smda_report.smda_version = report_dict["smda_version"]
        # mirror toDict: statistics is {} on a report without a disassembly
        statistics_raw = report_dict.get("statistics")
        smda_report.statistics = DisassemblyStatistics.fromDict(statistics_raw) if statistics_raw else None
        smda_report.status = report_dict["status"]
        # mirror toDict: a report serialized without a disassembly carries an
        # empty timestamp, which must round-trip back to None rather than raise
        timestamp_raw = report_dict.get("timestamp", "")
        smda_report.timestamp = (
            datetime.datetime.strptime(timestamp_raw, "%Y-%m-%dT%H-%M-%S") if timestamp_raw else None
        )
        smda_report.data_refs_from = {int(k): sorted(v) for k, v in report_dict.get("xdata_refs_from", {}).items()}
        smda_report.data_refs_to = {int(k): sorted(v) for k, v in report_dict.get("xdata_refs_to", {}).items()}
        binary_info = BinaryInfo(b"")
        binary_info.architecture = smda_report.architecture
        binary_info.abi = smda_report.abi
        binary_info.base_addr = smda_report.base_addr
        binary_info.binary_size = smda_report.binary_size
        binary_info.oep = smda_report.oep
        smda_report.xcfg = {
            int(function_addr): SmdaFunction.fromDict(
                function_dict,
                binary_info=binary_info,
                version=smda_report.smda_version,
                smda_report=smda_report,
            )
            for function_addr, function_dict in report_dict["xcfg"].items()
        }
        smda_report._num_blocks = sum(f.num_blocks for f in smda_report.xcfg.values())
        smda_report._num_instructions = sum(f.num_instructions for f in smda_report.xcfg.values())
        smda_report.xheader = bytes.fromhex(report_dict["xheader"]) if "xheader" in report_dict else None
        smda_report.xmetadata = report_dict.get("xmetadata", None)
        # buffer is only present when the report was serialized with STORE_BUFFER enabled;
        # older reports omit it and keep buffer == None for backward compatibility.
        if report_dict.get("buffer") is not None:
            try:
                smda_report.buffer = cls._unpackBuffer(report_dict["buffer"])
            except Exception as exc:
                # re-raise genuine non-operational errors (MemoryError, etc.); a corrupt/tampered
                # buffer field is operational and must not abort loading the rest of the report
                reraise_non_operational_exception(exc)
                LOGGER.warning("Failed to unpack stored buffer, leaving it unset: %s", exc)
        return smda_report

    def toDict(self) -> dict:
        transformed_code_sections = []
        if self.code_sections:
            for section in self.code_sections:
                if section is not None:
                    transformed_code_sections.append(("", section[1], section[2]))
                else:
                    transformed_code_sections.append(("", 0, 0))
        report_dict = {
            "architecture": self.architecture,
            "abi": self.abi,
            "base_addr": self.base_addr,
            "binary_size": self.binary_size,
            "bitness": self.bitness,
            "code_areas": self.code_areas,
            "code_sections": transformed_code_sections,
            "confidence_threshold": self.confidence_threshold,
            "disassembly_errors": self.disassembly_errors,
            "execution_time": self.execution_time,
            "identified_alignment": self.identified_alignment,
            "metadata": {
                "binweight": self.binweight,
                "component": self.component,
                "family": self.family,
                "filename": self.filename,
                "is_library": self.is_library,
                "is_buffer": self.is_buffer,
                "version": self.version,
            },
            "message": self.message,
            "oep": self.oep,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "smda_version": self.smda_version,
            "statistics": self.statistics.toDict() if self.statistics else {},
            "status": self.status,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H-%M-%S") if self.timestamp else "",
            "xcfg": {function_addr: smda_function.toDict() for function_addr, smda_function in self.xcfg.items()},
            "xdata_refs_from": self.data_refs_from if self.data_refs_from is not None else {},
            "xdata_refs_to": self.data_refs_to if self.data_refs_to is not None else {},
            "xheader": self.xheader.hex() if self.xheader else "",
            "xmetadata": self.xmetadata,
        }
        # only emit the (compressed) buffer when one was retained, e.g. via STORE_BUFFER;
        # keeps serialized reports unchanged for the default file/memory analysis path.
        # `is not None` so an intentionally stored empty buffer survives as b"" (not dropped).
        if self.buffer is not None:
            report_dict["buffer"] = self._packBuffer(self.buffer)
        return report_dict

    def toFile(self, output_filepath) -> None:
        with open(output_filepath, "w") as fout:
            json.dump(self.toDict(), fout, indent=1, sort_keys=True)
            LOGGER.info(f"SmdaReport saved to: {output_filepath}")

    def __str__(self):
        if self.status == "error":
            return f"{self.execution_time:>6.3f}s -> {self.message}"
        arch_str = f"{self.architecture}.{self.bitness}bit" if self.bitness else self.architecture
        return f"{self.execution_time:>6.3f}s -> (architecture: {arch_str}, base_addr: 0x{self.base_addr:08x}): {len(self.xcfg)} functions"
