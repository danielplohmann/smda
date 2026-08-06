import base64
import datetime
import io
import json
import logging
import os
import zipfile
from typing import Any, Dict, Iterator, List, Optional

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs

from smda.common.BlockLocator import BlockLocator
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.DisassemblyStatistics import DisassemblyStatistics

from .BinaryInfo import BinaryInfo
from .SmdaBasicBlock import SmdaBasicBlock
from .SmdaFunction import MAX_ADDRESS_VALUE, SmdaFunction

LOGGER = logging.getLogger(__name__)

REQUIRED_REPORT_FIELDS = frozenset(
    {
        "architecture",
        "base_addr",
        "binary_size",
        "bitness",
        "code_areas",
        "confidence_threshold",
        "disassembly_errors",
        "execution_time",
        "identified_alignment",
        "message",
        "sha256",
        "smda_version",
        "status",
        "xcfg",
    }
)
INTEGER_REPORT_FIELDS = frozenset(
    {
        "base_addr",
        "binary_size",
        "bitness",
        "identified_alignment",
        "oep",
    }
)
REAL_REPORT_FIELDS = frozenset({"confidence_threshold", "execution_time"})
REQUIRED_STATISTICS_FIELDS = frozenset(
    {
        "num_functions",
        "num_recursive_functions",
        "num_leaf_functions",
        "num_basic_blocks",
        "num_instructions",
        "num_api_calls",
        "num_function_calls",
        "num_failed_functions",
        "num_failed_instructions",
    }
)


class SmdaReport:
    architecture = None
    abi = None
    base_addr = None
    binary_size = None
    binweight = 0
    bitness = None
    block_locator = None
    buffer = None
    code_areas = None
    # immutable-by-convention sentinel: __init__ always rebinds this to a fresh list
    code_sections: List[Any] = []
    component = None
    confidence_threshold = None
    disassembly_errors = None
    execution_time = None
    family = None
    filename = None
    identified_alignment = None
    is_library = None
    is_buffer = None
    language = None
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
    # likewise a sentinel only; every construction path assigns a fresh dict below
    xcfg: Dict[int, "SmdaFunction"] = {}
    xheader = None
    pe_header_hash = None
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
        # never leave this pointing at the shared class-level sentinel
        self.code_sections = []
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
            self.language = self._normalizeLanguage(disassembly.language)
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
            self.pe_header_hash = disassembly.binary_info.getPeHeaderHash()
            pairs = sorted((s, d) for s, ds in disassembly.data_refs_from.items() for d in ds)
            self.data_refs_from = {}
            self.data_refs_to = {}
            for src, dst in pairs:
                self.data_refs_from.setdefault(src, []).append(dst)
                self.data_refs_to.setdefault(dst, []).append(src)
            self.xmetadata = {
                "exported_functions": disassembly.binary_info.getExportedFunctions(),
                "exported_symbols": disassembly.binary_info.getExportedSymbols(),
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

    def getBuffer(self) -> Optional[bytes]:
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

    def __getstate__(self):
        # the capstone singleton holds ctypes pointers and cannot be pickled; the class-level
        # default makes attribute lookup fall through to None after unpickling, so getCapstone()
        # simply re-creates it on demand
        state = self.__dict__.copy()
        state.pop("capstone", None)
        return state

    def getCapstone(self):
        if self.capstone is None:
            if self.architecture is not None and self.architecture not in ("intel", "aarch64"):
                raise NotImplementedError(
                    f"getCapstone() is only available for Intel and AArch64, not '{self.architecture}'"
                )
            if self.architecture == "aarch64":
                self.capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            else:
                self.capstone = Cs(CS_ARCH_X86, CS_MODE_64) if self.bitness == 64 else Cs(CS_ARCH_X86, CS_MODE_32)
            self.capstone.detail = True
        return self.capstone

    def getInstructionEscaper(self):
        return SmdaFunction.getInstructionEscaper(self.architecture)

    def synthesizeBinary(
        self, output_format=None, function_offsets=None, with_imports=True, with_strings=True
    ) -> bytes:
        """Experimental: rebuild a fictive unmapped binary file (PE/ELF/Mach-O) from this report.

        Recovered function bytes are planted at their original virtual addresses, referenced
        strings at their data addresses, and import metadata is fused into a loadable import
        structure. ``output_format`` ("pe", "elf", "macho") defaults to sniffing the stored
        xheader; it is required for headerless reports (e.g. shellcode buffers).
        """
        from smda.synthesis import createSynthesizer

        if self.architecture in ("cil", "dalvik"):
            raise NotImplementedError(f"binary synthesis is not supported for '{self.architecture}' reports")
        missing = [field for field in ("base_addr", "binary_size", "bitness") if getattr(self, field) is None]
        if missing:
            raise ValueError(f"cannot synthesize a binary from a report without {', '.join(missing)}")
        synthesizer = createSynthesizer(self, output_format)
        return synthesizer.synthesize(
            function_offsets=function_offsets, with_imports=with_imports, with_strings=with_strings
        )

    def getSection(self, offset):
        for section in self.code_sections:
            if section[1] <= offset < section[2]:
                return section

    def isAddrWithinMemoryImage(self, offset):
        base_addr = self.base_addr or 0
        return base_addr <= offset < base_addr + (self.binary_size or 0)

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
            with open(file_path, encoding="utf-8") as fjson:
                smda_json = json.load(fjson)
        else:
            raise FileNotFoundError
        return SmdaReport.fromDict(smda_json)

    @staticmethod
    def _normalizeLanguage(language):
        """Normalize legacy report values to the score-only language contract."""
        if isinstance(language, str):
            language_name = language.strip().lower()
            if not language_name:
                return {}
            if language_name == "cil":
                language_name = ".net"
            return {language_name: 1.0}
        if not isinstance(language, dict):
            return {}

        normalized = {}
        for language_name, score in language.items():
            if not isinstance(language_name, str) or language_name.startswith("_"):
                continue
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            score = float(score)
            if language_name == "delphi_kb_file":
                language_name = "delphi"
            elif language_name == "cil":
                language_name = ".net"
            normalized[language_name] = max(normalized.get(language_name, 0.0), score)
        return normalized

    @staticmethod
    def _validatedFunctionAddress(function_addr):
        """xcfg keys become function offsets; the synthesizers pack them unsigned."""
        address = int(function_addr)
        if not 0 <= address < MAX_ADDRESS_VALUE:
            raise ValueError("serialized report xcfg addresses must be in the 64-bit space")
        return address

    @classmethod
    def fromDict(cls, report_dict) -> Optional["SmdaReport"]:
        if not isinstance(report_dict, dict):
            raise ValueError("serialized report must be a dictionary")
        if not REQUIRED_REPORT_FIELDS.issubset(report_dict):
            raise ValueError("serialized report is incomplete")
        if not isinstance(report_dict["xcfg"], dict):
            raise ValueError("serialized report xcfg must be a dictionary")
        if "metadata" in report_dict and not isinstance(report_dict["metadata"], dict):
            raise ValueError("serialized report metadata must be a dictionary")
        for field in ("xdata_refs_from", "xdata_refs_to"):
            references = report_dict.get(field, {})
            if not isinstance(references, dict) or any(
                not isinstance(targets, (list, tuple)) or not all(isinstance(target, int) for target in targets)
                for targets in references.values()
            ):
                raise ValueError(f"serialized report {field} must map addresses to lists")
        code_sections = report_dict.get("code_sections", [])
        if not isinstance(code_sections, list) or any(
            not isinstance(section, (list, tuple)) or len(section) < 3 for section in code_sections
        ):
            raise ValueError("serialized report code_sections must contain three-item sequences")
        statistics = report_dict.get("statistics")
        if statistics:
            if not isinstance(statistics, dict):
                raise ValueError("serialized report statistics must be a dictionary")
            if not REQUIRED_STATISTICS_FIELDS.issubset(statistics):
                raise ValueError("serialized report statistics are incomplete")
        if not isinstance(report_dict.get("timestamp", ""), str):
            raise ValueError("serialized report timestamp must be a string")
        if "xheader" in report_dict and not isinstance(report_dict["xheader"], str):
            raise ValueError("serialized report xheader must be a string")
        if (
            "xmetadata" in report_dict
            and report_dict["xmetadata"] is not None
            and not isinstance(report_dict["xmetadata"], dict)
        ):
            raise ValueError("serialized report xmetadata must be a dictionary")
        if report_dict.get("smda_version") is not None and not isinstance(report_dict["smda_version"], str):
            raise ValueError("serialized report smda_version must be a string")
        for field in INTEGER_REPORT_FIELDS:
            value = report_dict.get(field)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"serialized report {field} must be an integer")
            if not 0 <= value < MAX_ADDRESS_VALUE:
                raise ValueError(f"serialized report {field} must fit in a 64-bit address space")
        for field in REAL_REPORT_FIELDS:
            value = report_dict.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
                raise ValueError(f"serialized report {field} must be a number")
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
            if "language" in report_dict["metadata"]:
                smda_report.language = cls._normalizeLanguage(report_dict["metadata"]["language"])
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
            cls._validatedFunctionAddress(function_addr): SmdaFunction.fromDict(
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
        smda_report.pe_header_hash = report_dict.get("pe_header_hash") or None
        # fromDict mirrors __init__'s xmetadata = {} (not None) so downstream
        # consumers (e.g. BinarySynthesizer) never hit a TypeError on xmetadata["..."].
        smda_report.xmetadata = report_dict.get("xmetadata") or {}
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
                "language": self.language,
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
            "pe_header_hash": self.pe_header_hash if self.pe_header_hash else "",
            "xmetadata": self.xmetadata,
        }
        # only emit the (compressed) buffer when one was retained, e.g. via STORE_BUFFER;
        # keeps serialized reports unchanged for the default file/memory analysis path.
        # `is not None` so an intentionally stored empty buffer survives as b"" (not dropped).
        if self.buffer is not None:
            report_dict["buffer"] = self._packBuffer(self.buffer)
        return report_dict

    def toFile(self, output_filepath) -> None:
        with open(output_filepath, "w", encoding="utf-8") as fout:
            json.dump(self.toDict(), fout, indent=1, sort_keys=True)
            LOGGER.info(f"SmdaReport saved to: {output_filepath}")

    def __str__(self):
        duration = f"{self.execution_time:>6.3f}s" if self.execution_time is not None else "     ?s"
        if self.status == "error":
            return f"{duration} -> {self.message}"
        arch_str = f"{self.architecture}.{self.bitness}bit" if self.bitness else self.architecture
        base_addr = f"0x{self.base_addr:08x}" if self.base_addr is not None else "0x????????"
        return f"{duration} -> (architecture: {arch_str}, base_addr: {base_addr}): {len(self.xcfg)} functions"
