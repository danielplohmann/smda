import binascii
import datetime
import json
import os
import zipfile
from typing import Optional, Iterator
try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from .BinaryInfo import BinaryInfo
from .SmdaFunction import SmdaFunction
from .SmdaBasicBlock import SmdaBasicBlock
from smda.common.CodeXref import CodeXref
from smda.common.BlockLocator import BlockLocator
from smda.DisassemblyStatistics import DisassemblyStatistics


class SmdaReport(object):

    architecture = None
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

    # on first usage, initialize codexrefs objects for all functions based on inrefs/outrefs (requires knowledge about all functions)
    _has_codexrefs = False
    # in case we need to re-disassemble with more detail, we hold an initialized capstone instance as singleton
    capstone = None

    def __init__(self, disassembly=None, config=None, buffer=None):
        if disassembly is not None:
            self.architecture = disassembly.binary_info.architecture
            self.base_addr = disassembly.binary_info.base_addr
            self.binary_size = disassembly.binary_info.binary_size
            self.binweight = 0
            self.bitness = disassembly.binary_info.bitness
            self.buffer = buffer
            self.code_areas = disassembly.binary_info.code_areas
            self.code_sections = [section for section in disassembly.binary_info.getSections()]
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
            self.timestamp = datetime.datetime.utcnow()
            self.version = disassembly.binary_info.version
            self.xcfg = self._convertCfg(disassembly, config=config)

    def _convertCfg(self, disassembly, config=None):
        function_results = {}
        for function_offset in disassembly.functions:
            if self.confidence_threshold and function_offset in disassembly.candidates and disassembly.candidates[function_offset].getConfidence() < self.confidence_threshold:
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
        sum_blocks = 0
        for function in self.getFunctions():
            sum_blocks += function.num_blocks
        return sum_blocks

    @property
    def num_instructions(self):
        sum_instructions = 0
        for function in self.getFunctions():
            sum_instructions += function.num_instructions
        return sum_instructions

    def getBuffer(self) -> bytes:
        return self.buffer

    def getFunction(self, function_addr)  -> Optional["SmdaFunction"]:
        return self.xcfg[function_addr] if function_addr in self.xcfg else None

    def getFunctions(self) -> Iterator["SmdaFunction"]:
        for _, smda_function in sorted(self.xcfg.items()):
            yield smda_function

    def getExportedFunctions(self):
        for _, smda_function in sorted(self.xcfg.items()):
            if smda_function.isExported():
                yield smda_function

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
            # create ins2fn map, and offset to SmdaInstruction map
            ins2fn = {}
            offset2ins = {}
            tmp_functions = []
            for function in self.getFunctions():
                tmp_functions.append(function.offset)
                for instruction in function.getInstructions():
                    ins2fn[instruction.offset] = function
                    offset2ins[instruction.offset] = instruction
            # for all functions, populate code references
            for function in self.getFunctions():
                function.code_inrefs = []
                for inref in function.inrefs:
                    if inref in offset2ins:
                        function.code_inrefs.append(CodeXref(offset2ins[inref], offset2ins[function.offset]))
                function.code_outrefs = []
                for outref_src, outref_dsts in function.outrefs.items():
                    for target in outref_dsts:
                        if target in offset2ins:
                            function.code_outrefs.append(CodeXref(offset2ins[outref_src], offset2ins[target]))
            self._has_codexrefs = True

    def _packBuffer(self, buffer):
        # TODO
        # create zip
        # XOR with some key
        # base64
        return b""

    def _unpackBuffer(self, buffer):
        # TODO
        # de-base64
        # XOR with some key
        # read from zip
        return b""

    @classmethod
    def fromFile(cls, file_path):
        smda_json = {}
        if os.path.isfile(file_path):
            with open(file_path, "r") as fjson:
                smda_json = json.load(fjson)
        else:
            raise FileNotFoundError
        return SmdaReport.fromDict(smda_json)

    @classmethod
    def fromDict(cls, report_dict) -> Optional["SmdaReport"]:
        smda_report = cls(None)
        smda_report.architecture = report_dict["architecture"]
        smda_report.base_addr = report_dict["base_addr"]
        smda_report.binary_size = report_dict["binary_size"]
        smda_report.bitness = report_dict["bitness"]
        smda_report.code_areas = report_dict["code_areas"]
        smda_report.code_sections = [("", section[1], section[2]) for section in report_dict["code_sections"]] if "code_sections" in report_dict else []
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
            smda_report.is_buffer = report_dict["metadata"]["is_buffer"] if "is_buffer" in report_dict["metadata"] else False
        smda_report.message = report_dict["message"]
        smda_report.oep = report_dict["oep"] if "oep" in report_dict else None
        smda_report.sha256 = report_dict["sha256"]
        smda_report.sha1 = report_dict["sha1"] if "sha1" in report_dict else None
        smda_report.md5 = report_dict["md5"] if "md5" in report_dict else None
        smda_report.smda_version = report_dict["smda_version"]
        smda_report.statistics = DisassemblyStatistics.fromDict(report_dict["statistics"])
        smda_report.status = report_dict["status"]
        smda_report.timestamp = datetime.datetime.strptime(report_dict["timestamp"], "%Y-%m-%dT%H-%M-%S")
        binary_info = BinaryInfo(b"")
        binary_info.architecture = smda_report.architecture
        binary_info.base_addr = smda_report.base_addr
        binary_info.binary_size = smda_report.binary_size
        binary_info.oep = smda_report.oep
        smda_report.xcfg = {int(function_addr): SmdaFunction.fromDict(function_dict, binary_info=binary_info, version=smda_report.smda_version, smda_report=smda_report) for function_addr, function_dict in report_dict["xcfg"].items()}
        return smda_report

    def toDict(self) -> dict:
        return {
            "architecture": self.architecture,
            "base_addr": self.base_addr,
            "binary_size": self.binary_size,
            "bitness": self.bitness,
            "code_areas": self.code_areas,
            "code_sections": [("", section[1], section[2]) for section in self.code_sections],
            "confidence_threshold": self.confidence_threshold,
            "disassembly_errors": self.disassembly_errors,
            "execution_time": self.execution_time,
            "identified_alignment": self.identified_alignment,
            "metadata" : {
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
            "statistics": self.statistics.toDict(),
            "status": self.status,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H-%M-%S"),
            "xcfg": {function_addr: smda_function.toDict() for function_addr, smda_function in self.xcfg.items()}
        }

    def __str__(self):
        if self.status == "error":
            return "{:>6.3f}s -> {}".format(self.execution_time, self.message)
        return "{:>6.3f}s -> (architecture: {}.{}bit, base_addr: 0x{:08x}): {} functions".format(self.execution_time, self.architecture, self.bitness, self.base_addr, len(self.xcfg))
