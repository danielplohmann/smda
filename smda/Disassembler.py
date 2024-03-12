import hashlib
import datetime
import traceback
import logging

from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.StringExtractor import extract_strings
from smda.SmdaConfig import SmdaConfig
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaReport import SmdaReport
from .intel.IntelDisassembler import IntelDisassembler
from .ida.IdaExporter import IdaExporter

LOGGER = logging.getLogger(__name__)




class Disassembler(object):

    def __init__(self, config=None, backend="intel"):
        if config is None:
            config = SmdaConfig()
        self.config = config
        self.disassembler = None
        if backend == "intel":
            self.disassembler = IntelDisassembler(self.config)
        elif backend == "IDA":
            self.disassembler = IdaExporter(self.config)
        self._start_time = None
        self._timeout = 0
        # cache the last DisassemblyResult
        self.disassembly = None

    def _getDurationInSeconds(self, start_ts, end_ts):
        return (end_ts - start_ts).seconds + ((end_ts - start_ts).microseconds / 1000000.0)

    def _callbackAnalysisTimeout(self):
        if not self._timeout:
            return False
        time_diff = datetime.datetime.utcnow() - self._start_time
        LOGGER.debug("Current analysis callback time %s", (time_diff))
        return time_diff.seconds >= self._timeout
    
    def _addStringsToReport(self, smda_report, buffer):
        smda_report.buffer = buffer
        for smda_function in smda_report.getFunctions():
            function_strings = {}
            for string, addr in extract_strings(smda_function):
                function_strings[addr] = string
            smda_function.stringrefs = function_strings

    def disassembleFile(self, file_path, pdb_path=""):
        loader = FileLoader(file_path, map_file=True)
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
        binary_info.code_areas = loader.getCodeAreas()
        start = datetime.datetime.utcnow()
        try:
            self.disassembler.addPdbFile(binary_info, pdb_path)
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                self._addStringsToReport(smda_report, file_content)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            LOGGER.error("An error occurred while disassembling file.")
            # print("-> an error occured (", str(exc), ").")
            smda_report = self._createErrorReport(start, exc)
        return smda_report

    def disassembleUnmappedBuffer(self, file_content):
        loader = MemoryFileLoader(file_content, map_file=True)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        # we want the SHA256/SHA1/MD5 of the unmapped file not how we mapped it to memory
        binary_info.sha256 = hashlib.sha256(binary_info.raw_data).hexdigest()
        binary_info.sha1 = hashlib.sha1(binary_info.raw_data).hexdigest()
        binary_info.md5 = hashlib.md5(binary_info.raw_data).hexdigest()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        start = datetime.datetime.utcnow()
        try:
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                self._addStringsToReport(smda_report, file_content)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            LOGGER.error("An error occurred while disassembling unmapped buffer.")
            # print("-> an error occured (", str(exc), ").")
            smda_report = self._createErrorReport(start, exc)
        return smda_report

    def disassembleBuffer(self, file_content, base_addr, bitness=None, code_areas=None, oep=None):
        """
        Disassemble a given buffer (file_content), with given base_addr.
        Optionally specify bitness, the areas to which disassembly should be limited to (code_areas) and an entry point (oep)
        """
        start = datetime.datetime.utcnow()
        try:
            binary_info = BinaryInfo(file_content)
            binary_info.base_addr = base_addr
            binary_info.bitness = bitness
            binary_info.is_buffer = True
            binary_info.code_areas = code_areas
            binary_info.oep = oep
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.WITH_STRINGS:
                self._addStringsToReport(smda_report, file_content)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            LOGGER.error("An error occurred while disassembling buffer.")
            # print("-> an error occured (", str(exc), ").")
            smda_report = self._createErrorReport(start, exc)
        return smda_report

    def _disassemble(self, binary_info, timeout=0):
        self._start_time = datetime.datetime.utcnow()
        self._timeout = timeout
        self.disassembly = self.disassembler.analyzeBuffer(binary_info, self._callbackAnalysisTimeout)
        return SmdaReport(self.disassembly, config=self.config)

    def _createErrorReport(self, start, exception):
        report = SmdaReport(config=self.config)
        report.smda_version = self.config.VERSION
        report.status = "error"
        report.execution_time = self._getDurationInSeconds(start, datetime.datetime.utcnow())
        report.message = traceback.format_exc()
        return report
