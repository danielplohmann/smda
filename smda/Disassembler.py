import datetime
import traceback

from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.SmdaConfig import SmdaConfig
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaReport import SmdaReport
from .intel.IntelDisassembler import IntelDisassembler
from .ida.IdaExporter import IdaExporter

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
        return time_diff.seconds >= self._timeout

    def disassembleFile(self, file_path, pdb_path=""):
        loader = FileLoader(file_path, map_file=True)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = file_path
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        start = datetime.datetime.utcnow()
        try:
            self.disassembler.addPdbFile(binary_info, pdb_path)
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            print("-> an error occured (", str(exc), ").")
            smda_report = self._createErrorReport(start, exc)
        return smda_report

    def disassembleUnmappedBuffer(self, file_content):
        loader = MemoryFileLoader(file_content, map_file=True)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        start = datetime.datetime.utcnow()
        try:
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            print("-> an error occured (", str(exc), ").")
            smda_report = self._createErrorReport(start, exc)
        return smda_report

    def disassembleBuffer(self, file_content, base_addr, bitness=None):
        start = datetime.datetime.utcnow()
        try:
            binary_info = BinaryInfo(file_content)
            binary_info.base_addr = base_addr
            binary_info.bitness = bitness
            binary_info.is_buffer = True
            smda_report = self._disassemble(binary_info, timeout=self.config.TIMEOUT)
            if self.config.STORE_BUFFER:
                smda_report.buffer = file_content
        except Exception as exc:
            print("-> an error occured (", str(exc), ").")
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
        report.message = traceback.format_exc(exception)
        return report
