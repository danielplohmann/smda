import datetime
import hashlib
import os
import time
import traceback

from .DisassemblyStatistics import DisassemblyStatistics
from .intel.IntelDisassembler import IntelDisassembler
from smda.utility.FileLoader import FileLoader

class Disassembler(object):

    def __init__(self, config):
        self.config = config
        self.disassembler = IntelDisassembler(config)
        self.disassembly = None
        self._start_time = None
        self._timeout = 0

    def _callbackAnalysisTimeout(self):
        if not self._timeout:
            return False
        return time.time() - self._start_time > self._timeout

    def disassembleFile(self, file_path, pdb_path=""):
        loader = FileLoader(file_path, map_file=True)
        base_addr = loader.getBaseAddress()
        file_content = loader.getData()
        start = time.clock()
        try:
            self.disassembler.setFilePath(file_path)
            self.disassembler.addPdbFile(pdb_path, base_addr)
            disassembly = self.disassemble(file_content, base_addr, timeout=self.config.TIMEOUT)
            report = self.getDisassemblyReport(disassembly)
            report["filename"] = os.path.basename(file_path)
            print(disassembly)
        except Exception as exc:
            print("-> an error occured (", str(exc), ").")
            report = {"status":"error", "meta": {"traceback": traceback.format_exc(exc)}, "execution_time": time.clock() - start}
        return report

    def disassembleBuffer(self, file_content, base_addr, bitness=None):
        start = time.clock()
        try:
            self.disassembler.setFilePath("")
            disassembly = self.disassemble(file_content, base_addr, bitness, timeout=self.config.TIMEOUT)
            report = self.getDisassemblyReport(disassembly)
            report["filename"] = ""
            print(disassembly)
        except Exception as exc:
            print("-> an error occured (", str(exc), ").")
            report = {"status":"error", "meta": {"traceback": traceback.format_exc(exc)}, "execution_time": time.clock() - start}
        return report

    def disassemble(self, binary, base_addr, bitness=None, timeout=0):
        self._start_time = time.time()
        self._timeout = timeout
        self.disassembly = self.disassembler.analyzeBuffer(binary, base_addr, bitness, self._callbackAnalysisTimeout)
        return self.disassembly

    def getDisassemblyReport(self, disassembly=None):
        report = {}
        if disassembly is None:
            if self.disassembly is not None:
                disassembly = self.disassembly
            else:
                return {}
        stats = DisassemblyStatistics(disassembly)
        report = {
            "architecture": "intel",
            "base_addr": disassembly.base_addr,
            "bitness": disassembly.bitness,
            "buffer_size": len(disassembly.binary),
            "execution_time": disassembly.getAnalysisDuration(),
            "meta" : {
                "message": "Analysis finished regularly."
            },
            "sha256": hashlib.sha256(disassembly.binary).hexdigest(),
            "smda_version": self.config.VERSION,
            "status": disassembly.getAnalysisOutcome(),
            "summary": stats.calculate(),
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
            "xcfg": disassembly.collectCfg(),
        }
        return report
