import hashlib
import datetime
import time

import lief

from .DisassemblyStatistics import DisassemblyStatistics
from .intel.IntelDisassembler import IntelDisassembler


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
            "execution_time": disassembly.getAnalysisDuration(),
            "meta" : {
                "message": "Analysis finished regularly."
            },
            "sha256": hashlib.sha256(disassembly.binary).hexdigest(),
            "version": self.config.VERSION,
            "status": disassembly.getAnalysisOutcome(),
            "summary": stats.calculate(),
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
            "xcfg": disassembly.collectCfg(),
        }
        return report
