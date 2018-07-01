import hashlib
import signal
import datetime

from smda.common.SmdaExceptions import TimeoutException
from .DisassemblyStatistics import DisassemblyStatistics
from .intel.IntelDisassembler import IntelDisassembler


def signal_handler(signum, frame):
    raise TimeoutException("timed out")


class Disassembler(object):

    def __init__(self, config):
        self.config = config
        self.disassembler = IntelDisassembler(config)
        self.disassembly = None

    def disassemble(self, binary, base_addr, timeout=0):
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(timeout)
        self.disassembly = self.disassembler.analyzeBuffer(binary, base_addr)
        signal.alarm(0)
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
            "message": "Analysis finished regularly.",
            "sha256": hashlib.sha256(disassembly.binary).hexdigest(),
            "version": self.config.VERSION,
            "status": "ok",
            "summary": stats.calculate(),
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
            "xcfg": disassembly.collectCfg(),
        }
        return report

