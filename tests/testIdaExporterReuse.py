import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.DisassemblyResult import DisassemblyResult
from smda.ida.IdaExporter import IdaExporter
from smda.SmdaConfig import SmdaConfig


def _binary_info(base_addr, code):
    binary_info = BinaryInfo(code)
    binary_info.base_addr = base_addr
    binary_info.bitness = 64
    binary_info.architecture = "intel"
    return binary_info


class _FakeIdaInterface:
    """Stands in for one loaded IDA database: a single function of a single block."""

    def __init__(self, function_addr, instruction_bytes):
        self.function_addr = function_addr
        self.instruction_bytes = instruction_bytes

    def getArchitecture(self):
        return "intel"

    def getBaseAddr(self):
        return self.function_addr & ~0xFFF

    def getBinary(self):
        return self.instruction_bytes

    def getBitness(self):
        return 64

    def getFunctionSymbols(self):
        return {}

    def getApiMap(self):
        return {}

    def getFunctions(self):
        return [self.function_addr]

    def isExternalFunction(self, offset):
        return False

    def getBlocks(self, offset):
        return [[self.function_addr]]

    def getInstructionBytes(self, offset):
        return self.instruction_bytes

    def getCodeInRefs(self, offset):
        return []

    def getCodeOutRefs(self, offset):
        return []


class IdaExporterReuseTestSuite(unittest.TestCase):
    """A reused IdaExporter must not merge the previous database into the new report.

    Every other backend re-allocates its DisassemblyResult in analyzeBuffer; IdaExporter
    built one only in __init__. Because Disassembler(backend="IDA") pins the backend
    (_explicit_backend) and never rebuilds it, a second disassembleFile/analyzeBuffer
    accumulated the previous run's functions, instructions and xrefs into the new report.
    """

    @staticmethod
    def _exporter(ida_interface):
        exporter = IdaExporter.__new__(IdaExporter)  # no IDA environment available in tests
        exporter.config = SmdaConfig()
        exporter.bitness = 64
        exporter.architecture = "intel"
        exporter.disassembly = DisassemblyResult()
        exporter.ida_interface = ida_interface
        exporter._initCapstone()
        return exporter

    def test_second_analysis_does_not_accumulate_the_first(self):
        ret = b"\xc3"
        first = self._exporter(_FakeIdaInterface(0x1000, ret))
        first_report = first.analyzeBuffer(_binary_info(0x1000, ret))
        self.assertEqual(len(first_report.functions), 1)
        self.assertIn(0x1000, first_report.functions)

        # same exporter object, a different "database"
        first.ida_interface = _FakeIdaInterface(0x2000, ret)
        second_report = first.analyzeBuffer(_binary_info(0x2000, ret))

        self.assertEqual(len(second_report.functions), 1, "first run's functions leaked into the second report")
        self.assertIn(0x2000, second_report.functions)
        self.assertNotIn(0x1000, second_report.functions)

    def test_analyze_buffer_populates_report_metadata(self):
        # a bare `self.disassembly.binary_info = binary_info` assignment skipped
        # setBinaryInfo(), so IDA reports never populated exported_functions or oep
        ret = b"\xc3"
        exporter = self._exporter(_FakeIdaInterface(0x1000, ret))

        report = exporter.analyzeBuffer(_binary_info(0x1000, ret))

        self.assertEqual(report.smda_version, SmdaConfig.VERSION)
        self.assertIsNotNone(report.exported_functions)


class IdaInterfaceSingletonTestSuite(unittest.TestCase):
    def setUp(self):
        from smda.ida.IdaInterface import IdaInterface

        self._saved = IdaInterface.instance
        self.addCleanup(setattr, IdaInterface, "instance", self._saved)

    def test_close_clears_the_cached_singleton(self):
        # the cached instance is class-level, process-global state; closing through the
        # facade used to leave the closed backend cached, so later attribute access hit a
        # closed database and a fresh IdaInterface() returned the same dead object
        from smda.ida.IdaInterface import IdaInterface

        closed = []
        IdaInterface.instance = SimpleNamespace(close=lambda: closed.append(True))

        IdaInterface.__new__(IdaInterface).close()

        self.assertEqual(closed, [True])
        self.assertIsNone(IdaInterface.instance)


if __name__ == "__main__":
    unittest.main()
