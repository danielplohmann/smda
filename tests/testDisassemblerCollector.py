import gc
import unittest
from unittest import mock

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler

X86 = bytes([0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3])  # push rbp; mov rbp, rsp; pop rbp; ret


class TestCollectorSuspendedDuringAnalysis(unittest.TestCase):
    """Full collections over the growing analysis heap find no garbage, so they are skipped."""

    def setUp(self):
        self.addCleanup(gc.enable if gc.isenabled() else gc.disable)
        self.collecting = []

    def _recordingReport(self, *args, **kwargs):
        self.collecting.append(gc.isenabled())
        return SmdaReport(*args, **kwargs)

    def test_collector_is_off_while_analysing_and_back_on_afterwards(self):
        gc.enable()
        with mock.patch("smda.Disassembler.SmdaReport", side_effect=self._recordingReport):
            report = Disassembler().disassembleBuffer(X86, 0x400000, bitness=64, architecture="intel")

        self.assertEqual(report.status, "ok")
        self.assertEqual(self.collecting, [False])
        self.assertTrue(gc.isenabled())

    def test_collector_is_back_on_after_a_failed_analysis(self):
        gc.enable()
        with mock.patch("smda.Disassembler.SmdaReport", side_effect=[RuntimeError("boom"), SmdaReport()]):
            report = Disassembler().disassembleBuffer(X86, 0x400000, bitness=64, architecture="intel")

        self.assertEqual(report.status, "error")
        self.assertTrue(gc.isenabled())

    def test_a_caller_that_disabled_the_collector_keeps_it_disabled(self):
        gc.disable()
        Disassembler().disassembleBuffer(X86, 0x400000, bitness=64, architecture="intel")

        self.assertFalse(gc.isenabled())


if __name__ == "__main__":
    unittest.main()
