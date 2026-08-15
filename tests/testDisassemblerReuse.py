import datetime
import logging
import unittest

from smda.Disassembler import Disassembler


class TestDisassemblerReuse(unittest.TestCase):
    X86 = bytes([0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3])  # push rbp; mov rbp, rsp; pop rbp; ret
    ARM = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

    def test_fresh_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        report = d.disassembleBuffer(self.ARM, 0x400000, bitness=64, architecture="arm")
        self.assertEqual(report.status, "error")

    def test_reused_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        first = d.disassembleBuffer(self.X86, 0x400000, bitness=64, architecture="intel")
        self.assertEqual(first.status, "ok")
        self.assertEqual(first.architecture, "intel")

        second = d.disassembleBuffer(self.ARM, 0x400000, bitness=64, architecture="arm")
        self.assertEqual(second.status, "error")


class TestAnalysisTimeoutIsAnnounced(unittest.TestCase):
    """A timed-out run returns a partial report that otherwise looks like a complete one, so the
    stop has to be announced once at default log level rather than only at debug level."""

    def setUp(self):
        # several test modules call logging.disable(CRITICAL) at import time, and that is
        # process-global, so assertLogs sees nothing in a full-suite run unless it is lifted
        previously_disabled = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previously_disabled)

    def _expiredDisassembler(self):
        disassembler = Disassembler()
        disassembler._timeout = 10
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
        return disassembler

    def test_the_stop_is_reported_once_however_often_the_callback_runs(self):
        disassembler = self._expiredDisassembler()

        with self.assertLogs("smda.Disassembler", level="WARNING") as logged:
            self.assertTrue(disassembler._callbackAnalysisTimeout())
            self.assertTrue(disassembler._callbackAnalysisTimeout())

        self.assertEqual(len(logged.output), 1)
        self.assertIn("incomplete", logged.output[0])

    def test_a_run_within_its_budget_reports_nothing(self):
        disassembler = Disassembler()
        disassembler._timeout = 300
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc)

        with self.assertNoLogs("smda.Disassembler", level="WARNING"):
            self.assertFalse(disassembler._callbackAnalysisTimeout())

    def test_a_reused_instance_reports_the_next_run_too(self):
        disassembler = self._expiredDisassembler()
        with self.assertLogs("smda.Disassembler", level="WARNING"):
            self.assertTrue(disassembler._callbackAnalysisTimeout())

        disassembler.disassembleBuffer(TestDisassemblerReuse.X86, 0x400000, bitness=64, architecture="intel")
        disassembler._timeout = 10
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)

        with self.assertLogs("smda.Disassembler", level="WARNING"):
            self.assertTrue(disassembler._callbackAnalysisTimeout())


if __name__ == "__main__":
    unittest.main()
