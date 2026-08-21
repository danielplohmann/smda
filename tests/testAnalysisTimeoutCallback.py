#!/usr/bin/python
"""The live analysis-timeout callback must reach candidate identification.

RecursiveDisassembler.analyzeBuffer received cbAnalysisTimeout but did not pass it
to fc_manager.init(), so a tripping callback could never halt the candidate scans
themselves — only the per-function analysis loops afterwards. These tests drive
analyzeBuffer end-to-end with an already-tripped callback and assert that the
scan-produced candidates (prologue/call-reference) are absent, on both backends.
"""

import unittest
from types import SimpleNamespace

from smda.aarch64.AArch64Disassembler import AArch64Disassembler
from smda.common.analysis_budget import analysisTimeoutTripped
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader
from tests.testAArch64Disassembler import _build_aarch64_elf, _fixture_code

# push rbp; mov rbp, rsp; pop rbp; ret — a common-prologue function at base
INTEL_BUF = b"\x55\x48\x89\xe5\x5d\xc3"
INTEL_BASE = 0x1000


def _intel_binary_info():
    binary_info = BinaryInfo(INTEL_BUF)
    binary_info.base_addr = INTEL_BASE
    binary_info.bitness = 64
    binary_info.architecture = "intel"
    return binary_info


def _aarch64_binary_info():
    loader = FileLoader("/", map_file=True)
    loader._loadFile(_build_aarch64_elf(_fixture_code()))
    return Disassembler()._populateBinaryInfo(loader)


class TimeoutCallbackReachesCandidateScansTestSuite(unittest.TestCase):
    def test_intel_tripped_callback_halts_candidate_identification(self):
        config = SmdaConfig()
        control = IntelDisassembler(config)
        control.analyzeBuffer(_intel_binary_info(), cbAnalysisTimeout=None)
        self.assertIn(INTEL_BASE, control.fc_manager.candidates)

        disassembler = IntelDisassembler(config)
        result = disassembler.analyzeBuffer(_intel_binary_info(), cbAnalysisTimeout=lambda: True)
        self.assertNotIn(INTEL_BASE, disassembler.fc_manager.candidates)
        self.assertTrue(result.analysis_timeout)

    def test_aarch64_tripped_callback_halts_candidate_identification(self):
        # f2 @ 0x401010 is discovered by the BL call-reference scan, which runs
        # after the first timeout check (the OEP/symbol pass before it still seeds
        # 0x401000 even when tripped, so assert on the scan-produced candidate).
        config = SmdaConfig()
        control = AArch64Disassembler(config)
        control.analyzeBuffer(_aarch64_binary_info(), cbAnalysisTimeout=None)
        self.assertIn(0x401010, control.fc_manager.candidates)

        disassembler = AArch64Disassembler(config)
        result = disassembler.analyzeBuffer(_aarch64_binary_info(), cbAnalysisTimeout=lambda: True)
        self.assertNotIn(0x401010, disassembler.fc_manager.candidates)
        self.assertTrue(result.analysis_timeout)


class BudgetVerdictLatchTestSuite(unittest.TestCase):
    """A caller scopes a budget by where it is called from - "spent while the tailcall pass is
    running" - so once that pass returns, the same callback answers "not spent". Every backend
    used to re-ask it at each pass and at the end, so a run the budget had already cut short
    reported ok. The verdict latches onto the result instead, and every later poll reads that
    first. All three analyzeBuffer implementations - native, CIL and Dalvik - share this."""

    def _spentOnceThenNot(self):
        """The shape a call-site-scoped budget presents: True while its pass runs, then False."""
        state = {"asked": 0}

        def callback():
            state["asked"] += 1
            return state["asked"] == 1

        return callback, state

    def test_a_verdict_that_tripped_once_stays_tripped(self):
        disassembly = SimpleNamespace(analysis_timeout=False)
        callback, state = self._spentOnceThenNot()

        self.assertTrue(analysisTimeoutTripped(disassembly, callback))
        self.assertTrue(disassembly.analysis_timeout)
        self.assertTrue(analysisTimeoutTripped(disassembly, callback))
        self.assertEqual(state["asked"], 1, "the latch must answer without asking again")

    def test_a_budget_that_never_trips_latches_nothing(self):
        """Positive control: the latch only records a real trip, so an intact budget is not
        turned into a timeout by having been polled."""
        disassembly = SimpleNamespace(analysis_timeout=False)

        self.assertFalse(analysisTimeoutTripped(disassembly, lambda: False))
        self.assertFalse(disassembly.analysis_timeout)

    def test_no_callback_at_all_never_trips(self):
        disassembly = SimpleNamespace(analysis_timeout=False)

        self.assertFalse(analysisTimeoutTripped(disassembly, None))
        self.assertFalse(disassembly.analysis_timeout)

    def test_a_missing_result_object_is_tolerated(self):
        """Passes construct backends without a result in places; the helper must not require
        one to answer."""
        self.assertFalse(analysisTimeoutTripped(None, lambda: False))
        self.assertTrue(analysisTimeoutTripped(None, lambda: True))


class IdaExporterTimeoutTestSuite(unittest.TestCase):
    def test_tripped_callback_halts_ida_function_collection(self):
        # IdaExporter.analyzeBuffer accepted cb_analysis_timeout but never polled
        # it; a tripping callback must stop function collection and flag the report
        from smda.DisassemblyResult import DisassemblyResult
        from smda.ida.IdaExporter import IdaExporter
        from smda.SmdaConfig import SmdaConfig

        exporter = IdaExporter.__new__(IdaExporter)  # no IDA environment available
        exporter.config = SmdaConfig()  # analyzeBuffer re-allocates the DisassemblyResult
        exporter.bitness = 64
        exporter.architecture = "intel"
        exporter.capstone = None
        exporter.disassembly = DisassemblyResult()
        exporter.ida_interface = SimpleNamespace(
            getArchitecture=lambda: "intel",
            getFunctionSymbols=dict,
            getApiMap=dict,
            getFunctions=lambda: [0x1000, 0x2000],
            isExternalFunction=lambda offset: False,
            getBlocks=lambda offset: [],
        )
        result = exporter.analyzeBuffer(_intel_binary_info(), cb_analysis_timeout=lambda: True)
        self.assertTrue(result.analysis_timeout)
        self.assertEqual(result.functions, {})


if __name__ == "__main__":
    unittest.main()
