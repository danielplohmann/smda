#!/usr/bin/python
"""The live analysis-timeout callback must reach candidate identification.

RecursiveDisassembler.analyzeBuffer received cbAnalysisTimeout but did not pass it
to fc_manager.init(), so a tripping callback could never halt the candidate scans
themselves — only the per-function analysis loops afterwards. These tests drive
analyzeBuffer end-to-end with an already-tripped callback and assert that the
scan-produced candidates (prologue/call-reference) are absent, on both backends.
"""

import unittest

from smda.aarch64.AArch64Disassembler import AArch64Disassembler
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


if __name__ == "__main__":
    unittest.main()
