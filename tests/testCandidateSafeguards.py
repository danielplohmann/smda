#!/usr/bin/python

import logging
import types
import unittest

from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)


def _make_manager(config, binary=b"\x55\x8b\xec" * 1024, base_addr=0x1000, bitness=32):
    """build a minimal FunctionCandidateManager wired with just enough state to exercise the caps."""
    manager = FunctionCandidateManager(config)
    binary_info = types.SimpleNamespace(bitness=bitness, base_addr=base_addr, binary=binary)
    manager.disassembly = types.SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
    manager.bitness = bitness
    return manager


class CandidateSafeguardsTestSuite(unittest.TestCase):
    """Tests for the memory-usage-explosion safeguards added for issue #85."""

    def test_max_function_candidates_cap_is_honored(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 10
        manager = _make_manager(config)
        # request far more candidates than the cap allows
        for offset in range(1000):
            manager.ensureCandidate(0x1000 + offset)
        self.assertEqual(len(manager.candidates), 10)

    def test_refused_candidate_does_not_raise_keyerror(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 1
        manager = _make_manager(config)
        # the first candidate is accepted, every later distinct address is refused; none of the
        # add-helpers must raise a KeyError when their candidate gets refused.
        for offset in range(5):
            addr = 0x1000 + offset * 4
            manager.addReferenceCandidate(addr, 0x2000 + offset)
            manager.addGapCandidate(addr + 1)
            manager.addTailcallCandidate(addr + 2)
            manager.addSymbolCandidate(addr + 3)
            manager.addExceptionCandidate(addr + 3)
            manager.addLanguageSpecCandidate(addr + 3, "go")
        self.assertEqual(len(manager.candidates), 1)

    def test_unlimited_when_cap_is_zero(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 0
        manager = _make_manager(config)
        for offset in range(500):
            manager.ensureCandidate(0x1000 + offset)
        self.assertEqual(len(manager.candidates), 500)

    def test_max_call_refs_per_candidate_cap_is_honored(self):
        config = SmdaConfig()
        config.MAX_CALL_REFS_PER_CANDIDATE = 5
        manager = _make_manager(config)
        for source in range(1000):
            manager.addReferenceCandidate(0x1000, 0x9000 + source)
        self.assertEqual(len(manager.candidates[0x1000].call_ref_sources), 5)

    def test_call_refs_unlimited_when_cap_is_zero(self):
        config = SmdaConfig()
        config.MAX_CALL_REFS_PER_CANDIDATE = 0
        manager = _make_manager(config)
        for source in range(200):
            manager.addReferenceCandidate(0x1000, 0x9000 + source)
        self.assertEqual(len(manager.candidates[0x1000].call_ref_sources), 200)

    def test_default_config_values(self):
        config = SmdaConfig()
        self.assertEqual(config.MAX_FUNCTION_CANDIDATES, 200000)
        self.assertEqual(config.MAX_CALL_REFS_PER_CANDIDATE, 2000)


if __name__ == "__main__":
    unittest.main()
