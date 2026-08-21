import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.aarch64.definitions import BTI_C, BTI_JC
from smda.aarch64.FunctionCandidate import FunctionCandidate as AArch64FunctionCandidate
from smda.common.FunctionCandidate import FunctionCandidate as CommonFunctionCandidate
from smda.common.RecursiveDisassembler import RecursiveDisassembler
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.intel.FunctionCandidate import FunctionCandidate as IntelFunctionCandidate

ENDBR64 = b"\xf3\x0f\x1e\xfa"
PROLOGUE = b"\x55\x48\x89\xe5"  # push rbp; mov rbp, rsp


def _intelCandidate(payload, bitness=64, base_addr=0x400000):
    binary_info = SimpleNamespace(
        binary=payload,
        base_addr=base_addr,
        binary_size=len(payload),
        bitness=bitness,
        architecture="intel",
    )
    return IntelFunctionCandidate(binary_info, base_addr)


class LandingPadEntryTestSuite(unittest.TestCase):
    """`endbr64` marks an address an indirect branch may legally target, so a candidate
    carrying one was declared by the image rather than guessed by a scan."""

    def test_an_endbr64_entry_is_a_landing_pad(self):
        self.assertTrue(_intelCandidate(ENDBR64 + PROLOGUE + b"\x90" * 16).isLandingPadEntry())

    def test_a_bare_prologue_is_not_a_landing_pad(self):
        """Positive control for the pair: the same prologue without the pad must answer False,
        so the predicate is reading the pad and not the prologue behind it."""
        self.assertFalse(_intelCandidate(PROLOGUE + b"\x90" * 16).isLandingPadEntry())

    def test_the_pad_is_64_bit_only(self):
        """`f3 0f 1e fa` decodes as `endbr64` only in 64-bit mode."""
        self.assertFalse(_intelCandidate(ENDBR64 + PROLOGUE + b"\x90" * 16, bitness=32).isLandingPadEntry())

    def test_a_backend_without_the_concept_answers_false(self):
        candidate = CommonFunctionCandidate.__new__(CommonFunctionCandidate)

        self.assertFalse(candidate.isLandingPadEntry())

    def test_the_entry_shape_score_still_reads_the_prologue_behind_the_pad(self):
        """The pad is not itself a prologue, so both spellings must score the same - which is
        what makes the lower address win the tie in FunctionCandidate.__lt__."""
        padded = _intelCandidate(ENDBR64 + PROLOGUE + b"\x90" * 16)
        bare = _intelCandidate(PROLOGUE + b"\x90" * 16)

        self.assertEqual(padded.getFunctionStartScore(), bare.getFunctionStartScore())
        self.assertGreater(padded.getFunctionStartScore(), 0)


def _aarch64Candidate(payload, base_addr=0x400000):
    binary_info = SimpleNamespace(
        binary=payload,
        base_addr=base_addr,
        binary_size=len(payload),
        bitness=64,
        architecture="aarch64",
    )
    return AArch64FunctionCandidate(binary_info, base_addr)


class AArch64LandingPadEntryTestSuite(unittest.TestCase):
    """AArch64Disassembler subclasses RecursiveDisassembler, so it reaches the same revert;
    BTI is its landing pad and needs the same protection the intel pad gets."""

    STP = (0xA9BF7BFD).to_bytes(4, "little")  # stp x29, x30, [sp, #-16]!

    def test_a_bti_entry_is_a_landing_pad(self):
        for word in (BTI_C, BTI_JC):
            with self.subTest(word=hex(word)):
                payload = word.to_bytes(4, "little") + self.STP
                self.assertTrue(_aarch64Candidate(payload).isLandingPadEntry())

    def test_a_frame_record_store_is_not_a_landing_pad(self):
        """Positive control: the ordinary AArch64 entry must answer False, so the predicate is
        reading BTI rather than any plausible-looking first word."""
        self.assertFalse(_aarch64Candidate(self.STP + self.STP).isLandingPadEntry())

    def test_a_short_candidate_is_not_a_landing_pad(self):
        self.assertFalse(_aarch64Candidate(b"\x5f").isLandingPadEntry())


class GapFunctionRevertTestSuite(unittest.TestCase):
    """A gap function is reverted when a later candidate reaches its bytes, on the premise that
    the gap scan claimed a fall-through it should not have. A landing-pad entry was not claimed
    by guessing, so that premise does not apply to it."""

    def _disassembler(self, candidate):
        disassembler = RecursiveDisassembler.__new__(RecursiveDisassembler)
        disassembler.disassembly = MagicMock()
        disassembler.disassembly.ins2fn = {0x401010: 0x401000}
        disassembler.disassembly.functions = {0x401000: []}
        disassembler.fc_manager = MagicMock()
        disassembler.fc_manager.candidates = {0x401000: candidate}
        disassembler.backend = MagicMock()
        return disassembler

    def _candidate(self, payload):
        candidate = _intelCandidate(payload, base_addr=0x401000)
        candidate.setIsGapCandidate(True)
        return candidate

    def test_a_landing_pad_gap_function_is_not_reverted(self):
        disassembler = self._disassembler(self._candidate(ENDBR64 + PROLOGUE + b"\x90" * 16))

        self.assertFalse(disassembler._revertGapFunction(0x401010, 0x401020))
        disassembler.backend.createAnalysisState.assert_not_called()

    def test_a_gap_function_without_a_pad_is_still_reverted(self):
        """Positive control: the exemption must be narrow, or it would disable the mechanism."""
        disassembler = self._disassembler(self._candidate(PROLOGUE + b"\x90" * 16))

        self.assertTrue(disassembler._revertGapFunction(0x401010, 0x401020))
        disassembler.backend.createAnalysisState.assert_called_once()

    def test_a_non_gap_candidate_is_never_reverted(self):
        candidate = _intelCandidate(PROLOGUE + b"\x90" * 16, base_addr=0x401000)
        disassembler = self._disassembler(candidate)

        self.assertFalse(disassembler._revertGapFunction(0x401010, 0x401020))


class TailcallAbsorptionTestSuite(unittest.TestCase):
    """The tailcall pass reverts a function when an external jump lands inside it, then
    re-creates it only if the new analysis did not swallow its start. A start the image
    declared with a landing pad must be re-created even when it was swallowed."""

    DESTINATION_FUNCTION = 0x400000
    DESTINATION_ADDR = 0x400010

    def _run(self, entry_payload):
        analyzer = TailcallAnalyzer()
        reverted = []
        destination_function = SimpleNamespace(
            start_addr=self.DESTINATION_FUNCTION,
            is_tailcall_function=False,
            revertAnalysis=lambda: reverted.append(True),
        )
        # the new analysis swallowed the old start, which is the branch under test
        absorbing_function = SimpleNamespace(
            start_addr=self.DESTINATION_ADDR,
            is_tailcall_function=False,
            instruction_start_bytes={self.DESTINATION_FUNCTION, self.DESTINATION_ADDR},
        )
        analyzer._TailcallAnalyzer__functions = [destination_function, absorbing_function]
        analyzer.getTailcalls = lambda: [
            {
                "source_addr": 0x400100,
                "destination_addr": self.DESTINATION_ADDR,
                "destination_function": self.DESTINATION_FUNCTION,
            }
        ]

        disassembler = MagicMock()
        disassembler._analysisTimeoutTripped.return_value = False
        disassembler.fc_manager.candidates = {
            self.DESTINATION_FUNCTION: _intelCandidate(entry_payload, base_addr=self.DESTINATION_FUNCTION)
        }

        def analyze(addr):
            if addr == self.DESTINATION_FUNCTION:
                analyzer._TailcallAnalyzer__functions.append(destination_function)

        disassembler.analyzeFunction.side_effect = analyze
        analyzer.resolveTailcalls(disassembler)
        analysed = [call.args[0] for call in disassembler.analyzeFunction.call_args_list]
        return reverted, analysed

    def test_a_swallowed_landing_pad_start_is_restored(self):
        reverted, analysed = self._run(ENDBR64 + PROLOGUE + b"\x90" * 16)

        self.assertEqual(reverted, [True])
        self.assertIn(self.DESTINATION_FUNCTION, analysed)

    def test_a_swallowed_ordinary_start_stays_absorbed(self):
        """Positive control: absorbing a start the scan guessed is the mechanism working, so
        the exemption must not reach it."""
        reverted, analysed = self._run(PROLOGUE + b"\x90" * 16)

        self.assertEqual(reverted, [True])
        self.assertEqual(analysed, [self.DESTINATION_ADDR])


if __name__ == "__main__":
    unittest.main()
