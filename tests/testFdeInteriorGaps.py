"""The FDE-interior gap rule, and the two conditions that keep it from costing recall.

Refusing a gap candidate inside a range the image's own `.eh_frame` declares is only sound
while the range really is one function starting where it says. Two shapes break that, and both
were found by measuring what the rule cost without them: a procedure linkage table, whose whole
block sits under a single FDE, and an FDE that begins in the alignment padding ahead of its
function.
"""

import logging
import os
import tempfile
import unittest

import lief

from smda.common.EhFrameDecoder import decodeEhFrameFdeRanges
from smda.common.FunctionCandidateManager import FunctionCandidateManager
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)
lief.logging.disable()

FIXTURE = "elf_cet_landing_pads_x64_xored"
AARCH64_FIXTURE = "aarch64_static_xored"


def loadFixture(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(path, "rb") as fixture_file:
        raw = fixture_file.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class FdeInteriorGapRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = loadFixture(FIXTURE)
        cls.binary = lief.ELF.parse(list(cls.data))

    def recoveredWith(self, interior_gaps):
        config = SmdaConfig()
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        config.USE_ELF_FDE_INTERIOR_GAPS = interior_gaps
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as handle:
            handle.write(self.data)
            temp_path = handle.name
        try:
            report = Disassembler(config).disassembleFile(temp_path)
        finally:
            os.unlink(temp_path)
        return {function.offset for function in report.getFunctions()}

    def testTheRuleIsOnByDefault(self):
        # enabling it moved two bundled fixture baselines deliberately; the assertions below
        # drive it explicitly either way so they say what it does rather than what is shipped
        self.assertTrue(SmdaConfig().USE_ELF_FDE_INTERIOR_GAPS)

    def testTheSwitchCaseLabelsInsideOneFunctionAreRefused(self):
        off, on = self.recoveredWith(False), self.recoveredWith(True)
        # control: the run works either way, so the difference below is the rule rather than
        # an analysis that returned nothing
        self.assertGreater(len(off), 10)
        self.assertGreater(len(on), 10)
        dropped = off - on
        self.assertTrue(dropped, "the rule refused nothing on a fixture built to carry the shape")
        text = next(s for s in self.binary.sections if s.name == ".text")
        content = bytes(text.content)
        for address in dropped:
            offset = address - text.virtual_address
            self.assertEqual(
                content[offset : offset + 4],
                b"\xf3\x0f\x1e\xfa",
                f"0x{address:x} was refused but does not open with an endbr64",
            )
        # and none of them is a symbol the image names, which is what makes them case labels
        named = {symbol.value for symbol in self.binary.symbols if symbol.value}
        self.assertEqual(dropped & named, set())

    def testNothingTheImageNamesIsRefused(self):
        off, on = self.recoveredWith(False), self.recoveredWith(True)
        named = {symbol.value for symbol in self.binary.symbols if symbol.value}
        self.assertTrue(named & off, "the fixture names no recovered function, so this proves nothing")
        self.assertEqual((off & named) - on, set())


class FdeInteriorGapRuleAArch64Test(unittest.TestCase):
    """The rule lives in the shared candidate manager and both gap scans consult it.

    A backend that never exercised it would leave the arm of the rule that matters for AArch64
    untested, and the two backends do not share the scan loop that calls it.
    """

    @classmethod
    def setUpClass(cls):
        cls.data = loadFixture(AARCH64_FIXTURE)
        cls.binary = lief.ELF.parse(list(cls.data))

    def recoveredWith(self, interior_gaps):
        config = SmdaConfig()
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        config.USE_ELF_FDE_INTERIOR_GAPS = interior_gaps
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as handle:
            handle.write(self.data)
            temp_path = handle.name
        try:
            report = Disassembler(config).disassembleFile(temp_path)
        finally:
            os.unlink(temp_path)
        return {function.offset for function in report.getFunctions()}

    def testEveryRefusedAddressSatisfiesTheRulesOwnContract(self):
        off, on = self.recoveredWith(False), self.recoveredWith(True)
        # control: the analysis works either way, so a difference is the rule rather than a
        # run that returned nothing
        self.assertGreater(len(off), 200)
        self.assertGreater(len(on), 200)
        dropped = off - on
        self.assertTrue(dropped, "the rule refused nothing on a fixture whose ranges carry interiors")

        eh_frame = next(section for section in self.binary.sections if section.name == ".eh_frame")
        ranges = [
            (start, start + length)
            for start, length in decodeEhFrameFdeRanges(bytes(eh_frame.content), eh_frame.virtual_address)
            if length
        ]
        self.assertTrue(ranges)
        for address in sorted(dropped):
            owner = next(((start, end) for start, end in ranges if start < address < end), None)
            self.assertIsNotNone(owner, f"0x{address:x} was refused but is inside no declared range")
            # the condition that keeps an FDE opening in padding from refusing its own function
            self.assertIn(owner[0], on, f"0x{address:x} was refused by a range whose start is not a function")

    def analysedFixture(self, claim=None):
        """Run the fixture, optionally having the rule claim one address, and keep the manager."""
        config = SmdaConfig()
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        original = FunctionCandidateManager.declaredInteriorOwner
        if claim is not None:
            address, owner = claim

            def claiming(manager, candidate_address):
                if candidate_address == address:
                    return owner
                return original(manager, candidate_address)

            FunctionCandidateManager.declaredInteriorOwner = claiming
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as handle:
                handle.write(self.data)
                temp_path = handle.name
            disassembler = Disassembler(config)
            report = disassembler.disassembleFile(temp_path)
        finally:
            if temp_path is not None:
                os.unlink(temp_path)
            # restore inside the finally, and with everything after the patch inside the try:
            # a failure while writing the sample or building the disassembler would otherwise
            # leave the claim installed on the class for every later test in the process
            FunctionCandidateManager.declaredInteriorOwner = original
        return disassembler.disassembler, {function.offset for function in report.getFunctions()}

    def testAnalysisItselfDeclinesWhatTheRuleClaims(self):
        """The refusal is wired into analysis, not only into the gap scan.

        On this fixture every address the rule would claim is one the gap scan already
        refused or the collision check already caught, so asserting over what it happens to
        drop here would assert nothing. Claiming one address the fixture does recover is what
        shows analysis consults the rule at all, and that it declines rather than reports.
        """
        _, baseline = self.analysedFixture()
        self.assertGreater(len(baseline), 200)
        owner, target = sorted(baseline)[0], sorted(baseline)[1]

        backend, recovered = self.analysedFixture(claim=(target, owner))
        self.assertNotIn(target, recovered, "analysis reported an address the rule claimed")
        self.assertEqual(baseline - recovered, {target}, "the claim moved more than the address it named")
        # the reason is not asserted: a refused address is offered again as a gap candidate,
        # and that pass records its own outcome over this one
        self.assertTrue(backend.fc_manager.candidates[target].analysis_aborted)


class _RecoveredDisassembly:
    """The two things `declaredInteriorOwner` reads about what analysis has recovered."""

    def __init__(self, functions, borders):
        self.functions = functions
        self.function_borders = borders


def declaredOwnerOf(address, ranges, functions, borders, plt=(), enabled=True, pdata=(), pe_enabled=True):
    manager = FunctionCandidateManager(SmdaConfig())
    manager.config.USE_ELF_FDE_INTERIOR_GAPS = enabled
    manager.config.USE_PE_X64_PDATA_INTERIOR_GAPS = pe_enabled
    manager.disassembly = _RecoveredDisassembly(dict.fromkeys(functions), dict(borders))
    manager._eh_frame_fde_ranges = list(ranges)
    manager._eh_frame_fde_starts = [start for start, _ in ranges]
    manager._plt_ranges = list(plt)
    manager._pdata_ranges = list(pdata)
    manager._pdata_range_starts = None
    return manager.declaredInteriorOwner(address)


class DeclaredInteriorOwnerTest(unittest.TestCase):
    """The conditions the analysis-time refusal requires, one at a time.

    The gap scan reaches a candidate only where its pointer walks; this answers the same
    question for a candidate from any source, so each condition needs a case of its own
    rather than whatever a corpus happens to exercise.
    """

    RANGES = [(0x1000, 0x2000)]
    FUNCTIONS = [0x1000]
    BORDERS = {0x1000: (0x1000, 0x1F00)}

    def testAnAddressItsOwnerSurroundsIsRefused(self):
        self.assertEqual(declaredOwnerOf(0x1500, self.RANGES, self.FUNCTIONS, self.BORDERS), 0x1000)

    def testARangeStartIsNotInteriorToItself(self):
        self.assertIsNone(declaredOwnerOf(0x1000, self.RANGES, self.FUNCTIONS, self.BORDERS))

    def testAnAddressOutsideEveryRangeIsKept(self):
        self.assertIsNone(declaredOwnerOf(0x2500, self.RANGES, self.FUNCTIONS, self.BORDERS))

    def testARangeWhoseStartWasNotRecoveredRefusesNothing(self):
        # an FDE can begin in the alignment padding ahead of its function, and then the real
        # entry a few bytes in is interior to nothing
        self.assertIsNone(declaredOwnerOf(0x1500, self.RANGES, [], self.BORDERS))

    def testAnAddressPastTheOwnersRecoveredExtentIsKept(self):
        # the declared range reaches further than the owner's control flow arrived; refusing
        # out there discards bytes nothing else claims, and any reference only they carry
        short = {0x1000: (0x1000, 0x1100)}
        self.assertIsNone(declaredOwnerOf(0x1500, self.RANGES, self.FUNCTIONS, short))

    def testAnOwnerWithNoRecordedExtentRefusesNothing(self):
        self.assertIsNone(declaredOwnerOf(0x1500, self.RANGES, self.FUNCTIONS, {}))

    def testAStubInADeclaredPltIsExempt(self):
        # the whole table sits under one FDE, so every stub after the first reads as interior
        self.assertIsNone(declaredOwnerOf(0x1500, self.RANGES, self.FUNCTIONS, self.BORDERS, plt=[(0x1400, 0x1600)]))

    def testTheFlagTurnsTheRefusalOff(self):
        self.assertIsNone(declaredOwnerOf(0x1500, self.RANGES, self.FUNCTIONS, self.BORDERS, enabled=False))


class DeclaredInteriorOwnerPeTest(unittest.TestCase):
    """The same question asked of a PE exception directory rather than an `.eh_frame`.

    The two structures never describe the same image, so the arms are exercised apart: an
    ELF names no `RUNTIME_FUNCTION` extents and a PE decodes no FDE ranges.
    """

    PDATA = [(0x1000, 0x2000, False)]
    FUNCTIONS = [0x1000]
    BORDERS = {0x1000: (0x1000, 0x1F00)}

    def ownerOf(self, address, **kwargs):
        options = {
            "ranges": [],
            "functions": self.FUNCTIONS,
            "borders": self.BORDERS,
            "pdata": self.PDATA,
            **kwargs,
        }
        return declaredOwnerOf(address, **options)

    def testAnAddressInsideADeclaredExtentIsRefused(self):
        self.assertEqual(self.ownerOf(0x1500), 0x1000)

    def testAnExtentStartIsNotInteriorToItself(self):
        self.assertIsNone(self.ownerOf(0x1000))

    def testAnExtentWhoseOwnerWasNotRecoveredRefusesNothing(self):
        self.assertIsNone(self.ownerOf(0x1500, functions=[]))

    def testAnAddressPastTheOwnersRecoveredExtentIsKept(self):
        self.assertIsNone(self.ownerOf(0x1500, borders={0x1000: (0x1000, 0x1100)}))

    def testAFragmentRecordDeclinesRatherThanRefusing(self):
        # the gap scan takes a fragment as evidence on its own; here the record's own start is
        # not the function covering the address, so it fails the recovered-owner test instead
        self.assertIsNone(self.ownerOf(0x1500, pdata=[(0x1400, 0x1600, True)]))

    def testTheFlagTurnsTheRefusalOff(self):
        self.assertIsNone(self.ownerOf(0x1500, pe_enabled=False))

    def testTheElfFlagDoesNotGateTheExceptionDirectory(self):
        # the two arms carry their own switches; turning the ELF one off leaves this one alone
        self.assertEqual(self.ownerOf(0x1500, enabled=False), 0x1000)


if __name__ == "__main__":
    unittest.main()
