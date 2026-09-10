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


if __name__ == "__main__":
    unittest.main()


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
