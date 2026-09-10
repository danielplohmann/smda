#!/usr/bin/python
"""The ARM64 PE interior-gap rule, on a real ARM64 PE rather than a synthesised one.

`testAArch64PdataExtraction.py` drives `USE_PE_ARM64_PDATA_INTERIOR_GAPS` over an image this
suite builds itself, which pins the decode and the refusal but cannot say the rule meets the
shapes a compiler actually emits. Until this fixture there was no ARM64 PE among the bundled
samples at all -- scanning them for a PE machine field found 8 x i386, 4 x AMD64 and one
ReadyToRun image, and no 0xAA64.

`arm64_pe_probe_xored` is built from source rather than taken from a system, so it can be
redistributed and rebuilt:

    aarch64-w64-mingw32-clang++ -O2 -g -gdwarf-4 probe.cpp -o probe.exe   (llvm-mingw 20250430)

The source exercises catch funclets, cleanup funclets and a `[[noreturn]]` cold path, which
are the shapes that get their own unwind record, and clang emits one `.pdata` record per named
function without splitting any of them. That is what makes it a control as well as a fixture:
the over-seeding an MSVC-built ARM64 PE shows does not occur here, so anything this test
refuses is refused on the extent evidence rather than on a compiler's chunking habit.
"""

import os
import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

FIXTURE = "arm64_pe_probe_xored"

#: the eight addresses the rule refuses, each interior to a RUNTIME_FUNCTION extent whose own
#: function the analysis recovered. Listed rather than counted so a change that refuses a
#: different set fails instead of staying green on an unchanged total.
REFUSED = {
    0x1400014E8,
    0x1400015F8,
    0x140001614,
    0x140001628,
    0x140001674,
    0x140001840,
    0x140001A7C,
    0x140001B48,
}


def loadFixture(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(path, "rb") as fixture_file:
        raw = fixture_file.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class Arm64PeInteriorGapFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = loadFixture(FIXTURE)

    def recoveredWith(self, interior_gaps):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        config.USE_PE_ARM64_PDATA_INTERIOR_GAPS = interior_gaps
        report = Disassembler(config).disassembleUnmappedBuffer(self.data)
        self.assertEqual(report.status, "ok")
        return {function.offset for function in report.getFunctions()}

    def testTheFixtureIsAnArm64Pe(self):
        # the gap this file exists to close: without an 0xAA64 image the rule below is only
        # ever exercised against one this suite wrote itself
        self.assertEqual(self.data[:2], b"MZ")
        pe_offset = int.from_bytes(self.data[0x3C:0x40], "little")
        self.assertEqual(self.data[pe_offset : pe_offset + 4], b"PE\x00\x00")
        self.assertEqual(int.from_bytes(self.data[pe_offset + 4 : pe_offset + 6], "little"), 0xAA64)

    def testTheDeclaredExtentsRefuseTheirInteriorAddresses(self):
        off, on = self.recoveredWith(False), self.recoveredWith(True)
        # control: the analysis works either way, so the difference is the rule rather than a
        # run that returned nothing
        self.assertGreater(len(off), 100)
        self.assertGreater(len(on), 100)
        self.assertEqual(off - on, REFUSED)
        self.assertEqual(on - off, set())

    def testEveryRefusedAddressWasReachableOnlyWithTheRuleOff(self):
        on = self.recoveredWith(True)
        self.assertFalse(REFUSED & on)
