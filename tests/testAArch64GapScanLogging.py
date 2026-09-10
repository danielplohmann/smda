#!/usr/bin/python
"""Every refusal in the AArch64 gap scan names the address it refused.

Its intel counterpart emits a `LOGGER.debug` on each path that declines a gap pointer, so
a suppression can be read back from a run. The AArch64 loop had no logging at all, which
made the two paths diverge on the one axis they are otherwise deliberately identical on:
the first ARM64 PE that suppresses something surprising would have been harder to explain
than the x64 equivalent.

The messages the bundled AArch64 fixture reaches are asserted individually rather than as
a count, so a path that stops logging fails as itself.
"""

import logging
import os
import tempfile
import unittest

from smda.aarch64.definitions import INSTRUCTION_SIZE
from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64CandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig

FIXTURE = "aarch64_static_xored"
LOGGER_NAME = "smda.aarch64.FunctionCandidateManager"

#: the refusals this fixture actually walks into, so none of these assertions is vacuous.
#: The declared `.pdata` extent, the LSDA landing pad, the BTI interior pad, the trap word
#: and the code filter are reachable in the loop but not on an ELF the size of this one.
#:
#: The sweep over bytes outside every executable section is deliberately not logged. It
#: refuses no candidate -- it steps over what is not code at all -- it has no intel
#: counterpart, and on this fixture alone it would emit 156,758 identical lines, which is
#: 91% of everything the loop would say.
EXPECTED = (
    "nextGapCandidate() found padding word - gap_ptr += %d: 0x%08x",
    "nextGapCandidate() gap_ptr is already inside code map: 0x%08x",
    "nextGapCandidate() gap_ptr is already inside data map: 0x%08x",
    "nextGapCandidate() gap_ptr is inside a declared FDE range: 0x%08x",
    "nextGapCandidate() gap run flows into the interior of a mapped function: 0x%08x",
    "nextGapCandidate() using 0x%08x as candidate",
)


def loadFixture(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(path, "rb") as fixture_file:
        raw = fixture_file.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class AArch64GapScanLoggingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = loadFixture(FIXTURE)

    def setUp(self):
        # several modules in this suite call logging.disable() at import, which suppresses
        # records before any handler sees them and would leave assertLogs with nothing
        self._previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)

    def tearDown(self):
        logging.disable(self._previous_disable)

    def recoveredWithLogs(self):
        config = SmdaConfig()
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as handle:
            handle.write(self.data)
            temp_path = handle.name
        try:
            with self.assertLogs(LOGGER_NAME, level=logging.DEBUG) as captured:
                report = Disassembler(config).disassembleFile(temp_path)
        finally:
            os.unlink(temp_path)
        return report, captured.records

    def testEveryRefusalTheFixtureReachesIsRecorded(self):
        report, records = self.recoveredWithLogs()
        # control: the run did its normal work, so a missing message is a missing message
        # rather than an analysis that returned nothing
        self.assertGreater(len({function.offset for function in report.getFunctions()}), 200)
        emitted = {record.msg for record in records}
        for message in EXPECTED:
            self.assertIn(message, emitted, f"the gap scan never emitted: {message}")

    def testEachRecordNamesAnAddressInsideTheImage(self):
        report, records = self.recoveredWithLogs()
        # the mapped image is larger than the file it came from, so the file length is not
        # the bound the scan walks to
        base = report.base_addr
        end = base + report.binary_size
        addresses = [record.args[-1] for record in records if record.msg in EXPECTED]
        self.assertTrue(addresses)
        for address in addresses:
            self.assertIsInstance(address, int)
            self.assertTrue(base <= address < end, f"0x{address:x} is outside the image")


BASE = 0x400000
PADDING_WORDS = 64
AARCH64_NOP = b"\x1f\x20\x03\xd5"
FRAME_PROLOGUE = b"\xfd\x7b\xbf\xa9"


class AArch64GapScanRepeatedPointerLoggingTest(unittest.TestCase):
    """The branch that meets a gap pointer the scan already handed out once.

    No bundled fixture reaches it: it needs the caller to ask again from the same address
    rather than from where the previous candidate ended, so it is driven directly.
    """

    def setUp(self):
        self._previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)

    def tearDown(self):
        logging.disable(self._previous_disable)

    @staticmethod
    def manager():
        image = AARCH64_NOP * PADDING_WORDS + FRAME_PROLOGUE * 4
        binary_info = BinaryInfo(image)
        binary_info.base_addr = BASE
        binary_info.bitness = 64
        binary_info.architecture = "aarch64"
        binary_info.code_areas = [[BASE, BASE + len(image)]]
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        manager = AArch64CandidateManager(SmdaConfig())
        manager.init(disassembly, None)
        return manager

    def testAskingTwiceFromTheSameAddressIsRecorded(self):
        manager = self.manager()
        first = manager.nextGapCandidate(BASE)
        # control: the scan walked the padding and produced a candidate, so the second call
        # below is a repeat rather than a scan that never got started
        self.assertEqual(first, BASE + PADDING_WORDS * INSTRUCTION_SIZE)

        with self.assertLogs(LOGGER_NAME, level=logging.DEBUG) as captured:
            manager.nextGapCandidate(first)
        self.assertIn(
            "--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed",
            {record.msg for record in captured.records},
        )


if __name__ == "__main__":
    unittest.main()
