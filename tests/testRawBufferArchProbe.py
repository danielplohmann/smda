import logging
import unittest
from pathlib import Path

from smda.aarch64.definitions import (
    MAX_BYTES_PER_RETURN_WORD,
    MIN_RETURN_WORDS,
    RET_X30_BYTES,
    looksLikeAArch64,
)
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

FIXTURE_DIR = Path(__file__).resolve().parent


def _decode(name):
    return bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / name).read_bytes()))


def _mapped(name):
    loader = FileLoader(str(FIXTURE_DIR / name), map_file=False)
    decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(loader.getRawData()))
    return decoded


class LooksLikeAArch64Test(unittest.TestCase):
    def testAArch64FixtureIsRecognized(self):
        self.assertTrue(looksLikeAArch64(_decode("aarch64_static_xored")))

    def testSmallAArch64FixtureIsRecognized(self):
        self.assertTrue(looksLikeAArch64(_decode("aarch64_switch_macho_O0_xored")))

    def testIntelFixturesAreNotRecognized(self):
        for name in ("cutwail_xored", "mirai_x64_xored", "asprox_0x008D0000_xored"):
            self.assertFalse(looksLikeAArch64(_decode(name)), name)

    def testForeignArchitecturesAreNotRecognized(self):
        for name in ("mirai_arm_xored", "mirai_mips_xored", "mirai_ppc_xored"):
            self.assertFalse(looksLikeAArch64(_decode(name)), name)

    def testTooFewReturnWordsIsNotEnoughEvidence(self):
        self.assertFalse(looksLikeAArch64(RET_X30_BYTES * (MIN_RETURN_WORDS - 1)))

    def testUnalignedReturnWordsAreNotCounted(self):
        buffer = b"\x00" + RET_X30_BYTES * MIN_RETURN_WORDS
        self.assertFalse(looksLikeAArch64(buffer))

    def testReturnWordsTooSparseForTheImageAreRejected(self):
        buffer = RET_X30_BYTES * MIN_RETURN_WORDS
        buffer += b"\x00" * (MIN_RETURN_WORDS * MAX_BYTES_PER_RETURN_WORD + 4)
        self.assertFalse(looksLikeAArch64(buffer))

    def testDenseEnoughReturnWordsAreAccepted(self):
        self.assertTrue(looksLikeAArch64(RET_X30_BYTES * MIN_RETURN_WORDS))


class RawBufferArchitectureSelectionTest(unittest.TestCase):
    def testAArch64BufferIsNotDisassembledAsIntel(self):
        buffer = _mapped("aarch64_static_xored")
        config = SmdaConfig()
        config.TIMEOUT = 60
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this test only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)
        with self.assertLogs("smda.Disassembler", level=logging.WARNING):
            report = Disassembler(config).disassembleBuffer(buffer, 0x400000)
        self.assertEqual(report.architecture, "aarch64")
        self.assertEqual(report.bitness, 64)

    def testExplicitBackendIsNotOverridden(self):
        buffer = _mapped("aarch64_static_xored")
        config = SmdaConfig()
        config.TIMEOUT = 30
        report = Disassembler(config, backend="intel").disassembleBuffer(buffer, 0x400000)
        self.assertEqual(report.architecture, "intel")

    def testIntelBufferKeepsTheIntelBackend(self):
        buffer = _mapped("mirai_x64_xored")
        config = SmdaConfig()
        config.TIMEOUT = 60
        report = Disassembler(config).disassembleBuffer(buffer, 0x400000)
        self.assertEqual(report.architecture, "intel")


if __name__ == "__main__":
    unittest.main()
