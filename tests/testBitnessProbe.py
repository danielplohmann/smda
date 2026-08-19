import logging
import unittest
from pathlib import Path

from smda.Disassembler import Disassembler
from smda.intel.BitnessAnalyzer import (
    REX_W_MAX_SAMPLES,
    REX_W_MIN_SAMPLES,
    BitnessAnalyzer,
)
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.PeFileLoader import PeFileLoader

FIXTURE_DIR = Path(__file__).resolve().parent


def _decode(name):
    return bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / name).read_bytes()))


class RexWShareTest(unittest.TestCase):
    def testRexWPairsReadAs64Bit(self):
        binary = b"\x48\x89" * REX_W_MIN_SAMPLES
        self.assertEqual(BitnessAnalyzer().determineBitness(binary), 64)

    def testDecEaxWithUnrelatedFollowerReadsAs32Bit(self):
        binary = b"\x48\x50" * REX_W_MIN_SAMPLES
        self.assertEqual(BitnessAnalyzer().determineBitness(binary), 32)

    def testShareBelowSampleFloorFallsBackToStartBytes(self):
        analyzer = BitnessAnalyzer()
        binary = b"\x48\x89" * (REX_W_MIN_SAMPLES - 1)
        share, observed = analyzer._rexWShare(binary)
        self.assertIsNone(share)
        self.assertEqual(observed, REX_W_MIN_SAMPLES - 1)
        self.assertEqual(analyzer.determineBitness(binary), 32)

    def testSamplingStopsAtTheCap(self):
        binary = b"\x48\x89" * (REX_W_MAX_SAMPLES + 8)
        share, observed = BitnessAnalyzer()._rexWShare(binary)
        self.assertEqual(observed, REX_W_MAX_SAMPLES)
        self.assertEqual(share, 1.0)

    def testTrailingPrefixByteIsNotCounted(self):
        binary = b"\x48\x89" * REX_W_MIN_SAMPLES + b"\x48"
        share, observed = BitnessAnalyzer()._rexWShare(binary)
        self.assertEqual(observed, REX_W_MIN_SAMPLES)
        self.assertEqual(share, 1.0)

    def testMixedShareBelowThresholdReadsAs32Bit(self):
        binary = (b"\x48\x89" + b"\x48\x50" * 3) * REX_W_MIN_SAMPLES
        self.assertEqual(BitnessAnalyzer().determineBitness(binary), 32)


class MappedFixtureBitnessTest(unittest.TestCase):
    """Ground truth: the bundled fixtures, mapped the way a dump reaches SMDA."""

    def testMapped64BitPeIsRecognized(self):
        mapped = PeFileLoader.mapBinary(_decode("rust_pe_gnu_xored"))
        self.assertEqual(BitnessAnalyzer().determineBitness(mapped), 64)

    def testMapped32BitPeIsRecognized(self):
        mapped = PeFileLoader.mapBinary(_decode("cutwail_xored"))
        self.assertEqual(BitnessAnalyzer().determineBitness(mapped), 32)

    def test32BitMemoryDumpIsRecognized(self):
        self.assertEqual(BitnessAnalyzer().determineBitness(_decode("asprox_0x008D0000_xored")), 32)

    def test64BitElfIsRecognized(self):
        loader = FileLoader(str(FIXTURE_DIR / "bashlite_xored"), map_file=False)
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(loader.getRawData()))
        self.assertEqual(BitnessAnalyzer().determineBitness(decoded), 64)


class MemoryDumpRecoveryTest(unittest.TestCase):
    """End to end from a mapped image with no bitness supplied - the shape a memory
    dump arrives in. Reading a 64-bit image as 32-bit does not fail loudly; it
    decodes every REX prefix as `dec`/`inc` and buries the run in bogus candidates."""

    def testMapped64BitImageRecoversFunctions(self):
        loader = FileLoader(str(FIXTURE_DIR / "mirai_x64_xored"), map_file=False)
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(loader.getRawData()))
        mapped = MemoryFileLoader(decoded, map_file=True)
        config = SmdaConfig()
        config.TIMEOUT = 300
        config.WITH_STRINGS = False

        report = Disassembler(config).disassembleBuffer(mapped.getData(), mapped.getBaseAddress())

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.bitness, 64)
        self.assertEqual(report.architecture, "intel")
        self.assertGreater(report.num_functions, 100)


class ProbedBitnessIsAnnouncedTest(unittest.TestCase):
    def setUp(self):
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records - and assertNoLogs pass vacuously - depending on collection order
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def testBufferWithoutBitnessLogsThatItWasInferred(self):
        mapped = PeFileLoader.mapBinary(_decode("cutwail_xored"))
        config = SmdaConfig()
        config.TIMEOUT = 10
        with self.assertLogs("smda.common.RecursiveDisassembler", level=logging.WARNING) as captured:
            Disassembler(config).disassembleBuffer(mapped, 0x4000000)
        self.assertTrue(any("inferred 32-bit" in message for message in captured.output))

    def testSuppliedBitnessIsNotAnnounced(self):
        mapped = PeFileLoader.mapBinary(_decode("cutwail_xored"))
        config = SmdaConfig()
        config.TIMEOUT = 10
        logger = logging.getLogger("smda.common.RecursiveDisassembler")
        with self.assertNoLogs(logger, level=logging.WARNING):
            Disassembler(config).disassembleBuffer(mapped, 0x4000000, bitness=32)


if __name__ == "__main__":
    unittest.main()
