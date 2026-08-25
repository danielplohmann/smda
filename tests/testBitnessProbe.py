import logging
import unittest
from pathlib import Path
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
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


class CodeAreaSamplingTest(unittest.TestCase):
    """Data dilutes the whole-image share toward the uniform one, so the loader's code
    areas are sampled when it named any."""

    CODE = b"\x48\x89" * REX_W_MIN_SAMPLES
    # 0x48 followed by a byte no REX.W form uses: what data contributes to the count
    DATA = b"\x48\x50" * (REX_W_MIN_SAMPLES * 4)

    def _binary_info(self, buffer, code_areas):
        binary_info = BinaryInfo(buffer)
        binary_info.base_addr = 0x400000
        binary_info.code_areas = code_areas
        return binary_info

    def testDilutedImageIsStillReadAs64BitThroughItsCodeAreas(self):
        buffer = self.CODE + self.DATA
        self.assertEqual(BitnessAnalyzer().determineBitness(buffer), 32)  # whole image: diluted
        binary_info = self._binary_info(buffer, [[0x400000, 0x400000 + len(self.CODE)]])
        disassembly = SimpleNamespace(binary_info=binary_info)
        self.assertEqual(BitnessAnalyzer().determineBitnessFromDisassembly(disassembly), 64)

    def testCodeAreasAreClampedToTheBuffer(self):
        binary_info = self._binary_info(self.CODE, [[0x300000, 0x500000]])
        self.assertEqual(BitnessAnalyzer()._codeRegions(binary_info), [(0, len(self.CODE))])

    def testEmptyAreasAreDropped(self):
        binary_info = self._binary_info(self.CODE, [[0x400010, 0x400010]])
        self.assertEqual(BitnessAnalyzer()._codeRegions(binary_info), [])

    def testTooLittleCodeFallsBackToTheWholeImage(self):
        # the named area holds one sample; the image holds enough
        buffer = self.CODE + self.DATA
        binary_info = self._binary_info(buffer, [[0x400000, 0x400002]])
        disassembly = SimpleNamespace(binary_info=binary_info)
        self.assertEqual(BitnessAnalyzer().determineBitnessFromDisassembly(disassembly), 32)

    def testAnImageWithoutCodeAreasIsJudgedWhole(self):
        binary_info = self._binary_info(self.CODE, [])
        disassembly = SimpleNamespace(binary_info=binary_info)
        self.assertEqual(BitnessAnalyzer().determineBitnessFromDisassembly(disassembly), 64)


class MappedFixtureBitnessTest(unittest.TestCase):
    """Ground truth: the bundled fixtures, mapped the way a dump reaches SMDA."""

    def testMapped64BitPeIsRecognized(self):
        mapped = PeFileLoader.mapBinary(_decode("rust_pe_gnu_xored"))
        self.assertEqual(BitnessAnalyzer().determineBitness(mapped), 64)

    def testMapped32BitPeIsRecognized(self):
        mapped = PeFileLoader.mapBinary(_decode("cutwail_xored"))
        self.assertEqual(BitnessAnalyzer().determineBitness(mapped), 32)

    def testTheProbeAloneStillReadsBothMappedFixturesCorrectly(self):
        # these two now answer from the COFF machine field, so without this the byte
        # probe would be untested on them and a regression in it would go unseen
        analyzer = BitnessAnalyzer()
        share64, observed64 = analyzer._rexWShare(PeFileLoader.mapBinary(_decode("rust_pe_gnu_xored")))
        share32, observed32 = analyzer._rexWShare(PeFileLoader.mapBinary(_decode("cutwail_xored")))
        self.assertGreaterEqual(observed64, REX_W_MIN_SAMPLES)
        self.assertGreaterEqual(observed32, REX_W_MIN_SAMPLES)
        self.assertGreater(share64, 0.5)
        self.assertLess(share32, 0.5)

    def test32BitMemoryDumpIsRecognized(self):
        self.assertEqual(BitnessAnalyzer().determineBitness(_decode("asprox_0x008D0000_xored")), 32)

    def test64BitElfIsRecognized(self):
        loader = FileLoader(str(FIXTURE_DIR / "bashlite_xored"), map_file=False)
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(loader.getRawData()))
        self.assertEqual(BitnessAnalyzer().determineBitness(decoded), 64)


class DeclaredBitnessTest(unittest.TestCase):
    """A dump of a mapped image still carries its own headers, and the COFF machine
    field settles what the byte probe can only guess at."""

    #: 0x48 followed by a REX.W opcode: what the probe reads as 64-bit code
    REX_W_DENSE = b"\x48\x89" * REX_W_MIN_SAMPLES

    @staticmethod
    def _pe(machine, body=b""):
        header_offset = 0x80
        image = bytearray(header_offset + 0x40 + len(body))
        image[0:2] = b"MZ"
        image[0x3C:0x40] = header_offset.to_bytes(4, "little")
        image[header_offset : header_offset + 4] = b"PE\x00\x00"
        image[header_offset + 4 : header_offset + 6] = machine.to_bytes(2, "little")
        image[header_offset + 0x40 :] = body
        return bytes(image)

    def testA32BitImageFullOfRexWBytesIsStillRead32Bit(self):
        # the shape that made the probe wrong on real 32-bit malware dumps: the byte
        # evidence says 64, the image says 32, and the image is right
        image = self._pe(0x14C, self.REX_W_DENSE)
        share, observed = BitnessAnalyzer()._rexWShare(image)
        self.assertGreaterEqual(observed, REX_W_MIN_SAMPLES)
        self.assertGreater(share, 0.5, "control: the probe alone must get this one wrong")
        self.assertEqual(BitnessAnalyzer().determineBitness(image), 32)

    def testA64BitImageIsReadFromItsMachineField(self):
        self.assertEqual(BitnessAnalyzer().determineBitness(self._pe(0x8664)), 64)

    def testAnArm64ImageIsRead64Bit(self):
        self.assertEqual(BitnessAnalyzer().determineBitness(self._pe(0xAA64)), 64)

    def testAnUnknownMachineFallsThroughToTheProbe(self):
        image = self._pe(0x1C0, self.REX_W_DENSE)
        self.assertIsNone(BitnessAnalyzer()._declaredBitness(image))
        self.assertEqual(BitnessAnalyzer().determineBitness(image), 64)

    def testAnMzWithoutAPeSignatureFallsThroughToTheProbe(self):
        image = bytearray(self._pe(0x14C, self.REX_W_DENSE))
        image[0x80:0x84] = b"NE\x00\x00"
        self.assertIsNone(BitnessAnalyzer()._declaredBitness(bytes(image)))
        self.assertEqual(BitnessAnalyzer().determineBitness(bytes(image)), 64)

    def testAHeaderlessDumpFallsThroughToTheProbe(self):
        self.assertIsNone(BitnessAnalyzer()._declaredBitness(self.REX_W_DENSE))
        self.assertEqual(BitnessAnalyzer().determineBitness(self.REX_W_DENSE), 64)

    def testATruncatedHeaderFallsThroughToTheProbe(self):
        self.assertIsNone(BitnessAnalyzer()._declaredBitness(b"MZ"))
        self.assertIsNone(BitnessAnalyzer()._declaredBitness(b""))


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
