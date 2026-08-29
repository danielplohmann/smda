import logging
import unittest
from pathlib import Path

from smda.aarch64.definitions import looksLikeAArch64
from smda.Disassembler import Disassembler, declaredArchitecture
from smda.SmdaConfig import SmdaConfig
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.PeFileLoader import PeFileLoader

logging.disable(logging.CRITICAL)

FIXTURE_DIR = Path(__file__).resolve().parent


def _decode(name):
    return bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / name).read_bytes()))


def _pe(machine):
    header_offset = 0x80
    image = bytearray(header_offset + 0x40)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = header_offset.to_bytes(4, "little")
    image[header_offset : header_offset + 4] = b"PE\x00\x00"
    image[header_offset + 4 : header_offset + 6] = machine.to_bytes(2, "little")
    return bytes(image)


class DeclaredArchitectureTest(unittest.TestCase):
    def testPeMachineFieldNamesTheInstructionSet(self):
        self.assertEqual(declaredArchitecture(_pe(0x14C)), "intel")
        self.assertEqual(declaredArchitecture(_pe(0x8664)), "intel")
        self.assertEqual(declaredArchitecture(_pe(0xAA64)), "aarch64")

    def testAPeMachineWithNoBackendDeclaresNothing(self):
        self.assertEqual(declaredArchitecture(_pe(0x1C0)), "")

    def testAnMzWithoutAPeSignatureDeclaresNothing(self):
        image = bytearray(_pe(0xAA64))
        image[0x80:0x84] = b"NE\x00\x00"
        self.assertEqual(declaredArchitecture(bytes(image)), "")

    def testABufferCarryingNoContainerDeclaresNothing(self):
        self.assertEqual(declaredArchitecture(b"\x90" * 4096), "")
        self.assertEqual(declaredArchitecture(b""), "")

    def testAManagedPeStillDeclaresIntel(self):
        # its CLR metadata is addressed by file offset, which a mapped image no longer
        # has, so naming cil here would route a dump to a backend that cannot read it
        managed = _decode("njrat_xored")
        self.assertEqual(PeFileLoader.getArchitecture(managed), "cil")
        self.assertEqual(declaredArchitecture(managed), "intel")

    def testElfHeaderNamesTheInstructionSet(self):
        self.assertEqual(declaredArchitecture(_decode("bashlite_xored")), "intel")
        self.assertEqual(declaredArchitecture(_decode("aarch64_static_xored")), "aarch64")

    def testAnElfForAnUnsupportedInstructionSetDeclaresNothing(self):
        self.assertEqual(declaredArchitecture(_decode("mirai_arm_xored")), "")
        self.assertEqual(declaredArchitecture(_decode("mirai_mips_xored")), "")

    def testMachoHeaderNamesTheInstructionSet(self):
        macho = _decode("aarch64_macho_corpus/objective-see/BlueNoroff_469fd8a280e8.xored")
        self.assertTrue(MachoFileLoader.isCompatible(macho))
        self.assertEqual(declaredArchitecture(macho), "aarch64")


class DeclaredArchitectureRoutesTheBufferTest(unittest.TestCase):
    """A real sample the density heuristic gets wrong, routed by its own header."""

    def setUp(self):
        self.macho = _decode("aarch64_macho_corpus/objective-see/BlueNoroff_469fd8a280e8.xored")

    def testTheDensityHeuristicMissesThisSampleAndTheHeaderDoesNot(self):
        # control: this is why the header is consulted at all -- the sample holds too
        # few aligned return words for the density probe to call it AArch64
        self.assertFalse(looksLikeAArch64(self.macho))
        self.assertEqual(declaredArchitecture(self.macho), "aarch64")

    def testTheBufferIsDisassembledAsAArch64(self):
        config = SmdaConfig()
        config.TIMEOUT = 60
        report = Disassembler(config).disassembleBuffer(self.macho, MachoFileLoader.getBaseAddress(self.macho))
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")
        self.assertEqual(report.bitness, 64)
        self.assertGreater(report.num_functions, 0)

    def testADeclaredIntelBufferTakesTheSamePathWithoutAssumingItsBitness(self):
        # the intel arm leaves bitness to the probe; only the AArch64 arm names one
        config = SmdaConfig()
        config.TIMEOUT = 10
        report = Disassembler(config).disassembleBuffer(_pe(0x14C), 0x400000)
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "intel")
        self.assertEqual(report.bitness, 32)

    def testAnExplicitArchitectureStillWins(self):
        config = SmdaConfig()
        config.TIMEOUT = 10
        report = Disassembler(config).disassembleBuffer(self.macho, 0x100000000, architecture="intel")
        self.assertEqual(report.architecture, "intel")


if __name__ == "__main__":
    unittest.main()
