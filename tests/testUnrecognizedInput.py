import struct
import unittest
from pathlib import Path

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader
from tests.testDalvikDisassembler import build_dex_header

FIXTURE_DIR = Path(__file__).resolve().parent
DUMP = bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / "asprox_0x008D0000_xored").read_bytes()))


class UnrecognizedInputMappingTest(unittest.TestCase):
    def testMappingAnUnrecognizedBufferReturnsItsBytes(self):
        loader = MemoryFileLoader(DUMP, map_file=True)
        self.assertEqual(loader.getData(), DUMP)
        self.assertEqual(loader.getRawData(), DUMP)

    def testUnrecognizedBufferLeavesFormatMetadataUnset(self):
        loader = MemoryFileLoader(DUMP, map_file=True)
        self.assertEqual(loader.getArchitecture(), "")
        self.assertEqual(loader.getBitness(), 0)
        self.assertEqual(loader.getBaseAddress(), 0)
        self.assertEqual(loader.getCodeAreas(), [])
        self.assertFalse(loader.getHasBackend())

    def testRecognizedBufferStillMaps(self):
        pe = bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / "cutwail_xored").read_bytes()))
        loader = MemoryFileLoader(pe, map_file=True)
        self.assertNotEqual(loader.getData(), pe)
        self.assertEqual(loader.getArchitecture(), "intel")

    def testUnmappedLoadReturnsTheBytesUnchanged(self):
        loader = MemoryFileLoader(DUMP, map_file=False)
        self.assertEqual(loader.getData(), DUMP)


def _elf_with_machine(machine):
    """Minimal ELF64 header naming an instruction set, and nothing else."""
    header = bytearray(64)
    header[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HH", header, 16, 2, machine)  # e_type = ET_EXEC, e_machine
    struct.pack_into("<I", header, 20, 1)  # e_version
    struct.pack_into("<HH", header, 52, 64, 0)  # e_ehsize, e_phentsize
    struct.pack_into("<HH", header, 58, 64, 0)  # e_shentsize, e_shnum
    return bytes(header)


EM_AVR = 83


class RecognizedFormatWithoutAnArchitectureTest(unittest.TestCase):
    """A container SMDA parses but whose machine type it has no mapping for also ends
    up with an empty architecture, and telling that caller to retry as a memory dump
    would send them after something that cannot help."""

    def testLoaderReportsTheFormatAsRecognized(self):
        loader = MemoryFileLoader(_elf_with_machine(EM_AVR), map_file=True)
        self.assertTrue(loader.getFormatRecognized())
        self.assertEqual(loader.getArchitecture(), "")

    def testLoaderReportsAnUnclaimedBufferAsUnrecognized(self):
        self.assertFalse(MemoryFileLoader(DUMP, map_file=True).getFormatRecognized())

    def testAFormatWithoutItsOwnBackendFlagIsStillRecognized(self):
        # DEX and the Delphi knowledge base do not expose getHasBackend(), so they take
        # the other arm of the dispatch and have to set the same flag
        loader = MemoryFileLoader(build_dex_header(), map_file=True)
        self.assertTrue(loader.getFormatRecognized())
        self.assertEqual(loader.getArchitecture(), "dalvik")
        self.assertTrue(loader.getHasBackend())

    def testTheMessageNamesTheInstructionSetAsWhatIsMissing(self):
        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_elf_with_machine(EM_AVR))
        self.assertEqual(report.status, "error")
        self.assertIn("names an instruction set SMDA has no backend for", report.message)


class UnrecognizedInputReportTest(unittest.TestCase):
    def testDisassemblingADumpAsAFileExplainsWhatToDo(self):
        path = FIXTURE_DIR / "asprox_0x008D0000_xored"
        loader = FileLoader(str(path), map_file=True)
        self.assertEqual(loader.getData(), loader.getRawData())
        report = Disassembler(SmdaConfig()).disassembleFile(str(path))
        self.assertEqual(report.status, "error")
        self.assertIn("has to be passed to disassembleBuffer() with its base address", report.message)


if __name__ == "__main__":
    unittest.main()
