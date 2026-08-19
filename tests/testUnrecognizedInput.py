import unittest
from pathlib import Path

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader

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
