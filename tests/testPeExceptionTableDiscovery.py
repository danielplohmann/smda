import logging
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

import lief

from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.intel.FunctionCandidateManager import (
    FunctionCandidateManager as IntelFunctionCandidateManager,
)
from smda.SmdaConfig import SmdaConfig
from smda.utility.PeFileLoader import PeFileLoader

logging.disable(logging.CRITICAL)

FIXTURE_DIR = Path(__file__).resolve().parent
FIXTURE = "dotnet_readytorun_pe_xored"


def _decode(name):
    return bytes(byte ^ (index % 256) for index, byte in enumerate((FIXTURE_DIR / name).read_bytes()))


def _exceptionDirectory(parsed):
    for directory in parsed.data_directories:
        if "EXCEPTION" in str(directory.type) and directory.size:
            return directory
    return None


def _offsetOfRva(parsed, rva):
    for section in parsed.sections:
        extent = max(section.size, section.sizeof_raw_data)
        if section.virtual_address <= rva < section.virtual_address + extent:
            return section.pointerto_raw_data + (rva - section.virtual_address)
    return None


def _declaredFunctionStarts(data, parsed):
    """Every RUNTIME_FUNCTION BeginAddress the image's exception directory names."""
    directory = _exceptionDirectory(parsed)
    base = _offsetOfRva(parsed, directory.rva)
    starts = set()
    for index in range(directory.size // 12):
        begin, _end, _unwind = struct.unpack("<III", data[base + index * 12 : base + index * 12 + 12])
        if begin:
            starts.add(begin)
    return starts


class ExceptionTableLocationTest(unittest.TestCase):
    """A ReadyToRun image declares an exception table and does not put it in `.pdata`."""

    def setUp(self):
        self.data = _decode(FIXTURE)
        self.parsed = lief.PE.parse(self.data)

    def testTheFixtureCarriesItsTableOutsideAPdataSection(self):
        # control: without this the test below would pass on any ordinary MSVC image
        # and prove nothing about where the table was found
        directory = _exceptionDirectory(self.parsed)
        self.assertIsNotNone(directory)
        self.assertNotIn(".pdata", [section.name for section in self.parsed.sections])
        owner = None
        for section in self.parsed.sections:
            extent = max(section.size, section.sizeof_raw_data)
            if section.virtual_address <= directory.rva < section.virtual_address + extent:
                owner = section.name
        self.assertEqual(owner, ".data")
        self.assertGreater(directory.size // 12, 500)

    def testTheDirectoryIsReadAsTheTableAddress(self):
        binary_info = BinaryInfo(self.data)
        binary_info.base_addr = 0
        directory = _exceptionDirectory(self.parsed)
        self.assertEqual(
            binary_info.getExceptionDirectory(),
            (directory.rva, directory.rva + directory.size),
        )

    def testEveryDeclaredNativeFunctionIsRecovered(self):
        # the managed routing sends this image to the CIL backend, which reports method
        # bodies by file offset and never looks at the precompiled native code; the
        # native view is what the exception table describes
        declared = _declaredFunctionStarts(self.data, self.parsed)
        config = SmdaConfig()
        config.TIMEOUT = 300
        mapped = PeFileLoader.mapBinary(self.data)
        report = Disassembler(config, backend="intel").disassembleBuffer(mapped, 0, bitness=64)
        self.assertEqual(report.status, "ok")
        recovered = {function.offset for function in report.getFunctions()}
        self.assertEqual(declared - recovered, set())
        self.assertGreaterEqual(len(recovered), len(declared))


class OverstatedTableSizeTest(unittest.TestCase):
    """A declared size is a 32-bit field the image controls; the walk must not follow it
    past the bytes that exist."""

    def setUp(self):
        self.data = _decode(FIXTURE)
        self.parsed = lief.PE.parse(self.data)
        self.declared = _declaredFunctionStarts(self.data, self.parsed)

    @staticmethod
    def _recovered(buffer, table_end_override=None):
        config = SmdaConfig()
        config.TIMEOUT = 300
        disassembler = Disassembler(config, backend="intel")
        if table_end_override is not None:
            original = BinaryInfo.getExceptionDirectory

            def overstated(self):
                declared = original(self)
                return None if declared is None else (declared[0], table_end_override)

            BinaryInfo.getExceptionDirectory = overstated
            try:
                report = disassembler.disassembleBuffer(buffer, 0, bitness=64)
            finally:
                BinaryInfo.getExceptionDirectory = original
        else:
            report = disassembler.disassembleBuffer(buffer, 0, bitness=64)
        return report

    def testASizeReachingPastTheImageRecoversTheSameFunctions(self):
        mapped = PeFileLoader.mapBinary(self.data)
        honest = self._recovered(mapped)
        overstated = self._recovered(mapped, table_end_override=len(mapped) * 64)
        self.assertEqual(honest.status, "ok")
        self.assertEqual(overstated.status, "ok")
        self.assertEqual(
            {function.offset for function in honest.getFunctions()},
            {function.offset for function in overstated.getFunctions()},
        )
        # control: the honest run is the one that recovers everything the image declares
        self.assertEqual(self.declared - {function.offset for function in honest.getFunctions()}, set())


class ExceptionTableTimeoutTest(unittest.TestCase):
    """A declared table can be as long as the image, so bounding the walk is not enough."""

    SIZE = 1 << 20
    BASE = 0x140000000

    def _entriesWalked(self, timeout_tripped):
        # uniformly nonzero, so no entry reads as a zero BeginAddress and nothing in the
        # walk's own stop conditions ends it before the declared range does
        buffer = bytes(((index * 7) % 255) + 1 for index in range(4096)) * (self.SIZE // 4096)
        binary_info = BinaryInfo(buffer)
        binary_info.base_addr = self.BASE
        binary_info.bitness = 64
        manager = IntelFunctionCandidateManager(SmdaConfig())
        manager.bitness = 64
        manager.disassembly = SimpleNamespace(
            binary_info=binary_info,
            getRawBytes=lambda offset, size: buffer[offset : offset + size],
            analysis_timeout=False,
        )
        manager._cb_analysis_timeout = lambda: timeout_tripped
        walked = []
        manager._admitExceptionRecord = lambda *args: walked.append(args)
        manager._readExceptionTable(self.BASE, self.BASE, self.BASE + self.SIZE, False)
        return len(walked)

    def testAWalkOverATableAsLongAsTheImageStopsOnTheTimeout(self):
        entries = self.SIZE // 12
        # control: with time left the walk covers every entry the range declares, so the
        # short count below is the timeout stopping it rather than the range being empty
        self.assertEqual(self._entriesWalked(timeout_tripped=False), entries)
        self.assertLess(self._entriesWalked(timeout_tripped=True), entries // 10)


def _withoutExceptionDirectory(data, parsed):
    """The same image with its exception directory zeroed, keeping the .pdata section.

    A damaged or hand-built image can carry the section and lose the directory, which
    is the only thing the section-name fallback is still there for.
    """
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    optional_header = pe_offset + 0x18
    magic = int.from_bytes(data[optional_header : optional_header + 2], "little")
    # the data directory array follows NumberOfRvaAndSizes: 0x60 into a PE32
    # optional header, 0x70 into a PE32+ one
    directories_at = optional_header + (0x60 if magic == 0x10B else 0x70)
    entry = directories_at + 3 * 8  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    directory = _exceptionDirectory(parsed)
    assert int.from_bytes(data[entry : entry + 4], "little") == directory.rva, "directory offset mis-derived"
    patched = bytearray(data)
    patched[entry : entry + 8] = b"\x00" * 8
    return bytes(patched)


class PdataSectionFallbackTest(unittest.TestCase):
    """When the directory is gone, the section named .pdata is the remaining evidence."""

    FIXTURE = "msvc_cxx_pe_xored"

    def setUp(self):
        self.data = _decode(self.FIXTURE)
        self.parsed = lief.PE.parse(self.data)
        self.declared = _declaredFunctionStarts(self.data, self.parsed)
        self.blinded = _withoutExceptionDirectory(self.data, self.parsed)

    def testTheFixtureHasBothAndTheBlindedCopyHasOnlyTheSection(self):
        # control: the fallback is only meaningful if the directory really is gone
        # and the section really is still there. Keep each parse bound to a name --
        # lief section objects do not own their parent, so reading them off a
        # temporary is a use-after-free.
        self.assertIn(".pdata", [section.name for section in self.parsed.sections])
        self.assertIsNotNone(_exceptionDirectory(self.parsed))
        blinded = lief.PE.parse(self.blinded)
        self.assertIsNone(_exceptionDirectory(blinded))
        self.assertIn(".pdata", [section.name for section in blinded.sections])
        self.assertGreater(len(self.declared), 0)

    def testTheSameFunctionsAreRecoveredFromTheSection(self):
        config = SmdaConfig()
        config.TIMEOUT = 300
        base = PeFileLoader.getBaseAddress(self.data)
        recovered = set()
        for buffer in (self.data, self.blinded):
            report = Disassembler(config, backend="intel").disassembleBuffer(
                PeFileLoader.mapBinary(buffer), base, bitness=64
            )
            self.assertEqual(report.status, "ok")
            recovered = {function.offset for function in report.getFunctions()}
            self.assertEqual({base + start for start in self.declared} - recovered, set())


class OverstatedSectionExtentTest(unittest.TestCase):
    """A section extent is rounded up and a dump can be truncated inside it."""

    def testAWalkPastTheMappedBytesStopsInsteadOfRaising(self):
        data = _decode(FIXTURE)
        mapped = PeFileLoader.mapBinary(data)
        truncated = mapped[: len(mapped) // 2]
        config = SmdaConfig()
        config.TIMEOUT = 120
        report = Disassembler(config, backend="intel").disassembleBuffer(truncated, 0, bitness=64)
        self.assertEqual(report.status, "ok")


class ExceptionDirectoryAccessorTest(unittest.TestCase):
    def testAnImageWithNoExceptionTableReportsNone(self):
        binary_info = BinaryInfo(_decode("cutwail_xored"))
        binary_info.base_addr = 0x400000
        self.assertIsNone(binary_info.getExceptionDirectory())

    def testANonPeReportsNone(self):
        binary_info = BinaryInfo(_decode("bashlite_xored"))
        self.assertIsNone(binary_info.getExceptionDirectory())

    def testAnEmptyBufferReportsNone(self):
        self.assertIsNone(BinaryInfo(b"").getExceptionDirectory())


if __name__ == "__main__":
    unittest.main()
