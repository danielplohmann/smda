import os
import struct
import unittest

import lief

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.ElfFileLoader import ElfFileLoader

lief.logging.disable()

#: clang 18.1.3 --target=x86_64-linux-gnu -O1 -fPIC -shared -nostdlib -fuse-ld=lld -Wl,--build-id=none
#: over five exported functions and one exported variable; lld places its RW segment, and the
#: dynamic table in it, 0x3000 above its file offset.
EXPORTS_FIXTURE = "elf_shared_exports_x64_xored"
EXPORTED_FUNCTIONS = {0x1460: "api_add", 0x1480: "api_mul", 0x14A0: "api_sel", 0x14F0: "api_store", 0x1500: "api_chain"}
#: g++ 13.3.0 -O2, imports its runtime through the dynamic table
IMPORTS_FIXTURE = "elf_cxx_landing_pads_arm64_xored"


def loadFixture(name):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), name), "rb") as fixture_file:
        raw = fixture_file.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def mapImage(data):
    """Place every PT_LOAD at its p_vaddr, the way a loader leaves an ELF in memory."""
    binary = lief.ELF.parse(list(data))
    loads = [segment for segment in binary.segments if segment.type == lief.ELF.Segment.TYPE.LOAD]
    image = bytearray(max(segment.virtual_address + segment.virtual_size for segment in loads))
    for segment in loads:
        content = bytes(segment.content)
        image[segment.virtual_address : segment.virtual_address + len(content)] = content
    dynamic = next(segment for segment in binary.segments if segment.type == lief.ELF.Segment.TYPE.DYNAMIC)
    return bytes(image), (dynamic.virtual_address, dynamic.physical_size)


def disassemble(data, as_buffer):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    disassembler = Disassembler(config)
    return disassembler.disassembleBuffer(data, 0) if as_buffer else disassembler.disassembleUnmappedBuffer(data)


class ElfMappedBufferTestSuite(unittest.TestCase):
    """A mapped ELF image keeps the dynamic symbols its file has, read through its dynamic table."""

    def testMappedImageKeepsExports(self):
        data = loadFixture(EXPORTS_FIXTURE)
        image, _dynamic = mapImage(data)
        file_report = disassemble(data, as_buffer=False)
        buffer_report = disassemble(image, as_buffer=True)
        self.assertEqual(buffer_report.status, "ok")
        for key in ("exported_functions", "exported_symbols", "imported_functions"):
            self.assertEqual(buffer_report.xmetadata[key], file_report.xmetadata[key], key)
        names = {function.offset: function.function_name for function in buffer_report.getFunctions()}
        self.assertEqual({offset: names.get(offset) for offset in EXPORTED_FUNCTIONS}, EXPORTED_FUNCTIONS)

    def testMappedImageKeepsImports(self):
        data = loadFixture(IMPORTS_FIXTURE)
        image, _dynamic = mapImage(data)
        file_report = disassemble(data, as_buffer=False)
        buffer_report = disassemble(image, as_buffer=True)
        self.assertEqual(buffer_report.status, "ok")
        self.assertTrue(file_report.xmetadata["imported_functions"])
        self.assertEqual(buffer_report.xmetadata["imported_functions"], file_report.xmetadata["imported_functions"])

    def testFileLayoutIsLeftAlone(self):
        data = loadFixture(EXPORTS_FIXTURE)
        self.assertIsNone(ElfFileLoader.unmapImage(data, lief.ELF.parse(list(data))))

    def testCorruptDynamicTableDegrades(self):
        image, (start, size) = mapImage(loadFixture(EXPORTS_FIXTURE))
        variants = {
            "no DT_NULL": image[:start] + b"\x41" * size + image[start + size :],
            "zeroed": image[:start] + bytes(size) + image[start + size :],
            "truncated": image[: start + 8],
            "truncated before": image[:start],
        }
        for label, variant in variants.items():
            with self.subTest(label):
                self.assertIsNone(ElfFileLoader.unmapImage(variant, lief.ELF.parse(list(variant))))
                report = disassemble(variant, as_buffer=True)
                self.assertEqual(report.status, "ok")
                self.assertFalse(report.xmetadata["exported_functions"])

    def testOversizedSegmentIsRefused(self):
        image, _dynamic = mapImage(loadFixture(EXPORTS_FIXTURE))
        parsed = lief.ELF.parse(list(image))
        # the RW segment claiming more file bytes than the whole image holds
        rw_load = [segment for segment in parsed.segments if segment.type == lief.ELF.Segment.TYPE.LOAD][2]
        index = list(parsed.segments).index(rw_load)
        header = bytearray(image)
        struct.pack_into("<Q", header, parsed.header.program_header_offset + index * 56 + 32, len(image))
        self.assertIsNone(ElfFileLoader.unmapImage(bytes(header), lief.ELF.parse(list(header))))

    def testNonElfBuffer(self):
        report = disassemble(b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3" * 64, as_buffer=True)
        self.assertEqual(report.status, "ok")
        self.assertIsNone(ElfFileLoader.unmapImage(b"\x7fELF" + bytes(12), None))


if __name__ == "__main__":
    unittest.main()
