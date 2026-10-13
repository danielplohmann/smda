"""The byte table of a two-level switch is data (#384).

For a switch over many values with few distinct cases MSVC reads a case number from a byte
table and indexes the jump table with it. The byte table lies after the jump table, between two
functions, and its bytes decode as code (`04 04` is `add al, 4`).
"""

import unittest
from types import SimpleNamespace

from smda.common.RecursiveDisassembler import RecursiveDisassembler
from smda.Disassembler import Disassembler
from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer
from smda.SmdaConfig import SmdaConfig

BASE = 0x1000


class TwoLevelSwitchTest(unittest.TestCase):
    HOST = 0x40
    CASES = (HOST + 0x18, HOST + 0x1B, HOST + 0x21, HOST + 0x27, HOST + 0x2D)
    DEFAULT = HOST + 0x33
    TABLE = HOST + 0x3C
    INDEX = TABLE + 4 * len(CASES)
    VALUES = 0x40

    def _image(self):
        image = bytearray(b"\xcc" * 0x200)
        caller = b"\xe8" + (self.HOST - 5).to_bytes(4, "little", signed=True) + b"\xc3"
        image[: len(caller)] = caller
        host = (
            b"\x0f\xb6\x4c\x24\x04"  # movzx ecx, byte ptr [esp + 4]
            + b"\x83\xf9"  # cmp ecx, VALUES - 1
            + bytes([self.VALUES - 1])
            + b"\x77"  # ja default
            + bytes([self.DEFAULT - (self.HOST + 10)])
            + b"\x0f\xb6\x89"  # movzx ecx, byte ptr [ecx + index]
            + (BASE + self.INDEX).to_bytes(4, "little")
            + b"\xff\x24\x8d"  # jmp dword ptr [ecx*4 + table]
            + (BASE + self.TABLE).to_bytes(4, "little")
            + b"\x33\xc0\xc3"  # case 0: xor eax, eax; ret
            + b"".join(b"\xb8" + bytes([case]) + b"\x00\x00\x00\xc3" for case in range(1, len(self.CASES)))
            + b"\xb8\x0c\x00\x00\x00\xc3"  # default: mov eax, 12; ret
        )
        self.assertEqual(len(host), self.DEFAULT + 6 - self.HOST)
        image[self.HOST : self.HOST + len(host)] = host
        for index, target in enumerate(self.CASES):
            image[self.TABLE + 4 * index : self.TABLE + 4 * index + 4] = (BASE + target).to_bytes(4, "little")
        # mostly the last case, as in a whitespace scanner: `04 04` decodes as `add al, 4`
        image[self.INDEX : self.INDEX + self.VALUES] = bytes(min(value, 4) for value in range(self.VALUES))
        return bytes(image)

    def testTheByteTableIsDataAndStartsNoFunction(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(self._image(), BASE, bitness=32)
        self.assertEqual(report.status, "ok")
        starts = {function.offset - BASE for function in report.getFunctions()}
        self.assertEqual({start for start in starts if self.TABLE <= start < self.INDEX + self.VALUES}, set())
        data_map = disassembler.disassembler.disassembly.data_map
        self.assertTrue(all(BASE + self.INDEX + offset in data_map for offset in range(self.VALUES)))


class IndexTableExtentTest(unittest.TestCase):
    """Where the byte table lies, from its bytes and the jump table in front of it."""

    def _analyzer(self, layout):
        image = bytes(layout)
        disassembly = SimpleNamespace(
            getBytes=lambda addr, size: image[addr - BASE : addr - BASE + size] if addr >= BASE else None
        )
        analyzer = JumpTableAnalyzer.__new__(JumpTableAnalyzer)
        analyzer.disassembly = disassembly
        return analyzer

    def testATableIndexedFromZeroIsAsLongAsItsBound(self):
        analyzer = self._analyzer([0, 1, 2, 1, 0xCC])
        self.assertEqual(analyzer._indexTableExtent(BASE, 4, [BASE - 12, BASE - 8, BASE - 4]), (BASE, 4))

    def testABiasedTableStartsBehindTheJumpTableAndEndsAtThePadding(self):
        # [value + BASE] with values from 8: the table starts behind the jump table at BASE + 8
        layout = [0xFF] * 8 + [0, 1, 1, 0, 1] + [0xCC] * 3
        analyzer = self._analyzer(layout)
        self.assertEqual(analyzer._indexTableExtent(BASE, 0x59, [BASE, BASE + 4]), (BASE + 8, 5))

    def testABiasedTableEndingInCodeIsLeftAlone(self):
        layout = [0xFF] * 8 + [0, 1, 1, 0, 1, 0x55, 0x8B, 0xEC]
        analyzer = self._analyzer(layout)
        self.assertIsNone(analyzer._indexTableExtent(BASE, 0x59, [BASE, BASE + 4]))

    def testNoTableWithoutJumpTableEntriesOrWithOneOutOfReach(self):
        analyzer = self._analyzer([0, 1, 0xCC])
        self.assertIsNone(analyzer._indexTableExtent(BASE, 2, []))
        self.assertIsNone(analyzer._indexTableExtent(BASE, 0, [BASE + 0x200]))
        self.assertIsNone(analyzer._indexTableExtent(BASE, 0, [BASE - 4]))
        self.assertIsNone(analyzer._indexTableExtent(BASE - 0x10, 0, [BASE - 0x10]))


class X64IndexTableTest(unittest.TestCase):
    """x64 addresses both tables as RVAs off a register holding the image base."""

    IMAGE_BASE = 0x180000000
    JUMP = 0x180001457
    TABLE = 0x180001514
    INDEX = 0x180001528
    #: case_b2_whitespace from the issue's reproducer, MSVC x64 /O2
    WINDOW = (
        (0x180001425, 3, "movzx", "ecx, byte ptr [rcx]"),
        (0x180001428, 3, "sub", "ecx, 9"),
        (0x18000142B, 6, "cmp", "ecx, 0xd9"),
        (0x180001431, 6, "ja", "0x180001511"),
        (0x180001437, 7, "lea", "r10, [rip - 0x143e]"),
        (0x18000143E, 2, "nop", ""),
        (0x180001440, 3, "movsxd", "rcx, ecx"),
        (0x180001443, 9, "movzx", "ecx, byte ptr [r10 + rcx + 0x1528]"),
        (0x18000144C, 8, "mov", "edx, dword ptr [r10 + rcx*4 + 0x1514]"),
        (0x180001454, 3, "add", "rdx, r10"),
    )

    def _record(self, window):
        image = {self.INDEX + offset: offset % 5 for offset in range(0xDA)}
        analyzer = JumpTableAnalyzer.__new__(JumpTableAnalyzer)
        analyzer.disassembler = SimpleNamespace(
            getReferencedAddr=lambda op: RecursiveDisassembler.getReferencedAddr(None, op)
        )
        analyzer.disassembly = SimpleNamespace(
            getBytes=lambda addr, size: bytes(image.get(addr + offset, 0xCC) for offset in range(size))
        )
        booked = []
        state = SimpleNamespace(
            data_refs={(self.JUMP, self.TABLE + 4 * index) for index in range(5)},
            addDataRef=lambda source, target, size=1: booked.append((target, size)),
        )
        analyzer._recordIndexTable((self.JUMP, 2, "jmp", "rdx"), state, list(window))
        return booked

    def testTheIndexTableIsFoundOffTheImageBase(self):
        self.assertIn((self.INDEX, 0xDA), self._record(self.WINDOW))

    def testAnUnresolvedImageBaseBooksNothing(self):
        window = [instruction for instruction in self.WINDOW if instruction[2] != "lea"]
        self.assertEqual(self._record(window), [])


if __name__ == "__main__":
    unittest.main()
