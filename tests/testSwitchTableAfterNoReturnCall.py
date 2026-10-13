"""A switch table placed after a call that does not return is data, not code (#384).

MSVC places an x86 switch's jump table right after the function's last block. When that block
ends in a call that never returns, decoding on past the call runs into the table, and from the
table, misaligned, into the function after it.
"""

import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x1000


class SwitchTableAfterNoReturnCallTest(unittest.TestCase):
    HOST = 0x40
    FATAL = 0x30
    CASE_0 = HOST + 0x10
    CASE_1 = HOST + 0x13
    DEFAULT = HOST + 0x19
    ERROR = HOST + 0x1F
    TABLE = HOST + 0x26
    NEXT = TABLE + 12

    def _image(self, guard_first):
        image = bytearray(b"\xcc" * 0x100)
        caller = bytearray()
        for _ in range(8):  # enough call references to analyze the host ahead of the function after it
            caller += b"\xe8" + (self.HOST - (len(caller) + 5)).to_bytes(4, "little", signed=True)
        caller += b"\xe8" + (self.NEXT - (len(caller) + 5)).to_bytes(4, "little", signed=True)
        caller += b"\xc3"
        image[: len(caller)] = caller
        image[self.FATAL : self.FATAL + 2] = b"\xeb\xfe"  # jmp $, never returns
        guard = b"\x85\xc9" + b"\x74" + bytes([self.ERROR - (self.HOST + 4)])  # test ecx, ecx; je error
        bound = b"\x83\xfa\x02" + b"\x77" + bytes([self.DEFAULT - (self.HOST + 9)])  # cmp edx, 2; ja default
        if not guard_first:
            # the same checks, the other way round: the dispatch is decoded before the error path
            guard, bound = (
                b"\x83\xfa\x02" + b"\x77" + bytes([self.DEFAULT - (self.HOST + 5)]),
                b"\x85\xc9" + b"\x74" + bytes([self.ERROR - (self.HOST + 9)]),
            )
        host = (
            guard
            + bound
            + b"\xff\x24\x95"  # jmp dword ptr [edx*4 + table]
            + (BASE + self.TABLE).to_bytes(4, "little")
            + b"\x33\xc0\xc3"  # case 0: xor eax, eax; ret
            + b"\xb8\x01\x00\x00\x00\xc3"  # case 1: mov eax, 1; ret
            + b"\xb8\x0c\x00\x00\x00\xc3"  # default: mov eax, 12; ret
            + b"\x6a\x00"  # error: push 0
            + b"\xe8"  # call fatal
            + (self.FATAL - (self.ERROR + 7)).to_bytes(4, "little", signed=True)
        )
        self.assertEqual(len(host), self.TABLE - self.HOST)
        image[self.HOST : self.TABLE] = host
        for index, target in enumerate((self.CASE_0, self.CASE_1, self.DEFAULT)):
            image[self.TABLE + 4 * index : self.TABLE + 4 * index + 4] = (BASE + target).to_bytes(4, "little")
        # the function after the table: push ebp; mov ebp, esp; mov eax, 2; pop ebp; ret
        image[self.NEXT : self.NEXT + 10] = b"\x55\x8b\xec\xb8\x02\x00\x00\x00\x5d\xc3"
        return bytes(image)

    def _functions(self, guard_first):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleBuffer(self._image(guard_first), BASE, bitness=32)
        self.assertEqual(report.status, "ok")
        return {
            function.offset - BASE: {instruction.offset - BASE for instruction in function.getInstructions()}
            for function in report.getFunctions()
        }

    def testTheTableEndsTheFunctionAndTheNextOneStartsAfterIt(self):
        for guard_first in (False, True):
            with self.subTest(guard_first=guard_first):
                functions = self._functions(guard_first)
                host = functions[self.HOST]
                self.assertTrue({self.CASE_0, self.CASE_1, self.DEFAULT, self.ERROR + 2} <= host)
                self.assertEqual({offset for offset in host if offset >= self.TABLE}, set())
                self.assertIn(self.NEXT, functions)


if __name__ == "__main__":
    unittest.main()
