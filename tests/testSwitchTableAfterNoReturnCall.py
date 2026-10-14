"""A switch table placed after a call that does not return is data, not code (#384).

MSVC places an x86 switch's jump table right after the function's last block. When that block
ends in a call that never returns, decoding on past the call runs into the table, and from the
table, misaligned, into the function after it.
"""

import unittest
from types import SimpleNamespace

from smda.common.RecursiveDisassembler import RecursiveDisassembler
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

    def _image(self, guard_first, host_calls=8, base=BASE):
        image = bytearray(b"\xcc" * 0x100)
        caller = bytearray()
        for _ in range(host_calls):  # enough call references to analyze the host ahead of the function after it
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
            + (base + self.TABLE).to_bytes(4, "little")
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
            image[self.TABLE + 4 * index : self.TABLE + 4 * index + 4] = (base + target).to_bytes(4, "little")
        # the function after the table: push ebp; mov ebp, esp; mov eax, 2; pop ebp; ret
        image[self.NEXT : self.NEXT + 10] = b"\x55\x8b\xec\xb8\x02\x00\x00\x00\x5d\xc3"
        return bytes(image)

    def _functions(self, guard_first, host_calls=8):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(self._image(guard_first, host_calls), BASE, bitness=32)
        self.assertEqual(report.status, "ok")
        functions = {
            function.offset - BASE: {instruction.offset - BASE for instruction in function.getInstructions()}
            for function in report.getFunctions()
        }
        return functions, disassembler.disassembler.disassembly

    def testTheTableEndsTheFunctionAndTheNextOneStartsAfterIt(self):
        for guard_first in (False, True):
            with self.subTest(guard_first=guard_first):
                functions, disassembly = self._functions(guard_first)
                host = functions[self.HOST]
                self.assertTrue({self.CASE_0, self.CASE_1, self.DEFAULT, self.ERROR + 2} <= host)
                self.assertEqual({offset for offset in host if offset >= self.TABLE}, set())
                self.assertIn(self.NEXT, functions)
                fatal_call = BASE + self.ERROR + 2
                self.assertNotIn(BASE + self.TABLE, disassembly.code_refs_from.get(fatal_call, ()))

    def testAGapFunctionTheDiscardedPassRevertedIsRestored(self):
        # a candidate found late, after the gap scan, decodes through the table into a gap
        # function and reverts it; the repeated pass stops at the table and must give it back.
        # At this base the table entries hold no `00 00`, which would end the pass as suspicious.
        base = 0x10001000
        config = SmdaConfig()
        config.WITH_STRINGS = False
        disassembler = Disassembler(config)
        disassembler.disassembleBuffer(self._image(guard_first=True, base=base), base, bitness=32)
        engine = disassembler.disassembler
        candidates = engine.fc_manager.candidates
        candidates[base + self.NEXT].is_gap_candidate = True
        candidates[base + self.HOST].is_gap_candidate = True
        self.assertTrue(engine._revertGapFunction(base + self.HOST, base))
        candidates[base + self.HOST].is_gap_candidate = False
        # as if the host had never been analyzed: nothing knows its table yet
        engine.disassembly.data_map.difference_update(range(base + self.TABLE, base + self.NEXT))
        engine.analyzeFunction(base + self.HOST)
        self.assertIn(base + self.HOST, engine.disassembly.functions)
        self.assertIn(base + self.NEXT, engine.disassembly.functions)
        self.assertFalse(candidates[base + self.NEXT].analysis_aborted)


class DatumAfterNoReturnCallTest(unittest.TestCase):
    """A function of one block that ends where the datum it reads begins is still a function."""

    HOST = 0x40
    FATAL = 0x30
    DATUM = HOST + 11

    def testTheBlockEndsAtTheDatumAndCounts(self):
        image = bytearray(b"\xcc" * 0x80)
        image[:6] = b"\xe8" + (self.HOST - 5).to_bytes(4, "little", signed=True) + b"\xc3"
        image[self.FATAL : self.FATAL + 2] = b"\xeb\xfe"  # jmp $, never returns
        host = (
            b"\xa1"
            + (BASE + self.DATUM).to_bytes(4, "little")  # mov eax, dword ptr [datum]
            + b"\x50"  # push eax
            + b"\xe8"
            + (self.FATAL - (self.HOST + 11)).to_bytes(4, "little", signed=True)  # call fatal
        )
        image[self.HOST : self.DATUM] = host
        image[self.DATUM : self.DATUM + 4] = b"\x05\x00\x00\x00"  # decodes as `add eax, ...`
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleBuffer(bytes(image), BASE, bitness=32)
        functions = {function.offset - BASE: function for function in report.getFunctions()}
        self.assertIn(self.HOST, functions)
        offsets = {instruction.offset - BASE for instruction in functions[self.HOST].getInstructions()}
        self.assertEqual(offsets, {self.HOST, self.HOST + 5, self.HOST + 6})


class RestoreRevertedGapFunctionsTest(unittest.TestCase):
    """Which reverted gap functions are analyzed again, and what a failed one is left as."""

    def testAbsorbedOnesAreSkippedAndFailedOnesStayAborted(self):
        absorbed, failing = 0x2000, 0x3000
        aborted, analyzed = [], []
        candidate = SimpleNamespace(analysis_aborted=True, abortion_reason="Reverted")
        engine = SimpleNamespace(
            disassembly=SimpleNamespace(ins2fn={absorbed: 0x1000}, functions={}),
            fc_manager=SimpleNamespace(
                candidates={failing: candidate},
                updateAnalysisAborted=lambda addr, reason: aborted.append(addr),
            ),
            analyzeFunction=lambda addr, as_gap=False: analyzed.append((addr, as_gap)),
        )
        RecursiveDisassembler._restoreRevertedGapFunctions(engine, [absorbed, failing])
        self.assertEqual(analyzed, [(failing, True)])
        self.assertEqual(aborted, [failing])
        self.assertEqual(candidate.abortion_reason, "")


if __name__ == "__main__":
    unittest.main()
