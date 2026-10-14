"""A frame setup behind an early-exit check belongs to the function that runs the check (#384).

MSVC shrink-wraps: a check that can return without a frame comes first, and the register saves
follow it. The saves look like a function start, but the code before them branches to them or
falls through into them, so they are the body of the function that starts at the check.
"""

import unittest
from types import SimpleNamespace

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from smda.aarch64.definitions import direct_branch_target, flows_into, is_frame_setup
from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from tests.testAArch64HoistedGuardEntry import REGION, SCAFFOLD_ENTRIES, _disassemble, _render, _scaffold

BASE = 0x400000

NOP = 0xD503201F
RET = 0xD65F03C0
MOV_W0_7 = 0x528000E0  # mov w0, #7
MOV_X0_0 = 0xD2800000  # mov x0, #0
LDR_X3_X2 = 0xF9400043  # ldr x3, [x2]
CMP_W8_5 = 0x7100151F  # cmp w8, #5
SAVE_X19_X20 = 0xA9BE53F3  # stp x19, x20, [sp, #-0x20]!
SAVE_LR = 0xF9000BFE  # str x30, [sp, #0x10]
RESTORE_LR = 0xF9400BFE  # ldr x30, [sp, #0x10]
RESTORE_X19_X20 = 0xA8C253F3  # ldp x19, x20, [sp], #0x20
FRAME_RECORD = 0xA9BF7BFD  # stp x29, x30, [sp, #-0x10]!
SAVE_D8_D9 = 0x6DBE27E8  # stp d8, d9, [sp, #-0x20]!
SAVE_D10_D11 = 0x6D012FEA  # stp d10, d11, [sp, #0x10]
PACIASP = 0xD503233F
SUB_SP_0X40 = 0xD10103FF  # sub sp, sp, #0x40
TBNZ_W9_14 = 0x37700069  # tbnz w9, #14, <pc + 12>
#: a double constant between functions: its low word decodes as `b.hi`, its high word not at all
DATA_LOW = 0x54442D18
DATA_HIGH = 0xBFE921FB


def _cbnz(source, target):
    return 0xB5000000 | ((((target - source) // 4) & 0x7FFFF) << 5)  # cbnz x0, <label>


def _cbz_x3(source, target):
    return 0xB4000003 | ((((target - source) // 4) & 0x7FFFF) << 5)  # cbz x3, <label>


def _b_eq(source, target):
    return 0x54000000 | ((((target - source) // 4) & 0x7FFFF) << 5)


def _b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


class WordEncodingTest(unittest.TestCase):
    """The words the tests below are built from, checked against capstone."""

    def testEveryWordDecodesAsItsComment(self):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        expected = {
            MOV_W0_7: "mov w0, #7",
            LDR_X3_X2: "ldr x3, [x2]",
            CMP_W8_5: "cmp w8, #5",
            SAVE_X19_X20: "stp x19, x20, [sp, #-0x20]!",
            SAVE_LR: "str x30, [sp, #0x10]",
            RESTORE_LR: "ldr x30, [sp, #0x10]",
            RESTORE_X19_X20: "ldp x19, x20, [sp], #0x20",
            FRAME_RECORD: "stp x29, x30, [sp, #-0x10]!",
            SAVE_D8_D9: "stp d8, d9, [sp, #-0x20]!",
            SAVE_D10_D11: "stp d10, d11, [sp, #0x10]",
            _cbnz(BASE, BASE + 12): f"cbnz x0, #{BASE + 12:#x}",
            _b_eq(BASE, BASE - 8): f"b.eq #{BASE - 8:#x}",
            SUB_SP_0X40: "sub sp, sp, #0x40",
            TBNZ_W9_14: f"tbnz w9, #0xe, #{BASE + 12:#x}",
        }
        for word, text in expected.items():
            insn = next(md.disasm(word.to_bytes(4, "little"), BASE))
            self.assertEqual(f"{insn.mnemonic} {insn.op_str}", text)
        self.assertIsNone(next(md.disasm(DATA_HIGH.to_bytes(4, "little"), BASE), None))

    def testBranchTargetsSignExtend(self):
        self.assertEqual(direct_branch_target(_b_eq(BASE, BASE - 8), BASE), BASE - 8)
        self.assertEqual(direct_branch_target(_b(BASE, BASE - 0x100), BASE), BASE - 0x100)
        self.assertEqual(direct_branch_target(_cbnz(BASE, BASE + 12), BASE), BASE + 12)
        self.assertEqual(direct_branch_target(TBNZ_W9_14, BASE), BASE + 12)
        self.assertEqual(direct_branch_target(TBNZ_W9_14 | 0x7FFE0, BASE), BASE - 4)
        self.assertIsNone(direct_branch_target(_bl(BASE, BASE + 8), BASE))

    def testAStackAllocationIsFrameSetup(self):
        self.assertTrue(is_frame_setup(SUB_SP_0X40))
        self.assertTrue(is_frame_setup(SAVE_D8_D9))
        self.assertFalse(is_frame_setup(LDR_X3_X2))

    def testAnUnconditionalBranchDoesNotEnterTheWordItTargets(self):
        # how a function tail-calls the one laid out after it
        self.assertFalse(flows_into([MOV_X0_0, _b(BASE + 4, BASE + 8)], BASE, BASE + 8))
        self.assertTrue(flows_into([MOV_X0_0, _cbnz(BASE + 4, BASE + 8)], BASE, BASE + 8))


class HoistedEntryWalkTest(unittest.TestCase):
    """`hoistedEntryBefore` on hand-placed words, one shape per test."""

    def _manager(self, words, records=()):
        image = b"".join(word.to_bytes(4, "little") for word in words)
        binary_info = BinaryInfo(image)
        binary_info.base_addr = BASE
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False, code_map={})
        manager.bitness = 64
        manager._code_areas = []
        manager._exception_record_begins = {BASE + 4 * index for index in records}
        return manager

    def testAnEarlyReturnAheadOfTheSaves(self):
        # sqlite3_errcode: cbnz x0, body; mov w0, #7; ret; body: stp x19, x20, [sp, #-0x20]!
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, SAVE_X19_X20, SAVE_LR])
        self.assertEqual(manager.hoistedEntryBefore(BASE + 16), BASE + 4)

    def testACheckThatFallsThroughIntoTheSaves(self):
        # groupConcatStep: ...; cmp w8, #5; b.eq <exit>; stp x19, x20, [sp, #-0x40]!
        manager = self._manager([NOP, LDR_X3_X2, CMP_W8_5, _b_eq(BASE + 12, BASE + 0x40), SAVE_X19_X20])
        self.assertEqual(manager.hoistedEntryBefore(BASE + 16), BASE + 4)

    def testFloatingPointSavesAheadOfTheFrameRecord(self):
        manager = self._manager([RET, SAVE_D8_D9, SAVE_D10_D11, FRAME_RECORD], records=(1,))
        self.assertEqual(manager.hoistedEntryBefore(BASE + 12), BASE + 4)

    def testTheEntryIsFoundWithoutPaddingAfterTheFunctionBefore(self):
        # the previous function ends in `ret` right where this one starts
        manager = self._manager([MOV_X0_0, RET, _cbnz(BASE + 8, BASE + 20), MOV_W0_7, RET, SAVE_X19_X20])
        self.assertEqual(manager.hoistedEntryBefore(BASE + 20), BASE + 8)

    def testATailCallIntoTheNextFunctionLeavesItAlone(self):
        manager = self._manager([NOP, MOV_X0_0, _b(BASE + 8, BASE + 12), SAVE_X19_X20])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 12))

    def testALeafThatReturnsBeforeTheNextFunctionLeavesItAlone(self):
        manager = self._manager([NOP, CMP_W8_5, _b_eq(BASE + 8, BASE + 0x40), RET, SAVE_X19_X20])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 16))

    def testACallBeforeTheSavesIsABoundary(self):
        # a call that does not return, then the next function
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 0x40), _bl(BASE + 8, BASE + 0x80), SAVE_X19_X20])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 12))

    def testConstantsBetweenFunctionsAreNotCode(self):
        manager = self._manager([NOP, DATA_LOW, DATA_HIGH, SAVE_X19_X20])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 12))

    def testAPointerAuthEntryIsNeverMoved(self):
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, PACIASP])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 16))

    def testAHoistedRecordIsSeededAtTheCheckUnlessItsStartIsCalled(self):
        words = [NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, SAVE_X19_X20, SAVE_LR]
        for called, expected in ((False, BASE + 4), (True, BASE + 16)):
            manager = self._manager(words)
            manager.candidates = {}
            manager._call_targets = {BASE + 16} if called else set()
            manager._admitExceptionRecordEntry(BASE + 16, SAVE_X19_X20)
            manager._admitHoistedExceptionRecords()
            self.assertEqual(
                {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}, {expected}
            )

    def testAMisalignedOrOutOfImageAddressHasNoEntry(self):
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, SAVE_X19_X20])
        self.assertIsNone(manager.hoistedEntryBefore(BASE + 18))
        self.assertIsNone(manager.hoistedEntryBefore(BASE - 4))

    def testARunOfFloatingPointSavesIsSeededWhereItStarts(self):
        words = [RET, SAVE_D8_D9, SAVE_D10_D11, FRAME_RECORD]
        for records, from_record in (((1,), True), ((), False)):
            manager = self._manager(words, records=records)
            manager.candidates = {}
            manager._admitPrologueRunEntry(BASE + 4)
            self.assertEqual(set(manager.candidates), {BASE + 4})
            self.assertEqual(manager.candidates[BASE + 4].is_exception_handler, from_record)

    def testARunEntryThatIsItselfEnteredIsNotSeeded(self):
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, SAVE_D8_D9, FRAME_RECORD])
        manager.candidates = {}
        manager._admitPrologueRunEntry(BASE + 16)
        self.assertEqual(manager.candidates, {})

    def testHoistedRecordsAreAdmittedWhenTheTimeoutTripsAfterTheRecords(self):
        manager = self._manager([NOP, _cbnz(BASE + 4, BASE + 16), MOV_W0_7, RET, SAVE_X19_X20, SAVE_LR])
        manager.candidates = {}
        manager._call_targets = set()
        manager.locateSymbolCandidates = lambda: None
        manager.locatePeExceptionCandidates = lambda: manager._admitExceptionRecordEntry(BASE + 16, SAVE_X19_X20)
        trips = iter((False, True))
        manager._candidateTimeoutTripped = lambda: next(trips)
        manager.locateCandidates()
        self.assertEqual(set(manager.candidates), {BASE + 4})


class ShrinkWrappedEntryInAGapTest(unittest.TestCase):
    """Nothing calls the function, so only the gap scan reaches its entry. Its 16-aligned saves
    used to be analysed first as a function of their own, leaving the check as a second one."""

    def _image(self):
        words = {}
        _scaffold(words)
        words.update(
            {
                REGION: LDR_X3_X2,
                REGION + 0x04: _cbz_x3(REGION + 0x04, REGION + 0x28),
                REGION + 0x08: CMP_W8_5,
                REGION + 0x0C: _b_eq(REGION + 0x0C, REGION + 0x28),
                REGION + 0x10: SAVE_X19_X20,
                REGION + 0x14: SAVE_LR,
                REGION + 0x18: MOV_X0_0,
                REGION + 0x1C: RESTORE_LR,
                REGION + 0x20: RESTORE_X19_X20,
                REGION + 0x24: RET,
                REGION + 0x28: MOV_W0_7,
                REGION + 0x2C: RET,
            }
        )
        return _render(words)

    def testTheCheckAndTheBodyAreOneFunction(self):
        report = _disassemble(self._image())
        self.assertEqual(report.status, "ok")
        functions = {function.offset: function for function in report.getFunctions()}
        self.assertEqual(sorted(set(functions) - SCAFFOLD_ENTRIES), [REGION])
        offsets = {instruction.offset for instruction in functions[REGION].getInstructions()}
        self.assertEqual(offsets, set(range(REGION, REGION + 0x30, 4)))


class X86BodyBehindAnEarlyReturnTest(unittest.TestCase):
    """x86: `cmp; je body; ret; body: push ebp; mov ebp, esp; ...`, as in sqlite's computeJD.
    The body is a prologue candidate and nothing else; the jcc keeps it in the function."""

    HOST = 0x40

    def _image(self, host=HOST, calls=8):
        image = bytearray(b"\xcc" * 0x80)
        caller = bytearray()
        for _ in range(calls):  # 5 or more put the host ahead of the body's prologue in the order
            caller += b"\xe8" + (host - (len(caller) + 5)).to_bytes(4, "little", signed=True)
        caller += b"\xc3"
        image[: len(caller)] = caller
        body = (
            b"\x80\x79\x28\x00"  # cmp byte ptr [ecx + 0x28], 0
            b"\x74\x01"  # je body
            b"\xc3"  # ret
            b"\x55\x8b\xec"  # body: push ebp; mov ebp, esp
            b"\xb8\x01\x00\x00\x00"  # mov eax, 1
            b"\x5d"  # pop ebp
            b"\xc3"  # ret
        )
        image[host : host + len(body)] = body
        return bytes(image)

    def _assertTheBodyStaysInTheFunction(self, host, calls=8):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleBuffer(self._image(host, calls), 0x1000, bitness=32)
        self.assertEqual(report.status, "ok")
        functions = {function.offset - 0x1000: function for function in report.getFunctions()}
        self.assertNotIn(host + 7, functions)
        offsets = {instruction.offset - 0x1000 for instruction in functions[host].getInstructions()}
        self.assertIn(host + 7, offsets)

    def testTheBodyStaysInTheFunction(self):
        self._assertTheBodyStaysInTheFunction(self.HOST)

    def testAnAlignedBodyRightBehindTheReturnStaysInTheFunction(self):
        # the body lands on 0x50: aligned, but behind the `ret` rather than behind padding
        self._assertTheBodyStaysInTheFunction(0x49)

    def testTheBodyStaysInTheFunctionWhenItIsAnalyzedFirst(self):
        # with four calls or fewer the body's prologue outranks the host, so the body is a
        # function already when the host's jcc reaches it (#388)
        for calls in (0, 1, 4):
            with self.subTest(calls=calls):
                self._assertTheBodyStaysInTheFunction(self.HOST, calls)


class X86PointerReachedFunctionBehindPaddingTest(unittest.TestCase):
    """x86: a jcc into a function that sits aligned behind padding does not absorb it.

    Only a pointer reaches the target (a callback, a vtable slot), so it has no call reference,
    but the compiler placed it as a function of its own, unlike a body behind an early `ret`.
    """

    BASE = 0x401000
    JUMPER = BASE + 0x80
    TARGET = BASE + 0xA0
    TAKER = BASE + 0xC0

    def _image(self, calls=8):
        image = bytearray(b"\xcc" * 0x200)

        def put(address, data):
            image[address - self.BASE : address - self.BASE + len(data)] = data

        def rel(source, size, destination):
            return (destination - (source + size)).to_bytes(4, "little", signed=True)

        caller = bytearray()
        for _ in range(calls):  # 8 analyze the jumper before the target, none after it
            caller += b"\xe8" + rel(self.BASE + len(caller), 5, self.JUMPER)
        caller += b"\xe8" + rel(self.BASE + len(caller), 5, self.TAKER) + b"\xc3"
        put(self.BASE, caller)
        put(self.JUMPER, b"\x85\xc9\x0f\x85" + rel(self.JUMPER + 2, 6, self.TARGET) + b"\x31\xc0\xc3")
        put(self.TARGET, b"\x55\x8b\xec\x8b\x45\x08\x5d\xc3")  # push ebp; mov ebp, esp; ...; ret
        # push offset target; call dword ptr [eax]
        put(self.TAKER, b"\x55\x8b\xec\x68" + self.TARGET.to_bytes(4, "little") + b"\xff\x10\x83\xc4\x04\x5d\xc3")
        return bytes(image)

    def testTheTargetStaysAFunctionOfItsOwn(self):
        for calls in (8, 0):
            with self.subTest(calls=calls):
                config = SmdaConfig()
                config.WITH_STRINGS = False
                report = Disassembler(config).disassembleBuffer(self._image(calls), self.BASE, bitness=32)
                functions = {function.offset: function for function in report.getFunctions()}
                self.assertIn(self.TARGET, functions)
                self.assertEqual(functions[self.TARGET].num_instructions, 5)
                self.assertEqual(functions[self.JUMPER].num_instructions, 4)


if __name__ == "__main__":
    unittest.main()
