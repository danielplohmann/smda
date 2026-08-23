#!/usr/bin/python

import struct
import types
import unittest

from smda.Disassembler import Disassembler
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig

ENDBR64 = bytes.fromhex("f30f1efa")
CALLER = 0x100
STUB = 0x200
TARGET = 0x210


def _disassembler(is_candidate=True):
    return types.SimpleNamespace(fc_manager=types.SimpleNamespace(isFunctionCandidate=lambda addr: is_candidate))


def _state(max_instruction_start=0):
    return types.SimpleNamespace(max_instruction_start=max_instruction_start)


class PaddedLandingPadShapeTest(unittest.TestCase):
    """What the cut requires, one condition at a time. Only a pad reached by falling through
    padding starts a function: one that begins a block is the target of a branch already
    inside the function, which is how a switch case body is spelled in CET code."""

    NOP = (0x20C, 1, "nop", "")

    def _isEntry(self, **overrides):
        arguments = {
            "d": _disassembler(),
            "state": _state(),
            "i_address": TARGET,
            "previous_instruction": self.NOP,
            "start_addr": STUB,
        }
        arguments.update(overrides)
        return X86Backend._isPaddedLandingPad(**arguments)

    def test_a_padded_landing_pad_at_the_boundary_is_an_entry(self):
        self.assertTrue(self._isEntry())

    def test_a_pad_that_begins_a_block_is_not(self):
        self.assertFalse(self._isEntry(previous_instruction=None))

    def test_the_function_s_own_entry_is_not(self):
        self.assertFalse(self._isEntry(i_address=STUB, start_addr=STUB))

    def test_a_pad_off_the_alignment_boundary_is_not(self):
        self.assertFalse(self._isEntry(i_address=TARGET + 4))

    def test_a_pad_reached_without_padding_is_not(self):
        self.assertFalse(self._isEntry(previous_instruction=(0x20C, 3, "xor", "eax, eax")))

    def test_an_address_that_is_no_candidate_is_not(self):
        self.assertFalse(self._isEntry(d=_disassembler(is_candidate=False)))

    def test_a_function_that_already_reaches_past_the_pad_is_not_cut(self):
        """The function wraps around the pad, so cutting would nest one inside the other -
        the alignment cut beside this one declines for the same reason."""
        self.assertFalse(self._isEntry(state=_state(max_instruction_start=TARGET + 0x40)))

    def test_a_prefixed_nop_still_reads_as_padding(self):
        """Capstone spells the multi-byte pads with their prefix in the mnemonic."""
        self.assertTrue(self._isEntry(previous_instruction=(0x20C, 4, "cs nop", "word ptr [rax + rax]")))


class PaddedLandingPadRecoveryTest(unittest.TestCase):
    """End to end: an entry stub that sets one argument and falls through padding into the
    function it fronts. glibc's multiarch entries are exactly this shape, and decoding
    straight through reports the pair as one function and loses the second entry."""

    def _image(self, body, target=TARGET):
        buffer = bytearray(0x2000)
        # three calls, so the stub outranks the landing pad in the candidate queue and is
        # the one that gets to run into it
        caller = bytes.fromhex("554889e5")  # push rbp; mov rbp, rsp
        for _ in range(3):
            caller += bytes.fromhex("e8") + struct.pack("<i", STUB - (CALLER + len(caller) + 5))
        caller += bytes.fromhex("5dc3")  # pop rbp; ret
        buffer[CALLER : CALLER + len(caller)] = caller
        stub = ENDBR64 + body
        buffer[STUB : STUB + len(stub)] = stub
        entry = ENDBR64 + bytes.fromhex("89f8c3")  # mov eax, edi; ret
        buffer[target : target + len(entry)] = entry
        return bytes(buffer)

    def _offsets(self, body, target=TARGET):
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = False
        report = Disassembler(config).disassembleBuffer(self._image(body, target), 0, bitness=64)
        self.assertEqual(report.status, "ok")
        return sorted(function.offset for function in report.getFunctions())

    @staticmethod
    def _padded(body, target=TARGET):
        return body + b"\x90" * (target - STUB - len(ENDBR64) - len(body))

    def test_both_entries_are_recovered(self):
        self.assertEqual(self._offsets(self._padded(bytes.fromhex("bf01000000"))), [CALLER, STUB, TARGET])

    def test_a_landing_pad_off_the_boundary_is_still_absorbed(self):
        """Control: the same stub, the same padding, the same landing pad - only not at an
        alignment boundary, so nothing says it is an entry. Reads the same on either side of
        the change."""
        body = self._padded(bytes.fromhex("bf01000000"), TARGET + 4)

        self.assertEqual(self._offsets(body, target=TARGET + 4), [CALLER, STUB])

    def test_a_landing_pad_reached_without_padding_is_still_absorbed(self):
        """Control: the stub runs right up to the boundary. The padding is what says the next
        address is an entry rather than the next statement, and this reads the same on either
        side of the change."""
        body = bytes.fromhex("bf01000000")  # mov edi, 1
        body += bytes.fromhex("4831c0")  # xor rax, rax
        body += bytes.fromhex("31c0") * ((TARGET - STUB - len(ENDBR64) - len(body)) // 2)  # xor eax, eax
        self.assertEqual(STUB + len(ENDBR64) + len(body), TARGET)

        self.assertEqual(self._offsets(body), [CALLER, STUB])


class SwitchCaseLandingPadTest(unittest.TestCase):
    """A CET switch lays its case bodies out on alignment boundaries, each behind padding and
    each opening with a landing pad, so the cut fires between them. It must end the block and
    nothing more: the bodies are targets of the dispatch and belong to the function that
    dispatches, whether or not one case runs into the next."""

    FUNCTION = 0x100
    TABLE = 0x1000
    FIRST_CASE = 0x200
    STRIDE = 0x10
    CASES = 4

    def _case_targets(self):
        return [self.FIRST_CASE + index * self.STRIDE for index in range(self.CASES)]

    def _image(self, cases_fall_through):
        buffer = bytearray(0x2000)
        head = bytes.fromhex("554889e5") + bytes.fromhex("83ff03")  # push rbp; mov rbp, rsp; cmp edi, 3
        lea_end = self.FUNCTION + len(head) + 2 + 7
        load = bytes.fromhex("488d35") + struct.pack("<i", self.TABLE - lea_end) + bytes.fromhex("488b04c6")
        code = head + bytes.fromhex("89f8") + load + bytes.fromhex("ffe0")  # mov eax, edi; ...; jmp rax
        buffer[self.FUNCTION : self.FUNCTION + len(code)] = code
        for index, target in enumerate(self._case_targets()):
            body = ENDBR64 + bytes.fromhex("b8") + struct.pack("<I", index)  # endbr64; mov eax, <case>
            if not (cases_fall_through and index < self.CASES - 1):
                body += bytes.fromhex("c3")  # ret
            buffer[target : target + len(body)] = body
            for pad in range(target + len(body), target + self.STRIDE):
                buffer[pad] = 0x90  # nop
        buffer[self.TABLE : self.TABLE + 8 * self.CASES] = b"".join(
            struct.pack("<Q", target) for target in self._case_targets()
        )
        return bytes(buffer)

    def _functions(self, cases_fall_through):
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = False
        report = Disassembler(config).disassembleBuffer(self._image(cases_fall_through), 0, bitness=64)
        self.assertEqual(report.status, "ok")
        return sorted(report.getFunctions(), key=lambda function: function.offset)

    def test_the_switch_stays_one_function_when_each_case_returns(self):
        functions = self._functions(cases_fall_through=False)

        self.assertEqual([function.offset for function in functions], [self.FUNCTION])
        blocks = {block.offset for block in functions[0].getBlocks()}
        self.assertTrue(set(self._case_targets()) <= blocks)

    def test_the_switch_stays_one_function_when_a_case_runs_into_the_next(self):
        """The shape the cut could get wrong: arriving at the next landing pad by falling
        through padding is exactly what it looks for, and it does fire here. It ends the
        block; the body is still a target of the dispatch, so it stays in the function."""
        functions = self._functions(cases_fall_through=True)

        self.assertEqual([function.offset for function in functions], [self.FUNCTION])
        blocks = {block.offset for block in functions[0].getBlocks()}
        self.assertTrue(set(self._case_targets()) <= blocks)


class ComputedGotoFallthroughTest(unittest.TestCase):
    """A computed-goto interpreter built with CET and 16-byte label alignment, taken verbatim
    from gcc 13.3 -O2 output. Its labels are landing pads on alignment boundaries behind
    padding, and one label falls through into the next - the exact shape the cut looks for,
    with a real edge across it. Ending the block must not delete that edge."""

    BASE = 0x400000
    FUNCTION = 0x401130
    TABLE = 0x403E20
    # interp(): endbr64; movzx eax,[rdi]; lea r8,[rip+..]; ...; jmp rcx; then four aligned
    # landing-pad labels, of which the first falls through into the second
    CODE = bytes.fromhex(
        "f30f1efa0fb6074c8d05e22c000031d283e003498b0cc0b801000000ffe16690"
        "f30f1efa83c201660f1f840000000000f30f1efa83f20339c67e350f1f440000"
        "89c183c0010fb60c0f83e103498b0cc8ffe166662e0f1f8400000000000f1f00"
        "f30f1efa8d149239f07cd50f1f44000089d0c366662e0f1f8400000000006690"
        "f30f1efa83ea0739c67fb589d0c3"
    )
    LABELS = (0x401150, 0x401160, 0x401190, 0x4011B0)

    def _function(self):
        buffer = bytearray(0x4000)
        buffer[self.FUNCTION - self.BASE : self.FUNCTION - self.BASE + len(self.CODE)] = self.CODE
        buffer[self.TABLE - self.BASE : self.TABLE - self.BASE + 32] = b"".join(
            struct.pack("<Q", label) for label in self.LABELS
        )
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = False
        report = Disassembler(config).disassembleBuffer(bytes(buffer), self.BASE, bitness=64)
        self.assertEqual(report.status, "ok")
        return next(f for f in report.getFunctions() if f.offset == self.FUNCTION)

    def test_the_interpreter_is_one_function_holding_every_label(self):
        function = self._function()

        self.assertTrue(set(self.LABELS) <= {block.offset for block in function.getBlocks()})

    def test_the_label_that_falls_through_keeps_its_successor(self):
        """The first label runs into the second, so the block ended at the padding has to keep
        that edge. This image is not enough on its own to pin the reference the cut used to
        remove - the same assertion holds with it removed, because the second label is a
        dispatch target too - but on the binary this code was taken from, where the analysis
        reaches the labels in a different order, removing it left this block with no successor
        at all."""
        function = self._function()

        self.assertEqual(function.blockrefs.get(self.LABELS[0]), [self.LABELS[1]])
