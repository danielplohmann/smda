import struct
import unittest

from smda.Disassembler import Disassembler
from smda.intel.definitions import stripFlatSegmentOverride
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
TEXT_RVA = 0x1000
TABLE_RVA = 0x2000
IMAGE_SIZE = 0x3000
CASES = 6


def _config():
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    return config


def _notrackSwitchImage(segment_prefix=b"\x3e"):
    """A 64-bit image whose one function dispatches a bounded switch through a jump table.

    The shape is what gcc emits for a dense switch in a non-PIE x86-64 binary built with CET
    branch protection: the bound is compared against the memory cell the index is loaded from,
    and the indirect jump carries the 0x3e "notrack" prefix, which capstone renders as a ds:
    segment override on the memory operand.
    """
    image = bytearray(IMAGE_SIZE)
    body = bytearray()
    body += b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
    body += b"\x80\x3f" + bytes([CASES - 1])  # cmp byte ptr [rdi], CASES-1
    ja_at = len(body)
    body += b"\x0f\x87" + struct.pack("<i", 0)  # ja default (patched once its offset is known)
    body += b"\x0f\xb6\x07"  # movzx eax, byte ptr [rdi]
    dispatch_at = len(body)
    body += segment_prefix + b"\xff\x24\xc5" + struct.pack("<I", BASE + TABLE_RVA)
    case_offsets = []
    for index in range(CASES):
        case_offsets.append(len(body))
        body += b"\xb8" + struct.pack("<I", index) + b"\x5d\xc3"  # mov eax, i ; pop rbp ; ret
    default_offset = len(body)
    body += b"\x31\xc0\x5d\xc3"  # xor eax, eax ; pop rbp ; ret
    struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))

    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    table = b"".join(struct.pack("<Q", BASE + TEXT_RVA + offset) for offset in case_offsets)
    image[TABLE_RVA : TABLE_RVA + len(table)] = table
    return bytes(image), BASE + TEXT_RVA + dispatch_at, [BASE + TEXT_RVA + o for o in case_offsets]


class FlatSegmentOverrideTestSuite(unittest.TestCase):
    """CS/DS/ES/SS have a zero base, so their override is noise on an image address;
    FS/GS carry a thread-local base and must keep the prefix that marks them unresolvable."""

    def test_zero_base_overrides_are_removed(self):
        for operand, expected in (
            ("qword ptr ds:[rax*8 + 0x402018]", "qword ptr [rax*8 + 0x402018]"),
            ("dword ptr cs:[0x8049000]", "dword ptr [0x8049000]"),
            ("dword ptr es:[edi]", "dword ptr [edi]"),
            ("qword ptr ss:[rsp + 8]", "qword ptr [rsp + 8]"),
        ):
            with self.subTest(operand=operand):
                self.assertEqual(stripFlatSegmentOverride(operand), expected)

    def test_thread_local_overrides_are_kept(self):
        for operand in ("qword ptr fs:[0x30]", "qword ptr gs:[0x60]"):
            with self.subTest(operand=operand):
                self.assertEqual(stripFlatSegmentOverride(operand), operand)

    def test_operands_without_an_override_are_unchanged(self):
        for operand in ("qword ptr [rip + 0x2f31]", "rax", "0x33:0x401000", ""):
            with self.subTest(operand=operand):
                self.assertEqual(stripFlatSegmentOverride(operand), operand)


class NotrackDispatchRecoveryTestSuite(unittest.TestCase):
    """A jump whose memory operand carries a segment override used to be classified as a far
    jump -- ":" appears in both spellings -- so the dispatch was dropped, its case bodies were
    never linked, and the gap scan promoted each of them to a function of its own."""

    def test_case_bodies_stay_inside_the_dispatching_function(self):
        image, dispatch, cases = _notrackSwitchImage()
        report = Disassembler(config=_config()).disassembleBuffer(image, BASE, bitness=64)

        self.assertEqual(report.status, "ok")
        functions = {function.offset for function in report.getFunctions()}
        self.assertEqual(functions, {BASE + TEXT_RVA})
        blocks = {
            instruction.offset
            for function in report.getFunctions()
            for block in function.getBlocks()
            for instruction in block.getInstructions()
        }
        for case in cases:
            self.assertIn(case, blocks)
        self.assertIn(dispatch, blocks)

    def test_unprefixed_dispatch_recovers_identically(self):
        """Positive control: the same switch without the notrack prefix always worked, so the
        assertion above cannot be passing because the image is degenerate."""
        image, _dispatch, cases = _notrackSwitchImage(segment_prefix=b"\x90")
        report = Disassembler(config=_config()).disassembleBuffer(image, BASE, bitness=64)

        self.assertEqual(report.status, "ok")
        self.assertEqual({function.offset for function in report.getFunctions()}, {BASE + TEXT_RVA})
        blocks = {
            instruction.offset
            for function in report.getFunctions()
            for block in function.getBlocks()
            for instruction in block.getInstructions()
        }
        for case in cases:
            self.assertIn(case, blocks)


def _tableLoadSwitchImage(segment_prefix=b"\x3e"):
    """A 32-bit switch whose table base is loaded through a segment-qualified operand.

    The dispatch here is a plain `jmp eax`; what carries the override is the load of the
    table entry, which the jump-table analyzer finds by matching an anchored pattern against
    the instructions it walks back over. Those instructions are stored as capstone rendered
    them, so a prefix on the load hides the table just as one on the branch hid the dispatch.
    """
    image = bytearray(IMAGE_SIZE)
    body = bytearray(b"\x55\x89\xe5")  # push ebp ; mov ebp, esp
    body += b"\x80\x3f" + bytes([CASES - 1])  # cmp byte ptr [edi], CASES-1
    ja_at = len(body)
    body += b"\x0f\x87" + struct.pack("<i", 0)  # ja default (patched below)
    body += b"\x0f\xb6\x07"  # movzx eax, byte ptr [edi]
    body += segment_prefix + b"\x8b\x04\x85" + struct.pack("<I", BASE + TABLE_RVA)
    body += b"\xff\xe0"  # jmp eax
    case_offsets = []
    for index in range(CASES):
        case_offsets.append(len(body))
        body += b"\xb8" + struct.pack("<I", index) + b"\x5d\xc3"  # mov eax, i ; pop ebp ; ret
    default_offset = len(body)
    body += b"\x31\xc0\x5d\xc3"  # xor eax, eax ; pop ebp ; ret
    struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))

    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    table = b"".join(struct.pack("<I", BASE + TEXT_RVA + offset) for offset in case_offsets)
    image[TABLE_RVA : TABLE_RVA + len(table)] = table
    return bytes(image), [BASE + TEXT_RVA + offset for offset in case_offsets]


class SegmentQualifiedTableLoadTestSuite(unittest.TestCase):
    """Seeing the dispatch is not enough on its own: the same override defeats every anchored
    pattern the jump-table analyzer matches against the instructions it walks back over."""

    def _functions(self, segment_prefix):
        image, cases = _tableLoadSwitchImage(segment_prefix)
        report = Disassembler(config=_config()).disassembleBuffer(image, BASE, bitness=32)
        self.assertEqual(report.status, "ok")
        return {function.offset for function in report.getFunctions()}, cases

    def test_a_segment_qualified_table_load_still_finds_the_table(self):
        functions, cases = self._functions(b"\x3e")

        self.assertEqual(functions, {BASE + TEXT_RVA})
        self.assertEqual(functions & set(cases), set())

    def test_an_unprefixed_table_load_recovers_identically(self):
        """Positive control: the same switch with no override, which always worked - without
        it a fixture that recovered nothing would satisfy the assertion above."""
        functions, cases = self._functions(b"")

        self.assertEqual(functions, {BASE + TEXT_RVA})
        self.assertEqual(functions & set(cases), set())


class SegmentQualifiedBranchClassificationTestSuite(unittest.TestCase):
    def _analyze(self, code, bitness=64):
        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        report = Disassembler(config=_config()).disassembleBuffer(bytes(image), BASE, bitness=bitness)
        function = next((f for f in report.getFunctions() if f.offset == BASE + TEXT_RVA), None)
        self.assertIsNotNone(function, "the fixture must recover a function at the code start")
        return report, function

    def test_thread_local_indirect_jump_books_no_target(self):
        # push rbp ; mov rbp, rsp ; jmp qword ptr gs:[0x60] -- the base is not in the image,
        # so no code reference can be booked for it
        code = b"\x55\x48\x89\xe5\x65\xff\x24\x25\x60\x00\x00\x00"
        _report, function = self._analyze(code)

        self.assertEqual([xref.to_instruction.offset for xref in function.getCodeOutrefs()], [])

    def test_far_jump_books_no_target(self):
        """Positive control for the same arm: a real far pointer (seg:offset, no memory
        operand) must still be dropped, which is what the colon test was there for."""
        # push rbp ; mov rbp, rsp ; ljmp 0x33:0x401000
        code = b"\x55\x48\x89\xe5\xff\x2c\x25\x00\x10\x40\x00"
        _report, function = self._analyze(code)

        self.assertEqual([xref.to_instruction.offset for xref in function.getCodeOutrefs()], [])

    def _callThroughSlotImage(self, segment_prefix):
        """push rbp ; mov rbp, rsp ; <prefix> call qword ptr [rip + disp] ; ret

        The pointer slot sits at a displacement of at least 0x10 so capstone prints it
        0x-prefixed: it renders a smaller one as a bare decimal, which the shared operand
        reader deliberately does not match.
        """
        image = bytearray(IMAGE_SIZE)
        slot_rva = TEXT_RVA + 0x40
        callee_rva = slot_rva + 8
        prologue = b"\x55\x48\x89\xe5"
        call_rva = TEXT_RVA + len(prologue)
        call_size = len(segment_prefix) + 6
        displacement = (TEXT_RVA + 0x40) - (call_rva + call_size)
        code = bytearray(prologue)
        code += segment_prefix + b"\xff\x15" + struct.pack("<i", displacement)
        code += b"\xc3"
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        image[slot_rva : slot_rva + 8] = struct.pack("<Q", BASE + callee_rva)
        callee = b"\x55\x48\x89\xe5\x5d\xc3"
        image[callee_rva : callee_rva + len(callee)] = callee
        return bytes(image), BASE + callee_rva

    def _bookedCallTargets(self, segment_prefix):
        image, callee = self._callThroughSlotImage(segment_prefix)
        report = Disassembler(config=_config()).disassembleBuffer(image, BASE, bitness=64)
        self.assertEqual(report.status, "ok")
        caller = next(f for f in report.getFunctions() if f.offset == BASE + TEXT_RVA)
        return {xref.to_instruction.offset for xref in caller.getCodeOutrefs()}, callee

    def _outrefsOf(self, image):
        """Raw outref targets, not getCodeOutrefs(): a near indirect jump books the pointer
        slot, which is data and therefore has no instruction to resolve to."""
        report = Disassembler(config=_config()).disassembleBuffer(image, BASE, bitness=32)
        self.assertEqual(report.status, "ok")
        function = next((f for f in report.getFunctions() if f.offset == BASE + TEXT_RVA), None)
        self.assertIsNotNone(function, "the fixture must recover a function at the code start")
        return {target for targets in (function.outrefs or {}).values() for target in targets}

    def _farIndirectTargets(self, segment_prefix):
        """<prefix> ff 2d <disp32> -- a far indirect jump, which loads a seg:offset pair.

        capstone renders it "ptr [0x...]" against a near indirect jump's "dword ptr [0x...]",
        and the width is the only thing telling them apart once a zero-base override is
        normalized away: both spell a colon while the prefix is still there.
        """
        image = bytearray(IMAGE_SIZE)
        slot_rva = TEXT_RVA + 0x40
        code = bytearray(b"\x55\x89\xe5")  # push ebp ; mov ebp, esp
        code += segment_prefix + b"\xff\x2d" + struct.pack("<I", BASE + slot_rva)
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        image[slot_rva : slot_rva + 4] = struct.pack("<I", BASE + TEXT_RVA + 0x20)
        callee = b"\x55\x89\xe5\x5d\xc3"
        image[TEXT_RVA + 0x20 : TEXT_RVA + 0x20 + len(callee)] = callee
        return self._outrefsOf(bytes(image))

    def test_a_far_indirect_jump_books_no_target(self):
        for segment_prefix, label in ((b"", "none"), (b"\x2e", "cs"), (b"\x3e", "ds")):
            with self.subTest(prefix=label):
                self.assertEqual(self._farIndirectTargets(segment_prefix), set())

    def test_a_near_indirect_jump_through_the_same_slot_is_booked(self):
        """Positive control: the same encoding one modrm bit away (ff 25, near) does reach an
        address in this image, so the assertion above is about the far form and not about the
        fixture being unreachable."""
        image = bytearray(IMAGE_SIZE)
        slot_rva = TEXT_RVA + 0x40
        code = bytearray(b"\x55\x89\xe5")
        code += b"\x3e\xff\x25" + struct.pack("<I", BASE + slot_rva)
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        image[slot_rva : slot_rva + 4] = struct.pack("<I", BASE + TEXT_RVA + 0x20)
        callee = b"\x55\x89\xe5\x5d\xc3"
        image[TEXT_RVA + 0x20 : TEXT_RVA + 0x20 + len(callee)] = callee

        self.assertEqual(self._outrefsOf(bytes(image)), {BASE + slot_rva})

    def test_segment_qualified_indirect_call_is_booked(self):
        targets, callee = self._bookedCallTargets(b"\x3e")

        self.assertIn(callee, targets)

    def test_unprefixed_indirect_call_is_booked(self):
        """Positive control: the same call without the notrack prefix always resolved."""
        targets, callee = self._bookedCallTargets(b"\x90")

        self.assertIn(callee, targets)


if __name__ == "__main__":
    unittest.main()
