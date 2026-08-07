import struct
import unittest

from dncil.cil.body.reader import read_method_body_from_bytes

from smda.cil.CilDisassembler import CilDisassembler
from smda.common.BinaryInfo import BinaryInfo
from smda.SmdaConfig import SmdaConfig


def _build_try_catch_body():
    """try { nop; leave.s L } catch { pop; nop; leave.s L } L: ret

    Real CIL: a fat method header with a small exception section carrying one catch
    clause, parsed by dncil exactly as it would be from a .NET assembly.
    """
    code = bytes(
        [
            0x00,  # nop
            0xDE,
            0x04,  # leave.s -> ret
            0x26,  # pop        (catch handler entry)
            0x00,  # nop
            0xDE,
            0x00,  # leave.s -> ret
            0x2A,  # ret
        ]
    )
    # fat header (3 dwords), FatFormat | MoreSects
    body = struct.pack("<HHII", (3 << 12) | 0x03 | 0x08, 8, len(code), 0) + code
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    body += struct.pack("<BBH", 0x01, 4 + 12, 0)  # small EH section, one clause
    # clause: flags=0 (catch), try_start=0, try_len=3, handler_start=3, handler_len=4
    body += struct.pack("<HHBHBI", 0, 0, 3, 3, 4, 0x01000000)
    return read_method_body_from_bytes(body)


def _build_throw_try_catch_body():
    """try { nop; throw } catch { pop; nop; leave.s L } L: ret

    A try block whose last instruction is `throw`: the throw terminates control
    flow but is followed by the handler entry, so block reconstruction must end
    the try block at the throw instead of falling through into the handler.
    """
    code = bytes(
        [
            0x00,  # nop
            0x7A,  # throw
            0x26,  # pop        (catch handler entry)
            0x00,  # nop
            0xDE,
            0x00,  # leave.s -> ret
            0x2A,  # ret
        ]
    )
    body = struct.pack("<HHII", (3 << 12) | 0x03 | 0x08, 8, len(code), 0) + code
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    body += struct.pack("<BBH", 0x01, 4 + 12, 0)  # small EH section, one clause
    body += struct.pack("<HHBHBI", 0, 0, 2, 2, 4, 0x01000000)
    return read_method_body_from_bytes(body)


def _build_filter_body():
    """try { nop; leave.s L } filter { ldc.i4.1; endfilter } catch { pop; leave.s L } L: ret

    A filter clause (C# `catch ... when (...)`) is the one ordinary layout where a
    flow-terminating instruction is immediately followed by a handler entry that no
    branch points at, so only END_INS can end the filter block there.
    """
    code = bytes(
        [
            0x00,  # nop
            0xDE,
            0x06,  # leave.s -> ret
            0x17,  # ldc.i4.1   (filter entry)
            0xFE,
            0x11,  # endfilter
            0x26,  # pop        (catch handler entry)
            0xDE,
            0x00,  # leave.s -> ret
            0x2A,  # ret
        ]
    )
    body = struct.pack("<HHII", (3 << 12) | 0x03 | 0x08, 8, len(code), 0) + code
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    body += struct.pack("<BBH", 0x01, 4 + 12, 0)  # small EH section, one clause
    # clause: flags=1 (filter), try_start=0, try_len=3, handler_start=6, handler_len=3, filter_start=3
    body += struct.pack("<HHBHBI", 1, 0, 3, 6, 3, 3)
    return read_method_body_from_bytes(body)


class CilExceptionHandlingTestSuite(unittest.TestCase):
    """Two defects that had to be fixed together (audit finding 5).

    5a: reachability was cleared only for ret/endfinally/endfilter, jmp and throw/rethrow,
    so an unconditional br/leave still emitted a fall-through edge to the next instruction
    - and because addCodeRef had just set is_jmp for the branch itself, that bogus edge was
    also registered as a jump target.

    5b: method_body.exception_handlers was never read, so a catch/finally/filter entry -
    which no intra-method branch points at - became a block ONLY via 5a's accidental edge.

    Fixing 5a alone would therefore have deleted every handler body from the CFG.
    """

    def setUp(self):
        self.method_body = _build_try_catch_body()
        disassembler = CilDisassembler(SmdaConfig())
        binary_info = BinaryInfo(b"\x00" * 0x100)
        binary_info.base_addr = 0
        disassembler.disassembly.binary_info = binary_info
        self.state = disassembler.analyzeFunction(None, self.method_body.instructions[0].offset, self.method_body)
        self.code_start = self.method_body.instructions[0].offset

    def test_unconditional_leave_emits_no_fall_through_edge(self):
        leave_addr = self.code_start + 1
        handler_addr = self.code_start + 3
        ret_addr = self.code_start + 7

        self.assertIn((leave_addr, ret_addr), self.state.code_refs)
        self.assertNotIn((leave_addr, handler_addr), self.state.code_refs)

    def test_exception_handler_body_is_still_recovered(self):
        # the handler block must survive on its own evidence, not via the false edge
        blocks = [[instruction[0] for instruction in block] for block in self.state.getBlocks()]
        handler_block = [self.code_start + 3, self.code_start + 4, self.code_start + 5]

        self.assertIn(handler_block, blocks)

    def test_handler_and_try_entries_are_seeded_as_block_starts(self):
        self.assertIn(self.code_start + 0, self.state.jump_targets)  # try_start
        self.assertIn(self.code_start + 3, self.state.jump_targets)  # handler_start

    def test_all_instructions_remain_covered_by_blocks(self):
        covered = {instruction[0] for block in self.state.getBlocks() for instruction in block}
        expected = {instruction.offset for instruction in self.method_body.instructions}

        self.assertEqual(covered, expected)

    def test_throwing_try_does_not_double_count_handler_instructions(self):
        # A try ending in `throw` used to fall through into the (separately seeded)
        # handler block, so the same instructions landed in two blocks, inflating
        # num_blocks/num_instructions and double-hashing them for PicHash/OpcHash.
        method_body = _build_throw_try_catch_body()
        disassembler = CilDisassembler(SmdaConfig())
        binary_info = BinaryInfo(b"\x00" * 0x100)
        binary_info.base_addr = 0
        disassembler.disassembly.binary_info = binary_info
        state = disassembler.analyzeFunction(None, method_body.instructions[0].offset, method_body)

        blocks = state.getBlocks()
        instruction_blocks = {instruction[0] for block in blocks for instruction in block}
        expected = {instruction.offset for instruction in method_body.instructions}
        self.assertEqual(len(blocks), 3)
        self.assertEqual(instruction_blocks, expected)
        self.assertEqual(sum(len(block) for block in blocks), len(expected))

    def test_filter_block_ends_at_endfilter(self):
        # Same class as the `throw` case: `endfilter` terminates control flow but was
        # missing from END_INS, so the filter block ran on into the catch handler that
        # follows it - and the handler, being separately seeded, opened its own block too.
        method_body = _build_filter_body()
        disassembler = CilDisassembler(SmdaConfig())
        binary_info = BinaryInfo(b"\x00" * 0x100)
        binary_info.base_addr = 0
        disassembler.disassembly.binary_info = binary_info
        state = disassembler.analyzeFunction(None, method_body.instructions[0].offset, method_body)

        blocks = state.getBlocks()
        instruction_blocks = {instruction[0] for block in blocks for instruction in block}
        expected = {instruction.offset for instruction in method_body.instructions}
        self.assertEqual(len(blocks), 4)
        self.assertEqual(instruction_blocks, expected)
        self.assertEqual(sum(len(block) for block in blocks), len(expected))


if __name__ == "__main__":
    unittest.main()
