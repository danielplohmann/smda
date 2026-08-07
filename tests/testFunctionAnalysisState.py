import unittest

from smda.common.FunctionAnalysisState import FunctionAnalysisState


class _BareState(FunctionAnalysisState):
    """Disassembly-free subclass so unit tests need no DisassemblyResult."""

    def __init__(self, start_addr):
        super().__init__(start_addr, None)
        self.CALL_MNEMONICS = frozenset(["call"])
        self.END_MNEMONICS = frozenset(["ret", "jmp"])


class FunctionAnalysisStateTestSuite(unittest.TestCase):
    def test_removeCodeRef_purges_only_real_jump_edges(self):
        # A conditional branch targets 0x106 (a real block start) while a later
        # call falls through into the same address. The fall-through purge must
        # not delete the address from jump_targets, or getBlocks() loses the block.
        state = _BareState(0x100)
        state.addInstruction(0x100, 2, "cmp", "", b"\x00\x00")
        state.addInstruction(0x102, 2, "jne", "0x106", b"\x00\x00")
        state.addInstruction(0x104, 2, "call", "0x200", b"\x00\x00")
        state.addInstruction(0x106, 2, "ret", "", b"\x00\x00")
        state.addCodeRef(0x102, 0x106, by_jump=True)

        # fall-through edge for the call (booked by addInstruction, by_jump=False)
        self.assertIn((0x104, 0x106), state.code_refs)
        self.assertIn(0x106, state.jump_targets)

        state.removeCodeRef(0x104, 0x106)

        self.assertNotIn((0x104, 0x106), state.code_refs)
        self.assertIn(0x106, state.jump_targets)
        starts = {block[0][0] for block in state.getBlocks()}
        self.assertIn(0x106, starts)

    def test_remove_real_jump_edge_releases_target_when_alone(self):
        state = _BareState(0x100)
        state.addInstruction(0x100, 2, "cmp", "", b"\x00\x00")
        state.addInstruction(0x106, 2, "ret", "", b"\x00\x00")
        state.addCodeRef(0x100, 0x106, by_jump=True)
        self.assertIn(0x106, state.jump_targets)
        state.removeCodeRef(0x100, 0x106)
        self.assertNotIn(0x106, state.jump_targets)
        starts = {block[0][0] for block in state.getBlocks()}
        self.assertNotIn(0x106, starts)


if __name__ == "__main__":
    unittest.main()
