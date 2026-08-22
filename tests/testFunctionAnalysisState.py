import unittest

from smda.cil.FunctionAnalysisState import FunctionAnalysisState as CilFunctionAnalysisState
from smda.common.BinaryInfo import BinaryInfo
from smda.common.FunctionAnalysisState import FunctionAnalysisState
from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState
from smda.DisassemblyResult import DisassemblyResult


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


class CilFunctionAnalysisStateTestSuite(unittest.TestCase):
    """The CIL state carries its own copy of the edge book-keeping."""

    def test_removeCodeRef_purges_only_real_jump_edges(self):
        state = CilFunctionAnalysisState(0x100, 0x100, None)
        state.addCodeRef(0x102, 0x106, by_jump=True)
        state.addCodeRef(0x104, 0x106)
        self.assertIn(0x106, state.jump_targets)

        state.removeCodeRef(0x104, 0x106)

        self.assertNotIn((0x104, 0x106), state.code_refs)
        self.assertIn(0x106, state.jump_targets)

    def test_remove_real_jump_edge_releases_target_when_alone(self):
        state = CilFunctionAnalysisState(0x100, 0x100, None)
        state.addCodeRef(0x100, 0x106, by_jump=True)

        state.removeCodeRef(0x100, 0x106)

        self.assertNotIn(0x106, state.jump_targets)


class DalvikFunctionAnalysisStateTestSuite(unittest.TestCase):
    """The Dalvik state carries its own copy of the edge book-keeping."""

    def test_removeCodeRef_purges_only_real_jump_edges(self):
        state = DalvikFunctionAnalysisState(0x100, None)
        state.addCodeRef(0x102, 0x106, by_jump=True)
        state.addCodeRef(0x104, 0x106)
        self.assertIn(0x106, state.jump_targets)

        state.removeCodeRef(0x104, 0x106)

        self.assertNotIn((0x104, 0x106), state.code_refs)
        self.assertIn(0x106, state.jump_targets)

    def test_remove_real_jump_edge_releases_target_when_alone(self):
        state = DalvikFunctionAnalysisState(0x100, None)
        state.addCodeRef(0x100, 0x106, by_jump=True)

        state.removeCodeRef(0x100, 0x106)

        self.assertNotIn(0x106, state.jump_targets)


class _RecordingDisassembly:
    def __init__(self):
        self.function_borders = {}
        self.function_symbols = {}
        self.instructions = {}
        self.code_map = {}
        self.ins2fn = {}
        self.data_map = set()
        self.functions = {}
        self.recursive_functions = set()
        self.leaf_functions = set()
        self.thunk_functions = set()
        self.code_refs_from = {}
        self.code_refs_to = {}

    def addCodeRefs(self, addr_from, addr_to):
        pass

    def removeCodeRefs(self, addr_from, addr_to):
        pass

    def addDataRefs(self, addr_from, addr_to):
        pass

    def removeDataRefs(self, addr_from, addr_to):
        pass


class BlockQueueTestSuite(unittest.TestCase):
    def test_a_block_is_queued_once_however_often_it_is_referenced(self):
        state = _BareState(0x100)
        state.addBlockToQueue(0x200)
        state.addBlockToQueue(0x200)
        state.addBlockToQueue(0x300)

        self.assertEqual(state.block_queue, [0x100, 0x200, 0x300])

        state.chooseNextBlock()
        state.addBlockToQueue(0x300)

        self.assertEqual(state.block_queue, [0x100, 0x200])
        self.assertTrue(state.hasUnprocessedBlocks())

    def test_jump_latch_does_not_survive_a_block_that_never_booked_it(self):
        # a branch books its jump ref, then the instruction is dropped (already claimed
        # elsewhere) so addInstruction never consumes the latch; the next block's first
        # fall-through edge must not be recorded as a jump target
        state = _BareState(0x100)
        state.addCodeRef(0x100, 0x300, by_jump=True)
        self.assertTrue(state.is_jmp)

        state.endBlock()
        self.assertFalse(state.is_jmp)

        state.addBlockToQueue(0x200)
        state.addCodeRef(0x400, 0x500, by_jump=True)
        state.chooseNextBlock()
        self.assertFalse(state.is_jmp)

        state.addInstruction(0x200, 2, "mov", "", b"\x00\x00")
        self.assertNotIn(0x202, state.jump_targets)


class RevertAnalysisTestSuite(unittest.TestCase):
    def test_revert_undoes_every_start_addr_keyed_result(self):
        disassembly = _RecordingDisassembly()
        state = FunctionAnalysisState(0x100, disassembly)
        state.CALL_MNEMONICS = frozenset(["call"])
        state.END_MNEMONICS = frozenset(["ret"])
        state.label = "some_function"
        state.addInstruction(0x100, 2, "ret", "", b"\xc3\x90")
        state.endBlock()
        state.is_recursive = True
        state.is_thunk_call = True
        state._finalizeRegularAnalysis()

        self.assertEqual(disassembly.function_symbols[0x100], "some_function")
        self.assertEqual(disassembly.leaf_functions, {0x100})
        self.assertEqual(disassembly.recursive_functions, {0x100})
        self.assertEqual(disassembly.thunk_functions, {0x100})

        state.revertAnalysis()

        self.assertNotIn(0x100, disassembly.functions)
        self.assertNotIn(0x100, disassembly.function_symbols)
        self.assertEqual(disassembly.leaf_functions, set())
        self.assertEqual(disassembly.recursive_functions, set())
        self.assertEqual(disassembly.thunk_functions, set())


class DalvikRevertAnalysisTestSuite(unittest.TestCase):
    def test_revert_undoes_every_start_addr_keyed_result(self):
        disassembly = _RecordingDisassembly()
        disassembly.function_metadata = {}
        state = DalvikFunctionAnalysisState(0x100, disassembly)
        state.label = "Lfoo;->bar()V"
        state.addInstruction(0x100, 2, "return-void", "", b"\x0e\x00")
        state.endBlock()
        state.is_recursive = True
        state.is_thunk_call = True
        state._finalizeRegularAnalysis()

        self.assertEqual(disassembly.function_symbols[0x100], "Lfoo;->bar()V")
        self.assertIn(0x100, disassembly.function_metadata)
        self.assertEqual(disassembly.leaf_functions, {0x100})

        state.revertAnalysis()

        self.assertNotIn(0x100, disassembly.functions)
        self.assertNotIn(0x100, disassembly.function_symbols)
        self.assertNotIn(0x100, disassembly.function_metadata)
        self.assertEqual(disassembly.leaf_functions, set())
        self.assertEqual(disassembly.recursive_functions, set())
        self.assertEqual(disassembly.thunk_functions, set())


class FunctionBorderTestSuite(unittest.TestCase):
    """Instructions reach finalize in analysis order, which is not address order."""

    def test_cil_borders_span_the_lowest_and_highest_instruction(self):
        disassembly = _RecordingDisassembly()
        state = CilFunctionAnalysisState(0x200, 0x200, disassembly)
        state.addInstruction(0x200, 1, "nop", "", b"\x00")
        state.addInstruction(0x100, 2, "nop", "", b"\x00\x00")
        state.addInstruction(0x300, 4, "ret", "", b"\x2a")

        state.finalizeAnalysis()

        self.assertEqual((0x100, 0x304), disassembly.function_borders[0x200])

    def test_dalvik_borders_span_the_lowest_and_highest_instruction(self):
        disassembly = _RecordingDisassembly()
        disassembly.function_metadata = {}
        state = DalvikFunctionAnalysisState(0x200, disassembly)
        state.label = "Lfoo;->bar()V"
        state.addInstruction(0x200, 2, "nop", "", b"\x00\x00")
        state.addInstruction(0x100, 2, "nop", "", b"\x00\x00")
        state.addInstruction(0x300, 2, "return-void", "", b"\x0e\x00")
        state.endBlock()

        state._finalizeRegularAnalysis()

        self.assertEqual((0x100, 0x302), disassembly.function_borders[0x200])


class CilBlockCollisionTestSuite(unittest.TestCase):
    def test_fall_through_into_a_colliding_address_drops_the_code_ref(self):
        state = CilFunctionAnalysisState(0x100, 0x100, None)
        state.addInstruction(0x100, 2, "br", "", b"\x00\x00")
        state.addInstruction(0x110, 1, "ret", "", b"\x00")
        state.colliding_addresses.add(0x102)

        self.assertIn((0x100, 0x102), state.code_refs)

        blocks = state.getBlocks()

        self.assertNotIn((0x100, 0x102), state.code_refs)
        self.assertEqual([[0x100]], [[ins[0] for ins in block] for block in blocks])

    def test_a_reference_to_the_next_instruction_alone_keeps_the_block_open(self):
        state = CilFunctionAnalysisState(0x100, 0x100, None)
        state.addInstruction(0x100, 2, "br", "", b"\x00\x00")
        state.addInstruction(0x102, 1, "ret", "", b"\x00")

        blocks = state.getBlocks()

        self.assertEqual([[0x100, 0x102]], [[ins[0] for ins in block] for block in blocks])


if __name__ == "__main__":
    unittest.main()


class FunctionEntryIntegrityTestSuite(unittest.TestCase):
    """A recorded function's entry must be the start of one of its own blocks.

    analyzeFunction declines to book an instruction whose address is already claimed as data,
    so a candidate that lands inside a datum can finish analysis with blocks decoded from a
    branch target and nothing at its own entry. Recording that produces a function whose
    offset is not in any of its blocks, and whose borders and ins2fn describe a different
    address range than the offset it is filed under.
    """

    def _state(self, start_addr):
        disassembly = DisassemblyResult()
        disassembly.binary_info = BinaryInfo(b"\x00" * 0x200)
        state = FunctionAnalysisState(start_addr, disassembly)
        state.CALL_MNEMONICS = frozenset(["call"])
        state.END_MNEMONICS = frozenset(["ret", "jmp"])
        state.label = ""
        return state, disassembly

    def test_a_function_whose_entry_produced_no_instruction_is_declined(self):
        state, disassembly = self._state(0x100)
        state.addInstruction(0x80, 1, "ret", "", b"\xc3")
        state.endBlock()

        self.assertFalse(state.finalizeAnalysis())
        self.assertNotIn(0x100, disassembly.functions)
        self.assertNotIn(0x100, disassembly.function_borders)

    def test_a_function_whose_entry_produced_an_instruction_is_kept(self):
        """Control for the rule above: the guard must decline only the malformed shape."""
        state, disassembly = self._state(0x100)
        state.addInstruction(0x100, 1, "ret", "", b"\xc3")
        state.endBlock()

        self.assertTrue(state.finalizeAnalysis())
        self.assertIn(0x100, disassembly.functions)
        self.assertEqual({block[0][0] for block in disassembly.functions[0x100]}, {0x100})

    def test_a_block_below_the_entry_is_kept_when_the_entry_itself_decoded(self):
        """A backward branch into a block that starts below the entry is ordinary - a shared
        tail or thunk - and must not be confused with the malformed shape above."""
        state, disassembly = self._state(0x100)
        state.addInstruction(0x100, 2, "jmp", "0x80", b"\xeb\x7e")
        state.endBlock()
        state.addInstruction(0x80, 1, "ret", "", b"\xc3")
        state.endBlock()

        self.assertTrue(state.finalizeAnalysis())
        self.assertIn(0x100, disassembly.functions)
        self.assertIn(0x100, {block[0][0] for block in disassembly.functions[0x100]})
