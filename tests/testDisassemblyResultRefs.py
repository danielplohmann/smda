import copy
import pickle
import unittest

from smda.common.FunctionAnalysisState import FunctionAnalysisState
from smda.DisassemblyResult import AddressRefs, DisassemblyResult


class TestAddressRefs(unittest.TestCase):
    def test_a_lone_reference_is_stored_bare_and_read_as_a_set(self):
        refs = AddressRefs()
        refs.add(0x100, 0x104)

        self.assertEqual(dict.get(refs, 0x100), 0x104)
        self.assertEqual(refs[0x100], {0x104})
        self.assertEqual(refs.get(0x100), {0x104})
        self.assertEqual(list(refs.items()), [(0x100, {0x104})])
        self.assertEqual(list(refs.values()), [{0x104}])
        self.assertEqual(refs.get(0x200, ()), ())

    def test_a_second_reference_promotes_the_entry_to_a_set(self):
        refs = AddressRefs()
        refs.add(0x100, 0x104)
        refs.add(0x100, 0x104)
        self.assertEqual(dict.get(refs, 0x100), 0x104)
        refs.add(0x100, 0x200)

        self.assertEqual(dict.get(refs, 0x100), {0x104, 0x200})
        self.assertEqual(refs, {0x100: {0x104, 0x200}})

    def test_discard_leaves_an_empty_set_behind_like_the_set_based_maps_did(self):
        refs = AddressRefs()
        refs.add(0x100, 0x104)
        refs.discard(0x100, 0x104)
        refs.discard(0x300, 0x304)

        self.assertEqual(refs, {0x100: set(), 0x300: set()})
        self.assertNotEqual(refs, {0x100: set()})

    def test_copies_keep_the_stored_form(self):
        refs = AddressRefs()
        refs.add(0x100, 0x104)
        refs.add(0x200, 0x204)
        refs.add(0x200, 0x300)

        for duplicate in (refs.copy(), copy.deepcopy(refs), pickle.loads(pickle.dumps(refs))):
            self.assertIs(type(duplicate), AddressRefs)
            self.assertEqual(dict(duplicate), dict(refs))
            duplicate.add(0x100, 0x108)
            self.assertEqual(duplicate[0x100], {0x104, 0x108})
            self.assertEqual(refs[0x100], {0x104})


class TestDisassemblyResultRefs(unittest.TestCase):
    def test_finalized_fall_through_refs_are_not_boxed_in_sets(self):
        disassembly = DisassemblyResult()
        state = FunctionAnalysisState(0x100, disassembly)
        state.addInstruction(0x100, 2, "nop", "", b"\x90\x90")
        state.addInstruction(0x102, 1, "ret", "", b"\xc3")
        state.endBlock()
        state.finalizeAnalysis()

        self.assertEqual(dict.get(disassembly.code_refs_from, 0x100), 0x102)
        self.assertEqual(dict.get(disassembly.code_refs_to, 0x102), 0x100)
        self.assertEqual(disassembly.getBlockRefs(0x100), {0x100: []})
        disassembly.removeCodeRefs(0x100, 0x102)
        self.assertEqual(disassembly.code_refs_from[0x100], set())

    def test_code_map_is_the_per_byte_owner_map_not_a_copy(self):
        disassembly = DisassemblyResult()
        state = FunctionAnalysisState(0x100, disassembly)
        state.addInstruction(0x100, 2, "nop", "", b"\x90\x90")
        state.endBlock()
        state.finalizeAnalysis()

        self.assertIs(disassembly.code_map, disassembly.ins2fn)
        self.assertEqual(sorted(disassembly.code_map), [0x100, 0x101])
        state.revertAnalysis()
        self.assertEqual(disassembly.code_map, {})


if __name__ == "__main__":
    unittest.main()
