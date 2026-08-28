import unittest
from types import SimpleNamespace

from smda.DisassemblyResult import DisassemblyResult


class TestDisassemblyResultGetOutRefs(unittest.TestCase):
    def _build_disassembly(self, target_addr):
        disassembly = DisassemblyResult()
        disassembly.binary_info = SimpleNamespace(base_addr=0x1000, binary_size=0x100)
        func_addr = 0x1000
        ins_addr = 0x1000
        # a single instruction block, representing the function's only block
        disassembly.functions[func_addr] = [[(ins_addr, 5, "call", "0x0")]]
        disassembly.code_refs_from[ins_addr] = {target_addr}
        return disassembly, ins_addr

    def test_out_ref_exactly_at_exclusive_upper_bound_is_filtered_out(self):
        # base_addr + binary_size == 0x1000 + 0x100 == 0x1100, one byte PAST the mapped image
        max_addr = 0x1000 + 0x100
        disassembly, ins_addr = self._build_disassembly(max_addr)
        out_refs = disassembly.getOutRefs(0x1000)
        self.assertNotIn(ins_addr, out_refs)

    def test_out_ref_one_byte_before_upper_bound_is_kept(self):
        # base_addr + binary_size - 1 == 0x10ff, the last valid mapped byte
        last_valid_addr = 0x1000 + 0x100 - 1
        disassembly, ins_addr = self._build_disassembly(last_valid_addr)
        out_refs = disassembly.getOutRefs(0x1000)
        self.assertIn(ins_addr, out_refs)
        self.assertEqual(out_refs[ins_addr], [last_valid_addr])

    def test_out_refs_are_sorted_and_exclude_in_function_destinations(self):
        disassembly = DisassemblyResult()
        disassembly.binary_info = SimpleNamespace(base_addr=0x1000, binary_size=0x200)
        func_addr = 0x1000
        call_addr = 0x1000
        fallthrough = 0x1005
        disassembly.functions[func_addr] = [
            [(call_addr, 5, "call", "0x1100"), (fallthrough, 1, "ret", "")],
        ]
        disassembly.code_refs_from[call_addr] = {0x1180, 0x1100, fallthrough, func_addr}
        out_refs = disassembly.getOutRefs(func_addr)
        self.assertEqual(out_refs[call_addr], [func_addr, 0x1100, 0x1180])


if __name__ == "__main__":
    unittest.main()
