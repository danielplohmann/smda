import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig

_KIND_CALL = 0
_KIND_RET = 4


def _record(op_str, *, image_size=0x1000, base_addr=0x400000, code_areas=None, kind=_KIND_RET):
    """Run the absolute-operand data-ref pass and return the refs it booked."""
    disassembly = MagicMock()
    disassembly.binary_info = SimpleNamespace(
        binary=b"\x00" * image_size,
        base_addr=base_addr,
        binary_size=image_size,
        bitness=32,
        code_areas=code_areas or [],
        isInCodeAreas=lambda addr: any(start <= addr < end for start, end in (code_areas or [])),
    )
    disassembly.isAddrWithinMemoryImage = lambda addr: base_addr <= addr < base_addr + image_size
    disassembler = MagicMock()
    disassembler.disassembly = disassembly
    state = SimpleNamespace(data_refs=set(), data_bytes=set())
    state.addDataRef = lambda a, b, size=1: (
        state.data_refs.add((a, b)),
        state.data_bytes.update(range(b, b + size)),
    )
    X86Backend._recordAbsoluteDataRefs(disassembler, 0x401000, op_str, state, kind)
    return {ref[1] for ref in state.data_refs}


class AbsoluteOperandTestSuite(unittest.TestCase):
    def test_an_absolute_source_is_recorded(self):
        self.assertEqual(_record("edx, dword ptr [0x400500]"), {0x400500})

    def test_an_absolute_destination_is_recorded(self):
        """A store names the address just as a load does; a global written to is still data."""
        self.assertEqual(_record("dword ptr [0x400500], eax"), {0x400500})

    def test_a_bare_absolute_operand_is_recorded(self):
        self.assertEqual(_record("[0x400500]"), {0x400500})

    def test_a_segment_override_is_normalized_away(self):
        self.assertEqual(_record("edx, dword ptr ds:[0x400500]"), {0x400500})

    def test_a_register_relative_operand_is_not_an_absolute_address(self):
        """Positive control for the whole class: the effective address is unknown here, so
        recording the displacement would name something the instruction never touches."""
        self.assertEqual(_record("edx, dword ptr [eax + 0x400500]"), set())

    def test_a_scaled_index_operand_is_not_recorded(self):
        self.assertEqual(_record("edx, dword ptr [eax*4 + 0x400500]"), set())

    def test_a_rip_relative_operand_is_not_recorded(self):
        self.assertEqual(_record("rdx, qword ptr [rip + 0x400500]"), set())

    def test_an_address_outside_the_image_is_not_recorded(self):
        self.assertEqual(_record("edx, dword ptr [0x7fff0000]"), set())

    def test_a_branch_operand_is_left_to_the_branch_analyzers(self):
        self.assertEqual(_record("dword ptr [0x400500]", kind=_KIND_CALL), set())

    def test_a_declared_code_area_is_not_data(self):
        self.assertEqual(_record("edx, dword ptr [0x400500]", code_areas=[(0x400000, 0x400800)]), set())

    def test_a_declared_code_area_still_admits_an_address_outside_it(self):
        """Control for the rule above: the code-area veto must narrow the result, not empty it."""
        self.assertEqual(_record("edx, dword ptr [0x400900]", code_areas=[(0x400000, 0x400800)]), {0x400900})

    def test_an_image_declaring_no_code_areas_still_records(self):
        """A raw memory dump declares none, and isInCodeAreas then answers True for the whole
        image - consulting it there would refuse every reference, which is the case this
        pass exists for."""
        self.assertEqual(_record("edx, dword ptr [0x400500]", code_areas=[]), {0x400500})

    def test_an_image_with_no_binary_info_records_nothing(self):
        """Tests build partial disassembly doubles, so the pass must survive one."""
        disassembler = MagicMock()
        disassembler.disassembly = SimpleNamespace(binary_info=None)
        state = SimpleNamespace(data_refs=set())
        state.addDataRef = lambda a, b, size=1: state.data_refs.add((a, b))

        X86Backend._recordAbsoluteDataRefs(disassembler, 0x401000, "edx, dword ptr [0x400500]", state, _KIND_RET)

        self.assertEqual(state.data_refs, set())

    def test_both_operands_are_read(self):
        self.assertEqual(_record("dword ptr [0x400500], dword ptr [0x400600]"), {0x400500, 0x400600})

    def test_the_same_address_twice_is_recorded_once(self):
        self.assertEqual(_record("dword ptr [0x400500], dword ptr [0x400500]"), {0x400500})


class AbsoluteDataRefEndToEndTestSuite(unittest.TestCase):
    """A dispatch table a function loads outright leaves no trace without this pass."""

    BASE = 0x400000
    TABLE = 0x400800

    def _report(self):
        buffer = bytearray(0x1000)
        code = b"\x55"  # push ebp
        code += b"\x8b\xec"  # mov ebp, esp
        code += b"\x8b\x15" + struct.pack("<I", self.TABLE)  # mov edx, dword ptr [0x400800]
        code += b"\x5d"  # pop ebp
        code += b"\xc3"  # ret
        buffer[0x100 : 0x100 + len(code)] = code
        struct.pack_into("<I", buffer, self.TABLE - self.BASE, self.BASE + 0x100)
        binary_info = BinaryInfo(bytes(buffer))
        binary_info.base_addr = self.BASE
        binary_info.bitness = 32
        binary_info.architecture = "intel"
        config = SmdaConfig()
        config.TIMEOUT = 0
        return IntelDisassembler(config).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

    def test_the_loaded_table_address_is_referenced(self):
        result = self._report()

        self.assertIn(self.TABLE, result.data_refs_from.get(0x400103, set()))


if __name__ == "__main__":
    unittest.main()
