"""Regressions for two defects introduced while making the tree type-check clean.

Both share a root cause: a guard or sentinel was rewritten to satisfy a static
type checker in a way that inverted or widened the runtime semantics.
"""

import unittest

from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.SmdaConfig import SmdaConfig


class TestDelphiReSymReadByte(unittest.TestCase):
    """_read_byte's bounds check must return the byte in range and None outside."""

    def _provider(self, binary):
        provider = DelphiReSymProvider(SmdaConfig())
        provider._binary = binary
        return provider

    def test_in_range_offset_returns_the_byte(self):
        provider = self._provider(b"\x05ABCDE")
        self.assertEqual(0x05, provider._read_byte(0))
        self.assertEqual(ord("C"), provider._read_byte(3))

    def test_offset_past_end_returns_none_without_raising(self):
        provider = self._provider(b"\x05ABCDE")
        self.assertIsNone(provider._read_byte(6))
        self.assertIsNone(provider._read_byte(1000))

    def test_negative_offset_returns_none_instead_of_wrapping(self):
        # a negative index would silently read from the tail of the buffer
        provider = self._provider(b"\x05ABCDE")
        self.assertIsNone(provider._read_byte(-1))

    def test_pascal_string_roundtrip_depends_on_read_byte(self):
        # _read_pascal_string reads its length prefix via _read_byte; an inverted
        # guard makes every in-range read None and yields an empty string
        provider = self._provider(b"\x03abc")
        self.assertEqual("abc", provider._read_pascal_string(0))


class _StubReport(SmdaReport):
    def __init__(self, base_addr, binary_size, capstone):
        super().__init__()
        self.architecture = "intel"
        self.base_addr = base_addr
        self.binary_size = binary_size
        self.bitness = 32
        self.data_refs_from = None
        self.code_areas = []
        self._capstone = capstone

    def getCapstone(self):
        return self._capstone


class TestGetDataRefsRegisterOperands(unittest.TestCase):
    """Register operands must not contribute address 0 as a data reference."""

    def _instruction(self, hex_bytes, offset, operands, base_addr, binary_size=0x10000):
        import capstone

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        report = _StubReport(base_addr=base_addr, binary_size=binary_size, capstone=cs)
        function = SmdaFunction(smda_report=report)
        return SmdaInstruction([offset, hex_bytes, "mov", operands], smda_function=function)

    def test_register_operand_does_not_emit_zero_on_base_zero_image(self):
        # `mov eax, 0x200` (b800020000) has one register operand and one immediate.
        # Only the immediate is an address. On a base-0 memory dump address 0 is
        # inside the image, so a 0 placeholder for `eax` would be emitted as a
        # bogus data reference alongside the real one.
        ins = self._instruction("b800020000", 0x100, "eax, 0x200", base_addr=0)
        self.assertEqual([0x200], list(ins.getDataRefs()))

    def test_zero_placeholder_is_filtered_when_base_addr_is_nonzero(self):
        # with a nonzero base the bogus 0 fell outside the image and was masked;
        # pin the same expectation so the two paths cannot diverge again
        ins = self._instruction("b800104000", 0x400100, "eax, 0x401000", base_addr=0x400000)
        self.assertEqual([0x401000], list(ins.getDataRefs()))


if __name__ == "__main__":
    unittest.main()
