"""Bytes capstone cannot decode are split into instruction-sized chunks of the function's mode."""

import unittest

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

from smda.common.BinaryInfo import BinaryInfo
from smda.export.BackendInterface import BackendInterface
from smda.export.Exporter import Exporter
from smda.SmdaConfig import SmdaConfig

# 0xb400 is a push with an empty register list, which capstone rejects
UNDECODABLE_T16_PAIR = bytes.fromhex("00b400b4")


class _UndecodableThumbInterface(BackendInterface):
    """One Thumb function whose single head is two undecodable halfwords."""

    BASE = 0x10000

    def getArchitecture(self):
        return "arm"

    def getBitness(self):
        return 32

    def getBaseAddr(self):
        return self.BASE

    def getBinary(self):
        return UNDECODABLE_T16_PAIR

    def getFunctions(self):
        return [self.BASE]

    def isExternalFunction(self, function_offset):
        return False

    def isThumb(self, offset):
        return True

    def getBlocks(self, function_offset):
        return [[self.BASE]]

    def getInstructionBytes(self, offset):
        return UNDECODABLE_T16_PAIR

    def getCodeInRefs(self, offset):
        return []

    def getCodeOutRefs(self, offset):
        return []

    def getFunctionSymbols(self, demangle=False):
        return {}

    def getApiMap(self):
        return {}


class ExporterThumbSplitTestSuite(unittest.TestCase):
    def _split(self, mode):
        capstone = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
        errors = {}
        split = Exporter._splitInstructionBytes(capstone, 0x1000, UNDECODABLE_T16_PAIR, "arm", errors)
        return [(address, size) for address, size, *_ in split], errors

    def test_thumb_falls_back_to_halfwords(self):
        split, errors = self._split(CS_MODE_THUMB)
        self.assertEqual(split, [(0x1000, 2), (0x1002, 2)])
        self.assertEqual(sorted(errors), [0x1000, 0x1002])

    def test_a32_falls_back_to_words(self):
        capstone = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        word = bytes.fromhex("ffffffff")
        self.assertEqual(list(capstone.disasm_lite(word, 0)), [])
        split = Exporter._splitInstructionBytes(capstone, 0x1000, word + word, "arm")
        self.assertEqual([(address, size) for address, size, *_ in split], [(0x1000, 4), (0x1004, 4)])

    def test_exporter_uses_the_mode_of_a_thumb_function(self):
        interface = _UndecodableThumbInterface()
        binary_info = BinaryInfo(UNDECODABLE_T16_PAIR)
        binary_info.base_addr = interface.BASE
        disassembly = Exporter(SmdaConfig(), interface).analyzeBuffer(binary_info)
        instructions = [ins[:2] for block in disassembly.functions[interface.BASE] for ins in block]
        self.assertEqual(instructions, [(0x10000, 2), (0x10002, 2)])


if __name__ == "__main__":
    unittest.main()
