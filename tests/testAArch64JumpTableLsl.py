import struct
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.DisassemblyResult import DisassemblyResult


class TestAArch64JumpTableLsl(unittest.TestCase):
    def test_shifted_add_scales_entry(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64JumpTableAnalyzer

        base = 0x400000
        words = [
            0x90000088,  # adrp x8, #0x411000
            0x91040108,  # add  x8, x8, #0x100        (x8 = 0x411100)
            0x39400109,  # ldrb w9, [x8]              (load entry byte)
            0x8B090908,  # add  x8, x8, x9, lsl #2    (scale index by 4)
            0xD61F0100,  # br   x8
        ]

        mapped = bytearray(0x15000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        struct.pack_into("<B", mapped, 0x411100 - base, 8)
        struct.pack_into("<B", mapped, 0x411101 - base, 16)
        struct.pack_into("<B", mapped, 0x411102 - base, 24)

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.binary_size = len(mapped)
        binary_info.isInCodeAreas = lambda addr: 0x400000 <= addr < 0x415000

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True

        class FakeDisassembler:
            def __init__(self, disassembly_result, capstone):
                self.disassembly = disassembly_result
                self.capstone = capstone

            def getBitMask(self):
                return 0xFFFFFFFFFFFFFFFF

        fake_disassembler = FakeDisassembler(disassembly, capstone)

        class FakeState:
            def __init__(self, instructions):
                self.instructions = instructions
                self.data_refs = []

            def backtrackInstructions(self, addr_from, num_instructions):
                return self.instructions

            def addDataRef(self, from_addr, to_addr, size=1):
                self.data_refs.append((from_addr, to_addr, size))

        instructions = []
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            inst = next(capstone.disasm(w.to_bytes(4, "little"), addr))
            instructions.append((addr, 4, inst.mnemonic, inst.op_str, inst.bytes))

        fake_state = FakeState(instructions)
        analyzer = AArch64JumpTableAnalyzer(fake_disassembler)

        targets = analyzer.getJumpTargets(instructions[-1], fake_state)
        self.assertEqual(targets[:3], [0x411120, 0x411140, 0x411160])


if __name__ == "__main__":
    unittest.main()
