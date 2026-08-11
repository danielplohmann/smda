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

    def test_anchor_in_second_add_operand_is_still_the_rebase_base(self):
        # `add Xd, Xindex, Xanchor` puts the constant in the second operand, so the
        # anchor is captured by the elif arm. Targets must still be rebased on the
        # anchor rather than on the table address the later ldr records.
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64JumpTableAnalyzer

        base = 0x400000
        words = [
            0x90000088,  # adrp x8, #0x411000
            0x91040108,  # add  x8, x8, #0x100     (x8 = 0x411100, the anchor)
            0x39400109,  # ldrb w9, [x8]           (load entry byte)
            0x8B080128,  # add  x8, x9, x8         (anchor is operand 2)
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

        analyzer = AArch64JumpTableAnalyzer(FakeDisassembler(disassembly, capstone))
        targets = analyzer.getJumpTargets(instructions[-1], FakeState(instructions))

        self.assertEqual(targets[:3], [0x411108, 0x411110, 0x411118])

    def test_extended_register_add_marks_a_signed_table(self):
        # `add x8, x8, w9, sxtw #2` folds the index's sign-extension into the merging add,
        # so the table is signed with no ldrsw/sxtw anywhere for the reverse scan to see.
        # Read as unsigned, every backward entry becomes a multi-gigabyte delta and the walk
        # aborts on the first one, losing the whole table.
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64JumpTableAnalyzer

        base = 0x400000
        words = [
            0x90000088,  # adrp x8, #0x411000
            0x91040108,  # add  x8, x8, #0x100       (x8 = 0x411100, the table)
            0xB9400109,  # ldr  w9, [x8]             (plain 32-bit load, unsigned by itself)
            0x8B29C908,  # add  x8, x8, w9, sxtw #2  (sign-extend + scale, folded in)
            0xD61F0100,  # br   x8
        ]

        mapped = bytearray(0x15000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        for entry, delta in enumerate((-0x40, -0x80, 0x40)):
            struct.pack_into("<i", mapped, 0x411100 - base + entry * 4, delta)

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

        analyzer = AArch64JumpTableAnalyzer(FakeDisassembler(disassembly, capstone))
        targets = analyzer.getJumpTargets(instructions[-1], FakeState(instructions))

        # anchor 0x411100 + (delta << 2): two entries resolve *before* the table, which is
        # exactly what the unsigned read cannot express.
        self.assertEqual(targets[:3], [0x411000, 0x410F00, 0x411200])


if __name__ == "__main__":
    unittest.main()
