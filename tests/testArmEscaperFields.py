"""Binary escaping of the AArch32 fields that change with link order: T32 branch offsets
whatever their distance, and the offsets of every PC-relative literal load.

The literal loads are ``llvm-mc -triple=armv7-linux-gnueabihf -show-encoding`` and
``llvm-mc -triple=thumbv7-linux-gnueabihf -show-encoding`` output; the T32 branches are
encoded here and checked against capstone, so any offset can be tried.
"""

import unittest

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

from smda.arm.ArmInstructionEscaper import ArmInstructionEscaper

_THUMB = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
_ADDRESS = 0x2000000


class _Instruction:
    def __init__(self, raw, mnemonic, thumb):
        self.bytes = raw
        self.mnemonic = mnemonic
        self.operands = ""
        self.smda_function = type("F", (), {"architecture_metadata": {"thumb": thumb}})()


def _t32Branch(kind, offset, cond=0):
    """B.W (T4), BL, BLX (T1/T2) or B<cond>.W (T3) of ``offset`` bytes from PC, as hex."""
    s = 1 if offset < 0 else 0
    if kind == "bcond":
        imm = (offset >> 1) & 0xFFFFF
        hw1 = 0xF000 | (s << 10) | (cond << 6) | (imm >> 11) & 0x3F
        hw2 = 0x8000 | (((imm >> 17) & 1) << 13) | (((imm >> 18) & 1) << 11) | imm & 0x7FF
    else:
        imm = (offset >> 1) & 0xFFFFFF
        j1 = 1 - (((imm >> 22) & 1) ^ s)
        j2 = 1 - (((imm >> 21) & 1) ^ s)
        hw1 = 0xF000 | (s << 10) | (imm >> 11) & 0x3FF
        hw2 = {"b.w": 0x9000, "bl": 0xD000, "blx": 0xC000}[kind] | (j1 << 13) | (j2 << 11) | imm & 0x7FF
    return (hw1 | hw2 << 16).to_bytes(4, "little").hex()


class T32BranchEscapingTest(unittest.TestCase):
    OFFSETS = (0x100, -0x100, 0x3FF000, -0x400000, 0x500000, -0x500000, 0x8F0120, 0xFFF000, -0x1000000)
    COND_OFFSETS = (0x100, -0x100, 0x3F000, -0x40000, 0x50000, -0x50000, 0xFFF00, -0x100000)

    def _escape(self, raw, mnemonic):
        return ArmInstructionEscaper.escapeBinary(_Instruction(raw, mnemonic, True))

    def _opcodes(self, raw, mnemonic):
        return ArmInstructionEscaper.escapeToOpcodeOnly(_Instruction(raw, mnemonic, True))

    def _decoded(self, raw):
        decoded = list(_THUMB.disasm(bytes.fromhex(raw), _ADDRESS))
        self.assertEqual(len(decoded), 1, raw)
        return decoded[0]

    def test_the_encoder_matches_capstone_and_llvm(self):
        # llvm-mc + llvm-objdump: "bl far" at 0x500004, 0x8f0120 beyond PC
        self.assertEqual(_t32Branch("bl", 0x8F0120), "f0f090d8")
        for kind, offsets in (("bl", self.OFFSETS), ("blx", self.OFFSETS), ("b.w", self.OFFSETS)):
            for offset in offsets:
                with self.subTest(kind=kind, offset=offset):
                    decoded = self._decoded(_t32Branch(kind, offset))
                    self.assertEqual(decoded.mnemonic, kind)
                    target = (_ADDRESS + 4) & ~3 if kind == "blx" else _ADDRESS + 4
                    self.assertEqual(int(decoded.op_str.lstrip("#"), 0), target + offset)
        for offset in self.COND_OFFSETS:
            with self.subTest(kind="beq.w", offset=offset):
                decoded = self._decoded(_t32Branch("bcond", offset))
                self.assertEqual(decoded.mnemonic, "beq.w")
                self.assertEqual(int(decoded.op_str.lstrip("#"), 0), _ADDRESS + 4 + offset)

    def test_branches_escape_the_same_at_any_distance(self):
        for kind in ("bl", "blx", "b.w"):
            with self.subTest(kind=kind):
                escaped = {self._escape(_t32Branch(kind, offset), kind) for offset in self.OFFSETS}
                self.assertEqual(len(escaped), 1, escaped)
                opcodes = {self._opcodes(_t32Branch(kind, offset), kind) for offset in self.OFFSETS}
                self.assertEqual(len(opcodes), 1, opcodes)
        for cond in range(14):
            with self.subTest(kind="bcond", cond=cond):
                escaped = {self._escape(_t32Branch("bcond", offset, cond), "b") for offset in self.COND_OFFSETS}
                self.assertEqual(len(escaped), 1, escaped)

    def test_a_far_bl_escapes_like_a_near_one(self):
        # J2 flips past 4 MiB and J1, in the nibble with the opcode bits, past 8 MiB
        near, far = _t32Branch("bl", 0x120), _t32Branch("bl", 0x8F0120)
        self.assertNotEqual(near[4:], far[4:])
        self.assertEqual(self._escape(near, "bl"), self._escape(far, "bl"))

    def test_the_branch_kind_and_condition_are_kept(self):
        escaped = {
            "bl": self._escape(_t32Branch("bl", 0x500000), "bl"),
            "blx": self._escape(_t32Branch("blx", 0x500000), "blx"),
            "b.w": self._escape(_t32Branch("b.w", 0x500000), "b.w"),
            "beq.w": self._escape(_t32Branch("bcond", 0x50000, 0), "beq.w"),
            "bne.w": self._escape(_t32Branch("bcond", 0x50000, 1), "bne.w"),
        }
        self.assertEqual(
            escaped,
            {"bl": "??f???f?", "blx": "??f???e?", "b.w": "??f???b?", "beq.w": "0?f0??8?", "bne.w": "4?f0??8?"},
        )
        opcodes = {kind: self._opcodes(_t32Branch(kind, 0x500000), kind) for kind in ("bl", "blx", "b.w")}
        opcodes["beq.w"] = self._opcodes(_t32Branch("bcond", 0x50000), "beq.w")
        self.assertEqual(opcodes, {"bl": "??f???f?", "blx": "??f???e?", "b.w": "??f???b?", "beq.w": "??f???8?"})


class LiteralLoadEscapingTest(unittest.TestCase):
    def _assertEscapes(self, cases, thumb):
        for raw, mnemonic, expected in cases:
            with self.subTest(instruction=f"{mnemonic} {raw}"):
                self.assertEqual(ArmInstructionEscaper.escapeBinary(_Instruction(raw, mnemonic, thumb)), expected)

    def test_a32_literal_loads_wildcard_their_offset(self):
        self._assertEscapes(
            [
                # ldr r3, [pc, #56] / ldrb r3, [pc, #56] / ldrb r3, [pc, #-56]: imm12
                ("38309fe5", "ldr", "??3?9fe5"),
                ("3830dfe5", "ldrb", "??3?dfe5"),
                ("38305fe5", "ldrb", "??3?5fe5"),
                # ldrh / ldrsb / ldrsh r3, [pc, #56] and ldrd r2, r3, [pc, #56]: imm4H and imm4L
                ("b833dfe1", "ldrh", "b?3?dfe1"),
                ("d833dfe1", "ldrsb", "d?3?dfe1"),
                ("f833dfe1", "ldrsh", "f?3?dfe1"),
                ("d823cfe1", "ldrd", "d?2?cfe1"),
            ],
            thumb=False,
        )

    def test_a32_loads_and_stores_off_other_registers_are_kept(self):
        self._assertEscapes(
            [
                ("b833d1e1", "ldrh", "b833d1e1"),
                ("b833c1e1", "strh", "b833c1e1"),
                ("f823c1e1", "strd", "f823c1e1"),
                ("d823c1e1", "ldrd", "d823c1e1"),
            ],
            thumb=False,
        )

    def test_t32_literal_loads_wildcard_their_offset(self):
        self._assertEscapes(
            [
                # ldr.w, ldrb.w, ldrh.w, ldrsb.w, ldrsh.w r3, [pc, #56]: imm12
                ("dff83830", "ldr.w", "dff8??3?"),
                ("9ff83830", "ldrb.w", "9ff8??3?"),
                ("bff83830", "ldrh.w", "bff8??3?"),
                ("9ff93830", "ldrsb.w", "9ff9??3?"),
                ("bff93830", "ldrsh.w", "bff9??3?"),
                # ldrd r2, r3, [pc, #56] and [pc, #-56]: imm8
                ("dfe90e23", "ldrd", "dfe9??23"),
                ("5fe90e23", "ldrd", "5fe9??23"),
                # T16 ldr r0, [pc, #4]: imm8
                ("0148", "ldr", "??48"),
            ],
            thumb=True,
        )

    def test_t32_neighbours_of_the_literal_ldrd_are_kept(self):
        self._assertEscapes(
            [
                ("d1e90e23", "ldrd", "d1e90e23"),
                ("51e8002f", "ldrex", "51e8002f"),
                ("d0e801f0", "tbb", "d0e801f0"),
            ],
            thumb=True,
        )


if __name__ == "__main__":
    unittest.main()
