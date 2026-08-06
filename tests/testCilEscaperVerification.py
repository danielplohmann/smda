import logging
import os
import unittest

import pytest
from dncil.cil.opcode import OpCode, OpCodes

from smda.cil.CilInstructionEscaper import CilInstructionEscaper
from smda.common.SmdaFunction import CIL_PIC_HASH_ESCAPE_VERSION, SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

pytestmark = pytest.mark.slow

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")

_RESERVED_MNEMONICS = frozenset(
    {
        "UNKNOWN1",
        "UNKNOWN2",
        "prefix1",
        "prefix2",
        "prefix3",
        "prefix4",
        "prefix5",
        "prefix6",
        "prefix7",
        "prefixref",
    }
)

# Pinned group assignments for every dncil opcode — any deviation is a deliberate
# change that must be updated here and in the escaper simultaneously.
_EXPECTED_GROUPS = {
    "UNKNOWN1": "U",
    "UNKNOWN2": "U",
    "add": "A",
    "add.ovf": "A",
    "add.ovf.un": "A",
    "and": "A",
    "arglist": "M",
    "beq": "C",
    "beq.s": "C",
    "bge": "C",
    "bge.s": "C",
    "bge.un": "C",
    "bge.un.s": "C",
    "bgt": "C",
    "bgt.s": "C",
    "bgt.un": "C",
    "bgt.un.s": "C",
    "ble": "C",
    "ble.s": "C",
    "ble.un": "C",
    "ble.un.s": "C",
    "blt": "C",
    "blt.s": "C",
    "blt.un": "C",
    "blt.un.s": "C",
    "bne.un": "C",
    "bne.un.s": "C",
    "box": "S",
    "br": "C",
    "br.s": "C",
    "break": "P",
    "brfalse": "C",
    "brfalse.s": "C",
    "brtrue": "C",
    "brtrue.s": "C",
    "call": "C",
    "calli": "C",
    "callvirt": "C",
    "castclass": "S",
    "ceq": "C",
    "cgt": "C",
    "cgt.un": "C",
    "ckfinite": "C",
    "clt": "C",
    "clt.un": "C",
    "constrained.": "N",
    "conv.i": "S",
    "conv.i1": "S",
    "conv.i2": "S",
    "conv.i4": "S",
    "conv.i8": "S",
    "conv.ovf.i": "S",
    "conv.ovf.i.un": "S",
    "conv.ovf.i1": "S",
    "conv.ovf.i1.un": "S",
    "conv.ovf.i2": "S",
    "conv.ovf.i2.un": "S",
    "conv.ovf.i4": "S",
    "conv.ovf.i4.un": "S",
    "conv.ovf.i8": "S",
    "conv.ovf.i8.un": "S",
    "conv.ovf.u": "S",
    "conv.ovf.u.un": "S",
    "conv.ovf.u1": "S",
    "conv.ovf.u1.un": "S",
    "conv.ovf.u2": "S",
    "conv.ovf.u2.un": "S",
    "conv.ovf.u4": "S",
    "conv.ovf.u4.un": "S",
    "conv.ovf.u8": "S",
    "conv.ovf.u8.un": "S",
    "conv.r.un": "S",
    "conv.r4": "F",
    "conv.r8": "F",
    "conv.u": "S",
    "conv.u1": "S",
    "conv.u2": "S",
    "conv.u4": "S",
    "conv.u8": "S",
    "cpblk": "M",
    "cpobj": "M",
    "div": "A",
    "div.un": "A",
    "dup": "S",
    "endfilter": "C",
    "endfinally": "C",
    "initblk": "M",
    "initobj": "M",
    "isinst": "S",
    "jmp": "C",
    "ldarg": "S",
    "ldarg.0": "S",
    "ldarg.1": "S",
    "ldarg.2": "S",
    "ldarg.3": "S",
    "ldarg.s": "S",
    "ldarga": "M",
    "ldarga.s": "M",
    "ldc.i4": "S",
    "ldc.i4.0": "S",
    "ldc.i4.1": "S",
    "ldc.i4.2": "S",
    "ldc.i4.3": "S",
    "ldc.i4.4": "S",
    "ldc.i4.5": "S",
    "ldc.i4.6": "S",
    "ldc.i4.7": "S",
    "ldc.i4.8": "S",
    "ldc.i4.m1": "S",
    "ldc.i4.s": "S",
    "ldc.i8": "S",
    "ldc.r4": "F",
    "ldc.r8": "F",
    "ldelem": "S",
    "ldelem.i": "S",
    "ldelem.i1": "S",
    "ldelem.i2": "S",
    "ldelem.i4": "S",
    "ldelem.i8": "S",
    "ldelem.r4": "F",
    "ldelem.r8": "F",
    "ldelem.ref": "S",
    "ldelem.u1": "S",
    "ldelem.u2": "S",
    "ldelem.u4": "S",
    "ldelema": "S",
    "ldfld": "S",
    "ldflda": "S",
    "ldftn": "S",
    "ldind.i": "S",
    "ldind.i1": "S",
    "ldind.i2": "S",
    "ldind.i4": "S",
    "ldind.i8": "S",
    "ldind.r4": "F",
    "ldind.r8": "F",
    "ldind.ref": "S",
    "ldind.u1": "S",
    "ldind.u2": "S",
    "ldind.u4": "S",
    "ldlen": "S",
    "ldloc": "S",
    "ldloc.0": "S",
    "ldloc.1": "S",
    "ldloc.2": "S",
    "ldloc.3": "S",
    "ldloc.s": "S",
    "ldloca": "S",
    "ldloca.s": "S",
    "ldnull": "S",
    "ldobj": "S",
    "ldsfld": "S",
    "ldsflda": "S",
    "ldstr": "S",
    "ldtoken": "M",
    "ldvirtftn": "S",
    "leave": "C",
    "leave.s": "C",
    "localloc": "M",
    "mkrefany": "S",
    "mul": "A",
    "mul.ovf": "A",
    "mul.ovf.un": "A",
    "neg": "A",
    "newarr": "M",
    "newobj": "C",
    "no.": "N",
    "nop": "N",
    "not": "A",
    "or": "A",
    "pop": "S",
    "prefix1": "U",
    "prefix2": "U",
    "prefix3": "U",
    "prefix4": "U",
    "prefix5": "U",
    "prefix6": "U",
    "prefix7": "U",
    "prefixref": "U",
    "readonly.": "N",
    "refanytype": "S",
    "refanyval": "S",
    "rem": "A",
    "rem.un": "A",
    "ret": "C",
    "rethrow": "C",
    "shl": "A",
    "shr": "A",
    "shr.un": "A",
    "sizeof": "S",
    "starg": "M",
    "starg.s": "M",
    "stelem": "M",
    "stelem.i": "M",
    "stelem.i1": "M",
    "stelem.i2": "M",
    "stelem.i4": "M",
    "stelem.i8": "M",
    "stelem.r4": "F",
    "stelem.r8": "F",
    "stelem.ref": "M",
    "stfld": "M",
    "stind.i": "M",
    "stind.i1": "M",
    "stind.i2": "M",
    "stind.i4": "M",
    "stind.i8": "M",
    "stind.r4": "F",
    "stind.r8": "F",
    "stind.ref": "M",
    "stloc": "S",
    "stloc.0": "S",
    "stloc.1": "S",
    "stloc.2": "S",
    "stloc.3": "S",
    "stloc.s": "S",
    "stobj": "M",
    "stsfld": "M",
    "sub": "A",
    "sub.ovf": "A",
    "sub.ovf.un": "A",
    "switch": "C",
    "tail.": "N",
    "throw": "C",
    "unaligned.": "N",
    "unbox": "S",
    "unbox.any": "S",
    "volatile.": "N",
    "xor": "A",
}


class TestCilEscaperVerification(unittest.TestCase):
    # ----------------------------------------------------------------
    # Gate 1 — coverage: every dncil name has a non-"U" group
    # ----------------------------------------------------------------

    def test_all_dncil_opcodes_have_non_u_group(self):
        missing = []
        for attr in dir(OpCodes):
            if not attr.startswith("_"):
                opcode = getattr(OpCodes, attr)
                if not isinstance(opcode, OpCode):
                    continue
                if opcode.name in _RESERVED_MNEMONICS:
                    continue
                letter = CilInstructionEscaper.escapeMnemonic(opcode.name)
                if letter == "U":
                    missing.append(opcode.name)
        self.assertEqual([], missing, f"mnemonics falling through to 'U': {missing}")

    def test_reserved_mnemonics_return_u_without_error(self):
        for name in _RESERVED_MNEMONICS:
            letter = CilInstructionEscaper.escapeMnemonic(name)
            self.assertEqual("U", letter, f"reserved mnemonic '{name}' should map to 'U'")

    def test_no_unhandled_mnemonic_error_logged_for_any_opcode(self):
        dncil_names = []
        for attr in dir(OpCodes):
            if not attr.startswith("_"):
                opcode = getattr(OpCodes, attr)
                if isinstance(opcode, OpCode):
                    dncil_names.append(opcode.name)
        logger = logging.getLogger("smda.cil.CilInstructionEscaper")
        with self.assertNoLogs(logger, level="ERROR"):
            for name in dncil_names:
                CilInstructionEscaper.escapeMnemonic(name)

    # ----------------------------------------------------------------
    # Gate 2 — pinned group table (deliberate-change gate)
    # ----------------------------------------------------------------

    def test_mnemonic_groups_pinned(self):
        for name, expected_letter in _EXPECTED_GROUPS.items():
            actual = CilInstructionEscaper.escapeMnemonic(name)
            self.assertEqual(
                expected_letter,
                actual,
                f"mnemonic '{name}' group changed from '{expected_letter}' to '{actual}'",
            )

    # ----------------------------------------------------------------
    # Gate 3 — escapeBinary token wildcarding
    # ----------------------------------------------------------------

    @staticmethod
    def _make_ins(offset, hex_bytes, mnemonic, operands=""):
        return SmdaInstruction([offset, hex_bytes, mnemonic, operands])

    def test_escape_binary_token_wildcards_rid(self):
        cases = [
            ("call", "280a000006", "28??????06", "1-byte InlineMethod"),
            ("callvirt", "6fbb00000a", "6f??????0a", "1-byte InlineMethod"),
            ("ldstr", "7200000170", "72??????70", "1-byte InlineString — was missed"),
            ("cpobj", "700000012a", "70??????2a", "1-byte InlineType — was missed"),
            ("ldelema", "8f00000102", "8f??????02", "1-byte InlineType — was missed"),
            ("ldelem", "a300000102", "a3??????02", "1-byte InlineType — was missed"),
            ("stelem", "a400000102", "a4??????02", "1-byte InlineType — was missed"),
            ("mkrefany", "c600000102", "c6??????02", "1-byte InlineType — was missed"),
            ("refanyval", "c200000102", "c2??????02", "1-byte InlineType — was missed"),
            ("newobj", "7300000106", "73??????06", "1-byte InlineMethod"),
            ("ldftn", "fe0600000106", "fe06??????06", "2-byte InlineMethod"),
            ("ldvirtftn", "fe0700000106", "fe07??????06", "2-byte InlineMethod — was missed"),
            ("sizeof", "fe1c00000102", "fe1c??????02", "2-byte InlineType — was missed"),
            ("constrained.", "fe1600000102", "fe16??????02", "2-byte InlineType (prefix)"),
            ("initobj", "fe1500000102", "fe15??????02", "2-byte InlineType"),
        ]
        for mnemonic, hex_bytes, expected, label in cases:
            with self.subTest(mnemonic=mnemonic, label=label):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeBinary(ins)
                self.assertEqual(expected, result)

    def test_escape_binary_token_unaffected_by_jump_flag(self):
        ins = self._make_ins(0, "280a000006", "call")
        result = CilInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)
        self.assertEqual("28??????06", result, "token wildcarding must not depend on escape_intraprocedural_jumps")

    # ----------------------------------------------------------------
    # Gate 4 — escapeBinary branch wildcarding
    # ----------------------------------------------------------------

    def test_escape_binary_branch_wildcards_on_flag(self):
        cases = [
            ("br.s", "2b10", "2b??", "ShortInlineBrTarget"),
            ("brfalse", "3920000000", "39????????", "InlineBrTarget"),
            ("brtrue.s", "2d3a", "2d??", "ShortInlineBrTarget"),
            ("beq", "3be0000000", "3b????????", "InlineBrTarget"),
            ("leave.s", "de10", "de??", "ShortInlineBrTarget — was missed"),
            ("leave", "dd20000000", "dd????????", "InlineBrTarget — was missed"),
            ("switch", "450300000002000000060000000a000000", "45????????????????????????????????", "InlineSwitch"),
        ]
        for mnemonic, hex_bytes, expected, label in cases:
            with self.subTest(mnemonic=mnemonic, label=label):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)
                self.assertEqual(expected, result)

    def test_escape_binary_branch_preserves_on_no_flag(self):
        cases = [
            ("br.s", "2b10", "2b10"),
            ("brfalse", "3920000000", "3920000000"),
            ("brtrue.s", "2d3a", "2d3a"),
            ("beq", "3be0000000", "3be0000000"),
            ("leave.s", "de10", "de10"),
            ("leave", "dd20000000", "dd20000000"),
            ("switch", "450300000002000000060000000a000000", "450300000002000000060000000a000000"),
        ]
        for mnemonic, hex_bytes, expected in cases:
            with self.subTest(mnemonic=mnemonic):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=False)
                self.assertEqual(expected, result)

    # ----------------------------------------------------------------
    # Gate 5 — escapeBinary keeps constants and prefix operands
    # ----------------------------------------------------------------

    def test_escape_binary_keeps_constants(self):
        cases = [
            ("ldc.i4", "20c48efb0e", "20c48efb0e"),
            ("ldc.i4.s", "1f7f", "1f7f"),
            ("ldc.r4", "220000003f", "220000003f"),
            ("ldc.i8", "210000000000000000", "210000000000000000"),
        ]
        for mnemonic, hex_bytes, expected in cases:
            with self.subTest(mnemonic=mnemonic):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeBinary(ins)
                self.assertEqual(expected, result)

    def test_escape_binary_keeps_prefix_operands(self):
        cases = [
            ("unaligned.", "fe1201", "fe1201", "1-byte operand preserved"),
            ("no.", "fe1903", "fe1903", "1-byte operand preserved"),
        ]
        for mnemonic, hex_bytes, expected, label in cases:
            with self.subTest(mnemonic=mnemonic, label=label):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeBinary(ins)
                self.assertEqual(expected, result)

    # ----------------------------------------------------------------
    # Gate 6 — escapeToOpcodeOnly
    # ----------------------------------------------------------------

    def test_escape_to_opcode_only_detects_two_byte_prefix(self):
        cases = [
            ("ldftn", "fe0600000106", "fe06????????"),
            ("call", "280a000006", "28????????"),
            ("sizeof", "fe1c00000102", "fe1c????????"),
        ]
        for mnemonic, hex_bytes, expected in cases:
            with self.subTest(mnemonic=mnemonic):
                ins = self._make_ins(0, hex_bytes, mnemonic)
                result = CilInstructionEscaper.escapeToOpcodeOnly(ins)
                self.assertEqual(expected, result)

    # ----------------------------------------------------------------
    # Gate 7 — escapeOperands offsets-only
    # ----------------------------------------------------------------

    def test_escape_operands_offsets_only_returns_offset(self):
        branch_cases = [
            (0x1000, "2b10", "br.s", ""),
            (0x1000, "3920000000", "brfalse", ""),
            (0x1000, "4503000000", "switch", ""),
            (0x1000, "dd20000000", "leave", ""),
        ]
        for offset, hb, mnem, ops in branch_cases:
            with self.subTest(mnemonic=mnem):
                ins = self._make_ins(offset, hb, mnem, ops)
                result = CilInstructionEscaper.escapeOperands(ins, offsets_only=True)
                self.assertEqual("OFFSET", result)

    def test_escape_operands_offsets_only_returns_empty_for_operandless_cfg(self):
        cases = [
            ("ret", "2a", ""),
            ("throw", "7a", ""),
            ("rethrow", "fe1a", ""),
            ("endfilter", "fe11", ""),
            ("endfinally", "dc", ""),
        ]
        for mnem, hb, ops in cases:
            with self.subTest(mnemonic=mnem):
                ins = self._make_ins(0, hb, mnem, ops)
                result = CilInstructionEscaper.escapeOperands(ins, offsets_only=True)
                self.assertEqual("", result)

    def test_escape_operands_offsets_only_for_call_like(self):
        ins = self._make_ins(0, "280a000006", "call")
        self.assertEqual("OFFSET", CilInstructionEscaper.escapeOperands(ins, offsets_only=True))
        ins = self._make_ins(0, "7300000106", "newobj")
        self.assertEqual("OFFSET", CilInstructionEscaper.escapeOperands(ins, offsets_only=True))

    # ----------------------------------------------------------------
    # Gate 8 — corpus: njrat has zero unknown mnemonics
    # ----------------------------------------------------------------

    def test_njrat_zero_unknown_mnemonics(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        fixture_path = os.path.join(config.PROJECT_ROOT, "tests", "njrat_xored")
        self.assertTrue(os.path.exists(fixture_path), "njrat_xored fixture not found")

        with open(fixture_path, "rb") as f:
            binary = f.read()
        decrypted = bytearray()
        for index, byte in enumerate(binary):
            decrypted.append(byte ^ (index % 256))

        disasm = Disassembler(config, backend="cil")
        report = disasm.disassembleUnmappedBuffer(bytes(decrypted))
        self.assertEqual(64, report.num_functions)

        unknown_mnemonics = set()
        for fn in report.getFunctions():
            for ins in fn.getInstructions():
                letter = CilInstructionEscaper.escapeMnemonic(ins.mnemonic)
                if letter == "U":
                    unknown_mnemonics.add(ins.mnemonic)
        self.assertEqual(
            set(),
            unknown_mnemonics,
            f"njrat contains mnemonics mapping to 'U': {unknown_mnemonics}",
        )

    def test_njrat_hashes_computable(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = True
        config.CALCULATE_SCC = True
        config.CALCULATE_NESTING = True
        fixture_path = os.path.join(config.PROJECT_ROOT, "tests", "njrat_xored")

        with open(fixture_path, "rb") as f:
            binary = f.read()
        decrypted = bytearray()
        for index, byte in enumerate(binary):
            decrypted.append(byte ^ (index % 256))

        disasm = Disassembler(config, backend="cil")
        report = disasm.disassembleUnmappedBuffer(bytes(decrypted))
        for fn in report.getFunctions():
            self.assertIsNotNone(fn.pic_hash, f"function 0x{fn.offset:x} has no pic_hash")

    # ----------------------------------------------------------------
    # Gate 9 — hash migration
    # ----------------------------------------------------------------

    def _make_cil_function(self, smda_report):
        fn = SmdaFunction()
        fn.smda_report = smda_report
        fn.offset = 0
        fn.blocks = {
            0: [
                SmdaInstruction((0, "2a", "ret", "")),
            ]
        }
        fn._sorted_block_keys = [0]
        fn._escaper = CilInstructionEscaper
        fn.architecture_metadata = {}
        fn.blockrefs = {0: []}
        return fn

    def test_cil_pic_hash_import_recalculates_before_escape_version(self):
        report = SmdaReport()
        report.architecture = "cil"
        report.base_addr = 0
        report.binary_size = 0x100
        report.code_areas = []
        report.data_refs_from = {}

        fn = self._make_cil_function(report)
        expected_pic_hash = fn.getPicHash(report)
        fn_dict = fn.toDict()
        fn_dict["metadata"]["pic_hash"] = 0x0123456789ABCDEF

        imported = SmdaFunction.fromDict(fn_dict, version="4.2.0", smda_report=report)
        self.assertEqual(expected_pic_hash, imported.pic_hash)
        self.assertLess([4, 2, 0], CIL_PIC_HASH_ESCAPE_VERSION)

    def test_cil_pic_hash_import_preserves_at_escape_version(self):
        report = SmdaReport()
        report.architecture = "cil"
        report.base_addr = 0
        report.binary_size = 0x100
        report.code_areas = []
        report.data_refs_from = {}

        fn = self._make_cil_function(report)
        fn_dict = fn.toDict()
        stored_hash = 0x0123456789ABCDEF
        fn_dict["metadata"]["pic_hash"] = stored_hash
        gate_version = ".".join(str(v) for v in CIL_PIC_HASH_ESCAPE_VERSION)

        imported = SmdaFunction.fromDict(fn_dict, version=gate_version, smda_report=report)
        self.assertEqual(stored_hash, imported.pic_hash)

    def test_cil_pic_hash_constant_exists(self):
        self.assertIsInstance(CIL_PIC_HASH_ESCAPE_VERSION, list)
        self.assertGreater(len(CIL_PIC_HASH_ESCAPE_VERSION), 0)


if __name__ == "__main__":
    unittest.main()
