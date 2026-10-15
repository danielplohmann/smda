import os
import struct
import unittest
from tempfile import TemporaryDirectory

import lief

from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.synthesis import FORMAT_PE
from smda.synthesis.PeSynthesizer import MACHINE_ARM, MACHINE_ARMNT


def _make_function(address, instructions, thumb=False):
    function = SmdaFunction()
    function.offset = address
    function.blocks = {
        address: [
            SmdaInstruction((address + index * 4, raw, mnemonic, operands))
            for index, (raw, mnemonic, operands) in enumerate(instructions)
        ]
    }
    function._sorted_block_keys = [address]
    function.architecture_metadata = {"thumb": thumb}
    return function


def _make_report(functions, entry, thumb_entry=False):
    report = SmdaReport()
    report.architecture = "arm"
    report.bitness = 32
    report.base_addr = min(functions)
    report.binary_size = max(functions) - report.base_addr + 0x100
    report.oep = entry | (1 if thumb_entry else 0)
    report.xheader = None
    report.xcfg = functions
    for function in functions.values():
        function.smda_report = report
    return report


class ArmPeSynthesisTests(unittest.TestCase):
    def _synthesize(self, report):
        return lief.parse(report.synthesizeBinary(output_format=FORMAT_PE, with_imports=False, with_strings=False))

    def test_a32_only_minimal_output_uses_arm_machine(self):
        code = bytes.fromhex("10402de90700a0e31080bde8")
        report = Disassembler(SmdaConfig(), backend="arm").disassembleBuffer(
            code,
            base_addr=0x1000,
            bitness=32,
            code_areas=[[0x1000, 0x100C]],
            oep=0x1000,
            architecture="arm",
        )
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_imports=False, with_strings=False)
        parsed = lief.parse(synthesized)

        self.assertEqual(int(parsed.header.machine), MACHINE_ARM)
        self.assertEqual(parsed.optional_header.addressof_entrypoint & 1, 0)
        # an open NamedTemporaryFile cannot be opened again by name on Windows
        with TemporaryDirectory() as tmp_dir:
            pe_path = os.path.join(tmp_dir, "synthesized.exe")
            with open(pe_path, "wb") as pe_file:
                pe_file.write(synthesized)
            rebuilt = Disassembler(SmdaConfig(), backend="arm").disassembleFile(pe_path)
        self.assertEqual(rebuilt.architecture, "arm")
        self.assertTrue(any(not function.architecture_metadata.get("thumb") for function in rebuilt.getFunctions()))

    def test_thumb_entry_is_tagged_in_the_minimal_pe_header(self):
        report = _make_report(
            {0x1000: _make_function(0x1000, [("7047", "bx", "lr")], thumb=True)}, 0x1000, thumb_entry=True
        )
        blob = report.synthesizeBinary(output_format=FORMAT_PE, with_imports=False, with_strings=False)
        parsed = lief.parse(blob)
        e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
        entry_rva = struct.unpack_from("<I", blob, e_lfanew + 24 + 16)[0]

        self.assertEqual(int(parsed.header.machine), MACHINE_ARMNT)
        self.assertEqual(entry_rva & 1, 1)

    def test_thumb_fallback_entry_uses_function_mode_metadata(self):
        report = _make_report({0x1000: _make_function(0x1000, [("7047", "bx", "lr")], thumb=True)}, 0x1000)
        report.oep = None
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_imports=False, with_strings=False)
        parsed = lief.parse(synthesized)

        self.assertEqual(parsed.optional_header.addressof_entrypoint & 1, 1)

    def test_thumb_fallback_entry_points_to_the_function_after_alignment_padding(self):
        report = _make_report({0x1012: _make_function(0x1012, [("7047", "bx", "lr")], thumb=True)}, 0x1012)
        report.oep = None
        parsed = self._synthesize(report)

        self.assertEqual(parsed.optional_header.imagebase + parsed.optional_header.addressof_entrypoint, 0x1013)

    def test_mixed_mode_output_uses_interworking_capable_arm_machine(self):
        report = _make_report(
            {
                0x1000: _make_function(0x1000, [("04e02de5", "stmdb", "sp!, {lr}")]),
                0x1010: _make_function(0x1010, [("7047", "bx", "lr")], thumb=True),
            },
            0x1000,
        )
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_imports=False, with_strings=False)
        parsed = lief.parse(synthesized)

        self.assertEqual(int(parsed.header.machine), MACHINE_ARM)

    def test_incompatible_armnt_source_machine_is_corrected_for_a32(self):
        thumb_report = _make_report(
            {0x1000: _make_function(0x1000, [("7047", "bx", "lr")], thumb=True)}, 0x1000, thumb_entry=True
        )
        a32_report = _make_report({0x1000: _make_function(0x1000, [("04e02de5", "stmdb", "sp!, {lr}")])}, 0x1000)
        a32_report.xheader = thumb_report.synthesizeBinary(
            output_format=FORMAT_PE, with_imports=False, with_strings=False
        )

        self.assertEqual(int(self._synthesize(a32_report).header.machine), MACHINE_ARM)

    def test_compatible_legacy_arm_source_machine_is_preserved_for_thumb(self):
        a32_report = _make_report({0x1000: _make_function(0x1000, [("1eff2fe1", "bx", "lr")])}, 0x1000)
        thumb_report = _make_report({0x1000: _make_function(0x1000, [("7047", "bx", "lr")], thumb=True)}, 0x1000)
        thumb_report.xheader = a32_report.synthesizeBinary(
            output_format=FORMAT_PE, with_imports=False, with_strings=False
        )

        parsed = self._synthesize(thumb_report)
        self.assertEqual(int(parsed.header.machine), MACHINE_ARM)
        self.assertEqual(parsed.optional_header.addressof_entrypoint & 1, 1)


class ArmApiThunkTests(unittest.TestCase):
    def _function(self, instructions):
        report = SmdaReport()
        report.architecture = "arm"
        function = _make_function(
            0x1000,
            [("00000000", mnemonic, operands) for mnemonic, operands in instructions],
        )
        function.smda_report = report
        function.apirefs = {function.blocks[0x1000][-1].offset: ("KERNEL32.dll", "ExitProcess")}
        return function

    def test_argument_setting_wrapper_is_not_an_api_thunk(self):
        function = self._function([("mov", "r0, #1"), ("ldr", "pc, [pc, #0x10]")])
        mismatched_transfer = self._function(
            [("movw", "ip, #0x1234"), ("movt", "ip, #0x5678"), ("add", "ip, pc"), ("mov", "pc, r0")]
        )

        self.assertFalse(function.isApiThunk())
        self.assertFalse(mismatched_transfer.isApiThunk())

    def test_literal_pc_load_is_an_api_thunk(self):
        function = self._function([("ldr", "pc, [pc, #0x10]")])

        self.assertTrue(function.isApiThunk())

    def test_a_conditional_transfer_is_not_an_unconditional_api_thunk(self):
        self.assertFalse(self._function([("ldreq", "pc, [pc, #0x10]")]).isApiThunk())

    def test_thumb_to_arm_import_veneer_is_an_api_thunk(self):
        self.assertTrue(self._function([("bx", "pc")]).isApiThunk())

    def test_plt_and_msvc_import_thunks_are_recognized(self):
        plt = self._function([("add", "ip, pc, #0x10"), ("add", "ip, ip, #0x20"), ("ldr", "pc, [ip, #0x30]!")])
        msvc = self._function([("movw", "ip, #0x1234"), ("movt", "ip, #0x5678"), ("ldr", "ip, [ip]"), ("bx", "ip")])
        veneer = self._function([("movw", "ip, #0x1234"), ("movt", "ip, #0x5678"), ("add", "ip, pc"), ("bx", "ip")])
        thumb = self._function([("movw", "r3, #0x1234"), ("movt", "r3, #0x5678"), ("ldr.w", "r3, [r3]"), ("bx", "r3")])

        self.assertTrue(plt.isApiThunk())
        self.assertTrue(msvc.isApiThunk())
        self.assertTrue(veneer.isApiThunk())
        self.assertTrue(thumb.isApiThunk())


if __name__ == "__main__":
    unittest.main()
