import hashlib
import struct
import unittest

from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import LazyIntKeyDict, SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport


class TestCommonModels(unittest.TestCase):
    def test_lazy_int_key_dict_materializes_for_comparison_and_repr(self):
        expected = {1: "one", 2: "two"}

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertFalse(lazy._is_converted)
        self.assertEqual(lazy, expected)
        self.assertTrue(lazy._is_converted)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(expected, lazy)
        self.assertTrue(lazy._is_converted)

        left = LazyIntKeyDict({"1": "one", "2": "two"})
        right = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(left, right)
        self.assertTrue(left._is_converted)
        self.assertTrue(right._is_converted)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertFalse(lazy != expected)
        self.assertTrue(lazy._is_converted)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(repr(lazy), "{1: 'one', 2: 'two'}")
        self.assertTrue(lazy._is_converted)

    def test_empty_basic_block_string_is_safe(self):
        self.assertEqual(str(SmdaBasicBlock([])), "0x????????: (   0)")

    def test_report_without_disassembly_has_empty_cfg(self):
        # reports built without a disassembly (e.g. controlled error reports
        # for unsupported architectures) must expose an empty CFG, not crash
        report = SmdaReport()
        self.assertEqual(report.num_functions, 0)
        self.assertIsNone(report.getFunction(0x1000))
        self.assertEqual(list(report.getFunctions()), [])

    def test_report_without_disassembly_serializes(self):
        # such a report must also survive toDict() (no xmetadata/timestamp crash)
        report_dict = SmdaReport().toDict()
        self.assertEqual(report_dict["xcfg"], {})
        self.assertEqual(report_dict["xmetadata"], {})
        self.assertEqual(report_dict["timestamp"], "")
        # and round-trip back through fromDict without a strptime("") crash
        restored = SmdaReport.fromDict(report_dict)
        self.assertIsNone(restored.timestamp)
        self.assertEqual(restored.num_functions, 0)

    def test_function_hash_helpers_use_little_endian(self):
        function = SmdaFunction()
        function.pic_hash = 0x0102030405060708
        function.getPicHashSequence = lambda binary_info: b"pic-sequence"
        function.getOpcHashSequence = lambda: b"opc-sequence"

        self.assertEqual(function.getPicHashAsHex(), struct.pack("<Q", function.pic_hash).hex())
        self.assertEqual(
            function.getPicHash(None),
            struct.unpack("<Q", hashlib.sha256(b"pic-sequence").digest()[:8])[0],
        )
        self.assertEqual(
            function.getOpcHash(),
            struct.unpack("<Q", hashlib.sha256(b"opc-sequence").digest()[:8])[0],
        )

    def test_num_calls_and_returns_count_prefixed_mnemonics(self):
        # capstone prepends mandatory prefixes (bnd/rep/lock/...) to the mnemonic string;
        # a bnd-prefixed call/ret must still be counted as such.
        function = SmdaFunction()
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "f2e80b100000", "bnd call", "0x1010")),
                SmdaInstruction((0x1006, "f2c3", "bnd ret", "")),
            ]
        }

        self.assertEqual(function.num_calls, 1)
        self.assertEqual(function.num_returns, 1)

    def test_is_api_thunk_recognizes_prefixed_jump(self):
        # a single bnd-prefixed jmp/call through an API reference is still a thunk.
        function = SmdaFunction()
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "f2ff25", "bnd jmp", "dword ptr [0x2000]"))]}
        function.apirefs = {0x1000: ("kernel32.dll", "ExitProcess")}

        self.assertTrue(function.isApiThunk())

    def test_aarch64_num_calls_and_returns(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "94000001", "bl", "#0x1004")),
                SmdaInstruction((0x1004, "d63f0000", "blr", "x0")),
                SmdaInstruction((0x1008, "d65f0bff", "retaa", "")),
            ]
        }

        self.assertEqual(function.num_calls, 2)
        self.assertEqual(function.num_returns, 1)

    def test_aarch64_num_returns_counts_pac_and_exception_returns(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "d65f0fff", "retab", "")),
            ],
            0x1004: [
                SmdaInstruction((0x1004, "d69f0bff", "eretaa", "")),
            ],
        }

        self.assertEqual(function.num_returns, 2)

    def test_aarch64_is_api_thunk_recognizes_branch(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "d61f0200", "br", "x16"))]}
        function.apirefs = {0x1000: ("libc.so", "printf")}

        self.assertTrue(function.isApiThunk())

        function.blocks = {0x1000: [SmdaInstruction((0x1000, "14000000", "b", "#0x1000"))]}
        self.assertTrue(function.isApiThunk())

    def test_aarch64_is_api_thunk_recognizes_multi_insn_plt(self):
        # ELF/Mach-O import stubs are adrp+ldr(+add)+br, optionally prefixed with bti/nop.
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x402000
        function.blocks = {
            0x402000: [
                SmdaInstruction((0x402000, "d503245f", "bti", "c")),
                SmdaInstruction((0x402004, "b0000010", "adrp", "x16, #0x403000")),
                SmdaInstruction((0x402008, "f9400e11", "ldr", "x17, [x16, #0x18]")),
                SmdaInstruction((0x40200C, "91006210", "add", "x16, x16, #0x18")),
                SmdaInstruction((0x402010, "d61f0220", "br", "x17")),
            ]
        }
        function.apirefs = {0x402010: ("libc.so", "puts")}

        self.assertTrue(function.isApiThunk())

        # A real function body (stp frame + bl) with an API ref is not a thunk.
        function.blocks = {
            0x402000: [
                SmdaInstruction((0x402000, "a9bf7bfd", "stp", "x29, x30, [sp, #-0x10]!")),
                SmdaInstruction((0x402004, "94000001", "bl", "#0x402008")),
                SmdaInstruction((0x402008, "d65f03c0", "ret", "")),
            ]
        }
        function.apirefs = {0x402004: ("libc.so", "puts")}
        self.assertFalse(function.isApiThunk())

    def test_aarch64_is_api_thunk_rejects_argument_setting_wrapper(self):
        # A wrapper that sets up an argument before tail-branching to an import
        # is a real function, not an import stub - mov/movz/movk/movn/ldp never
        # appear in a genuine ELF/Mach-O import-stub body.
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "52800020", "mov", "w0, #1")),
                SmdaInstruction((0x1004, "14000000", "b", "#0x1004")),
            ]
        }
        function.apirefs = {0x1004: ("libc.so", "exit")}

        self.assertFalse(function.isApiThunk())

    def test_cil_num_calls_counts_callvirt_and_calli(self):
        report = SmdaReport()
        report.architecture = "cil"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "28", "call", "0x06000001")),
                SmdaInstruction((0x1005, "6f", "callvirt", "0x0a000002")),
                SmdaInstruction((0x100A, "29", "calli", "0x11000003")),
                SmdaInstruction((0x100F, "2a", "ret", "")),
            ]
        }

        self.assertEqual(function.num_calls, 3)
        self.assertEqual(function.num_returns, 1)

    def test_cil_is_api_thunk_recognizes_callvirt(self):
        report = SmdaReport()
        report.architecture = "cil"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "6f", "callvirt", "0x0a000002"))]}
        function.apirefs = {0x1000: ("mscorlib.dll", "WriteLine")}

        self.assertTrue(function.isApiThunk())

    def test_dalvik_is_api_thunk_recognizes_invoke(self):
        report = SmdaReport()
        report.architecture = "dalvik"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "6e10", "invoke-virtual", "{v0}, Ljava/io/PrintStream;"))]}
        function.apirefs = {0x1000: ("Ljava/io/PrintStream;", "println")}

        self.assertTrue(function.isApiThunk())


if __name__ == "__main__":
    unittest.main()
