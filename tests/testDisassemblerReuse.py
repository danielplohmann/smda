import unittest

from smda.Disassembler import Disassembler


class TestDisassemblerReuse(unittest.TestCase):
    X86 = bytes([0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3])  # push rbp; mov rbp, rsp; pop rbp; ret
    ARM = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

    def test_fresh_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        report = d.disassembleBuffer(self.ARM, 0x400000, bitness=64, architecture="arm")
        self.assertEqual(report.status, "error")

    def test_reused_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        first = d.disassembleBuffer(self.X86, 0x400000, bitness=64, architecture="intel")
        self.assertEqual(first.status, "ok")
        self.assertEqual(first.architecture, "intel")

        second = d.disassembleBuffer(self.ARM, 0x400000, bitness=64, architecture="arm")
        self.assertEqual(second.status, "error")


if __name__ == "__main__":
    unittest.main()
