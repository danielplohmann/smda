import struct
import unittest

from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

BASE_ADDR = 0x140000000
BINARY_SIZE = 0x4000
PDATA_OFFSET = 0x1000


class MockBinaryInfo:
    def __init__(self, bitness, base_addr, binary, pdata_size=0):
        self.bitness = bitness
        self.base_addr = base_addr
        self.binary = binary
        self.code_areas = []
        self.pdata_size = pdata_size

    def getSections(self):
        # yields name, start, end
        if self.pdata_size > 0:
            # .pdata at 0x1000
            yield ".pdata", self.base_addr + PDATA_OFFSET, self.base_addr + PDATA_OFFSET + self.pdata_size


class PdataExtractionTestSuite(unittest.TestCase):
    def test_pdata_candidates(self):
        config = SmdaConfig()
        fcm = FunctionCandidateManager(config)

        # Entry format: Start RVA, End RVA, Unwind RVA
        entries = [(0x2000, 0x2040, 0x3000), (0x2050, 0x2090, 0x3010), (0x2100, 0x2150, 0x3020)]

        pdata_bytes = b"".join(struct.pack("III", *entry) for entry in entries)

        # Fill binary with zeros
        binary_size = BINARY_SIZE
        binary = bytearray(binary_size)

        # Place pdata at 0x1000
        binary[PDATA_OFFSET : PDATA_OFFSET + len(pdata_bytes)] = pdata_bytes

        # Initialize Mock Disassembly and BinaryInfo
        disasm = DisassemblyResult()
        disasm.binary_info = MockBinaryInfo(64, BASE_ADDR, bytes(binary), pdata_size=len(pdata_bytes))

        fcm.init(disasm)

        candidates = fcm.candidates

        self.assertIn(BASE_ADDR + 0x2000, candidates)
        self.assertIn(BASE_ADDR + 0x2050, candidates)
        self.assertIn(BASE_ADDR + 0x2100, candidates)
        self.assertEqual(len(candidates), 3)

    def test_pdata_with_zero_entry(self):
        config = SmdaConfig()
        fcm = FunctionCandidateManager(config)

        entries = [
            (0x2000, 0x2040, 0x3000),
            (0, 0, 0),  # Zero entry
            (0x2100, 0x2150, 0x3020),
        ]

        pdata_bytes = b"".join(struct.pack("III", *entry) for entry in entries)

        binary = bytearray(BINARY_SIZE)
        binary[PDATA_OFFSET : PDATA_OFFSET + len(pdata_bytes)] = pdata_bytes

        disasm = DisassemblyResult()
        disasm.binary_info = MockBinaryInfo(64, BASE_ADDR, bytes(binary), pdata_size=len(pdata_bytes))

        fcm.init(disasm)

        candidates = fcm.candidates
        self.assertIn(BASE_ADDR + 0x2000, candidates)
        self.assertNotIn(BASE_ADDR + 0x2100, candidates)
        self.assertNotIn(BASE_ADDR, candidates)
        self.assertEqual(len(candidates), 1)

    def test_pdata_misaligned_size(self):
        config = SmdaConfig()
        fcm = FunctionCandidateManager(config)

        entries = [(0x2000, 0x2040, 0x3000)]

        pdata_bytes = b"".join(struct.pack("III", *entry) for entry in entries)

        # Add some extra bytes to make it misaligned (not multiple of 12)
        pdata_bytes += b"\x90\x90"

        binary = bytearray(BINARY_SIZE)
        binary[PDATA_OFFSET : PDATA_OFFSET + len(pdata_bytes)] = pdata_bytes

        disasm = DisassemblyResult()
        disasm.binary_info = MockBinaryInfo(64, BASE_ADDR, bytes(binary), pdata_size=len(pdata_bytes))

        fcm.init(disasm)

        candidates = fcm.candidates
        self.assertIn(BASE_ADDR + 0x2000, candidates)
        self.assertEqual(len(candidates), 1)


if __name__ == "__main__":
    unittest.main()
