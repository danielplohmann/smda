import struct
import unittest
from types import SimpleNamespace

from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

BASE_ADDR = 0x140000000
BINARY_SIZE = 0x4000
PDATA_OFFSET = 0x1000
TEXT_RVA = 0x1000
PDATA_RVA = 0x2000
XDATA_RVA = 0x3000
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000


def build_x64_pe(text_bytes, pdata_entries):
    pdata_bytes = b"".join(struct.pack("<III", *entry) for entry in pdata_entries)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 240, 0x0022)
    data_directories = [(0, 0)] * 16
    data_directories[3] = (PDATA_RVA, len(pdata_bytes))
    optional_header = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        len(text_bytes),
        0,
        0,
        TEXT_RVA,
        TEXT_RVA,
        BASE_ADDR,
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x4000,
        FILE_ALIGNMENT,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_directories)

    def section_header(name, rva, virtual_size, raw_offset, characteristics):
        return struct.pack(
            "<8sIIIIIIHHI",
            name,
            virtual_size,
            rva,
            FILE_ALIGNMENT,
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )

    sections = (
        section_header(b".text", TEXT_RVA, len(text_bytes), 0x200, 0x60000020)
        + section_header(b".pdata", PDATA_RVA, len(pdata_bytes), 0x400, 0x40000040)
        + section_header(b".xdata", XDATA_RVA, 0x40, 0x600, 0x40000040)
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional_header + sections
    image = bytearray(0x800)
    image[: len(headers)] = headers
    image[0x200 : 0x200 + len(text_bytes)] = text_bytes
    image[0x400 : 0x400 + len(pdata_bytes)] = pdata_bytes
    return bytes(image)


def disassemble_x64_pe(text_bytes, pdata_entries):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    config.USE_PE_X64_PDATA_ENDS = True
    return Disassembler(config).disassembleUnmappedBuffer(build_x64_pe(text_bytes, pdata_entries))


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

    def getExceptionDirectory(self):
        # this fixture is bytes rather than a PE, so it declares no directory and the
        # section name is the only evidence of where the table is
        return None

    def getLiefBinary(self):
        # nor a parsed container, so the declared-range lookup finds no `.eh_frame` and the
        # rules built on it are inert here
        return None


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

    def test_pdata_chained_unwind_info_excluded(self):
        config = SmdaConfig()
        fcm = FunctionCandidateManager(config)

        # Entry format: Start RVA, End RVA, Unwind RVA
        entries = [
            (0x2000, 0x2040, 0x3000),  # primary entry, unwind info at 0x3000 (Flags=0)
            (0x2050, 0x2090, 0x3010),  # chained entry, unwind info at 0x3010 (UNW_FLAG_CHAININFO set)
        ]

        pdata_bytes = b"".join(struct.pack("III", *entry) for entry in entries)

        binary = bytearray(BINARY_SIZE)
        binary[PDATA_OFFSET : PDATA_OFFSET + len(pdata_bytes)] = pdata_bytes
        # UNWIND_INFO header byte 0 packs Version (bits 0-2) and Flags (bits 3-7); 0x20 sets
        # UNW_FLAG_CHAININFO (0x4) with Version 0.
        binary[0x3010] = 0x20

        disasm = DisassemblyResult()
        disasm.binary_info = MockBinaryInfo(64, BASE_ADDR, bytes(binary), pdata_size=len(pdata_bytes))

        fcm.init(disasm)

        candidates = fcm.candidates
        self.assertIn(BASE_ADDR + 0x2000, candidates)
        self.assertNotIn(BASE_ADDR + 0x2050, candidates)
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


class PdataEndSplitTestSuite(unittest.TestCase):
    def test_non_fallthrough_entry_ref_splits_at_pdata_end(self):
        text = bytearray(b"\x90" * 0x40)
        text[0x10] = 0xC3
        text[0x20:0x25] = b"\xe9" + struct.pack("<i", -0x15)
        report = disassemble_x64_pe(
            bytes(text),
            [
                (TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA),
                (TEXT_RVA + 0x10, TEXT_RVA + 0x11, XDATA_RVA + 0x10),
                (TEXT_RVA + 0x20, TEXT_RVA + 0x25, XDATA_RVA + 0x20),
            ],
        )

        self.assertEqual(report.status, "ok")
        starts = {function.offset for function in report.getFunctions()}
        self.assertIn(BASE_ADDR + TEXT_RVA, starts)
        self.assertIn(BASE_ADDR + TEXT_RVA + 0x10, starts)
        self.assertIn(BASE_ADDR + TEXT_RVA + 0x20, starts)
        first = report.getFunction(BASE_ADDR + TEXT_RVA)
        second = report.getFunction(BASE_ADDR + TEXT_RVA + 0x10)
        self.assertEqual([instruction.mnemonic for instruction in first.getInstructions()], ["nop"] * 16)
        self.assertEqual([instruction.mnemonic for instruction in second.getInstructions()], ["ret"])
        self.assertEqual(first.outrefs, {})
        self.assertIn(BASE_ADDR + TEXT_RVA + 0x20, second.inrefs)

    def test_pdata_candidate_with_only_fallthrough_ref_is_not_split(self):
        text = bytearray(b"\x90" * 0x20)
        text[0x10] = 0xC3
        report = disassemble_x64_pe(
            bytes(text),
            [
                (TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA),
                (TEXT_RVA + 0x10, TEXT_RVA + 0x11, XDATA_RVA + 0x10),
            ],
        )

        self.assertEqual(report.status, "ok")
        starts = {function.offset for function in report.getFunctions()}
        self.assertIn(BASE_ADDR + TEXT_RVA, starts)
        self.assertNotIn(BASE_ADDR + TEXT_RVA + 0x10, starts)
        merged = report.getFunction(BASE_ADDR + TEXT_RVA)
        self.assertEqual(
            [instruction.mnemonic for instruction in merged.getInstructions()],
            ["nop"] * 16 + ["ret"],
        )

    def test_existing_function_start_with_backward_block_is_not_resplit(self):
        text = bytearray(b"\x90" * 0x30)
        text[0] = 0xC3
        text[8] = 0xC3
        text[0x10:0x13] = b"\x75\xf6\xc3"
        text[0x20:0x25] = b"\xe9" + struct.pack("<i", -0x15)
        pdata_entries = [
            (TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA),
            (TEXT_RVA + 0x10, TEXT_RVA + 0x13, XDATA_RVA + 0x10),
            (TEXT_RVA + 0x20, TEXT_RVA + 0x25, XDATA_RVA + 0x20),
        ]
        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.USE_PE_X64_PDATA_ENDS = True
        disassembler = Disassembler(config)
        report = disassembler.disassembleUnmappedBuffer(build_x64_pe(bytes(text), pdata_entries))

        self.assertEqual(report.status, "ok")
        starts = {function.offset for function in report.getFunctions()}
        self.assertIn(BASE_ADDR + TEXT_RVA + 0x10, starts)
        existing = report.getFunction(BASE_ADDR + TEXT_RVA + 0x10)
        self.assertEqual(
            [instruction.offset for instruction in existing.getInstructions()],
            [BASE_ADDR + TEXT_RVA + 8, BASE_ADDR + TEXT_RVA + 0x10, BASE_ADDR + TEXT_RVA + 0x12],
        )

    def test_internal_jump_to_split_interior_preserves_disjoint_ownership(self):
        text = bytearray(b"\x90" * 0x40)
        text[0:2] = b"\x75\x0f"
        text[0x10:0x12] = b"\x90\xc3"
        text[0x20:0x25] = b"\xe9" + struct.pack("<i", 0x10 - (0x20 + 5))
        report = disassemble_x64_pe(
            bytes(text),
            [
                (TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA),
                (TEXT_RVA + 0x10, TEXT_RVA + 0x12, XDATA_RVA + 0x10),
                (TEXT_RVA + 0x20, TEXT_RVA + 0x25, XDATA_RVA + 0x20),
            ],
        )

        self.assertEqual(report.status, "ok")
        owner = report.getFunction(BASE_ADDR + TEXT_RVA)
        split = report.getFunction(BASE_ADDR + TEXT_RVA + 0x10)
        owner_addresses = {instruction.offset for instruction in owner.getInstructions()}
        split_addresses = {instruction.offset for instruction in split.getInstructions()}
        self.assertIn(BASE_ADDR + TEXT_RVA + 0x11, split_addresses)
        self.assertNotIn(BASE_ADDR + TEXT_RVA + 0x11, owner_addresses)
        self.assertTrue(owner_addresses.isdisjoint(split_addresses))

    def test_unowned_non_fallthrough_ref_does_not_authorize_split(self):
        config = SmdaConfig()
        config.USE_PE_X64_PDATA_ENDS = True
        disassembler = Disassembler(config, backend="intel").disassembler
        disassembler.disassembly.instructions = {0x1000: ("jmp", 5)}
        disassembler.disassembly.code_refs_to = {0x1010: {0x1000}}
        disassembler.disassembly.ins2fn = {}

        self.assertFalse(disassembler._hasNonFallthroughCodeRef(0x1010, 0x2000))

    def test_partition_does_not_consult_stale_data_map_bytes(self):
        text = bytearray(b"\x90" * 0x40)
        text[0x10] = 0xC3
        text[0x20:0x25] = b"\xe9" + struct.pack("<i", -0x15)
        entries = [
            (TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA),
            (TEXT_RVA + 0x10, TEXT_RVA + 0x11, XDATA_RVA + 0x10),
            (TEXT_RVA + 0x20, TEXT_RVA + 0x25, XDATA_RVA + 0x20),
        ]
        config = SmdaConfig()
        config.WITH_STRINGS = False
        disassembler = Disassembler(config)
        report = disassembler.disassembleUnmappedBuffer(build_x64_pe(bytes(text), entries))
        self.assertEqual(report.status, "ok")

        engine = disassembler.disassembler
        split_addr = BASE_ADDR + TEXT_RVA + 0x10
        engine.config.USE_PE_X64_PDATA_ENDS = True
        engine.fc_manager.pdata_start_addresses = {split_addr}
        engine.fc_manager.pdata_end_addresses = {split_addr}
        engine.disassembly.data_map.add(split_addr)

        self.assertEqual(engine._splitMergedFunctionsAtPdataEnds(), 1)
        self.assertIn(split_addr, engine.disassembly.instructions)
        self.assertEqual(engine.disassembly.ins2fn[split_addr], split_addr)
        self.assertIn(split_addr, engine.disassembly.data_map)

    def test_timeout_skips_pdata_split_pass(self):
        config = SmdaConfig()
        config.USE_PE_X64_PDATA_ENDS = True
        disassembler = Disassembler(config, backend="intel").disassembler
        disassembler.fc_manager = SimpleNamespace(pdata_start_addresses={0x1010}, pdata_end_addresses={0x1010})
        callback_calls = 0

        def timeout():
            nonlocal callback_calls
            callback_calls += 1
            return True

        self.assertEqual(disassembler._splitMergedFunctionsAtPdataEnds(timeout), 0)
        self.assertEqual(callback_calls, 1)
        self.assertTrue(disassembler.disassembly.analysis_timeout)


if __name__ == "__main__":
    unittest.main()
