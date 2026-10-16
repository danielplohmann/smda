"""Recovery quality of the 32-bit ARM backend against the symbol tables of real builds.

The fixtures are clang builds of the lz4 library with their symbol tables removed:
``arm_lz4_mixed_O2`` interleaves A32 and T32 functions at -O2, ``arm_lz4_mixed_Os``
alternates A32 and T32 object files at -Os, ``arm_lz4_thumb_Os`` is T32 at -Os, and ``armnt_lz4_dll`` is a Windows on ARM (ARMNT, T32 only) DLL importing
from kernel32. ``arm_ground_truth.json`` holds the function starts and instruction sets
the unstripped builds and the linker map name, and for the ld.lld builds the literal pools and jump
tables inside those functions, which give every instruction start. ``arm_go_stripped`` is a Go 1.24 hello world
(``println``) built with ``GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0``, ``-trimpath`` and
``-ldflags="-s -w -buildid= -R 0x1000"`` (4 KiB segment alignment instead of 64 KiB keeps the
file small; the runtime is the rest); its own pclntab, which lists the same starts as the
unstripped build's symbol table, is the truth.
"""

import functools
import json
import struct
import unittest
from pathlib import Path

import lief
import pytest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.ElfFileLoader import ElfFileLoader

pytestmark = pytest.mark.slow

FIXTURES = Path(__file__).resolve().parent
GROUND_TRUTH = json.loads((FIXTURES / "arm_ground_truth.json").read_text())


def _load(name):
    data = (FIXTURES / name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _config(**overrides):
    config = SmdaConfig()
    config.TIMEOUT = 0
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _truth(name):
    return {int(address, 16): mode == "thumb" for address, mode in GROUND_TRUTH[name]["functions"].items()}


@functools.cache
def _instructionStarts(name):
    """Each function decoded linearly in its mode up to the next start, its data skipped."""
    text = lief.ELF.parse(list(_load(name))).get_section(".text")
    code, base = bytes(text.content), text.virtual_address
    data = dict(tuple(int(bound, 16) for bound in span.split("-")) for span in GROUND_TRUTH[name]["data_in_code"])
    functions = sorted(_truth(name).items())
    ends = [start for start, _ in functions[1:]] + [base + len(code)]
    starts = {}
    for (address, thumb), end in zip(functions, ends, strict=True):
        while address < end:
            if address in data:
                address = data[address]
                continue
            starts[address] = thumb
            halfword = int.from_bytes(code[address - base : address - base + 2], "little")
            address += 2 if thumb and halfword >> 11 < 0x1D else 4
    return starts


class ArmCorpusRecoveryTest(unittest.TestCase):
    def _assertRecovery(self, name, report, recall, precision, truth=None):
        truth = _truth(name) if truth is None else truth
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "arm")
        found = {function.offset: function for function in report.getFunctions()}
        low, high = min(truth), max(truth)
        in_text = {address for address in found if low <= address <= high}
        matched = set(truth) & in_text
        self.assertGreaterEqual(len(matched) / len(truth), recall)
        self.assertGreaterEqual(len(matched) / len(in_text), precision)
        wrong_mode = [hex(a) for a in matched if found[a].architecture_metadata.get("thumb") != truth[a]]
        self.assertEqual(wrong_mode, [])
        if "data_in_code" in GROUND_TRUTH.get(name, {}):
            # every decoded instruction starts where the build put one, in the same mode
            starts = _instructionStarts(name)
            low, high = min(starts), max(starts)
            misplaced = [
                hex(instruction.offset)
                for function in report.getFunctions()
                for instruction in function.getInstructions()
                if low <= instruction.offset <= high
                and starts.get(instruction.offset) != function.architecture_metadata["thumb"]
            ]
            self.assertEqual(misplaced, [])

    def test_stripped_mixed_mode_shared_object(self):
        name = "arm_lz4_mixed_O2_xored"
        report = Disassembler(_config()).disassembleUnmappedBuffer(_load(name))
        self._assertRecovery(name, report, recall=0.98, precision=0.98)

    def test_address_taken_a32_functions_between_thumb_objects(self):
        name = "arm_lz4_mixed_Os_xored"
        report = Disassembler(_config()).disassembleUnmappedBuffer(_load(name))
        self._assertRecovery(name, report, recall=1.0, precision=0.99)

    def test_stripped_thumb_shared_object(self):
        name = "arm_lz4_thumb_Os_xored"
        report = Disassembler(_config()).disassembleUnmappedBuffer(_load(name))
        self._assertRecovery(name, report, recall=0.97, precision=0.98)

    def test_without_the_unwind_index(self):
        name = "arm_lz4_thumb_Os_xored"
        report = Disassembler(_config(USE_ARM_EXIDX_CANDIDATES=False)).disassembleUnmappedBuffer(_load(name))
        self._assertRecovery(name, report, recall=0.97, precision=0.98)

    def test_headerless_memory_image(self):
        name = "arm_lz4_thumb_Os_xored"
        raw = _load(name)
        mapped = ElfFileLoader.mapBinary(raw)
        base = ElfFileLoader.getBaseAddress(raw)
        # no container left to name the instruction set: the buffer's code has to
        mapped = b"\x00" * 0x40 + mapped[0x40:]
        report = Disassembler(_config()).disassembleBuffer(mapped, base)
        self._assertRecovery(name, report, recall=0.9, precision=0.9)

    def test_a_symbol_name_that_is_not_utf8(self):
        name = "arm_lz4_mixed_Os_xored"
        data = bytearray(_load(name))
        index = data.find(b"LZ4_compress_default\0")
        data[index + 3] = 0xFF
        report = Disassembler(_config()).disassembleUnmappedBuffer(bytes(data))
        self._assertRecovery(name, report, recall=1.0, precision=0.99)

    def test_windows_ce_exception_directory(self):
        # the ARMNT DLL relabelled as a Windows CE Thumb image (machine 0x1C2), its .pdata
        # rewritten into that layout: PrologLen:8 | FuncLen:22 (halfwords) | 32Bit:1 | Exc:1
        name = "armnt_lz4_dll_xored"
        data = bytearray(_load(name))
        pe = lief.PE.parse(list(data))
        directory = pe.data_directory(lief.PE.DataDirectory.TYPES.EXCEPTION_TABLE)
        table = pe.rva_to_offset(directory.rva)
        for index in range(0, directory.size, 8):
            unwind = struct.unpack_from("<I", data, table + index + 4)[0]
            if unwind & 3:
                length = ((unwind >> 2) & 0x7FF) * 2
            else:
                length = (struct.unpack_from("<I", data, pe.rva_to_offset(unwind))[0] & 0x3FFFF) * 2
            struct.pack_into("<I", data, table + index + 4, 6 | (length // 2) << 8)
        struct.pack_into("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4, 0x1C2)
        report = Disassembler(_config()).disassembleUnmappedBuffer(bytes(data))
        self._assertRecovery(name, report, recall=0.99, precision=0.99)

    def test_armnt_dll(self):
        name = "armnt_lz4_dll_xored"
        report = Disassembler(_config()).disassembleUnmappedBuffer(_load(name))
        self._assertRecovery(name, report, recall=0.99, precision=0.99)
        apis = {api for function in report.getFunctions() for api in function.apirefs.values()}
        self.assertTrue({"kernel32.dll!HeapAlloc", "kernel32.dll!HeapFree"} <= apis, apis)
        self.assertTrue(all(function.architecture_metadata["thumb"] for function in report.getFunctions()))

    def test_gcc_static_malware_sample(self):
        report = Disassembler(_config()).disassembleUnmappedBuffer(_load("mirai_arm_xored"))
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "arm")
        functions = {function.offset for function in report.getFunctions()}
        called = {
            int(instruction.operands.lstrip("#"), 16)
            for function in report.getFunctions()
            for instruction in function.getInstructions()
            if instruction.mnemonic in ("bl", "blx") and instruction.operands.startswith("#")
        }
        self.assertGreater(len(functions), 150)
        self.assertEqual(sorted(hex(a) for a in called - functions), [])
        self.assertFalse(any(function.architecture_metadata["thumb"] for function in report.getFunctions()))

    def test_stripped_go_image(self):
        # Go emits A32 only and fills its code with zero-word nops and with data words that
        # land in code: pclntab has to decide every start, in A32
        raw = _load("arm_go_stripped_xored")
        mapped = ElfFileLoader.mapBinary(raw)
        binary_info = BinaryInfo(mapped)
        binary_info.raw_data = raw
        binary_info.base_addr = ElfFileLoader.getBaseAddress(raw)
        provider = GoSymbolProvider(SmdaConfig())
        provider.update(binary_info)
        truth = dict.fromkeys(provider.getFunctionSymbols(), False)
        self.assertGreater(len(truth), 1000)
        report = Disassembler(_config()).disassembleUnmappedBuffer(raw)
        self._assertRecovery("arm_go_stripped_xored", report, recall=0.99, precision=0.99, truth=truth)
        self.assertFalse(any(function.architecture_metadata["thumb"] for function in report.getFunctions()))

    def test_report_round_trip_keeps_the_instruction_set(self):
        name = "arm_lz4_mixed_O2_xored"
        config = _config(CALCULATE_HASHING=True)
        report = Disassembler(config).disassembleUnmappedBuffer(_load(name))
        restored = type(report).fromDict(report.toDict())
        modes = {f.offset: f.architecture_metadata["thumb"] for f in report.getFunctions()}
        self.assertEqual({f.offset: f.architecture_metadata["thumb"] for f in restored.getFunctions()}, modes)
        self.assertTrue(any(modes.values()) and not all(modes.values()))
        hashes = {f.offset: f.pic_hash for f in report.getFunctions()}
        self.assertEqual({f.offset: f.pic_hash for f in restored.getFunctions()}, hashes)
        thumb_function = next(f for f in restored.getFunctions() if f.architecture_metadata["thumb"])
        instruction = next(thumb_function.getInstructions())
        self.assertEqual(instruction.getDetailed().address, instruction.offset)


if __name__ == "__main__":
    unittest.main()
