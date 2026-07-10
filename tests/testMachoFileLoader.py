import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import lief

from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader


class _Segment:
    virtual_address = 0x1000
    virtual_size = 4
    file_size = 4
    file_offset = 0
    content = b"CODE"


class _MachoSlice:
    imagebase = 0x1000
    sections = []
    segments = [_Segment()]
    header = SimpleNamespace(cpu_type=lief.MachO.Header.CPU_TYPE.X86_64, is_64bit=True)


class TestMachoFileLoader(unittest.TestCase):
    def test_all_loader_accessors_use_the_selected_macho_slice(self):
        fat_binary = object()
        selected = _MachoSlice()

        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ) as get_active:
            self.assertEqual(MachoFileLoader.getBaseAddress(b"", parsed=fat_binary), 0x1000)
            self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=fat_binary), "intel")
            self.assertEqual(MachoFileLoader.getBitness(b"", parsed=fat_binary), 64)
            self.assertEqual(MachoFileLoader.getCodeAreas(b"", parsed=fat_binary), [])
            mapped = MachoFileLoader.mapBinary(b"", parsed=fat_binary)

        self.assertEqual(mapped[:4], b"CODE")
        self.assertTrue(any(call.args[0] is fat_binary for call in get_active.call_args_list))

    def test_intel_macho_mapped_and_unmapped_results_match(self):
        xored = (Path(__file__).resolve().parent / "komplex_xored").read_bytes()
        raw = bytes(byte ^ (index % 256) for index, byte in enumerate(xored))
        loader = MemoryFileLoader(raw, map_file=True)

        binary_info = BinaryInfo(loader.getData())
        binary_info.raw_data = raw
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.architecture = loader.getArchitecture()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()

        config = SmdaConfig()
        config.WITH_STRINGS = False
        controlled = Disassembler(config, backend="intel")._disassemble(binary_info)
        unmapped = Disassembler(config).disassembleUnmappedBuffer(raw)

        self.assertEqual(unmapped.status, "ok")
        self.assertEqual(unmapped.architecture, "intel")
        self.assertEqual(unmapped.bitness, 64)
        self.assertEqual(unmapped.base_addr, 0x100000000)
        self.assertEqual(unmapped.oep, 0x6C80)
        self.assertEqual(unmapped.getFunction(unmapped.base_addr + unmapped.oep).function_name, "_main")
        self.assertEqual(controlled.num_functions, unmapped.num_functions)
        self.assertEqual(controlled.xmetadata, unmapped.xmetadata)


if __name__ == "__main__":
    unittest.main()
