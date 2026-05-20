import struct
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.intel.LanguageAnalyzer import LanguageAnalyzer


class _DummyDisassembly:
    def __init__(self, binary_info):
        self.binary_info = binary_info


class TestDelphiPythiaProvider(unittest.TestCase):
    def _pack_ptr(self, value, ptr_size=4):
        return struct.pack("<I" if ptr_size == 4 else "<Q", value)

    def _build_binary_info(self, include_valid_vmt=True, invalid_method_ptr=False):
        base_addr = 0x400000
        binary = bytearray(0x3000)
        binary[:2] = b"MZ"

        parent_candidate_offset = 0x1000
        child_candidate_offset = 0x1100
        class_name_parent_offset = 0x1080
        class_name_child_offset = 0x1180
        child_interface_offset = 0x11D0
        child_interface_methods_offset = 0x1200
        child_dynamic_offset = 0x1190
        child_method_table_offset = 0x11A0
        child_vmt_offset = child_candidate_offset + 0x4C
        parent_vmt_offset = parent_candidate_offset + 0x4C

        if include_valid_vmt:
            for candidate_offset, class_name_offset, class_name, method_base in (
                (parent_candidate_offset, class_name_parent_offset, b"\x07TParent", 0x401300),
                (child_candidate_offset, class_name_child_offset, b"\x06TChild", 0x401350),
            ):
                binary[candidate_offset : candidate_offset + 4] = self._pack_ptr(base_addr + candidate_offset + 0x4C)
                binary[candidate_offset + 0x20 : candidate_offset + 0x24] = self._pack_ptr(
                    base_addr + class_name_offset
                )
                binary[candidate_offset + 0x24 : candidate_offset + 0x28] = self._pack_ptr(0x30)
                binary[class_name_offset : class_name_offset + len(class_name)] = class_name
                for slot_index in range(8):
                    slot_addr = method_base + (slot_index * 0x10)
                    if invalid_method_ptr and candidate_offset == child_candidate_offset and slot_index == 0:
                        slot_addr = 0x600000
                    slot_offset = candidate_offset + 0x2C + (slot_index * 4)
                    binary[slot_offset : slot_offset + 4] = self._pack_ptr(slot_addr)

            binary[child_candidate_offset + 0x18 : child_candidate_offset + 0x1C] = self._pack_ptr(
                base_addr + child_method_table_offset
            )
            binary[child_candidate_offset + 0x1C : child_candidate_offset + 0x20] = self._pack_ptr(
                base_addr + child_dynamic_offset
            )
            binary[child_candidate_offset + 0x04 : child_candidate_offset + 0x08] = self._pack_ptr(
                base_addr + child_interface_offset
            )
            binary[child_candidate_offset + 0x28 : child_candidate_offset + 0x2C] = self._pack_ptr(
                base_addr + parent_vmt_offset
            )

            binary[child_vmt_offset : child_vmt_offset + 4] = self._pack_ptr(0x401360)
            binary[child_vmt_offset + 4 : child_vmt_offset + 8] = self._pack_ptr(0x401370)

            binary[child_dynamic_offset : child_dynamic_offset + 2] = struct.pack("<H", 1)
            binary[child_dynamic_offset + 2 : child_dynamic_offset + 4] = struct.pack("<H", 0)
            binary[child_dynamic_offset + 4 : child_dynamic_offset + 8] = self._pack_ptr(0x4013A0)

            binary[child_interface_offset + 20 : child_interface_offset + 24] = self._pack_ptr(
                base_addr + child_interface_methods_offset
            )
            binary[child_interface_methods_offset : child_interface_methods_offset + 4] = self._pack_ptr(0x4013C0)
            binary[child_interface_methods_offset + 4 : child_interface_methods_offset + 8] = self._pack_ptr(0)

            binary[child_method_table_offset : child_method_table_offset + 2] = struct.pack("<H", 2)
            entry_offset = child_method_table_offset + 2
            for method_addr, method_name in ((0x401390, b"Init"), (0x4013B0, b"DoIt")):
                entry_size = 2 + 4 + 1 + len(method_name)
                binary[entry_offset : entry_offset + 2] = struct.pack("<H", entry_size)
                binary[entry_offset + 2 : entry_offset + 6] = self._pack_ptr(method_addr)
                binary[entry_offset + 6] = len(method_name)
                binary[entry_offset + 7 : entry_offset + 7 + len(method_name)] = method_name
                entry_offset += entry_size

        binary_info = BinaryInfo(bytes(binary))
        binary_info._lief_binary = False
        binary_info.base_addr = base_addr
        binary_info.bitness = 32
        binary_info.code_areas = [[base_addr + 0x1000, base_addr + 0x2000]]
        return binary_info

    def test_provider_recovers_symbols_from_valid_legacy_vmt(self):
        provider = DelphiPythiaProvider(None)
        provider.update(self._build_binary_info())
        symbols = provider.getFunctionSymbols()

        self.assertEqual(symbols.get(0x401390), "Init")
        self.assertEqual(symbols.get(0x4013B0), "DoIt")
        self.assertIn(0x4013A0, symbols)
        self.assertIn(0x4013C0, symbols)
        self.assertIn(0x401360, symbols)
        self.assertIn(0x401300, symbols)
        self.assertIn(0x401310, symbols)
        self.assertIn(0x401350, symbols)

    def test_provider_rejects_false_positive_candidate(self):
        provider = DelphiPythiaProvider(None)
        provider.update(self._build_binary_info(invalid_method_ptr=True))
        symbols = provider.getFunctionSymbols()

        self.assertNotIn(0x401390, symbols)
        self.assertNotIn(0x4013B0, symbols)
        self.assertIn(0x401300, symbols)

    def test_language_analyzer_preserves_get_delphi_objects_contract(self):
        binary_info = self._build_binary_info()
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary_info))

        symbols = analyzer.getDelphiObjects()

        self.assertEqual(symbols[0x401390], "Init")
        self.assertEqual(symbols[0x4013B0], "DoIt")
        self.assertEqual(symbols[0x401360], "")


if __name__ == "__main__":
    unittest.main()
