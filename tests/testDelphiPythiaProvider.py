import logging
import struct
import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.LanguageAnalyzer import LanguageAnalyzer


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
                (parent_candidate_offset, class_name_parent_offset, b"\x07TObject", 0x401300),
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
        self.assertEqual(analyzer.getDelphiScore(), 0.9)
        self.assertTrue(analyzer.checkDelphi())

    def test_provider_registered_as_engine_symbol_provider(self):
        from smda.common.RecursiveDisassembler import RecursiveDisassembler
        from smda.intel.X86Backend import X86Backend
        from smda.SmdaConfig import SmdaConfig

        engine = RecursiveDisassembler(SmdaConfig(), X86Backend())
        provider_types = {type(provider) for provider in engine.symbol_providers}

        self.assertIn(DelphiPythiaProvider, provider_types)
        self.assertNotIn(DelphiPythiaProvider, {type(provider) for provider in engine.api_providers})


class TestDelphiReSymDeadEndLogging(unittest.TestCase):
    """Both paths run after the MZ + TObject signature match, so they are real dead ends."""

    def setUp(self):
        # another test module's import-time logging.disable() would hide these records
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    @staticmethod
    def _delphi_binary_info(code_areas):
        binary = bytearray(0x2000)
        binary[:2] = b"MZ"
        binary[0x100:0x107] = b"TObject"
        binary_info = BinaryInfo(bytes(binary))
        binary_info.base_addr = 0x400000
        binary_info.bitness = 32
        binary_info.code_areas = code_areas
        return binary_info

    def test_a_binary_without_code_areas_is_reported_at_warning(self):
        provider = DelphiReSymProvider(None)

        with self.assertLogs("smda.common.labelprovider.DelphiReSymProvider", level="WARNING") as logged:
            provider.update(self._delphi_binary_info([]))

        self.assertIn("No code areas found", logged.output[0])

    def test_out_of_bounds_code_area_offsets_are_reported_at_warning(self):
        provider = DelphiReSymProvider(None)

        with self.assertLogs("smda.common.labelprovider.DelphiReSymProvider", level="WARNING") as logged:
            provider.update(self._delphi_binary_info([(0x400000, 0x409000)]))

        self.assertIn("out of bounds", logged.output[0])


class TestDelphiReSymNegativeOffsets(unittest.TestCase):
    def test_method_entry_below_the_image_is_rejected(self):
        parser = DelphiReSymProvider.__new__(DelphiReSymProvider)
        parser._binary = b"\x41" * 0x100
        parser._base_addr = 0x400000
        parser._settings = SimpleNamespace(ptr_size=4, jump_dist=0)

        self.assertIsNone(parser._extract_method_info(-1))


class TestDelphiTableWalksStopAtTheImageEdge(unittest.TestCase):
    """Both walks take their entry count from a 16-bit field in the image, so a corrupt or
    hostile table declares up to 65535 entries. The read offset only grows, so the first
    unreadable entry means every later one is unreadable too: the walk has to stop there
    instead of running out the declared count."""

    def test_dynamic_method_walk_stops_at_the_image_edge(self):
        provider = DelphiPythiaProvider.__new__(DelphiPythiaProvider)
        provider._base_addr = 0x400000
        provider._bitness = 32
        provider._binary_info = SimpleNamespace(isInCodeAreas=lambda addr: True)
        table_length = 0xFFFF
        # the pointer array follows the 2-byte count plus one word per declared entry
        pointers_offset = 2 + 2 * table_length
        binary = bytearray(pointers_offset + 8)
        binary[0:2] = struct.pack("<H", table_length)
        binary[pointers_offset : pointers_offset + 8] = struct.pack("<II", 0x401000, 0x402000)
        provider._binary = bytes(binary)
        reads = []
        read_ptr = provider._read_ptr
        provider._read_ptr = lambda offset, ptr_size: reads.append(offset) or read_ptr(offset, ptr_size)
        class_info = SimpleNamespace(dynamic_table_addr=provider._base_addr)
        function_offsets = set()

        provider._extract_dynamic_methods(class_info, function_offsets)

        self.assertEqual(function_offsets, {0x401000, 0x402000})
        self.assertEqual(len(reads), 3)

    def test_method_definition_table_walk_stops_at_the_image_edge(self):
        provider = DelphiReSymProvider.__new__(DelphiReSymProvider)
        provider._base_addr = 0x400000
        provider._settings = SimpleNamespace(ptr_size=4, jump_dist=0)
        entry_stride = provider._settings.ptr_size + 4
        binary = bytearray(4 + 2 * entry_stride)
        binary[2:4] = struct.pack("<H", 0xFFFF)
        binary[4:8] = struct.pack("<I", 0x401000)
        binary[4 + entry_stride : 8 + entry_stride] = struct.pack("<I", 0x402000)
        provider._binary = bytes(binary)
        provider._extract_method_info = lambda offset: {"offset": offset}
        reads = []
        read_ptr = provider._read_ptr
        provider._read_ptr = lambda offset: reads.append(offset) or read_ptr(offset)

        methods = provider._parse_mdt(0)

        self.assertEqual(methods, [{"offset": 0x1000}, {"offset": 0x2000}])
        self.assertEqual(len(reads), 3)


if __name__ == "__main__":
    unittest.main()
