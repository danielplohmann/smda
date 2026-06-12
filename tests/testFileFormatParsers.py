#!/usr/bin/python

import logging
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import lief

from smda.cil.CilDisassembler import CilDisassembler
from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.CilSymbolProvider import CilSymbolProvider
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig
from smda.utility.ElfFileLoader import ElfFileLoader, _resolve_elf_machine
from smda.utility.FileLoader import FileLoader
from smda.utility.MachoFileLoader import MachoFileLoader, _resolve_macho_cpu

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class SmdaIntegrationTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def _load_xored_fixture(self, fixture_name):
        with open(os.path.join(config.PROJECT_ROOT, "tests", fixture_name), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_binary = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_binary.append(byte ^ (index % 256))
        return bytes(decrypted_binary)

    def _create_binary_info(self, binary):
        loader = FileLoader("/", map_file=True)
        loader._loadFile(binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.abi = loader.getAbi()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        return binary_info

    def testPeParsingWithCutwail(self):
        disasm = Disassembler(config, backend="intel")
        cutwail_binary = self._load_xored_fixture("cutwail_xored")
        # run FileLoader and disassemble as file
        binary_info = self._create_binary_info(cutwail_binary)
        # parse bytes of 0x400 truncated PE header
        pe_header = lief.parse(binary_info.getHeaderBytes())
        assert pe_header.dos_header.magic == 0x5A4D
        assert pe_header.header.machine == 0x14C
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 33
        cutwail_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cutwail_binary)
        assert cutwail_unmapped_disassembly.num_functions == 33
        assert cutwail_unmapped_disassembly.getFunction(0x4001730).function_name == "original_entry_point"

    def testPeExportLabelExtraction(self):
        disasm = Disassembler(config, backend="intel")
        pe_export_binary = self._load_xored_fixture("pe_export_label_test_xored")
        binary_info = self._create_binary_info(pe_export_binary)

        assert binary_info.getExportedFunctions() == {0x401000: "exported_test_function"}

        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 1
        assert controlled_disassembly.getFunction(0x401000).function_name == "exported_test_function"

        unmapped_disassembly = disasm.disassembleUnmappedBuffer(pe_export_binary)
        assert unmapped_disassembly.num_functions == 1
        assert unmapped_disassembly.getFunction(0x401000).function_name == "exported_test_function"

    def testElfParsingWithBashlite(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted benign /bin/cat
        bashlite_binary = self._load_xored_fixture("bashlite_xored")
        # run FileLoader and disassemble as file
        binary_info = self._create_binary_info(bashlite_binary)
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 177
        bashlite_unmapped_disassembly = disasm.disassembleUnmappedBuffer(bashlite_binary)
        assert bashlite_unmapped_disassembly.num_functions == 177
        assert len([f.function_name for f in bashlite_unmapped_disassembly.getFunctions() if f.function_name]) == 174
        assert binary_info.abi == "SYSTEMV"
        # test section extraction
        sections = {name: (start, end) for name, start, end in binary_info.getSections()}
        assert len(sections) > 0
        assert ".text" in sections

    def testDotnetParsingWithNjRAT(self):
        disasm = Disassembler(config, backend="cil")
        # load encrypted malicious win.cutwail
        with open(os.path.join(config.PROJECT_ROOT, "tests", "njrat_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_njrat = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_njrat.append(byte ^ (index % 256))
        njrat_binary = bytes(decrypted_njrat)
        # run FileLoader and disassemble as file
        njrat_unmapped_disassembly = disasm.disassembleUnmappedBuffer(njrat_binary)
        assert njrat_unmapped_disassembly.num_functions == 64
        assert len([f.function_name for f in njrat_unmapped_disassembly.getFunctions() if f.function_name]) == 64

    def testMacOsParsingWithKomplex(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted malicious osx.komplex
        with open(os.path.join(config.PROJECT_ROOT, "tests", "komplex_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_komplex = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_komplex.append(byte ^ (index % 256))
        komplex_binary = bytes(decrypted_komplex)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(komplex_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        disasm._disassemble(binary_info)
        komplex_unmapped_disassembly = disasm.disassembleUnmappedBuffer(komplex_binary)
        self.assertEqual(komplex_unmapped_disassembly.num_functions, 211)

    def test_binary_info_and_file_loader_do_not_share_code_areas(self):
        first_binary = BinaryInfo(b"a")
        second_binary = BinaryInfo(b"b")
        first_binary.code_areas.append([1, 2])

        first_loader = FileLoader("/", load_file=False)
        second_loader = FileLoader("/", load_file=False)
        first_loader.getCodeAreas().append([3, 4])

        self.assertEqual(second_binary.code_areas, [])
        self.assertEqual(second_loader.getCodeAreas(), [])

    def test_pe_symbol_provider_returns_empty_mapping_without_code_section(self):
        symbol_provider = PeSymbolProvider(None)
        lief_binary = SimpleNamespace(sections=[], symbols=[])

        self.assertEqual(symbol_provider.parseSymbols(lief_binary), {})

    def test_go_pclntab_offset_returns_numeric_zero(self):
        provider = GoSymbolProvider(None)
        pclntab = b"\x00\xff\xff\xff\x00\x00\x01\x04"

        self.assertEqual(provider.getPcLntabOffset(pclntab), 0)

    def test_cil_disassembler_accepts_missing_timeout_callback(self):
        binary_info = BinaryInfo(b"MZ")
        fake_pe = SimpleNamespace(net=SimpleNamespace(mdtables=SimpleNamespace(MethodDef=[])))

        with mock.patch("smda.cil.CilDisassembler.dnfile.dnPE", return_value=fake_pe):
            result = CilDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertFalse(result.analysis_timeout)

    def test_cil_jmp_records_edge_without_aborting_function_analysis(self):
        class FakeInstruction:
            offset = 0x1000
            opcode = "jmp"
            operand = object()

            def get_bytes(self):
                return b"\x27\x00"

        disassembler = CilDisassembler(SmdaConfig())
        disassembler.disassembly = DisassemblyResult()
        method_body = SimpleNamespace(offset=0x1000, instructions=[FakeInstruction()])

        with mock.patch("smda.cil.CilDisassembler.format_operand", return_value="0x2000"):
            state = disassembler.analyzeFunction(None, method_body.offset, method_body)

        self.assertEqual(state.code_refs_from[0x1000], {0x2000})
        self.assertIn(0x1000, disassembler.disassembly.functions)

    def test_elf_api_resolver_uses_relocation_slot_address(self):
        resolver = ElfApiResolver(None)
        resolver._api_map["lief"][0x4018] = ("GLIBC_2.2.5", "puts")

        self.assertEqual(resolver.getApi(0x4018, absolute_addr=0x1000), ("GLIBC_2.2.5", "puts"))
        self.assertEqual(resolver.getApi(0x1000, absolute_addr=0x4018), (None, None))

    def test_cil_symbol_provider_clears_symbols_before_parse(self):
        provider = CilSymbolProvider(None)
        provider._addr_to_func_symbols[0x1000] = "stale"
        provider._func_symbol_to_addr["stale"] = 0x1000
        binary_info = BinaryInfo(b"not a dotnet file")

        with mock.patch("smda.common.labelprovider.CilSymbolProvider.dnfile.dnPE", side_effect=ValueError("bad pe")):
            provider.update(binary_info)

        self.assertEqual(provider.getFunctionSymbols(), {})
        self.assertIsNone(provider.getAddress("stale"))

    @staticmethod
    def _fake_macho(cpu_type):
        return SimpleNamespace(header=SimpleNamespace(cpu_type=cpu_type))

    def test_macho_cpu_type_resolves_architecture_bitness_and_support(self):
        cpu = lief.MachO.Header.CPU_TYPE
        # cpu_type -> (architecture, bitness, has_backend)
        cases = [
            (cpu.X86, ("intel", 32, True)),
            (cpu.X86_64, ("intel", 64, True)),
            # recognized but unsupported (no backend): metadata must stay accurate
            (cpu.ARM, ("arm", 32, False)),
            (cpu.ARM64, ("arm", 64, False)),
            (cpu.POWERPC, ("ppc", 32, False)),
            (cpu.POWERPC64, ("ppc", 64, False)),
        ]
        for cpu_type, expected in cases:
            with self.subTest(cpu_type=cpu_type):
                fake_macho = self._fake_macho(cpu_type)
                self.assertEqual(_resolve_macho_cpu(fake_macho), expected)
                self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=fake_macho), expected[0])
                self.assertEqual(MachoFileLoader.getBitness(b"", parsed=fake_macho), expected[1])

    def test_macho_unknown_cpu_type_reports_empty_metadata(self):
        # SPARC is intentionally not in the mapping -> unsupported/empty, no raise
        fake_macho = self._fake_macho(lief.MachO.Header.CPU_TYPE.SPARC)
        self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=fake_macho), "")
        self.assertEqual(MachoFileLoader.getBitness(b"", parsed=fake_macho), 0)

    def test_macho_metadata_empty_when_parse_failed(self):
        self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=None), "")
        self.assertEqual(MachoFileLoader.getBitness(b"", parsed=None), 0)

    def test_macho_fat_binary_without_header_reports_empty_metadata(self):
        # a FAT Mach-O parses to a header-less FatBinary -> unsupported, no raise
        fat_binary = SimpleNamespace(architectures=[])
        self.assertEqual(_resolve_macho_cpu(fat_binary), ("", 0, False))
        self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=fat_binary), "")
        self.assertEqual(MachoFileLoader.getBitness(b"", parsed=fat_binary), 0)

    @staticmethod
    def _fake_elf(machine_type, identity_class):
        return SimpleNamespace(header=SimpleNamespace(machine_type=machine_type, identity_class=identity_class))

    def test_elf_machine_type_resolves_architecture_bitness_and_support(self):
        # (machine_type, identity_class) -> (architecture, bitness, has_backend)
        cases = [
            (lief.ELF.ARCH.I386, lief.ELF.Header.CLASS.ELF32, ("intel", 32, True)),
            (lief.ELF.ARCH.X86_64, lief.ELF.Header.CLASS.ELF64, ("intel", 64, True)),
            # recognized but unsupported (no backend): metadata must stay accurate
            (lief.ELF.ARCH.AARCH64, lief.ELF.Header.CLASS.ELF64, ("arm", 64, False)),
            # width-ambiguous machine types: bitness comes from the ELF class
            (lief.ELF.ARCH.MIPS, lief.ELF.Header.CLASS.ELF64, ("mips", 64, False)),
            (lief.ELF.ARCH.MIPS, lief.ELF.Header.CLASS.ELF32, ("mips", 32, False)),
            (lief.ELF.ARCH.RISCV, lief.ELF.Header.CLASS.ELF64, ("riscv", 64, False)),
        ]
        for machine_type, identity_class, expected in cases:
            with self.subTest(machine_type=machine_type):
                fake_elf = self._fake_elf(machine_type, identity_class)
                self.assertEqual(_resolve_elf_machine(fake_elf), expected)
                # public accessors must agree with the central resolver
                self.assertEqual(ElfFileLoader.getArchitecture(b"", parsed=fake_elf), expected[0])
                self.assertEqual(ElfFileLoader.getBitness(b"", parsed=fake_elf), expected[1])

    def test_elf_unknown_machine_type_reports_empty_metadata(self):
        # AVR is intentionally not in the mapping -> unsupported/empty, not "intel"
        fake_elf = self._fake_elf(lief.ELF.ARCH.AVR, lief.ELF.Header.CLASS.ELF32)
        self.assertEqual(ElfFileLoader.getArchitecture(b"", parsed=fake_elf), "")
        self.assertEqual(ElfFileLoader.getBitness(b"", parsed=fake_elf), 0)

    def test_elf_metadata_empty_when_parse_failed(self):
        self.assertEqual(ElfFileLoader.getArchitecture(b"", parsed=None), "")
        self.assertEqual(ElfFileLoader.getBitness(b"", parsed=None), 0)

    def test_elf_metadata_empty_for_header_less_object(self):
        # an incomplete/unexpected parse result without a header -> unsupported, no raise
        header_less = SimpleNamespace(sections=[])
        self.assertEqual(_resolve_elf_machine(header_less), ("", 0, False))
        self.assertEqual(ElfFileLoader.getArchitecture(b"", parsed=header_less), "")
        self.assertEqual(ElfFileLoader.getBitness(b"", parsed=header_less), 0)


if __name__ == "__main__":
    unittest.main()
