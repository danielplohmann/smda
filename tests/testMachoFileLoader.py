import struct
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
    def __init__(
        self,
        virtual_address=0x1000,
        virtual_size=4,
        file_size=4,
        file_offset=0,
        content=b"CODE",
        init_protection=0,
    ):
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.file_size = file_size
        self.file_offset = file_offset
        self.content = content
        self.init_protection = init_protection


class _MachoSlice:
    imagebase = 0x1000
    sections = []
    segments = [_Segment()]
    header = SimpleNamespace(cpu_type=lief.MachO.Header.CPU_TYPE.X86_64, is_64bit=True)


class _Section:
    def __init__(self, virtual_address, size, flags, alignment=1):
        self.virtual_address = virtual_address
        self.size = size
        self.flags = SimpleNamespace(value=flags)
        self.alignment = alignment


class _MappableSection(SimpleNamespace):
    """Section double carrying the fields MachoFileLoader.mapBinary actually reads."""

    def __init__(self, virtual_address, size, offset, content, alignment=1, flags=0):
        super().__init__(
            virtual_address=virtual_address,
            size=size,
            offset=offset,
            content=content,
            alignment=alignment,
            flags=SimpleNamespace(value=flags),
        )


class _MappableSlice(SimpleNamespace):
    # the loader's helpers are @lru_cache-decorated on the parsed object, so it must be
    # hashable; SimpleNamespace's structural __eq__ otherwise makes it unhashable
    def __init__(self, sections, segments, imagebase=0x8000):
        super().__init__(sections=sections, segments=segments, imagebase=imagebase)

    def __hash__(self):
        return id(self)


def _decode_xored_fixture(path):
    xored = path.read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(xored))


def _build_fat_macho(slices):
    """Build a standard big-endian 32-bit fat header around real thin slices."""
    alignment = 0x1000
    header_size = 8 + 20 * len(slices)
    next_offset = (header_size + alignment - 1) & ~(alignment - 1)
    entries = []
    payloads = []
    for cpu_type, cpu_subtype, raw in slices:
        entries.append(struct.pack(">IIIII", cpu_type, cpu_subtype, next_offset, len(raw), 12))
        payloads.append((next_offset, raw))
        next_offset = (next_offset + len(raw) + alignment - 1) & ~(alignment - 1)

    result = bytearray(struct.pack(">II", 0xCAFEBABE, len(slices)) + b"".join(entries))
    for offset, raw in payloads:
        result.extend(b"\x00" * (offset - len(result)))
        result.extend(raw)
    return bytes(result)


class TestMachoFileLoader(unittest.TestCase):
    def test_is_compatible_accepts_thin_and_fat_magics(self):
        thin_le = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
        thin_be = (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
        for magic in thin_le + thin_be:
            self.assertTrue(MachoFileLoader.isCompatible(magic + b"\x00" * 16), magic.hex())

        # Real universal binary on this host (if present)
        true_path = Path("/usr/bin/true")
        if true_path.is_file():
            raw = true_path.read_bytes()
            if raw[:4] == b"\xca\xfe\xba\xbe":
                self.assertTrue(MachoFileLoader.isCompatible(raw))
                self.assertTrue(MachoFileLoader.getHasBackend(raw) or MachoFileLoader.getArchitecture(raw))

        # Java class files share FAT_MAGIC but must not match
        java = b"\xca\xfe\xba\xbe\x00\x00\x00\x37" + b"\x00" * 64
        self.assertFalse(MachoFileLoader.isCompatible(java))

    def test_unsupported_cpu_metadata_has_no_backend(self):
        selected = _MachoSlice()
        selected.header = SimpleNamespace(cpu_type=lief.MachO.Header.CPU_TYPE.POWERPC, is_64bit=False)
        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            self.assertEqual(MachoFileLoader.getArchitecture(b"", parsed=object()), "ppc")
            self.assertEqual(MachoFileLoader.getBitness(b"", parsed=object()), 32)
            self.assertFalse(MachoFileLoader.getHasBackend(b"", parsed=object()))

    def test_unsupported_macho_arch_yields_controlled_error_report(self):
        # Valid minimal Mach-O executable headers: these pass through actual
        # compatibility checks, LIEF parsing, loader metadata, and public API
        # dispatch without executing fixture content.
        headers = {
            "ppc": struct.pack(">IIIIIII", 0xFEEDFACE, 18, 0, 2, 0, 0, 0),
            "arm": struct.pack("<IIIIIII", 0xFEEDFACE, 12, 0, 2, 0, 0, 0),
        }
        for architecture, raw in headers.items():
            with self.subTest(architecture=architecture):
                loader = MemoryFileLoader(raw, map_file=True)
                self.assertEqual(loader.getArchitecture(), architecture)
                self.assertEqual(loader.getBitness(), 32)
                self.assertFalse(loader.getHasBackend())

                report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(raw)
                self.assertEqual(report.status, "error")
                self.assertEqual(report.num_functions, 0)
                self.assertEqual(list(report.getFunctions()), [])
                self.assertEqual(report.toDict()["status"], "error")
                self.assertIn(f"No disassembly backend available for architecture '{architecture}'", report.message)

    def test_fat_universal_system_binary_loads_when_present(self):
        true_path = Path("/usr/bin/true")
        if not true_path.is_file():
            self.skipTest("/usr/bin/true not available")
        raw = true_path.read_bytes()
        if raw[:4] != b"\xca\xfe\xba\xbe":
            self.skipTest("/usr/bin/true is not a fat/universal Mach-O on this host")

        self.assertTrue(MachoFileLoader.isCompatible(raw))
        loader = MemoryFileLoader(raw, map_file=True)
        self.assertIn(loader.getArchitecture(), ("intel", "aarch64"))
        self.assertTrue(loader.getHasBackend())
        self.assertTrue(loader.getBitness() in (32, 64))
        self.assertTrue(loader.getData())
        self.assertTrue(loader.getCodeAreas())

        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(raw)
        self.assertEqual(report.status, "ok")
        self.assertIn(report.architecture, ("intel", "aarch64"))
        self.assertGreater(report.num_functions, 0)

    def test_fat_corpus_slices_are_preserved_and_first_slice_is_loaded(self):
        tests_dir = Path(__file__).resolve().parent
        intel_raw = _decode_xored_fixture(tests_dir / "komplex_xored")
        arm_raw = _decode_xored_fixture(
            tests_dir / "aarch64_macho_corpus" / "objective-see" / "BlueNoroff_469fd8a280e8.xored"
        )
        raw = _build_fat_macho(
            [
                (0x01000007, 3, intel_raw),  # CPU_TYPE_X86_64
                (0x0100000C, 0, arm_raw),  # CPU_TYPE_ARM64
            ]
        )

        parsed = MachoFileLoader.parseBinary(raw)
        self.assertIsInstance(parsed, lief.MachO.FatBinary)
        self.assertEqual(len(parsed), 2)

        loader = MemoryFileLoader(raw, map_file=True)
        self.assertEqual(loader.getArchitecture(), "intel")
        self.assertEqual(loader.getBitness(), 64)
        self.assertTrue(loader.getHasBackend())

        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(raw)
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "intel")
        self.assertEqual(report.bitness, 64)
        self.assertGreater(report.num_functions, 0)

    def test_reloading_unrecognized_data_clears_loader_metadata(self):
        raw = _decode_xored_fixture(Path(__file__).resolve().parent / "komplex_xored")
        loader = MemoryFileLoader(raw, map_file=True)
        self.assertEqual(loader.getArchitecture(), "intel")
        self.assertTrue(loader.getHasBackend())

        loader._loadFile(b"not a recognized binary")

        self.assertEqual(loader.getData(), b"")
        self.assertEqual(loader.getBaseAddress(), 0)
        self.assertEqual(loader.getBitness(), 0)
        self.assertEqual(loader.getAbi(), "")
        self.assertEqual(loader.getArchitecture(), "")
        self.assertFalse(loader.getHasBackend())
        self.assertEqual(loader.getCodeAreas(), [])

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

    def test_code_areas_include_executable_segments(self):
        exec_prot = int(lief.MachO.SegmentCommand.VM_PROTECTIONS.X)
        selected = _MachoSlice()
        selected.sections = []
        selected.segments = [
            _Segment(virtual_address=0x100000000, virtual_size=0x8000, init_protection=exec_prot | 1),
            _Segment(virtual_address=0x100008000, virtual_size=0x1000, init_protection=3),
        ]

        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            areas = MachoFileLoader.getCodeAreas(b"", parsed=object())

        self.assertEqual(areas, [[0x100000000, 0x100008000]])

    def test_instruction_sections_take_precedence_over_broad_executable_segment(self):
        exec_prot = int(lief.MachO.SegmentCommand.VM_PROTECTIONS.X)
        ins_flags = lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS.value
        selected = _MachoSlice()
        selected.sections = [_Section(0x100004000, 0x5000, ins_flags)]
        selected.segments = [_Segment(virtual_address=0x100000000, virtual_size=0xC000, init_protection=exec_prot | 1)]

        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            areas = MachoFileLoader.getCodeAreas(b"", parsed=object())

        self.assertEqual(areas, [[0x100004000, 0x100009000]])

    def test_get_has_backend_for_supported_cpu(self):
        selected = _MachoSlice()
        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            self.assertTrue(MachoFileLoader.getHasBackend(b"", parsed=object()))

        selected.header = SimpleNamespace(cpu_type=lief.MachO.Header.CPU_TYPE.POWERPC, is_64bit=False)
        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            self.assertFalse(MachoFileLoader.getHasBackend(b"", parsed=object()))

    def test_map_binary_clamps_header_copy_to_truncated_raw_binary(self):
        # min_raw_offset (from segment.file_offset) is larger than the raw
        # binary actually supplied; the header-copy slice must clamp to the
        # shorter of the two instead of shrinking mapped_binary via a
        # length-mismatched bytearray slice assignment.
        selected = _MachoSlice()
        selected.sections = []
        # virtual_address 0x1600 (rva 0x600, since imagebase/base_addr is 0x1000) is
        # deliberately placed AFTER the header-copy region (clamped to 0x100, well
        # below min_raw_offset's 0x500) so the two writes don't land on the same
        # bytes -- mapBinary() always maps the header last, so a segment write that
        # overlaps the header region gets overwritten by design, independent of this
        # fix; that's a distinct, unrelated behavior from the length-clamp under test.
        selected.segments = [
            _Segment(
                virtual_address=0x1600,
                virtual_size=0x2000,
                file_size=4,
                file_offset=0x500,
                content=b"CODE",
            )
        ]
        expected_len = 0x3000  # align((0x1600 + 0x2000) - 0x1000, 0x1000)
        truncated_binary = b"\x00" * 0x100  # shorter than min_raw_offset (0x500)

        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            mapped = MachoFileLoader.mapBinary(truncated_binary, parsed=object())

        self.assertEqual(len(mapped), expected_len)
        self.assertEqual(mapped[0x600:0x604], b"CODE")

    def test_map_binary_clamps_segment_write_to_buffer_capacity(self):
        # mapped_binary's capacity is sized from virtual_size, but a
        # crafted/corrupted segment can declare a file_size far larger than
        # that capacity while still self-consistently matching its own
        # content length; the write must clamp to the buffer's remaining
        # capacity instead of growing/corrupting mapped_binary.
        selected = _MachoSlice()
        selected.sections = []
        oversized_content = b"X" * 0x2000
        selected.segments = [
            _Segment(
                virtual_address=0x1000,
                virtual_size=0x100,
                file_size=len(oversized_content),
                file_offset=0,
                content=oversized_content,
            )
        ]
        expected_len = 0x1000  # align(max_virtual_address - base_addr, 0x1000)

        with mock.patch(
            "smda.utility.MachoFileLoader.get_active_macho_binary",
            return_value=selected,
        ):
            mapped = MachoFileLoader.mapBinary(b"", parsed=object())

        self.assertEqual(len(mapped), expected_len)
        self.assertEqual(mapped[:4], b"XXXX")

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
        binary_info.has_backend = loader.getHasBackend()
        binary_info.oep = binary_info.getOep()

        config = SmdaConfig()
        config.WITH_STRINGS = False
        controlled = Disassembler(config, backend="intel")._disassemble(binary_info)
        unmapped = Disassembler(config).disassembleUnmappedBuffer(raw)

        self.assertTrue(loader.getHasBackend())
        self.assertTrue(binary_info.has_backend)
        self.assertTrue(any(start <= 0x100006C80 < end for start, end in loader.getCodeAreas()))
        self.assertEqual(unmapped.status, "ok")
        self.assertEqual(unmapped.architecture, "intel")
        self.assertEqual(unmapped.bitness, 64)
        self.assertEqual(unmapped.base_addr, 0x100000000)
        self.assertEqual(unmapped.oep, 0x6C80)
        self.assertEqual(unmapped.getFunction(unmapped.base_addr + unmapped.oep).function_name, "_main")
        self.assertEqual(controlled.num_functions, unmapped.num_functions)
        self.assertEqual(controlled.xmetadata, unmapped.xmetadata)

    def test_calculate_base_address_rejects_negative_candidates(self):
        # a section whose offset exceeds its virtual address yields a negative base
        # candidate; accepting it would make getBaseAddress() negative, shifting every
        # reported VA and inflating mapBinary's virtual_size by the same amount.
        sections = [
            _MappableSection(virtual_address=0x8000, size=0x100, offset=0, content=b"\x11" * 0x100),
            _MappableSection(virtual_address=0x7F00, size=0x200, offset=0x8000, content=b"\x22" * 0x200),
        ]
        macho = _MappableSlice(sections=sections, segments=[])

        self.assertEqual(MachoFileLoader.getBaseAddress(b"", parsed=macho), 0x8000)

    def test_map_binary_skips_sections_below_the_base_address(self):
        # with the negative candidate filtered, the base stays 0x8000 and the second
        # section maps at rva == -0x100. An unguarded negative slice start wraps to the
        # end of the buffer and the length-mismatched assignment grows mapped_binary.
        sections = [
            _MappableSection(virtual_address=0x8000, size=0x100, offset=0, content=b"\x11" * 0x100),
            _MappableSection(virtual_address=0x7F00, size=0x200, offset=0x8000, content=b"\x22" * 0x200),
        ]
        macho = _MappableSlice(sections=sections, segments=[])

        mapped = MachoFileLoader.mapBinary(b"", parsed=macho)

        self.assertEqual(len(mapped), 0x1000)
        self.assertNotIn(b"\x22", mapped)

    def test_map_binary_zero_pads_short_section_content(self):
        # short content used to skip the section entirely; ELF zero-pads it instead
        sections = [
            _MappableSection(virtual_address=0x1000, size=0x100, offset=0x1000, content=b"\x55" * 0x40),
        ]
        macho = _MappableSlice(sections=sections, segments=[])

        mapped = MachoFileLoader.mapBinary(b"", parsed=macho)

        self.assertEqual(mapped[0x1000:0x1040], b"\x55" * 0x40)
        self.assertEqual(mapped[0x1040:0x1100], b"\x00" * 0xC0)


if __name__ == "__main__":
    unittest.main()
