import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiPythiaProvider import (
    MAX_INTERFACE_METHOD_SCAN,
    DelphiClassInfo,
    DelphiPythiaProvider,
)
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.LanguageAnalyzer import LanguageAnalyzer
from smda.SmdaConfig import SmdaConfig

CORPUS = Path(__file__).parent / "delphi_corpus"


def load_fixture(bitness):
    fixture = json.loads((CORPUS / f"inno-7.1.0-tobject-{bitness}.json").read_text())
    data = bytearray(fixture["size"])
    for offset, hex_data in fixture["segments"]:
        segment = bytes.fromhex(hex_data)
        data[offset : offset + len(segment)] = segment
    info = BinaryInfo(bytes(data))
    info.base_addr = fixture["base_addr"]
    info.bitness = fixture["bitness"]
    info.code_areas = fixture["code_areas"]
    return info, fixture


def image(bitness=32, vmt=0x201, metadata=0x500, method_target=0x1100):
    size = bitness // 8
    base = 0x400000 if bitness == 32 else 0x140000000
    jump = 88 if bitness == 32 else 200
    data = bytearray(0x2000)
    data[:2] = b"MZ"
    data[0x80:0x87] = b"TObject"

    def ptr(offset, value):
        struct.pack_into("<I" if size == 4 else "<Q", data, offset, value)

    def string(offset, value):
        value = value.encode("latin-1")
        data[offset : offset + len(value) + 1] = bytes([len(value)]) + value

    ptr(vmt, base + vmt + jump)
    ptr(vmt + 6 * size, base + metadata)
    ptr(vmt + 4 * size, base + 0x400)
    ptr(vmt + 8 * size, base + 0x380)
    string(0x380, "TWidget")
    data[0x400] = 7
    string(0x401, "TWidget")
    ptr(0x409, base + vmt + jump)
    ptr(0x409 + size, 0)
    string(0x409 + 2 * size + 2, "Example")
    for field in range(11, 22):
        ptr(vmt + field * size, 0 if field == 14 else base + method_target)
    struct.pack_into("<HH", data, metadata, 0, 1)
    ptr(metadata + 4, base + 0x700)
    string(0x700 + size + 2, "Create")
    signature = 0x700 + size + 2 + 7
    data[signature : signature + 2] = b"\x03\x00"
    ptr(signature + 2, 0)
    data[signature + size + 4] = 1
    param = signature + size + 6
    ptr(param, base + 0x3F0)
    ptr(0x3F0, base + 0x400)
    string(param + size + 2, "Self")
    end = param + size + 2 + 5
    struct.pack_into("<H", data, 0x700, end - 0x700)
    ptr(0x702, base + method_target)
    data[method_target] = 0xC3
    info = BinaryInfo(bytes(data))
    info.base_addr = base
    info.bitness = bitness
    info.code_areas = [(base + 0x1000, base + 0x1800)]
    return info, SimpleNamespace(
        vmt=vmt, metadata=metadata, method=0x700, signature=signature, param=param, ptr=ptr, data=data
    )


def mutate(info, layout):
    info.binary = bytes(layout.data)
    return info


def add_bare_vmt(info, layout, vmt=0xA00):
    """Add a second validated VMT with no RTTI or method table, sharing the first one's name and code."""
    size = info.bitness // 8
    jump = 88 if size == 4 else 200
    layout.ptr(vmt, info.base_addr + vmt + jump)
    layout.ptr(vmt + 8 * size, info.base_addr + 0x380)
    for field in range(11, 22):
        layout.ptr(vmt + field * size, 0 if field == 14 else info.base_addr + 0x1100)
    return mutate(info, layout)


@pytest.mark.parametrize("bitness", [32, 64])
def test_real_tobject_metadata(bitness):
    info, fixture = load_fixture(bitness)
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert provider.getFunctionSymbols() == {int(addr): name for addr, name in fixture["symbols"].items()}
    for addr, name in provider.getFunctionSymbols().items():
        assert provider.getSymbol(addr) == name
        assert name.isprintable()


@pytest.mark.parametrize("bitness", [32, 64])
def test_unaligned_vmt_in_data_and_class_rtti_without_padding(bitness):
    info, _ = image(bitness)
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create(Self: Example.TWidget): void"


def test_methods_can_live_in_a_second_code_region():
    info, _ = image()
    info.code_areas.insert(0, (info.base_addr + 0x900, info.base_addr + 0xA00))
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert provider.is_active()


def test_bad_code_range_does_not_disable_valid_ranges():
    info, _ = image()
    info.code_areas.insert(0, (info.base_addr - 1, info.base_addr))
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert provider.is_active()


def test_metadata_may_precede_vmt():
    info, _ = image(vmt=0x900)
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert provider.is_active()


def test_external_ancestor_does_not_corrupt_namespace():
    info, layout = image()
    layout.ptr(0x40D, 0x70000000)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100).startswith("Example.TWidget.Create(")


def test_published_entries_precede_extended_references():
    info, layout = image()
    data = layout.data
    table = layout.metadata
    entry = struct.pack("<HI", 2 + 4 + 1 + 4, info.base_addr + 0x1120) + b"\x04Free"
    struct.pack_into("<H", data, table, 1)
    data[table + 2 : table + 2 + len(entry)] = entry
    struct.pack_into("<H", data, table + 2 + len(entry), 1)
    layout.ptr(table + 4 + len(entry), info.base_addr + layout.method)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1120) == "Example.TWidget.Free"
    assert provider.getSymbol(info.base_addr + 0x1100).startswith("Example.TWidget.Create(")


@pytest.mark.parametrize("target", [0, 0x400100, 0x80000000])
def test_method_targets_must_be_executable(target):
    info, layout = image()
    layout.ptr(layout.method + 2, target)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert not provider.is_active()


def test_corrupt_signature_preserves_name_without_reading_next_record():
    info, layout = image()
    struct.pack_into("<H", layout.data, layout.method, 13)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create"


def test_corrupt_parameter_count_preserves_name():
    info, layout = image()
    layout.data[layout.signature + 8] = 255
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create"


def test_invalid_return_type_is_unknown_instead_of_void():
    info, layout = image()
    layout.ptr(layout.signature + 2, 0x80000000)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100).endswith(": ?")


def test_control_characters_never_enter_symbol_candidate_map():
    info, layout = image()
    layout.data[layout.method + 7] = 0
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getFunctionSymbols() == {}


def test_printable_non_ascii_names_are_preserved():
    info, layout = image()
    layout.data[layout.method + 7] = 0xDC
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert ".Üreate(" in provider.getSymbol(info.base_addr + 0x1100)


def test_truncated_vmt_cannot_pass_missing_pointer_checks():
    info, layout = image()
    info.binary = info.binary[: layout.vmt + 50]
    info.code_areas = [(info.base_addr, info.base_addr + len(info.binary))]
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert not provider.is_active()


def test_scan_matches_bytewise_oracle_at_every_alignment():
    for residue in range(8):
        info, _ = image(64, vmt=0x200 + residue)
        provider = DelphiReSymProvider(None)
        provider.update(info)
        expected = [
            off
            for off in range(len(info.binary) - 8 + 1)
            if provider._read_ptr(off) == info.base_addr + off + 200 and provider._check_vmt_candidate(off, off + 200)
        ]
        with patch.object(provider, "_read_ptr", wraps=provider._read_ptr) as read:
            assert list(provider._find_vmts()) == expected == [0x200 + residue]
            assert read.call_count < 128


def test_metadata_budget_bounds_alias_expansion():
    info, layout = image()
    struct.pack_into("<H", layout.data, layout.metadata + 2, 300)
    for index in range(300):
        layout.ptr(layout.metadata + 4 + index * 8, info.base_addr + layout.method)
    config = SmdaConfig()
    config.MAX_DELPHI_METADATA_ENTRIES = 5
    provider = DelphiReSymProvider(config)
    with patch.object(provider, "_extract_method_info", wraps=provider._extract_method_info) as extract:
        provider.update(mutate(info, layout))
        assert extract.call_count <= 5
        assert provider._remaining_entries == 0


def test_zero_metadata_budget_skips_image_scan():
    info, _ = image()
    config = SmdaConfig()
    config.MAX_DELPHI_METADATA_ENTRIES = 0
    provider = DelphiReSymProvider(config)
    with patch.object(provider, "_find_vmts", side_effect=AssertionError("scan should be skipped")):
        provider.update(info)
    assert provider.getFunctionSymbols() == {}


def test_pythia_parses_shared_method_table_once():
    base = 0x400000
    target = base + 0x1100
    data = bytearray(0x2000)
    table = 0x500
    entry = struct.pack("<HI", 10, target) + b"\x03Run"
    struct.pack_into("<H", data, table, 1)
    data[table + 2 : table + 2 + len(entry)] = entry
    info = BinaryInfo(bytes(data))
    info.base_addr = base
    info.bitness = 32
    info.code_areas = [(base + 0x1000, base + 0x1800)]
    provider = DelphiPythiaProvider(None)
    provider._binary_info = info
    provider._binary = info.binary
    provider._base_addr = base
    provider._bitness = 32
    provider._scan_ranges = [(0, len(data))]
    classes = [
        DelphiClassInfo(method_table_addr=base + table),
        DelphiClassInfo(method_table_addr=base + table),
    ]
    with (
        patch.object(provider, "_scan_code_range", return_value=classes),
        patch.object(provider, "_read_word", wraps=provider._read_word) as read_word,
    ):
        provider._parse_delphi_objects()
    assert read_word.call_count == 2
    assert provider.getFunctionSymbols() == {target: "Run"}


def test_pythia_keeps_class_with_external_ancestor():
    base = 0x400000
    data = bytearray(0x2000)
    info = BinaryInfo(bytes(data))
    info.base_addr = base
    info.bitness = 32
    info.code_areas = [(base + 0x200, base + 0x1800)]
    provider = DelphiPythiaProvider(None)
    provider._binary_info = info
    provider._binary = info.binary
    provider._base_addr = base
    provider._bitness = 32
    profile = provider._profiles[32][0]
    candidate = 0x200

    def put_pointer(offset, value):
        struct.pack_into("<I", data, offset, value)

    put_pointer(candidate + profile.class_name_field_offset, base + 0x900)
    put_pointer(candidate + profile.instance_size_field_offset, 0x100)
    put_pointer(candidate + 10 * profile.ptr_size, 0x70000000)
    for index in range(profile.fixed_method_count):
        put_pointer(candidate + profile.fixed_method_offset + index * 4, base + 0x1100)
    data[0x900:0x907] = b"\x06TChild"
    provider._binary = bytes(data)
    class_info = provider._build_class_info(profile, candidate, len(data))
    assert class_info is not None
    assert class_info.method_slots == [base + 0x1100] * profile.fixed_method_count


def test_pythia_method_name_cannot_read_past_entry():
    info, _ = image()
    data = bytearray(info.binary)
    table = 0x500
    target = info.base_addr + 0x1100
    struct.pack_into("<HHI", data, table, 1, 7, target)
    data[table + 8 : table + 13] = b"\x04Evil"
    info.binary = bytes(data)
    provider = DelphiPythiaProvider(None)
    provider._binary_info = info
    provider._binary = info.binary
    provider._base_addr = info.base_addr
    provider._bitness = 32
    offsets = set()
    names = {}
    provider._extract_method_table_symbols(DelphiClassInfo(method_table_addr=info.base_addr + table), offsets, names)
    assert offsets == {target}
    assert names == {}


def test_pythia_bounds_interface_method_walk():
    base = 0x400000
    data = bytearray(0x5000)
    info = BinaryInfo(bytes(data))
    info.base_addr = base
    info.bitness = 32
    info.code_areas = [(base + 0x1000, base + 0x1800)]
    provider = DelphiPythiaProvider(None)
    provider._binary_info = info
    provider._binary = info.binary
    provider._base_addr = base
    provider._bitness = 32
    table = 0x100
    methods = 0x400
    target = base + 0x1100
    struct.pack_into("<I", data, table + 20, base + methods)
    for index in range(MAX_INTERFACE_METHOD_SCAN):
        struct.pack_into("<I", data, methods + index * 4, target)
    provider._binary = bytes(data)
    offsets = set()
    with patch.object(provider, "_read_ptr", wraps=provider._read_ptr) as read_ptr:
        provider._extract_interface_methods(DelphiClassInfo(interface_table_addr=base + table), offsets)
    assert offsets == {target}
    assert read_ptr.call_count == MAX_INTERFACE_METHOD_SCAN + 1


def test_pythia_skips_non_x86_architectures():
    info, _ = image()
    info.architecture = "arm"
    provider = DelphiPythiaProvider(None)
    with patch.object(provider, "_parse_delphi_objects") as parse:
        provider.update(info)
    parse.assert_not_called()


def test_update_clears_symbols_and_caches_between_images():
    info, _ = image()
    provider = DelphiReSymProvider(None)
    provider.update(info)
    expected = provider.getFunctionSymbols().copy()
    provider.update(BinaryInfo(b""))
    assert provider.getFunctionSymbols() == {}
    provider.update(info)
    assert provider.getFunctionSymbols() == expected


def test_language_analyzer_reuses_already_updated_delphi_providers():
    info, _ = image()
    resym = DelphiReSymProvider(None)
    resym.update(info)
    pythia = DelphiPythiaProvider(None)
    pythia._func_symbols = {info.base_addr + 0x1100: ""}
    analyzer = LanguageAnalyzer(
        SimpleNamespace(binary_info=info), {DelphiReSymProvider: resym, DelphiPythiaProvider: pythia}
    )
    with patch.object(resym, "update") as update_resym, patch.object(pythia, "update") as update_pythia:
        assert analyzer.getDelphiReSymObjects() is resym.getFunctionSymbols()
        assert analyzer.getDelphiObjects() is pythia.getFunctionSymbols()
        assert analyzer.checkDelphi()
        update_resym.assert_not_called()
        update_pythia.assert_not_called()


def test_zero_parameter_static_method_is_not_dropped():
    info, layout = image()
    layout.data[layout.signature + 8] = 0
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create"


def test_duplicate_parameter_names_discard_only_the_signature():
    info, layout = image()
    layout.data[layout.signature + 8] = 2
    second = layout.param + 4 + 2 + 5 + 3
    layout.data[second : second + 11] = layout.data[layout.param : layout.param + 11]
    struct.pack_into("<H", layout.data, layout.method, second + 11 - layout.method)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create"


def test_engine_runs_delphi_metadata_extraction_once():
    from smda.Disassembler import Disassembler

    info, _ = image()
    calls = []
    original = DelphiReSymProvider._find_vmts

    def find_vmts(provider):
        calls.append(provider)
        return original(provider)

    with patch.object(DelphiReSymProvider, "_find_vmts", find_vmts):
        report = Disassembler().disassembleBuffer(
            info.binary, info.base_addr, bitness=info.bitness, code_areas=info.code_areas
        )
    assert len(calls) == 1
    assert report.getFunction(info.base_addr + 0x1100).function_name.startswith("Example.TWidget.Create")


def test_architecture_gate_excludes_arm_pe_images():
    info, _ = image(64)
    info.architecture = "aarch64"
    provider = DelphiReSymProvider(None)
    provider.update(info)
    assert not provider.is_active()


def test_utf8_method_names_use_byte_lengths_for_signature_offsets():
    info, layout = image()
    layout.data[layout.method + 7 : layout.method + 13] = "Créer".encode()
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Créer(Self: Example.TWidget): void"


def test_utf8_class_and_parameter_names_use_byte_lengths():
    info, layout = image()
    layout.data[0x402:0x409] = "TÜbung".encode()
    layout.data[layout.param + 7 : layout.param + 11] = "Sèf".encode()
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TÜbung.Create(Sèf: Example.TÜbung): void"


@pytest.mark.parametrize("bitness", [32, 64])
@pytest.mark.parametrize("base", [0, 0x400000, 0x40FF80, 0xFFFFFF00, 0x140000000, 0xFFFFFFFFFFFFFFF0])
def test_scan_prefilter_preserves_candidates_across_address_carries(bitness, base):
    from smda.common.labelprovider.DelphiReSymProvider import ArchitectureSettings

    size = bitness // 8
    jump = 88 if bitness == 32 else 200
    data = bytearray(0x24000)
    for offset in (0, 1, 0xFF00, 0xFF7F, 0xFFFF, 0x10000, 0x10009, len(data) - size):
        expected = base + offset + jump
        if expected < 1 << bitness:
            struct.pack_into("<I" if size == 4 else "<Q", data, offset, expected)
    provider = DelphiReSymProvider(None)
    provider._binary = bytes(data)
    provider._base_addr = base
    provider._settings = ArchitectureSettings(size, jump)
    oracle = [offset for offset in range(len(data) - size + 1) if provider._read_ptr(offset) == base + offset + jump]
    with patch.object(provider, "_check_vmt_candidate", return_value=True):
        assert list(provider._find_vmts()) == oracle


def test_named_tkunknown_type_is_preserved():
    info, layout = image()
    layout.ptr(layout.signature + 2, info.base_addr + 0x840)
    layout.ptr(0x840, info.base_addr + 0x850)
    layout.data[0x850:0x858] = b"\x00\x06TOther"
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100).endswith(": TOther")


@pytest.mark.parametrize("bitness", [32, 64])
def test_structural_resym_metadata_is_delphi_language_evidence(bitness):
    info = add_bare_vmt(*image(bitness))
    analyzer = LanguageAnalyzer(SimpleNamespace(binary_info=info))
    assert analyzer.getDelphiObjects() == {}
    assert analyzer.checkDelphi()
    assert analyzer.delphi_resym_resolver.getVmtCount() == 2


def test_single_resym_vmt_is_not_delphi_language_evidence():
    info, _ = image()
    analyzer = LanguageAnalyzer(SimpleNamespace(binary_info=info))
    assert analyzer.getDelphiReSymObjects()
    assert analyzer.delphi_resym_resolver.getVmtCount() == 1
    assert not analyzer.checkDelphi()


def test_pdb_supplement_does_not_erase_delphi_symbols():
    from smda.common.RecursiveDisassembler import RecursiveDisassembler
    from smda.intel.X86Backend import X86Backend

    info, _ = image()
    engine = RecursiveDisassembler(SmdaConfig(), X86Backend())
    engine._updateLabelProviders(info)
    expected = engine.resolveSymbol(info.base_addr + 0x1100)
    assert expected
    with patch("smda.common.labelprovider.PdbSymbolProvider.PdbSymbolProvider.update"):
        engine.addPdbFile(info, "symbols.pdb")
        engine._updateLabelProviders(info)
    engine._symbol_cache.clear()
    assert engine.resolveSymbol(info.base_addr + 0x1100) == expected


@pytest.mark.parametrize("bitness", [32, 64])
def test_missing_class_rtti_preserves_class_and_method_name(bitness):
    info, layout = image(bitness)
    layout.ptr(layout.vmt + 4 * (bitness // 8), 0)
    provider = DelphiReSymProvider(None)
    provider.update(mutate(info, layout))
    assert provider.getSymbol(info.base_addr + 0x1100) == "TWidget.Create(Self: Example.TWidget): void"


@pytest.mark.parametrize("bitness", [32, 64])
def test_real_fixed_methods_survive_removal_of_extended_metadata(bitness):
    info, fixture = load_fixture(bitness)
    data = bytearray(info.binary)
    size = bitness // 8
    struct.pack_into("<I" if size == 4 else "<Q", data, fixture["vmt_offset"] + 6 * size, 0)
    info.binary = bytes(data)
    info.code_areas = [(info.base_addr + fixture["vmt_offset"], info.base_addr + len(data))]
    provider = DelphiPythiaProvider(None)
    provider.update(info)
    fixed_targets = {
        struct.unpack_from("<I" if size == 4 else "<Q", data, fixture["vmt_offset"] + field * size)[0]
        for field in range(11, 22)
        if field != 14
    }
    assert fixed_targets <= set(provider.getFunctionSymbols())


def test_metadata_budget_preserves_already_parsed_methods():
    info, layout = image()
    struct.pack_into("<H", layout.data, layout.metadata + 2, 10)
    for index in range(10):
        layout.ptr(layout.metadata + 4 + index * 8, info.base_addr + layout.method)
    config = SmdaConfig()
    config.MAX_DELPHI_METADATA_ENTRIES = 5
    provider = DelphiReSymProvider(config)
    provider.update(mutate(info, layout))
    assert provider._remaining_entries == 0
    assert provider.getSymbol(info.base_addr + 0x1100) == "Example.TWidget.Create(Self: Example.TWidget): void"
