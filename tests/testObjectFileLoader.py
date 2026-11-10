import hashlib
import json
import os
import struct
from pathlib import Path

import lief
import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.MemoryFileLoader import MemoryFileLoader
from smda.utility.ObjectFileLoader import ObjectImage, ObjectSection, ObjectSymbol, load_object


def elf_object(
    bits=64,
    padding=False,
    external=False,
    common=False,
    relocation=None,
    alpha_name="alpha",
    alpha_body=None,
    alpha_size=None,
    call_offset=1,
):
    wide = bits == 64
    body = alpha_body or bytes.fromhex("e800000000554889e531c05dc3" if wide else "e8000000005589e531c05dc3")
    prefix = bytes([0x90]) * 16 if padding else b""
    alpha = prefix + body
    beta = bytes.fromhex("8b0500000000c3" if wide else "a100000000c3")
    labels = [
        "",
        ".text.alpha",
        ".text.beta",
        ".data",
        ".bss",
        ".strtab",
        ".symtab",
        ".rela.text.alpha" if wide else ".rel.text.alpha",
        ".rela.text.beta" if wide else ".rel.text.beta",
        ".shstrtab",
    ]
    section_names = b"\0"
    name_offsets = []
    for label in labels:
        name_offsets.append(len(section_names))
        section_names += label.encode() + b"\0"
    symbols = [
        ("", 0, 0, 0, 0),
        (alpha_name, 1, len(prefix), alpha_size or len(body), 0x12),
        ("beta", 2, 0, len(beta), 0x12),
        ("data", 3, 0, 4, 0x11),
        ("bss", 4, 0, 32, 0x11),
        ("outside", 0, 0, 0, 0x12),
    ]
    if padding:
        symbols.append(("padding_without_a_special_prefix", 1, 0, len(prefix), 0x12))
        symbols.append(("alpha_alias", 1, len(prefix), len(body), 0x12))
    if common:
        symbols.append(("common", 0xFFF2, 8, 24, 0x11))
    names = b"\0"
    symtab = b""
    for name, section, value, size, info in symbols:
        offset = len(names)
        names += name.encode() + b"\0"
        symtab += (
            struct.pack("<IBBHQQ", offset, info, 0, section, value, size)
            if wide
            else struct.pack("<IIIBBH", offset, value, size, info, 0, section)
        )
    call_symbol = 5 if external else 2
    call_kind = relocation if relocation is not None else (4 if wide else 2)
    if wide:
        call = struct.pack("<QQq", len(prefix) + call_offset, (call_symbol << 32) | call_kind, -4)
        read = struct.pack("<QQq", 2, (3 << 32) | 2, -4)
    else:
        alpha = bytearray(alpha)
        alpha[len(prefix) + 1 : len(prefix) + 5] = struct.pack("<i", -4)
        call = struct.pack("<II", len(prefix) + 1, (call_symbol << 8) | call_kind)
        read = struct.pack("<II", 1, (3 << 8) | 1)
    payloads = [b"", bytes(alpha), beta, b"\x78\x56\x34\x12", b"", names, symtab, call, read, section_names]
    kinds = [0, 1, 1, 1, 8, 3, 2, 4 if wide else 9, 4 if wide else 9, 3]
    flags = [0, 6, 6, 3, 3, 0, 0, 0, 0, 0]
    links = [0, 0, 0, 0, 0, 0, 5, 6, 6, 0]
    infos = [0, 0, 0, 0, 0, 0, 1, 1, 2, 0]
    sym_width, rel_width = (24, 24) if wide else (16, 8)
    entry_sizes = [0, 0, 0, 0, 0, 0, sym_width, rel_width, rel_width, 0]
    data = bytearray(64 if wide else 52)
    headers = []
    for index, payload in enumerate(payloads):
        while len(data) % 8:
            data.append(0)
        offset = len(data)
        data.extend(payload)
        headers.append(
            (
                name_offsets[index],
                kinds[index],
                flags[index],
                0,
                offset,
                32 if index == 4 else len(payload),
                links[index],
                infos[index],
                8,
                entry_sizes[index],
            )
        )
    shoff = len(data)
    for header in headers:
        data.extend(struct.pack("<IIQQQQIIQQ" if wide else "<IIIIIIIIII", *header))
    data[:16] = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    fmt = "<HHIQQQIHHHHHH" if wide else "<HHIIIIIHHHHHH"
    struct.pack_into(
        fmt,
        data,
        16,
        1,
        62 if wide else 3,
        1,
        0,
        0,
        shoff,
        0,
        64 if wide else 52,
        0,
        0,
        64 if wide else 40,
        len(headers),
        9,
    )
    return bytes(data)


def coff_object(
    bits=64, external=False, relocation=None, alpha_name="alpha", directive=False, call_symbol=None, extra_symbols=()
):
    wide = bits == 64
    alpha = bytes.fromhex("e800000000554889e531c05dc3" if wide else "e8000000005589e531c05dc3")
    beta = bytes.fromhex("8b0500000000c3" if wide else "a100000000c3")
    sections = [
        (b".text$a", alpha, 0x60500020),
        (b".text$b", beta, 0x60500020),
        (b".data", b"\x78\x56\x34\x12", 0xC0300040),
    ]
    if directive:
        sections.append((b".drectve", b"\x55\x89\xe5\x31\xc0\xc3", 0x00100A00))
    data = bytearray(20 + len(sections) * 40)
    headers = []
    for index, (name, content, flags) in enumerate(sections):
        offset = len(data)
        data.extend(content)
        reloff, relcount = 0, 0
        if index in (0, 1):
            reloff, relcount = len(data), 1
            kind = (4 if wide else 0x14) if index == 0 else (4 if wide else 6)
            if relocation is not None and index == 0:
                kind = relocation
            symbol = (call_symbol or (5 if external else 2)) if index == 0 else 4
            data.extend(struct.pack("<IIH", 1 if index == 0 or not wide else 2, symbol, kind))
        headers.append((name.ljust(8, b"\0"), 0, 0, len(content), offset, reloff, 0, relcount, 0, flags))
    strings = bytearray(4)
    symbols = [(alpha_name, 0, 1, 0x20), ("beta", 0, 2, 0x20), ("data", 0, 3, 0), ("outside", 0, 0, 0x20)]
    symoff = len(data)
    symbol_count = 0
    for name, value, section, kind in symbols:
        raw = name.encode()
        if len(raw) > 8:
            raw = struct.pack("<II", 0, len(strings))
            strings.extend(name.encode() + b"\0")
        aux = 1 if section in (1, 2) else 0
        data.extend(struct.pack("<8sIhHBB", raw.ljust(8, b"\0"), value, section, kind, 2, aux))
        if aux:
            data.extend(struct.pack("<IIIIH", 0, len(alpha) if section == 1 else len(beta), 0, 0, 0))
        symbol_count += 1 + aux
    for name, value, section, storage, weak_target in extra_symbols:
        aux = 0 if weak_target is None else 1
        data.extend(struct.pack("<8sIhHBB", name.encode().ljust(8, b"\0"), value, section, 0, storage, aux))
        if aux:
            data.extend(struct.pack("<II10x", weak_target, 3))
        symbol_count += 1 + aux
    struct.pack_into("<I", strings, 0, len(strings))
    data.extend(strings)
    struct.pack_into("<HHIIIHH", data, 0, 0x8664 if wide else 0x14C, len(sections), 0, symoff, symbol_count, 0, 0)
    for index, header in enumerate(headers):
        struct.pack_into("<8sIIIIIIHHI", data, 20 + index * 40, *header)
    return bytes(data)


def functions_by_name(report):
    return {f.function_name: f.offset for f in report.getFunctions()}


@pytest.mark.parametrize("builder", [elf_object, coff_object])
@pytest.mark.parametrize("bits", [32, 64])
def test_section_relative_zero_symbols_resolve_and_relocations_match_targets(builder, bits):
    raw = builder(bits)
    image = load_object(raw)
    functions = {name: address for address, name in image.functions.items()}
    assert set(functions) == {"alpha", "beta"}
    assert functions["alpha"] != functions["beta"]
    assert image.relocations[0].target == functions["beta"]
    start = functions["alpha"] - image.base
    displacement = int.from_bytes(image.data[start + 1 : start + 5], "little", signed=True)
    assert functions["alpha"] + 5 + displacement == functions["beta"]
    report = Disassembler().disassembleFile("probe.o", buffer=raw)
    assert report.status == "ok", report.message
    assert report.sha256 == hashlib.sha256(raw).hexdigest()
    assert {f.function_name for f in report.getFunctions()} == {"alpha", "beta"}
    restored = SmdaReport.fromDict(json.loads(json.dumps(report.toDict())))
    assert restored.xmetadata["object_image"]["layout"] == "section-order-v1"
    assert restored.sha256 == report.sha256


@pytest.mark.parametrize("bits", [32, 64])
def test_padding_names_never_absorb_the_real_function_and_aliases_are_preserved(bits):
    raw = elf_object(bits, padding=True, external=True)
    image = load_object(raw)
    report = Disassembler().disassembleFile("probe.ko", buffer=raw)
    assert report.status == "ok", report.message
    functions = {f.function_name: f for f in report.getFunctions()}
    assert set(functions) == {"alpha", "beta"}
    alpha = functions["alpha"]
    assert alpha.num_instructions > 1
    assert "alpha_alias" in image.aliases[alpha.offset]
    assert image.is_function_interior(alpha.offset + 5)
    assert not image.is_function_interior(alpha.offset)
    assert all(not f.function_name.startswith("padding") for f in functions.values())


@pytest.mark.parametrize("builder", [elf_object, coff_object])
@pytest.mark.parametrize("bits", [32, 64])
def test_unresolved_external_calls_are_named_without_mapping_executable_stubs(builder, bits):
    image = load_object(builder(bits, external=True))
    target = image.relocations[0].target
    assert image.imports[target] == "outside"
    assert target >= image.base + len(image.data)
    assert all(not start <= target < end for start, end in image.code_areas)


@pytest.mark.parametrize("bits", [32, 64])
def test_bss_common_and_alignment_are_placed_without_consuming_raw_data(bits):
    image = load_object(elf_object(bits, common=True))
    bss = image.sections[4]
    common = next(s for s in image.symbols.values() if s.name == "common")
    assert image.data[bss.address - image.base : bss.address - image.base + 32] == bytes(32)
    assert common.address % 8 == 0
    assert image.data[common.address - image.base : common.address - image.base + 24] == bytes(24)
    assert not any(start <= bss.address < end for start, end in image.code_areas)


@pytest.mark.parametrize("builder", [elf_object, coff_object])
def test_unsupported_relocations_are_explicit_errors(builder):
    with pytest.raises(ValueError, match="Unsupported.*relocation"):
        load_object(builder(relocation=255))
    report = Disassembler().disassembleFile("unsupported.o", buffer=builder(relocation=255))
    assert report.status == "error"
    assert "relocation" in report.message


@pytest.mark.parametrize("builder", [elf_object, coff_object])
@pytest.mark.parametrize("length", [2, 18, 40, 64, 100])
def test_truncated_object_tables_are_refused(builder, length):
    raw = builder()[:length]
    if builder is coff_object or length < 18:
        assert load_object(raw) is None
    else:
        with pytest.raises(ValueError):
            load_object(raw)


def test_coff_directives_do_not_become_code_and_decorated_names_are_readable():
    raw = coff_object(alpha_name="?add@@YAHHH@Z", directive=True)
    image = load_object(raw)
    assert all(section.name != ".drectve" for section in image.sections.values())
    report = Disassembler().disassembleFile("probe.obj", buffer=raw)
    assert report.status == "ok", report.message
    assert any("add(" in f.function_name for f in report.getFunctions())


def test_loader_reuse_clears_object_metadata():
    loader = MemoryFileLoader(elf_object(), map_file=True)
    assert loader.getObjectImage() is not None
    loader._loadFile(buffer=b"unrecognized")
    assert loader.getObjectImage() is None
    assert not loader.getFormatRecognized()


def test_object_mapping_has_bounded_allocation_and_relocation_writes(monkeypatch):
    monkeypatch.setattr(SmdaConfig, "MAX_IMAGE_SIZE", 128)
    image = ObjectImage("ELF_REL", 64)
    with pytest.raises(ValueError, match="MAX_IMAGE_SIZE"):
        image.allocate(129)
    with pytest.raises(ValueError, match="alignment"):
        image.allocate(1, 3)
    image.allocate(8)
    with pytest.raises(ValueError, match="outside"):
        image.write(image.base + 7, 4, 1)
    with pytest.raises(ValueError, match="encoding"):
        image.write(image.base, 4, 1 << 32)


@pytest.mark.parametrize("builder", [elf_object, coff_object])
@pytest.mark.parametrize(
    "setting,limit,kind", [("MAX_OBJECT_SYMBOLS", 1, "symbol"), ("MAX_OBJECT_RELOCATIONS", 1, "relocation")]
)
def test_object_record_counts_are_bounded(builder, setting, limit, kind, monkeypatch):
    monkeypatch.setattr(SmdaConfig, setting, limit)
    with pytest.raises(ValueError, match=kind + " count"):
        load_object(builder())


def test_object_abi_preserves_the_elf_os_identifier():
    assert MemoryFileLoader(elf_object(), map_file=True).getAbi() == "SYSTEMV"
    raw = bytearray(elf_object())
    raw[7] = 9
    assert MemoryFileLoader(raw, map_file=True).getAbi() == "FREEBSD"
    raw[7] = 200
    assert MemoryFileLoader(raw, map_file=True).getAbi() == ""
    assert MemoryFileLoader(coff_object(), map_file=True).getAbi() == ""


def test_data_only_objects_are_not_disassembled_as_raw_code():
    raw = bytearray(coff_object())
    for index in (0, 1):
        struct.pack_into("<I", raw, 20 + index * 40 + 36, 0xC0300040)
    report = Disassembler().disassembleFile("data.obj", buffer=bytes(raw))
    assert report.status == "error"
    assert "no executable sections" in report.message


def test_archives_are_out_of_scope_and_unchanged():
    assert load_object(b"!<arch>\n") is None


def test_invalid_section_sizes_and_machine_are_not_silently_accepted():
    raw = bytearray(elf_object())
    struct.pack_into("<H", raw, 18, 183)
    with pytest.raises(ValueError, match="machine"):
        load_object(raw)
    image = ObjectImage("ELF_REL", 64, sections={1: ObjectSection(1, ".text", 1, 1, b"\xc3", True)})
    image.place()
    assert image.code_areas == [(image.base, image.base + 1)]


def test_trap_bodies_and_standalone_nops_are_not_discarded_as_prefix_padding():
    image = ObjectImage("ELF_REL", 64)
    image.sections[1] = ObjectSection(1, ".text", 3, 1, b"\xcc\xc3\x90", True)
    image.symbols = {
        0: ObjectSymbol("trap", 1, 0, 1, True),
        1: ObjectSymbol("return", 1, 1, 1, True),
        2: ObjectSymbol("standalone_nop", 1, 2, 1, True),
    }
    image.place()
    assert set(image.functions.values()) == {"trap", "return", "standalone_nop"}


def test_large_nop_extents_are_conservatively_kept_without_a_padding_decode(monkeypatch):
    import smda.utility.ObjectFileLoader as loader_module

    class NoPaddingDecoder:
        def disasm_lite(self, *args):
            pytest.fail("Large function bodies must not be decoded during padding detection")

    monkeypatch.setattr(loader_module, "Cs", lambda *args: NoPaddingDecoder())
    image = ObjectImage("ELF_REL", 64)
    image.sections[1] = ObjectSection(1, ".text", 129, 1, b"\x90" * 128 + b"\xc3", True)
    image.symbols = {0: ObjectSymbol("large_nop_body", 1, 0, 128, True), 1: ObjectSymbol("next", 1, 128, 1, True)}
    image.place()
    assert set(image.functions.values()) == {"large_nop_body", "next"}


@pytest.mark.parametrize("builder", [elf_object, coff_object])
def test_long_names_are_bounded_without_truncating_their_identity(builder, monkeypatch):
    monkeypatch.setattr(SmdaConfig, "MAX_OBJECT_NAME_LENGTH", 32)
    with pytest.raises(ValueError, match="oversized.*name"):
        load_object(builder(alpha_name="long_symbol_name_" * 8))


def test_noop_relocations_still_count_towards_the_record_limit(monkeypatch):
    monkeypatch.setattr(SmdaConfig, "MAX_OBJECT_RELOCATIONS", 1)
    with pytest.raises(ValueError, match="relocation count"):
        load_object(elf_object(relocation=0))


def test_calls_inside_sized_functions_still_seed_unnamed_callees():
    body = bytes.fromhex("554889e5e800000000e8020000005dc3b80100000083c002c3")
    raw = elf_object(alpha_body=body, alpha_size=16, call_offset=5)
    disassembler = Disassembler()
    report = disassembler.disassembleFile("probe.o", buffer=raw)
    assert report.status == "ok", report.message
    functions = {f.offset: f for f in report.getFunctions()}
    alpha = next(f for f in functions.values() if f.function_name == "alpha")
    assert alpha.num_instructions == 6
    assert functions[alpha.offset + 16].function_name == ""
    candidates = disassembler.disassembler.fc_manager.candidates
    assert candidates[alpha.offset + 16].call_ref_sources == {alpha.offset + 9}
    assert alpha.offset + 4 in candidates[functions_by_name(report)["beta"]].call_ref_sources
    assert not any(alpha.offset < address < alpha.offset + 16 for address in candidates)


def test_i386_plt_calls_are_relocated_like_pc_relative_calls():
    image = load_object(elf_object(32, relocation=4))
    functions = {name: address for address, name in image.functions.items()}
    start = functions["alpha"] - image.base
    displacement = int.from_bytes(image.data[start + 1 : start + 5], "little", signed=True)
    assert functions["alpha"] + 5 + displacement == functions["beta"]


def test_coff_absolute_relocations_wrap_negative_inline_addends():
    raw = bytearray(coff_object(32))
    position = raw.index(bytes.fromhex("a100000000c3"))
    struct.pack_into("<i", raw, position + 1, -4)
    image = load_object(bytes(raw))
    relocation = image.relocations[1]
    assert relocation.symbol == "data"
    stored = int.from_bytes(image.data[relocation.address - image.base :][:4], "little")
    assert stored == relocation.target - 4


def test_coff_debug_symbols_are_not_placed_as_common_storage():
    plain = load_object(coff_object())
    image = load_object(coff_object(extra_symbols=[(".file", 0x25, -2, 103, None)]))
    assert len(image.data) == len(plain.data)
    assert image.functions == plain.functions
    with pytest.raises(ValueError, match="unavailable symbol"):
        load_object(coff_object(call_symbol=6, extra_symbols=[(".file", 0, -2, 103, None)]))


def test_coff_weak_externals_resolve_to_their_default_without_an_import():
    chain = 2000
    weak = [(f"w{index}", 0, 0, 105, 6 + 2 * (index + 1) if index + 1 < chain else 2) for index in range(chain)]
    image = load_object(coff_object(call_symbol=6, extra_symbols=weak))
    functions = {name: address for address, name in image.functions.items()}
    assert image.relocations[0].symbol == "w0"
    assert image.relocations[0].target == functions["beta"]
    assert set(image.imports.values()) == {"outside"}
    for cycle in ([("w0", 0, 0, 105, 6)], [("w0", 0, 0, 105, 8), ("w1", 0, 0, 105, 6)]):
        with pytest.raises(ValueError, match="Cyclic"):
            load_object(coff_object(extra_symbols=cycle))
    with pytest.raises(ValueError, match="weak external symbol index"):
        load_object(coff_object(extra_symbols=[("w0", 0, 0, 105, 7)]))


@pytest.mark.parametrize("prefix", ["4c01c0c3", "6486c0c3"])
def test_raw_code_with_a_coff_machine_prefix_is_not_claimed_as_an_object(prefix):
    raw = bytes.fromhex(prefix) + bytes(60)
    assert load_object(raw) is None
    report = Disassembler(backend="intel").disassembleFile("code.bin", buffer=raw)
    assert report.status == "ok", report.message
    damaged = bytearray(coff_object())
    struct.pack_into("<I", damaged, 20 + 20, len(damaged))
    with pytest.raises(ValueError, match="Truncated"):
        load_object(bytes(damaged))


@pytest.mark.parametrize("builder", [elf_object, coff_object])
@pytest.mark.parametrize("bits", [32, 64])
def test_external_addresses_follow_the_image_instead_of_the_size_limit(builder, bits, monkeypatch):
    monkeypatch.setattr(SmdaConfig, "MAX_IMAGE_SIZE", 1 << 31)
    image = load_object(builder(bits, external=True))
    target = image.relocations[0].target
    assert image.imports[target] == "outside"
    assert image.base + len(image.data) <= target < image.base + len(image.data) + 0x10000


def test_object_metadata_is_a_detached_summary():
    image = load_object(elf_object(external=True))
    metadata = image.metadata()
    assert metadata["relocation_count"] == len(image.relocations) == 2
    assert "relocations" not in metadata
    metadata["unresolved_symbols"].clear()
    metadata["function_sizes"].clear()
    metadata["symbol_aliases"].clear()
    assert image.imports and image.function_sizes and image.aliases


@pytest.mark.skipif(
    not os.environ.get("SMDA_TEST_KO_FILE"), reason="Set SMDA_TEST_KO_FILE to the pinned Ubuntu CRC32 module"
)
def test_real_distribution_module_matches_symbol_addresses_extents_and_instruction_counts():
    raw = Path(os.environ["SMDA_TEST_KO_FILE"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "8dcf24cc22b706cc3ee8d8c3368b0ba42a45441198af5ba44c5de60be1567982"
    expected = {
        "crc32_cra_init",
        "crc32_setkey",
        "crc32_init",
        "crc32_final",
        "crc32_digest",
        "crc32_finup",
        "crc32_update",
        "crc32_mod_init",
        "crc32_mod_fini",
    }
    parsed = lief.ELF.parse(raw)
    image = load_object(raw)
    report = Disassembler().disassembleFile("crc32_generic.ko", buffer=raw)
    assert report.status == "ok", report.message
    functions = {f.function_name: f for f in report.getFunctions()}
    assert set(functions) == expected
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    original_sections = list(parsed.sections)
    for name in expected:
        symbol = next(s for s in parsed.symtab_symbols if s.name == name)
        section = image.sections[symbol.shndx]
        function = functions[name]
        assert function.offset == section.address + symbol.value
        original = bytes(original_sections[symbol.shndx].content)[symbol.value : symbol.value + symbol.size]
        assert len(list(decoder.disasm_lite(original, function.offset))) == function.num_instructions
        assert all(function.offset <= i.offset < function.offset + symbol.size for i in function.getInstructions())
    assert "init_module" in image.aliases[functions["crc32_mod_init"].offset]
    assert "cleanup_module" in image.aliases[functions["crc32_mod_fini"].offset]
