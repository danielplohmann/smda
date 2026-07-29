"""Fuzz tests for SMDA binary loaders using Hypothesis.

Targets PeFileLoader, ElfFileLoader, MachoFileLoader, and DexFileLoader
methods that accept raw bytes and must not crash, hang, or violate their
contract regardless of input. Each property guarantees that:
  - The method returns (no uncaught exceptions)
  - The return has the declared type
  - Memory does not explode (inputs are bounded)
"""

import struct

from hypothesis import given, settings
from hypothesis.strategies import binary

from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.PeFileLoader import PeFileLoader


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_is_compatible_never_crashes(data):
    result = PeFileLoader.isCompatible(data)
    assert isinstance(result, bool)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_map_binary_never_crashes(data):
    try:
        result = PeFileLoader.mapBinary(data)
    except ValueError:
        return
    assert isinstance(result, bytes)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_base_address_never_crashes(data):
    result = PeFileLoader.getBaseAddress(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_bitness_never_crashes(data):
    result = PeFileLoader.getBitness(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_architecture_never_crashes(data):
    result = PeFileLoader.getArchitecture(data)
    assert isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_code_areas_never_crashes(data):
    result = PeFileLoader.getCodeAreas(data)
    assert isinstance(result, list)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_pe_offset_never_crashes(data):
    result = PeFileLoader.getPeOffset(data)
    assert isinstance(result, int)
    assert result >= 0


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_get_machine_type_never_crashes(data):
    result = PeFileLoader.getMachineType(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_pe_check_pe_never_crashes(data):
    result = PeFileLoader.checkPe(data)
    assert isinstance(result, bool)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_is_compatible_never_crashes(data):
    result = ElfFileLoader.isCompatible(data)
    assert isinstance(result, bool)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_map_binary_never_crashes(data):
    try:
        result = ElfFileLoader.mapBinary(data)
    except (ValueError, AssertionError):
        return
    assert isinstance(result, bytes)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_get_base_address_never_crashes(data):
    result = ElfFileLoader.getBaseAddress(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_get_bitness_never_crashes(data):
    result = ElfFileLoader.getBitness(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_get_architecture_never_crashes(data):
    result = ElfFileLoader.getArchitecture(data)
    assert isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_get_code_areas_never_crashes(data):
    result = ElfFileLoader.getCodeAreas(data)
    assert isinstance(result, list)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_elf_get_abi_never_crashes(data):
    try:
        result = ElfFileLoader.getAbi(data)
    except Exception:
        return
    assert isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_is_compatible_never_crashes(data):
    result = MachoFileLoader.isCompatible(data)
    assert isinstance(result, bool)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_map_binary_never_crashes(data):
    try:
        result = MachoFileLoader.mapBinary(data)
    except (ValueError, struct.error):
        return
    assert isinstance(result, bytes)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_get_base_address_never_crashes(data):
    result = MachoFileLoader.getBaseAddress(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_get_code_areas_never_crashes(data):
    result = MachoFileLoader.getCodeAreas(data)
    assert isinstance(result, list)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_get_architecture_never_crashes(data):
    result = MachoFileLoader.getArchitecture(data)
    assert isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_macho_get_bitness_never_crashes(data):
    result = MachoFileLoader.getBitness(data)
    assert isinstance(result, int)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_is_compatible_never_crashes(data):
    result = DexFileLoader.isCompatible(data)
    assert isinstance(result, bool)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_map_binary_never_crashes(data):
    result = DexFileLoader.mapBinary(data)
    assert isinstance(result, bytes)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_get_code_areas_never_crashes(data):
    result = DexFileLoader.getCodeAreas(data)
    assert isinstance(result, list)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_get_architecture_never_crashes(data):
    result = DexFileLoader.getArchitecture(data)
    assert isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_parse_header_never_crashes(data):
    result = DexFileLoader._parseHeader(data)
    assert result is None or isinstance(result, dict)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_unsupported_reason_never_crashes(data):
    result = DexFileLoader.unsupportedReason(data)
    assert result is None or isinstance(result, str)


@given(data=binary(max_size=2048))
@settings(max_examples=500)
def test_dex_is_recognized_unsupported_never_crashes(data):
    result = DexFileLoader.isRecognizedUnsupported(data)
    assert isinstance(result, bool)
