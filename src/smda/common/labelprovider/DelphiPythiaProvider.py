#!/usr/bin/python
"""
DelphiPythiaProvider - Pythia-style Delphi VMT discovery for SMDA.

The implementation below intentionally ports the *algorithmic approach* from
NCC Group's Pythia without copying its code. The goal is to keep SMDA's legacy
``getDelphiObjects()`` API intact while replacing its old whole-image scan with
an efficient code-section-only VMT scan.

Pythia-style workflow summary
-----------------------------
1. Enumerate PE code sections and scan them linearly on pointer alignment.
2. For each aligned pointer at address ``A``, treat it as a VMT candidate when
   the stored value equals ``A + distance``. The classic legacy Delphi profile
   uses ``distance == 0x4C`` on 32-bit binaries; modern profiles use larger
   fixed distances because more compiler-generated slots precede the VMT.
3. Validate the candidate aggressively before extracting anything:
   * the instance size must be reasonable,
   * the class name pointer must decode to a plausible Pascal string,
   * the fixed VMT method slots must point into executable code areas,
   * metadata pointers must stay inside the mapped image.
4. Extract the class name, parent VMT pointer, method table, dynamic table,
   and virtual method slots directly from the mapped image.
5. Compare child and parent VMT slots to identify inherited vs. overridden
   methods. SMDA's public API still only returns ``{address: function_name}``,
   but the provider keeps this relationship internally for future use.

Compared to the historic implementation, this is significantly faster on large
inputs because it scans only code sections, advances in pointer-sized steps, and
avoids repeatedly traversing unrelated data. It also improves version coverage
by supporting both classic 32-bit Delphi VMT layouts and conservative modern
profiles, including limited 64-bit handling where the VMT layout is still
compatible with the documented self-pointer scheme.
"""

import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import lief

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)

IMAGE_SCN_CNT_CODE = 0x00000020
VMT_HEADER_FIELD_COUNT = 11
MAX_INSTANCE_SIZE = 1024 * 500
MAX_VIRTUAL_SLOT_SCAN = 512


@dataclass(frozen=True)
class DelphiVmtProfile:
    """Static layout information for a Delphi VMT profile."""

    name: str
    bitness: int
    self_ptr_distance: int
    optional_zero_slots: Tuple[int, ...] = ()

    @property
    def ptr_size(self) -> int:
        return 4 if self.bitness == 32 else 8

    @property
    def fixed_method_offset(self) -> int:
        return self.ptr_size * VMT_HEADER_FIELD_COUNT

    @property
    def fixed_method_count(self) -> int:
        return max(0, (self.self_ptr_distance - self.fixed_method_offset) // self.ptr_size)

    @property
    def class_name_field_offset(self) -> int:
        return self.ptr_size * 8

    @property
    def instance_size_field_offset(self) -> int:
        return self.ptr_size * 9

    @property
    def parent_field_offset(self) -> int:
        return self.ptr_size * 10

    @property
    def interface_table_field_offset(self) -> int:
        return self.ptr_size

    @property
    def method_table_field_offset(self) -> int:
        return self.ptr_size * 6

    @property
    def dynamic_table_field_offset(self) -> int:
        return self.ptr_size * 7


@dataclass
class DelphiClassInfo:
    """Internal representation of a Delphi class recovered from a VMT."""

    profile_name: str
    candidate_offset: int
    vmt_offset: int
    class_name: str
    parent_vmt_addr: int = 0
    method_table_addr: int = 0
    dynamic_table_addr: int = 0
    interface_table_addr: int = 0
    method_slots: List[int] = field(default_factory=list)
    inherited_slots: List[int] = field(default_factory=list)
    overridden_slots: List[int] = field(default_factory=list)


class DelphiPythiaProvider(AbstractLabelProvider):
    """
    Recover Delphi function symbols from legacy/early modern VMT layouts.

    The provider keeps the exact public SMDA contract used by the old
    ``getDelphiObjects()`` implementation and returns a dictionary mapping
    absolute function addresses to optional function names.
    """

    _profiles = {
        32: (
            DelphiVmtProfile(name="legacy32", bitness=32, self_ptr_distance=0x4C, optional_zero_slots=(0,)),
            DelphiVmtProfile(name="modern32", bitness=32, self_ptr_distance=0x58, optional_zero_slots=(3,)),
        ),
        64: (
            DelphiVmtProfile(name="legacy64", bitness=64, self_ptr_distance=0x98, optional_zero_slots=(0,)),
            DelphiVmtProfile(name="modern64", bitness=64, self_ptr_distance=0xC8, optional_zero_slots=(3,)),
        ),
    }

    def __init__(self, config):
        self._config = config
        self._binary_info = None
        self._binary = b""
        self._base_addr = 0
        self._bitness = 0
        self._scan_ranges: List[Tuple[int, int]] = []
        self._func_symbols: Dict[int, str] = {}
        self._classes: Dict[int, DelphiClassInfo] = {}

    def update(self, binary_info):
        """Parse Delphi metadata from the given binary info."""
        self._binary_info = binary_info
        self._binary = binary_info.binary or b""
        self._base_addr = binary_info.base_addr
        self._bitness = binary_info.bitness
        self._func_symbols = {}
        self._classes = {}

        if not self._binary or self._bitness not in self._profiles:
            return

        self._scan_ranges = self._get_scan_ranges(binary_info)
        if not self._scan_ranges:
            return

        self._parse_delphi_objects()

    def _parse_delphi_objects(self) -> None:
        function_offsets = set()
        name_mapping: Dict[int, str] = {}
        classes_by_vmt_addr: Dict[int, DelphiClassInfo] = {}

        for profile in self._profiles.get(self._bitness, ()):
            for start_offset, end_offset in self._scan_ranges:
                for class_info in self._scan_code_range(profile, start_offset, end_offset):
                    classes_by_vmt_addr[self._offset_to_addr(class_info.vmt_offset)] = class_info
                    function_offsets.update(class_info.method_slots)
                    self._extract_dynamic_methods(class_info, function_offsets)
                    self._extract_interface_methods(class_info, function_offsets)
                    self._extract_method_table_symbols(class_info, function_offsets, name_mapping)

        self._classes = classes_by_vmt_addr
        self._resolve_inheritance()

        for function_addr in sorted(function_offsets):
            if self._binary_info.isInCodeAreas(function_addr):
                self._func_symbols[function_addr] = name_mapping.get(function_addr, "")

    def _get_scan_ranges(self, binary_info) -> List[Tuple[int, int]]:
        """
        Return merged file-offset scan ranges for PE code sections.

        Pythia scans sections marked as containing code. When section metadata is
        not available, fall back to SMDA's code areas. As a last resort, scan the
        whole mapped image on pointer alignment.
        """
        ranges: List[Tuple[int, int]] = []
        parsed_binary = binary_info.getLiefBinary()
        if isinstance(parsed_binary, lief.PE.Binary):
            for section in parsed_binary.sections:
                if not section.characteristics & IMAGE_SCN_CNT_CODE:
                    continue
                start_offset = section.virtual_address
                section_size = max(section.virtual_size, section.size)
                end_offset = min(len(self._binary), start_offset + section_size)
                if start_offset < end_offset:
                    ranges.append((start_offset, end_offset))
        if not ranges and binary_info.code_areas:
            for start_addr, end_addr in binary_info.code_areas:
                start_offset = max(0, start_addr - self._base_addr)
                end_offset = min(len(self._binary), end_addr - self._base_addr)
                if start_offset < end_offset:
                    ranges.append((start_offset, end_offset))
        if not ranges and self._binary:
            ranges.append((0, len(self._binary)))
        return self._merge_ranges(ranges)

    @staticmethod
    def _merge_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Merge overlapping or touching scan ranges."""
        if not ranges:
            return []
        merged = []
        for start_offset, end_offset in sorted(ranges):
            if not merged or start_offset > merged[-1][1]:
                merged.append([start_offset, end_offset])
            else:
                merged[-1][1] = max(merged[-1][1], end_offset)
        return [tuple(entry) for entry in merged]

    def _scan_code_range(
        self, profile: DelphiVmtProfile, start_offset: int, end_offset: int
    ) -> Iterable[DelphiClassInfo]:
        """Yield validated VMTs from a single code range."""
        current_offset = self._align_offset(start_offset, profile.ptr_size)
        upper_bound = end_offset - profile.ptr_size
        while current_offset <= upper_bound:
            target_addr = self._read_ptr(current_offset, profile.ptr_size)
            if target_addr == self._offset_to_addr(current_offset + profile.self_ptr_distance):
                class_info = self._build_class_info(profile, current_offset, end_offset)
                if class_info is not None:
                    yield class_info
            current_offset += profile.ptr_size

    @staticmethod
    def _align_offset(offset: int, alignment: int) -> int:
        """Align the given offset upwards."""
        remainder = offset % alignment
        return offset if remainder == 0 else offset + (alignment - remainder)

    def _build_class_info(
        self, profile: DelphiVmtProfile, candidate_offset: int, range_end_offset: int
    ) -> Optional[DelphiClassInfo]:
        """Validate a VMT candidate and extract its metadata."""
        class_name_addr = self._read_ptr(candidate_offset + profile.class_name_field_offset, profile.ptr_size)
        instance_size = self._read_ptr(candidate_offset + profile.instance_size_field_offset, profile.ptr_size)
        parent_vmt_addr = self._read_ptr(candidate_offset + profile.parent_field_offset, profile.ptr_size) or 0
        method_table_addr = self._read_ptr(candidate_offset + profile.method_table_field_offset, profile.ptr_size) or 0
        dynamic_table_addr = (
            self._read_ptr(candidate_offset + profile.dynamic_table_field_offset, profile.ptr_size) or 0
        )
        interface_table_addr = (
            self._read_ptr(candidate_offset + profile.interface_table_field_offset, profile.ptr_size) or 0
        )
        vmt_offset = candidate_offset + profile.self_ptr_distance

        if instance_size is None or instance_size > MAX_INSTANCE_SIZE:
            return None
        if vmt_offset >= len(self._binary):
            return None

        class_name = self._read_pascal_string(self._addr_to_offset(class_name_addr))
        if not self._is_probable_class_name(class_name):
            return None

        metadata_addresses = (
            class_name_addr,
            parent_vmt_addr,
            method_table_addr,
            dynamic_table_addr,
            interface_table_addr,
        )
        if not self._validate_metadata_addresses(metadata_addresses):
            return None

        fixed_methods = self._read_fixed_methods(profile, candidate_offset)
        if not self._validate_fixed_methods(profile, fixed_methods):
            return None

        virtual_methods = self._read_virtual_methods(profile, candidate_offset, range_end_offset)
        if not virtual_methods and not self._binary_info.isInCodeAreas(self._offset_to_addr(vmt_offset)):
            return None

        class_info = DelphiClassInfo(
            profile_name=profile.name,
            candidate_offset=candidate_offset,
            vmt_offset=vmt_offset,
            class_name=class_name,
            parent_vmt_addr=parent_vmt_addr,
            method_table_addr=method_table_addr,
            dynamic_table_addr=dynamic_table_addr,
            interface_table_addr=interface_table_addr,
            method_slots=fixed_methods + virtual_methods,
        )
        return class_info

    def _validate_metadata_addresses(self, addresses: Sequence[int]) -> bool:
        """Ensure optional metadata pointers remain inside the mapped image."""
        return all(not (address and not self._is_mapped_address(address)) for address in addresses)

    def _read_fixed_methods(self, profile: DelphiVmtProfile, candidate_offset: int) -> List[int]:
        """Read the fixed compiler-emitted method slots preceding vmtSelfPtr."""
        methods = []
        current_offset = candidate_offset + profile.fixed_method_offset
        for _ in range(profile.fixed_method_count):
            method_addr = self._read_ptr(current_offset, profile.ptr_size) or 0
            methods.append(method_addr)
            current_offset += profile.ptr_size
        return methods

    def _validate_fixed_methods(self, profile: DelphiVmtProfile, methods: Sequence[int]) -> bool:
        """Reject candidates whose fixed VMT slots do not point to executable code."""
        for index, method_addr in enumerate(methods):
            if method_addr == 0 and index in profile.optional_zero_slots:
                continue
            if not method_addr or not self._binary_info.isInCodeAreas(method_addr):
                return False
        return True

    def _read_virtual_methods(
        self, profile: DelphiVmtProfile, candidate_offset: int, range_end_offset: int
    ) -> List[int]:
        """Read additional VMT slots that start at the address stored in vmtSelfPtr."""
        methods = []
        start_offset = candidate_offset + profile.self_ptr_distance
        stop_offsets = []
        for field_offset in (
            candidate_offset + profile.method_table_field_offset,
            candidate_offset + profile.dynamic_table_field_offset,
            candidate_offset + profile.class_name_field_offset,
        ):
            metadata_addr = self._read_ptr(field_offset, profile.ptr_size)
            metadata_offset = self._addr_to_offset(metadata_addr)
            if metadata_addr and start_offset < metadata_offset < len(self._binary):
                stop_offsets.append(metadata_offset)
        stop_offset = min(stop_offsets) if stop_offsets else range_end_offset
        current_offset = start_offset
        slots_read = 0
        while current_offset + profile.ptr_size <= stop_offset and slots_read < MAX_VIRTUAL_SLOT_SCAN:
            method_addr = self._read_ptr(current_offset, profile.ptr_size)
            if not method_addr or not self._binary_info.isInCodeAreas(method_addr):
                break
            methods.append(method_addr)
            current_offset += profile.ptr_size
            slots_read += 1
        return methods

    def _extract_dynamic_methods(self, class_info: DelphiClassInfo, function_offsets: set) -> None:
        """Recover method pointers from a dynamic table when present."""
        if not class_info.dynamic_table_addr:
            return
        dynamic_offset = self._addr_to_offset(class_info.dynamic_table_addr)
        table_length = self._read_word(dynamic_offset)
        if table_length is None or table_length == 0:
            return
        function_offset = dynamic_offset + 2 + (2 * table_length)
        for _ in range(table_length):
            method_addr = self._read_ptr(function_offset, self._ptr_size)
            if method_addr and self._binary_info.isInCodeAreas(method_addr):
                function_offsets.add(method_addr)
            function_offset += self._ptr_size

    def _extract_method_table_symbols(
        self, class_info: DelphiClassInfo, function_offsets: set, name_mapping: Dict[int, str]
    ) -> None:
        """Parse the classic Delphi method table and recover symbol names."""
        if not class_info.method_table_addr:
            return
        entry_offset = self._addr_to_offset(class_info.method_table_addr)
        entry_count = self._read_word(entry_offset)
        if entry_count is None or entry_count == 0:
            return
        entry_offset += 2
        for _ in range(entry_count):
            entry_size = self._read_word(entry_offset)
            method_addr = self._read_ptr(entry_offset + 2, self._ptr_size)
            method_name = self._read_pascal_string(entry_offset + 2 + self._ptr_size)
            if method_addr and self._binary_info.isInCodeAreas(method_addr):
                function_offsets.add(method_addr)
                if method_name:
                    name_mapping[method_addr] = method_name
            if not entry_size or entry_size < 2 + self._ptr_size:
                break
            entry_offset += entry_size

    def _extract_interface_methods(self, class_info: DelphiClassInfo, function_offsets: set) -> None:
        """Parse interface tables conservatively for classic 32-bit Delphi layouts."""
        if self._bitness != 32 or not class_info.interface_table_addr:
            return
        interface_offset = self._addr_to_offset(class_info.interface_table_addr)
        start_interface_addr = self._read_ptr(interface_offset + 20, self._ptr_size)
        if not start_interface_addr:
            return
        current_offset = self._addr_to_offset(start_interface_addr)
        while 0 <= current_offset + self._ptr_size <= len(self._binary):
            method_addr = self._read_ptr(current_offset, self._ptr_size)
            if not method_addr or not self._binary_info.isInCodeAreas(method_addr):
                break
            function_offsets.add(method_addr)
            current_offset += self._ptr_size

    def _resolve_inheritance(self) -> None:
        """Mark inherited versus overridden VMT slots using Delphi's single inheritance."""
        for class_info in self._classes.values():
            parent = self._classes.get(class_info.parent_vmt_addr)
            if not parent:
                continue
            for index, method_addr in enumerate(class_info.method_slots):
                if index >= len(parent.method_slots):
                    break
                if method_addr == parent.method_slots[index]:
                    class_info.inherited_slots.append(index)
                else:
                    class_info.overridden_slots.append(index)

    @property
    def _ptr_size(self) -> int:
        return 4 if self._bitness == 32 else 8

    def _read_ptr(self, offset: int, ptr_size: int) -> Optional[int]:
        """Read a little-endian pointer from the mapped image."""
        if offset < 0 or offset + ptr_size > len(self._binary):
            return None
        if ptr_size == 4:
            return struct.unpack("<I", self._binary[offset : offset + 4])[0]
        return struct.unpack("<Q", self._binary[offset : offset + 8])[0]

    def _read_word(self, offset: int) -> Optional[int]:
        """Read a little-endian 16-bit value from the mapped image."""
        if offset < 0 or offset + 2 > len(self._binary):
            return None
        return struct.unpack("<H", self._binary[offset : offset + 2])[0]

    def _read_pascal_string(self, offset: int) -> str:
        """Read a Pascal-style string from the mapped image."""
        if offset < 0 or offset >= len(self._binary):
            return ""
        length = self._binary[offset]
        end_offset = offset + 1 + length
        if length == 0 or end_offset > len(self._binary):
            return ""
        return self._binary[offset + 1 : end_offset].decode("latin-1", errors="ignore")

    @staticmethod
    def _is_probable_class_name(class_name: str) -> bool:
        """Heuristic rejection for obviously invalid class names."""
        if not class_name or len(class_name) > 255:
            return False
        if not all(character.isprintable() for character in class_name):
            return False
        return any(character.isalpha() for character in class_name)

    def _is_mapped_address(self, address: int) -> bool:
        """Check whether an address can be resolved into the mapped image."""
        return self._base_addr <= address < self._base_addr + len(self._binary)

    def _offset_to_addr(self, offset: int) -> int:
        """Convert mapped-image offset to absolute address."""
        return self._base_addr + offset

    def _addr_to_offset(self, address: Optional[int]) -> int:
        """Convert absolute address to mapped-image offset."""
        if address is None:
            return -1
        return address - self._base_addr

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return None

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def getRelocations(self):
        return {}
