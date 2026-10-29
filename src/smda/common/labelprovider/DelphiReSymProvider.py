#!/usr/bin/python
"""
DelphiReSymProvider - Delphi Symbol Recovery for SMDA
Adapted from DelphiReSym by Lukas Wenz (https://github.com/WenzWenzWenz/DelphiReSym)
Parses Delphi metadata structures (VMT, MDT, RTTI) to extract function symbols from Delphi binaries.
Uses the modern Windows Delphi VMT layout documented for Delphi 2010 through 13.

BSD 3-Clause License

Copyright (c) 2025, Lukas Wenz

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import logging
import struct
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from .AbstractLabelProvider import AbstractLabelProvider
from .DelphiVmtScanner import iter_vmt_self_references

LOGGER = logging.getLogger(__name__)

# VMT (Virtual Method Table) structure constants
VMT_MDT_FIELD_INDEX = 6  # Index of MDT pointer field in VMT
VMT_RTTI_FIELD_INDEX = 4  # Index of RTTI_Class pointer field in VMT
VMT_VMETHOD_START_INDEX = 11  # First virtual method field index
VMT_VMETHOD_END_INDEX = 22  # Last virtual method field index (exclusive)
VMT_SAFECALL_EXCEPTION_INDEX = 14  # SafeCallException field (optional, skip in validation)

# Architecture-specific VMT jump distances (distance from VMT start to first method)
VMT_JUMP_DIST_32BIT = 88
VMT_JUMP_DIST_64BIT = 200

# RTTI (Runtime Type Information) constants
RTTI_MAX_MAGIC_BYTE = 0x15  # Maximum valid magic byte value for RTTI objects
RTTI_CLASS_MAGIC_BYTE = 0x07  # Magic byte indicating RTTI_Class type

# Method entry structure magic value for parameter offset calculation
# This value is from the original DelphiReSym and works for Delphi 11
PARAM_ENTRY_PADDING = 3


@dataclass(slots=True)
class ArchitectureSettings:
    """Architecture-specific settings for VMT/MDT parsing."""

    ptr_size: int
    jump_dist: int  # Expected distance from VMT to first method

    @property
    def mdt_offset(self) -> int:
        """Offset to MDT pointer within VMT structure."""
        return self.ptr_size * VMT_MDT_FIELD_INDEX

    @property
    def rtti_offset(self) -> int:
        """Offset to RTTI_Class pointer within VMT structure."""
        return self.ptr_size * VMT_RTTI_FIELD_INDEX


@dataclass(slots=True)
class ParameterInfo:
    """Information about a function parameter."""

    type_name: Optional[str] = None
    parameter_name: str = ""


@dataclass(slots=True)
class MethodInfo:
    """Information about a method extracted from MDT."""

    function_offset: int
    function_name: str = ""
    return_type: str = "void"
    parameters: List[ParameterInfo] = field(default_factory=list)


class DelphiReSymProvider(AbstractLabelProvider):
    """Recover modern Delphi method names from a mapped PE image.

    Offsets in this provider are RVAs into BinaryInfo.binary, never raw-file offsets.
    Code ranges constrain function targets; metadata may reside in any mapped region.
    """

    def __init__(self, config):
        self._config = config
        self._func_symbols: dict[int, str] = {}
        self._vmt_count = 0
        self._binary: bytes = b""
        self._base_addr: int = 0
        self._settings = ArchitectureSettings(4, VMT_JUMP_DIST_32BIT)
        self._code_ranges: List[Tuple[int, int]] = []
        self._code_starts: List[int] = []
        self._type_cache: dict[int, Optional[str]] = {}

    def update(self, binary_info):
        self._func_symbols = {}
        self._vmt_count = 0
        self._binary = binary_info.binary
        self._base_addr = binary_info.base_addr
        self._settings = ArchitectureSettings(4, VMT_JUMP_DIST_32BIT)
        self._code_ranges = []
        self._code_starts = []
        self._type_cache = {}
        self._remaining_entries = getattr(self._config, "MAX_DELPHI_METADATA_ENTRIES", 1000000)
        self._budget_logged = False
        if (
            getattr(binary_info, "architecture", "") not in ("", "intel")
            or not self._is_compatible()
            or b"TObject" not in self._binary
        ):
            return
        if not binary_info.code_areas:
            LOGGER.warning("No code areas found, skipping DelphiReSym parsing")
            return
        if self._remaining_entries <= 0:
            return
        ranges = []
        for start, end in sorted(binary_info.code_areas):
            start, end = start - self._base_addr, end - self._base_addr
            if not 0 <= start < end <= len(self._binary):
                LOGGER.warning("Code area offsets out of bounds: %s-%s, binary size: %s", start, end, len(self._binary))
                continue
            if ranges and start <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], max(end, ranges[-1][1]))
            else:
                ranges.append((start, end))
        self._code_ranges = ranges
        self._code_starts = [start for start, _ in ranges]
        if not ranges:
            return
        if binary_info.bitness == 32:
            self._settings = ArchitectureSettings(4, VMT_JUMP_DIST_32BIT)
        elif binary_info.bitness == 64:
            self._settings = ArchitectureSettings(8, VMT_JUMP_DIST_64BIT)
        else:
            return
        try:
            self._parse_delphi_symbols()
        finally:
            self._type_cache.clear()

    def _is_compatible(self):
        return len(self._binary) >= 0x40 and self._binary[:2] == b"MZ"

    def _read_ptr(self, offset: int) -> Optional[int]:
        size = self._settings.ptr_size
        if 0 <= offset <= len(self._binary) - size:
            return int(struct.unpack_from("<I" if size == 4 else "<Q", self._binary, offset)[0])
        return None

    def _read_byte(self, offset: int) -> Optional[int]:
        return self._binary[offset] if 0 <= offset < len(self._binary) else None

    def _read_short(self, offset: int) -> Optional[int]:
        if 0 <= offset <= len(self._binary) - 2:
            return int(struct.unpack_from("<H", self._binary, offset)[0])
        return None

    def _read_pascal_string(self, offset: int, end: Optional[int] = None) -> str:
        length = self._read_byte(offset)
        limit = len(self._binary) if end is None else min(end, len(self._binary))
        if not length or offset + 1 + length > limit:
            return ""
        data = self._binary[offset + 1 : offset + 1 + length]
        try:
            value = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                value = data.decode("cp1252")
            except UnicodeDecodeError:
                return ""
        return value if value.isprintable() else ""

    def _offset_in_code_area(self, offset: int) -> bool:
        index = bisect_right(self._code_starts, offset) - 1
        return index >= 0 and offset < self._code_ranges[index][1]

    def _addr_to_offset(self, addr: int) -> int:
        return addr - self._base_addr

    def _offset_to_addr(self, offset: int) -> int:
        return offset + self._base_addr

    def _check_vmt_candidate(self, vmt_offset: int, next_struct_offset: int) -> bool:
        size = self._settings.ptr_size
        if not 0 <= vmt_offset < next_struct_offset < len(self._binary):
            return False
        if vmt_offset + self._settings.jump_dist > len(self._binary):
            return False
        fields = struct.unpack_from("<22I" if size == 4 else "<22Q", self._binary, vmt_offset)
        class_addr = fields[8]
        if not class_addr or not self._read_pascal_string(self._addr_to_offset(class_addr)):
            return False
        for field_num in (VMT_MDT_FIELD_INDEX, VMT_RTTI_FIELD_INDEX):
            addr = fields[field_num]
            if addr and not 0 <= self._addr_to_offset(addr) < len(self._binary):
                return False
        rtti_addr = fields[VMT_RTTI_FIELD_INDEX]
        if rtti_addr:
            rtti = self._addr_to_offset(rtti_addr)
            name = self._read_pascal_string(rtti + 1)
            if self._read_byte(rtti) != RTTI_CLASS_MAGIC_BYTE or not name:
                return False
            if self._read_ptr(rtti + (self._read_byte(rtti + 1) or 0) + 2) != self._offset_to_addr(next_struct_offset):
                return False
        for field_num in range(VMT_VMETHOD_START_INDEX, VMT_VMETHOD_END_INDEX):
            addr = fields[field_num]
            if field_num == VMT_SAFECALL_EXCEPTION_INDEX and addr == 0:
                continue
            if not addr or not self._offset_in_code_area(self._addr_to_offset(addr)):
                return False
        return True

    def _find_vmts(self) -> Iterator[int]:
        jump = self._settings.jump_dist
        for offset in iter_vmt_self_references(
            self._binary, self._base_addr, self._settings.ptr_size, jump, 0, len(self._binary)
        ):
            if self._check_vmt_candidate(offset, offset + jump):
                yield offset

    def _traverse_rtti_object(self, rtti_offset: int, validate_pointers: bool = True) -> Optional[str]:
        kind = self._read_byte(rtti_offset)
        if kind is None or kind > RTTI_MAX_MAGIC_BYTE:
            return None
        name = self._read_pascal_string(rtti_offset + 1)
        if not name:
            return None
        if kind != RTTI_CLASS_MAGIC_BYTE:
            return name
        ptr_offset = rtti_offset + (self._read_byte(rtti_offset + 1) or 0) + 2
        if validate_pointers:
            ptr = self._read_ptr(ptr_offset)
            if ptr is None or (ptr and not 0 <= self._addr_to_offset(ptr) < len(self._binary)):
                return None
        namespace = self._read_pascal_string(ptr_offset + 2 * self._settings.ptr_size + 2)
        return f"{namespace}.{name}" if namespace else name

    def _resolve_type_from_double_ptr(self, ptr_field_offset: int) -> Optional[str]:
        addr = self._read_ptr(ptr_field_offset)
        if not addr:
            return None
        cache = self._type_cache
        if addr not in cache:
            rtti_addr = self._read_ptr(self._addr_to_offset(addr))
            cache[addr] = self._traverse_rtti_object(self._addr_to_offset(rtti_addr), False) if rtti_addr else None
        return cache[addr]

    def _take_entry(self) -> bool:
        remaining = getattr(self, "_remaining_entries", 1000000)
        if remaining <= 0:
            if not getattr(self, "_budget_logged", False):
                LOGGER.warning("Delphi metadata entry budget exhausted")
                self._budget_logged = True
            return False
        self._remaining_entries = remaining - 1
        return True

    def _extract_method_info(self, method_entry_offset: int) -> Optional[MethodInfo]:
        size = self._settings.ptr_size
        length = self._read_short(method_entry_offset)
        if length is None or length < size + 3 or method_entry_offset + length > len(self._binary):
            return None
        end = method_entry_offset + length
        func_addr = self._read_ptr(method_entry_offset + 2)
        if not func_addr or not self._offset_in_code_area(self._addr_to_offset(func_addr)):
            return None
        name_offset = method_entry_offset + size + 2
        name = self._read_pascal_string(name_offset, end)
        if not name:
            return None
        method = MethodInfo(self._addr_to_offset(func_addr), name)
        signature = name_offset + (self._read_byte(name_offset) or 0) + 1
        param_count_offset = signature + size + 4
        if param_count_offset + 2 > end or self._read_byte(signature) != 3:
            return method
        return_field = signature + 2
        return_type = self._resolve_type_from_double_ptr(return_field) if self._read_ptr(return_field) else "void"
        parameters = []
        parameter_names = set()
        offset = param_count_offset + 2
        for _ in range(self._read_byte(param_count_offset) or 0):
            if not self._take_entry():
                return method
            param_name_offset = offset + size + 2
            param_name = self._read_pascal_string(param_name_offset, end)
            if not param_name:
                return method
            if param_name.casefold() in parameter_names:
                return method
            parameter_names.add(param_name.casefold())
            parameters.append(ParameterInfo(self._resolve_type_from_double_ptr(offset), param_name))
            offset = param_name_offset + (self._read_byte(param_name_offset) or 0) + 1 + PARAM_ENTRY_PADDING
        method.return_type = return_type or "?"
        method.parameters = parameters
        return method

    def _parse_mdt(self, mdt_offset: int) -> list:
        methods = []
        count = self._read_short(mdt_offset)
        if count is None:
            return methods
        cursor = mdt_offset + 2
        for _ in range(count):
            if not self._take_entry():
                return methods
            length = self._read_short(cursor)
            if not length or length < self._settings.ptr_size + 3 or cursor + length > len(self._binary):
                return methods
            method = self._extract_method_info(cursor)
            if method:
                methods.append(method)
            cursor += length
        count = self._read_short(cursor)
        if count is None:
            return methods
        cursor += 2
        method_cache = {}
        for _ in range(count):
            addr = self._read_ptr(cursor)
            if addr is None:
                break
            if not self._take_entry() or cursor + self._settings.ptr_size + 4 > len(self._binary):
                break
            offset = self._addr_to_offset(addr)
            if offset not in method_cache:
                method_cache[offset] = self._extract_method_info(offset)
            method = method_cache[offset]
            if method:
                methods.append(method)
            cursor += self._settings.ptr_size + 4
        return methods

    def _parse_delphi_symbols(self):
        for vmt in self._find_vmts():
            if not self._take_entry():
                break
            self._vmt_count += 1
            mdt_addr = self._read_ptr(vmt + self._settings.mdt_offset)
            if not mdt_addr:
                continue
            rtti_addr = self._read_ptr(vmt + self._settings.rtti_offset)
            namespace = self._traverse_rtti_object(self._addr_to_offset(rtti_addr)) if rtti_addr else None
            if not namespace:
                class_addr = self._read_ptr(vmt + 8 * self._settings.ptr_size)
                namespace = self._read_pascal_string(self._addr_to_offset(class_addr)) if class_addr else ""
            for method in self._parse_mdt(self._addr_to_offset(mdt_addr)):
                name = f"{namespace}.{method.function_name}" if namespace else method.function_name
                if method.return_type != "void" or method.parameters:
                    params = ", ".join(f"{p.parameter_name}: {p.type_name or '?'}" for p in method.parameters)
                    name = f"{name}({params}): {method.return_type}"
                addr = self._offset_to_addr(method.function_offset)
                previous = self._func_symbols.get(addr, "")
                if not previous or ("(" not in previous and "(" in name):
                    self._func_symbols[addr] = name

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

    def getVmtCount(self):
        """Number of validated VMTs in the last update, with or without method tables."""
        return self._vmt_count

    def getRelocations(self):
        return {}

    def is_active(self):
        return bool(self._func_symbols)
