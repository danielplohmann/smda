#!/usr/bin/python
"""
DelphiReSymProvider - Delphi Symbol Recovery for SMDA
Adapted from DelphiReSym by Lukas Wenz (https://github.com/WenzWenzWenz/DelphiReSym)
Parses Delphi metadata structures (VMT, MDT, RTTI) to extract function symbols from Delphi binaries.
Supports Delphi versions 2010 through 12 Athens.
"""

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .AbstractLabelProvider import AbstractLabelProvider

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


@dataclass
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


@dataclass
class ParameterInfo:
    """Information about a function parameter."""

    type_name: Optional[str] = None
    parameter_name: str = ""


@dataclass
class MethodInfo:
    """Information about a method extracted from MDT."""

    function_offset: int
    function_name: str = ""
    return_type: str = "void"
    parameters: List[ParameterInfo] = field(default_factory=list)


class DelphiReSymProvider(AbstractLabelProvider):
    """
    Label provider for extracting Delphi symbols from modern Delphi executables.
    Parses Virtual Method Tables (VMT), Method Definition Tables (MDT), and RTTI metadata.
    """

    def __init__(self, config):
        self._config = config
        self._func_symbols = {}
        self._binary = None
        self._base_addr = 0
        self._bitness = 32
        self._code_start = 0
        self._code_end = 0
        self._settings = None

    def update(self, binary_info):
        """Parse Delphi metadata from the given binary."""
        self._binary = binary_info.binary
        self._base_addr = binary_info.base_addr
        self._bitness = binary_info.bitness

        # Only process PE files with .text sections
        if not self._is_compatible():
            return

        # Determine code areas
        code_areas = binary_info.code_areas
        if not code_areas:
            LOGGER.debug("No code areas found, skipping DelphiReSym parsing")
            return

        # Code areas are virtual addresses - convert to file offsets for scanning
        # Use the first code area (typically .text section)
        code_area_start_va = code_areas[0][0]
        code_area_end_va = code_areas[0][1]

        # Convert virtual addresses to file offsets
        self._code_start = code_area_start_va - self._base_addr
        self._code_end = code_area_end_va - self._base_addr

        # Validate the offsets are within binary bounds
        if self._code_start < 0 or self._code_end > len(self._binary):
            LOGGER.debug(
                f"Code area offsets out of bounds: {self._code_start}-{self._code_end}, binary size: {len(self._binary)}"
            )
            return

        # Set up architecture-specific settings
        if self._bitness == 32:
            self._settings = ArchitectureSettings(ptr_size=4, jump_dist=VMT_JUMP_DIST_32BIT)
        elif self._bitness == 64:
            self._settings = ArchitectureSettings(ptr_size=8, jump_dist=VMT_JUMP_DIST_64BIT)
        else:
            LOGGER.warning(f"Unsupported bitness: {self._bitness}")
            return

        try:
            LOGGER.debug("Starting DelphiReSym symbol extraction...")
            self._parse_delphi_symbols()
            if self._func_symbols:
                LOGGER.info(f"Extracted {len(self._func_symbols)} Delphi symbols")
            else:
                LOGGER.debug("No Delphi symbols extracted")
        except Exception as e:
            LOGGER.warning(f"Error during DelphiReSym parsing: {e}")

    def _is_compatible(self):
        """Check if binary is a PE file."""
        if len(self._binary) < 0x40:
            return False
        return self._binary[:2] == b"MZ"

    def _read_ptr(self, offset: int) -> Optional[int]:
        """Read a pointer at the given offset."""
        try:
            if self._settings.ptr_size == 4:
                return struct.unpack("<I", self._binary[offset : offset + 4])[0]
            else:
                return struct.unpack("<Q", self._binary[offset : offset + 8])[0]
        except (struct.error, IndexError):
            return None

    def _read_byte(self, offset: int) -> Optional[int]:
        """Read a byte at the given offset."""
        if 0 <= offset < len(self._binary):
            return self._binary[offset]
        return None

    def _read_short(self, offset: int) -> Optional[int]:
        """Read a 16-bit value at the given offset."""
        try:
            return struct.unpack("<H", self._binary[offset : offset + 2])[0]
        except (struct.error, IndexError):
            return None

    def _read_pascal_string(self, offset: int) -> str:
        """
        Read a Pascal-style string (length byte followed by characters).
        Returns empty string on error.
        """
        try:
            length = self._read_byte(offset)
            if length is None or length == 0:
                return ""

            string_data = self._binary[offset + 1 : offset + 1 + length]
            if len(string_data) < length:
                return ""

            return string_data.decode("latin-1", errors="ignore")
        except (IndexError, UnicodeDecodeError):
            return ""

    def _offset_in_code_area(self, offset: int) -> bool:
        """Check if offset is within code area."""
        return self._code_start <= offset < self._code_end

    def _addr_to_offset(self, addr: int) -> int:
        """Convert virtual address to file offset."""
        return addr - self._base_addr

    def _offset_to_addr(self, offset: int) -> int:
        """Convert file offset to virtual address."""
        return offset + self._base_addr

    def _check_vmt_candidate(self, vmt_offset: int, next_struct_offset: int) -> bool:
        """
        Perform sanity checks on a VMT candidate.
        Returns True if the candidate passes all checks.
        """
        addresses_to_check = [next_struct_offset]

        # Check MDT pointer
        mdt_offset_field = vmt_offset + self._settings.mdt_offset
        mdt_addr = self._read_ptr(mdt_offset_field)
        if mdt_addr is not None:
            mdt_offset = self._addr_to_offset(mdt_addr)
            addresses_to_check.append(mdt_offset)
            # MDTs should be at higher addresses than VMTs
            if mdt_offset <= vmt_offset:
                return False

        # Check virtual method pointers (fields 11-22, excluding SafeCallException which is optional)
        for field_num in range(VMT_VMETHOD_START_INDEX, VMT_VMETHOD_END_INDEX):
            if field_num != VMT_SAFECALL_EXCEPTION_INDEX:
                field_offset = vmt_offset + (self._settings.ptr_size * field_num)
                method_addr = self._read_ptr(field_offset)
                if method_addr is not None:
                    method_offset = self._addr_to_offset(method_addr)
                    addresses_to_check.append(method_offset)

        # All addresses should be within code area
        return all(self._offset_in_code_area(off) for off in addresses_to_check)

    def _find_vmts(self) -> list:
        """
        Scan for Virtual Method Tables in the code section.
        Uses a sliding window approach to find VMT structures.
        """
        vmt_offsets = []
        current_offset = self._code_start

        LOGGER.debug(f"Scanning for VMTs from 0x{current_offset:x} to 0x{self._code_end:x}")

        while current_offset < self._code_end - self._settings.ptr_size:
            ptr_value = self._read_ptr(current_offset)
            if ptr_value is None:
                current_offset += 1
                continue

            target_offset = self._addr_to_offset(ptr_value)
            distance = target_offset - current_offset

            # Check if this matches the expected VMT jump distance
            if distance == self._settings.jump_dist and self._check_vmt_candidate(current_offset, target_offset):
                vmt_offsets.append(current_offset)
                LOGGER.debug(f"Found VMT at offset 0x{current_offset:x}")

            current_offset += 1

        return vmt_offsets

    def _traverse_rtti_object(self, rtti_offset: int) -> Optional[str]:
        """
        Traverse an RTTI object to extract type information.
        Returns the type name (with namespace for RTTI_Class types).
        """
        magic_byte = self._read_byte(rtti_offset)
        if magic_byte is None or magic_byte > RTTI_MAX_MAGIC_BYTE:
            return None

        # Read object name (Pascal string at offset +1)
        object_name = self._read_pascal_string(rtti_offset + 1)
        if not object_name:
            return None

        # RTTI_Class contains namespace information
        # RTTI_Class structure layout:
        #   MagicByte(1) + ObjectName(pascal) + Unknown(1) + Pointers(2*ptr_size) + Unknown(2) + Namespace(pascal)
        if magic_byte == RTTI_CLASS_MAGIC_BYTE:
            namespace_offset = rtti_offset + 1 + len(object_name) + 1 + 2 * self._settings.ptr_size + 2
            namespace = self._read_pascal_string(namespace_offset)
            if namespace:
                return f"{namespace}.{object_name}"

        return object_name

    def _resolve_type_from_double_ptr(self, ptr_field_offset: int) -> Optional[str]:
        """
        Resolve a type name from a double-dereferenced pointer to an RTTI object.
        Used for both return types and parameter types.
        """
        ptr_addr = self._read_ptr(ptr_field_offset)
        if ptr_addr is None or ptr_addr == 0:
            return None

        ptr_offset = self._addr_to_offset(ptr_addr)
        rtti_addr = self._read_ptr(ptr_offset)
        if rtti_addr is None or rtti_addr == 0:
            return None

        rtti_offset = self._addr_to_offset(rtti_addr)
        return self._traverse_rtti_object(rtti_offset)

    def _extract_method_info(self, method_entry_offset: int) -> Optional[MethodInfo]:
        """Extract detailed information about a method from its MethodEntry structure."""
        try:
            # Function entry point (offset +2)
            func_addr = self._read_ptr(method_entry_offset + 2)
            if func_addr is None:
                return None
            func_offset = self._addr_to_offset(func_addr)

            # Function name (Pascal string at offset +ptr_size+2)
            func_name_offset = method_entry_offset + self._settings.ptr_size + 2
            func_name = self._read_pascal_string(func_name_offset)
            if not func_name:
                return None

            method_info = MethodInfo(function_offset=func_offset, function_name=func_name)

            # Return type (at offset +function_name_len+ptr_size+4)
            return_type_field_offset = method_entry_offset + len(func_name) + 1 + self._settings.ptr_size + 4
            return_type_name = self._resolve_type_from_double_ptr(return_type_field_offset)
            if return_type_name:
                method_info.return_type = return_type_name

            # Parameter count (at offset +function_name_len+2*ptr_size+6)
            param_count_offset = method_entry_offset + len(func_name) + 1 + 2 * self._settings.ptr_size + 6
            param_count = self._read_byte(param_count_offset)

            if param_count is not None and param_count > 0:
                # Parse parameters
                param_offset = param_count_offset + 2
                for _ in range(param_count):
                    # Parameter RTTI (double-dereferenced pointer)
                    param_type_name = self._resolve_type_from_double_ptr(param_offset)

                    # Parameter name (Pascal string at offset +ptr_size+2)
                    param_name_offset = param_offset + self._settings.ptr_size + 2
                    param_name = self._read_pascal_string(param_name_offset)

                    method_info.parameters.append(ParameterInfo(type_name=param_type_name, parameter_name=param_name))

                    # Move to next parameter entry
                    param_offset = param_name_offset + len(param_name) + 1 + PARAM_ENTRY_PADDING

            return method_info

        except Exception as e:
            LOGGER.debug(f"Error extracting method info at 0x{method_entry_offset:x}: {e}")
            return None

    def _parse_mdt(self, mdt_offset: int) -> list:
        """Parse a Method Definition Table to extract method information."""
        methods = []

        # Read number of method entries (short at offset +2)
        num_entries = self._read_short(mdt_offset + 2)
        if num_entries is None or num_entries == 0:
            return methods

        # Method entry references start at offset +4
        me_refs_start = mdt_offset + 4

        for i in range(num_entries):
            me_ref_offset = me_refs_start + i * (self._settings.ptr_size + 4)
            me_addr = self._read_ptr(me_ref_offset)

            if me_addr is None:
                continue

            me_offset = self._addr_to_offset(me_addr)
            method_info = self._extract_method_info(me_offset)

            if method_info:
                methods.append(method_info)

        return methods

    def _parse_delphi_symbols(self):
        """Main parsing routine to extract Delphi symbols."""
        # Step 1: Find all VMT structures
        vmt_offsets = self._find_vmts()
        LOGGER.debug(f"Found {len(vmt_offsets)} VMT candidates")

        if not vmt_offsets:
            return

        # Step 2: For each VMT, extract MDT and parse methods
        for vmt_offset in vmt_offsets:
            # Get MDT address from VMT
            mdt_field_offset = vmt_offset + self._settings.mdt_offset
            mdt_addr = self._read_ptr(mdt_field_offset)

            if mdt_addr is None:
                continue

            mdt_offset = self._addr_to_offset(mdt_addr)

            # Get RTTI namespace for this VMT
            rtti_field_offset = vmt_offset + self._settings.rtti_offset
            rtti_addr = self._read_ptr(rtti_field_offset)
            namespace = None
            if rtti_addr is not None:
                rtti_offset = self._addr_to_offset(rtti_addr)
                namespace = self._traverse_rtti_object(rtti_offset)

            # Parse all methods in this MDT
            methods = self._parse_mdt(mdt_offset)

            # Store function symbols
            for method in methods:
                func_addr = self._offset_to_addr(method.function_offset)

                # Build function name with namespace if available
                full_name = f"{namespace}.{method.function_name}" if namespace else method.function_name

                # Add return type and parameters to make it more informative
                if method.return_type != "void" or method.parameters:
                    param_str = ", ".join([f"{p.parameter_name}: {p.type_name or '?'}" for p in method.parameters])
                    full_name = f"{full_name}({param_str}): {method.return_type}"

                self._func_symbols[func_addr] = full_name

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, absolute_addr):
        return None

    def getSymbol(self, address):
        # sanitize output because the extractor may produce non-printable characters
        symbol = self._func_symbols.get(address, "")
        if not all(c.isprintable() or c.isspace() for c in symbol):
            symbol = ""
        return symbol

    def getFunctionSymbols(self):
        return self._func_symbols

    def getRelocations(self):
        return {}
