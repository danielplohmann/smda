#!/usr/bin/python

import logging

import lief

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.utility.MachoBinary import get_active_macho_binary, get_macho_address_adjustment

from .AbstractLabelProvider import AbstractLabelProvider
from .import_parsers import resolve_pe_base_addr
from .rust_demangler import demangle
from .rust_demangler.rust import TypeNotFoundError
from .rust_demangler.rust_legacy import UnableToLegacyDemangle
from .rust_demangler.rust_v0 import UnableTov0Demangle
from .rust_demangler.utils import remove_bad_spaces

LOGGER = logging.getLogger(__name__)

# Specific exceptions that can be raised during Rust demangling
_DEMANGLE_ERRORS = (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle)


class RustSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for Rust symbols"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def update(self, binary_info):
        self._func_symbols = {}

        try:
            lief_binary = binary_info.getLiefBinary()
        except Exception as exc:
            reraise_non_operational_exception(exc)
            LOGGER.debug("Failed to parse binary with LIEF: %s", type(exc).__name__)
            return

        if not lief_binary or not self.is_rust_binary(binary_info):
            return

        # Dispatch to appropriate handler based on binary type
        if isinstance(lief_binary, lief.ELF.Binary):
            self._update_elf(lief_binary)
        elif isinstance(lief_binary, lief.PE.Binary):
            self._update_pe(lief_binary, binary_info.base_addr)
        elif isinstance(lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary)):
            self._update_macho(lief_binary, binary_info)

    def is_rust_binary(self, binary_info):
        """
        Checks for Rust signatures in the binary data.
        Based on Ghidra's Rust detection logic.
        """
        if hasattr(binary_info, "_is_rust"):
            return binary_info._is_rust

        try:
            lief_binary = binary_info.getLiefBinary()
            if lief_binary:
                # Mach-O Itanium C++ also uses __ZN; only treat Rust v0 (_R/__R) as
                # symbol-table evidence there. ELF/PE keep legacy _ZN as well.
                is_macho = isinstance(lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary))
                symbol_binary = lief_binary
                if isinstance(lief_binary, lief.MachO.FatBinary):
                    symbol_binary = get_active_macho_binary(
                        lief_binary,
                        bitness=getattr(binary_info, "bitness", None),
                        architecture=getattr(binary_info, "architecture", "") or "",
                    )
                rust_prefixes = ("_R", "__R") if is_macho else ("_ZN", "_R", "__ZN", "__R")
                symbol_lists = []
                if hasattr(symbol_binary, "exported_functions"):
                    symbol_lists.append(symbol_binary.exported_functions)
                if hasattr(symbol_binary, "symbols"):
                    symbol_lists.append(symbol_binary.symbols)
                if hasattr(symbol_binary, "exported_symbols"):
                    symbol_lists.append(symbol_binary.exported_symbols)
                if hasattr(symbol_binary, "symtab_symbols"):
                    symbol_lists.append(symbol_binary.symtab_symbols)
                if hasattr(symbol_binary, "dynamic_symbols"):
                    symbol_lists.append(symbol_binary.dynamic_symbols)
                for symbols in symbol_lists:
                    for sym in symbols or []:
                        try:
                            sym_name = sym.name
                        except (UnicodeDecodeError, AttributeError):
                            continue
                        if sym_name and sym_name.startswith(rust_prefixes):
                            binary_info._is_rust = True
                            return True
        except Exception as exc:
            reraise_non_operational_exception(exc)

        # Fallback to scanning the binary data (cached)
        data = self._get_binary_data(binary_info)
        if not data:
            binary_info._is_rust = False
            return False

        # Ghidra checks for these byte sequences
        signatures = [b"RUST_BACKTRACE", b"RUST_MIN_STACK", b"/rustc/"]
        is_rust = any(sig in data for sig in signatures)
        binary_info._is_rust = is_rust
        return is_rust

    def _get_binary_data(self, binary_info):
        """Safely retrieves binary data from either raw_data or a file path."""
        data = getattr(binary_info, "raw_data", None)
        file_path = getattr(binary_info, "file_path", None)
        if not data and file_path:
            try:
                with open(binary_info.file_path, "rb") as fin:
                    data = fin.read()
            except OSError as e:
                LOGGER.debug("Failed to read binary from path %s: %s", binary_info.file_path, e)
                return None
        return data

    def _update_elf(self, lief_binary):
        """Process ELF binary symbols for Rust demangling."""
        self._func_symbols.update(self._parse_lief_symbols(lief_binary.symtab_symbols))
        self._func_symbols.update(self._parse_lief_symbols(lief_binary.dynamic_symbols))

    def _update_macho(self, lief_binary, binary_info):
        """Process Mach-O binary symbols for Rust demangling."""
        macho_binary = get_active_macho_binary(
            lief_binary,
            bitness=getattr(binary_info, "bitness", None),
            architecture=getattr(binary_info, "architecture", "") or "",
        )
        if not macho_binary or not isinstance(macho_binary, lief.MachO.Binary):
            return
        adjustment = get_macho_address_adjustment(
            macho_binary,
            base_addr=getattr(binary_info, "base_addr", 0) or 0,
            bitness=getattr(binary_info, "bitness", None),
            architecture=getattr(binary_info, "architecture", "") or "",
        )
        for symbol_list in (
            getattr(macho_binary, "symbols", None),
            getattr(macho_binary, "exported_symbols", None),
        ):
            if not symbol_list:
                continue
            for symbol in symbol_list:
                try:
                    raw_name = symbol.name
                except (UnicodeDecodeError, AttributeError):
                    continue
                if not raw_name or not getattr(symbol, "value", 0):
                    continue
                if not self._is_rust_symbol(raw_name):
                    continue
                adjusted = symbol.value + adjustment
                if binary_info and not binary_info.isInCodeAreas(adjusted):
                    continue
                try:
                    demangled = demangle(raw_name)
                    if demangled:
                        demangled = remove_bad_spaces(demangled)
                        self._func_symbols[adjusted] = demangled
                except _DEMANGLE_ERRORS as exc:
                    LOGGER.debug("Failed to demangle Rust symbol %s: %s", raw_name, exc)

    def _update_pe(self, lief_binary, base_addr=None):
        """Process PE binary symbols for Rust demangling."""
        active_base = resolve_pe_base_addr(lief_binary, base_addr)
        # Parse PE exports
        export = lief_binary.get_export()
        for function in export.entries if export is not None else []:
            if function.is_extern or function.is_forwarded:
                # forwarder/extern entries redirect to another module's export and have no
                # local address (LIEF sets .address to 0 for them) - not a local function.
                continue
            try:
                try:
                    raw_name = function.name
                except (UnicodeDecodeError, AttributeError):
                    continue

                if self._is_rust_symbol(raw_name):
                    demangled = demangle(raw_name)
                    if demangled:
                        demangled = remove_bad_spaces(demangled)
                        self._func_symbols[active_base + function.address] = demangled
            except _DEMANGLE_ERRORS as exc:
                LOGGER.debug("Failed to demangle Rust symbol %s: %s", function.name, exc)

        # working example: 3969e1a88a063155a6f61b0ca1ac33114c1a39151f3c7dd019084abd30553eab
        # Parse PE symbols (COFF) if available and LIEF extracted them
        # (Similar logic to PeSymbolProvider but focusing on Rust)
        for symbol in lief_binary.symbols:
            # Check if it is a function symbol and has a section
            if hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION":
                if symbol.section is None:
                    # section_idx 0/-1/-2 (undefined-external/absolute/debug): not a locally
                    # defined function, its value is not a usable in-image offset.
                    continue
                try:
                    try:
                        raw_name = symbol.name
                    except (UnicodeDecodeError, AttributeError):
                        continue
                    if self._is_rust_symbol(raw_name):
                        demangled = demangle(raw_name)
                        if demangled:
                            demangled = remove_bad_spaces(demangled)
                            function_offset = active_base + symbol.section.virtual_address + symbol.value
                            if function_offset not in self._func_symbols:
                                self._func_symbols[function_offset] = demangled
                except _DEMANGLE_ERRORS as exc:
                    LOGGER.debug("Failed to demangle Rust symbol %s: %s", symbol.name, exc)

    def _parse_lief_symbols(self, symbols):
        # working example: 3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75
        function_symbols = {}
        for symbol in symbols:
            if symbol is not None and symbol.is_function and symbol.value != 0:
                # We want the raw name to check for Rust mangling
                raw_name = symbol.name
                if self._is_rust_symbol(raw_name):
                    try:
                        demangled = demangle(raw_name)
                        if demangled:
                            demangled = remove_bad_spaces(demangled)
                            function_symbols[symbol.value] = demangled
                    except _DEMANGLE_ERRORS as exc:
                        LOGGER.debug("Failed to demangle Rust symbol %s: %s", raw_name, exc)
        return function_symbols

    def _is_rust_symbol(self, name: str) -> bool:
        """Check if a symbol name appears to be a Rust mangled symbol.

        Legacy Rust mangling uses _ZN prefix (compatible with C++ Itanium ABI).
        Rust v0 mangling uses _R prefix.
        Some platforms may use __ prefix variants.

        Note: We intentionally exclude bare 'R' and 'ZN' prefixes as they are
        too broad and could match non-Rust symbols.
        """
        return name.startswith(("_ZN", "_R", "__ZN", "__R"))

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
