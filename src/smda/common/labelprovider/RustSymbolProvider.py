#!/usr/bin/python

import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider
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

    def getApi(self, to_address, api_address=None):
        return ("", "")

    def update(self, binary_info):
        self._func_symbols = {}

        try:
            lief_binary = binary_info.getLiefBinary()
        except Exception as exc:
            LOGGER.debug("Failed to parse binary with LIEF: %s", type(exc).__name__)
            return

        if not lief_binary or not self.is_rust_binary(binary_info):
            return

        # Dispatch to appropriate handler based on binary type
        if isinstance(lief_binary, lief.ELF.Binary):
            self._update_elf(lief_binary)
        elif isinstance(lief_binary, lief.PE.Binary):
            self._update_pe(lief_binary)

    def is_rust_binary(self, binary_info):
        """
        Checks for Rust signatures in the binary data.
        Based on Ghidra's Rust detection logic.
        """
        data = self._get_binary_data(binary_info)
        if not data:
            return False

        # Ghidra checks for these byte sequences
        signatures = [b"RUST_BACKTRACE", b"RUST_MIN_STACK", b"/rustc/"]

        return any(sig in data for sig in signatures)

    def _get_binary_data(self, binary_info):
        """Safely retrieves binary data from either raw_data or a file path."""
        data = binary_info.raw_data
        if not data and binary_info.file_path:
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

    def _update_pe(self, lief_binary):
        """Process PE binary symbols for Rust demangling."""
        # Parse PE exports
        for function in lief_binary.exported_functions:
            try:
                try:
                    raw_name = function.name
                except (UnicodeDecodeError, AttributeError):
                    continue

                if self._is_rust_symbol(raw_name):
                    demangled = demangle(raw_name)
                    if demangled:
                        demangled = remove_bad_spaces(demangled)
                        self._func_symbols[lief_binary.imagebase + function.address] = demangled
            except _DEMANGLE_ERRORS as exc:
                LOGGER.debug("Failed to demangle Rust symbol %s: %s", function.name, exc)

        code_base_address = None
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                code_base_address = lief_binary.imagebase + section.virtual_address
                break
        if code_base_address is None:
            return
        # working example: 3969e1a88a063155a6f61b0ca1ac33114c1a39151f3c7dd019084abd30553eab
        # Parse PE symbols (COFF) if available and LIEF extracted them
        # (Similar logic to PeSymbolProvider but focusing on Rust)
        for symbol in lief_binary.symbols:
            # Check if it is a function symbol and has a section
            if (
                hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION"
            ):  # and symbol.has_section:
                try:
                    try:
                        raw_name = symbol.name
                    except (UnicodeDecodeError, AttributeError):
                        continue
                    if self._is_rust_symbol(raw_name):
                        demangled = demangle(raw_name)
                        if demangled:
                            demangled = remove_bad_spaces(demangled)
                            function_offset = code_base_address + symbol.value
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
