#!/usr/bin/python

import logging

from .AbstractLabelProvider import AbstractLabelProvider
from .rust_demangler import demangle
from .rust_demangler.utils import remove_bad_spaces

LOGGER = logging.getLogger(__name__)


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

        # Optional: Check if this is likely a Rust binary before proceeding
        # This can be used to skip processing or to provide a confidence metric,
        # though currently we just use it for logging or future optimization.
        # Ideally, if it's NOT a Rust binary, we might want to avoid aggressive symbol checks,
        # but the _is_rust_symbol check is specific enough.
        # self.is_rust_binary(binary_info)

        # Check if it is ELF
        if binary_info.raw_data and binary_info.raw_data[:4] == b"\x7fELF":
            self._update_elf(binary_info)
        # Check if it is PE (start with MZ)
        elif binary_info.raw_data and binary_info.raw_data[:2] == b"MZ":
            self._update_pe(binary_info)

    def is_rust_binary(self, binary_info):
        """
        Checks for Rust signatures in the binary data.
        Based on Ghidra's Rust detection logic.
        """
        data = binary_info.raw_data
        if not data and binary_info.file_path:
            try:
                with open(binary_info.file_path, "rb") as fin:
                    data = fin.read()
            except OSError:
                return False

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

    def _update_elf(self, binary_info):
        try:
            import lief

            lief.logging.disable()
        except ImportError:
            return

        data = self._get_binary_data(binary_info)
        if not data:
            return

        try:
            lief_binary = lief.parse(data)
        except Exception as exc:
            LOGGER.debug("Failed to parse ELF binary with LIEF: %s", type(exc).__name__)
            return

        if not lief_binary:
            return

        self._func_symbols.update(self._parse_lief_symbols(lief_binary.symtab_symbols))
        self._func_symbols.update(self._parse_lief_symbols(lief_binary.dynamic_symbols))

    def _update_pe(self, binary_info):
        try:
            import lief

            lief.logging.disable()
        except ImportError:
            return

        data = self._get_binary_data(binary_info)
        if not data:
            return

        try:
            lief_binary = lief.parse(data)
        except Exception as exc:
            LOGGER.debug("Failed to parse PE binary with LIEF: %s", type(exc).__name__)
            return

        if not lief_binary:
            return

        # Parse PE exports
        for function in lief_binary.exported_functions:
            try:
                raw_name = function.name
                if self._is_rust_symbol(raw_name):
                    demangled = demangle(raw_name)
                    if demangled:
                        demangled = remove_bad_spaces(demangled)
                        self._func_symbols[lief_binary.imagebase + function.address] = demangled
            except Exception as exc:
                LOGGER.debug("Failed to demangle Rust symbol %s: %s", function.name, exc)

        # Parse PE symbols (COFF) if available and LIEF extracted them
        # (Similar logic to PeSymbolProvider but focusing on Rust)
        code_base_address = None
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                code_base_address = lief_binary.imagebase + section.virtual_address
                break

        if code_base_address is not None:
            for symbol in lief_binary.symbols:
                # Check if it is a function symbol (simple check)
                if hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION":
                    try:
                        raw_name = symbol.name
                        if self._is_rust_symbol(raw_name):
                            demangled = demangle(raw_name)
                            if demangled:
                                demangled = remove_bad_spaces(demangled)
                                function_offset = code_base_address + symbol.value
                                if function_offset not in self._func_symbols:
                                    self._func_symbols[function_offset] = demangled
                    except Exception as exc:
                        LOGGER.debug("Failed to demangle Rust symbol %s: %s", symbol.name, exc)

    def _parse_lief_symbols(self, symbols):
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
                    except Exception as exc:
                        LOGGER.debug("Failed to demangle Rust symbol %s: %s", raw_name, exc)
        return function_symbols

    def _is_rust_symbol(self, name):
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
