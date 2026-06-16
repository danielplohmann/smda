#!/usr/bin/python

import contextlib
import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider
from .import_parsers import parse_pe_imports, resolve_pe_base_addr

lief.logging.disable()
LOGGER = logging.getLogger(__name__)


class PeSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for PE symbols"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return (None, None)

    def _resolve_base_addr(self, lief_binary, base_addr):
        return resolve_pe_base_addr(lief_binary, base_addr)

    def _parseOep(self, lief_binary, base_addr=None):
        if lief_binary:
            active_base = self._resolve_base_addr(lief_binary, base_addr)
            oep_rva = lief_binary.optional_header.addressof_entrypoint
            self._func_symbols[active_base + oep_rva] = "original_entry_point"

    def update(self, binary_info):
        self._func_symbols = {}

        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.PE.Binary):
            return

        active_base = binary_info.base_addr
        self._parseOep(lief_binary, active_base)
        self._func_symbols.update(self.parseExports(lief_binary, active_base))
        self._func_symbols.update(self.parseSymbols(lief_binary, active_base))

    def parseExports(self, lief_binary, base_addr=None):
        active_base = self._resolve_base_addr(lief_binary, base_addr)
        function_symbols = {}
        for function in lief_binary.exported_functions:
            function_name = ""
            with contextlib.suppress(UnicodeDecodeError, AttributeError):
                # here may occur a LIEF exception that we want to skip ->
                # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                function_name = function.name
            if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                function_symbols[active_base + function.address] = function_name
        return function_symbols

    def parseSymbols(self, lief_binary, base_addr=None):
        active_base = self._resolve_base_addr(lief_binary, base_addr)
        # find VA of first code section
        function_symbols = {}
        code_base_address = None
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                code_base_address = active_base + section.virtual_address
                break
        if code_base_address is None:
            return function_symbols
        for symbol in lief_binary.symbols:
            if hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION":
                function_name = ""
                with contextlib.suppress(UnicodeDecodeError, AttributeError):
                    # here may occur a LIEF exception that we want to skip ->
                    # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                    function_name = symbol.name
                if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                    # for some reason, we need to add the section_offset of .text here
                    function_offset = code_base_address + symbol.value
                    if function_offset not in function_symbols:
                        function_symbols[function_offset] = function_name
        return function_symbols

    def parseImports(self, lief_binary, base_addr=None):
        return parse_pe_imports(lief_binary, base_addr)

    def collectSymbols(self, lief_binary, base_addr=None):
        symbols = {}
        symbols.update(self.parseExports(lief_binary, base_addr))
        symbols.update(self.parseSymbols(lief_binary, base_addr))
        return symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
