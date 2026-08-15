#!/usr/bin/python

import logging

import lief

from smda.utility.lief_helper import lief_name

from .AbstractLabelProvider import AbstractLabelProvider
from .import_parsers import parse_pe_delay_imports, parse_pe_imports, resolve_pe_base_addr
from .ItaniumDemangler import demangle_itanium_symbol

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
        export = lief_binary.get_export()
        if export is None:
            return function_symbols
        for function in export.entries:
            if function.is_extern or function.is_forwarded:
                # forwarder/extern entries redirect to another module's export and have no
                # local address (LIEF sets .address to 0 for them) - not a local function.
                continue
            function_name = lief_name(function)
            if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                function_symbols[active_base + function.address] = demangle_itanium_symbol(function_name)
        return function_symbols

    def parseSymbols(self, lief_binary, base_addr=None):
        active_base = self._resolve_base_addr(lief_binary, base_addr)
        # lief reports Symbol.section as None for every PE symbol, on 0.17 and 1.0 alike, so
        # resolving through it dropped the entire COFF symbol table. The 1-based section_idx
        # carries the same information and is populated across the supported lief range.
        sections = list(lief_binary.sections)
        function_symbols = {}
        num_candidates = 0
        for symbol in lief_binary.symbols:
            if hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION":
                num_candidates += 1
                section_idx = getattr(symbol, "section_idx", 0)
                if not 1 <= section_idx <= len(sections):
                    # 0/-1/-2 are undefined-external/absolute/debug: not a locally defined
                    # function, so its value is not a usable in-image offset.
                    continue
                function_name = lief_name(symbol)
                if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                    function_offset = active_base + sections[section_idx - 1].virtual_address + symbol.value
                    if function_offset not in function_symbols:
                        function_symbols[function_offset] = demangle_itanium_symbol(function_name)
        if num_candidates and not function_symbols:
            # the previous failure mode was silent: a whole corpus could be built unnamed
            # without anything complaining, so say so rather than contributing nothing
            LOGGER.warning(
                "PE COFF symbol table holds %d function symbols but none resolved to an in-image offset",
                num_candidates,
            )
        return function_symbols

    def parseImports(self, lief_binary, base_addr=None):
        import_symbols = parse_pe_imports(lief_binary, base_addr)
        import_symbols.update(parse_pe_delay_imports(lief_binary, base_addr))
        return import_symbols

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
