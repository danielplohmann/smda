#!/usr/bin/python

import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider

lief.logging.disable()
LOGGER = logging.getLogger(__name__)


class MachoSymbolProvider(AbstractLabelProvider):
    """Resolver for Mach-O symbols, exports, and imports"""

    def __init__(self, config):
        self._config = config
        self._func_symbols = {}
        self._api_map = {}

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return True

    def getApi(self, to_addr, absolute_addr=None):
        return self._api_map.get(to_addr, ("", ""))

    def _get_macho_binary(self, lief_binary):
        if isinstance(lief_binary, lief.MachO.FatBinary):
            if len(lief_binary) > 0:
                return lief_binary[0]
            return None
        return lief_binary

    def update(self, binary_info):
        self._func_symbols = {}
        self._api_map = {}
        lief_binary = self._get_macho_binary(binary_info.getLiefBinary())

        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return

        if hasattr(lief_binary, "entrypoint") and binary_info.isInCodeAreas(lief_binary.entrypoint):
            self._func_symbols[lief_binary.entrypoint] = "original_entry_point"

        # Parse export trie symbols
        for addr, name in self.parseExports(lief_binary).items():
            if binary_info.isInCodeAreas(addr):
                self._func_symbols[addr] = name

        # Parse general symtab symbols
        for addr, name in self.parseSymbols(lief_binary).items():
            if binary_info.isInCodeAreas(addr):
                self._func_symbols[addr] = name

        # Parse symbol stubs
        try:
            for stub in lief_binary.symbol_stubs:
                if stub.address != 0 and binary_info.isInCodeAreas(stub.address):
                    self._func_symbols[stub.address] = f"stub_{stub.address:x}"
        except Exception:
            pass

        # Populate API map from imports/bindings
        self._api_map = self.parseImports(lief_binary)

    def parseExports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        exported = {}
        for symbol in lief_binary.exported_symbols:
            if symbol.value != 0 and symbol.name:
                exported[symbol.value] = symbol.name
        return exported

    def parseSymbols(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        symbols = {}
        for symbol in lief_binary.symbols:
            if symbol.value != 0 and symbol.name:
                func_name = getattr(symbol, "demangled_name", None) or symbol.name
                symbols[symbol.value] = func_name
        return symbols

    def parseImports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        imports = {}
        try:
            for binding in lief_binary.bindings:
                if binding.address != 0 and binding.symbol and binding.symbol.name:
                    lib_name = binding.library.name.lower() if binding.has_library else ""
                    imports[binding.address] = (lib_name, binding.symbol.name)
        except Exception as e:
            LOGGER.debug("Failed to parse Mach-O bindings: %s", e)
        return imports

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols) or bool(self._api_map)
