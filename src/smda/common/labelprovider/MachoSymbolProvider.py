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
        self._binary_info = None

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return True

    def getApi(self, to_addr, absolute_addr=None):
        return self._api_map.get(to_addr, ("", ""))

    def _get_macho_binary(self, lief_binary):
        if isinstance(lief_binary, lief.MachO.FatBinary):
            if len(lief_binary) == 0:
                return None
            if hasattr(self, "_binary_info") and self._binary_info:
                target_bitness = self._binary_info.bitness
                for binary in lief_binary:
                    binary_bitness = 64 if binary.header.is_64bit else 32
                    if target_bitness and binary_bitness != target_bitness:
                        continue
                    return binary
            return lief_binary[0]
        return lief_binary

    def _get_address_adjustment(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary:
            return 0
        candidates = []
        if hasattr(lief_binary, "imagebase"):
            candidates.append(lief_binary.imagebase)
        for section in getattr(lief_binary, "sections", []):
            if section.virtual_address and section.offset:
                candidates.append(section.virtual_address - section.offset)
        lief_base = min(candidates) if candidates else 0
        smda_base = lief_base
        if hasattr(self, "_binary_info") and self._binary_info:
            smda_base = self._binary_info.base_addr
        return smda_base - lief_base

    def update(self, binary_info):
        self._binary_info = binary_info
        self._func_symbols = {}
        self._api_map = {}
        lief_binary = self._get_macho_binary(binary_info.getLiefBinary())

        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return

        adjustment = self._get_address_adjustment(lief_binary)

        if hasattr(lief_binary, "entrypoint"):
            adjusted_entrypoint = lief_binary.entrypoint + adjustment
            if binary_info.isInCodeAreas(adjusted_entrypoint):
                self._func_symbols[adjusted_entrypoint] = "original_entry_point"

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
                adjusted_stub_addr = stub.address + adjustment
                if stub.address != 0 and binary_info.isInCodeAreas(adjusted_stub_addr):
                    self._func_symbols[adjusted_stub_addr] = f"stub_{adjusted_stub_addr:x}"
        except Exception:
            pass

        # Populate API map from imports/bindings
        self._api_map = self.parseImports(lief_binary)

    def parseExports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        exported = {}
        for symbol in lief_binary.exported_symbols:
            if symbol.value != 0 and symbol.name:
                adjusted_val = symbol.value + adjustment
                exported[adjusted_val] = symbol.name
        return exported

    def parseSymbols(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        symbols = {}
        for symbol in lief_binary.symbols:
            if symbol.value != 0 and symbol.name:
                func_name = getattr(symbol, "demangled_name", None) or symbol.name
                adjusted_val = symbol.value + adjustment
                symbols[adjusted_val] = func_name
        return symbols

    def parseImports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        imports = {}
        try:
            for binding in lief_binary.bindings:
                if binding.address != 0 and binding.symbol and binding.symbol.name:
                    lib_name = binding.library.name.lower() if binding.has_library else ""
                    adjusted_addr = binding.address + adjustment
                    imports[adjusted_addr] = (lib_name, binding.symbol.name)
        except Exception as e:
            LOGGER.debug("Failed to parse Mach-O bindings: %s", e)
        return imports

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols) or bool(self._api_map)
