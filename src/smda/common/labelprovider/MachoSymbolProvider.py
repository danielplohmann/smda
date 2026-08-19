#!/usr/bin/python

import logging

import lief

from smda.utility.lief_helper import lief_name
from smda.utility.MachoBinary import (
    get_active_macho_binary,
    get_macho_address_adjustment,
)

from .AbstractLabelProvider import AbstractLabelProvider
from .import_parsers import parse_macho_bindings
from .MachoDemangler import demangle_macho_symbol

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
        if to_addr in self._api_map:
            return self._api_map[to_addr]
        if absolute_addr is not None and absolute_addr in self._api_map:
            return self._api_map[absolute_addr]
        return (None, None)

    def _get_macho_binary(self, lief_binary):
        binary_info = getattr(self, "_binary_info", None)
        return get_active_macho_binary(
            lief_binary,
            bitness=getattr(binary_info, "bitness", None) if binary_info else None,
            architecture=getattr(binary_info, "architecture", "") if binary_info else "",
        )

    def _get_address_adjustment(self, lief_binary):
        binary_info = getattr(self, "_binary_info", None)
        return get_macho_address_adjustment(
            lief_binary,
            base_addr=getattr(binary_info, "base_addr", 0) if binary_info else 0,
            bitness=getattr(binary_info, "bitness", None) if binary_info else None,
            architecture=getattr(binary_info, "architecture", "") if binary_info else "",
        )

    _get_symbol_name = staticmethod(lief_name)

    @classmethod
    def _format_symbol_name(cls, symbol):
        raw_name = cls._get_symbol_name(symbol)
        if not raw_name:
            return ""
        demangled = lief_name(symbol, "demangled_name")
        if demangled and demangled != raw_name:
            return demangled
        return demangle_macho_symbol(raw_name)

    def _filter_symbols_to_code(self, symbols, binary_info):
        if not binary_info:
            return symbols
        return {addr: name for addr, name in symbols.items() if binary_info.isInCodeAreas(addr)}

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

        for addr, name in self.parseExports(lief_binary).items():
            if binary_info.isInCodeAreas(addr):
                self._func_symbols[addr] = name

        for addr, name in self.parseSymbols(lief_binary).items():
            if binary_info.isInCodeAreas(addr):
                self._func_symbols[addr] = name

        try:
            for stub in getattr(lief_binary, "symbol_stubs", []):
                adjusted_stub_addr = stub.address + adjustment
                if (
                    stub.address != 0
                    and binary_info.isInCodeAreas(adjusted_stub_addr)
                    and adjusted_stub_addr not in self._func_symbols
                ):
                    self._func_symbols[adjusted_stub_addr] = f"stub_{adjusted_stub_addr:x}"
        except Exception:
            pass

        self._api_map = self.parseImports(lief_binary)

    def parseExports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        exported = {}
        try:
            for symbol in getattr(lief_binary, "exported_symbols", []):
                symbol_name = self._get_symbol_name(symbol)
                if symbol.value != 0 and symbol_name:
                    adjusted_val = symbol.value + adjustment
                    exported[adjusted_val] = demangle_macho_symbol(symbol_name)
        except Exception as e:
            LOGGER.debug("Failed to parse Mach-O exports: %s", e)
        return exported

    def parseSymbols(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        symbols = {}
        try:
            for symbol in getattr(lief_binary, "symbols", []):
                symbol_name = self._format_symbol_name(symbol)
                if symbol.value != 0 and symbol_name:
                    adjusted_val = symbol.value + adjustment
                    symbols[adjusted_val] = symbol_name
        except Exception as e:
            LOGGER.debug("Failed to parse Mach-O symbols: %s", e)
        return symbols

    def parseImports(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        adjustment = self._get_address_adjustment(lief_binary)
        return parse_macho_bindings(lief_binary, adjustment)

    def collectSymbols(self, lief_binary):
        lief_binary = self._get_macho_binary(lief_binary)
        if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
            return {}
        symbols = {}
        symbols.update(self.parseExports(lief_binary))
        symbols.update(self.parseSymbols(lief_binary))
        return symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols) or bool(self._api_map)
