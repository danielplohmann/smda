#!/usr/bin/python

import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider

lief.logging.disable()
LOGGER = logging.getLogger(__name__)


class ElfSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for ELF symbols"""

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

    def _parseOep(self, lief_result):
        if lief_result:
            self._func_symbols[lief_result.header.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        # works both for PE and ELF
        self._func_symbols = {}

        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.ELF.Binary):
            return

        self._parseOep(lief_binary)
        # Keep only local/defined function symbols here: exported functions plus defined
        # static and dynamic symtab entries (parseSymbols drops undefined imports via value != 0).
        # Imported, relocation-backed API names are intentionally NOT merged in - they are
        # resolved as APIs by ElfApiResolver, so this stays a pure symbol provider
        # (isApiProvider() == False) and relocation slot addresses are not mistaken for symbols.
        self._func_symbols.update(self.parseExports(lief_binary))
        self._func_symbols.update(self.parseSymbols(lief_binary.symtab_symbols))
        self._func_symbols.update(self.parseSymbols(lief_binary.dynamic_symbols))

    def parseExports(self, binary):
        function_symbols = {}
        for function in binary.exported_functions:
            function_symbols[function.address] = function.name
        return function_symbols

    def parseSymbols(self, symbols):
        function_symbols = {}
        for symbol in symbols:
            if symbol is not None and symbol.is_function and symbol.value != 0:
                func_name = ""
                func_name = getattr(symbol, "demangled_name", None) or symbol.name
                function_symbols[symbol.value] = func_name
        return function_symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
