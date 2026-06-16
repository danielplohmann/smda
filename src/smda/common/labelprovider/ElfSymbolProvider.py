#!/usr/bin/python

import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider

lief.logging.disable()
LOGGER = logging.getLogger(__name__)


def parse_relocation_imports(lief_binary):
    """Build import map keyed by relocation slot address: addr -> (lib, name)."""
    if not isinstance(lief_binary, lief.ELF.Binary):
        return {}
    import_symbols = {}
    for relocation in lief_binary.relocations:
        if not relocation.has_symbol:
            continue
        symbol = relocation.symbol
        if symbol is None:
            continue
        if not symbol.imported or not symbol.is_function:
            continue

        lib = None
        if symbol.has_version and symbol.symbol_version.has_auxiliary_version:
            lib = symbol.symbol_version.symbol_version_auxiliary.name

        import_symbols[relocation.address] = (lib, symbol.name)
    return import_symbols


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
        return (None, None)

    def _parseOep(self, lief_result):
        # Symbol map keys use absolute VAs; BinaryInfo.getOep() stores a base-relative offset.
        if lief_result:
            self._func_symbols[lief_result.header.entrypoint] = "original_entry_point"

    def update(self, binary_info):
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

    def parseImports(self, lief_binary):
        if not isinstance(lief_binary, lief.ELF.Binary):
            return {}
        return parse_relocation_imports(lief_binary)

    def collectSymbols(self, lief_binary):
        if not isinstance(lief_binary, lief.ELF.Binary):
            return {}
        symbols = {}
        symbols.update(self.parseExports(lief_binary))
        symbols.update(self.parseSymbols(lief_binary.symtab_symbols))
        symbols.update(self.parseSymbols(lief_binary.dynamic_symbols))
        return symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
