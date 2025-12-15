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

    def _parseOep(self, lief_result):
        if lief_result:
            self._func_symbols[lief_result.header.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        # works both for PE and ELF
        self._func_symbols = {}
        data = b""
        if binary_info.file_path:
            with open(binary_info.file_path, "rb") as fin:
                data = fin.read()
        elif binary_info.raw_data:
            data = binary_info.raw_data
        else:
            return
        if data[:4] != b"\x7fELF" or lief is None:
            return
        lief_binary = lief.parse(data)
        self._parseOep(lief_binary)
        # TODO split resolution into API/dynamic part and local symbols
        self._func_symbols.update(self.parseExports(lief_binary))
        self._func_symbols.update(self.parseSymbols(lief_binary.symtab_symbols))
        self._func_symbols.update(self.parseSymbols(lief_binary.dynamic_symbols))
        for reloc in lief_binary.relocations:
            if reloc.has_symbol:
                self._func_symbols[reloc.address] = reloc.symbol.name

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
                try:
                    func_name = symbol.demangled_name
                except AttributeError:
                    func_name = symbol.name
                function_symbols[symbol.value] = func_name
        return function_symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
