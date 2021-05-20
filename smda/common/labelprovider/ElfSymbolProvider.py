#!/usr/bin/python

import logging
from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)

try:
    import lief
    lief.logging.disable()
except:
    lief = None
    LOGGER.warning("3rd party library LIEF not installed - won't be able to extract symbols for ELF files where available.")



class ElfSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for ELF symbols """

    def __init__(self, config):
        self._config = config
        #addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def _parseOep(self, lief_result):
        if lief_result:
            self._func_symbols[lief_result.header.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        #works both for PE and ELF
        self._func_symbols = {}
        if not binary_info.file_path:
            return
        data = ""
        with open(binary_info.file_path, "rb") as fin:
            data = fin.read(16)
        if data[:4] != b"\x7FELF" or lief is None:
            return
        lief_binary = lief.parse(binary_info.file_path)
        self._parseOep(lief_binary)
        # TODO split resolution into API/dynamic part and local symbols
        self._parseExports(lief_binary)
        self._parseSymbols(lief_binary.static_symbols)
        self._parseSymbols(lief_binary.dynamic_symbols)
        for reloc in lief_binary.relocations:
            if reloc.has_symbol:
                self._func_symbols[reloc.address] = reloc.symbol.name

    def _parseExports(self, binary):
        for function in binary.exported_functions:
            self._func_symbols[function.address] = function.name

    def _parseSymbols(self, symbols):
        for symbol in symbols:
            if symbol.is_function:
                if symbol.value != 0:
                    func_name = ""
                    try:
                        func_name = symbol.demangled_name
                    except:
                        func_name = symbol.name
                    self._func_symbols[symbol.value] = func_name

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
