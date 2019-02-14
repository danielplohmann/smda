#!/usr/bin/python

import json
import logging
import os
LOGGER = logging.getLogger(__name__)

try:
    import lief
except:
    lief = None
    LOGGER.warn("3rd party library LIEF not installed - won't be able to extract symbols for ELF files where available.")

from .AbstractLabelProvider import AbstractLabelProvider


class ElfSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for ELF symbols """

    def __init__(self, config):
        self._config = config
        #addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def update(self, file_path, binary):
        #works both for PE and ELF
        self._func_symbols = {}
        if not file_path:
            return
        data = ""
        with open(file_path, "rb") as fin:
            data = fin.read()
        if not data[:4] == b"\x7FELF":
            return
        lief_binary = lief.parse(file_path)
        # TODO split resolution into API/dynamic part and local symbols
        self._parseSymbols(lief_binary.static_symbols)
        self._parseSymbols(lief_binary.dynamic_symbols)
        for reloc in lief_binary.relocations:
            self._func_symbols[reloc.address] = reloc.symbol.name

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
