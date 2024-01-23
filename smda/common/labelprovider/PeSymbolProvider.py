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



class PeSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for PE symbols """

    def __init__(self, config):
        self._config = config
        #addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def _parseOep(self, lief_result):
        if lief_result:
            self._func_symbols[lief_result.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        #works both for PE and ELF
        self._func_symbols = {}
        if not binary_info.file_path:
            return
        data = ""
        with open(binary_info.file_path, "rb") as fin:
            data = fin.read(16)
        if data[:2] != b"MZ" or lief is None:
            return
        lief_binary = lief.parse(binary_info.file_path)
        if lief_binary is not None:
            self._parseOep(lief_binary)
            self._parseExports(lief_binary)
            self._parseSymbols(lief_binary)

    def _parseExports(self, binary):
        for function in binary.exported_functions:
            function_name = ""
            try:
                # here may occur a LIEF exception that we want to skip ->
                # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                function_name = function.name
            except:
                pass
            if function_name and all(c in range(0x20, 0x7f) for c in function_name):
                self._func_symbols[binary.imagebase + function.address] = function_name

    def _parseSymbols(self, lief_binary):
        # find VA of first code section
        code_base_address = None
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                code_base_address = lief_binary.imagebase + section.virtual_address
                break
        if code_base_address is None:
            return
        for symbol in lief_binary.symbols:
            if symbol.complex_type.name == "FUNCTION":
                function_name = ""
                try:
                    # here may occur a LIEF exception that we want to skip ->
                    # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                    function_name = symbol.name
                except:
                    pass
                if function_name and all(c in range(0x20, 0x7f) for c in function_name):
                    # for some reason, we need to add the section_offset of .text here
                    function_offset = code_base_address + symbol.value
                    if function_offset not in self._func_symbols:
                        self._func_symbols[function_offset] = function_name

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
