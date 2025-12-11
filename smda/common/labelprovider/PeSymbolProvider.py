#!/usr/bin/python

import contextlib
import logging

import lief

from smda.common.labelprovider.OrdinalHelper import OrdinalHelper

from .AbstractLabelProvider import AbstractLabelProvider

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

    def _parseOep(self, lief_result):
        if lief_result:
            self._func_symbols[lief_result.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        # works both for PE and ELF
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
            self._func_symbols.update(self.parseExports(lief_binary))
            self._func_symbols.update(self.parseSymbols(lief_binary))

    def parseExports(self, lief_binary):
        function_symbols = {}
        for function in lief_binary.exported_functions:
            function_name = ""
            with contextlib.suppress(UnicodeDecodeError, AttributeError):
                # here may occur a LIEF exception that we want to skip ->
                # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                function_name = function.name
            if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                function_symbols[lief_binary.imagebase + function.address] = function_name
        return function_symbols

    def parseSymbols(self, lief_binary):
        # find VA of first code section
        function_symbols = {}
        code_base_address = None
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                code_base_address = lief_binary.imagebase + section.virtual_address
                break
        if code_base_address is None:
            return
        for symbol in lief_binary.symbols:
            if hasattr(symbol.complex_type, "name") and symbol.complex_type.name == "FUNCTION":
                function_name = ""
                with contextlib.suppress(UnicodeDecodeError, AttributeError):
                    # here may occur a LIEF exception that we want to skip ->
                    # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
                    function_name = symbol.name
                if function_name and all(ord(c) in range(0x20, 0x7F) for c in function_name):
                    # for some reason, we need to add the section_offset of .text here
                    function_offset = code_base_address + symbol.value
                    if function_offset not in function_symbols:
                        function_symbols[function_offset] = function_name
        return function_symbols

    def parseImports(self, lief_binary):
        import_symbols = {}
        for imported_library in lief_binary.imports:
            for func in imported_library.entries:
                if func.name:
                    import_symbols[func.iat_address + lief_binary.imagebase] = (
                        imported_library.name.lower(),
                        func.name,
                    )
                elif func.is_ordinal:
                    resolved_ordinal = OrdinalHelper.resolveOrdinal(imported_library.name.lower(), func.ordinal)
                    ordinal_name = resolved_ordinal if resolved_ordinal else f"#{func.ordinal}"
                    import_symbols[func.iat_address + lief_binary.imagebase] = (
                        imported_library.name.lower(),
                        ordinal_name,
                    )
        return import_symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
