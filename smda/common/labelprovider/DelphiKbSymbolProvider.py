#!/usr/bin/python
import logging
import os
import re
from io import BytesIO

from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)


class DelphiKbSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for Delphi knowledge base files"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}
        self._relocations = {}

    def update(self, binary_info):
        binary = binary_info.binary
        if DelphiKbFileLoader.isCompatible(binary):
            self._func_symbols = self.parseKbBuffer(binary, binary_info.base_addr)

    def isSymbolProvider(self):
        return True

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def getRelocations(self):
        return self._relocations

    def parseKbBuffer(self, binary, base_addr):
        result = {}
        fh = BytesIO(binary)
        fh.seek(-4, os.SEEK_END)
        fh.seek(int.from_bytes(fh.read(4), byteorder="little"))
        # process modules
        len_mod_data_table = int.from_bytes(fh.read(4), byteorder="little")
        fh.read(4)
        modules = {}
        for _i in range(len_mod_data_table):
            offset = int.from_bytes(fh.read(4), byteorder="little")
            size = int.from_bytes(fh.read(4), byteorder="little")
            modId = int.from_bytes(fh.read(4), byteorder="little")
            namID = int.from_bytes(fh.read(4), byteorder="little")
            modules[modId] = {}
            modules[modId]["offset"] = offset
            modules[modId]["size"] = size
            modules[modId]["namID"] = namID
        temp_off = fh.tell()
        for modID in modules:
            fh.seek(modules[modID]["offset"])
            if modID != int.from_bytes(fh.read(2), byteorder="little"):
                print("ModID doesnt match" + str(modules[modID]["offset"]))
            len_name = int.from_bytes(fh.read(2), byteorder="little")
            modules[modID]["name"] = fh.read(len_name).decode()
            modules[modID]["functions"] = []
        fh.seek(temp_off)
        # process functions and their code
        for _i in range(4):
            fh.seek(int.from_bytes(fh.read(4), byteorder="little") * 16 + fh.tell() + 4)
        len_fun_data_table = int.from_bytes(fh.read(4), byteorder="little")
        fh.read(4)
        for _i in range(len_fun_data_table):
            offset = int.from_bytes(fh.read(4), byteorder="little")
            temp_off = fh.tell()
            fh.seek(offset)
            function_info = {}
            function_info["modId"] = int.from_bytes(fh.read(2), byteorder="little")
            len_name = int.from_bytes(fh.read(2), byteorder="little")
            function_info["name"] = fh.read(len_name).decode()
            fh.read(9)
            len_type = int.from_bytes(fh.read(2), byteorder="little")
            fh.read(len_type)
            fh.read(5)
            function_info["dump_size"] = int.from_bytes(fh.read(4), byteorder="little")
            fh.read(4)
            function_code_start_offset = fh.tell()
            result[base_addr + function_code_start_offset] = function_info["name"]
            function_info["dump"] = list(fh.read(function_info["dump_size"]))
            # relocations mark both call but also data ref offsets
            function_info["reloc"] = fh.read(function_info["dump_size"])
            for match in re.finditer(b"\xff\xff\xff\xff", function_info["reloc"]):
                self._relocations[function_code_start_offset + match.start()] = 0
            modules[function_info["modId"]]["functions"].append(function_info)
            fh.seek(temp_off + 12)
        return result
