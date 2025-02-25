#!/usr/bin/python

import logging

import dnfile
from dnfile.enums import MetadataTables

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)


class CilSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for CIL/DOTNET symbols """

    def __init__(self, config):
        self._config = config
        #addr:func_name
        self._addr_to_func_symbols = {}
        self._func_symbol_to_addr = {}

    def isSymbolProvider(self):
        return True
    
    def decodeSymbolName(self, value):
        """ ensure a proper utf-8 escaped string """
        return value.encode("utf-8").decode("utf-8")

    def update(self, binary_info):
        pe = dnfile.dnPE(data=binary_info.raw_data)
        for row in pe.net.mdtables.MethodDef:
            addr = pe.get_offset_from_rva(row.Rva)
            func_name = self.decodeSymbolName(row.Name.value)
            self._addr_to_func_symbols[addr] = func_name
            self._func_symbol_to_addr[func_name] = addr

    def getSymbol(self, address):
        return self._addr_to_func_symbols.get(address, "")

    def getAddress(self, func_symbol):
        return self._func_symbol_to_addr.get(func_symbol, None)

    def getFunctionSymbols(self):
        return self._addr_to_func_symbols
