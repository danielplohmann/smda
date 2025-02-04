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
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def update(self, binary_info):
        pe = dnfile.dnPE(data=binary_info.raw_data)
        for row in pe.net.mdtables.MethodDef:
            addr = pe.get_offset_from_rva(row.Rva)
            func_name = str(row.Name)
            self._func_symbols[addr] = func_name

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
