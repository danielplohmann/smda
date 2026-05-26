#!/usr/bin/python

import logging

import dnfile

from smda.common.ExceptionHandling import reraise_non_operational_exception

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)


class CilSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for CIL/DOTNET symbols"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._addr_to_func_symbols = {}
        self._func_symbol_to_addr = {}

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def decodeSymbolName(self, value):
        """ensure a proper utf-8 escaped string"""
        return value.encode("utf-8").decode("utf-8")

    def update(self, binary_info):
        try:
            pe = dnfile.dnPE(data=binary_info.raw_data)
        except Exception as exc:
            reraise_non_operational_exception(exc)
            LOGGER.debug("Failed to parse CIL symbols: %s", exc)
            return
        if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
            return
        method_defs = getattr(pe.net.mdtables, "MethodDef", None)
        if not method_defs:
            return
        for row in method_defs:
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
