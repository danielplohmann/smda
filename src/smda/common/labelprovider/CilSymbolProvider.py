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
        self._ambiguous_func_symbols = set()

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def decodeSymbolName(self, value):
        """ensure a proper utf-8 escaped string"""
        return value.encode("utf-8").decode("utf-8")

    def update(self, binary_info, parsed=None):
        self._addr_to_func_symbols = {}
        self._func_symbol_to_addr = {}
        self._ambiguous_func_symbols = set()
        try:
            pe = dnfile.dnPE(data=binary_info.raw_data) if parsed is None else parsed
        except Exception as exc:
            reraise_non_operational_exception(exc)
            LOGGER.warning("Failed to parse CIL symbols: %s", exc)
            return
        if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
            return
        method_defs = getattr(pe.net.mdtables, "MethodDef", None)
        if not method_defs:
            return
        for row in method_defs:
            if not row.Rva or not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
                continue
            try:
                # get_offset_from_rva raises PEFormatError for any RVA outside a section,
                # trivially reachable from a crafted MethodDef row; skip that row only
                addr = pe.get_offset_from_rva(row.Rva)
                func_name = self.decodeSymbolName(row.Name.value)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.debug("Skipping malformed CIL MethodDef row: %s", exc)
                continue
            self._addr_to_func_symbols[addr] = func_name
            if func_name in self._func_symbol_to_addr:
                # a name is not a key: .ctor and every overload set repeat, and resolving
                # one to whichever row happened to be parsed last rewrites a call operand
                # to a different method that merely shares the name
                self._ambiguous_func_symbols.add(func_name)
            else:
                self._func_symbol_to_addr[func_name] = addr

    def getSymbol(self, address):
        return self._addr_to_func_symbols.get(address, "")

    def getAddress(self, func_symbol):
        if func_symbol in self._ambiguous_func_symbols:
            return None
        return self._func_symbol_to_addr.get(func_symbol, None)

    def getFunctionSymbols(self):
        return self._addr_to_func_symbols
