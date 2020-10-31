#!/usr/bin/python

import logging

from smda.utility.PeFileLoader import PeFileLoader
from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)

try:
    import pdbparse
    from pdbparse.undname import undname
except:
    pdbparse = None
    LOGGER.debug("3rd party library pdbparse (use fork @ https://github.com/VPaulV/pdbparse) not installed - won't be able to extract symbols from PDB files where available.")


class DummyOmap(object):
    def remap(self, addr):
        return addr


class PdbSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for PDB symbols """

    def __init__(self, config):
        self._config = config
        self._base_addr = 0
        # addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def _parseOep(self, data):
        oep_rva = PeFileLoader.getOEP(data)
        if oep_rva:
            self._func_symbols[self._base_addr + oep_rva] = "original_entry_point"

    def update(self, binary_info):
        self._base_addr = binary_info.base_addr
        if not binary_info.file_path:
            return
        data = ""
        with open(binary_info.file_path, "rb") as fin:
            data = fin.read(16)
        self._parseOep(data)
        if data[:15] != b"Microsoft C/C++" or pdbparse is None:
            return
        try:
            pdb = pdbparse.parse(binary_info.file_path)
            self._parseSymbols(pdb)
        except Exception as exc:
            LOGGER.error("Failed parsing \"%s\" with exception type: %s", binary_info.file_path, type(exc))

    def _parseSymbols(self, pdb):
        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            omap = pdb.STREAM_OMAP_FROM_SRC
        except AttributeError:
            sects = pdb.STREAM_SECT_HDR.sections
            omap = DummyOmap()
        gsyms = pdb.STREAM_GSYM
        for sym in gsyms.globals:
            try:
                off = sym.offset
                if len(sects) < sym.segment:
                    continue
                virt_base = sects[sym.segment - 1].VirtualAddress
                function_address = (self._base_addr + omap.remap(off + virt_base))
                demangled_name = undname(sym.name)
                if sym.symtype == 2:
                    # print("0x%x + 0x%x + 0x%x = 0x%x: %s || %s (type: %d)" % (self._base_addr, off, virt_base, function_address, sym.name, demangled_name, sym.symtype))
                    self._func_symbols[function_address] = demangled_name
            except AttributeError:
                pass

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols
