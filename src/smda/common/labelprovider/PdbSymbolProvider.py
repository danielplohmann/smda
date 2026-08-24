#!/usr/bin/python

import logging
import os
from bisect import bisect_right

import purepdb

from smda.common.ExceptionHandling import reraise_non_operational_exception

from .AbstractLabelProvider import AbstractLabelProvider
from .MsvcDemangler import demangle_msvc_symbol
from .rust_demangler import demangle
from .RustSymbolEvidence import is_rust_language_evidence

LOGGER = logging.getLogger(__name__)

PDB_MAGIC = b"Microsoft C/C++"
IMPORT_MODULE_PREFIX = "Import:"


def _demangleSymbolName(name):
    """Return the readable form of an MSVC or Rust symbol, or the name as the PDB spells it."""
    try:
        if name.startswith("?"):
            return demangle_msvc_symbol(name)
        if is_rust_language_evidence(name):
            demangled = demangle(name)
            if demangled:
                return demangled
    except Exception as exc:
        reraise_non_operational_exception(exc)
        LOGGER.debug("Failed to demangle symbol %s: %s", name, exc)
    return name


class PdbSymbolProvider(AbstractLabelProvider):
    """Resolver for PDB symbols. MSVC and Rust names are demangled; every other name is
    reported as the PDB stores it."""

    def __init__(self, config):
        self._config = config
        self._base_addr = 0
        self._func_symbols = {}
        self._procedure_starts = []
        self._procedure_extents = []
        self._loaded_pdb_path = ""

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def update(self, binary_info):
        self._func_symbols = {}
        self._procedure_starts = []
        self._procedure_extents = []
        self._base_addr = binary_info.base_addr
        if not binary_info.file_path:
            return
        binary_data = binary_info.getBinaryData()
        if not binary_data:
            return
        if binary_data[: len(PDB_MAGIC)] != PDB_MAGIC:
            self._warnAboutUnusedPdb(binary_info.file_path)
            return
        try:
            pdb = purepdb.PDB.from_bytes(binary_data)
            self._parseSymbols(pdb)
            self._loaded_pdb_path = binary_info.file_path
            self._warnAboutThinPdb(binary_info.file_path, pdb)
        except Exception as exc:
            reraise_non_operational_exception(exc)
            LOGGER.warning('Failed parsing PDB "%s" with exception: %r', binary_info.file_path, exc)

    def _warnAboutUnusedPdb(self, file_path):
        if self._loaded_pdb_path:
            return
        if file_path.lower().endswith(".pdb"):
            LOGGER.warning('"%s" is not a PDB file - no symbols were loaded from it.', file_path)
            return
        candidate = os.path.splitext(file_path)[0] + ".pdb"
        if os.path.isfile(candidate):
            LOGGER.warning(
                'Ignoring "%s" next to "%s" - pass it explicitly to use its symbols.',
                candidate,
                file_path,
            )

    def _warnAboutThinPdb(self, file_path, pdb):
        if self._func_symbols and self._procedure_starts:
            return
        if self._func_symbols:
            subject = "no procedure records, so no code sizes and no fragment attribution"
        else:
            subject = "no usable symbols"
        reasons = "; ".join(pdb.diagnose().warnings)
        LOGGER.warning('"%s" yielded %s%s', file_path, subject, f": {reasons}" if reasons else "")

    def _parseSymbols(self, pdb):
        procedures = []
        for function in pdb.functions():
            if function.rva is None:
                continue
            address = self._base_addr + function.rva
            name = _demangleSymbolName(function.name)
            if not name or any(char < " " or char == "\x7f" for char in name):
                # a PDB string table holds whatever bytes were written into it, and this name
                # travels into the serialized report; the test is for control characters
                # rather than for non-ASCII, which a demangled Rust identifier legitimately is
                continue
            self._func_symbols[address] = name
            module = function.module or ""
            if function.code_size and not module.startswith(IMPORT_MODULE_PREFIX):
                procedures.append((address, address + function.code_size, name))
        procedures.sort()
        self._procedure_starts = [start for start, _, _ in procedures]
        self._procedure_extents = [(end, name) for _, end, name in procedures]

    def _getFragmentLabel(self, address):
        index = bisect_right(self._procedure_starts, address) - 1
        if index < 0:
            return ""
        start = self._procedure_starts[index]
        end, name = self._procedure_extents[index]
        if address >= end:
            return ""
        return f"{name}$+0x{address - start:x}"

    def getSymbol(self, address):
        symbol = self._func_symbols.get(address, "")
        if symbol:
            return symbol
        return self._getFragmentLabel(address)

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
