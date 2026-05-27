#!/usr/bin/python
import lief

from .AbstractLabelProvider import AbstractLabelProvider

lief.logging.disable()


class ElfApiResolver(AbstractLabelProvider):
    """Minimal ELF API reference resolver, extracting APIs from ELF imports"""

    def __init__(self, config):
        self._api_map = {"lief": {}}

    def update(self, binary_info):
        if binary_info.is_buffer:
            # cannot reconstruct from shellcode/memory dump at this time
            return

        else:
            lief_binary = binary_info.getLiefBinary()
            if not isinstance(lief_binary, lief.ELF.Binary):
                return

            for relocation in lief_binary.relocations:
                if not relocation.has_symbol:
                    continue
                symbol = relocation.symbol
                if symbol is None:
                    continue
                if not symbol.imported or not symbol.is_function:
                    continue

                # we can't really say what library the symbol came from
                # however, we can treat the version (if present) as relevant metadata?
                # note: this only works for GNU binaries, such as for Linux
                lib = None
                if symbol.has_version and symbol.symbol_version.has_auxiliary_version:
                    # like "GLIBC_2.2.5"
                    lib = symbol.symbol_version.symbol_version_auxiliary.name

                name = symbol.name
                address = relocation.address

                self._api_map["lief"][address] = (lib, name)

    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return True

    def isSymbolProvider(self):
        return False

    def getSymbol(self, address):
        return ""

    def getFunctionSymbols(self):
        return {}

    def getApi(self, to_addr, absolute_addr=None):
        """
        If the LabelProvider has any information about a used API for the given address, return (dll, api), else return (None, None).

        May return None for the `dll` if it cannot be determined.
        When it can be determined for ELF files, the `dll` field should be interpreted as the API version rather than shared library name.
        For example: "GLIBC_2.2.5".
        `absolute_addr` is part of the label-provider API but intentionally unused here:
        ELF lookups are keyed by relocation slot address (`to_addr`) in `_api_map["lief"]`.
        """
        return self._api_map["lief"].get(to_addr, (None, None))

    def is_active(self):
        return bool(self._api_map.get("lief"))
