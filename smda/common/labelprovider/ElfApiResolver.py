#!/usr/bin/python
import lief
lief.logging.disable()

from .AbstractLabelProvider import AbstractLabelProvider


class ElfApiResolver(AbstractLabelProvider):
    """ Minimal ELF API reference resolver, extracting APIs from ELF imports """

    def __init__(self, config):
        self._api_map = {
            "lief": {}
        }

    def update(self, binary_info):
        if binary_info.is_buffer:
            # cannot reconstruct from shellcode/memory dump at this time
            return

        else:
            lief_binary = lief.parse(binary_info.raw_data)

            if not isinstance(lief_binary, lief.ELF.Binary):
                return

            for relocation in lief_binary.relocations:
                if not relocation.has_symbol:
                    # doesn't have a name, we won't care about it
                    continue
                if not relocation.symbol.imported:
                    # only interested in APIs from external sources
                    continue
                if not relocation.symbol.is_function:
                    # only interested in APIs (which are functions)
                    continue

                # we can't really say what library the symbol came from
                # however, we can treat the version (if present) as relevant metadata?
                # note: this only works for GNU binaries, such as for Linux
                lib = None
                if relocation.symbol.has_version and relocation.symbol.symbol_version.has_auxiliary_version:
                    # like "GLIBC_2.2.5"
                    lib = relocation.symbol.symbol_version.symbol_version_auxiliary.name

                name = relocation.symbol.name
                address = relocation.address

                self._api_map["lief"][address] = (lib, name)

    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return True

    def getApi(self, to_addr, absolute_addr):
        """
        If the LabelProvider has any information about a used API for the given address, return (dll, api), else return (None, None).

        May return None for the `dll` if it cannot be determined.
        When it can be determined for ELF files, the `dll` field should be interpreted as the API version rather than shared library name.
        For example: "GLIBC_2.2.5".
        """
        return self._api_map["lief"].get(to_addr, (None, None))
