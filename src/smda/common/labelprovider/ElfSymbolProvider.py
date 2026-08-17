#!/usr/bin/python

import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider
from .import_parsers import parse_elf_relocation_imports
from .ItaniumDemangler import demangle_itanium_symbol

lief.logging.disable()
LOGGER = logging.getLogger(__name__)

# Backward-compatible alias for tests and callers that imported the old helper name.
parse_relocation_imports = parse_elf_relocation_imports

# Section indexes at or above SHN_LORESERVE do not denote a real section: SHN_ABS holds
# absolute values and SHN_COMMON holds tentative definitions that the linker has not
# placed yet. Neither is a defined function or a laid-out data export.
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
_TLS_SYMBOL_TYPE = getattr(lief.ELF.Symbol.TYPE, "TLS", None)


def is_defined_elf_symbol(symbol):
    """Return whether an ELF symbol is defined rather than a PLT-backed import.

    LIEF can report a nonzero PLT address for an undefined dynamic symbol, so the
    section index is the only reliable discriminator.
    """
    shndx = getattr(symbol, "shndx", None)
    if shndx is not None:
        return SHN_UNDEF < shndx < SHN_LORESERVE
    # Keep compatibility with older LIEF objects and the lightweight test
    # doubles that do not expose shndx.
    return bool(getattr(symbol, "value", 0)) and not getattr(symbol, "imported", False)


class ElfSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for ELF symbols"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return (None, None)

    def _parseOep(self, lief_result):
        # Symbol map keys use absolute VAs; BinaryInfo.getOep() stores a base-relative offset.
        if lief_result:
            self._func_symbols[lief_result.header.entrypoint] = "original_entry_point"

    def update(self, binary_info):
        self._func_symbols = {}

        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.ELF.Binary):
            return

        self._parseOep(lief_binary)
        # Keep only local/defined function symbols here: exported functions plus defined
        # static and dynamic symtab entries (parseSymbols drops undefined imports via value != 0).
        # Imported, relocation-backed API names are intentionally NOT merged in - they are
        # resolved as APIs by ElfApiResolver, so this stays a pure symbol provider
        # (isApiProvider() == False) and relocation slot addresses are not mistaken for symbols.
        self._func_symbols.update(self.parseExports(lief_binary))
        self._func_symbols.update(self.parseSymbols(lief_binary.symtab_symbols))
        self._func_symbols.update(self.parseSymbols(lief_binary.dynamic_symbols))

    def parseExports(self, binary):
        function_symbols = {}
        for function in binary.exported_functions:
            function_name = self._formatSymbolName(function)
            if function_name:
                function_symbols[function.address] = function_name
        return function_symbols

    _isDefinedSymbol = staticmethod(is_defined_elf_symbol)

    @staticmethod
    def _getSymbolName(symbol):
        try:
            raw_name = symbol.name
        except (AttributeError, UnicodeDecodeError):
            return ""
        return raw_name if isinstance(raw_name, str) else ""

    @classmethod
    def _formatSymbolName(cls, symbol):
        raw_name = cls._getSymbolName(symbol)
        if not raw_name:
            return ""
        try:
            demangled_name = getattr(symbol, "demangled_name", None)
        except (AttributeError, UnicodeDecodeError):
            demangled_name = None
        if demangled_name and demangled_name != raw_name:
            return demangled_name
        return demangle_itanium_symbol(raw_name)

    @staticmethod
    def _isThreadLocalSymbol(symbol):
        """Return whether the symbol's value is a TLS-block offset instead of an address."""
        symbol_type = getattr(symbol, "type", None)
        if _TLS_SYMBOL_TYPE is None or symbol_type is None:
            return False
        try:
            return symbol_type == _TLS_SYMBOL_TYPE
        except TypeError:
            # LIEF's enum comparison rejects foreign types outright.
            return False

    def parseExportedSymbols(self, binary):
        """Return every named, defined dynamic ELF symbol, including data exports.

        Keys are virtual addresses, so thread-local symbols are excluded: their value
        is an offset inside the TLS block, not an address in the mapped image. Aliases
        that share one address (for example the C1/C2 constructor pair) keep the first
        name the dynamic symbol table spells, so repeated runs agree.
        """
        if not isinstance(binary, lief.ELF.Binary):
            return {}
        exported_symbols = {}
        for symbol in binary.dynamic_symbols:
            if symbol is None or not self._isDefinedSymbol(symbol) or self._isThreadLocalSymbol(symbol):
                continue
            symbol_name = self._formatSymbolName(symbol)
            if symbol_name:
                exported_symbols.setdefault(symbol.value, symbol_name)
        return exported_symbols

    def parseSymbols(self, symbols):
        function_symbols = {}
        for symbol in symbols:
            if symbol is not None and symbol.is_function and symbol.value != 0 and self._isDefinedSymbol(symbol):
                symbol_name = self._formatSymbolName(symbol)
                if symbol_name:
                    function_symbols[symbol.value] = symbol_name
        return function_symbols

    def parseImports(self, lief_binary):
        """Return relocation-backed imports as the binary spells them.

        This is not a label view. It reaches xmetadata["imported_functions"], which
        BinarySynthesizer writes back as the literal names of a reconstructed import table,
        and which SmdaReport._mergeImportedFunctions fills from the undecorated API-resolver
        view as well - so a demangled spelling here is both an unusable import name and a
        second spelling of names already in the same dict.
        """
        return parse_elf_relocation_imports(lief_binary)

    def collectSymbols(self, lief_binary):
        if not isinstance(lief_binary, lief.ELF.Binary):
            return {}
        # Keep this legacy map function-only. Data exports are available from
        # BinaryInfo.getExportedSymbols() and SmdaReport.xmetadata["exported_symbols"].
        symbols = {}
        symbols.update(self.parseExports(lief_binary))
        symbols.update(self.parseSymbols(lief_binary.symtab_symbols))
        symbols.update(self.parseSymbols(lief_binary.dynamic_symbols))
        return symbols

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
