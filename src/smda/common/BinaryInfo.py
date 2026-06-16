import logging

import lief

from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider

LOGGER = logging.getLogger(__name__)


class BinaryInfo:
    """simple DTO to contain most information related to the binary/buffer to be analyzed

    xmetadata address conventions (via getExportedFunctions/getImportedFunctions/getSymbols):
    - PE: active ``base_addr`` (dump VA); falls back to LIEF imagebase when unset.
    - ELF: absolute virtual addresses from LIEF (relocation import slots included).
    - Mach-O: LIEF addresses adjusted to the active mapping via slice/base_addr offset.

    ``exported_functions`` holds the export table; ``symbols`` merges exports with
    symtab/COFF/defined function symbols. Overlap between the two dicts is expected
    when an export also appears in the symbol table.
    """

    architecture = ""
    base_addr = 0
    binary = b""
    raw_data = b""
    binary_size = 0
    bitness = None
    code_areas = None
    component = ""
    family = ""
    file_path = ""
    is_library = False
    is_buffer = False
    sha256 = ""
    sha1 = ""
    md5 = ""
    version = ""
    exported_functions = None
    imported_functions = None
    symbols = None
    oep = None

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.code_areas = []
        self._lief_binary = None
        self._lief_type = None
        self._symbol_provider = None
        self.abi = ""

    def _getLiefType(self):
        if self._lief_type is None:
            lief_result = self.getLiefBinary()
            if isinstance(lief_result, lief.PE.Binary):
                self._lief_type = "PE"
                self._symbol_provider = PeSymbolProvider(None)
            elif isinstance(lief_result, lief.ELF.Binary):
                self._lief_type = "ELF"
                self._symbol_provider = ElfSymbolProvider(None)
            elif isinstance(lief_result, (lief.MachO.Binary, lief.MachO.FatBinary)):
                self._lief_type = "MACH_O"
                self._symbol_provider = MachoSymbolProvider(None)
                self._symbol_provider._binary_info = self
            else:
                self._lief_type = "OTHER"
        return self._lief_type

    def getBinaryData(self):
        """Safely retrieves binary data from either raw_data or a file path."""
        data = self.raw_data
        if not data and self.file_path:
            try:
                with open(self.file_path, "rb") as fin:
                    data = fin.read()
            except OSError as e:
                LOGGER.debug("Failed to read binary from path %s: %s", self.file_path, e)
                return None
        return data

    def getLiefBinary(self):
        binary_data = self.getBinaryData()
        if self._lief_binary is None and binary_data:
            self._lief_binary = lief.parse(binary_data)
        return self._lief_binary

    def getOep(self):
        if self.oep is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            if lief_type == "PE":
                self.oep = lief_result.optional_header.addressof_entrypoint
            elif lief_type == "ELF":
                self.oep = lief_result.header.entrypoint - (self.base_addr or 0)
            elif lief_type == "MACH_O":
                macho_binary = self._symbol_provider._get_macho_binary(lief_result)
                if macho_binary and hasattr(macho_binary, "entrypoint"):
                    adjustment = self._symbol_provider._get_address_adjustment(macho_binary)
                    self.oep = (macho_binary.entrypoint + adjustment) - self.base_addr
        return self.oep

    def getExportedFunctions(self):
        if self.exported_functions is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            if lief_type == "PE":
                self.exported_functions = self._symbol_provider.parseExports(lief_result, self.base_addr)
            elif lief_type in ("ELF", "MACH_O"):
                self.exported_functions = self._symbol_provider.parseExports(lief_result)
        return self.exported_functions

    def getImportedFunctions(self):
        if self.imported_functions is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            if lief_type == "PE":
                self.imported_functions = self._symbol_provider.parseImports(lief_result, self.base_addr)
            elif lief_type in ("ELF", "MACH_O"):
                self.imported_functions = self._symbol_provider.parseImports(lief_result)
        return self.imported_functions

    def getSymbols(self):
        if self.symbols is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            if lief_type == "PE":
                self.symbols = self._symbol_provider.collectSymbols(lief_result, self.base_addr)
            elif lief_type == "ELF":
                self.symbols = self._symbol_provider.collectSymbols(lief_result)
            elif lief_type == "MACH_O":
                symbols = self._symbol_provider.collectSymbols(lief_result)
                self.symbols = self._symbol_provider._filter_symbols_to_code(symbols, self)
        return self.symbols

    def getSections(self):
        """
        Generator that yields (name, start_addr, end_addr) for each section.
        Supports PE, ELF, and Mach-O binaries.

        Section start addresses use the same VA convention as label metadata:
        PE uses ``base_addr + section.virtual_address``; ELF uses LIEF absolute
        ``section.virtual_address``; Mach-O applies the Mach-O base/adjustment offset.
        """
        parsed_binary = self.getLiefBinary()
        if not parsed_binary:
            return

        lief_type = self._getLiefType()
        if lief_type == "MACH_O":
            parsed_binary = self._symbol_provider._get_macho_binary(parsed_binary)

        if (
            not parsed_binary
            or lief_type not in ("PE", "ELF", "MACH_O")
            or not hasattr(parsed_binary, "sections")
            or not parsed_binary.sections
        ):
            return

        if lief_type == "PE":
            for section in parsed_binary.sections:
                section_start = self.base_addr + section.virtual_address
                section_size = section.virtual_size
                if section_size % 0x1000 != 0:
                    section_size += 0x1000 - (section_size % 0x1000)
                yield section.name, section_start, section_start + section_size
        elif lief_type == "ELF":
            for section in parsed_binary.sections:
                section_start = section.virtual_address
                section_size = section.size
                yield section.name, section_start, section_start + section_size
        elif lief_type == "MACH_O":
            adjustment = self._symbol_provider._get_address_adjustment(parsed_binary)
            for section in parsed_binary.sections:
                section_start = section.virtual_address + adjustment
                section_size = section.size
                yield section.name, section_start, section_start + section_size

    def isInCodeAreas(self, address):
        is_inside = False
        # if no code areas found, assume the whole image is code and calculate according to base address and size
        if self.code_areas is None or len(self.code_areas) == 0:
            if self.base_addr <= address <= self.base_addr + self.binary_size:
                is_inside = True
        else:
            is_inside = any(a[0] <= address < a[1] for a in self.code_areas)
        return is_inside

    def getHeaderBytes(self):
        if self.raw_data:
            lief_type = self._getLiefType()
            if lief_type == "PE":
                return self.raw_data[:0x400]
            elif lief_type == "ELF":
                return self.raw_data[:0x40]
            elif self.architecture == "dalvik" or self.raw_data[:4] == b"dex\n":
                return self.raw_data[:0x70]
        return None
