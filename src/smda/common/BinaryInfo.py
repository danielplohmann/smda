import contextlib
import hashlib
import logging

import lief

from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.utility.lief_helper import lief_name, safe_lief_parse
from smda.utility.MachoFileLoader import MachoFileLoader

LOGGER = logging.getLogger(__name__)


# lief spells the ELF header's type as an enum member; read it the way the symbol providers
# read theirs, so a lief that names it differently leaves every ELF looking relocated rather
# than raising in the middle of an analysis
_ELF_TYPE_EXEC = getattr(getattr(lief.ELF.Header, "FILE_TYPE", None), "EXEC", None)


class BinaryInfo:
    """simple DTO to contain most information related to the binary/buffer to be analyzed

    Two label views (do not conflate them):

    1. **xmetadata** (``SmdaReport.xmetadata``) — static format tables only:
       ``exported_functions``, ``exported_symbols``, ``imported_functions``, and ``symbols`` from the
       PE/ELF/Mach-O providers. Addresses follow the conventions below. This is
       the dump of import/export/symbol tables, not the final CFG labels.

    2. **function_name** (``SmdaFunction.function_name``) — resolved names after
       disassembly merges all active label providers (format symbols, API
       resolvers, Go pclntab, Rust demangling, PDB, Delphi, …). A function may
       have a non-empty ``function_name`` that does not appear in xmetadata
       (e.g. Go/Rust), and xmetadata may list symbols that never became FEPs.

    xmetadata address conventions (via getExportedFunctions/getExportedSymbols/getImportedFunctions/getSymbols):
    - PE: active ``base_addr`` (dump VA); falls back to LIEF imagebase when unset.
    - ELF: absolute virtual addresses from LIEF (relocation import slots included).
    - Mach-O: LIEF addresses adjusted to the active mapping via slice/base_addr offset.

    ``exported_functions`` holds function exports for candidate recovery.
    ``exported_symbols`` holds every defined dynamic export, including data symbols.
    ``symbols`` merges exports with symtab/COFF/defined function symbols. Overlap
    between the dictionaries is expected when an export also appears in a symbol table.
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
    has_backend = False
    format_recognized = False
    sha256 = ""
    sha1 = ""
    md5 = ""
    version = ""
    exported_functions = None
    exported_symbols = None
    imported_functions = None
    symbols = None
    oep = None

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.code_areas = []
        self.has_backend = False
        self._lief_binary = None
        self._lief_type = None
        self._position_independent_elf = None
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

    def isPositionIndependentElf(self):
        """Whether this is an ELF the loader places at a base of its own choosing.

        Every absolute address such an image stores has to be relocated when it is loaded, and
        no compiler emits a switch table that way: it emits offsets from a base the code
        computes for itself, precisely so the table needs no relocation. An absolute table of
        code addresses in a shared object is therefore something else - the function pointers a
        tail call dispatches through, whose targets are separate functions.

        An ELF whose header type cannot be read answers True as well. The caller uses this to
        refuse to read a table, and refusing one costs a switch its case bodies where admitting
        one merges whole functions together.
        """
        if self._position_independent_elf is None:
            self._position_independent_elf = False
            if self._getLiefType() == "ELF":
                header = getattr(self.getLiefBinary(), "header", None)
                file_type = getattr(header, "file_type", None)
                self._position_independent_elf = file_type is None or file_type != _ELF_TYPE_EXEC
        return self._position_independent_elf

    def getBinaryData(self):
        """Safely retrieves binary data from either raw_data or a file path."""
        data = self.raw_data
        if not data and self.file_path:
            try:
                with open(self.file_path, "rb") as fin:
                    data = fin.read()
            except OSError as e:
                LOGGER.warning("Failed to read binary from path %s: %s", self.file_path, e)
                return None
        return data

    def getLiefBinary(self):
        binary_data = self.getBinaryData()
        if self._lief_binary is None and binary_data:
            if MachoFileLoader.isCompatible(binary_data):
                self._lief_binary = MachoFileLoader.parseBinary(binary_data)
            else:
                self._lief_binary = safe_lief_parse(binary_data)
        return self._lief_binary

    def getOep(self):
        if self.oep is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            if lief_type == "PE":
                self.oep = lief_result.optional_header.addressof_entrypoint
            elif lief_type == "ELF":
                entrypoint = lief_result.header.entrypoint
                if self.base_addr and entrypoint >= self.base_addr:
                    entrypoint -= self.base_addr
                self.oep = entrypoint
            elif lief_type == "MACH_O":
                symbol_provider = self._symbol_provider
                if symbol_provider is None:
                    return self.oep
                macho_binary = symbol_provider._get_macho_binary(lief_result)
                if macho_binary and hasattr(macho_binary, "entrypoint"):
                    adjustment = symbol_provider._get_address_adjustment(macho_binary)
                    self.oep = (macho_binary.entrypoint + adjustment) - self.base_addr
        return self.oep

    def getExportedFunctions(self):
        if self.exported_functions is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            symbol_provider = self._symbol_provider
            if symbol_provider is None:
                return self.exported_functions
            if lief_type == "PE" and isinstance(symbol_provider, PeSymbolProvider):
                self.exported_functions = symbol_provider.parseExports(lief_result, self.base_addr)
            elif lief_type in ("ELF", "MACH_O"):
                self.exported_functions = symbol_provider.parseExports(lief_result)
        return self.exported_functions

    def getExportedSymbols(self):
        if self.exported_symbols is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            symbol_provider = self._symbol_provider
            if lief_type == "ELF" and isinstance(symbol_provider, ElfSymbolProvider):
                self.exported_symbols = symbol_provider.parseExportedSymbols(lief_result)
            else:
                # PE and Mach-O providers currently expose function exports only;
                # retain that established contract while ELF additionally records
                # its dynamic data exports.
                self.exported_symbols = dict(self.getExportedFunctions() or {})
        return self.exported_symbols

    def getImportedFunctions(self):
        if self.imported_functions is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            symbol_provider = self._symbol_provider
            if symbol_provider is None:
                return self.imported_functions
            if lief_type == "PE" and isinstance(symbol_provider, PeSymbolProvider):
                self.imported_functions = symbol_provider.parseImports(lief_result, self.base_addr)
            elif lief_type in ("ELF", "MACH_O"):
                self.imported_functions = symbol_provider.parseImports(lief_result)
        return self.imported_functions

    def getSymbols(self):
        if self.symbols is None:
            lief_result = self.getLiefBinary()
            lief_type = self._getLiefType()
            symbol_provider = self._symbol_provider
            if lief_type == "PE" and isinstance(symbol_provider, PeSymbolProvider):
                self.symbols = symbol_provider.collectSymbols(lief_result, self.base_addr)
            elif lief_type == "ELF" and isinstance(symbol_provider, ElfSymbolProvider):
                self.symbols = symbol_provider.collectSymbols(lief_result)
            elif lief_type == "MACH_O" and isinstance(symbol_provider, MachoSymbolProvider):
                symbols = symbol_provider.collectSymbols(lief_result)
                self.symbols = symbol_provider._filter_symbols_to_code(symbols, self)
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
        symbol_provider = self._symbol_provider
        if symbol_provider is None:
            return
        if lief_type == "MACH_O":
            parsed_binary = symbol_provider._get_macho_binary(parsed_binary)

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
                section_size = section.virtual_size or section.sizeof_raw_data
                if section_size % 0x1000 != 0:
                    section_size += 0x1000 - (section_size % 0x1000)
                yield lief_name(section), section_start, section_start + section_size
        elif lief_type == "ELF":
            for section in parsed_binary.sections:
                section_start = section.virtual_address
                section_size = section.size
                yield lief_name(section), section_start, section_start + section_size
        elif lief_type == "MACH_O":
            adjustment = symbol_provider._get_address_adjustment(parsed_binary)
            for section in parsed_binary.sections:
                section_start = section.virtual_address + adjustment
                section_size = section.size
                yield lief_name(section), section_start, section_start + section_size

    def isInCodeAreas(self, address):
        is_inside = False
        # if no code areas found, assume the whole image is code and calculate according to base address and size
        if self.code_areas is None or len(self.code_areas) == 0:
            if self.base_addr <= address < self.base_addr + self.binary_size:
                is_inside = True
        else:
            is_inside = any(a[0] <= address < a[1] for a in self.code_areas)
        return is_inside

    HEADER_CAP_PE = 0x1000
    HEADER_CAP_ELF = 0x400
    HEADER_CAP_MACHO = 0x2000
    HEADER_SIZE_DEX = 0x70

    @staticmethod
    def _trimTrailingZeros(data):
        end = len(data)
        while end > 0 and data[end - 1] == 0:
            end -= 1
        return data[:end]

    def _getPeHeaderRegion(self, data, lief_result):
        try:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            size_opt = int.from_bytes(data[e_lfanew + 20 : e_lfanew + 22], "little")
            num_sections = int.from_bytes(data[e_lfanew + 6 : e_lfanew + 8], "little")
            section_table = e_lfanew + 24 + size_opt
            section_table_end = section_table + num_sections * 0x28
        except Exception:
            return self.HEADER_CAP_PE
        sizeof_headers = 0
        with contextlib.suppress(Exception):
            sizeof_headers = lief_result.optional_header.sizeof_headers
        first_raw = None
        for index in range(min(num_sections, 4096)):
            entry = section_table + index * 0x28 + 20
            if entry + 4 > len(data):
                break
            praw = int.from_bytes(data[entry : entry + 4], "little")
            if praw > 0 and (first_raw is None or praw < first_raw):
                first_raw = praw
        if first_raw is None:
            first_raw = sizeof_headers or section_table_end
        header_cap = min(sizeof_headers, first_raw) if sizeof_headers else first_raw
        return max(section_table_end, header_cap)

    def _getElfHeaderRegion(self, data):
        try:
            is_64 = data[4] == 2
            endian = "little" if data[5] == 1 else "big"
            if is_64:
                e_phoff = int.from_bytes(data[0x20:0x28], endian)
                e_ehsize = int.from_bytes(data[0x34:0x36], endian)
                e_phentsize = int.from_bytes(data[0x36:0x38], endian)
                e_phnum = int.from_bytes(data[0x38:0x3A], endian)
            else:
                e_phoff = int.from_bytes(data[0x1C:0x20], endian)
                e_ehsize = int.from_bytes(data[0x28:0x2A], endian)
                e_phentsize = int.from_bytes(data[0x2A:0x2C], endian)
                e_phnum = int.from_bytes(data[0x2C:0x2E], endian)
        except Exception:
            return self.HEADER_CAP_ELF
        phdr_end = e_phoff + e_phnum * e_phentsize if e_phoff else e_ehsize
        return max(e_ehsize, phdr_end)

    def _getMachoHeaderRegion(self, data, lief_result):
        from smda.utility.MachoBinary import get_active_macho_binary

        active = get_active_macho_binary(
            lief_result,
            bitness=self.bitness or None,
            architecture=self.architecture or "",
        )
        if active is None:
            return 0, self.HEADER_CAP_MACHO
        slice_offset = 0
        try:
            slice_offset = active.fat_offset
        except Exception:
            slice_offset = 0
        try:
            is_64 = active.header.is_64bit
            header_size = 32 if is_64 else 28
            sizeof_cmds = active.header.sizeof_cmds
        except Exception:
            return slice_offset, self.HEADER_CAP_MACHO
        return slice_offset, header_size + sizeof_cmds

    def getPeHeaderHash(self):
        """sha256 over the PE header region with volatile/hash-busting fields
        (TimeDateStamp, CheckSum, SizeOfImage) zeroed, so builds differing only
        in those fields collide. Returns None for non-PE inputs."""
        if not self.raw_data:
            return None
        if self._getLiefType() != "PE":
            return None
        region = self._getPeHeaderRegion(self.raw_data, self.getLiefBinary())
        region = min(region, self.HEADER_CAP_PE, len(self.raw_data))
        header = bytearray(self.raw_data[:region])
        try:
            e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
            coff = e_lfanew + 4
            opt = coff + 20
            for offset in (coff + 8, opt + 56, opt + 64):
                if offset + 4 <= len(header):
                    header[offset : offset + 4] = b"\x00\x00\x00\x00"
        except Exception:
            return None
        return hashlib.sha256(bytes(header)).hexdigest()

    def getHeaderBytes(self):
        if not self.raw_data:
            return None
        data = self.raw_data
        lief_type = self._getLiefType()
        if lief_type == "PE":
            region = self._getPeHeaderRegion(data, self.getLiefBinary())
            region = min(region, self.HEADER_CAP_PE, len(data))
            return self._trimTrailingZeros(data[:region])
        elif lief_type == "ELF":
            region = self._getElfHeaderRegion(data)
            region = min(region, self.HEADER_CAP_ELF, len(data))
            return self._trimTrailingZeros(data[:region])
        elif lief_type == "MACH_O":
            slice_offset, region = self._getMachoHeaderRegion(data, self.getLiefBinary())
            region = min(region, self.HEADER_CAP_MACHO)
            end = min(slice_offset + region, len(data))
            return self._trimTrailingZeros(data[slice_offset:end])
        elif self.architecture == "dalvik" or data[:4] == b"dex\n":
            return data[: self.HEADER_SIZE_DEX]
        return None
