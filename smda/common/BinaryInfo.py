import hashlib

import lief

from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider

lief.logging.disable()


class BinaryInfo:
    """simple DTO to contain most information related to the binary/buffer to be analyzed"""

    architecture = ""
    base_addr = 0
    binary = b""
    raw_data = b""
    binary_size = 0
    bitness = None
    code_areas = []
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
    oep = None

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.sha256 = hashlib.sha256(binary).hexdigest()
        self.sha1 = hashlib.sha1(binary).hexdigest()
        self.md5 = hashlib.md5(binary).hexdigest()

    def getOep(self):
        if self.oep is None:
            lief_result = lief.parse(self.raw_data)
            if isinstance(lief_result, lief.PE.Binary):
                self.oep = lief_result.optional_header.addressof_entrypoint
            elif isinstance(lief_result, lief.ELF.Binary):
                self.oep = lief_result.header.entrypoint
        return self.oep

    def getExportedFunctions(self):
        if self.exported_functions is None:
            lief_result = lief.parse(self.raw_data)
            if isinstance(lief_result, lief.PE.Binary):
                self.exported_functions = PeSymbolProvider(None).parseExports(lief_result)
            elif isinstance(lief_result, lief.ELF.Binary):
                self.exported_functions = ElfSymbolProvider(None).parseExports(lief_result)
        return self.exported_functions

    def getImportedFunctions(self):
        if self.imported_functions is None:
            lief_result = lief.parse(self.raw_data)
            if isinstance(lief_result, lief.PE.Binary):
                PeSymbolProvider(None).parseSymbols(lief_result)
                self.imported_functions = PeSymbolProvider(None).parseImports(lief_result)
            elif isinstance(lief_result, lief.ELF.Binary):
                self.imported_functions = ElfSymbolProvider(None).parseSymbols(lief_result.dynamic_symbols)
        return self.imported_functions

    def getSections(self):
        pefile = lief.parse(self.raw_data)
        # TODO 20201030 might want to add ELF sections as well
        if not isinstance(pefile, lief.PE.Binary):
            return
        if pefile and pefile.sections:
            for section in pefile.sections:
                section_start = self.base_addr + section.virtual_address
                section_size = section.virtual_size
                if section_size % 0x1000 != 0:
                    section_size += 0x1000 - (section_size % 0x1000)
                section_end = section_start + section_size
                yield section.name, section_start, section_end

    def isInCodeAreas(self, address):
        is_inside = False
        # if no code areas found, assume the whole image is code and calculate according to base address and size
        if len(self.code_areas) == 0:
            if self.base_addr <= address <= self.base_addr + self.binary_size:
                is_inside = True
        else:
            is_inside = any(a[0] <= address < a[1] for a in self.code_areas)
        return is_inside

    def getHeaderBytes(self):
        if self.raw_data:
            lief_result = lief.parse(self.raw_data)
            if isinstance(lief_result, lief.PE.Binary):
                return self.raw_data[:0x400]
            elif isinstance(lief_result, lief.ELF.Binary):
                return self.raw_data[:0x40]
        return None
