import hashlib

import lief
lief.logging.disable()


class BinaryInfo(object):
    """ simple DTO to contain most information related to the binary/buffer to be analyzed """

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
    version = ""
    exported_functions = None
    oep = None

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.sha256 = hashlib.sha256(binary).hexdigest()

    def getOep(self):
        if self.oep is None:
            lief_result = lief.parse(bytearray(self.raw_data))
            if isinstance(lief_result, lief.PE.Binary):
                self.oep = lief_result.optional_header.addressof_entrypoint
            elif isinstance(lief_result, lief.ELF.Binary):
                self.oep = lief_result.header.entrypoint
        return self.oep

    def getExportedFunctions(self):
        if self.exported_functions is None:
            lief_result = lief.parse(bytearray(self.raw_data))
            if isinstance(lief_result, lief.PE.Binary) or isinstance(lief_result, lief.ELF.Binary):
                self.exported_functions = {}
                for function in lief_result.exported_functions:
                    self.exported_functions[function.address] = function.name
        return self.exported_functions

    def getSections(self):
        pefile = lief.parse(bytearray(self.raw_data))
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
