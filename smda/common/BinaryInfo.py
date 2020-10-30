import hashlib

import lief


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

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.sha256 = hashlib.sha256(binary).hexdigest()

    def getSections(self):
        pefile = lief.parse(bytearray(self.binary))
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
