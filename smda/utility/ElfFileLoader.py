import logging
import io

from elftools.elf.elffile import ELFFile

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class ElfFileLoader(object):

    @staticmethod
    def isCompatible(data):
        # check for ELF magic
        return data[:4] == b"\x7FELF"

    @staticmethod
    def mapData(binary):
        # ELFFile needs a file-like object...
        # Attention: for Python 2.x use the cStringIO package for StringIO
        filepointer = io.BytesIO(binary)
        mapped_binary = bytearray([])
        elffile = ELFFile(filepointer)

        # Determine base address of binary
        #
        base_addr = 0
        candidates = [0xFFFFFFFFFFFFFFFF]
        for section in elffile.iter_sections():
            if section.header.sh_addr:
                candidates.append(section.header.sh_addr - section.header.sh_offset)
                break
        if len(candidates) > 1:
            base_addr = min(candidates)

        # find begin of the first and end of the last section
        max_virt_section_offset = 0
        min_raw_section_offset = 0xFFFFFFFF
        for section in elffile.iter_sections():
            # print("{:20s} 0x{:08x} - 0x{:08x} / 0x{:08x}".format(section.name, section.header.sh_addr, section.header.sh_offset, section.header.sh_size))
            if section.header.sh_addr:
                max_virt_section_offset = max(max_virt_section_offset, section.header.sh_size + section.header.sh_addr)
                min_raw_section_offset = min(min_raw_section_offset, section.header.sh_addr)

        # copy binary to mapped_binary
        if max_virt_section_offset:
            mapped_binary = bytearray([0] * (max_virt_section_offset - base_addr))
            mapped_binary[0:min_raw_section_offset] = binary[0:min_raw_section_offset]
        for section in elffile.iter_sections():
            if section.header.sh_addr:
                rva = section.header.sh_addr - base_addr
                mapped_binary[rva:rva + section.header.sh_size] = section.data()

        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        return ELFFile(io.BytesIO(binary)).elfclass
