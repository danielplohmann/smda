import logging
import io


LOGGER = logging.getLogger(__name__)

LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
except:
    LOGGER.warning("LIEF not available, will not be able to parse data from ELF files.")


class ElfFileLoader(object):

    @staticmethod
    def isCompatible(data):
        if not LIEF_AVAILABLE:
            return False
        # check for ELF magic
        return data[:4] == b"\x7FELF"

    @staticmethod
    def getBaseAddress(binary):
        elffile = lief.parse(bytearray(binary))
        # Determine base address of binary
        #
        base_addr = 0
        candidates = [0xFFFFFFFFFFFFFFFF]
        for section in elffile.sections:
            if section.virtual_address:
                candidates.append(section.virtual_address - section.offset)
        if len(candidates) > 1:
            base_addr = min(candidates)
        return base_addr

    @staticmethod
    def mapBinary(binary):
        # ELFFile needs a file-like object...
        # Attention: for Python 2.x use the cStringIO package for StringIO
        elffile = lief.parse(bytearray(binary))
        base_addr = ElfFileLoader.getBaseAddress(binary)
        mapped_binary = b""
        LOGGER.debug("Assuming base address 0x%x for inference of reference counts (based on ELF header)", base_addr)

        # find begin of the first and end of the last section
        if elffile.sections:
            max_virt_section_offset = 0
            min_raw_section_offset = 0xFFFFFFFFFFFFFFFF
            for section in elffile.sections:
                # print("{:20s} 0x{:08x} - 0x{:08x} / 0x{:08x}".format(section.name, section.header.sh_addr, section.header.sh_offset, section.header.sh_size))
                if section.virtual_address:
                    max_virt_section_offset = max(max_virt_section_offset, section.size + section.virtual_address)
                    min_raw_section_offset = min(min_raw_section_offset, section.virtual_address)

            # copy binary to mapped_binary
            if max_virt_section_offset:
                mapped_binary = bytearray([0] * (max_virt_section_offset - base_addr))
                mapped_binary[0:min_raw_section_offset] = binary[0:min_raw_section_offset]
            for section in elffile.sections:
                if section.virtual_address:
                    rva = section.virtual_address - base_addr
                    mapped_binary[rva:rva + section.size] = section.content
        elif elffile.segments:
            max_virt_segment_offset = 0
            min_raw_segment_offset = 0xFFFFFFFFFFFFFFFF
            for segment in elffile.segments:
                if segment.virtual_address:
                    max_virt_segment_offset = max(max_virt_segment_offset, segment.physical_size + segment.virtual_address)
                    min_raw_segment_offset = min(min_raw_segment_offset, segment.virtual_address)

            # copy binary to mapped_binary
            if max_virt_segment_offset:
                mapped_binary = bytearray([0] * (max_virt_segment_offset - base_addr))
                mapped_binary[0:min_raw_segment_offset] = binary[0:min_raw_segment_offset]
            for segment in elffile.segments:
                if segment.virtual_address:
                    rva = segment.virtual_address - base_addr
                    mapped_binary[rva:rva + segment.physical_size] = segment.content

        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        # TODO add machine types whenever we add more architectures
        elffile = lief.parse(bytearray(binary))
        machine_type = elffile.header.machine_type
        if machine_type == lief.ELF.ARCH.x86_64:
            return 64
        elif machine_type == lief.ELF.ARCH.i386:
            return 32
        return 0

    @staticmethod
    def mergeCodeAreas(code_areas):
        merged_code_areas = sorted(code_areas)
        result = []
        index = 0
        while index < len(merged_code_areas) - 1:
            this_area = merged_code_areas[index]
            next_area = merged_code_areas[index + 1]
            if this_area[1] != next_area[0]:
                result.append(this_area)
                index += 1
            else:
                merged_code_areas = merged_code_areas[:index] + [[this_area[0], next_area[1]]] + merged_code_areas[index + 2:]
        return merged_code_areas

    @staticmethod
    def getCodeAreas(binary):
        # TODO add machine types whenever we add more architectures
        elffile = lief.parse(bytearray(binary))
        code_areas = []
        for section in elffile.sections:
            # SHF_EXECINSTR = 4
            if section.flags & 0x4:
                section_start = section.virtual_address
                section_size = section.size
                if section_size % section.alignment != 0:
                    section_size += section.alignment - (section_size % section.alignment)
                section_end = section_start + section_size
                code_areas.append([section_start, section_end])              
        return ElfFileLoader.mergeCodeAreas(code_areas)
