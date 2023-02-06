import logging

LOGGER = logging.getLogger(__name__)

LIEF_AVAILABLE = False
try:
    import lief
    lief.logging.disable()
    LIEF_AVAILABLE = True
except:
    LOGGER.warning("LIEF not available, will not be able to parse data from ELF files.")


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


class ElfFileLoader(object):

    @staticmethod
    def isCompatible(data):
        if not LIEF_AVAILABLE:
            return False
        # check for ELF magic
        return data[:4] == b"\x7FELF"

    @staticmethod
    def getBaseAddress(binary):
        elffile = lief.parse(binary)
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
        """
        map the ELF file sections and segments into a contiguous bytearray
        as if into virtual memory with the given base address.
        """
        # ELFFile needs a file-like object...
        # Attention: for Python 2.x use the cStringIO package for StringIO
        elffile = lief.parse(binary)
        base_addr = ElfFileLoader.getBaseAddress(binary)

        LOGGER.debug("ELF: base address: 0x%x", base_addr)

        # a segment may contain 0 or more sections.
        # ref: https://stackoverflow.com/a/14382477/87207
        #
        # i'm not sure if a section may be found outside of a segment.
        # therefore, lets load segments first, and then load sections over them.
        # we expect the section data to overwrite the segment data; however,
        # it should be exactly the same data.

        # find min and max virtual addresses.
        max_virtual_address = 0
        min_virtual_address = 0xFFFFFFFFFFFFFFFF
        min_raw_offset = 0xFFFFFFFFFFFFFFFF

        # find begin of the first section/segment and end of the last section/segment.
        for section in sorted(elffile.sections, key=lambda section: section.size, reverse=True):
            if not section.virtual_address:
                continue

            max_virtual_address = max(max_virtual_address, section.size + section.virtual_address)
            min_virtual_address = min(min_virtual_address, section.virtual_address)
            min_raw_offset = min(min_raw_offset, section.file_offset)

        for segment in elffile.segments:
            if not segment.virtual_address:
                continue
            max_virtual_address = max(max_virtual_address, segment.virtual_size + segment.virtual_address)
            min_virtual_address = min(min_virtual_address, segment.virtual_address)
            min_raw_offset = min(min_raw_offset, segment.file_offset)

        if not max_virtual_address:
            LOGGER.debug("ELF: no section or segment data")
            return bytes()

        # create mapped region.
        # offset 0x0 corresponds to the ELF base address
        virtual_size = max_virtual_address - base_addr
        LOGGER.debug("ELF: max virtual section offset: 0x%x", max_virtual_address)
        LOGGER.debug("ELF: mapped size: 0x%x", virtual_size)
        LOGGER.debug("ELF: min raw offset: 0x%x", min_raw_offset)
        mapped_binary = bytearray(align(virtual_size, 0x1000))

        # map segments.
        # segments may contains 0 or more sections,
        # so we do segments first.
        #
        # load sections from largest to smallest,
        # because some segments may overlap.
        #
        # technically, we should only have to load PT_LOAD segments,
        # but we do all of them here.
        for segment in sorted(elffile.segments, key=lambda segment: segment.physical_size, reverse=True):
            if not segment.virtual_address:
                continue
            rva = segment.virtual_address - base_addr
            LOGGER.debug("ELF: mapping segment of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)", segment.physical_size, rva, rva + segment.physical_size, segment.virtual_address)
            assert len(segment.content) == segment.physical_size
            mapped_binary[rva:rva + segment.physical_size] = segment.content

        # map sections.
        # may overwrite some segment data, but we expect the content to be identical.
        for section in sorted(elffile.sections, key=lambda section: section.size, reverse=True):
            if not section.virtual_address:
                continue
            rva = section.virtual_address - base_addr
            LOGGER.debug("ELF: mapping section of 0x%04x bytes (content: 0x%04x bytes) at 0x%08x-0x%08x (0x%08x)", section.size, len(section.content), rva, rva + section.size, section.virtual_address)
            # potentially perform zero padding if we have less content than section size
            content_to_be_mapped = bytearray(section.content)
            if len(section.content) < section.size:
                content_to_be_mapped += b"\x00" * (section.size - len(section.content))
            mapped_binary[rva:rva + section.size] = content_to_be_mapped

        # map header.
        # we consider the headers to be any data found before the first section/segment
        if min_raw_offset != 0:
            LOGGER.debug("ELF: mapping 0x%x bytes of header at 0x0 (0x%x)", min_raw_offset, base_addr)
            mapped_binary[0:min_raw_offset] = binary[0:min_raw_offset]

        LOGGER.debug("ELF: final mapped size: 0x%x", len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        # TODO add machine types whenever we add more architectures
        elffile = lief.parse(binary)
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
        elffile = lief.parse(binary)
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
