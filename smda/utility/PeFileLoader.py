import struct
import logging

import lief
lief.logging.disable()

LOG = logging.getLogger(__name__)



class PeFileLoader(object):

    BITNESS_MAP = {0x14c: 32, 0x8664: 64}

    @staticmethod
    def isCompatible(data):
        return data[:2] == b"MZ"

    @staticmethod
    def mapBinary(binary):
        # This is a pretty rough implementation but does the job for now
        mapped_binary = bytearray([])
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset:
            num_sections = 0
            bitness = 0
            section_infos = []
            optional_header_size = 0xF8
            if pe_offset and len(binary) >= pe_offset + 0x8:
                num_sections = struct.unpack("H", binary[pe_offset + 0x6:pe_offset + 0x8])[0]
                bitness = PeFileLoader.getBitness(binary)
                if bitness == 64:
                    optional_header_size = 0x108
            if pe_offset and num_sections and len(binary) >= pe_offset + optional_header_size + num_sections * 0x28:
                for section_index in range(num_sections):
                    section_offset = section_index * 0x28
                    slice_start = pe_offset + optional_header_size + section_offset + 0x8
                    slice_end = pe_offset + optional_header_size + section_offset + 0x8 + 0x10
                    virt_size, virt_offset, raw_size, raw_offset = struct.unpack("IIII", binary[slice_start:slice_end])
                    section_info = {
                        "section_index": section_index,
                        "virt_size": virt_size,
                        "virt_offset": virt_offset,
                        "raw_size": raw_size,
                        "raw_offset": raw_offset,
                    }
                    section_infos.append(section_info)
            max_virt_section_offset = 0
            min_raw_section_offset = 0xFFFFFFFF
            if section_infos:
                for section_info in section_infos:
                    max_virt_section_offset = max(max_virt_section_offset, section_info["virt_size"] + section_info["virt_offset"])
                    max_virt_section_offset = max(max_virt_section_offset, section_info["raw_size"] + section_info["virt_offset"])
                    if section_info["raw_offset"] > 0x200:
                        min_raw_section_offset = min(min_raw_section_offset, section_info["raw_offset"])
            # support up to 100MB for now.
            if max_virt_section_offset and max_virt_section_offset < 100 * 1024 * 1024:
                mapped_binary = bytearray([0] * max_virt_section_offset)
                mapped_binary[0:min_raw_section_offset] = binary[0:min_raw_section_offset]
            for section_info in section_infos:
                mapped_from = section_info["virt_offset"]
                mapped_to = section_info["virt_offset"] + section_info["raw_size"]
                mapped_binary[mapped_from:mapped_to] = binary[section_info["raw_offset"]:section_info["raw_offset"] + section_info["raw_size"]]
                LOG.debug("Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)",
                          section_info["section_index"],
                          section_info["raw_offset"],
                          section_info["raw_size"],
                          section_info["virt_offset"],
                          section_info["virt_size"])
            LOG.debug("Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes", len(binary), num_sections, len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        bitness_id = 0
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset:
            if pe_offset and len(binary) >= pe_offset + 0x6:
                bitness_id = struct.unpack("H", binary[pe_offset + 0x4:pe_offset + 0x6])[0]
        return PeFileLoader.BITNESS_MAP.get(bitness_id, 0)

    @staticmethod
    def getBaseAddress(binary):
        base_addr = 0
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x38:
            if PeFileLoader.getBitness(binary) == 32:
                base_addr = struct.unpack("I", binary[pe_offset + 0x34:pe_offset + 0x38])[0]
            elif PeFileLoader.getBitness(binary) == 64:
                base_addr = struct.unpack("Q", binary[pe_offset + 0x30:pe_offset + 0x38])[0]
        if base_addr:
            LOG.debug("Changing base address from 0 to: 0x%x for inference of reference counts (based on PE header)", base_addr)
        return base_addr

    @staticmethod
    def getPeOffset(binary):
        if len(binary) >= 0x40:
            pe_offset = struct.unpack("H", binary[0x3c:0x3c + 2])[0]
            return pe_offset
        return 0

    @staticmethod
    def getOEP(binary):
        oep_rva = 0
        if PeFileLoader.checkPe(binary):
            pe_offset = PeFileLoader.getPeOffset(binary)
            if pe_offset and len(binary) >= pe_offset + 0x2c:
                oep_rva = struct.unpack("I", binary[pe_offset + 0x28:pe_offset + 0x2C])[0]
        return oep_rva

    @staticmethod
    def checkPe(binary):
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 6:
            bitness = struct.unpack("H", binary[pe_offset + 4:pe_offset + 4 + 2])[0]
            return bitness in PeFileLoader.BITNESS_MAP
        return False

    @staticmethod
    def getCodeAreas(binary):
        pefile = lief.parse(binary)
        code_areas = []
        base_address = PeFileLoader.getBaseAddress(binary)
        if pefile and pefile.sections:
            for section in pefile.sections:
                # MEM_EXECUTE
                if section.characteristics & 0x20000000:
                    section_start = base_address + section.virtual_address
                    section_size = section.virtual_size
                    if section_size % 0x1000 != 0:
                        section_size += 0x1000 - (section_size % 0x1000)
                    section_end = section_start + section_size
                    code_areas.append([section_start, section_end])
        return PeFileLoader.mergeCodeAreas(code_areas)

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
