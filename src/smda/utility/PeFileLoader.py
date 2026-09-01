import logging
import struct

import lief

from smda.SmdaConfig import SmdaConfig
from smda.utility.common import mergeCodeAreas
from smda.utility.lief_helper import safe_lief_parse

LOGGER = logging.getLogger(__name__)

# Sentinel: distinguishes "caller did not supply parsed" (legacy direct
# call, do your own lief.parse) from "caller already tried to parse and got
# None" (e.g. FileLoader saw lief.parse fail; do NOT retry).
_NOT_PROVIDED = object()


class PeFileLoader:
    BITNESS_MAP = {0x14C: 32, 0x8664: 64, 0xAA64: 64}
    ARCHITECTURE_MAP = {0x14C: "intel", 0x8664: "intel", 0xAA64: "aarch64"}

    #: IMAGE_COR20_HEADER.ManagedNativeHeader, 64 bytes into the CLR header. A pure-IL
    #: assembly leaves it zero; a ReadyToRun assembly points it at a header whose first
    #: four bytes are this signature, and ships precompiled native code beside its CIL.
    CLR_MANAGED_NATIVE_HEADER_OFFSET = 0x40
    READY_TO_RUN_SIGNATURE = b"RTR\x00"

    @staticmethod
    def isCompatible(data):
        return data[:2] == b"MZ"

    @staticmethod
    def parseBinary(binary):
        # Single lief.parse entry point so FileLoader can share one parse
        # across all accessors instead of each accessor re-parsing.
        return safe_lief_parse(binary)

    @staticmethod
    def mapBinary(binary, parsed=_NOT_PROVIDED):
        # This is a pretty rough implementation but does the job for now
        mapped_binary = bytearray([])
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset:
            num_sections = 0
            bitness = 0
            section_infos = []
            optional_header_size = 0xF8
            if pe_offset and len(binary) >= pe_offset + 0x8:
                num_sections = struct.unpack("<H", binary[pe_offset + 0x6 : pe_offset + 0x8])[0]
                bitness = PeFileLoader.getBitness(binary)
                if bitness == 64:
                    optional_header_size = 0x108
            # the section table follows the optional header, whose size the COFF header
            # declares; the bitness-derived default above is only the usual value for it
            if pe_offset and len(binary) >= pe_offset + 0x16:
                declared_size = struct.unpack("<H", binary[pe_offset + 0x14 : pe_offset + 0x16])[0]
                if declared_size:
                    optional_header_size = 0x18 + declared_size
            if pe_offset and num_sections and len(binary) >= pe_offset + optional_header_size + num_sections * 0x28:
                for section_index in range(num_sections):
                    section_offset = section_index * 0x28
                    slice_start = pe_offset + optional_header_size + section_offset + 0x8
                    slice_end = pe_offset + optional_header_size + section_offset + 0x8 + 0x10
                    virt_size, virt_offset, raw_size, raw_offset = struct.unpack("<IIII", binary[slice_start:slice_end])
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
                    max_virt_section_offset = max(
                        max_virt_section_offset,
                        section_info["virt_size"] + section_info["virt_offset"],
                    )
                    max_virt_section_offset = max(
                        max_virt_section_offset,
                        section_info["raw_size"] + section_info["virt_offset"],
                    )
                    if section_info["raw_offset"] >= 0x200:
                        min_raw_section_offset = min(min_raw_section_offset, section_info["raw_offset"])
            # isCompatible() only checks for the "MZ" magic, so a DOS-stub-only binary, a
            # corrupted PE, or one with a garbage e_lfanew reaches this point with no usable
            # section data. That is not an oversized image - report it the way the ELF and
            # Mach-O loaders report the same condition, by returning no mapped data, instead
            # of raising a ValueError that claims the opposite of what happened.
            if not max_virt_section_offset:
                LOGGER.warning("PE: no section data")
                return b""
            # support up to 100MB for now.
            if max_virt_section_offset > SmdaConfig.MAX_IMAGE_SIZE:
                raise ValueError("PE file larger than MAX_IMAGE_SIZE")
            mapped_binary = bytearray([0] * max_virt_section_offset)
            # clamp to both the raw file's actual length and mapped_binary's capacity so this
            # header-copy slice assignment can never resize mapped_binary (same length on
            # both sides of the assignment, mirroring the per-section copy clamp below)
            header_copy_len = min(min_raw_section_offset, len(binary), len(mapped_binary))
            mapped_binary[0:header_copy_len] = binary[0:header_copy_len]

            for section_info in section_infos:
                # clamp the copy length to the bytes actually available in the raw file so a
                # truncated/malformed raw_size never shrinks mapped_binary via slice assignment
                # (the target region stays zero-filled beyond whatever was actually copied)
                available_raw_bytes = max(0, len(binary) - section_info["raw_offset"])
                copy_size = min(section_info["raw_size"], available_raw_bytes)
                mapped_from = section_info["virt_offset"]
                mapped_binary[mapped_from : mapped_from + copy_size] = binary[
                    section_info["raw_offset"] : section_info["raw_offset"] + copy_size
                ]
                LOGGER.debug(
                    "Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)",
                    section_info["section_index"],
                    section_info["raw_offset"],
                    section_info["raw_size"],
                    section_info["virt_offset"],
                    section_info["virt_size"],
                )
            LOGGER.debug(
                "Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes",
                len(binary),
                num_sections,
                len(mapped_binary),
            )
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary, parsed=_NOT_PROVIDED):
        return PeFileLoader.BITNESS_MAP.get(PeFileLoader.getMachineType(binary), 0)

    @staticmethod
    def getBaseAddress(binary, parsed=_NOT_PROVIDED):
        base_addr = 0
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x38:
            bitness = PeFileLoader.getBitness(binary)
            if bitness == 32:
                base_addr = struct.unpack("<I", binary[pe_offset + 0x34 : pe_offset + 0x38])[0]
            elif bitness == 64:
                base_addr = struct.unpack("<Q", binary[pe_offset + 0x30 : pe_offset + 0x38])[0]
        if base_addr:
            LOGGER.debug(
                "Changing base address from 0 to: 0x%x for inference of reference counts (based on PE header)",
                base_addr,
            )
        return base_addr

    @staticmethod
    def getPeOffset(binary):
        if len(binary) >= 0x40:
            pe_offset = struct.unpack("<I", binary[0x3C : 0x3C + 4])[0]
            return pe_offset
        return 0

    @staticmethod
    def getMachineType(binary):
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x6 and binary[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            return struct.unpack("<H", binary[pe_offset + 0x4 : pe_offset + 0x6])[0]
        return 0

    @staticmethod
    def getOEP(binary):
        oep_rva = 0
        if PeFileLoader.checkPe(binary):
            pe_offset = PeFileLoader.getPeOffset(binary)
            if pe_offset and len(binary) >= pe_offset + 0x2C:
                oep_rva = struct.unpack("<I", binary[pe_offset + 0x28 : pe_offset + 0x2C])[0]
        return oep_rva

    @staticmethod
    def getAbi(binary, parsed=_NOT_PROVIDED):
        return ""

    @staticmethod
    def getArchitecture(binary, parsed=_NOT_PROVIDED):
        architecture = PeFileLoader.ARCHITECTURE_MAP.get(PeFileLoader.getMachineType(binary), "")
        pefile = safe_lief_parse(binary) if parsed is _NOT_PROVIDED else parsed
        if pefile:
            for d in pefile.data_directories:
                if d.type == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER and d.size > 0:
                    architecture = "cil"
        return architecture

    @staticmethod
    def getReadyToRunArchitecture(binary, parsed=_NOT_PROVIDED):
        """Instruction set of a ReadyToRun assembly's precompiled body, or "".

        Empty for everything that is not one: a pure-IL assembly, a native PE, a damaged
        header. Also empty for a ReadyToRun image whose COFF machine field names no
        instruction set SMDA has a backend for -- there is no honest answer to route on
        when the image does not say what its native code is.

        `getArchitecture` reports such an image as `cil` because that is what its CLR
        header makes it, and that stays the default. This is the second fact needed to
        offer a caller the other half of the image.
        """
        pefile = safe_lief_parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not pefile:
            return ""
        if PeFileLoader._clrManagedNativeHeader(pefile) != PeFileLoader.READY_TO_RUN_SIGNATURE:
            return ""
        return PeFileLoader.ARCHITECTURE_MAP.get(PeFileLoader.getMachineType(binary), "")

    @staticmethod
    def _clrManagedNativeHeader(pefile):
        """First four bytes of whatever the CLR header's ManagedNativeHeader points at.

        Empty when the image declares no CLR header, when the header is too short to carry
        the field, when the field is empty, or when either read falls outside the image --
        lief answers an unmapped range with no bytes rather than raising.
        """
        directory = next(
            (
                candidate
                for candidate in pefile.data_directories
                if candidate.type == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER
                and candidate.rva
                and candidate.size >= PeFileLoader.CLR_MANAGED_NATIVE_HEADER_OFFSET + 8
            ),
            None,
        )
        if directory is None:
            return b""
        offset = directory.rva + PeFileLoader.CLR_MANAGED_NATIVE_HEADER_OFFSET
        field = bytes(pefile.get_content_from_virtual_address(offset, 8))
        if len(field) < 8:
            return b""
        rva, size = struct.unpack("<II", field)
        # the declared size has to cover the signature the caller is about to read: a header
        # that says it is one byte long does not become a ReadyToRun header because the three
        # bytes after it happen to spell the rest of `RTR\0`
        if not rva or size < len(PeFileLoader.READY_TO_RUN_SIGNATURE):
            return b""
        return bytes(pefile.get_content_from_virtual_address(rva, len(PeFileLoader.READY_TO_RUN_SIGNATURE)))

    @staticmethod
    def getHasBackend(binary, parsed=_NOT_PROVIDED):
        return PeFileLoader.getArchitecture(binary, parsed=parsed) in ("intel", "cil", "aarch64")

    @staticmethod
    def checkPe(binary):
        return PeFileLoader.getMachineType(binary) in PeFileLoader.BITNESS_MAP

    @staticmethod
    def getCodeAreas(binary, parsed=_NOT_PROVIDED):
        pefile = safe_lief_parse(binary) if parsed is _NOT_PROVIDED else parsed
        code_areas = []
        base_address = PeFileLoader.getBaseAddress(binary)
        if pefile and pefile.sections:
            for section in pefile.sections:
                # MEM_EXECUTE
                if section.characteristics & 0x20000000:
                    section_start = base_address + section.virtual_address
                    # the PE loader maps a zero-VirtualSize section to its raw size
                    section_size = section.virtual_size or section.sizeof_raw_data
                    if section_size % 0x1000 != 0:
                        section_size += 0x1000 - (section_size % 0x1000)
                    section_end = section_start + section_size
                    if section_end > section_start:
                        code_areas.append([section_start, section_end])
        return PeFileLoader.mergeCodeAreas(code_areas)

    @staticmethod
    def mergeCodeAreas(code_areas):
        return mergeCodeAreas(code_areas)
