import logging
from functools import lru_cache

from smda.SmdaConfig import SmdaConfig
from smda.utility.common import mergeCodeAreas

LOGGER = logging.getLogger(__name__)

LIEF_AVAILABLE = False
try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LOGGER.warning("LIEF not available, will not be able to parse data from MachO files.")

# Sentinel: distinguishes "caller did not supply parsed" (legacy direct
# call, do your own lief.parse) from "caller already tried to parse and
# got None" (e.g. FileLoader saw lief.parse fail; do NOT retry).
_NOT_PROVIDED = object()


def _build_macho_cpu_types():
    # Single source of truth mapping Mach-O CPU types to
    # (architecture, bitness, has_backend). Mach-O CPU types already encode
    # the width (the 64-bit flag is part of the CPU type), so no extra lookup
    # is needed to resolve bitness. SMDA only ships an Intel backend; recognized
    # non-Intel CPU types are still reported accurately so loader metadata stays
    # meaningful, but they intentionally resolve to no disassembler later
    # (controlled error report) instead of being mis-analyzed as x86.
    if not LIEF_AVAILABLE:
        return {}
    cpu = lief.MachO.Header.CPU_TYPE
    return {
        cpu.X86_64: ("intel", 64, True),
        cpu.X86: ("intel", 32, True),
        cpu.ARM64: ("arm", 64, False),
        cpu.ARM: ("arm", 32, False),
        cpu.POWERPC64: ("ppc", 64, False),
        cpu.POWERPC: ("ppc", 32, False),
    }


_MACHO_CPU_TYPES = _build_macho_cpu_types()


def _resolve_macho_cpu(macho_file):
    """Return (architecture, bitness, has_backend) for a parsed Mach-O file,
    derived from its CPU type. Unknown CPU types report empty/unsupported
    metadata rather than guessing."""
    if not macho_file:
        return "", 0, False
    return _MACHO_CPU_TYPES.get(macho_file.header.cpu_type, ("", 0, False))


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


@lru_cache(maxsize=16)
def _get_sorted_sections(macho_file):
    return sorted(macho_file.sections, key=lambda section: section.size, reverse=True)


@lru_cache(maxsize=16)
def _get_sorted_segments(macho_file):
    return sorted(macho_file.segments, key=lambda segment: segment.file_size, reverse=True)


@lru_cache(maxsize=16)
def _calculate_base_address(macho_file):
    base_addr = 0
    if not macho_file:
        return base_addr
    candidates = [0xFFFFFFFFFFFFFFFF, macho_file.imagebase]
    for section in macho_file.sections:
        if section.virtual_address:
            candidates.append(section.virtual_address - section.offset)
    if len(candidates) > 1:
        base_addr = min(candidates)
    return base_addr


@lru_cache(maxsize=16)
def _calculate_boundaries(macho_file):
    # find min and max virtual addresses.
    max_virtual_address = 0
    min_virtual_address = 0xFFFFFFFFFFFFFFFF
    min_raw_offset = 0xFFFFFFFFFFFFFFFF

    # find begin of the first section/segment and end of the last section/segment.
    for section in _get_sorted_sections(macho_file):
        if not section.virtual_address:
            continue

        max_virtual_address = max(max_virtual_address, section.size + section.virtual_address)
        min_virtual_address = min(min_virtual_address, section.virtual_address)
        min_raw_offset = min(min_raw_offset, section.offset)

    for segment in macho_file.segments:
        if not segment.virtual_address:
            continue
        max_virtual_address = max(max_virtual_address, segment.virtual_size + segment.virtual_address)
        min_virtual_address = min(min_virtual_address, segment.virtual_address)
        min_raw_offset = min(min_raw_offset, segment.file_offset)

    return max_virtual_address, min_virtual_address, min_raw_offset


class MachoFileLoader:
    @staticmethod
    def isCompatible(data):
        if not LIEF_AVAILABLE:
            return False
        # check for MachO magic
        return data[:4] == b"\xce\xfa\xed\xfe" or data[:4] == b"\xcf\xfa\xed\xfe"

    @staticmethod
    def parseBinary(binary):
        # Single lief.parse entry point so FileLoader can share one parse
        # across all accessors instead of each accessor re-parsing.
        return lief.parse(binary)

    @staticmethod
    def getBaseAddress(binary, parsed=_NOT_PROVIDED):
        macho_file = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not macho_file:
            return 0
        return _calculate_base_address(macho_file)

    @staticmethod
    def mapBinary(binary, parsed=_NOT_PROVIDED):
        """
        map the MachO file sections and segments into a contiguous bytearray
        as if into virtual memory with the given base address.
        """
        macho_file = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not macho_file:
            return b""
        base_addr = MachoFileLoader.getBaseAddress(binary, parsed=macho_file)

        LOGGER.debug("MachO: base address: 0x%x", base_addr)

        max_virtual_address, min_virtual_address, min_raw_offset = _calculate_boundaries(macho_file)

        if not max_virtual_address:
            LOGGER.debug("MachO: no section or segment data")
            return b""

        # create mapped region.
        # offset 0x0 corresponds to the MachO base address
        virtual_size = max_virtual_address - base_addr
        if virtual_size > SmdaConfig.MAX_IMAGE_SIZE:
            raise ValueError("MachO file larger than MAX_IMAGE_SIZE")
        LOGGER.debug("MachO: max virtual section offset: 0x%x", max_virtual_address)
        LOGGER.debug("MachO: mapped size: 0x%x", virtual_size)
        LOGGER.debug("MachO: min raw offset: 0x%x", min_raw_offset)
        mapped_binary = bytearray(align(virtual_size, 0x1000))

        # map segments.
        for segment in _get_sorted_segments(macho_file):
            if not segment.virtual_address:
                continue
            rva = segment.virtual_address - base_addr
            LOGGER.debug(
                "MachO: mapping segment of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)",
                segment.file_size,
                rva,
                rva + segment.file_size,
                segment.virtual_address,
            )
            if len(segment.content) != segment.file_size:
                raise ValueError(
                    f"Segment content size mismatch: expected {segment.file_size}, got {len(segment.content)}"
                )
            mapped_binary[rva : rva + segment.file_size] = segment.content

        # map sections.
        for section in _get_sorted_sections(macho_file):
            if not section.virtual_address:
                continue
            rva = section.virtual_address - base_addr
            LOGGER.debug(
                "MachO: mapping section of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)",
                section.size,
                rva,
                rva + section.size,
                section.virtual_address,
            )
            if len(section.content) == section.size:
                mapped_binary[rva : rva + section.size] = section.content

        # map header.
        if min_raw_offset != 0:
            LOGGER.debug(
                "MachO: mapping 0x%x bytes of header at 0x0 (0x%x)",
                min_raw_offset,
                base_addr,
            )
            mapped_binary[0:min_raw_offset] = binary[0:min_raw_offset]

        LOGGER.debug("MachO: final mapped size: 0x%x", len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getAbi(binary, parsed=_NOT_PROVIDED):
        del binary, parsed
        return ""

    @staticmethod
    def getArchitecture(binary, parsed=_NOT_PROVIDED):
        macho_file = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        return _resolve_macho_cpu(macho_file)[0]

    @staticmethod
    def getBitness(binary, parsed=_NOT_PROVIDED):
        macho_file = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        return _resolve_macho_cpu(macho_file)[1]

    @staticmethod
    def mergeCodeAreas(code_areas):
        return mergeCodeAreas(code_areas)

    @staticmethod
    def getCodeAreas(binary, parsed=_NOT_PROVIDED):
        macho_file = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not macho_file:
            return []
        ins_flags = (
            lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS.value
            + lief.MachO.Section.FLAGS.SELF_MODIFYING_CODE.value
            + lief.MachO.Section.FLAGS.SOME_INSTRUCTIONS.value
        )
        code_areas = []
        for section in macho_file.sections:
            # SHF_EXECINSTR = 4
            if section.flags.value & ins_flags:
                section_start = section.virtual_address
                section_size = section.size
                if section.alignment and section_size % section.alignment != 0:
                    section_size += section.alignment - (section_size % section.alignment)
                section_end = section_start + section_size
                code_areas.append([section_start, section_end])
        return MachoFileLoader.mergeCodeAreas(code_areas)
