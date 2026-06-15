import contextlib
import logging
import sys
from functools import lru_cache

import lief

from smda.SmdaConfig import SmdaConfig
from smda.utility.common import mergeCodeAreas

LOGGER = logging.getLogger(__name__)

# Sentinel: distinguishes "caller did not supply parsed" (legacy direct
# call, do your own lief.parse) from "caller already tried to parse and
# got None" (e.g. FileLoader saw lief.parse fail; do NOT retry).
_NOT_PROVIDED = object()

# Single source of truth mapping ELF machine types to (architecture, bitness,
# has_backend). SMDA only ships an Intel disassembly backend, but reporting the
# real architecture for recognized non-Intel ELFs keeps loader metadata honest
# instead of pretending every ELF is x86. Architectures with has_backend=False
# intentionally resolve to no disassembler later (controlled error report).
# A bitness of 0 here means the machine type alone is width-ambiguous; it is
# then resolved from the ELF class (identity_class) in _resolve_elf_machine().
_ELF_MACHINE_TYPES = {
    lief.ELF.ARCH.X86_64: ("intel", 64, True),
    lief.ELF.ARCH.I386: ("intel", 32, True),
    lief.ELF.ARCH.AARCH64: ("arm", 64, False),
    lief.ELF.ARCH.ARM: ("arm", 32, False),
    lief.ELF.ARCH.PPC64: ("ppc", 64, False),
    lief.ELF.ARCH.PPC: ("ppc", 32, False),
    lief.ELF.ARCH.SPARCV9: ("sparc", 64, False),
    lief.ELF.ARCH.SPARC: ("sparc", 32, False),
    lief.ELF.ARCH.MIPS: ("mips", 0, False),
    lief.ELF.ARCH.RISCV: ("riscv", 0, False),
    lief.ELF.ARCH.M68K: ("m68k", 0, False),
    lief.ELF.ARCH.SH: ("sh", 0, False),
    lief.ELF.ARCH.ALTERA_NIOS2: ("nios2", 0, False),
    lief.ELF.ARCH.OPENRISC: ("openrisc", 0, False),
    lief.ELF.ARCH.XTENSA: ("xtensa", 0, False),
}
# NOTE: MicroBlaze (e_machine 189) is intentionally absent: lief has no
# lief.ELF.ARCH enum value for it and reports the raw integer, so it resolves
# through the unknown-machine-type fallback below.


def _resolve_elf_machine(elffile):
    """Return (architecture, bitness, has_backend) for a parsed ELF.

    Architecture and support status come from the machine type. Bitness comes
    from the same mapping when the machine type implies a fixed width; for
    width-ambiguous architectures (e.g. MIPS, RISC-V) it falls back to the ELF
    class so the reported bitness stays correct.
    """
    # Guard against a missing header (failed parse, or an incomplete/mock
    # object) so we report unsupported metadata instead of raising. We avoid a
    # blanket try/except here so genuine parse/memory errors still surface.
    if elffile is None or not hasattr(elffile, "header"):
        return "", 0, False
    header = elffile.header
    architecture, bitness, has_backend = _ELF_MACHINE_TYPES.get(header.machine_type, ("", 0, False))
    if architecture and bitness == 0:
        identity_class = header.identity_class
        if identity_class == lief.ELF.Header.CLASS.ELF64:
            bitness = 64
        elif identity_class == lief.ELF.Header.CLASS.ELF32:
            bitness = 32
    return architecture, bitness, has_backend


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


@lru_cache(maxsize=16)
def has_bogus_sections(elffile, base_addr=0):
    max_virtual_address = 0
    for section in elffile.sections:
        if section.virtual_address:
            max_virtual_address = max(max_virtual_address, section.size + section.virtual_address)
    return (max_virtual_address - base_addr) > sys.maxsize


@lru_cache(maxsize=16)
def _calculate_base_address(elffile):
    base_addr = 0
    candidates = [0xFFFFFFFFFFFFFFFF]
    if not elffile:
        return base_addr
    if not has_bogus_sections(elffile):
        for section in elffile.sections:
            if section.virtual_address:
                addr = section.virtual_address - section.offset
                if addr >= 0:
                    candidates.append(addr)
    else:
        # go for segments only instead
        base_addr = 0
        candidates = [0xFFFFFFFFFFFFFFFF]
        for segment in elffile.segments:
            if not segment.virtual_address:
                continue
            candidates.append(segment.virtual_address)
    if len(candidates) > 1:
        base_addr = min(candidates)
    return base_addr


@lru_cache(maxsize=16)
def _get_sorted_sections(elffile):
    return sorted(elffile.sections, key=lambda section: section.size, reverse=True)


@lru_cache(maxsize=16)
def _get_boundaries(elffile, base_addr=0):
    # find min and max virtual addresses.
    max_virtual_address = 0
    min_virtual_address = 0xFFFFFFFFFFFFFFFF
    min_raw_offset = 0xFFFFFFFFFFFFFFFF

    # find begin of the first section/segment and end of the last section/segment.
    if not has_bogus_sections(elffile, base_addr):
        for section in _get_sorted_sections(elffile):
            if not section.virtual_address:
                continue
            LOGGER.debug(f"ELF: section: 0x{section.virtual_address:x} 0x{section.size:x} 0x{section.file_offset:x}")
            max_virtual_address = max(max_virtual_address, section.size + section.virtual_address)
            min_virtual_address = min(min_virtual_address, section.virtual_address)
            min_raw_offset = min(min_raw_offset, section.file_offset)
    else:
        LOGGER.warning("ELF: found possibly bogus section information, trying to parse segments.")
    # parse segments regardless
    for segment in elffile.segments:
        if not segment.virtual_address:
            continue
        LOGGER.debug(
            f"ELF: segment: 0x{segment.virtual_address:x} 0x{segment.virtual_size:x} 0x{segment.file_offset:x}"
        )
        max_virtual_address = max(max_virtual_address, segment.virtual_size + segment.virtual_address)
        min_virtual_address = min(min_virtual_address, segment.virtual_address)
        min_raw_offset = min(min_raw_offset, segment.file_offset)

    return max_virtual_address, min_virtual_address, min_raw_offset


class ElfFileLoader:
    @staticmethod
    def isCompatible(data):
        # check for ELF magic
        return data[:4] == b"\x7fELF"

    @staticmethod
    def parseBinary(binary):
        # Single lief.parse entry point so FileLoader can share one parse
        # across all accessors instead of each accessor re-parsing.
        return lief.parse(binary)

    @staticmethod
    def getBaseAddress(binary, parsed=_NOT_PROVIDED):
        elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not elffile:
            return 0
        return _calculate_base_address(elffile)

    @staticmethod
    def _calculate_boundaries(elffile, base_addr=0):
        return _get_boundaries(elffile, base_addr)

    @staticmethod
    def _map_segments(elffile, mapped_binary, base_addr):
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
            LOGGER.debug(
                "ELF: mapping segment of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)",
                segment.physical_size,
                rva,
                rva + segment.physical_size,
                segment.virtual_address,
            )
            if len(segment.content) != segment.physical_size:
                LOGGER.warning("ELF: Mismatch in segment content vs. header-specified physical size!")
                if len(segment.content) < segment.physical_size:
                    LOGGER.warning("ELF: Padding to physical size with zeroes!")
                    mapped_binary[rva : rva + len(segment.content)] = segment.content
                    mapped_binary[rva + len(segment.content) : rva + segment.physical_size] = b"\x00" * (
                        segment.physical_size - len(segment.content)
                    )
                else:
                    LOGGER.warning("ELF: More content than physical size!? Aborting, please report this case. :)")
                    raise AssertionError("Received more content than physical size, which should never be possible?")
            else:
                mapped_binary[rva : rva + segment.physical_size] = segment.content

    @staticmethod
    def _map_sections(elffile, mapped_binary, base_addr):
        # map sections.
        # may overwrite some segment data, but we expect the content to be identical.
        if not has_bogus_sections(elffile, base_addr):
            for section in _get_sorted_sections(elffile):
                if not section.virtual_address:
                    continue
                rva = section.virtual_address - base_addr
                LOGGER.debug(
                    "ELF: mapping section of 0x%04x bytes (content: 0x%04x bytes) at 0x%08x-0x%08x (0x%08x)",
                    section.size,
                    len(section.content),
                    rva,
                    rva + section.size,
                    section.virtual_address,
                )
                # potentially perform zero padding if we have less content than section size
                content_to_be_mapped = bytearray(section.content)
                if len(section.content) < section.size:
                    content_to_be_mapped += b"\x00" * (section.size - len(section.content))
                mapped_binary[rva : rva + section.size] = content_to_be_mapped

    @staticmethod
    def mapBinary(binary, parsed=_NOT_PROVIDED):
        """
        map the ELF file sections and segments into a contiguous bytearray
        as if into virtual memory with the given base address.
        """
        elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if not elffile:
            return b""
        base_addr = ElfFileLoader.getBaseAddress(binary, parsed=elffile)

        LOGGER.debug("ELF: base address: 0x%x", base_addr)

        # a segment may contain 0 or more sections.
        # ref: https://stackoverflow.com/a/14382477/87207
        #
        # i'm not sure if a section may be found outside of a segment.
        # therefore, lets load segments first, and then load sections over them.
        # we expect the section data to overwrite the segment data; however,
        # it should be exactly the same data.

        max_virtual_address, min_virtual_address, min_raw_offset = ElfFileLoader._calculate_boundaries(
            elffile, base_addr
        )

        if not max_virtual_address:
            LOGGER.debug("ELF: no section or segment data")
            return b""

        # create mapped region.
        # offset 0x0 corresponds to the ELF base address
        virtual_size = max_virtual_address - base_addr
        if virtual_size > SmdaConfig.MAX_IMAGE_SIZE:
            raise ValueError("ELF file larger than MAX_IMAGE_SIZE")
        LOGGER.debug("ELF: max virtual section offset: 0x%x", max_virtual_address)
        LOGGER.debug("ELF: min virtual section offset: 0x%x", min_virtual_address)
        LOGGER.debug("ELF: mapped size: 0x%x", virtual_size)
        LOGGER.debug("ELF: min raw offset: 0x%x", min_raw_offset)
        mapped_binary = bytearray(align(virtual_size, 0x1000))

        ElfFileLoader._map_segments(elffile, mapped_binary, base_addr)
        ElfFileLoader._map_sections(elffile, mapped_binary, base_addr)

        # map header.
        # we consider the headers to be any data found before the first section/segment
        if min_raw_offset != 0:
            LOGGER.debug(
                "ELF: mapping 0x%x bytes of header at 0x0 (0x%x)",
                min_raw_offset,
                base_addr,
            )
            mapped_binary[0:min_raw_offset] = binary[0:min_raw_offset]

        LOGGER.debug("ELF: final mapped size: 0x%x", len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getAbi(binary, parsed=_NOT_PROVIDED):
        abi = ""
        try:
            elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
            if elffile:
                abi = elffile.header.identity_os_abi.name
        except lief.bad_file as exc:
            LOGGER.warning("Failed to determine ELF ABI: %s", exc)
        return abi

    @staticmethod
    def getArchitecture(binary, parsed=_NOT_PROVIDED):
        elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        return _resolve_elf_machine(elffile)[0]

    @staticmethod
    def getBitness(binary, parsed=_NOT_PROVIDED):
        elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        return _resolve_elf_machine(elffile)[1]

    @staticmethod
    def mergeCodeAreas(code_areas):
        return mergeCodeAreas(code_areas)

    @staticmethod
    def getCodeAreas(binary, parsed=_NOT_PROVIDED):
        elffile = lief.parse(binary) if parsed is _NOT_PROVIDED else parsed
        if elffile is None:
            return []
        code_areas = []
        for section in elffile.sections:
            section_flags = 0
            # ignore invalid section flags and assume it's not a code section
            with contextlib.suppress(ValueError):
                section_flags = section.flags
            # SHF_EXECINSTR = 4
            if section_flags & lief.ELF.Section.FLAGS.EXECINSTR.value:
                section_start = section.virtual_address
                section_size = section.size
                if section_size % section.alignment != 0:
                    section_size += section.alignment - (section_size % section.alignment)
                section_end = section_start + section_size
                code_areas.append([section_start, section_end])
        for segment in sorted(elffile.segments, key=lambda segment: segment.physical_size, reverse=True):
            segment_flags = 0
            # ignore invalid segment flags and assume it's not a code section
            with contextlib.suppress(ValueError):
                segment_flags = segment.flags.value
            # SHF_EXECINSTR = 4
            if segment_flags & lief.ELF.Section.FLAGS.EXECINSTR.value:
                segment_start = segment.virtual_address
                segment_size = segment.virtual_size
                if segment.alignment and segment_size % segment.alignment != 0:
                    segment_size += segment.alignment - (segment_size % segment.alignment)
                segment_end = segment_start + segment_size
                code_areas.append([segment_start, segment_end])
        return ElfFileLoader.mergeCodeAreas(code_areas)
