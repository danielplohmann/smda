import logging
import struct
import warnings
from functools import lru_cache

from smda.SmdaConfig import SmdaConfig
from smda.utility.common import mergeCodeAreas
from smda.utility.lief_helper import safe_lief_parse
from smda.utility.MachoBinary import get_active_macho_binary

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

# Thin Mach-O: LE 32/64 and BE 32/64. Fat/universal: both endiannesses and 32/64 fat headers.
_THIN_MACHO_MAGICS = frozenset(
    {
        b"\xce\xfa\xed\xfe",  # MH_CIGAM (LE 32)
        b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (LE 64)
        b"\xfe\xed\xfa\xce",  # MH_MAGIC (BE 32)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (BE 64)
    }
)
_FAT_MACHO_MAGICS = frozenset(
    {
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM
        b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
        b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
    }
)
_SLICE_MACHO_MAGICS = _THIN_MACHO_MAGICS


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
        cpu.ARM64: ("aarch64", 64, True),
        cpu.ARM: ("arm", 32, False),
        cpu.POWERPC64: ("ppc", 64, False),
        cpu.POWERPC: ("ppc", 32, False),
    }


_MACHO_CPU_TYPES = _build_macho_cpu_types()


def _resolve_macho_cpu(macho_file):
    """Return (architecture, bitness, has_backend) for a parsed Mach-O file,
    derived from its CPU type. Unknown CPU types report empty/unsupported
    metadata rather than guessing."""
    # A FAT Mach-O parses to a lief.MachO.FatBinary, which has no ``header``;
    # guard against that (and any incomplete object) so we report unsupported
    # metadata instead of raising.
    if not macho_file or not hasattr(macho_file, "header"):
        return "", 0, False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        cpu_type = macho_file.header.cpu_type
    return _MACHO_CPU_TYPES.get(cpu_type, ("", 0, False))


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
            addr = section.virtual_address - section.offset
            # a negative candidate is not a valid image base; it would shift every reported
            # VA negative and inflate virtual_size in mapBinary by the same amount
            # (mirrors ElfFileLoader._calculate_base_address)
            if addr >= 0:
                candidates.append(addr)
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
    def _getMachoBinary(binary, parsed):
        # A slice returned from a temporary FatBinary does not retain its native
        # parent in some LIEF versions. Direct one-off accessor calls therefore
        # use LIEF's owned active Binary result; FileLoader/BinaryInfo pass a
        # retained FatBinary through ``parsed`` for explicit slice selection.
        macho_file = safe_lief_parse(binary) if parsed is _NOT_PROVIDED else parsed
        return get_active_macho_binary(macho_file)

    @staticmethod
    def _looks_like_fat_macho(data):
        """True for universal/fat Mach-O; rejects Java class files that share 0xcafebabe."""
        if len(data) < 8:
            return False
        magic = data[:4]
        if magic not in _FAT_MACHO_MAGICS:
            return False
        big_endian = magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
        is_64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        endian = ">" if big_endian else "<"
        nfat_arch = struct.unpack(endian + "I", data[4:8])[0]
        if nfat_arch == 0 or nfat_arch > 32:
            return False
        arch_size = 32 if is_64 else 20
        header_end = 8 + nfat_arch * arch_size
        if len(data) < header_end:
            return False
        offset = 8
        for _ in range(nfat_arch):
            if is_64:
                _cputype, _cpusub, slice_off, slice_size, _align, _reserved = struct.unpack(
                    endian + "IIQQII", data[offset : offset + 32]
                )
                offset += 32
            else:
                _cputype, _cpusub, slice_off, slice_size, _align = struct.unpack(
                    endian + "IIIII", data[offset : offset + 20]
                )
                offset += 20
            if slice_off < header_end or slice_off + slice_size > len(data):
                return False
            if data[slice_off : slice_off + 4] not in _SLICE_MACHO_MAGICS:
                return False
        return True

    @staticmethod
    def isCompatible(data):
        if not LIEF_AVAILABLE or not data or len(data) < 4:
            return False
        magic = data[:4]
        if magic in _THIN_MACHO_MAGICS:
            return True
        return MachoFileLoader._looks_like_fat_macho(data)

    @staticmethod
    def parseBinary(binary):
        # Preserve the FatBinary container so every accessor and provider can
        # select the same active slice instead of accepting lief.parse()'s
        # implicit first-slice conversion.
        return safe_lief_parse(binary, parser=lief.MachO.parse)

    @staticmethod
    def getBaseAddress(binary, parsed=_NOT_PROVIDED):
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
        if not macho_file:
            return 0
        return _calculate_base_address(macho_file)

    @staticmethod
    def mapBinary(binary, parsed=_NOT_PROVIDED):
        """
        map the MachO file sections and segments into a contiguous bytearray
        as if into virtual memory with the given base address.
        """
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
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
            if rva < 0:
                continue
            LOGGER.debug(
                "MachO: mapping segment of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)",
                segment.file_size,
                rva,
                rva + segment.file_size,
                segment.virtual_address,
            )
            # mapped_binary's capacity is sized from virtual_size, but lief.parse() never
            # validates file_size against virtual_size (only an explicit lief.MachO.check_layout()
            # call does, which this loader never makes); clamp the write extent so a crafted/
            # corrupted Mach-O with file_size > virtual_size can't write past the buffer.
            copy_size = min(segment.file_size, max(0, len(mapped_binary) - rva))
            # a truncated Mach-O (common for carved samples) used to abort the whole run here;
            # warn and zero-pad the shortfall instead, mirroring ElfFileLoader._map_segments
            if len(segment.content) != segment.file_size:
                LOGGER.warning("MachO: Mismatch in segment content vs. header-specified file size!")
                if len(segment.content) < segment.file_size:
                    LOGGER.warning("MachO: Padding to file size with zeroes!")
                    content_copy_size = min(len(segment.content), copy_size)
                    mapped_binary[rva : rva + content_copy_size] = segment.content[:content_copy_size]
                    mapped_binary[rva + content_copy_size : rva + copy_size] = b"\x00" * (copy_size - content_copy_size)
                    continue
                LOGGER.warning("MachO: More content than file size, truncating to the header-specified size.")
            mapped_binary[rva : rva + copy_size] = segment.content[:copy_size]

        # map sections.
        for section in _get_sorted_sections(macho_file):
            if not section.virtual_address:
                continue
            rva = section.virtual_address - base_addr
            if rva < 0:
                # a negative index wraps to the end of mapped_binary and the slice assignment
                # would then resize it, desynchronizing every later VA->offset translation
                continue
            LOGGER.debug(
                "MachO: mapping section of 0x%04x bytes at 0x%08x-0x%08x (0x%08x)",
                section.size,
                rva,
                rva + section.size,
                section.virtual_address,
            )
            # zero-pad short content instead of skipping the section entirely (mirrors
            # ElfFileLoader._map_sections) and clamp to the remaining capacity so both sides
            # of the assignment always have the same length
            content_to_be_mapped = bytearray(section.content)
            if len(content_to_be_mapped) < section.size:
                content_to_be_mapped += b"\x00" * (section.size - len(content_to_be_mapped))
            copy_size = min(section.size, max(0, len(mapped_binary) - rva))
            mapped_binary[rva : rva + copy_size] = content_to_be_mapped[:copy_size]

        # map header.
        if min_raw_offset != 0:
            LOGGER.debug(
                "MachO: mapping 0x%x bytes of header at 0x0 (0x%x)",
                min_raw_offset,
                base_addr,
            )
            # clamp to both the raw file's actual length and mapped_binary's capacity so this
            # slice assignment can never resize mapped_binary on a truncated/malformed file
            header_copy_len = min(min_raw_offset, len(binary), len(mapped_binary))
            mapped_binary[0:header_copy_len] = binary[0:header_copy_len]

        LOGGER.debug("MachO: final mapped size: 0x%x", len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getAbi(binary, parsed=_NOT_PROVIDED):
        del binary, parsed
        return ""

    @staticmethod
    def getArchitecture(binary, parsed=_NOT_PROVIDED):
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
        return _resolve_macho_cpu(macho_file)[0]

    @staticmethod
    def getBitness(binary, parsed=_NOT_PROVIDED):
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
        return _resolve_macho_cpu(macho_file)[1]

    @staticmethod
    def mergeCodeAreas(code_areas):
        return mergeCodeAreas(code_areas)

    @staticmethod
    def getCodeAreas(binary, parsed=_NOT_PROVIDED):
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
        if not macho_file:
            return []
        ins_flags = (
            lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS.value
            + lief.MachO.Section.FLAGS.SELF_MODIFYING_CODE.value
            + lief.MachO.Section.FLAGS.SOME_INSTRUCTIONS.value
        )
        exec_prot = int(lief.MachO.SegmentCommand.VM_PROTECTIONS.X)
        code_areas = []
        for section in macho_file.sections:
            if section.flags.value & ins_flags:
                section_start = section.virtual_address
                section_size = section.size
                if section.alignment and section_size % section.alignment != 0:
                    section_size += section.alignment - (section_size % section.alignment)
                section_end = section_start + section_size
                # a zero-width area is never a useful bound, and if it is the only one
                # recovered it turns isInCodeAreas into a filter that rejects everything
                if section_end > section_start:
                    code_areas.append([section_start, section_end])
        # Mach-O commonly marks the whole __TEXT segment executable even though
        # it also contains constants and strings. Prefer precise instruction
        # sections when present; use executable segments only as a fallback for
        # binaries whose sections do not carry instruction flags.
        if code_areas:
            return MachoFileLoader.mergeCodeAreas(code_areas)
        for segment in macho_file.segments:
            if not segment.virtual_address:
                continue
            if not (int(segment.init_protection) & exec_prot):
                continue
            segment_start = segment.virtual_address
            segment_size = segment.virtual_size
            if segment_size:
                code_areas.append([segment_start, segment_start + segment_size])
        return MachoFileLoader.mergeCodeAreas(code_areas)

    @staticmethod
    def getHasBackend(binary, parsed=_NOT_PROVIDED):
        macho_file = MachoFileLoader._getMachoBinary(binary, parsed)
        return _resolve_macho_cpu(macho_file)[2]
