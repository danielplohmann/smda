"""Bounded .eh_frame FDE-range decoder.

Extracts <initial_location, address_range> pairs from a raw ``.eh_frame``
section without building full CFI programs: only the CIE fields needed to
decode each FDE's PC-begin pointer are parsed (augmentation string, the ``zR``
FDE pointer encoding, and enough of the header to skip the rest).

Format reference: LSB / Linux Standard Base "Exception Frames" chapter
(4-byte record length with 0xFFFFFFFF extended-length escape, CIE id 0,
FDE CIE-pointer as a back-offset from its own field, DW_EH_PE pointer
encodings).

Deliberately conservative: records with unsupported versions, augmentations,
or pointer encodings are skipped individually (their length field still
advances the cursor), malformed lengths terminate the scan, and both record
count and per-record reads are bounded, so a hostile section cannot cause
quadratic work or giant allocations.
"""

# DW_EH_PE value formats (low nibble)
DW_EH_PE_absptr = 0x00
DW_EH_PE_udata2 = 0x02
DW_EH_PE_udata4 = 0x03
DW_EH_PE_udata8 = 0x04
DW_EH_PE_sdata2 = 0x0A
DW_EH_PE_sdata4 = 0x0B
DW_EH_PE_sdata8 = 0x0C
# DW_EH_PE application modes (high nibble); only absolute and pcrel are supported
DW_EH_PE_pcrel = 0x10
DW_EH_PE_indirect = 0x80
DW_EH_PE_omit = 0xFF

_VALUE_SIZES = {
    DW_EH_PE_udata2: (2, False),
    DW_EH_PE_udata4: (4, False),
    DW_EH_PE_udata8: (8, False),
    DW_EH_PE_sdata2: (2, True),
    DW_EH_PE_sdata4: (4, True),
    DW_EH_PE_sdata8: (8, True),
}

MAX_RECORDS = 200000


def _read_uleb128(data, pos, end):
    value, shift = 0, 0
    while pos < end and shift < 64:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, pos


def _read_sleb128(data, pos, end):
    value, shift = 0, 0
    while pos < end and shift < 64:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        shift += 7
        if not byte & 0x80:
            if byte & 0x40 and shift < 64:
                value -= 1 << shift
            return value, pos
    return None, pos


def _read_encoded_value(data, pos, end, encoding, pointer_size):
    """Returns (raw value, new pos) for the DW_EH_PE value format bits only
    (application bits are the caller's concern); (None, pos) if unsupported."""
    value_format = encoding & 0x0F
    if value_format == DW_EH_PE_absptr:
        size, signed = pointer_size, False
    elif value_format in _VALUE_SIZES:
        size, signed = _VALUE_SIZES[value_format]
    else:
        # uleb128/sleb128-encoded pointers are rare in .eh_frame; not supported
        return None, pos
    if pos + size > end:
        return None, pos
    value = int.from_bytes(data[pos : pos + size], "little", signed=signed)
    return value, pos + size


class _CieInfo:
    __slots__ = ("fde_encoding", "supported")

    def __init__(self, fde_encoding, supported):
        self.fde_encoding = fde_encoding
        self.supported = supported


def _parse_cie(data, pos, end, pointer_size):
    """Parses the CIE body starting after the id field; returns a _CieInfo."""
    unsupported = _CieInfo(DW_EH_PE_omit, False)
    if pos >= end:
        return unsupported
    version = data[pos]
    pos += 1
    if version not in (1, 3):
        return unsupported
    aug_end = data.find(b"\x00", pos, end)
    if aug_end < 0:
        return unsupported
    augmentation = data[pos:aug_end].decode("ascii", errors="replace")
    pos = aug_end + 1
    # the legacy "eh" augmentation carries an extra raw pointer we do not handle
    if augmentation and (not augmentation.startswith("z") or any(c not in "zRLPSB" for c in augmentation)):
        return unsupported
    code_alignment, pos = _read_uleb128(data, pos, end)
    if code_alignment is None:
        return unsupported
    data_alignment, pos = _read_sleb128(data, pos, end)
    if data_alignment is None:
        return unsupported
    if version == 1:
        if pos >= end:
            return unsupported
        pos += 1  # return address register (single byte)
    else:
        return_address_register, pos = _read_uleb128(data, pos, end)
        if return_address_register is None:
            return unsupported
    fde_encoding = DW_EH_PE_absptr
    if augmentation.startswith("z"):
        aug_length, pos = _read_uleb128(data, pos, end)
        if aug_length is None or pos + aug_length > end:
            return unsupported
        aug_data_end = pos + aug_length
        for char in augmentation[1:]:
            # 'S' (signal frame) and 'B' (AArch64 PAC) carry no augmentation data, so the
            # cursor legitimately sits at aug_data_end for a trailing one
            if char in "LPR" and pos >= aug_data_end:
                return unsupported
            if char == "L":
                pos += 1
            elif char == "P":
                personality_encoding = data[pos]
                pos += 1
                personality, pos = _read_encoded_value(data, pos, aug_data_end, personality_encoding, pointer_size)
                if personality is None:
                    # unknown personality-pointer size: the cursor cannot advance
                    # past it, so any following 'R' byte would be misread
                    return unsupported
            elif char == "R":
                fde_encoding = data[pos]
                pos += 1
            # 'S' (signal frame) and 'B' (AArch64 PAC) carry no augmentation data
    if fde_encoding & DW_EH_PE_indirect:
        return unsupported
    if (fde_encoding & 0x70) not in (0x00, DW_EH_PE_pcrel):
        # datarel/textrel/funcrel/aligned application modes are not supported
        return unsupported
    return _CieInfo(fde_encoding, True)


def decodeEhFrameFdeRanges(data, section_va, pointer_size=8, max_records=MAX_RECORDS):
    """Decodes FDE <initial_location, address_range> pairs from .eh_frame bytes.

    ``section_va`` is the virtual address the section bytes live at in the
    analyzed image (needed for DW_EH_PE_pcrel). Returns a list of
    ``(initial_location, address_range)`` tuples for every decodable FDE;
    undecodable records are skipped, a zero-length terminator or malformed
    length ends the scan.
    """
    ranges = []
    cies = {}
    pos = 0
    total = len(data)
    for _ in range(max_records):
        if pos + 4 > total:
            break
        record_start = pos
        length = int.from_bytes(data[pos : pos + 4], "little")
        pos += 4
        if length == 0:
            break  # ZERO terminator
        id_size = 4
        if length == 0xFFFFFFFF:
            # 8-byte extended length; read it so oversized records can be skipped
            if pos + 8 > total:
                break
            length = int.from_bytes(data[pos : pos + 8], "little")
            pos += 8
            # in the 64-bit DWARF format the CIE id / CIE pointer widens with the length
            id_size = 8
        record_end = pos + length
        if length > total or record_end > total:
            break  # malformed/truncated record: cannot trust the cursor anymore
        id_pos = pos
        cie_id = int.from_bytes(data[pos : pos + id_size], "little") if pos + id_size <= record_end else None
        pos += id_size
        if cie_id is None:
            break
        if cie_id == 0:
            cies[record_start] = _parse_cie(data, pos, record_end, pointer_size)
        else:
            cie = cies.get(id_pos - cie_id)
            if cie is not None and cie.supported:
                field_pos = pos
                initial_location, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding, pointer_size)
                address_range, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding & 0x0F, pointer_size)
                if initial_location is not None and address_range is not None:
                    if (cie.fde_encoding & 0x70) == DW_EH_PE_pcrel:
                        initial_location += section_va + field_pos
                    if initial_location >= 0 and address_range >= 0:
                        ranges.append((initial_location, address_range))
        pos = record_end
    return ranges


PT_GNU_EH_FRAME = 0x6474E550
EI_DATA = 5
ELFDATA2LSB = 1
_EH_FRAME_HDR_VERSION = 1
_EH_FRAME_HDR_TABLE_ENC = 0x3B  # DW_EH_PE_datarel | DW_EH_PE_sdata4
_EH_FRAME_HDR_COUNT_ENC = 0x03  # DW_EH_PE_udata4
_EH_FRAME_HDR_HEADER_SIZE = 12
_EH_FRAME_HDR_ENTRY_SIZE = 8
MAX_HDR_ENTRIES = MAX_RECORDS


def _readImageWord(image, offset, size):
    if offset < 0 or offset + size > len(image):
        return None
    return int.from_bytes(image[offset : offset + size], "little")


def _ehFrameHdrAddress(image, pointer_size):
    """Virtual address .eh_frame_hdr is mapped at, read from the program headers.

    Every field is read little-endian, so a big-endian image is rejected rather than
    decoded into byte-swapped offsets that address unrelated bytes.
    """
    if len(image) < 64 or image[:4] != b"\x7fELF":
        return None
    if image[EI_DATA] != ELFDATA2LSB:
        return None
    if pointer_size == 8:
        phoff = _readImageWord(image, 0x20, 8)
        entsize_off, num_off, vaddr_off = 0x36, 0x38, 0x10
    else:
        phoff = _readImageWord(image, 0x1C, 4)
        entsize_off, num_off, vaddr_off = 0x2A, 0x2C, 0x08
    entry_size = _readImageWord(image, entsize_off, 2)
    entry_count = _readImageWord(image, num_off, 2)
    if not phoff or not entry_size or not entry_count:
        return None
    for index in range(entry_count):
        header = phoff + index * entry_size
        if _readImageWord(image, header, 4) == PT_GNU_EH_FRAME:
            return _readImageWord(image, header + vaddr_off, pointer_size)
    return None


def decodeEhFrameHdrStarts(disassembly, pointer_size=8, max_entries=MAX_HDR_ENTRIES):
    """FDE start addresses read from .eh_frame_hdr's binary search table.

    PT_GNU_EH_FRAME points at that table, and program headers survive in a memory image
    where the section table does not, so this is the only route to a dumped ELF's FDE
    starts. The table is searched at both the recorded virtual address and that address
    rebased on the image, since a dump can carry either.
    """
    binary_info = disassembly.binary_info
    image = binary_info.binary
    if not image:
        return set()
    hdr_vaddr = _ehFrameHdrAddress(bytes(image[:0x1000]), pointer_size)
    if hdr_vaddr is None:
        return set()
    for hdr_address in (hdr_vaddr, binary_info.base_addr + hdr_vaddr):
        header = disassembly.getBytes(hdr_address, _EH_FRAME_HDR_HEADER_SIZE)
        if not header or len(header) < _EH_FRAME_HDR_HEADER_SIZE:
            continue
        header = bytes(header)
        if header[0] != _EH_FRAME_HDR_VERSION:
            continue
        if header[2] != _EH_FRAME_HDR_COUNT_ENC or header[3] != _EH_FRAME_HDR_TABLE_ENC:
            continue
        count = min(int.from_bytes(header[8:12], "little"), max_entries)
        table = disassembly.getBytes(hdr_address + _EH_FRAME_HDR_HEADER_SIZE, count * _EH_FRAME_HDR_ENTRY_SIZE)
        if not table:
            continue
        table = bytes(table)
        starts = set()
        for index in range(min(count, len(table) // _EH_FRAME_HDR_ENTRY_SIZE)):
            offset = index * _EH_FRAME_HDR_ENTRY_SIZE
            location = int.from_bytes(table[offset : offset + 4], "little", signed=True)
            starts.add(hdr_address + location)
        return starts
    return set()
