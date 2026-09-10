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
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2 = 0x02
DW_EH_PE_udata4 = 0x03
DW_EH_PE_udata8 = 0x04
DW_EH_PE_sleb128 = 0x09
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


def _read_lsda_value(data, pos, end, encoding, pointer_size):
    """Like _read_encoded_value, but also accepts the leb128 formats.

    Kept separate rather than widening _read_encoded_value: leb128 pointers really are rare in
    .eh_frame, and admitting them there would decode FDEs that are skipped today. In an LSDA
    call-site table leb128 is not rare, it is what gcc emits, so a reader that refuses it
    returns None for every entry and the table reads as empty rather than as unreadable.
    """
    value_format = encoding & 0x0F
    if value_format == DW_EH_PE_uleb128:
        return _read_uleb128(data, pos, end)
    if value_format == DW_EH_PE_sleb128:
        return _read_sleb128(data, pos, end)
    return _read_encoded_value(data, pos, end, encoding, pointer_size)


class _CieInfo:
    __slots__ = ("fde_encoding", "supported", "lsda_encoding")

    def __init__(self, fde_encoding, supported, lsda_encoding=DW_EH_PE_omit):
        self.fde_encoding = fde_encoding
        self.supported = supported
        #: DW_EH_PE_omit unless the augmentation carries 'L', in which case every FDE using
        #: this CIE opens its augmentation data with a pointer to its own LSDA
        self.lsda_encoding = lsda_encoding


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
    lsda_encoding = DW_EH_PE_omit
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
                lsda_encoding = data[pos]
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
    return _CieInfo(fde_encoding, True, lsda_encoding)


def _walkEhFrameFdes(data, pointer_size, max_records):
    """Yields ``(cie, body_pos, record_end)`` for every FDE whose CIE parsed.

    CIE records are consumed into a local table rather than yielded. A zero-length terminator,
    a malformed length or an unreadable id ends the walk: past any of those the cursor no
    longer describes record boundaries, so continuing would decode noise as records.
    """
    cies = {}
    pos = 0
    total = len(data)
    for _ in range(max_records):
        if pos + 4 > total:
            return
        record_start = pos
        length = int.from_bytes(data[pos : pos + 4], "little")
        pos += 4
        if length == 0:
            return  # ZERO terminator
        id_size = 4
        if length == 0xFFFFFFFF:
            # 8-byte extended length; read it so oversized records can be skipped
            if pos + 8 > total:
                return
            length = int.from_bytes(data[pos : pos + 8], "little")
            pos += 8
            # in the 64-bit DWARF format the CIE id / CIE pointer widens with the length
            id_size = 8
        record_end = pos + length
        if length > total or record_end > total:
            return  # malformed/truncated record: cannot trust the cursor anymore
        id_pos = pos
        cie_id = int.from_bytes(data[pos : pos + id_size], "little") if pos + id_size <= record_end else None
        pos += id_size
        if cie_id is None:
            return
        if cie_id == 0:
            cies[record_start] = _parse_cie(data, pos, record_end, pointer_size)
        else:
            cie = cies.get(id_pos - cie_id)
            if cie is not None and cie.supported:
                yield cie, pos, record_end
        pos = record_end


def decodeEhFrameFdeRanges(data, section_va, pointer_size=8, max_records=MAX_RECORDS):
    """Decodes FDE <initial_location, address_range> pairs from .eh_frame bytes.

    ``section_va`` is the virtual address the section bytes live at in the
    analyzed image (needed for DW_EH_PE_pcrel). Returns a list of
    ``(initial_location, address_range)`` tuples for every decodable FDE;
    undecodable records are skipped, a zero-length terminator or malformed
    length ends the scan.
    """
    ranges = []
    for cie, pos, record_end in _walkEhFrameFdes(data, pointer_size, max_records):
        field_pos = pos
        initial_location, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding, pointer_size)
        address_range, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding & 0x0F, pointer_size)
        if initial_location is None or address_range is None:
            continue
        if (cie.fde_encoding & 0x70) == DW_EH_PE_pcrel:
            initial_location += section_va + field_pos
        if initial_location >= 0 and address_range >= 0:
            ranges.append((initial_location, address_range))
    return ranges


#: an LSDA header plus its call-site table; larger than any single one gcc emits, and the
#: bound is what stops a corrupt pointer turning into an unbounded read
MAX_LSDA_BYTES = 0x10000
#: total call-site table bytes decoded for one section. Per-LSDA and per-record bounds do not
#: compose into one: MAX_RECORDS FDEs each naming a MAX_LSDA_BYTES table is minutes of work from
#: a section of a few hundred KB, and nothing polls the analysis budget inside this walk. It
#: counts what is decoded rather than what is read - a reader asks for MAX_LSDA_BYTES and gets
#: whatever the section holds, so charging the read would spend the budget on bytes no loop ever
#: touches. The heaviest real image measured here - a statically linked C++ test binary with
#: 3,062 landing pads - decodes 31 KB of tables, and libstdc++.so.6 decodes 26 KB, so this is
#: two orders of magnitude of headroom while capping a section built to be hostile at about a
#: second.
MAX_LSDA_TABLE_BYTES = 8 * 1024 * 1024


def _isSupportedApplication(encoding):
    """Whether this encoding's application mode is one the decoder actually applies.

    datarel/textrel/funcrel/aligned need a base this decoder does not have. Treating one as
    absolute does not fail, it silently yields a different address, so they are refused here
    the same way `_parse_cie` refuses them for an FDE.
    """
    return (encoding & 0x70) in (0x00, DW_EH_PE_pcrel)


def _decodeLsdaLandingPads(data, lsda_va, function_start, pointer_size, budget=None):
    """Landing-pad addresses one LSDA declares, or None if it does not decode.

    An empty set is a real answer: a function may have an LSDA with no call sites. Only None
    means the bytes were not an LSDA, so a caller must not treat the two alike.

    `budget` is a one-element list of call-site table bytes still allowed across the whole
    section; an exhausted one stops the decode rather than truncating its answer silently,
    which is why it returns None there.
    """
    pos = 0
    total = len(data)
    if pos >= total:
        return None
    lpstart_encoding = data[pos]
    pos += 1
    # LPStart defaults to the function start the FDE names -- the single most important
    # default here, because assuming zero yields section offsets that look like addresses
    landing_pad_start = function_start
    if lpstart_encoding != DW_EH_PE_omit:
        if not _isSupportedApplication(lpstart_encoding):
            return None
        value, pos = _read_lsda_value(data, pos, total, lpstart_encoding, pointer_size)
        if value is None:
            return None
        landing_pad_start = value + (lsda_va + 1 if (lpstart_encoding & 0x70) == DW_EH_PE_pcrel else 0)
    if pos >= total:
        return None
    ttype_encoding = data[pos]
    pos += 1
    if ttype_encoding != DW_EH_PE_omit:
        # the VALUE is the reader's failure signal; the cursor it returns beside it is always an
        # int, so testing that instead never fires and leaves a corrupted cursor decoding the
        # call-site table below
        ttype_offset, pos = _read_uleb128(data, pos, total)
        if ttype_offset is None:
            return None
    if pos >= total:
        return None
    call_site_encoding = data[pos]
    pos += 1
    # a call-site entry is an offset from a base this function already resolved, so an
    # application mode on it would be applied by nobody; reading one as absolute would
    # fabricate addresses rather than fail
    if (call_site_encoding & 0x70) != 0x00:
        return None
    table_length, pos = _read_uleb128(data, pos, total)
    if table_length is None:
        return None
    table_end = pos + table_length
    if table_end > total:
        return None
    if budget is not None:
        if budget[0] <= 0:
            return None
        budget[0] -= table_length
    pads = set()
    while pos < table_end:
        _start, pos = _read_lsda_value(data, pos, table_end, call_site_encoding, pointer_size)
        _length, pos = _read_lsda_value(data, pos, table_end, call_site_encoding, pointer_size)
        landing_pad, pos = _read_lsda_value(data, pos, table_end, call_site_encoding, pointer_size)
        _action, pos = _read_uleb128(data, pos, table_end)
        if landing_pad is None or _action is None:
            return None
        # a zero landing pad means "no handler here", not an address
        if landing_pad:
            pads.add(landing_pad_start + landing_pad)
    return pads


def decodeEhFrameLandingPads(
    data, section_va, read_va, pointer_size=8, max_records=MAX_RECORDS, max_table_bytes=MAX_LSDA_TABLE_BYTES
):
    """Every exception landing pad the image's own LSDAs declare.

    A landing pad is where the personality routine transfers control when unwinding, so it is
    interior to a function by construction and never a function start. Under
    ``-fcf-protection`` each one carries an ``endbr64``, which is why a scan looking for
    entry shapes finds them.

    Each FDE's augmentation opens with a pointer to its LSDA when the CIE's augmentation
    string carries 'L'. The LSDA lives in another section, so ``read_va(va, length)`` supplies
    the bytes; it may return fewer than asked for, or nothing.

    ``max_table_bytes`` bounds the call-site table bytes decoded across the whole section, and
    with them how often ``read_va`` is called at all. It is a parameter rather than only a
    constant so a test can exhaust it without building a section large enough to.
    """
    pads = set()
    # keyed by LSDA address: one LSDA legitimately serves one function, but nothing stops a
    # corrupt or hostile image pointing every FDE at the same table, and decoding it once per
    # FDE is the difference between milliseconds and minutes
    decoded = {}
    budget = [max_table_bytes]
    for cie, pos, record_end in _walkEhFrameFdes(data, pointer_size, max_records):
        if cie.lsda_encoding != DW_EH_PE_omit:
            pads |= _fdeLandingPads(data, pos, record_end, section_va, cie, read_va, pointer_size, decoded, budget)
    return pads


def _fdeLandingPads(data, pos, record_end, section_va, cie, read_va, pointer_size, decoded, budget):
    field_pos = pos
    initial_location, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding, pointer_size)
    address_range, pos = _read_encoded_value(data, pos, record_end, cie.fde_encoding & 0x0F, pointer_size)
    if initial_location is None or address_range is None:
        return set()
    if (cie.fde_encoding & 0x70) == DW_EH_PE_pcrel:
        initial_location += section_va + field_pos
    augmentation_length, pos = _read_uleb128(data, pos, record_end)
    if not augmentation_length:
        return set()
    lsda_field_pos = pos
    lsda_pointer, _pos = _read_lsda_value(data, pos, record_end, cie.lsda_encoding, pointer_size)
    if not lsda_pointer:
        return set()
    lsda_va = lsda_pointer
    if (cie.lsda_encoding & 0x70) == DW_EH_PE_pcrel:
        lsda_va += section_va + lsda_field_pos
    # the same LSDA under a different function start declares different addresses, so the
    # memo is keyed by both rather than by the table alone
    key = (lsda_va, initial_location)
    if key not in decoded:
        # the budget gates the read as well as the decode: the reader is asked for
        # MAX_LSDA_BYTES and a section naming a distinct LSDA per record would otherwise copy
        # that much per record before the decode declines it
        if budget[0] <= 0:
            return set()
        lsda_bytes = read_va(lsda_va, MAX_LSDA_BYTES)
        if not lsda_bytes:
            return set()
        # an exhausted budget reads as "declares nothing" from here on, which costs recall on
        # a section built to exhaust it and never invents a pad
        decoded[key] = _decodeLsdaLandingPads(lsda_bytes, lsda_va, initial_location, pointer_size, budget) or set()
    # A landing pad is interior to the function its own FDE names; the format says so, and over
    # 43,881 pads across four corpora and three system libraries not one falls outside. That
    # makes this the check separating a real table from an LSDA pointer that led into arbitrary
    # bytes and decoded anyway: on a NativeAOT image every one of 4,828 addresses produced this
    # way lands outside its FDE, and every one of them is noise.
    return {pad for pad in decoded[key] if initial_location <= pad < initial_location + address_range}


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
