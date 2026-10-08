import re
import string
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from capstone import CS_AC_WRITE, CS_GRP_BRANCH_RELATIVE, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET

from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.synthesis import sniffBinaryFormat

_IS_PRINTABLE_CHAR_CODE = tuple(chr(char) in string.printable for char in range(256))
_ASCII_RE = re.compile(b"[\x09-\x0d\x20-\x7e]*")
_UNICODE_RE = re.compile(b"(?:[\x09-\x0d\x20-\x7e]\x00)*")

# Go and Rust strings carry their own length; a larger one is a misread header, not a literal
MAX_SIZED_STRING_LEN = 0x10000
_SIZED_STRING_WHITESPACE = "\t\n\r\x0b\x0c"
_MEMORY_SLOT_RE = re.compile(r"\[(?P<base>[a-z][a-z0-9]*)(?:\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-f]+|\d+))?\]")
# how far around a pointer load the matching length load is looked for
_LENGTH_SCAN_WINDOW = 6
_SCAN_STOP_MNEMONICS = frozenset(("call", "ret", "bl", "blr", "b", "br", "cbz", "cbnz", "tbz", "tbnz"))
_FULL_WIDTH_REGISTER_ALIASES = {
    **{f"e{name}": f"r{name}" for name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")},
    **{f"r{number}d": f"r{number}" for number in range(8, 16)},
    **{f"w{number}": f"x{number}" for number in range(31)},
}
_REGISTER_ALIASES = {
    **{
        alias: f"r{name}"
        for name in ("ax", "bx", "cx", "dx")
        for alias in (name, f"e{name}", f"{name[0]}l", f"{name[0]}h")
    },
    **{alias: f"r{name}" for name in ("si", "di", "bp", "sp") for alias in (name, f"e{name}", f"{name}l")},
    **{f"r{number}{suffix}": f"r{number}" for number in range(8, 16) for suffix in ("b", "w", "d")},
    **{f"w{number}": f"x{number}" for number in range(31)},
}
_GO_ARGUMENT_REGISTERS = ("rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11")
_SYSV_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_WIN64_ARGUMENT_REGISTERS = ("rcx", "rdx", "r8", "r9")

# ported back from our PR to capa v4.0.0
# https://github.com/mandiant/capa/blob/v4.0.0/capa/features/extractors/smda/insn.py


def read_bytes(smda_report: SmdaReport, va: int, num_bytes: Optional[int] = None) -> bytes:
    """
    read up to MAX_BYTES_FEATURE_SIZE from the given address.
    """

    buffer = smda_report.buffer
    base_addr = smda_report.base_addr
    # base_addr joins the existing buffer check rather than getting its own: a report with no
    # base address cannot turn a VA into an offset at all, which is the same unusable state
    if buffer is None or base_addr is None:
        raise ValueError("buffer is empty")
    rva = va - base_addr
    buffer_end = len(buffer)
    max_bytes = num_bytes if num_bytes is not None else 0x100
    if rva + max_bytes > buffer_end:
        return buffer[rva:]
    else:
        return buffer[rva : rva + max_bytes]


def derefs(smda_report: SmdaReport, p: int) -> Iterator[int]:
    """
    recursively follow the given pointer, yielding the valid memory addresses along the way.
    useful when you may have a pointer to string, or pointer to pointer to string, etc.

    this is a "do what i mean" type of helper function.

    based on the implementation in viv/insn.py
    """
    cache = smda_report._derefs_cache
    if p in cache:
        yield from cache[p]
        return

    chain: List[int] = []
    current = p
    depth = 0
    word_size = 8 if smda_report.bitness == 64 else 4
    word_format = "<Q" if word_size == 8 else "<I"
    while True:
        if not smda_report.isAddrWithinMemoryImage(current):
            break
        chain.append(current)

        bytes_ = read_bytes(smda_report, current, num_bytes=word_size)
        if len(bytes_) < word_size:
            break
        val = struct.unpack(word_format, bytes_)[0]

        # sanity: pointer points to self or creates a loop
        if val == current or val in chain:
            break

        # sanity: avoid chains of pointers that are unreasonably deep
        depth += 1
        if depth > 10:
            break

        current = val

    cache[p] = chain
    yield from chain


def detect_ascii_len(smda_report: SmdaReport, offset: int, maxlen: Optional[int] = None) -> int:
    buffer = smda_report.buffer
    base_addr = smda_report.base_addr
    if buffer is None or base_addr is None:
        return 0
    buffer_len = len(buffer)
    rva = offset - base_addr
    if not 0 <= rva < buffer_len:
        return 0

    endpos = rva + maxlen if maxlen is not None else buffer_len
    match = _ASCII_RE.match(buffer, rva, endpos)
    if not match:
        return 0
    ascii_len = match.end() - rva
    next_char_idx = match.end()
    if (next_char_idx < buffer_len and buffer[next_char_idx] == 0) or (maxlen is not None and ascii_len >= maxlen):
        return ascii_len if maxlen is None else min(ascii_len, maxlen)
    return 0


def detect_unicode_len(smda_report: SmdaReport, offset: int, maxlen: Optional[int] = None) -> int:
    buffer = smda_report.buffer
    base_addr = smda_report.base_addr
    if buffer is None or base_addr is None:
        return 0
    buffer_len = len(buffer)
    rva = offset - base_addr
    if not 0 <= rva < buffer_len - 1:
        return 0

    endpos = rva + 2 * maxlen if maxlen is not None else buffer_len
    match = _UNICODE_RE.match(buffer, rva, endpos)
    if not match:
        return 0
    unicode_len = match.end() - rva
    next_char_idx = match.end()
    if (next_char_idx + 1 < buffer_len and buffer[next_char_idx] == 0 and buffer[next_char_idx + 1] == 0) or (
        maxlen is not None and unicode_len >= 2 * maxlen
    ):
        return unicode_len if maxlen is None else min(unicode_len, 2 * maxlen)
    return 0


def _looks_like_pointer(smda_report: SmdaReport, va: int) -> bool:
    word_size = 8 if smda_report.bitness == 64 else 4
    word_bytes = read_bytes(smda_report, va, num_bytes=word_size)
    if len(word_bytes) < word_size:
        return False
    return bool(smda_report.isAddrWithinMemoryImage(struct.unpack("<Q" if word_size == 8 else "<I", word_bytes)[0]))


def _within_mapped_section(smda_report: SmdaReport, va: int) -> bool:
    """Small immediates read as addresses of a zero-based image land in the file header, whose
    magic is printable. Literals always sit in a mapped section when the report knows its sections;
    sections at address 0 are the unmapped ones (ELF .comment, .debug_*)."""
    mapped = [section for section in smda_report.code_sections if section[1]]
    return not mapped or any(section[1] <= va < section[2] for section in mapped)


def read_sized_string(smda_report: SmdaReport, offset: int, length: int) -> Optional[Tuple[str, str]]:
    """Read a string of exactly length bytes, as Go and Rust store them: UTF-8 and not NUL-terminated.

    Both toolchains pack their string literals back to back, so the bytes past the end are usually
    the next literal and say nothing about where this one stops; the length has to come from the
    reference instead.
    """
    if not 0 < length <= MAX_SIZED_STRING_LEN or not smda_report.isAddrWithinMemoryImage(offset):
        return None
    if not _within_mapped_section(smda_report, offset):
        return None
    # a referenced slot holding an address is a pointer table or slice header; a short length
    # would otherwise accept its low bytes, which are often printable
    if _looks_like_pointer(smda_report, offset):
        return None
    raw = read_bytes(smda_report, offset, num_bytes=length)
    if len(raw) != length:
        return None
    try:
        # a NUL-terminated literal passed as a byte slice counts its terminator in the length
        decoded = raw.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    if not decoded or not all(char.isprintable() or char in _SIZED_STRING_WHITESPACE for char in decoded):
        return None
    return decoded, "ascii" if decoded.isascii() else "utf8"


def read_go_string(smda_report: SmdaReport, offset: int) -> Optional[Tuple[str, str]]:
    """Read the string a (pointer, length) header at offset describes.

    This is the layout of a Go string header and of a Rust &str, so it serves both.
    """
    if not smda_report.isAddrWithinMemoryImage(offset):
        return None
    word_size = 8 if smda_report.bitness == 64 else 4
    word_format = "<Q" if word_size == 8 else "<I"
    string_pointer_bytes = read_bytes(smda_report, offset, num_bytes=word_size)
    length_bytes = read_bytes(smda_report, offset + word_size, num_bytes=word_size)
    if len(string_pointer_bytes) < word_size or len(length_bytes) < word_size:
        return None
    string_pointer = struct.unpack(word_format, string_pointer_bytes)[0]
    length = struct.unpack(word_format, length_bytes)[0]
    return read_sized_string(smda_report, string_pointer, length)


def _parse_immediate(operand: str) -> Optional[int]:
    try:
        return int(operand.strip().lstrip("#"), 0)
    except ValueError:
        return None


def _normalize_location(operand: str) -> Optional[str]:
    """Canonical name for a register or a [base + disp] slot, None for anything else."""
    operand = operand.strip().lower()
    if "[" in operand:
        match = _MEMORY_SLOT_RE.search(operand)
        if not match:
            return None
        displacement = int(match.group("disp"), 0) if match.group("disp") else 0
        if match.group("sign") == "-":
            displacement = -displacement
        base = _REGISTER_ALIASES.get(match.group("base"), match.group("base"))
        return f"[{base}{displacement:+d}]"
    return _REGISTER_ALIASES.get(operand, operand)


def _length_registers(smda_report: SmdaReport, mode: str) -> Dict[str, str]:
    if smda_report.architecture == "aarch64":
        registers = tuple(f"x{number}" for number in range(16 if mode == "go" else 8))
    elif smda_report.bitness != 64:
        return {}
    elif mode == "go":
        registers = _GO_ARGUMENT_REGISTERS
    else:
        binary_format = sniffBinaryFormat(smda_report.xheader or smda_report.buffer)
        if binary_format == "pe":
            registers = _WIN64_ARGUMENT_REGISTERS
        elif binary_format in ("elf", "macho") or smda_report.abi in ("SYSTEMV", "LINUX"):
            registers = _SYSV_ARGUMENT_REGISTERS
        else:
            sysv = dict(zip(_SYSV_ARGUMENT_REGISTERS[:-1], _SYSV_ARGUMENT_REGISTERS[1:], strict=True))
            win64 = dict(zip(_WIN64_ARGUMENT_REGISTERS[:-1], _WIN64_ARGUMENT_REGISTERS[1:], strict=True))
            return {
                key: value
                for key, value in (sysv | win64).items()
                if key not in sysv or key not in win64 or sysv[key] == win64[key]
            }
    return dict(zip(registers[:-1], registers[1:], strict=True))


def _length_locations(location: str, word_size: int, registers: Dict[str, str]) -> Tuple[str, ...]:
    """Where the length of a (pointer, length) pair lives when the pointer is in location."""
    if location.startswith("["):
        base, sign, displacement = re.split(r"([+-])", location[1:-1], maxsplit=1)
        return (f"[{base}{int(sign + displacement) + word_size:+d}]",)
    return (registers[location],) if location in registers else ()


def _destination(insn) -> Optional[str]:
    operands = (insn.operands or "").split(",")
    return _normalize_location(operands[0]) if operands[0] else None


def _written_locations(insn):
    detailed = insn.getDetailed()
    _, written = detailed.regs_access()
    locations = {_normalize_location(detailed.reg_name(register)) for register in written}
    if detailed.operands and detailed.operands[0].access & CS_AC_WRITE:
        destination = _destination(insn)
        match = re.fullmatch(r"\[(\w+)([+-]\d+)\]", destination or "")
        if match:
            locations.update(
                f"[{match.group(1)}{int(match.group(2)) + displacement:+d}]"
                for displacement in range(detailed.operands[0].size)
            )
        else:
            locations.add(destination)
    return locations


def _full_width_location(operand: str, word_size: int) -> bool:
    operand = operand.strip()
    if "[" in operand:
        return operand.startswith("qword ptr " if word_size == 8 else "dword ptr ")
    if word_size == 4:
        return operand in _FULL_WIDTH_REGISTER_ALIASES
    return operand == _normalize_location(operand)


def _immediate_length_value(insn, word_size: int) -> Optional[int]:
    operands = (insn.operands or "").split(",")
    if insn.mnemonic != "mov" or len(operands) != 2:
        return None
    destination = operands[0].strip()
    if "[" in destination:
        if not destination.startswith("qword ptr " if word_size == 8 else "dword ptr "):
            return None
    elif destination != _normalize_location(destination) and destination not in _FULL_WIDTH_REGISTER_ALIASES:
        return None
    return _parse_immediate(operands[1])


def _location_invalidated(location: str, written, word_size: int) -> bool:
    if location in written:
        return True
    if location.startswith("["):
        match = re.fullmatch(r"\[(\w+)([+-]\d+)\]", location)
        return bool(
            match
            and (
                match.group(1) in written
                or any(
                    f"[{match.group(1)}{int(match.group(2)) + displacement:+d}]" in written
                    for displacement in range(word_size)
                )
            )
        )
    return False


def _scan_boundary(insn) -> bool:
    if insn.mnemonic in _SCAN_STOP_MNEMONICS or insn.mnemonic.startswith(("j", "b.")):
        return True
    return any(
        group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET, CS_GRP_INT, CS_GRP_BRANCH_RELATIVE)
        for group in insn.getDetailed().groups
    )


def _previous_length(instructions, index: int, locations, word_size: int) -> Optional[int]:
    for candidate in reversed(instructions[max(0, index - _LENGTH_SCAN_WINDOW) : index]):
        if _scan_boundary(candidate):
            break
        written = _written_locations(candidate)
        if any(_location_invalidated(location, written, word_size) for location in locations):
            if _destination(candidate) in locations:
                return _immediate_length_value(candidate, word_size)
            return None
    return None


def _immediate_length(instructions, index: int, word_size: int, registers: Dict[str, str]) -> Optional[int]:
    """Find a live immediate length paired with the referenced pointer, within a straight-line window."""
    insn = instructions[index]
    if insn.mnemonic == "push":
        previous = instructions[index - 1] if index > 0 else None
        if previous is not None and previous.mnemonic == "push":
            return _parse_immediate(previous.operands or "")
        return None
    pointer_location = _destination(insn)
    if pointer_location is None:
        return None
    pointers = {pointer_location}
    backward_locations = _length_locations(pointer_location, word_size, registers)
    for position, candidate in enumerate(instructions[index + 1 : index + 1 + _LENGTH_SCAN_WINDOW], index + 1):
        if _scan_boundary(candidate):
            break
        operands = (candidate.operands or "").split(",")
        copied_to = None
        if (
            candidate.mnemonic == "mov"
            and len(operands) == 2
            and _normalize_location(operands[1]) in pointers
            and all(_full_width_location(operand, word_size) for operand in operands)
        ):
            copied_to = _normalize_location(operands[0])
        written = _written_locations(candidate)
        pointers = {location for location in pointers if not _location_invalidated(location, written, word_size)}
        if copied_to is not None:
            pointers.add(copied_to)
            copied_locations = set(_length_locations(copied_to, word_size, registers)) - pointers
            copied_length = _previous_length(instructions, position, copied_locations, word_size)
            if copied_length is not None:
                return copied_length
        if pointer_location not in pointers:
            backward_locations = ()
        if not pointers:
            return None
        locations = {location for pointer in pointers for location in _length_locations(pointer, word_size, registers)}
        if any(_location_invalidated(location, written, word_size) for location in locations):
            if copied_to is not None:
                backward_locations = tuple(
                    location
                    for location in backward_locations
                    if not _location_invalidated(location, written, word_size)
                )
                continue
            if _destination(candidate) in locations:
                return _immediate_length_value(candidate, word_size)
            return None
    return _previous_length(instructions, index, backward_locations, word_size)


def _language_mode(smda_report: SmdaReport) -> Optional[str]:
    scores = smda_report.language if isinstance(smda_report.language, dict) else {}
    best = max(("go", "rust"), key=lambda name: scores.get(name, 0.0))
    return best if scores.get(best, 0.0) > 0.5 else None


def read_string(smda_report: SmdaReport, offset: int, maxlen: Optional[int] = None) -> Optional[Tuple[str, str]]:
    # NUL- or end-of-printable-terminated strings only; Go and Rust strings carry their length in
    # the reference instead and go through read_sized_string()
    buffer = smda_report.buffer
    base_addr = smda_report.base_addr
    if buffer is None or base_addr is None:
        return None
    cache = smda_report._string_cache
    cache_key = (offset, maxlen)
    if cache_key in cache:
        return cache[cache_key]

    rva = offset - base_addr
    if not 0 <= rva < len(buffer):
        res = None
    else:
        first_byte = buffer[rva]
        if not _IS_PRINTABLE_CHAR_CODE[first_byte]:
            res = None
        else:
            alen = detect_ascii_len(smda_report, offset, maxlen)
            ulen = detect_unicode_len(smda_report, offset, maxlen) if alen < 1 else 0
            if alen >= 1:
                res = (read_bytes(smda_report, offset, alen).decode("utf-8"), "ascii")
            elif ulen >= 2:
                res = (read_bytes(smda_report, offset, ulen).decode("utf-16"), "unicode")
            else:
                res = None

    # bound cache growth; only checked on the miss/write path, not on hits
    if len(cache) > 10000:
        cache.clear()
    cache[cache_key] = res
    return res


def extract_strings(f: SmdaFunction, mode: Optional[str] = None) -> Iterator[Tuple[str, Optional[int], int, str]]:
    """parse string features from the given instruction."""
    smda_report = f.smda_report
    if smda_report is None:
        # every helper below reads the buffer, base address and caches off the report, so a
        # function detached from one has nothing to search rather than an empty result
        return
    if mode is None:
        mode = _language_mode(smda_report)
    if mode in ("go", "rust"):
        # Go and Rust reference a string either directly, with its length loaded next to the pointer
        # (registers or stack slots), or through a (pointer, length) header in data
        # as detailed in https://cloud.google.com/blog/topics/threat-intelligence/extracting-strings-go-rust-executables/
        word_size = 8 if smda_report.bitness == 64 else 4
        registers = _length_registers(smda_report, mode)
        for block in f.getBlocks():
            instructions = list(block.getInstructions())
            for index, insn in enumerate(instructions):
                data_refs = list(insn.getDataRefs())
                if len(data_refs) != 1:
                    continue
                data_ref = data_refs[0]
                string_result = None
                length = _immediate_length(instructions, index, word_size, registers)
                if length:
                    string_result = read_sized_string(smda_report, data_ref, length)
                if string_result is None:
                    string_result = read_go_string(smda_report, data_ref)
                if string_result:
                    string_read, string_type = string_result
                    yield string_read, insn.offset, data_ref, string_type
    else:
        for insn in f.getInstructions():
            for data_ref in insn.getDataRefs():
                for v in derefs(smda_report, data_ref):
                    string_result = read_string(smda_report, v)
                    if string_result:
                        string_read, string_type = string_result
                        yield string_read.rstrip("\x00"), insn.offset, v, string_type
