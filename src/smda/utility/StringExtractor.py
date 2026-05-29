import re
import string
import struct
from typing import Iterator, Tuple

from smda.common import SmdaFunction
from smda.common.ExceptionHandling import reraise_non_operational_exception

_IS_PRINTABLE_CHAR_CODE = tuple(chr(char) in string.printable for char in range(256))
_ASCII_RE = re.compile(b"[\x09-\x0d\x20-\x7e]*")
_UNICODE_RE = re.compile(b"(?:[\x09-\x0d\x20-\x7e]\x00)*")

# ported back from our PR to capa v4.0.0
# https://github.com/mandiant/capa/blob/v4.0.0/capa/features/extractors/smda/insn.py


def read_bytes(smda_report, va, num_bytes=None):
    """
    read up to MAX_BYTES_FEATURE_SIZE from the given address.
    """

    rva = va - smda_report.base_addr
    if smda_report.buffer is None:
        raise ValueError("buffer is empty")
    buffer_end = len(smda_report.buffer)
    max_bytes = num_bytes if num_bytes is not None else 0x100
    if rva + max_bytes > buffer_end:
        return smda_report.buffer[rva:]
    else:
        return smda_report.buffer[rva : rva + max_bytes]


def derefs(smda_report, p):
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

    chain = []
    current = p
    depth = 0
    while True:
        if not smda_report.isAddrWithinMemoryImage(current):
            break
        chain.append(current)

        bytes_ = read_bytes(smda_report, current, num_bytes=4)
        if len(bytes_) < 4:
            break
        val = struct.unpack("I", bytes_)[0]

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


def detect_ascii_len(smda_report, offset, maxlen=None):
    if smda_report.buffer is None:
        return 0
    buffer = smda_report.buffer
    buffer_len = len(buffer)
    rva = offset - smda_report.base_addr
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


def detect_unicode_len(smda_report, offset, maxlen=None):
    if smda_report.buffer is None:
        return 0
    buffer = smda_report.buffer
    buffer_len = len(buffer)
    rva = offset - smda_report.base_addr
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


def read_go_string(smda_report, offset):
    # for Go strings, we need to deref once to get to the String struct (string pointer and len) and then
    # deref again for the actual string
    if smda_report.isAddrWithinMemoryImage(offset):
        if smda_report.bitness == 64:
            string_pointer_bytes = read_bytes(smda_report, offset, num_bytes=8)
            string_pointer = struct.unpack("Q", string_pointer_bytes)[0]
            length_bytes = read_bytes(smda_report, offset + 8, num_bytes=8)
            length = struct.unpack("Q", length_bytes)[0]
        else:
            string_pointer_bytes = read_bytes(smda_report, offset, num_bytes=4)
            string_pointer = struct.unpack("I", string_pointer_bytes)[0]
            length_bytes = read_bytes(smda_report, offset + 4, num_bytes=4)
            length = struct.unpack("I", length_bytes)[0]
        if smda_report.isAddrWithinMemoryImage(string_pointer):
            return read_string(smda_report, string_pointer, length)


def read_string(smda_report, offset, maxlen=None):
    # in case we are dealing with Go/Rust, we need to dereference the pointer and extract the expected length of the string
    # TODO handle Go/Rust
    if smda_report.buffer is None:
        return None
    cache = smda_report._string_cache
    cache_key = (offset, maxlen)
    if cache_key in cache:
        return cache[cache_key]

    rva = offset - smda_report.base_addr
    if not 0 <= rva < len(smda_report.buffer):
        res = None
    else:
        first_byte = smda_report.buffer[rva]
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


def extract_strings(f: SmdaFunction, mode=None) -> Iterator[Tuple[str, int]]:
    """parse string features from the given instruction."""
    if mode == "go":
        # we address stack assigned strings and String structs
        # as detailed in https://cloud.google.com/blog/topics/threat-intelligence/extracting-strings-go-rust-executables/
        # first go over the whole function and detect the stack-assigned string constructs
        instructions = list(f.getInstructions())
        for index, insn in enumerate(instructions):
            data_refs = list(insn.getDataRefs())
            if len(data_refs) == 1:
                data_ref = data_refs[0]
                # check if next two instructions are movs
                found_string = False
                if (
                    index + 2 < len(instructions)
                    and instructions[index + 1].mnemonic == "mov"
                    and instructions[index + 2].mnemonic == "mov"
                ):
                    operands = instructions[index + 2].operands.split(",")
                    if len(operands) == 2:
                        # check if the second instruction has an immediate value as second operand
                        try:
                            potential_string_len = int(operands[1])
                            if potential_string_len > 0:
                                string_result = read_string(f.smda_report, data_ref, potential_string_len)
                                if string_result:
                                    string_read, string_type = string_result
                                    found_string = True
                                    yield (
                                        string_read.rstrip("\x00"),
                                        insn.offset,
                                        data_ref,
                                        string_type,
                                    )
                        except Exception as exc:
                            reraise_non_operational_exception(exc)
                if not found_string:
                    string_result = read_go_string(f.smda_report, data_ref)
                    if string_result:
                        string_read, string_type = string_result
                        yield (
                            string_read.rstrip("\x00"),
                            insn.offset,
                            data_ref,
                            string_type,
                        )
    else:
        for insn in f.getInstructions():
            for data_ref in insn.getDataRefs():
                for v in derefs(f.smda_report, data_ref):
                    string_result = read_string(f.smda_report, v)
                    if string_result:
                        string_read, string_type = string_result
                        yield string_read.rstrip("\x00"), insn.offset, v, string_type
