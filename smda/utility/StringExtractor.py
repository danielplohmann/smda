import string
import struct
from typing import Tuple, Iterator

from smda.common import SmdaFunction

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
    depth = 0
    while True:
        if not smda_report.isAddrWithinMemoryImage(p):
            return
        yield p

        bytes_ = read_bytes(smda_report, p, num_bytes=4)
        val = struct.unpack("I", bytes_)[0]

        # sanity: pointer points to self
        if val == p:
            return

        # sanity: avoid chains of pointers that are unreasonably deep
        depth += 1
        if depth > 10:
            return

        p = val


def detect_ascii_len(smda_report, offset):
    if smda_report.buffer is None:
        return 0
    ascii_len = 0
    rva = offset - smda_report.base_addr
    char = smda_report.buffer[rva]
    while char < 127 and chr(char) in string.printable:
        ascii_len += 1
        rva += 1
        char = smda_report.buffer[rva]
    if char == 0:
        return ascii_len
    return 0


def detect_unicode_len(smda_report, offset):
    if smda_report.buffer is None:
        return 0
    unicode_len = 0
    rva = offset - smda_report.base_addr
    char = smda_report.buffer[rva]
    second_char = smda_report.buffer[rva + 1]
    while char < 127 and chr(char) in string.printable and second_char == 0:
        unicode_len += 2
        rva += 2
        char = smda_report.buffer[rva]
        second_char = smda_report.buffer[rva + 1]
    if char == 0 and second_char == 0:
        return unicode_len
    return 0


def read_string(smda_report, offset):
    alen = detect_ascii_len(smda_report, offset)
    if alen > 1:
        return read_bytes(smda_report, offset, alen).decode("utf-8")
    ulen = detect_unicode_len(smda_report, offset)
    if ulen > 2:
        return read_bytes(smda_report, offset, ulen).decode("utf-16")


def extract_strings(f: SmdaFunction) -> Iterator[Tuple[str, int]]:
    """parse string features from the given instruction."""
    for insn in f.getInstructions():
        for data_ref in insn.getDataRefs():
            for v in derefs(f.smda_report, data_ref):
                string_read = read_string(f.smda_report, v)
                if string_read:
                    yield string_read.rstrip("\x00"), insn.offset
