"""Exact, bounded-memory candidate discovery for Delphi VMT self pointers."""

import struct
from typing import Iterator


def iter_vmt_self_references(
    binary: bytes, base: int, ptr_size: int, distance: int, start: int, end: int, alignment: int = 1
) -> Iterator[int]:
    """Yield RVAs whose complete pointer equals base + RVA + distance.

    Within each address window the pointer's upper bytes are constant. Searching
    for that necessary suffix in C avoids unpacking every byte or aligned slot.
    Full-pointer verification preserves exactness, including carries and overlaps.
    The exclusive end bounds the bytes available to read, not just pointer starts.
    """
    limit = min(end, len(binary)) - ptr_size + 1
    max_pointer = (1 << (8 * ptr_size)) - 1
    start = max(start, 0, -base - distance)
    unpack = struct.Struct("<I" if ptr_size == 4 else "<Q").unpack_from
    while start < limit:
        expected = base + start + distance
        if expected > max_pointer:
            break
        window_end = min(limit, start + 0x10000 - (expected & 0xFFFF))
        needle = expected.to_bytes(ptr_size, "little")[2:]
        position = binary.find(needle, start + 2, window_end + ptr_size - 1)
        while position != -1:
            offset = position - 2
            if offset % alignment == 0 and unpack(binary, offset)[0] == base + offset + distance:
                yield offset
            position = binary.find(needle, position + 1, window_end + ptr_size - 1)
        start = window_end
