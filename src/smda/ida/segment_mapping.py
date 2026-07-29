"""Shared helper for assembling an IDA database's segments into a VA-addressable buffer.

Every consumer of ``getBinary()`` converts an address to a buffer offset with
``addr - base_addr`` (``DisassemblyResult.getBytes``/``getByte``/``dereferenceDword``/
``isAddrWithinMemoryImage``, plus string extraction and buffer carving). A plain
concatenation of segment bytes is only correct for that arithmetic when the first
segment starts exactly at ``base_addr`` and no gaps separate the segments - neither of
which holds in general. ``getBaseAddr()`` rounds the first segment start down to a
0x10000 boundary, so a PE whose first segment sits at 0x401000 with base 0x400000 skews
every read by 0x1000, and any inter-segment gap skews everything after it further.
"""

import logging

from smda.SmdaConfig import SmdaConfig

LOGGER = logging.getLogger(__name__)


def assembleSegmentBuffer(base_addr, segment_ranges, read_bytes):
    """Return a buffer whose offset 0 corresponds to *base_addr*.

    ``segment_ranges`` is an iterable of ``(start_ea, end_ea)`` pairs in any order;
    ``read_bytes(addr, size)`` reads that many bytes from the database. Gaps between
    segments (and any gap between *base_addr* and the first segment) are zero-filled, so
    ``buffer[addr - base_addr]`` addresses the byte at ``addr`` for every mapped address.
    """
    ranges = sorted((int(start), int(end)) for start, end in segment_ranges if int(end) > int(start))
    ranges = [(start, end) for start, end in ranges if end > base_addr]
    if not ranges:
        return b""

    size = ranges[-1][1] - base_addr
    if size > SmdaConfig.MAX_IMAGE_SIZE:
        LOGGER.warning(
            "IDA: segment span 0x%x exceeds MAX_IMAGE_SIZE, truncating the mapped buffer",
            size,
        )
        size = SmdaConfig.MAX_IMAGE_SIZE

    buffer = bytearray(size)
    for start, end in ranges:
        # a segment straddling base_addr contributes only the part at or above it
        start = max(start, base_addr)
        offset = start - base_addr
        if offset >= size:
            continue
        chunk = read_bytes(start, min(end - start, size - offset))
        if not chunk:
            continue
        buffer[offset : offset + len(chunk)] = chunk
    return bytes(buffer)
