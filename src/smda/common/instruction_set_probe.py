"""Recognize machine code SMDA has no backend for, in a buffer with no container header.

``disassembleBuffer`` defaults to intel, so a raw dump of any other instruction set is
decoded as x86 and comes back as a full report whose every block is wrong. There is no
header to read the instruction set from, so it is read from the code itself: each of these
architectures is fixed-width and spells its function return one way, which makes an aligned
count of that encoding separate them from x86 and from each other.

Counts over the bundled fixtures plus a locally built x86-64/x86 corpus (72 images): every
signature below scores at least 31 on its own architecture, and at most 3 on any other
image in the set. The threshold sits between those, biased hard towards silence - a false
positive turns a working x86 analysis into an error, while a false negative only leaves
today's behaviour in place.
"""

MIN_RETURN_SITES = 16
MAX_BYTES_PER_RETURN_SITE = 64 * 1024

RETURN_SIGNATURES = {
    "arm": ((b"\x1e\xff\x2f\xe1", b"\x0e\xf0\xa0\xe1", b"\xe1\x2f\xff\x1e", b"\xe1\xa0\xf0\x0e"), 4),
    "mips": ((b"\x03\xe0\x00\x08", b"\x08\x00\xe0\x03"), 4),
    "ppc": ((b"\x4e\x80\x00\x20", b"\x20\x00\x80\x4e"), 4),
    "sparc": ((b"\x81\xc3\xe0\x08", b"\x81\xc7\xe0\x08"), 4),
    "nios2": ((b"\x3a\x28\x00\xf8",), 4),
    "openrisc": ((b"\x44\x00\x48\x00",), 4),
    "sh4": ((b"\x0b\x00\x09\x00", b"\x00\x0b\x00\x09"), 2),
    "m68k": ((b"\x4e\x5e\x4e\x75",), 2),
    "xtensa": ((b"\x1d\xf0",), 2),
}


def countAlignedOccurrences(buffer, pattern, alignment, limit=None):
    """How many times pattern occurs in buffer at a multiple of alignment.

    Counting stops once limit is reached, because the caller only ever asks whether a
    count clears a threshold. Without it a buffer that is dense in one pattern costs an
    iteration per occurrence, which is 25 million of them for a 100 MB image.
    """
    found = 0
    index = buffer.find(pattern)
    while index >= 0:
        if index % alignment == 0:
            found += 1
            if limit is not None and found >= limit:
                break
        index = buffer.find(pattern, index + 1)
    return found


def detectUnsupportedInstructionSet(buffer):
    """Name the unsupported instruction set a raw buffer holds, or None.

    Returns None for x86, AArch64 and anything else the counts cannot separate; a caller
    that already knows the instruction set should never consult this.
    """
    required = max(MIN_RETURN_SITES, -(-len(buffer) // MAX_BYTES_PER_RETURN_SITE))
    for name, (patterns, alignment) in RETURN_SIGNATURES.items():
        found = 0
        for pattern in patterns:
            found += countAlignedOccurrences(buffer, pattern, alignment, limit=required - found)
            if found >= required:
                return name
    return None
