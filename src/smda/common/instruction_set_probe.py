"""Recognize machine code SMDA has no backend for, in a buffer with no container header.

``disassembleBuffer`` defaults to intel, so a raw dump of any other instruction set is
decoded as x86 and comes back as a full report whose every block is wrong. There is no
header to read the instruction set from, so it is read from the code itself: each of these
architectures is fixed-width and spells its function return one way, which makes an aligned
count of that encoding separate them from x86 and from each other.

What separates them is **density, measured over a window**, not a total. A count over the
whole buffer says nothing, because a dump is mostly data: 21 aligned hits of the openrisc
return word turned up in a real stripped x86-64 shared object, where the byte pattern
"\x44\x00\x48\x00" is "DH" in a UTF-16LE index table. Sixty-four bytes of UTF-16 text
appended to a bundled x86 memory dump was enough to flip it the same way. Foreign code
returns every 332 to 1961 bytes across the ten bundled samples; the densest accidental hit
anywhere in the fixture and ground-truth corpora is one per 27920 bytes. Requiring
MIN_RETURN_SITES within a single WINDOW_BYTES span puts the bar at one per 4096: twice the
sparsest real sample's density, and a seventh of the densest accident's. Because the span
slides with the hits rather than sitting on a grid, it still finds a small code region inside
a large dump - which a whole-buffer density never could.

The bias is deliberately towards silence: a false positive turns a working x86 analysis into
an error, while a false negative only leaves today's behaviour in place.
"""

from collections import deque

# Measured as the densest window count over the ten bundled foreign samples against 60939
# ordinary files of every type on one filesystem: every signature scores 24 to 189 on its own
# architecture and zero on anything that is not that architecture, so one floor serves them
# all - but two of them only reach it because they were lengthened rather than re-thresholded.
#
# xtensa's plain two-byte "retw.n" scored 43 on its own sample against 31 in a Python .pyc,
# and refused real x86-64 shared objects; sh4's return-plus-delay-slot scored 142 against 108
# in the go compiler. Neither gap supports a threshold. Both now carry one more word of the
# sequence their own sample emits - 24 and 73 hits respectively, against zero in every file
# that used to trip them. That is derived from a single artifact each, so it is a narrower
# claim than the others: an image that does not use the idiom is missed, which is the
# direction this module is biased in anyway. sh4's byte-swapped form has no sample behind it
# at all and is carried only for symmetry.
MIN_RETURN_SITES = 16
RETURN_SIGNATURES = {
    "arm": ((b"\x1e\xff\x2f\xe1", b"\x0e\xf0\xa0\xe1", b"\xe1\x2f\xff\x1e", b"\xe1\xa0\xf0\x0e"), 4),
    "mips": ((b"\x03\xe0\x00\x08", b"\x08\x00\xe0\x03"), 4),
    "ppc": ((b"\x4e\x80\x00\x20", b"\x20\x00\x80\x4e"), 4),
    "sparc": ((b"\x81\xc3\xe0\x08", b"\x81\xc7\xe0\x08"), 4),
    "nios2": ((b"\x3a\x28\x00\xf8",), 4),
    "openrisc": ((b"\x44\x00\x48\x00",), 4),
    "sh4": ((b"\x0b\x00\x09\x00\x09\x00", b"\x00\x0b\x00\x09\x00\x09"), 2),
    "m68k": ((b"\x4e\x5e\x4e\x75",), 2),
    "xtensa": ((b"\x3d\xf0\x1d\xf0",), 2),
}

# the span that `required` return sites must fall inside: large enough to hold the sparsest
# sample's returns many times over, small enough that a code region inside a much larger dump
# still fills one. The span slides with the hits rather than sitting on a grid, so a code
# region never falls across a boundary and the buffer is read once per signature.
WINDOW_BYTES = 64 * 1024
# a buffer dense in a MISALIGNED copy of a signature can offer an occurrence at every
# position while none of them counts. The scan skips to the next aligned offset rather than
# the next byte, and this caps what one pattern will look at even so: reaching it means the
# buffer is denser in near-misses than any real code, and the answer stays silence.
MAX_PROBES = 1 << 20
# bytes either side of a hit that decide whether it sits in code or in text
NEIGHBOURHOOD_BYTES = 32
# share of a neighbourhood's 2-byte units that must read as UTF-16 to disqualify a hit
TEXT_UNIT_SHARE = 0.8


def looksLikeText(buffer, offset):
    """Whether the bytes around offset read as UTF-16 rather than as machine code.

    Density alone cannot separate the two. A UTF-16LE index table in a real x86-64 shared
    object put 21 aligned openrisc return words across 37 KB - the same one-per-1786-bytes
    the sparsest bundled foreign sample scores - so the probe refused a legitimate x86 dump.
    What does separate them is the company each hit keeps: over the ten bundled foreign
    samples not one hit sits in a neighbourhood like this, while every one of the 21 did.
    """
    start = max(0, offset - NEIGHBOURHOOD_BYTES)
    start -= start % 2  # a UTF-16 code unit begins on an even offset
    window = buffer[start : offset + NEIGHBOURHOOD_BYTES]
    units = len(window) // 2
    if units < 8:
        return False
    little = sum(1 for i in range(0, units * 2, 2) if window[i + 1] == 0 and 0x20 <= window[i] < 0x7F)
    big = sum(1 for i in range(0, units * 2, 2) if window[i] == 0 and 0x20 <= window[i + 1] < 0x7F)
    return max(little, big) >= units * TEXT_UNIT_SHARE


def countCodeReturnSites(buffer, pattern, alignment, limit):
    """Aligned occurrences of pattern across buffer that are not sitting inside text."""
    found = 0
    for _offset in _codeReturnSites(buffer, pattern, alignment):
        found += 1
        if found >= limit:
            break
    return found


def hasDenseReturnRun(buffer, pattern, alignment, required):
    """Whether `required` aligned, non-text occurrences of pattern fall within one window.

    The count that matters is local. A whole-buffer total says nothing about a dump, which is
    mostly data: what says "code" is `required` of them close enough together to be one region.
    """
    recent = deque(maxlen=required)
    for offset in _codeReturnSites(buffer, pattern, alignment):
        recent.append(offset)
        if len(recent) == required and offset - recent[0] < WINDOW_BYTES:
            return True
    return False


def _codeReturnSites(buffer, pattern, alignment):
    """Offsets of pattern in buffer that are aligned and not sitting inside text."""
    probes = 0
    index = 0
    end = len(buffer)
    while index < end:
        index = buffer.find(pattern, index, end)
        if index < 0:
            return
        probes += 1
        if probes > MAX_PROBES:
            return
        remainder = index % alignment
        if remainder:
            # a misaligned occurrence can never count, and neither can any position before
            # the next aligned one, so resume the search there instead of one byte on
            index += alignment - remainder
            continue
        if not looksLikeText(buffer, index):
            yield index
        index += alignment


def detectUnsupportedInstructionSet(buffer):
    """Name the unsupported instruction set a raw buffer holds, or None.

    Returns None for x86, AArch64 and anything else the counts cannot separate; a caller
    that already knows the instruction set should never consult this.
    """
    for name, (patterns, alignment) in RETURN_SIGNATURES.items():
        for pattern in patterns:
            if hasDenseReturnRun(buffer, pattern, alignment, MIN_RETURN_SITES):
                return name
    return None
