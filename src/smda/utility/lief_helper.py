"""Safe wrapper around lief.parse for untrusted input.

lief is a C++ library. A crafted header (e.g. a PE/ELF/DWARF header with a
huge section/segment count or offset) makes lief attempt an unbounded
allocation that raises ``std::bad_alloc`` from inside the native call. On the
Python side that surfaces as ``MemoryError`` and aborts the whole process.

The same class of input can also surface as ``ValueError``: which of the two a
malformed header produces depends on the lief build and version, so catching
only ``MemoryError`` leaves the gap open on whichever lief the consumer happens
to resolve.

SMDA's loaders are documented to *degrade* on hostile input, so we catch both
and return ``None`` exactly as we would for an unparseable file. Callers
already handle a ``None`` result by returning empty bytes / an empty list / a
fallback value.
"""

from __future__ import annotations

import lief


def lief_name(obj, attribute="name"):
    """Return a name lief exposes as text, or "" when it is not usable.

    lief hands back the raw ``bytes`` when a name is not valid UTF-8 instead of
    raising, so a ``UnicodeDecodeError`` guard alone leaves the caller holding a
    value that every string operation on it rejects. Mapped images reach this
    routinely: a PE's COFF symbol table is located by a file offset, so reading
    one out of a memory image lands on unrelated bytes.
    """
    try:
        value = getattr(obj, attribute)
    except (AttributeError, UnicodeDecodeError):
        return ""
    return value if isinstance(value, str) else ""


def safe_lief_parse(binary, parser=None):
    """Parse ``binary``, returning None when lief rejects it natively.

    ``parser`` selects a format-specific entry point (``lief.MachO.parse``,
    ``lief.DEX.parse``, ...) for callers that must keep the format container
    rather than lief's generic result; it defaults to ``lief.parse``.
    """
    if parser is None:
        parser = lief.parse
    try:
        return parser(binary)
    except (MemoryError, ValueError):
        return None
