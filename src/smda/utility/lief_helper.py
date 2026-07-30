"""Safe wrapper around lief.parse for untrusted input.

lief is a C++ library. A crafted header (e.g. a PE/ELF/DWARF header with a
huge section/segment count or offset) makes lief attempt an unbounded
allocation that raises ``std::bad_alloc`` from inside the native call. On the
Python side that surfaces as ``MemoryError`` and aborts the whole process.

SMDA's loaders are documented to *degrade* on hostile input, so we catch the
allocation failure and return ``None`` exactly as we would for an unparseable
file. Callers already handle a ``None`` result by returning empty bytes / an
empty list / a fallback value.
"""

from __future__ import annotations

import lief


def safe_lief_parse(binary, parser=None):
    """Parse ``binary``, returning None when lief fails to allocate.

    ``parser`` selects a format-specific entry point (``lief.MachO.parse``,
    ``lief.DEX.parse``, ...) for callers that must keep the format container
    rather than lief's generic result; it defaults to ``lief.parse``.
    """
    if parser is None:
        parser = lief.parse
    try:
        return parser(binary)
    except MemoryError:
        return None
