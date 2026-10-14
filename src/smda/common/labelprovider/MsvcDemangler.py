"""Demangling for MSVC decorated symbol names."""

import re
from functools import lru_cache

import demangle

_STRING_LITERAL = re.compile(r"\?\?_C@_[01]([0-9]|[A-P]+@)[^@]*@([^@]*)@$")
_LITERAL_BYTE = re.compile(r"\?\$..|\?.|.", re.DOTALL)
# MSVC writes at most 32 bytes of a literal and records the full length beside them.
_LITERAL_BYTES_WRITTEN = 32
# A scope fragment opened by "?" is an unnamed namespace, a template, a nested symbol or a
# numbered local scope; an unnamed namespace carries no discriminator or a hexadecimal one.
_MALFORMED_SCOPE = re.compile(r"@\?(?![A$?]|[0-9]\?|[A-P]*@\?)|@\?A(?!@|0x[0-9a-fA-F]+@)")


def _decode_number(encoded):
    if encoded.isdigit():
        return int(encoded) + 1
    return int("".join("0123456789ABCDEF"[ord(char) - ord("A")] for char in encoded[:-1]), 16)


def _is_malformed(name):
    """Whether a name breaks a rule of the MSVC grammar that the library reads past."""
    literal = _STRING_LITERAL.match(name)
    if literal:
        declared = _decode_number(literal.group(1))
        written = len(_LITERAL_BYTE.findall(literal.group(2)))
        return written != declared and not _LITERAL_BYTES_WRITTEN <= written < declared
    if name.startswith(("??_C@", "??_R")):
        return False
    if name.startswith(("??B", "??$?B")) and not name.endswith("XZ"):
        return True
    return bool(_MALFORMED_SCOPE.search(name))


@lru_cache(maxsize=4096)
def demangle_msvc_symbol(name):
    """Return a readable C++ name, spelled the way llvm-undname spells it, or the original
    when it is not fully understood.

    A name carrying a control character is refused outright: a decorated name is read from a
    NUL-terminated string of source-legal characters and cannot hold one, and an expansion
    holding it would travel into the report as a symbol name. The identifier is copied into
    the answer verbatim, so testing the input is what keeps the answer clean.

    A name that breaks a rule of the grammar is refused even where the library, following
    llvm-undname, reads past it: a string literal whose recorded length disagrees with its
    bytes, a scope fragment that is none of the forms "?" opens, or a conversion operator
    taking parameters.

    The answer is also bounded by the size of the name that produced it: back-reference reuse
    can multiply a rendered type, and the library's own output bound is absolute rather than
    proportional.
    """
    if not name or not name.startswith("?"):
        return name
    if any(char < " " or char == "\x7f" for char in name):
        return name
    if _is_malformed(name):
        return name
    demangled = demangle.demangle(name, language="msvc")
    if len(demangled) > 8 * len(name) + 256:
        return name
    return demangled
