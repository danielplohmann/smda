"""Demangling for C++ Itanium ABI symbol names."""

import re
from functools import lru_cache

import demangle

from .RustSymbolEvidence import is_rust_hash_only_symbol, is_rust_language_evidence

_ITANIUM_PREFIXES = ("__Z", "_Z")
_MSVC_CPP_DECORATED_FUNCTION = re.compile(r"^\?[^@]+(?:@[^@]+)*@@.+Z$")
# Decorated data: the type code after "@@" is a digit, e.g. "?value@@3HA" (static int).
_MSVC_CPP_DECORATED_DATA = re.compile(r"^\?[^@]+(?:@[^@]+)*@@[0-9].+$")


@lru_cache(maxsize=4096)
def demangle_itanium_symbol(name):
    """Return a readable C++ name, spelled the way llvm-cxxfilt spells it.

    The scheme is forced rather than detected: a legacy Rust name shares the _ZN prefix,
    and is turned away here so that RustSymbolProvider can claim it.
    """
    if not name or not name.startswith(_ITANIUM_PREFIXES):
        return name
    if is_rust_language_evidence(name) or is_rust_hash_only_symbol(name):
        return name
    return demangle.demangle(name, language="itanium")


def is_itanium_cpp_symbol(name):
    """Return whether a name successfully decodes as an Itanium C++ symbol."""
    return bool(name and name.startswith(_ITANIUM_PREFIXES) and demangle_itanium_symbol(name) != name)


def is_msvc_cpp_symbol(name):
    """Recognize the documented C++ subset of MSVC decorated names.

    Covers both decorated functions and decorated data (class statics, globals in a
    namespace), since a C++ binary may export only the latter. Plain C
    calling-convention decorations (for example ``_name@8``) are intentionally
    excluded because Microsoft documents those as C and ``extern \"C\"`` forms too.
    """
    if not name:
        return False
    return bool(_MSVC_CPP_DECORATED_FUNCTION.match(name) or _MSVC_CPP_DECORATED_DATA.match(name))
