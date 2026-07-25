"""Demangling for C++ Itanium ABI symbol names."""

import re
from functools import lru_cache

import pycxxfilt

from .RustSymbolEvidence import is_rust_language_evidence

_ITANIUM_PREFIXES = ("__Z", "_Z")
_MSVC_CPP_DECORATED_NAME = re.compile(r"^\?[^@]+(?:@[^@]+)*@@.+Z$")


@lru_cache(maxsize=4096)
def demangle_itanium_symbol(name):
    """Return a readable C++ name using pycxxfilt's vendored LLVM demangler."""
    if not name or not name.startswith(_ITANIUM_PREFIXES):
        return name
    if is_rust_language_evidence(name):
        return name
    try:
        demangled = pycxxfilt.demangle(name)
    except ValueError:
        return name
    if demangled and demangled != name:
        return demangled
    return name


def is_itanium_cpp_symbol(name):
    """Return whether a name successfully decodes as an Itanium C++ symbol."""
    return bool(name and name.startswith(_ITANIUM_PREFIXES) and demangle_itanium_symbol(name) != name)


def is_msvc_cpp_symbol(name):
    """Recognize the documented C++ subset of MSVC decorated names.

    Plain C calling-convention decorations (for example ``_name@8``) are
    intentionally excluded because Microsoft documents those as C and
    ``extern \"C\"`` forms too.
    """
    return bool(name and _MSVC_CPP_DECORATED_NAME.match(name))
