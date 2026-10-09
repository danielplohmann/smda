#!/usr/bin/python

from functools import lru_cache

import demangle

from .ItaniumDemangler import demangle_itanium_symbol

_CXX_PREFIXES = ("__Z", "_Z")
_SWIFT_PREFIXES = ("_$s", "$s", "_$S", "$S")


def primeSwiftSymbols(names):
    """Kept for callers that batch a Mach-O's Swift names before the per-symbol lookups.

    Swift names used to be resolved through the host's `swift demangle`, a subprocess worth
    batching. They are now read in-process, so there is nothing left to batch, and a host
    without a Swift toolchain labels them all the same.
    """
    return None


@lru_cache(maxsize=4096)
def demangle_macho_symbol(name):
    """Best-effort demangling for Mach-O symbol names (C++ Itanium, Swift).

    C++ is spelled the way llvm-cxxfilt spells it and Swift the way `swift demangle` does,
    return type included. It returns the original name on failure.
    """
    if not name:
        return name
    if name.startswith(_CXX_PREFIXES):
        return demangle_itanium_symbol(name)
    if name.startswith(_SWIFT_PREFIXES):
        return demangle.demangle(name, language="swift")
    return name
