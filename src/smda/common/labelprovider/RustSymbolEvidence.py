"""Shared validation for Rust-specific mangled-symbol evidence."""

import re

from .rust_demangler import demangle
from .rust_demangler.rust import TypeNotFoundError
from .rust_demangler.rust_legacy import UnableToLegacyDemangle
from .rust_demangler.rust_v0 import UnableTov0Demangle

RUST_DEMANGLE_ERRORS = (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle)
_LEGACY_RUST_HASHED_SYMBOL = re.compile(r"^(?:_)?_ZN.*17h[0-9a-f]{16}E(?:[.$].*)?$")
_LEGACY_RUST_HASH_ONLY_SYMBOL = re.compile(r"^(?:_)?_ZN17h[0-9a-f]{16}E(?:[.$].*)?$")


def is_rust_language_evidence(name) -> bool:
    """Return whether a mangled name has Rust-specific, parseable structure."""
    if not name:
        return False
    if name.startswith(("_R", "__R")):
        try:
            demangle(name)
        except RUST_DEMANGLE_ERRORS:
            return False
        return True
    if not _LEGACY_RUST_HASHED_SYMBOL.match(name):
        return False
    try:
        demangle(name)
    except RUST_DEMANGLE_ERRORS:
        return False
    return True


def is_rust_hash_only_symbol(name) -> bool:
    """Return whether a name is a legacy Rust path holding nothing but its hash.

    Such a name spells nothing once the hash is dropped, so it is not Rust evidence, but it
    is not a C++ name either.
    """
    return bool(name and _LEGACY_RUST_HASH_ONLY_SYMBOL.match(name))
