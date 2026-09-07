"""Shared validation for Rust-specific mangled-symbol evidence."""

import re

from .rust_demangler import demangle
from .rust_demangler.rust import TypeNotFoundError
from .rust_demangler.rust_legacy import UnableToLegacyDemangle
from .rust_demangler.rust_v0 import UnableTov0Demangle

RUST_DEMANGLE_ERRORS = (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle)
_LEGACY_RUST_HASHED_SYMBOL = re.compile(r"^(?:_)?_ZN.*17h[0-9a-f]{16}E(?:[.$].*)?$")


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
