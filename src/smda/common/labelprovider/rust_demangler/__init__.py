"""Rust symbol demangling (legacy and v0) through the demangle library, spelled the way
rustc-demangle's alternate form spells a name: without the disambiguating hash.
"""

from .main import demangle

__all__ = ["demangle"]
