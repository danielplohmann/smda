"""Rust symbol demangling, derived from Team bi0s' rust_demangler (MIT) with
behaviour reimplemented from Ghidra's Rust demanglers. See NOTICE.
"""

from .main import demangle

__all__ = ["demangle"]
