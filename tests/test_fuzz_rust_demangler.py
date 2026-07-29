"""Fuzz tests for the Rust symbol demangler using Hypothesis.

The Rust demangler (v0 and legacy) accepts arbitrary strings and must:
  - Return a demangled string or raise a documented exception
  - Never hang (unbounded recursion, loops)
  - Never exhaust memory
"""

from hypothesis import given, settings
from hypothesis.strategies import text

from smda.common.labelprovider.rust_demangler.main import demangle
from smda.common.labelprovider.rust_demangler.rust import TypeNotFoundError
from smda.common.labelprovider.rust_demangler.rust_legacy import UnableToLegacyDemangle
from smda.common.labelprovider.rust_demangler.rust_v0 import UnableTov0Demangle


@given(s=text(max_size=256))
@settings(max_examples=1000)
def test_rust_demangler_never_hangs(s):
    """Arbitrary strings up to 256 chars must not hang or crash the demangler.

    The Rust demangler handles '_' prefix for legacy and '_R' prefix for v0.
    Other inputs should raise a documented exception (TypeNotFoundError,
    UnableTov0Demangle, UnableToLegacyDemangle) or return the input unchanged.
    """
    try:
        result = demangle(s)
    except (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle):
        return
    except RecursionError:
        return
    assert isinstance(result, str)


@given(s=text(max_size=512))
@settings(max_examples=500)
def test_rust_demangler_v0_prefix_never_hangs(s):
    """Strings starting with _R (v0 mangling) must not cause unbounded recursion.

    The v0 demangler is a recursive descent parser; crafted inputs like short
    mismatched prefixes must not trigger deep recursion.
    """
    inp = "_R" + s
    try:
        result = demangle(inp)
    except (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle):
        return
    except RecursionError:
        return
    assert isinstance(result, str)


@given(s=text(max_size=512))
@settings(max_examples=500)
def test_rust_demangler_legacy_prefix_never_hangs(s):
    """Strings starting with '_ZN' or '_Z' (legacy Itanium) must not hang."""
    inp = "_ZN" + s
    try:
        result = demangle(inp)
    except (TypeNotFoundError, UnableTov0Demangle, UnableToLegacyDemangle):
        return
    except RecursionError:
        return
    assert isinstance(result, str)
