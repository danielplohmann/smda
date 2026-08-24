"""Fuzz tests for the MSVC symbol demangler using Hypothesis.

The demangler accepts arbitrary strings and must:
  - never raise, whatever the input
  - never hang (unbounded recursion, runaway loops)
  - either expand a name or hand it back unchanged, never a third spelling
"""

from hypothesis import given, settings
from hypothesis.strategies import lists, sampled_from, text

from smda.common.labelprovider.MsvcDemangler import demangle_msvc_symbol

# the alphabet a decorated name is actually built from, so the fuzzer spends its budget
# inside the grammar rather than rejecting on the first character
_MANGLING_ALPHABET = list("?@$_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _assertAnswered(name, result):
    """Every property the module docstring promises, checked on one answer."""
    assert isinstance(result, str)
    if result == name:
        return
    # an expansion is a readable C++ spelling: no control characters, and in particular
    # never the declarator placeholder the renderer uses internally
    assert result.isprintable(), result
    # back-reference reuse can multiply a rendered type, so the result stays bounded by the
    # size of the name that produced it
    assert len(result) <= 8 * len(name) + 256, (len(name), len(result))


@given(s=text(max_size=256))
@settings(max_examples=500, deadline=None)
def test_arbitrary_text_is_answered(s):
    result = demangle_msvc_symbol(s)

    _assertAnswered(s, result)
    if not s.startswith("?"):
        assert result == s


@given(pieces=lists(sampled_from(_MANGLING_ALPHABET), min_size=1, max_size=64))
@settings(max_examples=500, deadline=None)
def test_decoration_shaped_input_is_answered(pieces):
    name = "?" + "".join(pieces)

    _assertAnswered(name, demangle_msvc_symbol(name))


@given(pieces=lists(sampled_from(_MANGLING_ALPHABET), min_size=1, max_size=64))
@settings(max_examples=500, deadline=None)
def test_every_prefix_of_a_generated_name_is_answered(pieces):
    name = "?" + "".join(pieces)

    for end in range(len(name) + 1):
        prefix = name[:end]
        _assertAnswered(prefix, demangle_msvc_symbol(prefix))
