from .rust import RustDemangler

_DEMANGLER = RustDemangler()
_DEMANGLE_CACHE = {}


def demangle(inp_str: str) -> str:
    """Demangle a Rust mangled symbol name.

    Args:
        inp_str: The mangled symbol name to demangle.

    Returns:
        The demangled symbol name.

    Raises:
        TypeNotFoundError: If the symbol doesn't match known Rust mangling schemes.
        UnableTov0Demangle: If v0 demangling fails.
        UnableToLegacyDemangle: If legacy demangling fails.
    """
    if inp_str in _DEMANGLE_CACHE:
        val = _DEMANGLE_CACHE[inp_str]
        if isinstance(val, Exception):
            raise val
        return val

    try:
        res = _DEMANGLER.demangle(inp_str)
        _DEMANGLE_CACHE[inp_str] = res
        return res
    except Exception as exc:
        from smda.common.ExceptionHandling import reraise_non_operational_exception

        reraise_non_operational_exception(exc)
        _DEMANGLE_CACHE[inp_str] = exc
        raise exc
