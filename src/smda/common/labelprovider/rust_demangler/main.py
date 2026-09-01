from typing import Dict, Union

from .rust import RustDemangler

_DEMANGLER = RustDemangler()
_DEMANGLE_CACHE: Dict[str, Union[str, Exception]] = {}
# the cache is process-lifetime and keyed by every mangled name ever seen; bound it so a
# long-running batch cannot grow it without limit (the sibling demanglers use
# lru_cache(maxsize=4096)). Results and exception objects are both cached, which lru_cache
# cannot express, so keep the dict and clear it wholesale when it fills.
_DEMANGLE_CACHE_MAX_SIZE = 4096


def _cacheResult(inp_str, value):
    if len(_DEMANGLE_CACHE) >= _DEMANGLE_CACHE_MAX_SIZE:
        _DEMANGLE_CACHE.clear()
    _DEMANGLE_CACHE[inp_str] = value


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
        _cacheResult(inp_str, res)
        return res
    except Exception as exc:
        from smda.common.ExceptionHandling import reraise_non_operational_exception

        reraise_non_operational_exception(exc)
        _cacheResult(inp_str, exc)
        raise exc
