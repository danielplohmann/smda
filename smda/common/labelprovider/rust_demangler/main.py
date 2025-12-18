from .rust import RustDemangler


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
    demangler = RustDemangler()
    return demangler.demangle(inp_str)
