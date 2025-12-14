from .rust import RustDemangler

_demangler = RustDemangler()


def demangle(inp_str: str):
    return _demangler.demangle(inp_str)
