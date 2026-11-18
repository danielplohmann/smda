from .ItaniumDemangler import demangle_itanium_symbol
from .MsvcDemangler import demangle_msvc_symbol


def readable_name(name):
    """Expand a decorated symbol name of a PE or object file, whichever compiler decorated it.

    The MSVC arm keys on the leading "?" rather than on ItaniumDemangler's
    is_msvc_cpp_symbol, whose job is language detection rather than dispatch: it wants a
    class-qualified shape, so it turns away the global operator forms ("??2@YAPAXI@Z" and
    friends) that this demangler reads perfectly well - 9 of the 355 names it expands in the
    reference corpus. Letting the demangler itself decide costs nothing, because a name it
    cannot read comes back unchanged.
    """
    if name.startswith("?"):
        return demangle_msvc_symbol(name)
    return demangle_itanium_symbol(name)
