FORMAT_PE = "pe"
FORMAT_ELF = "elf"
FORMAT_MACHO = "macho"

_THIN_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}


def sniffBinaryFormat(xheader):
    if not xheader:
        return None
    if xheader[:2] == b"MZ":
        return FORMAT_PE
    if xheader[:4] == b"\x7fELF":
        return FORMAT_ELF
    if xheader[:4] in _THIN_MACHO_MAGICS:
        return FORMAT_MACHO
    return None
