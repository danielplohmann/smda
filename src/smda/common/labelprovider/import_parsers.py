"""Shared LIEF import-table parsers keyed by slot address."""

import lief

from smda.common.labelprovider.OrdinalHelper import OrdinalHelper
from smda.utility.lief_helper import lief_name


def resolve_pe_base_addr(lief_binary, base_addr=None):
    if base_addr is None:
        return getattr(lief_binary, "imagebase", 0)
    return base_addr


def parse_pe_imports(lief_binary, base_addr=None):
    if not hasattr(lief_binary, "imports"):
        return {}
    active_base = resolve_pe_base_addr(lief_binary, base_addr)
    import_symbols = {}
    for imported_library in lief_binary.imports:
        lib_name_lower = lief_name(imported_library).lower()
        for func in imported_library.entries:
            func_name = lief_name(func)
            if func_name:
                import_symbols[func.iat_address + active_base] = (
                    lib_name_lower,
                    func_name,
                )
            elif func.is_ordinal:
                resolved_ordinal = OrdinalHelper.resolveOrdinal(lib_name_lower, func.ordinal)
                ordinal_name = resolved_ordinal if resolved_ordinal else f"#{func.ordinal}"
                import_symbols[func.iat_address + active_base] = (
                    lib_name_lower,
                    ordinal_name,
                )
    return import_symbols


def parse_pe_delay_imports(lief_binary, base_addr=None):
    if not hasattr(lief_binary, "delay_imports"):
        return {}
    if not lief_binary.has_delay_imports:
        return {}
    active_base = resolve_pe_base_addr(lief_binary, base_addr)
    magic = getattr(lief_binary.optional_header, "magic", None)
    ptr_size = 8 if magic is not None and magic == lief.PE.PE_TYPE.PE32_PLUS else 4
    import_symbols = {}
    for delay_import in lief_binary.delay_imports:
        lib_name_lower = lief_name(delay_import).lower()
        for index, func in enumerate(delay_import.entries):
            slot_addr = active_base + delay_import.iat + index * ptr_size
            func_name = lief_name(func)
            if func_name:
                import_symbols[slot_addr] = (lib_name_lower, func_name)
            elif func.is_ordinal:
                resolved_ordinal = OrdinalHelper.resolveOrdinal(lib_name_lower, func.ordinal)
                ordinal_name = resolved_ordinal if resolved_ordinal else f"#{func.ordinal}"
                import_symbols[slot_addr] = (lib_name_lower, ordinal_name)
    return import_symbols


def parse_elf_relocation_imports(lief_binary):
    """Build import map keyed by relocation slot address: addr -> (lib, name).

    Names stay exactly as the dynamic symbol table spells them. API resolution is
    keyed by these names, so they must remain comparable with PE and Mach-O imports,
    which are equally undecorated. Demangling happens one level up, where the result
    is only used as a human-readable label.
    """
    if not isinstance(lief_binary, lief.ELF.Binary):
        return {}
    import_symbols = {}
    for relocation in lief_binary.relocations:
        if not relocation.has_symbol:
            continue
        symbol = relocation.symbol
        if symbol is None:
            continue
        if not symbol.imported or not symbol.is_function:
            continue
        symbol_name = lief_name(symbol)
        if not symbol_name:
            continue

        lib = None
        symbol_version = getattr(symbol, "symbol_version", None)
        if symbol.has_version and symbol_version and symbol_version.has_auxiliary_version:
            aux = symbol_version.symbol_version_auxiliary
            lib = lief_name(aux) or None

        import_symbols[relocation.address] = (lib, symbol_name)
    return import_symbols


def parse_macho_bindings(lief_binary, adjustment=0):
    if not isinstance(lief_binary, lief.MachO.Binary):
        return {}
    imports = {}
    for binding in getattr(lief_binary, "bindings", []):
        try:
            symbol_name = lief_name(binding.symbol) if getattr(binding, "has_symbol", False) else ""
            if binding.address != 0 and symbol_name:
                lib_name = ""
                if getattr(binding, "has_library", False) and binding.library:
                    lib_name = lief_name(binding.library).lower()
                adjusted_addr = binding.address + adjustment
                imports[adjusted_addr] = (lib_name, symbol_name)
        except Exception:
            continue
    return imports
