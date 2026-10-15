"""Experimental binary synthesis: rebuild fictive unmapped files from an SmdaReport.

Dispatches to per-format synthesizers (PE, ELF, Mach-O) that plant the recovered
function bytes at their original virtual addresses and rebuild headers, sections,
and import metadata so the output parses cleanly with analysis tools.
"""

from smda.common.BinaryFormat import FORMAT_ELF, FORMAT_MACHO, FORMAT_PE, sniffBinaryFormat
from smda.synthesis.BinarySynthesizer import BinarySynthesizer

_FORMAT_ALIASES = {
    "pe": FORMAT_PE,
    "pe32": FORMAT_PE,
    "elf": FORMAT_ELF,
    "macho": FORMAT_MACHO,
    "mach-o": FORMAT_MACHO,
    "mach_o": FORMAT_MACHO,
}


def createSynthesizer(report, output_format=None) -> BinarySynthesizer:
    output_format = (output_format or "").lower() or sniffBinaryFormat(report.xheader)
    output_format = _FORMAT_ALIASES.get(output_format, output_format)
    if output_format == FORMAT_PE:
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        return PeSynthesizer(report)
    if output_format == FORMAT_ELF:
        from smda.synthesis.ElfSynthesizer import ElfSynthesizer

        return ElfSynthesizer(report)
    if output_format == FORMAT_MACHO:
        from smda.synthesis.MachoSynthesizer import MachoSynthesizer

        return MachoSynthesizer(report)
    raise ValueError(
        f"Cannot determine synthesis target format from {output_format or 'report'}; "
        f"pass output_format explicitly ({FORMAT_PE}, {FORMAT_ELF}, {FORMAT_MACHO})"
    )
