import logging

from smda.SmdaConfig import SmdaConfig

LOGGER = logging.getLogger(__name__)

AARCH64_NOP = bytes.fromhex("1f2003d5")
INTEL_NOP = b"\x90"


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def align_down(value, alignment):
    return value // alignment * alignment


class BinarySynthesizer:
    """Base class for per-format binary synthesizers.

    A synthesizer rebuilds a fictive unmapped binary file from a SmdaReport:
    recovered function bytes are planted at their original virtual addresses,
    referenced strings are written back at their data addresses, and import
    metadata from xmetadata is fused back into a loadable import structure.
    """

    def __init__(self, report):
        self.report = report
        self.warnings = []

    def synthesize(self, function_offsets=None, with_imports=True, with_strings=True) -> bytes:
        raise NotImplementedError

    def _warn(self, message, *args):
        rendered = message % args if args else message
        self.warnings.append(rendered)
        LOGGER.warning(rendered)

    def _resolveFunctionOffsets(self, function_offsets):
        offsets = sorted(self.report.xcfg.keys()) if function_offsets is None else list(function_offsets)
        resolved = sorted(offset for offset in offsets if offset in self.report.xcfg)
        skipped = len(offsets) - len(resolved)
        if skipped:
            self._warn("synthesis: %d requested function offsets are not in the report", skipped)
        if resolved:
            span = max(self._functionExtentEnd(self.report.xcfg[offset]) for offset in resolved) - resolved[0]
            if span > SmdaConfig.MAX_IMAGE_SIZE:
                raise ValueError(
                    f"synthesized image span of 0x{span:x} bytes exceeds MAX_IMAGE_SIZE; "
                    "the report's function offsets are too far apart to rebuild"
                )
        return resolved

    @staticmethod
    def _iterFunctionChunks(smda_function):
        """Yields (block_offset, block_bytes) per basic block.

        Planting must happen per block: blocks of one function are not necessarily
        contiguous, and the gaps between them can hold other functions' bytes."""
        for block_offset in sorted(smda_function.blocks.keys()):
            instructions = smda_function.blocks[block_offset]
            yield block_offset, b"".join(bytes.fromhex(instruction.bytes) for instruction in instructions)

    def _functionExtentEnd(self, smda_function):
        return max(offset + len(chunk) for offset, chunk in self._iterFunctionChunks(smda_function))

    def _syntheticSpan(self, offsets, start_alignment, end_alignment=16):
        """Page-aligned [start, end) guaranteed to cover every offset in ``offsets``.

        The floor rounds an offset down and the ceiling rounds an extent end up, and the
        two are independent: a report whose blocks sit below their own function offset
        yields an extent end under the floor and an inverted span, which reaches
        struct.pack as a negative size.
        """
        va_start = align_down(min(offsets), start_alignment)
        extent_end = max(self._functionExtentEnd(self.report.xcfg[offset]) for offset in offsets)
        return va_start, align_up(max(extent_end, max(offsets) + 1), end_alignment)

    def _nopPadding(self):
        return AARCH64_NOP if self.report.architecture == "aarch64" else INTEL_NOP

    def _nopFill(self, size):
        pattern = self._nopPadding()
        return (pattern * (size // len(pattern) + 1))[:size]

    def _getImportMap(self):
        imports = (self.report.xmetadata or {}).get("imported_functions") or {}
        import_map = {}
        for key, value in imports.items():
            if not value or len(value) < 2 or not value[1]:
                continue
            import_map[int(str(key))] = (value[0] or "", value[1])
        return import_map

    def _iterStringRefs(self):
        for smda_function in self.report.getFunctions():
            for stringref in smda_function.stringrefs or []:
                data_addr = stringref.get("data_addr")
                string = stringref.get("string")
                if data_addr is None or not string:
                    continue
                yield data_addr, string.encode("ascii", errors="ignore") + b"\x00"

    def _hasHeader(self, min_length=0x40):
        return bool(self.report.xheader) and len(self.report.xheader) >= min_length
