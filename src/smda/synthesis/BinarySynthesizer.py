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
        # a function with no blocks contributes no bytes to plant, and its extent is the max
        # of an empty sequence -- drop it here rather than raising further down
        resolved = sorted(
            offset for offset in offsets if offset in self.report.xcfg and self.report.xcfg[offset].blocks
        )
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

    def _resolveEntryPoint(self):
        """The report's entry point as an absolute address, or None when it has none.

        ``oep`` is stored absolute by some producers and relative to the report's own base by
        others; both forms reach us, so read it as relative only when the absolute reading
        would fall below the base.

        The result is unbounded, and every caller has to say so itself: _resolveFunctionOffsets
        caps how far apart the *functions* may sit, which is what keeps the RVAs derived from
        them inside a header field, but the entry point is not a function offset and that cap
        never sees it. A report may name one arbitrarily far from the image being rebuilt.
        """
        if not self.report.oep:
            return None
        base = self.report.base_addr
        return self.report.oep if self.report.oep >= base else base + self.report.oep

    @staticmethod
    def _fitsUnsigned(value, width_bits):
        """Whether ``value`` survives being packed into an unsigned field of that width."""
        return 0 <= value < (1 << width_bits)

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

    def _growSectionForOverflow(self, sections, section, block_end):
        """Extends an executable section's end towards block_end, stopping at the next section.

        Recovered code can run past the end of the section it starts in: a call at the tail of
        __text whose fall-through lands in the padding before __stubs is still part of the
        function, and the byte is still inside the mapped image, just not inside any section.
        Growth is capped at the following section's start, so it only ever claims address space
        no other section describes.
        """
        successors = [other["va_start"] for other in sections if other["va_start"] > section["va_start"]]
        limit = min(successors) if successors else block_end
        new_end = min(block_end, limit)
        if new_end <= section["va_end"]:
            return
        section["raw"].extend(self._nopFill(new_end - section["va_end"]))
        section["va_end"] = new_end

    def _plantFunctionChunks(self, sections, offsets):
        """Plants every block of every function into the executable sections covering it.

        Blocks are written per overlapping range rather than all-or-nothing: a block that runs
        one byte past its section would otherwise be dropped whole, taking the instructions that
        do fit with it.
        """
        ordered = sorted(sections, key=lambda section: section["va_start"])
        executable = [section for section in ordered if section["executable"] and section["raw"] is not None]
        for offset in offsets:
            for block_offset, chunk in self._iterFunctionChunks(self.report.xcfg[offset]):
                block_end = block_offset + len(chunk)
                for section in executable:
                    if section["va_start"] <= block_offset < section["va_end"] < block_end:
                        self._growSectionForOverflow(ordered, section, block_end)
                        break
                planted = 0
                for section in executable:
                    start = max(block_offset, section["va_start"])
                    end = min(block_end, section["va_end"])
                    if start >= end:
                        continue
                    section["raw"][start - section["va_start"] : end - section["va_start"]] = chunk[
                        start - block_offset : end - block_offset
                    ]
                    planted += end - start
                if planted < len(chunk):
                    self._warn(
                        "block 0x%x of function 0x%x: %d of %d bytes fit no executable section",
                        block_offset,
                        offset,
                        len(chunk) - planted,
                        len(chunk),
                    )

    def _nopPadding(self):
        return AARCH64_NOP if self.report.architecture == "aarch64" else INTEL_NOP

    def _nopFill(self, size):
        pattern = self._nopPadding()
        return (pattern * (size // len(pattern) + 1))[:size]

    def _getImportMap(self):
        metadata = self.report.xmetadata
        imports = metadata.get("imported_functions") if isinstance(metadata, dict) else None
        if not isinstance(imports, dict):
            return {}
        import_map = {}
        for key, value in imports.items():
            if not isinstance(value, (list, tuple)) or len(value) < 2 or not value[1]:
                continue
            try:
                import_map[int(str(key))] = (value[0] or "", value[1])
            except (TypeError, ValueError):
                continue
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
