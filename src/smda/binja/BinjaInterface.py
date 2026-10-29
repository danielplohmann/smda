import re

from smda.export.BackendInterface import BackendInterface
from smda.export.segment_mapping import assembleSegmentBuffer

# sections Binary Ninja synthesizes for imports and compiler builtins; they hold no real code
_SYNTHETIC_SECTIONS = {".extern", ".synthetic_builtins"}
_IMPORT_SYMBOL_TYPES = {"ImportAddressSymbol", "ImportedFunctionSymbol"}
_DEFAULT_NAME = re.compile("(j_)?sub_[0-9a-fA-F]+$")
# little-endian only: smda.export.Exporter decodes 32-bit ARM with little-endian Capstone
_ARM_ARCHITECTURES = {"armv7", "thumb2"}


def _ownBlocks(function):
    # Binary Ninja keeps a T32 function's branch into an A32 PLT entry inside that function, but
    # SMDA decodes a function in one instruction set, so blocks in the other one are left out
    return [block for block in function.basic_blocks if block.arch == function.arch]


def _hasInvalidInstructions(function):
    return any(block.has_invalid_instructions for block in _ownBlocks(function))


class BinjaInterface(BackendInterface):
    """BackendInterface over a Binary Ninja BinaryView, for smda.export.Exporter."""

    def __init__(self, bv):
        super().__init__()
        self.bv = bv
        self._functions = None
        self._code_refs = None
        self._block_addresses = {}
        self._instruction_bytes = {}
        # an address can hold both an A32 and a T32 instruction; the Exporter reads a function's
        # instruction bytes right after its getBlocks, so they resolve in that function's architecture
        self._current_arch = None

    def getArchitecture(self):
        name = self.bv.arch.name
        if name in ("x86", "x86_64"):
            return "intel"
        if name == "aarch64":
            return "aarch64"
        if name in _ARM_ARCHITECTURES:
            return "arm"
        raise ValueError(f"Unsupported Architecture: {name}")

    def getBitness(self):
        return self.bv.arch.address_size * 8

    def _functionMap(self):
        if self._functions is None:
            functions = list(self.bv.functions)
            rejected = self._modeOverlapLosers(functions)
            self._functions = {}
            for index, function in enumerate(functions):
                if index not in rejected:
                    self._functions.setdefault(function.start, function)
        return self._functions

    def _modeOverlapLosers(self, functions):
        """Indices of functions left out so that no A32 and T32 function claim the same bytes, since
        SmdaReport keeps one instruction and one set of code refs per address. Functions are kept in
        order of evidence: no invalid instructions, more code references to the start, earlier start."""
        if len({function.arch for function in functions}) < 2:
            return set()
        spans = sorted(
            (
                (block.start, block.end, function.arch, index)
                for index, function in enumerate(functions)
                for block in _ownBlocks(function)
            ),
            key=lambda span: span[:2],
        )
        conflicts = set()
        active = []
        for start, end, arch, index in spans:
            active = [span for span in active if span[1] > start]
            conflicts.update((other, index) for _, _, other_arch, other in active if other_arch != arch)
            active.append((start, end, arch, index))

        def evidence(index):
            function = functions[index]
            references = len(list(self.bv.get_code_refs(function.start)))
            return (not _hasInvalidInstructions(function), references, -function.start, -index)

        rivals = {}
        for first, second in conflicts:
            rivals.setdefault(first, set()).add(second)
            rivals.setdefault(second, set()).add(first)
        kept, losers = set(), set()
        for index in sorted(rivals, key=evidence, reverse=True):
            if rivals[index] & kept:
                losers.add(index)
            else:
                kept.add(index)
        return losers

    def getFunctions(self):
        return sorted(self._functionMap())

    def _instructionAddresses(self, block):
        arch = block.arch
        key = (block.start, block.end, arch)
        addresses = self._block_addresses.get(key)
        if addresses is None:
            addresses = []
            data = self.bv.read(block.start, block.end - block.start)
            address = block.start
            while address < block.end:
                length = self.bv.get_instruction_length(address, arch)
                if not length:
                    break
                addresses.append(address)
                instruction = data[address - block.start : address - block.start + length]
                if len(instruction) == length:
                    self._instruction_bytes[(address, arch)] = instruction
                address += length
            self._block_addresses[key] = addresses
        return addresses

    def getBlocks(self, function_offset):
        function = self._functionMap().get(function_offset)
        self._current_arch = function.arch if function is not None else None
        if function is None:
            return []
        blocks = [self._instructionAddresses(block) for block in _ownBlocks(function)]
        return sorted(block for block in blocks if block)

    def getInstructionBytes(self, offset):
        cached = self._instruction_bytes.get((offset, self._current_arch))
        if cached is not None:
            return cached
        length = self.bv.get_instruction_length(offset, self._current_arch)
        return self.bv.read(offset, length) if length else b""

    def _codeRefs(self):
        if self._code_refs is None:
            self._code_refs = self._buildCodeRefs()
        return self._code_refs

    def _buildCodeRefs(self):
        # IDA's flow xrefs include fall-through; Binary Ninja's get_code_refs_from also returns data
        # refs, so edges come from block successors and call targets instead.
        refs_from = {}
        for function in self._functionMap().values():
            call_sites = {reference.address for reference in function.call_sites}
            for block in _ownBlocks(function):
                addresses = self._instructionAddresses(block)
                for index, address in enumerate(addresses):
                    targets = set()
                    if address in call_sites:
                        targets.update(self.bv.get_callees(address, func=function))
                    if index + 1 < len(addresses):
                        targets.add(addresses[index + 1])
                    else:
                        targets.update(edge.target.start for edge in block.outgoing_edges)
                    refs_from.setdefault(address, set()).update(targets)
        refs_to = {}
        for source, targets in refs_from.items():
            for target in targets:
                refs_to.setdefault(target, set()).add(source)
        return refs_from, refs_to

    def getCodeInRefs(self, offset):
        return [(source, offset) for source in sorted(self._codeRefs()[1].get(offset, ()))]

    def getCodeOutRefs(self, offset):
        return [(offset, target) for target in sorted(self._codeRefs()[0].get(offset, ()))]

    def _demangler(self):
        import binaryninja  # ty: ignore[unresolved-import]

        config = binaryninja.DemanglerConfig.for_binary_view(self.bv)
        return lambda raw_name: binaryninja.demangle_any(raw_name, config)

    def _functionName(self, function, demangler):
        if demangler is not None:
            result = demangler(function.symbol.raw_name)
            return str(result.name) if result else function.name
        return function.name

    def getFunctionSymbols(self, demangle=False):
        demangler = self._demangler() if demangle else None
        symbols = {}
        for function in self._functionMap().values():
            name = self._functionName(function, demangler)
            if name and not _DEFAULT_NAME.match(name):
                symbols[function.start] = name
        return symbols

    def _dataSegments(self):
        return sorted(
            (segment for segment in self.bv.segments if segment.data_length),
            key=lambda segment: segment.start,
        )

    def getBaseAddr(self):
        segments = self._dataSegments()
        if not segments:
            return 0
        return (segments[0].start // 0x10000) * 0x10000

    def getBinary(self):
        """Image mapped at getBaseAddr(), with gaps between segments zero-filled, capped at MAX_IMAGE_SIZE."""
        segments = self._dataSegments()
        backed = {segment.start: min(segment.data_length, segment.end - segment.start) for segment in segments}
        return assembleSegmentBuffer(
            self.getBaseAddr(),
            [(segment.start, segment.end) for segment in segments],
            lambda address, size: self.bv.read(address, min(size, backed.get(address, size))),
        )

    def getApiMap(self):
        api_map = {}
        for symbol in self.bv.get_symbols():
            if symbol.type.name not in _IMPORT_SYMBOL_TYPES:
                continue
            module = str(symbol.namespace) if symbol.namespace else ""
            name = symbol.raw_name
            if module and module != "BNINTERNALNAMESPACE":
                name = f"{module}!{name}"
            api_map[symbol.address] = name
        return api_map

    def isThumb(self, offset):
        function = self._functionMap().get(offset)
        return function is not None and function.arch.name == "thumb2"

    def _platformAt(self, offset, thumb=False):
        """(platform, address) of code at *offset*, T32 when *thumb* or the ARM interworking low bit is set."""
        if self.bv.arch.name not in _ARM_ARCHITECTURES:
            return None, offset
        return self.bv.platform.get_associated_platform_by_address(offset | 1 if thumb else offset)

    def getFilePath(self):
        return self.bv.file.filename or self.bv.file.original_filename

    def makeFunction(self, offset, thumb=False):
        # without a platform, Binary Ninja creates an A32 function even at an odd address
        platform, offset = self._platformAt(offset, thumb)
        if self.bv.get_function_at(offset, platform) is not None:
            return False
        self._functions = None
        self._code_refs = None
        self._block_addresses.clear()
        self._instruction_bytes.clear()
        return self.bv.create_user_function(offset, platform) is not None

    def makeName(self, offset, name):
        _, offset = self._platformAt(offset)
        function = self.bv.get_function_at(offset)
        if function is not None and not _DEFAULT_NAME.match(function.name):
            return False
        import binaryninja  # ty: ignore[unresolved-import]

        self.bv.define_user_symbol(binaryninja.Symbol("FunctionSymbol", offset, name))
        return True

    def isExternalFunction(self, function_offset):
        return any(section.name in _SYNTHETIC_SECTIONS for section in self.bv.get_sections_at(function_offset))
