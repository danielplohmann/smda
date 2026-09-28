import re

from smda.export.BackendInterface import BackendInterface

# sections Binary Ninja synthesizes for imports and compiler builtins; they hold no real code
_SYNTHETIC_SECTIONS = {".extern", ".synthetic_builtins"}
_IMPORT_SYMBOL_TYPES = {"ImportAddressSymbol", "ImportedFunctionSymbol"}
_DEFAULT_NAME = re.compile("(j_)?sub_[0-9a-fA-F]+$")


class BinjaInterface(BackendInterface):
    """BackendInterface over a Binary Ninja BinaryView, for smda.export.Exporter."""

    def __init__(self, bv):
        super().__init__()
        self.bv = bv
        self._code_refs = None

    def getArchitecture(self):
        name = self.bv.arch.name
        if name in ("x86", "x86_64"):
            return "intel"
        if name == "aarch64":
            return "aarch64"
        raise ValueError(f"Unsupported Architecture: {name}")

    def getBitness(self):
        return self.bv.arch.address_size * 8

    def getFunctions(self):
        return sorted(function.start for function in self.bv.functions)

    def _instructionAddresses(self, block):
        addresses = []
        address = block.start
        for _tokens, length in block:
            addresses.append(address)
            address += length
        return addresses

    def getBlocks(self, function_offset):
        function = self.bv.get_function_at(function_offset)
        if function is None:
            return []
        blocks = [self._instructionAddresses(block) for block in function.basic_blocks]
        return sorted(block for block in blocks if block)

    def getInstructionBytes(self, offset):
        length = self.bv.get_instruction_length(offset)
        return self.bv.read(offset, length) if length else b""

    def _codeRefs(self):
        if self._code_refs is None:
            self._code_refs = self._buildCodeRefs()
        return self._code_refs

    def _buildCodeRefs(self):
        # IDA's flow xrefs include fall-through; Binary Ninja's get_code_refs_from also returns data
        # refs, so edges come from block successors and call targets instead.
        refs_from = {}
        for function in self.bv.functions:
            call_sites = {reference.address for reference in function.call_sites}
            for block in function.basic_blocks:
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
        for function in self.bv.functions:
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
        """Image mapped at getBaseAddr(), with gaps between segments zero-filled."""
        segments = self._dataSegments()
        if not segments:
            return b""
        base = self.getBaseAddr()
        image = bytearray(max(segment.end for segment in segments) - base)
        for segment in segments:
            data = self.bv.read(segment.start, min(segment.data_length, segment.end - segment.start))
            image[segment.start - base : segment.start - base + len(data)] = data
        return bytes(image)

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

    def getFilePath(self):
        return self.bv.file.filename or self.bv.file.original_filename

    def makeFunction(self, offset):
        if self.bv.get_function_at(offset) is not None:
            return False
        self._code_refs = None
        return self.bv.create_user_function(offset) is not None

    def makeName(self, offset, name):
        function = self.bv.get_function_at(offset)
        if function is not None and not _DEFAULT_NAME.match(function.name):
            return False
        import binaryninja  # ty: ignore[unresolved-import]

        self.bv.define_user_symbol(binaryninja.Symbol("FunctionSymbol", offset, name))
        return True

    def isExternalFunction(self, function_offset):
        return any(section.name in _SYNTHETIC_SECTIONS for section in self.bv.get_sections_at(function_offset))
