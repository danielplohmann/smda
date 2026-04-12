import contextlib
import datetime
import logging
import struct

import lief

from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState
from smda.dalvik.DalvikOpcodeDecoder import (
    decode_instruction,
    parse_code_item_header,
    read_sleb128,
    read_uleb128,
)
from smda.DisassemblyResult import DisassemblyResult
from smda.utility.DexFileLoader import DexFileLoader

LOGGER = logging.getLogger(__name__)


class DexReferenceResolver:
    PRIMITIVE_TYPES = {
        "VOID_T": "V",
        "VOID": "V",
        "BOOLEAN": "Z",
        "BYTE": "B",
        "SHORT": "S",
        "CHAR": "C",
        "INT": "I",
        "LONG": "J",
        "FLOAT": "F",
        "DOUBLE": "D",
    }
    STRING_PRIMITIVE_TYPES = {
        "void": "V",
        "boolean": "Z",
        "byte": "B",
        "short": "S",
        "char": "C",
        "int": "I",
        "long": "J",
        "float": "F",
        "double": "D",
    }
    ACCESS_FLAG_NAMES = [
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0020, "synchronized"),
        (0x0040, "bridge"),
        (0x0080, "varargs"),
        (0x0100, "native"),
        (0x0200, "interface"),
        (0x0400, "abstract"),
        (0x0800, "strict"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
        (0x8000, "unused"),
        (0x10000, "constructor"),
        (0x20000, "declared-synchronized"),
    ]

    def __init__(self, dex_file):
        self.dex_file = dex_file
        self.strings = list(getattr(dex_file, "strings", []))
        self.methods = self._index_items(getattr(dex_file, "methods", []))
        self.fields = self._index_items(getattr(dex_file, "fields", []))
        self.types = self._index_items(getattr(dex_file, "types", []))
        self.prototypes = self._index_items(getattr(dex_file, "prototypes", []))
        self.classes = self._index_items(getattr(dex_file, "classes", []))

    def _index_items(self, items):
        indexed = {}
        for index, item in enumerate(items):
            indexed[getattr(item, "index", index)] = item
        return indexed

    def _safe_get(self, collection, index):
        if index in collection:
            return collection[index]
        return None

    def _safe_attr(self, obj, attr, default=None):
        try:
            return getattr(obj, attr)
        except Exception:
            return default

    def _normalize_type_string(self, type_name):
        if not type_name:
            return None
        if type_name in {"V", "Z", "B", "S", "C", "I", "J", "F", "D"}:
            return type_name
        if type_name.startswith("[") or (type_name.startswith("L") and type_name.endswith(";")):
            return type_name
        lowered = type_name.lower()
        if lowered in self.STRING_PRIMITIVE_TYPES:
            return self.STRING_PRIMITIVE_TYPES[lowered]
        if "." in type_name and "/" not in type_name:
            return f"L{type_name.replace('.', '/')};"
        return type_name

    def _format_type(self, type_obj):
        if type_obj is None:
            return "<?>"
        if isinstance(type_obj, str):
            return self._normalize_type_string(type_obj)
        fullname = self._safe_attr(type_obj, "fullname", None)
        if fullname:
            return self._normalize_type_string(fullname)
        value = self._safe_attr(type_obj, "value", None)
        if value is not None:
            fullname = self._safe_attr(value, "fullname", None)
            if fullname:
                return self._normalize_type_string(fullname)
            primitive_name = self.PRIMITIVE_TYPES.get(self._safe_attr(value, "name", ""), None)
            if primitive_name:
                return primitive_name
            name = self._safe_attr(value, "name", None)
            if name:
                return self._normalize_type_string(name)
            with contextlib.suppress(Exception):
                normalized = self._normalize_type_string(str(value))
                if normalized and not normalized.startswith("<lief."):
                    return normalized
        name = self._safe_attr(type_obj, "name", None)
        if name:
            return self._normalize_type_string(name)
        with contextlib.suppress(Exception):
            type_as_string = self._normalize_type_string(str(type_obj))
            if type_as_string and not type_as_string.startswith("<lief.") and " - " not in type_as_string:
                return type_as_string
        with contextlib.suppress(Exception):
            return repr(type_obj)
        return "<?>"

    def _format_proto(self, prototype):
        if prototype is None:
            return "()<?>"
        params = []
        for param in getattr(prototype, "parameters_type", []):
            params.append(self._format_type(param))
        return_type = self._format_type(getattr(prototype, "return_type", None))
        return f"({''.join(params)}){return_type}"

    def format_method(self, method):
        if method is None:
            return "method@<?>"
        class_name = self._format_type(getattr(method, "cls", None))
        method_name = getattr(method, "name", "<?>")
        prototype = self._format_proto(getattr(method, "prototype", None))
        return f"{class_name}->{method_name}{prototype}"

    def format_field(self, field):
        if field is None:
            return "field@<?>"
        class_name = self._format_type(getattr(field, "cls", None))
        field_name = getattr(field, "name", "<?>")
        field_type = self._format_type(getattr(field, "type", None))
        return f"{class_name}->{field_name}:{field_type}"

    def format_proto(self, index):
        prototype = self._safe_get(self.prototypes, index)
        if prototype is None:
            return f"proto@{index}"
        return self._format_proto(prototype)

    def format_type_by_index(self, index):
        type_obj = self._safe_get(self.types, index)
        if type_obj is None:
            return f"type@{index}"
        return self._format_type(type_obj)

    def format_ref(self, ref_kind, index):
        if ref_kind == "string":
            if 0 <= index < len(self.strings):
                return '"' + self.strings[index].replace('"', '\\"') + '"'
            return f"string@{index}"
        if ref_kind == "type":
            return self.format_type_by_index(index)
        if ref_kind == "field":
            return self.format_field(self._safe_get(self.fields, index))
        if ref_kind == "method":
            return self.format_method(self._safe_get(self.methods, index))
        if ref_kind == "proto":
            return self.format_proto(index)
        if ref_kind == "method_handle":
            return f"method_handle@{index}"
        if ref_kind == "call_site":
            return f"call_site@{index}"
        return f"{ref_kind}@{index}" if ref_kind else f"item@{index}"

    def get_method(self, method_index):
        return self._safe_get(self.methods, method_index)

    def get_method_target(self, method_index):
        method = self.get_method(method_index)
        if method is None:
            return None, None
        code_offset = getattr(method, "code_offset", 0)
        code_info = getattr(method, "code_info", None)
        if code_offset and code_info:
            return code_offset, self.format_method(method)
        return None, self.format_method(method)

    def get_string_value(self, string_index):
        if 0 <= string_index < len(self.strings):
            return self.strings[string_index]
        return None

    def get_method_metadata(self, method):
        access_flags = getattr(method, "access_flags", 0)
        access_flags = getattr(access_flags, "value", access_flags)
        if isinstance(access_flags, (list, tuple, set)):
            normalized_flags = 0
            for flag in access_flags:
                normalized_flags |= getattr(flag, "value", 0)
            access_flags = normalized_flags
        access_flag_names = [name for mask, name in self.ACCESS_FLAG_NAMES if access_flags & mask]
        method_name = self.format_method(method)
        return {
            "method_name": method_name,
            "class_name": self._format_type(getattr(method, "cls", None)),
            "prototype": self._format_proto(getattr(method, "prototype", None)),
            "access_flags": access_flags,
            "access_flags_decoded": access_flag_names,
        }


class DalvikDisassembler:
    MAX_SWITCH_TARGETS_FOR_HEURISTIC = 32

    def __init__(self, config):
        self.config = config
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION

    def addPdbFile(self, binary_info, pdb_path):
        return

    def _formatReferenceCounts(self, reference_counts):
        active_counts = [f"{ref_kind}={count}" for ref_kind, count in reference_counts.items() if count]
        return ", ".join(active_counts) if active_counts else "none"

    def _summarizeHeuristics(self):
        heuristic_counts = {}
        for metadata in self.disassembly.function_metadata.values():
            for heuristic in metadata.get("heuristics", []):
                heuristic_counts[heuristic] = heuristic_counts.get(heuristic, 0) + 1
        if not heuristic_counts:
            return "none"
        return ", ".join(f"{name}={heuristic_counts[name]}" for name in sorted(heuristic_counts))

    def _logMethodDiagnostics(self, state):
        metadata = state.metadata
        outref_count = len(self.disassembly.getOutRefs(state.start_addr))
        string_ref_count = len(self.disassembly.getStringRefsForFunction(state.start_addr))
        heuristics = ", ".join(metadata["heuristics"]) if metadata["heuristics"] else "none"
        LOGGER.debug(
            "Analyzed Dalvik method 0x%08x %s: ins=%d blocks=%d outrefs=%d handlers=%d strings=%d refs=[%s] heuristics=[%s]",
            state.start_addr,
            state.label,
            len(state.instructions),
            len(self.disassembly.functions.get(state.start_addr, [])),
            outref_count,
            metadata.get("exception_handler_count", 0),
            string_ref_count,
            self._formatReferenceCounts(metadata["reference_counts"]),
            heuristics,
        )

    def _logAnalysisSummary(self, version, method_counts, analyzed_count):
        total_blocks = sum(len(blocks) for blocks in self.disassembly.functions.values())
        total_strings = sum(len(stringrefs) for stringrefs in self.disassembly.stringrefs.values())
        try_functions = sum(
            1 for metadata in self.disassembly.function_metadata.values() if metadata.get("exception_handler_count", 0)
        )
        LOGGER.debug(
            "Dalvik analysis summary: version=%s analyzed=%d/%d functions=%d blocks=%d instructions=%d "
            "api_refs=%d string_refs=%d try_functions=%d failed=%d skipped(no_class=%d,no_code=%d,invalid_offset=%d) "
            "heuristics=[%s]",
            version,
            analyzed_count,
            method_counts["total"],
            len(self.disassembly.functions),
            total_blocks,
            len(self.disassembly.instructions),
            len(self.disassembly.addr_to_api),
            total_strings,
            try_functions,
            len(self.disassembly.failed_analysis_addr),
            method_counts["skipped_no_class"],
            method_counts["skipped_no_code"],
            method_counts["skipped_invalid_offset"],
            self._summarizeHeuristics(),
        )

    def _getPayloadSize(self, bytecode, idx):
        if idx < 0 or idx + 2 > len(bytecode):
            return 0
        ident = struct.unpack_from("<H", bytecode, idx)[0]
        if ident == 0x0100:
            if idx + 8 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            return 8 + size * 4
        if ident == 0x0200:
            if idx + 4 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            return 4 + size * 8
        if ident == 0x0300:
            if idx + 8 > len(bytecode):
                return 0
            element_width = struct.unpack_from("<H", bytecode, idx + 2)[0]
            size = struct.unpack_from("<I", bytecode, idx + 4)[0]
            data_size = size * element_width
            if data_size % 2:
                data_size += 1
            return 8 + data_size
        return 0

    def _resolveSwitchTargets(self, bytecode, switch_insn_idx, payload_idx):
        if payload_idx < 0 or payload_idx + 4 > len(bytecode):
            return []
        ident = struct.unpack_from("<H", bytecode, payload_idx)[0]
        size = struct.unpack_from("<H", bytecode, payload_idx + 2)[0]
        targets = []
        if ident == 0x0100:
            targets_start = payload_idx + 8
            for index in range(size):
                off = targets_start + index * 4
                if off + 4 > len(bytecode):
                    break
                rel_offset = struct.unpack_from("<i", bytecode, off)[0]
                targets.append(switch_insn_idx + rel_offset * 2)
        elif ident == 0x0200:
            targets_start = payload_idx + 4 + size * 4
            for index in range(size):
                off = targets_start + index * 4
                if off + 4 > len(bytecode):
                    break
                rel_offset = struct.unpack_from("<i", bytecode, off)[0]
                targets.append(switch_insn_idx + rel_offset * 2)
        return targets

    def _resolveReference(self, resolver, ref_kind, ref_index):
        return resolver.format_ref(ref_kind, ref_index)

    def _parseTryBlocks(self, raw_data, resolver, bytecode_offset, insns_size_units, tries_size):
        if tries_size == 0:
            return []
        tries_offset = bytecode_offset + insns_size_units * 2
        if insns_size_units % 2:
            tries_offset += 2
        if tries_offset + tries_size * 8 > len(raw_data):
            raise ValueError("Invalid try_item table")
        handlers_offset = tries_offset + tries_size * 8
        encoded_handler_count, cursor = read_uleb128(raw_data, handlers_offset)
        handlers_by_offset = {}
        for _ in range(encoded_handler_count):
            handler_relative = cursor - handlers_offset
            encoded_size, cursor = read_sleb128(raw_data, cursor)
            catch_all_addr = None
            handlers = []
            for _ in range(abs(encoded_size)):
                type_idx, cursor = read_uleb128(raw_data, cursor)
                addr, cursor = read_uleb128(raw_data, cursor)
                handlers.append({"type_idx": type_idx, "addr_units": addr})
            if encoded_size <= 0:
                catch_all_addr, cursor = read_uleb128(raw_data, cursor)
            handlers_by_offset[handler_relative] = {
                "handlers": handlers,
                "catch_all_addr": catch_all_addr,
            }

        try_items = []
        for index in range(tries_size):
            start_addr_units, insn_count_units, handler_off = struct.unpack_from(
                "<IHH",
                raw_data,
                tries_offset + index * 8,
            )
            resolved = handlers_by_offset.get(handler_off, {"handlers": [], "catch_all_addr": None})
            try_items.append(
                {
                    "start_addr": bytecode_offset + start_addr_units * 2,
                    "end_addr": bytecode_offset + (start_addr_units + insn_count_units) * 2,
                    "handlers": [
                        {
                            "type_idx": handler["type_idx"],
                            "type_name": resolver.format_type_by_index(handler["type_idx"]),
                            "target_addr": bytecode_offset + handler["addr_units"] * 2,
                        }
                        for handler in resolved["handlers"]
                    ],
                    "catch_all_addr": (
                        bytecode_offset + resolved["catch_all_addr"] * 2
                        if resolved["catch_all_addr"] is not None
                        else None
                    ),
                }
            )
        return try_items

    def _instructionCanThrow(self, decoded):
        if decoded.can_throw:
            return True
        return decoded.mnemonic.startswith("invoke-")

    def _updateApiInformation(self, from_addr, api_name):
        self.disassembly.addr_to_api[from_addr] = api_name

    def _applyExceptionEdges(self, state, instruction_addr, decoded, try_blocks):
        for try_block in try_blocks:
            if not (try_block["start_addr"] <= instruction_addr < try_block["end_addr"]):
                continue
            for handler in try_block["handlers"]:
                target_addr = handler["target_addr"]
                state.addCodeRef(instruction_addr, target_addr)
                state.addBlockStart(target_addr)
                state.addBlockToQueue(target_addr)
            if try_block["catch_all_addr"] is not None:
                state.addCodeRef(instruction_addr, try_block["catch_all_addr"])
                state.addBlockStart(try_block["catch_all_addr"])
                state.addBlockToQueue(try_block["catch_all_addr"])

    def _buildFunctionMetadata(self, resolver, method, code_item_header, try_blocks):
        metadata = resolver.get_method_metadata(method)
        exception_handlers = []
        try_ranges = []
        for try_block in try_blocks:
            handlers = [dict(handler) for handler in try_block["handlers"]]
            handler_targets = [handler["target_addr"] for handler in handlers]
            for handler in handlers:
                exception_handlers.append(
                    {
                        "type_idx": handler["type_idx"],
                        "type_name": handler["type_name"],
                        "target_addr": handler["target_addr"],
                        "protected_range_start": try_block["start_addr"],
                        "protected_range_end": try_block["end_addr"],
                    }
                )
            catch_all_addr = try_block["catch_all_addr"]
            if catch_all_addr is not None:
                handler_targets.append(catch_all_addr)
                exception_handlers.append(
                    {
                        "type_idx": None,
                        "type_name": "<catch-all>",
                        "target_addr": catch_all_addr,
                        "protected_range_start": try_block["start_addr"],
                        "protected_range_end": try_block["end_addr"],
                    }
                )
            try_ranges.append(
                {
                    "start_addr": try_block["start_addr"],
                    "end_addr": try_block["end_addr"],
                    "handlers": handlers,
                    "handler_targets": handler_targets,
                    "catch_all_addr": catch_all_addr,
                }
            )
        metadata.update(
            {
                "registers_size": code_item_header["registers_size"],
                "ins_size": code_item_header["ins_size"],
                "outs_size": code_item_header["outs_size"],
                "tries_size": code_item_header["tries_size"],
                "debug_info_off": code_item_header["debug_info_off"],
                "insns_size_units": code_item_header["insns_size"],
                "exception_handler_count": len(exception_handlers),
                "exception_handlers": exception_handlers,
                "try_ranges": try_ranges,
                "heuristics": [],
                "reference_counts": {
                    "string": 0,
                    "type": 0,
                    "field": 0,
                    "method": 0,
                    "proto": 0,
                    "call_site": 0,
                    "method_handle": 0,
                },
            }
        )
        return metadata

    def _updateHeuristics(self, metadata, decoded, payload_size):
        heuristics = metadata["heuristics"]
        if metadata["tries_size"] > 0 and "exception-obfuscation-surface" not in heuristics:
            heuristics.append("exception-obfuscation-surface")
        if (
            decoded.mnemonic
            in {
                "invoke-custom",
                "invoke-custom/range",
                "invoke-polymorphic",
                "invoke-polymorphic/range",
            }
            and "advanced-dispatch" not in heuristics
        ):
            heuristics.append("advanced-dispatch")
        if (
            decoded.payload_kind in {"packed-switch", "sparse-switch"}
            and payload_size > self.MAX_SWITCH_TARGETS_FOR_HEURISTIC * 4
            and "large-switch-payload" not in heuristics
        ):
            heuristics.append("large-switch-payload")
        if decoded.ref_kind == "method":
            operand = decoded.operands
            if (
                any(indicator in operand for indicator in ("Ljava/lang/reflect/", "Ljava/lang/Class;->forName"))
                and "reflection-hotspot" not in heuristics
            ):
                heuristics.append("reflection-hotspot")
            if (
                any(
                    indicator in operand
                    for indicator in ("loadLibrary", "load(", "DexClassLoader", "InMemoryDexClassLoader")
                )
                and "native-or-dynamic-loading" not in heuristics
            ):
                heuristics.append("native-or-dynamic-loading")
        if (
            decoded.mnemonic == "const-string"
            and metadata["reference_counts"]["string"] >= 3
            and "string-staging" not in heuristics
        ):
            heuristics.append("string-staging")

    def analyzeFunction(self, dex_file, resolver, method):
        start_addr = getattr(method, "code_offset", 0)
        raw_data = self.disassembly.binary_info.raw_data
        bytecode_offset = start_addr
        header_offset = start_addr - 16
        code_item_header = parse_code_item_header(raw_data, header_offset)
        insns_size_bytes = code_item_header["insns_size"] * 2
        if bytecode_offset + insns_size_bytes > len(raw_data):
            raise ValueError("Invalid Dalvik bytecode range")

        bytecode = raw_data[bytecode_offset : bytecode_offset + insns_size_bytes]
        try_blocks = self._parseTryBlocks(
            raw_data,
            resolver,
            bytecode_offset,
            code_item_header["insns_size"],
            code_item_header["tries_size"],
        )

        state = DalvikFunctionAnalysisState(bytecode_offset, self.disassembly)
        metadata = self._buildFunctionMetadata(resolver, method, code_item_header, try_blocks)
        state.metadata = metadata
        for try_block in try_blocks:
            for handler in try_block["handlers"]:
                state.addBlockToQueue(handler["target_addr"])
            if try_block["catch_all_addr"] is not None:
                state.addBlockToQueue(try_block["catch_all_addr"])

        visited_offsets = set()
        payload_ranges = []

        while state.hasUnprocessedBlocks():
            block_start_addr = state.chooseNextBlock()
            idx = block_start_addr - bytecode_offset
            while 0 <= idx < len(bytecode):
                if any(start <= idx < end for start, end in payload_ranges):
                    break
                if idx in visited_offsets:
                    break
                visited_offsets.add(idx)

                try:
                    decoded = decode_instruction(
                        bytecode,
                        idx,
                        lambda ref_kind, ref_index: self._resolveReference(resolver, ref_kind, ref_index),
                    )
                except ValueError as exc:
                    self.disassembly.errors[bytecode_offset + idx] = {
                        "type": "dalvik_decode_error",
                        "instruction_bytes": bytecode[idx : idx + 2].hex(),
                        "message": str(exc),
                    }
                    LOGGER.warning("Failed to decode Dalvik instruction at 0x%x: %s", bytecode_offset + idx, exc)
                    break

                i_address = bytecode_offset + idx
                i_size = decoded.size_bytes
                i_mnemonic = decoded.mnemonic
                i_op_str = decoded.operands

                if decoded.ref_kind in metadata["reference_counts"]:
                    metadata["reference_counts"][decoded.ref_kind] += 1

                state.setNextInstructionReachable(not decoded.is_terminator)

                if decoded.ref_kind == "string" and decoded.ref_index is not None:
                    string_value = resolver.get_string_value(decoded.ref_index)
                    if string_value is not None:
                        self.disassembly.addStringRef(state.start_addr, i_address, string_value)
                if decoded.payload_idx is not None:
                    payload_size = self._getPayloadSize(bytecode, decoded.payload_idx)
                    if payload_size:
                        payload_ranges.append((decoded.payload_idx, decoded.payload_idx + payload_size))
                        payload_addr = bytecode_offset + decoded.payload_idx
                        state.addDataRef(i_address, payload_addr, size=payload_size)
                        if decoded.payload_kind in ("packed-switch", "sparse-switch"):
                            switch_targets = self._resolveSwitchTargets(bytecode, idx, decoded.payload_idx)
                            for target_idx in switch_targets:
                                target_addr = bytecode_offset + target_idx
                                state.addCodeRef(i_address, target_addr, by_jump=True)
                                state.addBlockStart(target_addr)
                                state.addBlockToQueue(target_addr)
                            fallthrough = i_address + i_size
                            state.addBlockStart(fallthrough)
                            state.addBlockToQueue(fallthrough)
                    self._updateHeuristics(metadata, decoded, payload_size)
                else:
                    self._updateHeuristics(metadata, decoded, 0)

                if i_mnemonic.startswith("goto"):
                    target_addr = bytecode_offset + decoded.branch_target_idx
                    state.addCodeRef(i_address, target_addr, by_jump=True)
                    state.addBlockStart(target_addr)
                    state.addBlockToQueue(target_addr)
                elif decoded.is_conditional and decoded.branch_target_idx is not None:
                    target_addr = bytecode_offset + decoded.branch_target_idx
                    state.addCodeRef(i_address, target_addr, by_jump=True)
                    state.addBlockStart(target_addr)
                    state.addBlockToQueue(target_addr)
                    fallthrough = i_address + i_size
                    state.addBlockStart(fallthrough)
                    state.addBlockToQueue(fallthrough)
                elif decoded.is_invoke:
                    state.setLeaf(False)
                    call_target = None
                    call_name = None
                    if decoded.ref_kind == "method" and decoded.ref_index is not None:
                        call_target, call_name = resolver.get_method_target(decoded.ref_index)
                    elif decoded.ref_index is not None:
                        call_name = resolver.format_ref(decoded.ref_kind, decoded.ref_index)
                    if call_target is not None:
                        state.addCodeRef(i_address, call_target)
                        if call_target == state.start_addr:
                            state.setRecursion(True)
                    elif call_name:
                        self._updateApiInformation(i_address, call_name)

                if self._instructionCanThrow(decoded) and try_blocks:
                    self._applyExceptionEdges(state, i_address, decoded, try_blocks)

                state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, decoded.bytes_)
                idx += i_size
                if not state.is_next_instruction_reachable:
                    break
            state.endBlock()

        state.label = resolver.format_method(method)
        state.finalizeAnalysis()
        if LOGGER.isEnabledFor(logging.DEBUG):
            self._logMethodDiagnostics(state)
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug("Analyzing buffer with %d bytes @0x%08x", binary_info.binary_size, binary_info.base_addr)
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "dalvik"
        self.disassembly.binary_info.version = ""
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        self.disassembly.language = "dalvik"

        if not DexFileLoader.isCompatible(binary_info.raw_data):
            raise ValueError("Buffer is not a valid DEX file")

        dex_file = None
        if getattr(binary_info, "file_path", "") and not getattr(binary_info, "is_buffer", False):
            with contextlib.suppress(Exception):
                dex_file = lief.DEX.parse(binary_info.file_path)
        if dex_file is None:
            dex_file = lief.DEX.parse(list(binary_info.raw_data))
        if dex_file is None:
            raise ValueError("Failed to parse DEX file")

        self.disassembly.binary_info.version = getattr(dex_file, "version", "")
        resolver = DexReferenceResolver(dex_file)
        methods = list(dex_file.methods)
        method_counts = {
            "total": len(methods),
            "skipped_no_class": 0,
            "skipped_no_code": 0,
            "skipped_invalid_offset": 0,
        }
        LOGGER.debug(
            "DEX summary: version=%s classes=%d methods=%d strings=%d types=%d fields=%d protos=%d",
            self.disassembly.binary_info.version,
            len(list(getattr(dex_file, "classes", []))),
            len(methods),
            len(resolver.strings),
            len(resolver.types),
            len(resolver.fields),
            len(resolver.prototypes),
        )

        analyzed_count = 0
        for method in methods:
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            if not getattr(method, "has_class", False):
                method_counts["skipped_no_class"] += 1
                continue
            if not getattr(method, "code_info", None):
                method_counts["skipped_no_code"] += 1
                continue
            if getattr(method, "code_offset", 0) < 16:
                method_counts["skipped_invalid_offset"] += 1
                continue
            try:
                self.analyzeFunction(dex_file, resolver, method)
                analyzed_count += 1
            except Exception as exc:
                LOGGER.warning(
                    "Failed to analyze Dalvik method %s @0x%x: %s",
                    resolver.format_method(method),
                    getattr(method, "code_offset", 0),
                    exc,
                )
                method_offset = getattr(method, "code_offset", 0)
                self.disassembly.failed_analysis_addr.append(method_offset)
                self.disassembly.errors[method_offset] = {
                    "type": "dalvik_function_error",
                    "instruction_bytes": "",
                    "message": str(exc),
                }

        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        if LOGGER.isEnabledFor(logging.DEBUG):
            self._logAnalysisSummary(self.disassembly.binary_info.version, method_counts, analyzed_count)
        return self.disassembly
