import contextlib
import datetime
import logging
import struct

import lief

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState
from smda.dalvik.DalvikOpcodeDecoder import (
    OPCODES,
    decode_instruction,
    parse_code_item_header,
    read_sleb128,
    read_uleb128,
)
from smda.DisassemblyResult import DisassemblyResult
from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.lief_helper import safe_lief_parse

LOGGER = logging.getLogger(__name__)


def parse_map_sections(raw_data):
    """Return {type_code: (offset, size)} from the DEX map_list (AOSP map_item)."""
    if not raw_data or len(raw_data) < 0x38:
        return {}
    map_off = struct.unpack_from("<I", raw_data, 0x34)[0]
    if map_off == 0 or map_off + 4 > len(raw_data):
        return {}
    count = struct.unpack_from("<I", raw_data, map_off)[0]
    sections = {}
    cursor = map_off + 4
    for _ in range(count):
        if cursor + 12 > len(raw_data):
            break
        type_code, _unused, size, offset = struct.unpack_from("<HHII", raw_data, cursor)
        sections[type_code] = (offset, size)
        cursor += 12
    return sections


class _OrphanCodeItemMethod:
    """Synthetic method object for gap-discovered code_items (no LIEF row)."""

    def __init__(self, code_offset):
        self.code_offset = code_offset
        self.code_info = object()
        self.has_class = True
        self.name = f"orphan_code_item@0x{code_offset:x}"
        self.cls = None
        self.prototype = None
        self.access_flags = 0


class DexReferenceResolver:
    # AOSP dex-format MethodHandleTypeCodes
    METHOD_HANDLE_TYPES = {
        0x00: "static-put",
        0x01: "static-get",
        0x02: "instance-put",
        0x03: "instance-get",
        0x04: "invoke-static",
        0x05: "invoke-instance",
        0x06: "invoke-constructor",
        0x07: "invoke-direct",
        0x08: "invoke-interface",
    }
    METHOD_HANDLE_FIELD_TYPES = {0x00, 0x01, 0x02, 0x03}
    # AOSP encoded_value type codes used by call_site_item
    VALUE_BYTE = 0x00
    VALUE_SHORT = 0x02
    VALUE_CHAR = 0x03
    VALUE_INT = 0x04
    VALUE_LONG = 0x06
    VALUE_FLOAT = 0x10
    VALUE_DOUBLE = 0x11
    VALUE_METHOD_TYPE = 0x15
    VALUE_METHOD_HANDLE = 0x16
    VALUE_STRING = 0x17
    VALUE_TYPE = 0x18
    VALUE_FIELD = 0x19
    VALUE_METHOD = 0x1A
    VALUE_ENUM = 0x1B
    VALUE_ARRAY = 0x1C
    VALUE_ANNOTATION = 0x1D
    VALUE_NULL = 0x1E
    VALUE_BOOLEAN = 0x1F
    TYPE_CALL_SITE_ID = 0x0007
    TYPE_METHOD_HANDLE = 0x0008

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

    def __init__(self, dex_file, raw_data=None):
        self.dex_file = dex_file
        self.raw_data = raw_data if raw_data is not None else getattr(dex_file, "raw", None)
        if isinstance(self.raw_data, memoryview):
            self.raw_data = self.raw_data.tobytes()
        elif self.raw_data is not None and not isinstance(self.raw_data, (bytes, bytearray)):
            with contextlib.suppress(Exception):
                self.raw_data = bytes(self.raw_data)
        self.strings = list(getattr(dex_file, "strings", []))
        self.methods = self._indexItems(getattr(dex_file, "methods", []))
        self.fields = self._indexItems(getattr(dex_file, "fields", []))
        self.types = self._indexItems(getattr(dex_file, "types", []))
        self.prototypes = self._indexItems(getattr(dex_file, "prototypes", []))
        self.classes = self._indexItems(getattr(dex_file, "classes", []))
        self.method_handles = {}
        self.call_sites = {}
        # id()-keyed: only safe while callers keep the LIEF objects alive for the
        # resolver's lifetime (resolver tables and analyzeBuffer's method list do);
        # an id reused after GC would alias a stale entry.
        self._method_format_cache = {}
        self._field_format_cache = {}
        # id()-keyed: only safe while callers keep the LIEF objects alive for the
        # resolver's lifetime (resolver tables and analyzeBuffer's method list do);
        # an id reused after GC would alias a stale entry.
        self._type_format_cache = {}
        self._loadExtendedTables()

    def _indexItems(self, items):
        indexed = {}
        for index, item in enumerate(items):
            indexed[getattr(item, "index", index)] = item
        return indexed

    def _safeGet(self, collection, index):
        if index in collection:
            return collection[index]
        return None

    def _safeAttr(self, obj, attr, default=None):
        try:
            return getattr(obj, attr)
        except Exception as exc:
            reraise_non_operational_exception(exc)
            return default

    def _normalizeTypeString(self, type_name):
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

    def _formatType(self, type_obj):
        if type_obj is None:
            return "<?>"
        if isinstance(type_obj, str):
            return self._normalizeTypeString(type_obj)
        # Type objects are id()-stable for the resolver's lifetime (LIEF keeps
        # them alive via the parsed dex_file and analyzeBuffer's method list),
        # so caching by id() avoids re-deriving the same descriptor thousands
        # of times across method/field/proto rendering — the dominant cost.
        cached = self._type_format_cache.get(id(type_obj))
        if cached is not None:
            return cached
        result = self._formatTypeUncached(type_obj)
        self._type_format_cache[id(type_obj)] = result
        return result

    def _formatTypeUncached(self, type_obj):
        if type_obj is None:
            return "<?>"
        if isinstance(type_obj, str):
            return self._normalizeTypeString(type_obj)
        fullname = self._safeAttr(type_obj, "fullname", None)
        if fullname:
            return self._normalizeTypeString(fullname)
        value = self._safeAttr(type_obj, "value", None)
        if value is not None:
            fullname = self._safeAttr(value, "fullname", None)
            if fullname:
                return self._normalizeTypeString(fullname)
            primitive_name = self.PRIMITIVE_TYPES.get(self._safeAttr(value, "name", ""), None)
            if primitive_name:
                return primitive_name
            name = self._safeAttr(value, "name", None)
            if name:
                return self._normalizeTypeString(name)
            with contextlib.suppress(Exception):
                normalized = self._normalizeTypeString(str(value))
                if normalized and not normalized.startswith("<lief."):
                    return normalized
        name = self._safeAttr(type_obj, "name", None)
        if name:
            return self._normalizeTypeString(name)
        with contextlib.suppress(Exception):
            # guard before normalizing: normalization rewrites dots to slashes and wraps the
            # result as "L...;", which turns an object repr into a plausible descriptor
            raw_type_string = str(type_obj)
            if not raw_type_string.startswith("<") and " - " not in raw_type_string:
                type_as_string = self._normalizeTypeString(raw_type_string)
                if type_as_string:
                    return type_as_string
        return f"<{type(type_obj).__name__}>"

    def _formatProto(self, prototype):
        if prototype is None:
            return "()<?>"
        params = []
        for param in getattr(prototype, "parameters_type", []):
            params.append(self._formatType(param))
        return_type = self._formatType(getattr(prototype, "return_type", None))
        return f"({''.join(params)}){return_type}"

    def formatMethod(self, method):
        if method is None:
            return "method@<?>"
        cache_key = id(method)
        cached = self._method_format_cache.get(cache_key)
        if cached is not None:
            return cached
        class_name = self._formatType(getattr(method, "cls", None))
        method_name = getattr(method, "name", "<?>")
        prototype = self._formatProto(getattr(method, "prototype", None))
        result = f"{class_name}->{method_name}{prototype}"
        self._method_format_cache[cache_key] = result
        return result

    def formatField(self, field):
        if field is None:
            return "field@<?>"
        cache_key = id(field)
        cached = self._field_format_cache.get(cache_key)
        if cached is not None:
            return cached
        class_name = self._formatType(getattr(field, "cls", None))
        field_name = getattr(field, "name", "<?>")
        field_type = self._formatType(getattr(field, "type", None))
        result = f"{class_name}->{field_name}:{field_type}"
        self._field_format_cache[cache_key] = result
        return result

    def formatProto(self, index):
        prototype = self._safeGet(self.prototypes, index)
        if prototype is None:
            return f"proto@{index}"
        return self._formatProto(prototype)

    def formatTypeByIndex(self, index):
        type_obj = self._safeGet(self.types, index)
        if type_obj is None:
            return f"type@{index}"
        return self._formatType(type_obj)

    # Baksmali-style escape map for DEX string literals.
    _STRING_ESCAPE_MAP = {
        '"': '\\"',
        "\\": "\\\\",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\0": "\\0",
    }

    @classmethod
    def _escapeDexString(cls, s):
        parts = []
        for ch in s:
            escaped = cls._STRING_ESCAPE_MAP.get(ch)
            if escaped:
                parts.append(escaped)
            elif ch.isprintable():
                parts.append(ch)
            else:
                parts.append(f"\\u{ord(ch):04x}")
        return "".join(parts)

    def _mapSections(self):
        return parse_map_sections(self.raw_data)

    def _loadExtendedTables(self):
        """Parse method_handles and call_site_ids from the DEX map (DEX 038+)."""
        sections = self._mapSections()
        mh = sections.get(self.TYPE_METHOD_HANDLE)
        if mh:
            offset, count = mh
            for index in range(count):
                item_off = offset + index * 8
                if self.raw_data is None or item_off + 8 > len(self.raw_data):
                    break
                handle_type, _u1, member_idx, _u2 = struct.unpack_from("<HHHH", self.raw_data, item_off)
                self.method_handles[index] = {
                    "type": handle_type,
                    "type_name": self.METHOD_HANDLE_TYPES.get(handle_type, f"type@{handle_type}"),
                    "member_index": member_idx,
                    "is_field": handle_type in self.METHOD_HANDLE_FIELD_TYPES,
                }
        cs = sections.get(self.TYPE_CALL_SITE_ID)
        if cs:
            offset, count = cs
            for index in range(count):
                item_off = offset + index * 4
                if self.raw_data is None or item_off + 4 > len(self.raw_data):
                    break
                call_site_off = struct.unpack_from("<I", self.raw_data, item_off)[0]
                self.call_sites[index] = self._parseCallSiteItem(call_site_off)

    def _readEncodedValue(self, data, offset):
        """Parse one encoded_value; return (python_value, next_offset)."""
        if offset >= len(data):
            raise ValueError("truncated encoded_value")
        header = data[offset]
        offset += 1
        value_type = header & 0x1F
        value_arg = (header >> 5) & 0x07
        if value_type == self.VALUE_NULL:
            return None, offset
        if value_type == self.VALUE_BOOLEAN:
            return bool(value_arg), offset
        if value_type == self.VALUE_ARRAY:
            return self._readEncodedArray(data, offset)
        if value_type == self.VALUE_ANNOTATION:
            # Skip nested annotation: type_idx, size, then size * (name_idx + value)
            _type_idx, offset = read_uleb128(data, offset)
            size, offset = read_uleb128(data, offset)
            for _ in range(size):
                _name_idx, offset = read_uleb128(data, offset)
                _val, offset = self._readEncodedValue(data, offset)
            return {"annotation": True}, offset
        size = value_arg + 1
        if offset + size > len(data):
            raise ValueError("truncated encoded_value payload")
        raw = data[offset : offset + size]
        offset += size
        # AOSP encoded_value extension rules: indices and char are zero-extended,
        # byte/short/int/long are sign-extended, float/double are zero-extended
        # to the right (bits occupy the high bytes of the IEEE754 pattern).
        int_val = int.from_bytes(raw, byteorder="little", signed=False)
        if value_type == self.VALUE_STRING:
            return ("string", int_val), offset
        if value_type == self.VALUE_TYPE:
            return ("type", int_val), offset
        if value_type == self.VALUE_FIELD or value_type == self.VALUE_ENUM:
            return ("field", int_val), offset
        if value_type == self.VALUE_METHOD:
            return ("method", int_val), offset
        if value_type == self.VALUE_METHOD_TYPE:
            return ("proto", int_val), offset
        if value_type == self.VALUE_METHOD_HANDLE:
            return ("method_handle", int_val), offset
        if value_type in (self.VALUE_BYTE, self.VALUE_SHORT, self.VALUE_INT, self.VALUE_LONG):
            return int.from_bytes(raw, byteorder="little", signed=True), offset
        if value_type == self.VALUE_FLOAT:
            bits = (int_val << (8 * (4 - size))) & 0xFFFFFFFF
            return struct.unpack("<f", struct.pack("<I", bits))[0], offset
        if value_type == self.VALUE_DOUBLE:
            bits = (int_val << (8 * (8 - size))) & 0xFFFFFFFFFFFFFFFF
            return struct.unpack("<d", struct.pack("<Q", bits))[0], offset
        # VALUE_CHAR and any unknown type code: keep the zero-extended value.
        return int_val, offset

    def _readEncodedArray(self, data, offset):
        size, offset = read_uleb128(data, offset)
        values = []
        for _ in range(size):
            value, offset = self._readEncodedValue(data, offset)
            values.append(value)
        return values, offset

    def _parseCallSiteItem(self, call_site_off):
        """
        call_site_item is an encoded_array (AOSP dex-format):
          [0] method_handle index, [1] method name string, [2] method type proto,
          [3..] bootstrap linker args.
        """
        raw = self.raw_data
        if raw is None or call_site_off < 0 or call_site_off >= len(raw):
            return {"offset": call_site_off, "values": [], "display": f"call_site@off={call_site_off}"}
        try:
            values, _ = self._readEncodedArray(raw, call_site_off)
        except Exception as exc:
            # a crafted call_site_ids entry reaches an arbitrary encoded_value tree, whose
            # nested arrays and annotations can exhaust the stack or index out of range as
            # well as fail to parse; none of that should end the run
            reraise_non_operational_exception(exc)
            return {"offset": call_site_off, "values": [], "display": f"call_site@off={call_site_off}"}
        handle_idx = None
        name_idx = None
        proto_idx = None
        bootstrap_args = []
        if values:
            v0 = values[0]
            if isinstance(v0, tuple) and v0[0] == "method_handle":
                handle_idx = v0[1]
            elif isinstance(v0, int):
                handle_idx = v0
        if len(values) > 1:
            v1 = values[1]
            if isinstance(v1, tuple) and v1[0] == "string":
                name_idx = v1[1]
        if len(values) > 2:
            v2 = values[2]
            if isinstance(v2, tuple) and v2[0] == "proto":
                proto_idx = v2[1]
        if len(values) > 3:
            bootstrap_args = values[3:]
        return {
            "offset": call_site_off,
            "values": values,
            "method_handle_index": handle_idx,
            "name_index": name_idx,
            "proto_index": proto_idx,
            "bootstrap_args": bootstrap_args,
            "display": None,
        }

    def formatMethodHandle(self, index):
        handle = self.method_handles.get(index)
        if handle is None:
            return f"method_handle@{index}"
        type_name = handle["type_name"]
        member_idx = handle["member_index"]
        if handle["is_field"]:
            member = self.formatField(self._safeGet(self.fields, member_idx))
        else:
            member = self.formatMethod(self._safeGet(self.methods, member_idx))
        return f"method_handle@{index}:{type_name}@{member}"

    def _formatBootstrapArg(self, arg):
        if arg is None:
            return "null"
        if isinstance(arg, bool):
            return "true" if arg else "false"
        if isinstance(arg, int):
            return hex(arg)
        if isinstance(arg, tuple) and len(arg) == 2:
            kind, idx = arg
            if kind == "string":
                if 0 <= idx < len(self.strings):
                    return '"' + self._escapeDexString(self.strings[idx]) + '"'
                return f"string@{idx}"
            if kind == "type":
                return self.formatTypeByIndex(idx)
            if kind == "field":
                return self.formatField(self._safeGet(self.fields, idx))
            if kind == "method":
                return self.formatMethod(self._safeGet(self.methods, idx))
            if kind == "proto":
                return self.formatProto(idx)
            if kind == "method_handle":
                return self.formatMethodHandle(idx)
            return f"{kind}@{idx}"
        if isinstance(arg, list):
            return "[" + ", ".join(self._formatBootstrapArg(v) for v in arg) + "]"
        if isinstance(arg, dict):
            return "annotation"
        return repr(arg)

    def formatCallSite(self, index):
        site = self.call_sites.get(index)
        if site is None:
            return f"call_site@{index}"
        if site.get("display"):
            return site["display"]
        handle_idx = site.get("method_handle_index")
        name_idx = site.get("name_index")
        proto_idx = site.get("proto_index")
        handle_str = self.formatMethodHandle(handle_idx) if handle_idx is not None else "method_handle@<?>"
        if name_idx is not None and 0 <= name_idx < len(self.strings):
            name_str = self.strings[name_idx]
        elif name_idx is not None:
            name_str = f"string@{name_idx}"
        else:
            name_str = "<?>"
        proto_str = self.formatProto(proto_idx) if proto_idx is not None else "()<?>"
        args = site.get("bootstrap_args") or []
        args_str = ", ".join(self._formatBootstrapArg(a) for a in args)
        if args_str:
            return f"call_site@{index}:{{{handle_str}, {name_str}, {proto_str}, {args_str}}}"
        return f"call_site@{index}:{{{handle_str}, {name_str}, {proto_str}}}"

    def formatRef(self, ref_kind, index):
        if ref_kind == "string":
            if 0 <= index < len(self.strings):
                return '"' + self._escapeDexString(self.strings[index]) + '"'
            return f"string@{index}"
        if ref_kind == "type":
            return self.formatTypeByIndex(index)
        if ref_kind == "field":
            return self.formatField(self._safeGet(self.fields, index))
        if ref_kind == "method":
            return self.formatMethod(self._safeGet(self.methods, index))
        if ref_kind == "proto":
            return self.formatProto(index)
        if ref_kind == "method_handle":
            return self.formatMethodHandle(index)
        if ref_kind == "call_site":
            return self.formatCallSite(index)
        return f"{ref_kind}@{index}" if ref_kind else f"item@{index}"

    def getMethod(self, method_index):
        return self._safeGet(self.methods, method_index)

    def getMethodTarget(self, method_index):
        method = self.getMethod(method_index)
        if method is None:
            return None, None
        code_offset = getattr(method, "code_offset", 0)
        code_info = getattr(method, "code_info", None)
        if code_offset and code_info:
            return code_offset, self.formatMethod(method)
        return None, self.formatMethod(method)

    def getStringValue(self, string_index):
        if 0 <= string_index < len(self.strings):
            return self.strings[string_index]
        return None

    def getMethodMetadata(self, method):
        access_flags = getattr(method, "access_flags", 0)
        access_flags = getattr(access_flags, "value", access_flags)
        if isinstance(access_flags, (list, tuple, set)):
            normalized_flags = 0
            for flag in access_flags:
                normalized_flags |= getattr(flag, "value", 0)
            access_flags = normalized_flags
        access_flag_names = [name for mask, name in self.ACCESS_FLAG_NAMES if access_flags & mask]
        method_name = self.formatMethod(method)
        return {
            "method_name": method_name,
            "class_name": self._formatType(getattr(method, "cls", None)),
            "prototype": self._formatProto(getattr(method, "prototype", None)),
            "access_flags": access_flags,
            "access_flags_decoded": access_flag_names,
        }


class DalvikDisassembler:
    MAX_SWITCH_TARGETS_FOR_HEURISTIC = 32

    def __init__(self, config):
        self.config = config
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)
        self._diag_stubs_suppressed = 0

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
        heuristics = metadata["heuristics"]
        n_ins = len(state.instructions)
        n_blocks = len(self.disassembly.functions.get(state.start_addr, []))
        n_handlers = metadata.get("exception_handler_count", 0)

        # Suppress trivial single-block stubs with no heuristics — typically generated
        # string-obfuscation shims.  Count them for the summary instead.
        if n_ins <= 8 and n_blocks <= 1 and n_handlers == 0 and not heuristics:
            self._diag_stubs_suppressed += 1
            return

        heuristic_str = ", ".join(heuristics) if heuristics else "none"
        outref_count = len(self.disassembly.getOutRefs(state.start_addr))
        string_ref_count = len(self.disassembly.getStringRefsForFunction(state.start_addr))
        fmt = "0x%08x %s: ins=%d blocks=%d outrefs=%d handlers=%d strings=%d refs=[%s] heuristics=[%s]"
        args = (
            state.start_addr,
            state.label,
            n_ins,
            n_blocks,
            outref_count,
            n_handlers,
            string_ref_count,
            self._formatReferenceCounts(metadata["reference_counts"]),
            heuristic_str,
        )
        # Both tiers logged at DEBUG — per-method detail belongs in verbose mode only.
        # Heuristic summary is surfaced via the INFO-level analysis banner instead.
        prefix = "[!] " if heuristics else ""
        LOGGER.debug(prefix + fmt, *args)

    def _logAnalysisSummary(self, version, method_counts, analyzed_count):
        total_blocks = sum(len(blocks) for blocks in self.disassembly.functions.values())
        total_strings = sum(len(stringrefs) for stringrefs in self.disassembly.stringrefs.values())
        try_functions = sum(
            1 for metadata in self.disassembly.function_metadata.values() if metadata.get("exception_handler_count", 0)
        )
        heuristics_str = self._summarizeHeuristics()
        sep = "-" * 68
        LOGGER.info(sep)
        LOGGER.info(
            "DEX v%s  |  analyzed %d/%d  |  functions=%d  blocks=%d  instructions=%d",
            version,
            analyzed_count,
            method_counts["total"],
            len(self.disassembly.functions),
            total_blocks,
            len(self.disassembly.instructions),
        )
        LOGGER.info(
            "         api_refs=%d  string_refs=%d  try_blocks=%d  failed=%d",
            len(self.disassembly.addr_to_api),
            total_strings,
            try_functions,
            len(self.disassembly.failed_analysis_addr),
        )
        skip_nc = method_counts["skipped_no_class"]
        skip_nc2 = method_counts["skipped_no_code"]
        skip_inv = method_counts["skipped_invalid_offset"]
        if skip_nc + skip_nc2 + skip_inv:
            LOGGER.info(
                "         skipped: no_class=%d  no_code=%d  invalid_offset=%d",
                skip_nc,
                skip_nc2,
                skip_inv,
            )
        if self._diag_stubs_suppressed:
            LOGGER.info("         (%d trivial stubs suppressed from per-method log)", self._diag_stubs_suppressed)
        if heuristics_str:
            LOGGER.info("[!]      heuristics: %s", heuristics_str)
        LOGGER.info(sep)

    def _getPayloadSize(self, bytecode, idx):
        if idx < 0 or idx + 2 > len(bytecode):
            return 0
        max_possible = len(bytecode) - idx
        ident = struct.unpack_from("<H", bytecode, idx)[0]
        if ident == 0x0100:
            # packed-switch-payload: ident(2) + size(2) + first_key(4) + targets(size*4)
            if idx + 8 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            raw_size = 8 + size * 4
            return min(raw_size, max_possible)
        if ident == 0x0200:
            # sparse-switch-payload: ident(2) + size(2) + keys(size*4) + targets(size*4)
            if idx + 4 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            raw_size = 4 + size * 8
            return min(raw_size, max_possible)
        if ident == 0x0300:
            # fill-array-data-payload: ident(2) + element_width(2) + size(4) + data
            if idx + 8 > len(bytecode):
                return 0
            element_width = struct.unpack_from("<H", bytecode, idx + 2)[0]
            if element_width == 0:
                return 0
            size = struct.unpack_from("<I", bytecode, idx + 4)[0]
            # Cap element count to prevent integer overflow on forged size fields
            max_elements = (max_possible - 8) // element_width
            size = min(size, max_elements)
            data_size = size * element_width
            if data_size % 2:
                data_size += 1
            raw_size = 8 + data_size
            return min(raw_size, max_possible)
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
        return resolver.formatRef(ref_kind, ref_index)

    def _parseTryBlocks(self, raw_data, resolver, bytecode_offset, insns_size_units, tries_size):
        if tries_size == 0:
            return [], []
        tries_offset = bytecode_offset + insns_size_units * 2
        if insns_size_units % 2:
            tries_offset += 2
        if tries_offset + tries_size * 8 > len(raw_data):
            raise ValueError("Invalid try_item table")
        handlers_offset = tries_offset + tries_size * 8
        encoded_handler_count, cursor = read_uleb128(raw_data, handlers_offset)
        handlers_by_offset = {}
        structural_violations = []
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
            resolved = handlers_by_offset.get(handler_off)
            if resolved is None:
                structural_violations.append(
                    {
                        "type": "invalid_handler_offset",
                        "try_start": hex(bytecode_offset + start_addr_units * 2),
                        "handler_offset": handler_off,
                    }
                )
                resolved = {"handlers": [], "catch_all_addr": None}
            try_items.append(
                {
                    "start_addr": bytecode_offset + start_addr_units * 2,
                    "end_addr": bytecode_offset + (start_addr_units + insn_count_units) * 2,
                    "handlers": [
                        {
                            "type_idx": handler["type_idx"],
                            "type_name": resolver.formatTypeByIndex(handler["type_idx"]),
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
        return try_items, structural_violations

    def _instructionCanThrow(self, decoded):
        return decoded.can_throw

    def _updateApiInformation(self, from_addr, api_name):
        self.disassembly.addr_to_api[from_addr] = api_name

    def _applyExceptionEdges(self, state, instruction_addr, decoded, try_blocks, metadata):
        """
        Add CFG edges from a throwable instruction to covering catch handlers.

        Edges are recorded both as ordinary code_refs (reachability / block split)
        and as typed exception_edges in function metadata.
        """
        applied = False
        exception_edges = metadata.setdefault("exception_edges", [])
        seen = metadata.setdefault("_exception_edge_keys", set())
        for try_block in try_blocks:
            if not (try_block["start_addr"] <= instruction_addr < try_block["end_addr"]):
                continue
            for handler in try_block["handlers"]:
                target_addr = handler["target_addr"]
                state.addCodeRef(instruction_addr, target_addr)
                state.addBlockStart(target_addr)
                state.addBlockToQueue(target_addr)
                key = (instruction_addr, target_addr, handler["type_idx"], False)
                if key not in seen:
                    seen.add(key)
                    exception_edges.append(
                        {
                            "from_addr": instruction_addr,
                            "to_addr": target_addr,
                            "kind": "exception",
                            "type_idx": handler["type_idx"],
                            "type_name": handler["type_name"],
                            "catch_all": False,
                            "mnemonic": decoded.mnemonic,
                        }
                    )
                applied = True
            if try_block["catch_all_addr"] is not None:
                target_addr = try_block["catch_all_addr"]
                state.addCodeRef(instruction_addr, target_addr)
                state.addBlockStart(target_addr)
                state.addBlockToQueue(target_addr)
                key = (instruction_addr, target_addr, None, True)
                if key not in seen:
                    seen.add(key)
                    exception_edges.append(
                        {
                            "from_addr": instruction_addr,
                            "to_addr": target_addr,
                            "kind": "exception",
                            "type_idx": None,
                            "type_name": "<catch-all>",
                            "catch_all": True,
                            "mnemonic": decoded.mnemonic,
                        }
                    )
                applied = True
        return applied

    def _buildFunctionMetadata(self, resolver, method, code_item_header, try_blocks):
        metadata = resolver.getMethodMetadata(method)
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
                "exception_edges": [],
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
                "structural_violations": [],
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
        # a packed-switch entry is 4 bytes (target only), a sparse-switch entry is 8
        # (key + target), so a shared 4-byte threshold fired at 16 sparse targets instead of 32
        entry_size = 8 if decoded.payload_kind == "sparse-switch" else 4
        if (
            decoded.payload_kind in {"packed-switch", "sparse-switch"}
            and payload_size > self.MAX_SWITCH_TARGETS_FOR_HEURISTIC * entry_size
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

    # Safety bound for the fixed-point payload discovery; each pass either
    # discovers a new payload range or the loop terminates.
    _MAX_PAYLOAD_DISCOVERY_PASSES = 256
    # Orphan scan: cap full-stream decode attempts (not just accepts).
    _MAX_ORPHAN_DECODE_ATTEMPTS = 256
    _MAX_ORPHAN_CANDIDATES = 64

    def _sweepInstructionStarts(self, bytecode, seed_payload_ranges=None):
        """One linear sweep with optional pre-seeded payload ranges excluded as data.

        Returns (valid_starts, payload_ranges, had_backward_payload) where
        payload_ranges is a list of (start, end) byte offsets and
        had_backward_payload is True if any 31t pointed to a range at/before
        the discovering instruction (only then is a re-sweep required).
        """
        valid = set()
        payload_ranges = list(seed_payload_ranges or [])
        seen_ranges = set(payload_ranges)
        had_backward_payload = False
        idx = 0
        null_resolve = lambda ref_kind, ref_index: ""  # noqa: E731
        # Dalvik instructions are 16-bit aligned (one "code unit"), so always
        # advance by 2 on resync — stepping by 1 wastes a decode attempt at every
        # odd offset on adversarial input.
        while idx < len(bytecode):
            if any(start <= idx < end for start, end in payload_ranges):
                idx += 2
                continue
            try:
                decoded = decode_instruction(bytecode, idx, null_resolve)
            except ValueError:
                idx += 2
                continue
            valid.add(idx)
            if decoded.payload_idx is not None:
                payload_size = self._getPayloadSize(bytecode, decoded.payload_idx)
                if payload_size:
                    range_pair = (decoded.payload_idx, decoded.payload_idx + payload_size)
                    if range_pair not in seen_ranges:
                        payload_ranges.append(range_pair)
                        seen_ranges.add(range_pair)
                        # Backward or self-overlapping payload relative to this insn.
                        if decoded.payload_idx <= idx:
                            had_backward_payload = True
            idx += decoded.size_bytes
        return valid, payload_ranges, had_backward_payload

    def _buildValidInstructionStarts(self, bytecode):
        """Fixed-point linear sweep of legal instruction-start offsets.

        Real compilers place switch/array payloads after the referencing 31t
        instruction, so a single forward pass is enough for legitimate DEX.
        Adversarial DEX can use a *backward* signed payload offset, which a
        single pass will have already mis-decoded as code. Re-sweep only when
        a backward payload is observed.

        Returns (valid_starts, payload_ranges).
        """
        payload_ranges = []
        valid = set()
        for pass_num in range(self._MAX_PAYLOAD_DISCOVERY_PASSES):
            valid, new_ranges, had_backward = self._sweepInstructionStarts(bytecode, payload_ranges)
            if len(new_ranges) == len(payload_ranges):
                payload_ranges = new_ranges
                break
            payload_ranges = new_ranges
            # Forward payloads are discovered at their 31t before the sweep
            # reaches them and are excluded within the same pass; only a
            # backward payload can have been mis-decoded as code already,
            # so only that case requires a re-sweep.
            if pass_num == 0 and not had_backward:
                break
        return valid, payload_ranges

    def _addStructuralViolation(self, metadata, violation_type, **fields):
        violation = {"type": violation_type}
        violation.update(fields)
        metadata.setdefault("structural_violations", []).append(violation)

    def _sanitizeTryBlocks(self, try_blocks, bytecode_offset, valid_instruction_starts):
        sanitized = []
        structural_violations = []
        for try_block in try_blocks:
            sanitized_handlers = []
            for handler in try_block["handlers"]:
                target_addr = handler["target_addr"]
                target_idx = target_addr - bytecode_offset
                if target_idx in valid_instruction_starts:
                    sanitized_handlers.append(handler)
                else:
                    structural_violations.append(
                        {
                            "type": "invalid_handler_target",
                            "protected_range_start": hex(try_block["start_addr"]),
                            "target": hex(target_addr),
                        }
                    )
            catch_all_addr = try_block["catch_all_addr"]
            if catch_all_addr is not None and (catch_all_addr - bytecode_offset) not in valid_instruction_starts:
                structural_violations.append(
                    {
                        "type": "invalid_handler_target",
                        "protected_range_start": hex(try_block["start_addr"]),
                        "target": hex(catch_all_addr),
                    }
                )
                catch_all_addr = None
            sanitized.append(
                {
                    "start_addr": try_block["start_addr"],
                    "end_addr": try_block["end_addr"],
                    "handlers": sanitized_handlers,
                    "catch_all_addr": catch_all_addr,
                }
            )
        return sanitized, structural_violations

    def _validateBranchTarget(
        self, metadata, source_addr, source_idx, target_idx, valid_instruction_starts, mnemonic=None
    ):
        target_addr = source_addr + (target_idx - source_idx)
        if target_idx == source_idx:
            # AOSP dalvik-bytecode: goto and goto/16 must not use offset 0;
            # goto/32 may (infinite-loop idiom used by packers).
            if mnemonic == "goto/32":
                return target_addr
            self._addStructuralViolation(
                metadata,
                "zero_branch_offset",
                from_addr=hex(source_addr),
                target=hex(target_addr),
            )
            return None
        if target_idx not in valid_instruction_starts:
            self._addStructuralViolation(
                metadata,
                "invalid_branch_target",
                from_addr=hex(source_addr),
                target=hex(target_addr),
            )
            return None
        return target_addr

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
        try_blocks, try_violations = self._parseTryBlocks(
            raw_data,
            resolver,
            bytecode_offset,
            code_item_header["insns_size"],
            code_item_header["tries_size"],
        )

        # Pass 1: fixed-point legal instruction starts + payload ranges.
        valid_instruction_starts, seed_payload_ranges = self._buildValidInstructionStarts(bytecode)

        try_blocks, target_violations = self._sanitizeTryBlocks(try_blocks, bytecode_offset, valid_instruction_starts)

        state = DalvikFunctionAnalysisState(bytecode_offset, self.disassembly)
        metadata = self._buildFunctionMetadata(resolver, method, code_item_header, try_blocks)
        state.metadata = metadata
        metadata["structural_violations"].extend(try_violations)
        metadata["structural_violations"].extend(target_violations)

        # Queue exception-handler entry points, validating against instruction boundaries.
        for try_block in try_blocks:
            for handler in try_block["handlers"]:
                target_addr = handler["target_addr"]
                state.addBlockStart(target_addr)
                state.addBlockToQueue(target_addr)
            if try_block["catch_all_addr"] is not None:
                ca_addr = try_block["catch_all_addr"]
                state.addBlockStart(ca_addr)
                state.addBlockToQueue(ca_addr)

        visited_offsets = set()
        # Seed the CFG pass with every payload range discovered by the fixed-point
        # sweep so a backward 31t reference cannot be walked as code.
        payload_ranges = list(seed_payload_ranges)
        payload_range_set = set(payload_ranges)

        while state.hasUnprocessedBlocks():
            block_start_addr = state.chooseNextBlock()
            if block_start_addr is None:
                break
            idx = block_start_addr - bytecode_offset
            while 0 <= idx < len(bytecode):
                if any(start <= idx < end for start, end in payload_ranges):
                    break
                if idx in visited_offsets:
                    break
                # Linear fall-through must land on a fixed-point-valid start (keeps
                # us out of payload / mid-instruction). Explicitly queued block
                # entries still get one decode attempt so decode errors surface.
                is_block_entry = idx == (block_start_addr - bytecode_offset)
                if not is_block_entry and idx not in valid_instruction_starts:
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
                    state.decode_error_count += 1
                    state.is_partial = True
                    break

                i_address = bytecode_offset + idx
                i_size = decoded.size_bytes
                i_mnemonic = decoded.mnemonic
                i_op_str = decoded.operands

                if decoded.ref_kind in metadata["reference_counts"]:
                    metadata["reference_counts"][decoded.ref_kind] += 1

                state.setNextInstructionReachable(not decoded.is_terminator)

                if decoded.ref_kind == "string" and decoded.ref_index is not None:
                    string_value = resolver.getStringValue(decoded.ref_index)
                    if string_value is not None:
                        self.disassembly.addStringRef(state.start_addr, i_address, string_value)
                if decoded.payload_idx is not None:
                    payload_size = self._getPayloadSize(bytecode, decoded.payload_idx)
                    if payload_size:
                        range_pair = (decoded.payload_idx, decoded.payload_idx + payload_size)
                        if range_pair not in payload_range_set:
                            payload_ranges.append(range_pair)
                            payload_range_set.add(range_pair)
                        payload_addr = bytecode_offset + decoded.payload_idx
                        state.addDataRef(i_address, payload_addr, size=payload_size)
                        if decoded.payload_kind in ("packed-switch", "sparse-switch"):
                            switch_targets = self._resolveSwitchTargets(bytecode, idx, decoded.payload_idx)
                            for target_idx in switch_targets:
                                target_addr = bytecode_offset + target_idx
                                if target_idx not in valid_instruction_starts:
                                    self._addStructuralViolation(
                                        metadata,
                                        "invalid_switch_target",
                                        from_addr=hex(i_address),
                                        target=hex(target_addr),
                                    )
                                    continue
                                state.addCodeRef(i_address, target_addr, by_jump=True)
                                state.addBlockStart(target_addr)
                                state.addBlockToQueue(target_addr)
                        # Sequential fallthrough must land on a real instruction
                        # start, never into a payload immediately after a 31t.
                        fallthrough_idx = idx + i_size
                        if fallthrough_idx not in valid_instruction_starts:
                            state.setNextInstructionReachable(False)
                        elif decoded.payload_kind in ("packed-switch", "sparse-switch"):
                            fallthrough = i_address + i_size
                            state.addBlockStart(fallthrough)
                            state.addBlockToQueue(fallthrough)
                    self._updateHeuristics(metadata, decoded, payload_size if payload_size else 0)
                else:
                    self._updateHeuristics(metadata, decoded, 0)

                if i_mnemonic.startswith("goto"):
                    target_addr = self._validateBranchTarget(
                        metadata,
                        i_address,
                        idx,
                        decoded.branch_target_idx,
                        valid_instruction_starts,
                        mnemonic=i_mnemonic,
                    )
                    if target_addr is not None:
                        state.addCodeRef(i_address, target_addr, by_jump=True)
                        state.addBlockStart(target_addr)
                        state.addBlockToQueue(target_addr)
                elif decoded.is_conditional and decoded.branch_target_idx is not None:
                    target_addr = self._validateBranchTarget(
                        metadata,
                        i_address,
                        idx,
                        decoded.branch_target_idx,
                        valid_instruction_starts,
                        mnemonic=i_mnemonic,
                    )
                    if target_addr is not None:
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
                        call_target, call_name = resolver.getMethodTarget(decoded.ref_index)
                    elif decoded.ref_index is not None:
                        call_name = resolver.formatRef(decoded.ref_kind, decoded.ref_index)
                    if call_target is not None:
                        state.addCodeRef(i_address, call_target)
                        if call_target == state.start_addr:
                            state.setRecursion(True)
                    elif call_name:
                        self._updateApiInformation(i_address, call_name)

                if self._instructionCanThrow(decoded) and try_blocks:
                    has_exception_edges = self._applyExceptionEdges(state, i_address, decoded, try_blocks, metadata)
                    if has_exception_edges and state.is_next_instruction_reachable:
                        fallthrough = i_address + i_size
                        fallthrough_idx = idx + i_size
                        if fallthrough_idx in valid_instruction_starts:
                            state.addBlockStart(fallthrough)
                            state.addBlockToQueue(fallthrough)

                state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, decoded.bytes_)
                idx += i_size
                if not state.is_next_instruction_reachable:
                    break
            state.endBlock()

        # Surface valid instruction starts never reached by the CFG walk (dead
        # code / opaque predicates); check against the final payload_ranges since
        # the CFG pass may have discovered more than the seed.
        unreached = sorted(
            bytecode_offset + off
            for off in valid_instruction_starts
            if off not in visited_offsets and not any(s <= off < e for s, e in payload_ranges)
        )
        if unreached:
            metadata["unreached_instruction_starts"] = unreached
            metadata["unreached_instruction_count"] = len(unreached)
            if "unreachable-code-surface" not in metadata["heuristics"]:
                metadata["heuristics"].append("unreachable-code-surface")

        # Prefer a clean orphan label over formatMethod's fallback for synthetic methods.
        orphan_name = getattr(method, "name", None)
        if orphan_name and str(orphan_name).startswith("orphan_code_item@"):
            state.label = orphan_name
        else:
            state.label = resolver.formatMethod(method)
        # Drop internal dedupe set before finalizing (not part of public metadata).
        metadata.pop("_exception_edge_keys", None)
        state.finalizeAnalysis()
        self._logMethodDiagnostics(state)
        return state

    # AOSP dex-format map_item type code for code_item
    _TYPE_CODE_ITEM = 0x2001

    def _codeItemSectionBounds(self, raw_data, data_off, data_end):
        """(start, end) of the map-declared code_item section, or (None, None)."""
        sections = parse_map_sections(raw_data)
        code_section = sections.get(self._TYPE_CODE_ITEM)
        if not code_section:
            return None, None
        code_off = code_section[0]
        if not (data_off <= code_off < data_end):
            # Map lies about the code section — distrust it entirely.
            return None, None
        # Map entries are sorted by offset (AOSP), so the section ends at the
        # next section's offset; guard against forged/unsorted maps anyway.
        following = [offset for offset, _size in sections.values() if code_off < offset <= data_end]
        code_end = min(following) if following else data_end
        return code_off, code_end

    def _claimCodeItemRange(self, claimed_intervals, header_off, insns_size_units):
        """Mark [header, header+16+insns) as occupied for orphan-scan skipping."""
        end = header_off + 16 + insns_size_units * 2
        claimed_intervals.append((header_off, end))

    def _intervalContains(self, claimed_intervals, point):
        return any(start <= point < end for start, end in claimed_intervals)

    def _intervalOverlaps(self, claimed_intervals, start, end):
        return any(start < b and a < end for a, b in claimed_intervals)

    def _discoverOrphanCodeItems(self, raw_data, known_code_offsets, max_candidates=None):
        """
        Bounded scan for plausible code_item headers not referenced by LIEF methods.

        code_item is 4-byte aligned (AOSP dex-format). Conservative filters keep
        false positives low while recovering hidden/orphaned method bodies used
        by some packers (completeness-over-precision, intel gap-scan analogue).
        """
        if max_candidates is None:
            max_candidates = self._MAX_ORPHAN_CANDIDATES
        if not raw_data or len(raw_data) < 0x70 + 16:
            return []
        header = DexFileLoader.parseBinary(raw_data)
        if not header:
            return []
        data_off = header.get("data_off") or 0x70
        data_end = data_off + (header.get("data_size") or 0)
        if data_end <= data_off or data_end > len(raw_data):
            data_off = 0x70
            data_end = len(raw_data)
        # Scope the scan to the map-declared code_item section (the analogue of
        # intel's executable-sections-only gap search); string/annotation bytes
        # outside it are never legal code_items. Fall back to the whole data
        # region if the map is absent or forged.
        code_off, code_end = self._codeItemSectionBounds(raw_data, data_off, data_end)
        if code_off is not None:
            data_off, data_end = code_off, code_end

        # Claim full known code_item ranges (header + insn stream) so interiors of
        # real methods cannot be re-parsed as orphan headers.
        claimed_intervals = []
        for code_offset in known_code_offsets:
            header_off = code_offset - 16
            if header_off < 0 or header_off + 16 > len(raw_data):
                continue
            try:
                hdr = parse_code_item_header(raw_data, header_off)
            except ValueError:
                claimed_intervals.append((header_off, code_offset + 2))
                continue
            self._claimCodeItemRange(claimed_intervals, header_off, hdr["insns_size"])

        candidates = []
        decode_attempts = 0
        scan = data_off + ((4 - (data_off % 4)) % 4)
        # Sort intervals for linear skip advancement.
        claimed_intervals.sort()
        while scan + 16 <= data_end and len(candidates) < max_candidates:
            if decode_attempts >= self._MAX_ORPHAN_DECODE_ATTEMPTS:
                break
            advanced = False
            for a, b in claimed_intervals:
                if a <= scan < b:
                    scan = b if b % 4 == 0 else b + (4 - (b % 4))
                    advanced = True
                    break
                if a > scan:
                    break
            if advanced:
                continue
            # Cheap header filter before counting a decode attempt.
            try:
                hdr = parse_code_item_header(raw_data, scan)
            except ValueError:
                scan += 4
                continue
            # Tight cheap filters: large insns_size on random data is the main cost driver.
            if (
                hdr["insns_size"] == 0
                or hdr["insns_size"] > 0x200
                or hdr["registers_size"] < hdr["ins_size"]
                or hdr["registers_size"] > 0x100
                or hdr["tries_size"] != 0
                or hdr["outs_size"] > hdr["registers_size"]
            ):
                scan += 4
                continue
            code_offset = scan + 16
            if code_offset + hdr["insns_size"] * 2 > len(raw_data):
                scan += 4
                continue
            # First unit must look like a real opcode (not map/string noise).
            first_op = raw_data[code_offset]
            if first_op not in OPCODES:
                scan += 4
                continue
            decode_attempts += 1
            accepted = self._tryAcceptOrphanCodeItem(raw_data, scan, claimed_intervals, known_code_offsets)
            if accepted is not None:
                candidates.append(accepted)
                self._claimCodeItemRange(claimed_intervals, scan, hdr["insns_size"])
                claimed_intervals.sort()
            scan += 4
        return candidates

    def _tryAcceptOrphanCodeItem(self, raw_data, header_off, claimed_intervals, known_code_offsets):
        """Return code_offset if header_off looks like a valid unclaimed code_item."""
        try:
            hdr = parse_code_item_header(raw_data, header_off)
        except ValueError:
            return None
        insns_size = hdr["insns_size"]
        registers_size = hdr["registers_size"]
        ins_size = hdr["ins_size"]
        tries_size = hdr["tries_size"]
        if insns_size == 0 or insns_size > 0x200:
            return None
        if registers_size < ins_size or registers_size > 0x100:
            return None
        if tries_size != 0:
            return None
        if hdr["outs_size"] > registers_size:
            return None
        code_offset = header_off + 16
        insns_bytes = insns_size * 2
        if code_offset + insns_bytes > len(raw_data):
            return None
        if code_offset in known_code_offsets:
            return None
        end = header_off + 16 + insns_bytes
        if self._intervalOverlaps(claimed_intervals, header_off, end):
            return None
        disassembly = getattr(self, "disassembly", None)
        if disassembly is not None:
            sample_end = min(code_offset + insns_bytes, code_offset + 64)
            if any(disassembly.isCode(addr) for addr in range(code_offset, sample_end, 2)):
                return None
        bytecode = raw_data[code_offset : code_offset + insns_bytes]
        valid, payload_ranges = self._buildValidInstructionStarts(bytecode)
        if not valid or 0 not in valid:
            return None
        if not self._walksCleanlyToEnd(bytecode, payload_ranges):
            return None
        return code_offset

    def _walksCleanlyToEnd(self, bytecode, payload_ranges):
        """Strict orphan acceptance: a genuine code_item decodes as one clean
        instruction stream (plus payloads/alignment nops) from offset 0 to
        exactly insns_size and reaches a terminator — junk data rarely does."""
        null_resolve = lambda ref_kind, ref_index: ""  # noqa: E731
        idx = 0
        saw_terminator = False
        while idx < len(bytecode):
            payload = next(((start, end) for start, end in payload_ranges if start <= idx < end), None)
            if payload is not None:
                idx = payload[1]
                continue
            try:
                decoded = decode_instruction(bytecode, idx, null_resolve)
            except ValueError:
                return False
            if decoded.is_terminator:
                saw_terminator = True
            idx += decoded.size_bytes
        return idx == len(bytecode) and saw_terminator

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        self._diag_stubs_suppressed = 0
        LOGGER.info("Analyzing buffer with %d bytes @0x%08x", binary_info.binary_size, binary_info.base_addr)
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setConfidenceThreshold(self.config.CONFIDENCE_THRESHOLD)
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "dalvik"
        self.disassembly.binary_info.bitness = 32  # Dalvik VM is always 32-bit
        self.disassembly.binary_info.version = ""
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        # A validated DEX header is conclusive format evidence. Keep the
        # public report contract score-only, like native and CIL reports.
        self.disassembly.language = {"dalvik": 1.0}

        raw_probe = binary_info.raw_data
        if not isinstance(raw_probe, (bytes, bytearray)):
            raw_probe = bytes(raw_probe)
        unsupported = DexFileLoader.unsupportedReason(raw_probe)
        if unsupported:
            raise ValueError(unsupported)
        if not DexFileLoader.isCompatible(raw_probe):
            raise ValueError("Buffer is not a valid DEX file")

        dex_file = None
        if getattr(binary_info, "file_path", "") and not getattr(binary_info, "is_buffer", False):
            with contextlib.suppress(Exception):
                dex_file = safe_lief_parse(binary_info.file_path, parser=lief.DEX.parse)
        if dex_file is None:
            # Prefer bytes/memoryview: list(raw_data) allocates a PyLong per byte
            # (~30x memory blowup on large DEX). Older LIEF builds only accept
            # List[int] and either raise TypeError or return None — fall back then.
            raw_data = binary_info.raw_data
            if not isinstance(raw_data, (bytes, bytearray)):
                raw_data = bytes(raw_data)
            try:
                dex_file = safe_lief_parse(raw_data, parser=lief.DEX.parse)
            except TypeError:
                dex_file = None
            if dex_file is None:
                dex_file = safe_lief_parse(list(raw_data), parser=lief.DEX.parse)
        if dex_file is None:
            raise ValueError("Failed to parse DEX file")

        self.disassembly.binary_info.version = getattr(dex_file, "version", "")
        raw_for_resolver = binary_info.raw_data
        if not isinstance(raw_for_resolver, (bytes, bytearray)):
            raw_for_resolver = bytes(raw_for_resolver)
        resolver = DexReferenceResolver(dex_file, raw_data=raw_for_resolver)
        methods = list(dex_file.methods)
        method_counts = {
            "total": len(methods),
            "skipped_no_class": 0,
            "skipped_no_code": 0,
            "skipped_invalid_offset": 0,
        }
        sep = "-" * 68
        LOGGER.info(sep)
        LOGGER.info(
            "DEX v%s  |  classes=%d  methods=%d  strings=%d  types=%d  fields=%d  protos=%d",
            self.disassembly.binary_info.version,
            len(list(getattr(dex_file, "classes", []))),
            len(methods),
            len(resolver.strings),
            len(resolver.types),
            len(resolver.fields),
            len(resolver.prototypes),
        )
        LOGGER.info(sep)

        analyzed_count = 0
        known_code_offsets = set()
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
            known_code_offsets.add(getattr(method, "code_offset", 0))
            try:
                self.analyzeFunction(dex_file, resolver, method)
                analyzed_count += 1
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.warning(
                    "Failed to analyze Dalvik method %s @0x%x: %s",
                    resolver.formatMethod(method),
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

        # Recover code_items hidden from the method table (orphans).
        method_counts["orphans_discovered"] = 0
        if not (cbAnalysisTimeout and cbAnalysisTimeout()):
            orphan_offsets = self._discoverOrphanCodeItems(raw_for_resolver, known_code_offsets)
            for code_offset in orphan_offsets:
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    break
                if code_offset in self.disassembly.functions:
                    continue
                # Refuse if primary recovery already claimed any insn bytes.
                if self.disassembly.isCode(code_offset):
                    continue
                orphan = _OrphanCodeItemMethod(code_offset)
                try:
                    self.analyzeFunction(dex_file, resolver, orphan)
                    method_counts["orphans_discovered"] += 1
                    analyzed_count += 1
                    meta = self.disassembly.function_metadata.get(code_offset, {})
                    if "orphan-code-item" not in meta.get("heuristics", []):
                        meta.setdefault("heuristics", []).append("orphan-code-item")
                    self.disassembly.function_symbols[code_offset] = orphan.name
                    meta["method_name"] = orphan.name
                    meta["class_name"] = "Lsmda/orphan;"
                except Exception as exc:
                    reraise_non_operational_exception(exc)
                    LOGGER.debug("Orphan code_item @0x%x rejected: %s", code_offset, exc)

        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        self._logAnalysisSummary(self.disassembly.binary_info.version, method_counts, analyzed_count)
        return self.disassembly
