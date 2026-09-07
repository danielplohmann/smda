import struct


class DexFileLoader:
    """Loader for standard single-DEX files (magic ``dex\\n``).

    ODEX (``dey\\n``) and CDEX (``cdex``) magics are *recognized* but not
    analysis-compatible: ODEX wraps a different outer layout and often carries
    quickened opcodes (0xE3–0xF9); CDEX uses a compact variable-size code_item.
    Both would be silently mis-parsed by the standard DEX pipeline, so they are
    rejected from ``isCompatible`` (analysis path) while remaining detectable via
    ``isRecognizedUnsupported``.
    """

    SUPPORTED_VERSIONS = {b"035", b"037", b"038", b"039", b"040"}
    HEADER_SIZE = 0x70
    ENDIAN_CONSTANT = 0x12345678
    REVERSE_ENDIAN_CONSTANT = 0x78563412

    @classmethod
    def isRecognizedUnsupported(cls, data):
        """True for ODEX/CDEX containers that SMDA will not analyze as DEX."""
        return cls.unsupportedReason(data) is not None

    @classmethod
    def unsupportedReason(cls, data):
        if not data or len(data) < 4:
            return None
        if data[:4] == b"dey\n":
            return (
                "ODEX (dey\\n) is not supported: outer layout differs from DEX and "
                "code may use quickened opcodes 0xE3-0xF9. Provide a standard DEX (dex\\n)."
            )
        if data[:4] == b"cdex":
            return (
                "CDEX (cdex) is not supported: compact code_item layout is not "
                "parsed by SMDA. Provide a standard DEX (dex\\n)."
            )
        return None

    @classmethod
    def _parseHeader(cls, data):
        if len(data) < cls.HEADER_SIZE:
            return None
        magic = data[:8]
        # Standard DEX only — ODEX/CDEX intentionally excluded (see class docstring).
        if not (magic.startswith(b"dex\n") and magic[7] == 0):
            return None
        version = magic[4:7]
        if version not in cls.SUPPORTED_VERSIONS:
            return None
        file_size = struct.unpack_from("<I", data, 0x20)[0]
        header_size = struct.unpack_from("<I", data, 0x24)[0]
        endian_tag = struct.unpack_from("<I", data, 0x28)[0]
        map_off = struct.unpack_from("<I", data, 0x34)[0]
        data_size = struct.unpack_from("<I", data, 0x68)[0]
        data_off = struct.unpack_from("<I", data, 0x6C)[0]
        if header_size != cls.HEADER_SIZE:
            return None
        if file_size == 0 or file_size > len(data):
            return None
        if endian_tag not in {cls.ENDIAN_CONSTANT, cls.REVERSE_ENDIAN_CONSTANT}:
            return None
        if map_off and map_off < header_size:
            return None
        if map_off and map_off >= file_size:
            return None
        if data_off and data_off > file_size:
            return None
        if data_size and data_off + data_size > file_size:
            return None
        return {
            "version": version.decode("ascii"),
            "file_size": file_size,
            "data_off": data_off,
            "data_size": data_size,
        }

    @classmethod
    def isCompatible(cls, data):
        return cls._parseHeader(data) is not None

    @classmethod
    def parseBinary(cls, data):
        return cls._parseHeader(data)

    @staticmethod
    def mapBinary(data, parsed=None):
        return data

    @staticmethod
    def getBaseAddress(data, parsed=None):
        return 0

    @staticmethod
    def getBitness(data, parsed=None) -> int:
        return 32

    @staticmethod
    def getArchitecture(data, parsed=None):
        return "dalvik"

    @staticmethod
    def getHasBackend(data, parsed=None):
        return True

    @staticmethod
    def getAbi(data, parsed=None):
        return ""

    @classmethod
    def getCodeAreas(cls, data, parsed=None):
        header = parsed if parsed is not None else cls._parseHeader(data)
        if not header:
            return []
        if header["data_off"] and header["data_size"]:
            return [(header["data_off"], header["data_off"] + header["data_size"])]
        return [(0, header["file_size"])]
