import struct


class DexFileLoader:
    SUPPORTED_VERSIONS = {b"035", b"037", b"038", b"039", b"040"}
    HEADER_SIZE = 0x70
    ENDIAN_CONSTANT = 0x12345678
    REVERSE_ENDIAN_CONSTANT = 0x78563412

    @classmethod
    def _parseHeader(cls, data):
        if len(data) < cls.HEADER_SIZE:
            return None
        magic = data[:8]
        # Standard DEX (dex\n) or ODEX (dey\n): same structure, same version table
        if magic.startswith((b"dex\n", b"dey\n")) and magic[7] == 0:
            version = magic[4:7]
            if version not in cls.SUPPORTED_VERSIONS:
                return None
        # CDEX (ART Compact DEX): cdex<ver>\0 — reduced validation; LIEF handles details
        elif data[:4] == b"cdex":
            return {"version": "cdex", "file_size": len(data), "data_off": 0, "data_size": len(data)}
        else:
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

    @staticmethod
    def mapBinary(data):
        return data

    @staticmethod
    def getBaseAddress(data):
        return 0

    @staticmethod
    def getBitness(data):
        return 32

    @staticmethod
    def getArchitecture(data):
        return "dalvik"

    @staticmethod
    def getAbi(data):
        return ""

    @classmethod
    def getCodeAreas(cls, data):
        header = cls._parseHeader(data)
        if not header:
            return []
        if header["data_off"] and header["data_size"]:
            return [(header["data_off"], header["data_off"] + header["data_size"])]
        return [(0, header["file_size"])]
