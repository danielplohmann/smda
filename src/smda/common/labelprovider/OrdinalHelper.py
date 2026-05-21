class OrdinalHelper:
    # Central mapping for DLL ordinals to function names.
    # Only include mappings that are stable across Windows versions (XP, Win7, Win10+).
    ORDINALS = {
        "ws2_32.dll": {
            1: "accept",
            2: "bind",
            3: "closesocket",
            4: "connect",
            97: "freeaddrinfo",
            98: "getaddrinfo",
            99: "getnameinfo",
            51: "gethostbyaddr",
            52: "gethostbyname",
            53: "getprotobyname",
            54: "getprotobynumber",
            55: "getservbyname",
            56: "getservbyport",
            57: "gethostname",
            5: "getpeername",
            6: "getsockname",
            7: "getsockopt",
            8: "htonl",
            9: "htons",
            10: "ioctlsocket",
            11: "inet_addr",
            12: "inet_ntoa",
            13: "listen",
            14: "ntohl",
            15: "ntohs",
            16: "recv",
            17: "recvfrom",
            18: "select",
            19: "send",
            20: "sendto",
            21: "setsockopt",
            22: "shutdown",
            23: "socket",
        },
        "oleaut32.dll": {
            2: "SysAllocString",
            4: "SysAllocStringLen",
            6: "SysFreeString",
            7: "SysStringLen",
            8: "VariantInit",
            9: "VariantClear",
            10: "VariantCopy",
            144: "DllCanUnloadNow",
            149: "SysStringByteLen",
            150: "SysAllocStringByteLen",
        },
    }

    @staticmethod
    def resolveOrdinal(dll_name, ordinal):
        dll_name = dll_name.lower()
        if dll_name in OrdinalHelper.ORDINALS and ordinal in OrdinalHelper.ORDINALS[dll_name]:
            return OrdinalHelper.ORDINALS[dll_name][ordinal]
        return ""
