class OrdinalHelper:
    # Central mapping for DLL ordinals to function names, synchronized from data/apiscout_*.json
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
        "ole32.dll": {
            101: "CoTaskMemAlloc",
            102: "CoTaskMemFree",
            103: "CoTaskMemRealloc",
            106: "CoUninitialize",
            134: "CreateBindCtx",
            214: "IIDFromString",
            217: "IsValidIid",
            218: "IsValidInterface",
            254: "OleInitialize",
            277: "OleUninitialize",
            324: "StringFromGUID2",
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
        "mfc42.dll": {
            1: "DllGetClassObject",
            2: "DllCanUnloadNow",
            3: "DllRegisterServer",
            4: "DllUnregisterServer",
        },
    }

    @staticmethod
    def resolveOrdinal(dll_name, ordinal):
        dll_name = dll_name.lower()
        if dll_name in OrdinalHelper.ORDINALS and ordinal in OrdinalHelper.ORDINALS[dll_name]:
            return OrdinalHelper.ORDINALS[dll_name][ordinal]
        return ""
