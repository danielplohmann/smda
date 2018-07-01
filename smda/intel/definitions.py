
# some mnemonics as specific to capstone
CJMP_INS = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz"]
LOOP_INS = ["loop", "loopne", "loope"]
JMP_INS = ["jmp", "ljmp"]
CALL_INS = ["call", "lcall"]
RET_INS = ["ret", "retn", "retf", "iret"]
END_INS = ["ret", "retn", "retf", "iret", "int3"]
REGS_32BIT = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
DOUBLE_ZERO = bytearray(b"\x00\x00")

DEFAULT_PROLOGUES = [
    b"\x8B\xFF\x55\x8B\xEC",
    b"\x89\xFF\x55\x8B\xEC",
    b"\x55\x8B\xEC"
]

# these cover 80%+ of manually confirmed function starts in the reference data set
COMMON_PROLOGUES = {
    "5": {
        32: {
            b"\x8B\xFF\x55\x8B\xEC": 5,  # mov edi, edi, push ebp, mov ebp, esp
            b"\x89\xFF\x55\x8B\xEC": 3,  # mov edi, edi, push ebp, mov ebp, esp
        },
        64: {}
        },
    "3": {
        32: {
            b"\x55\x8B\xEC": 3,  # push ebp, mov ebp, esp
        },
        64: {}
        },
    "2": {
        32: {
            b"\x8B\xFF": 3,  # mov edi, edi
            b"\xFF\x25": 3,  # jmp dword ptr <addr>
            b"\x33\xC0": 2,  # xor eax, eax
            b"\x83\xEC": 2,  # sub esp, <byte>
            b"\x8B\x44": 2,  # mov eax, dword ptr <esp + byte>
            b"\x81\xEC": 2,  # sub esp, <byte>
            b"\x8D\x4D": 2,  # lea ecx, dword ptr <ebp/esp +- byte>
            b"\x8D\x8D": 2,  # lea ecx, dword ptr <ebp/esp +- byte>
            b"\xFF\x74": 2,  # push dword ptr <addr>
        },
        64: {}
        },
    "1": {
        32: {
            b"\x6a": 3,  # push <const byte>
            b"\x56": 3,  # push esi
            b"\x53": 2,  # push ebx
            b"\x51": 2,  # push ecx
            b"\x57": 2,  # push edi
            b"\xE8": 1,  # call <offset>
            b"\xc3": 1   # ret
        },
        64: {
            b"\x40": 1,  # x64 - push rxx
            b"\x44": 1,  # x64 - mov rxx, ptr
            b"\x48": 1,  # x64 - mov *, *
            b"\x33": 1,  #       xor, eax, *
            b"\x4c": 1,  # x64 - mov reg, reg
            b"\xb8": 1,  #       mov reg, const
            b"\x8b": 1,  #       mov dword ptr, reg
            b"\x89": 1,  #       mov dword ptr, reg
            b"\x45": 1,  # x64 - xor, reg, reg
            b"\xc3": 1   #       retn
        }
    }
}

#TODO: 2018-06-27 expand the coverage in this list
GAP_SEQUENCES = {
    "1": [
        "\x90",  # nop
        "\xCC"  # int3
    ],
    "2": [
        b"\x8b\xc0",
        b"\x8b\xff",  # mov edi, edi
        b"\x8d\x00",  # lea eax, dword ptr [eax]
        b"\x86\xc0",  # xchg al, al
    ],
    "3": [
        b"\x8d\x40\x00",  # lea eax, dword ptr [eax]
        b"\x8d\x00\x00",  # lea eax, dword ptr [eax]
        b"\x8d\x49\x00",  # lea ecx, dword ptr [ecx]
        b"\x8d\x64\x24",  # lea esp, dword ptr [esp]
    ]
}


COMMON_START_BYTES = {
    "32": {
        "55": 8334,
        "6a": 758,
        "56": 756,
        "51": 312,
        "8d": 566,
        "83": 558,
        "53": 548
    },
    "64": {
        "48": 1341,
        "40": 349,
        "4c": 59,
        "33": 56,
        "44": 18,
        "45": 17,
        "e9": 16
    }
}
