
# some mnemonics as specific to capstone
CJMP_INS = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz"]
LOOP_INS = ["loop", "loopne", "loope"]
JMP_INS = ["jmp", "ljmp"]
CALL_INS = ["call", "lcall"]
RET_INS = ["ret", "retn", "retf", "iret"]
END_INS = ["ret", "retn", "retf", "iret", "int3", "hlt"]
REGS_32BIT = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
REGS_64BIT = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
DOUBLE_ZERO = bytearray(b"\x00\x00")

DEFAULT_PROLOGUES = [
    b"\x8B\xFF\x55\x8B\xEC",
    b"\x89\xFF\x55\x8B\xEC",
    b"\x55\x8B\xEC",
    b"\x55\x89\xE5"
]

# these cover 99% of confirmed function starts in the reference data set
COMMON_PROLOGUES = {
    "5": {
        32: {
            b"\x8B\xFF\x55\x8B\xEC": 50,  # mov edi, edi, push ebp, mov ebp, esp
            b"\x89\xFF\x55\x8B\xEC": 50,  # mov edi, edi, push ebp, mov ebp, esp
        },
        64: {}
        },
    "3": {
        32: {
            b"\x55\x8B\xEC": 50,  # push ebp, mov ebp, esp
        },
        64: {}
        },
    "1": {
        32: {
            b"\x55": 51,  # 311150 (51.09%) -- cumulative:  51.09%
            b"\x8b": 10,  #  62878 (10.32%) -- cumulative:  61.41%
            b"\x83": 7,  #  46477 (7.63%) -- cumulative:  69.05%
            b"\x53": 6,  #  38773 (6.37%) -- cumulative:  75.41%
            b"\x57": 5,  #  36048 (5.92%) -- cumulative:  81.33%
            b"\x56": 5,  #  31955 (5.25%) -- cumulative:  86.58%
            b"\xff": 4,  #  24444 (4.01%) -- cumulative:  90.59%
            b"\xe9": 2,  #  16420 (2.70%) -- cumulative:  93.29%
            b"\xb8": 1,  #   6577 (1.08%) -- cumulative:  94.37%
            b"\xc3": 1,  #   5638 (0.93%) -- cumulative:  95.29%
            b"\xa1": 1,  #   4168 (0.68%) -- cumulative:  95.98%
            b"\x6a": 1,  #   3815 (0.63%) -- cumulative:  96.60%
            b"\x51": 1,  #   2753 (0.45%) -- cumulative:  97.06%
            b"\x31": 1,  #   2514 (0.41%) -- cumulative:  97.47%
            b"\xf3": 1,  #   2109 (0.35%) -- cumulative:  97.82%
            b"\x33": 1,  #   1279 (0.21%) -- cumulative:  98.03%
            b"\x81": 1,  #   1261 (0.21%) -- cumulative:  98.23%
            b"\x85": 1,  #   1045 (0.17%) -- cumulative:  98.40%
            b"\xe8": 1,  #   1005 (0.17%) -- cumulative:  98.57%
            b"\x8d": 1,  #    896 (0.15%) -- cumulative:  98.72%
            b"\x68": 1,  #    749 (0.12%) -- cumulative:  98.84%
            b"\x80": 1,  #    703 (0.12%) -- cumulative:  98.95%
        },
        64: {
            b"\x55": 33,  # 196922 (33.40%) -- cumulative:  33.40%
            b"\x48": 21,  # 124360 (21.09%) -- cumulative:  54.49%
            b"\x41": 15,  #  91785 (15.57%) -- cumulative:  70.06%
            b"\x53": 6,  #  37559 (6.37%) -- cumulative:  76.43%
            b"\xff": 3,  #  22877 (3.88%) -- cumulative:  80.31%
            b"\x40": 3,  #  18018 (3.06%) -- cumulative:  83.36%
            b"\xe9": 2,  #  15434 (2.62%) -- cumulative:  85.98%
            b"\x50": 1,  #  11713 (1.99%) -- cumulative:  87.97%
            b"\x8b": 1,  #   9130 (1.55%) -- cumulative:  89.52%
            b"\x4c": 1,  #   6737 (1.14%) -- cumulative:  90.66%
            b"\xc3": 1,  #   5978 (1.01%) -- cumulative:  91.67%
            b"\x89": 1,  #   5852 (0.99%) -- cumulative:  92.66%
            b"\xb8": 1,  #   5073 (0.86%) -- cumulative:  93.52%
            b"\x31": 1,  #   4902 (0.83%) -- cumulative:  94.36%
            b"\x44": 1,  #   4504 (0.76%) -- cumulative:  95.12%
            b"\x0f": 1,  #   3196 (0.54%) -- cumulative:  95.66%
            b"\x83": 1,  #   3120 (0.53%) -- cumulative:  96.19%
            b"\xf3": 1,  #   2363 (0.40%) -- cumulative:  96.59%
            b"\xf2": 1,  #   2349 (0.40%) -- cumulative:  96.99%
            b"\x85": 1,  #   1806 (0.31%) -- cumulative:  97.30%
            b"\x33": 1,  #   1605 (0.27%) -- cumulative:  97.57%
            b"\x66": 1,  #   1370 (0.23%) -- cumulative:  97.80%
            b"\xba": 1,  #   1235 (0.21%) -- cumulative:  98.01%
            b"\x45": 1,  #   1227 (0.21%) -- cumulative:  98.22%
            b"\x80": 1,  #   1197 (0.20%) -- cumulative:  98.42%
            b"\xc7": 1,  #   1034 (0.18%) -- cumulative:  98.60%
            b"\xb0": 1,  #    911 (0.15%) -- cumulative:  98.75%
            b"\xbf": 1,  #    894 (0.15%) -- cumulative:  98.90%
        }
    }
}

#TODO: 2018-06-27 expand the coverage in this list
# https://stackoverflow.com/questions/25545470/long-multi-byte-nops-commonly-understood-macros-or-other-notation
GAP_SEQUENCES = {
    1: [
        b"\x90",  # NOP1_OVERRIDE_NOP - AMD / nop - INTEL
        b"\xCC",  # int3
        b"\x00",  # pass over sequences of null bytes
    ],
    2: [
        b"\x66\x90",  # NOP2_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x8b\xc0",
        b"\x8b\xff",  # mov edi, edi
        b"\x8d\x00",  # lea eax, dword ptr [eax]
        b"\x86\xc0",  # xchg al, al
        b"\x66\x2e",  # NOP2_OVERRIDE_NOP - AMD / nop - INTEL
    ],
    3: [
        b"\x0f\x1f\x00",  # NOP3_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x8d\x40\x00",  # lea eax, dword ptr [eax]
        b"\x8d\x00\x00",  # lea eax, dword ptr [eax]
        b"\x8d\x49\x00",  # lea ecx, dword ptr [ecx]
        b"\x8d\x64\x24",  # lea esp, dword ptr [esp]
        b"\x8d\x76\x00",
        b"\x66\x66\x90"
    ],
    4: [
        b"\x0f\x1f\x40\x00",  # NOP4_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x8d\x74\x26\x00",
        b"\x66\x66\x66\x90"
    ],
    5: [
        b"\x0f\x1f\x44\x00\x00",  # NOP5_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x90\x8d\x74\x26\x00"
    ],
    6: [
        b"\x66\x0f\x1f\x44\x00\x00",  # NOP6_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x8d\xb6\x00\x00\x00\x00"
    ],
    7: [
        b"\x0f\x1f\x80\x00\x00\x00\x00",  # NOP7_OVERRIDE_NOP - AMD / nop - INTEL,
        b"\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x8D\xBC\x27\x00\x00\x00\x00"
    ],
    8: [
        b"\x0f\x1f\x84\x00\x00\x00\x00\x00",  # NOP8_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x90\x8d\xb4\x26\x00\x00\x00\x00"
    ],
    9: [
        b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # NOP9_OVERRIDE_NOP - AMD / nop - INTEL
        b"\x89\xf6\x8d\xbc\x27\x00\x00\x00\x00"
    ],
    10: [
        b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # NOP10_OVERRIDE_NOP - AMD
        b"\x8d\x76\x00\x8d\xbc\x27\x00\x00\x00\x00",
        b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    ],
    11: [
        b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # NOP11_OVERRIDE_NOP - AMD
        b"\x8d\x74\x26\x00\x8d\xbc\x27\x00\x00\x00\x00",
        b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    ],
    12: [
        b"\x8d\xb6\x00\x00\x00\x00\x8d\xbf\x00\x00\x00\x00",
        b"\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    ],
    13: [
        b"\x8d\xb6\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00",
        b"\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    ],
    14: [
        b"\x8d\xb4\x26\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00",
        b"\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    ],
    15: [
        b"\x66\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
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
        "e9": 16,
    }
}
