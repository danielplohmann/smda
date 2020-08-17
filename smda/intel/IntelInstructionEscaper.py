#!/usr/bin/env python3
import logging
import re
import struct
import codecs

def occurrences(string, sub):
    # https://stackoverflow.com/a/2970542
    count = start = 0
    while True:
        start = string.find(sub, start) + 1
        if start > 0:
            count += 1
        else:
            return count

LOGGER = logging.getLogger(__name__)


class IntelInstructionEscaper:
    """ Escaper to abstract information from disassembled instructions. Based on capstone disassembly. """

    _aritlog_group = [
        "aaa", "aad", "aam", "aas", "adc", "adcx", "add", "adox", "and", "cdq",
        "cdqe", "daa", "das", "dec", "div", "idiv", "imul", "inc", "lzcnt", "mul",
        "mulx", "neg", "not", "or", "popcnt", "rcl", "rcr", "rol", "ror", "sal",
        "salc", "sar", "sbb", "shl", "shld", "shr", "shrd", "sub", "tzcnt", "xadd",
        "xor", "shlx", "shrx", "sarx"
    ]
    _cfg_group = [
        "arpl", "bound", "call", "clc", "cld", "cli", "cmc", "cmova", "cmovae", "cmovb",
        "cmovbe", "cmove", "cmovge", "cmovl", "cmovle", "cmovne", "cmovs", "cmp", "cmps", "cmpsb",
        "cmpsd", "cmpsw", "iret", "iretd", "ja", "jae", "jb", "jbe", "jcxz", "je",
        "jecxz", "jg", "jge", "jl", "jle", "jmp", "jne", "jno", "jnp", "jns",
        "jo", "jp", "jrcxz", "js", "lcall", "ljmp", "loop", "loope", "loopne", "ret",
        "retf", "retfq", "retn", "seta", "setae", "setb", "setbe", "sete", "setg", "setge",
        "setl", "setle", "setne", "setno", "setnp", "setns", "seto", "setp", "sets", "stc",
        "std", "sti", "test"
    ]
    _mem_group = [
        "bsf", "bsr", "bswap", "bt", "btc", "btr", "bts", "cbw", "cmovg", "cmovno",
        "cmovnp", "cmovns", "cmovo", "cmovp", "cmpxchg", "cmpxchg8b", "cqo", "cwd", "cwde", "lahf",
        "lar", "lds", "lea", "les", "lfs", "lgs", "lods", "lodsb", "lodsd", "lodsq",
        "lodsw", "lsl", "lss", "maskmovq", "mov", "movabs", "movnti", "movntq", "movs", "movsb",
        "movsd", "movss", "movsw", "movsx", "movsxd", "movzx", "rdmsr", "sahf", "scas", "scasb",
        "scasd", "scasq", "scasw", "stos", "stosb", "stosd", "stosq", "stosw", "wrmsr", "xabort",
        "xbegin", "xchg", "xlat", "xlatb", "movbe", "clflush"
    ]
    _stack_group = [
        "enter", "leave", "pop", "popad", "popal", "popf", "popfd", "popfq", "push", "pushad",
        "pushal", "pushf", "pushfd", "pushfq"
    ]
    _privileged_group = [
        "clts", "cpuid", "getsec", "hlt", "in", "ins", "insb", "insd", "insw", "int",
        "int1", "int3", "into", "invd", "invlpg", "lfence", "lgdt", "lidt", "lldt", "lmsw",
        "ltr", "mfence", "out", "outs", "outsb", "outsd", "outsw", "pause", "prefetchnta", "prefetcht0",
        "prefetcht1", "prefetcht2", "prefetchw", "rdpmc", "rdtsc", "rsm", "sfence", "sgdt", "sidt", "sldt",
        "smsw", "str", "syscall", "sysenter", "sysexit", "sysret", "ud", "ud2", "ud2b", "wait",
        "wbinvd", "xsaveopt", "ud0",
    ]
    _aes_group = [
        "aesdec", "aesdeclast", "aesenc", "aesenclast", "aesimc", "aeskeygenassist", "crc32", "rdrand", "rdseed", "sha1msg1",
        "sha1msg2", "sha1nexte", "sha1rnds4", "sha256msg1", "sha256msg2", "sha256rnds2", "vaesenc", "vaesenclast", "xcryptcbc", "xcryptcfb",
        "xcryptebc", "xcryptecb", "xcryptofb", "xstorerng", "xsha1", "xsha256", "xcryptctr", "vaesdec", "vaesdeclast"
    ]
    _float_group = [
        "f2xm1", "fabs", "fadd", "faddp", "fbld", "fbstp", "fchs", "fcmovb", "fcmovbe", "fcmove",
        "fcmovnb", "fcmovnbe", "fcmovne", "fcmovnu", "fcmovu", "fcom", "fcomi", "fcomp", "fcompi", "fcompp",
        "fcos", "fdecstp", "fdiv", "fdivp", "fdivr", "fdivrp", "ffree", "fiadd", "ficom", "ficomp",
        "fidiv", "fidivr", "fild", "fimul", "fincstp", "fist", "fistp", "fisttp", "fisub", "fisubr",
        "fld", "fld1", "fldcw", "fldenv", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fldpi", "fldz",
        "fmul", "fmulp", "fnclex", "fninit", "fnop", "fnsave", "fnstcw", "fnstenv", "fnstsw", "fpatan",
        "fprem", "fprem1", "fptan", "frndint", "frstor", "fscale", "fsetpm", "fsin", "fsincos", "fsqrt",
        "fst", "fstp", "fstpnce", "fsub", "fsubp", "fsubr", "fsubrp", "ftst", "fucom", "fucomi",
        "fucomp", "fucompi", "fucompp", "fxam", "fxch", "fxrstor", "fxsave", "fxtract", "fyl2x", "fyl2xp1",
        "fcomip", "fdisi8087_nop", "feni8087_nop", "ffreep", "fucomip",
    ]
    _xmm_group = [
        "addpd", "addps", "addsd", "addss", "addsubpd", "andn", "andnpd", "andnps", "andpd", "andps",
        "cmpeqps", "cmpeqsd", "cmplesd", "cmpltpd", "cmpltps", "cmpltsd", "cmpneqpd", "cmpneqsd", "cmpneqss", "cmpnlepd",
        "cmpnlesd", "cmpnltsd", "cmpps", "cmpsq", "comisd", "comiss", "cvtdq2pd", "cvtdq2ps", "cvtpd2dq", "cvtpd2ps",
        "cvtpi2ps", "cvtps2dq", "cvtps2pd", "cvtps2pi", "cvtsd2si", "cvtsd2ss", "cvtsi2sd", "cvtsi2ss", "cvtss2sd", "cvtss2si",
        "cvttpd2dq", "cvttps2dq", "cvttps2pi", "cvttsd2si", "cvttss2si", "divpd", "divps", "divsd", "divss", "emms",
        "femms", "haddpd", "lddqu", "ldmxcsr", "maxpd", "maxps", "maxsd", "maxss", "minpd", "minps",
        "minsd", "minss", "movapd", "movaps", "movd", "movddup", "movdq2q", "movdqa", "movdqu", "movhlps",
        "movhpd", "movhps", "movlhps", "movlpd", "movlps", "movmskpd", "movmskps", "movntdq", "movntps", "movq",
        "movsldup", "movsq", "movupd", "movups", "mulpd", "mulps", "mulsd", "mulss", "orpd", "orps",
        "pabsd", "pabsw", "packssdw", "packsswb", "packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw",
        "paddusb", "paddusw", "paddw", "palignr", "pand", "pandn", "pavgb", "pavgw", "pblendw", "pclmulqdq",
        "pcmpeqb", "pcmpeqd", "pcmpeqq", "pcmpeqw", "pcmpestri", "pcmpgtb", "pcmpgtd", "pcmpgtw", "pcmpistri", "pextrb",
        "pextrd", "pextrw", "phaddd", "phsubsw", "pinsrb", "pinsrd", "pinsrq", "pinsrw", "pmaddubsw", "pmaddwd",
        "pmaxsw", "pmaxub", "pminsw", "pminub", "pmovmskb", "pmovsxdq", "pmovzxwd", "pmulhuw", "pmulhw", "pmulld", "pmullw",
        "pmuludq", "popaw", "por", "psadbw", "pshufb", "pshufd", "pshufhw", "pshuflw", "pshufw", "psignw",
        "pslld", "pslldq", "psllq", "psllw", "psrad", "psraw", "psrld", "psrldq", "psrlq", "psrlw",
        "psubb", "psubd", "psubq", "psubsb", "psubsw", "psubusb", "psubusw", "psubw", "punpckhbw", "punpckhdq",
        "punpckhqdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklqdq", "punpcklwd", "pushaw", "pxor", "rcpps", "rcpss",
        "rorx", "roundsd", "rsqrtps", "shufpd", "shufps", "sqrtpd", "sqrtps", "sqrtsd", "sqrtss", "stmxcsr", "subpd",
        "subps", "subsd", "subss", "ucomisd", "ucomiss", "unpckhpd", "unpckhps", "unpcklpd", "unpcklps", "vaddpd",
        "vaddsd", "vaddss", "vandnpd", "vandpd", "vandps", "vbroadcasti128", "vcmplesd", "vcmpnltsd", "vcmppd", "vcomisd",
        "vcvtdq2pd", "vcvtpd2dq", "vcvtps2pd", "vcvtsd2ss", "vcvtsi2ss", "vcvtss2si", "vcvttpd2dq", "vcvttsd2si", "vdivsd", "verr",
        "verw", "vfmadd132pd", "vfmadd132sd", "vfmadd213sd", "vfmadd213ss", "vfmadd231sd", "vfmadd231ss", "vfmsub132sd", "vfmsub213sd", "vfmsub213ss",
        "vfmsubaddpd", "vfmsubpd", "vfnmadd132sd", "vfnmadd213sd", "vfnmadd231sd", "vhaddpd", "vinserti128", "vldmxcsr", "vmaxsd", "vmaxss",
        "vminpd", "vminsd", "vmovapd", "vmovd", "vmovddup", "vmovdqa", "vmovdqu", "vmovlhps", "vmovntdq", "vmovq",
        "vmovsd", "vmovss", "vmovups", "vmulpd", "vmulps", "vmulsd", "vorpd", "vorps", "vpackssdw", "vpackuswb",
        "vpaddb", "vpaddd", "vpaddq", "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw", "vpaddw", "vpalignr", "vpand",
        "vpandn", "vpavgb", "vpavgw", "vpblendd", "vpblendw", "vpbroadcastb", "vpclmulqdq", "vpcmpeqb", "vpcmpeqw", "vpcmpgtd",
        "vperm2f128", "vperm2i128", "vpermd", "vpinsrd", "vpmaddwd", "vpmaxsw", "vpmaxub", "vpmovmskb", "vpmullw", "vpor",
        "vprotd", "vprotq", "vpsadbw", "vpshufb", "vpshufd", "vpslld", "vpslldq", "vpsllq", "vpsrad", "vpsraw",
        "vpsrld", "vpsrldq", "vpsrlq", "vpsubd", "vpsubq", "vpsubusb", "vpsubw", "vptest", "vpunpckhbw", "vpunpckhdq",
        "vpunpckhqdq", "vpunpckhwd", "vpunpckldq", "vpxor", "vrcpss", "vroundsd", "vshufps", "vsqrtsd", "vstmxcsr", "vsubps",
        "vsubsd", "vucomisd", "vucomiss", "vunpcklpd", "vxorpd", "vxorps", "vzeroall", "vzeroupper", "xgetbv", "xorpd",
        "xorps",
        "vsubss", "vpmuldq", "vaddsubps", "vcvttsd2usi", "vcvttss2usi", "vmaxps", "vmovaps", "pfcmpge", "kmovb", "mpsadbw",
        "vextracti128", "vpbroadcastd", "vpbroadcastq", "vpcmpeqd", "vpcmpeqq", "vpermq", "vpextrq", "vpinsrq", "vpmuludq", "vpunpcklqdq"
    ]
    _vmx_group = [
        'invrpt', 'invvpid', 'vmcall', 'vmclear', 'vmfunc', 'vmlaunch', 'vmptrld', 'vmptrst', 'vmread', 'vmresume', 'vmwrite', 'vmxoff', 'vmxon'
    ]
    _registers = [
        "al", "bl", "cl", "dl",
        "ah", "bh", "ch", "dh",
        "ax", "bx", "cx", "dx", "sp", "bp", "si", "di",
        "eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi",
        # 64bit
        "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "sil", "dil", "bpl", "spl"
    ]
    _segment_registers = [
        # Segment Registers
        "cs", "ds", "es", "fs", "gs", "ss"
    ]
    _extended_registers = [
        # Extended Registers
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15"
    ]
    _control_registers = [
        # Debug Registers
        "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
        # Control Registers
        "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8",
        # Test Registers
        "tr3", "tr4", "tr5", "tr6", "tr7"
    ]

    @staticmethod
    def escapeMnemonic(mnemonic):
        mnemonic = mnemonic.split(" ")[-1]
        if mnemonic in IntelInstructionEscaper._aritlog_group:
            return "A"
        elif mnemonic in IntelInstructionEscaper._cfg_group:
            return "C"
        elif mnemonic in IntelInstructionEscaper._mem_group:
            return "M"
        elif mnemonic in IntelInstructionEscaper._stack_group:
            return "S"
        elif mnemonic in IntelInstructionEscaper._privileged_group:
            return "P"
        elif mnemonic in IntelInstructionEscaper._aes_group:
            return "Y"
        elif mnemonic in IntelInstructionEscaper._float_group:
            return "F"
        elif mnemonic in IntelInstructionEscaper._xmm_group:
            return "X"
        elif mnemonic in IntelInstructionEscaper._vmx_group:
            return "V"
        elif mnemonic == "nop":
            return "N"
        elif mnemonic == "error":
            return "U"
        else:
            LOGGER.error("********************************************** Unhandled mnemonic: %s", mnemonic)
            return "U"
        return mnemonic

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        escaped_field = ""
        if op_field == "":
            return ""
        if escape_registers:
            if op_field in IntelInstructionEscaper._registers:
                escaped_field = "REG"
            elif op_field in IntelInstructionEscaper._segment_registers:
                escaped_field = "SREG"
            elif op_field in IntelInstructionEscaper._extended_registers:
                escaped_field = "XREG"
            elif re.search("zmm[0-9]+", op_field):
                escaped_field = "XREG"
            elif op_field in IntelInstructionEscaper._control_registers:
                escaped_field = "CREG"
            elif op_field.startswith("st"):
                escaped_field = "FREG"
            elif op_field.startswith("mm"):
                escaped_field = "MMREG"
        if escape_pointers:
            if (op_field.startswith("xmmword ptr")
                    or op_field.startswith("ymmword ptr")
                    or op_field.startswith("zmmword ptr")
                    or op_field.startswith("xword ptr")
                    or op_field.startswith("tbyte ptr")
                    or op_field.startswith("qword ptr")
                    or op_field.startswith("dword ptr")
                    or op_field.startswith("word ptr")
                    or op_field.startswith("byte ptr")
                    or op_field.startswith("ptr")
                    or op_field.startswith("[")):
                escaped_field = "PTR"
        if escape_constants:
            # potentially include specific constants as extension to CONST
            try:
                op_as_int = int(op_field)
                # if op_as_int in [0, 1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0xFF, 0xFFFFFFFF, -1]:
                #     escaped_field += "_%d" % op_as_int
                escaped_field = "CONST"
            except:
                pass
            try:
                op_as_int = int(op_field, 16)
                # if op_as_int in [0, 1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0xFF, 0xFFFFFFFF, -1]:
                #     escaped_field += "_%d" % op_as_int
                escaped_field = "CONST"
            except:
                pass
            if ":" in op_field:
                escaped_field = "CONST"
        if not escaped_field:
            escaped_field = op_field
        return escaped_field

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        opstring = ins.operands
        op_fields = opstring.split(",")
        esc_regs = True
        esc_consts = True
        if offsets_only:
            if ins.mnemonic in [
                    "call", "lcall", "jmp", "ljmp",
                    "je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
                    "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz",
                    "loop", "loopne", "loope"]:
                return "OFFSET"
            esc_regs = False
            esc_consts = False
        escaped_fields = []
        for op_field in op_fields:
            escaped_fields.append(IntelInstructionEscaper.escapeField(op_field, escape_registers=esc_regs, escape_constants=esc_consts))
        return ", ".join(escaped_fields)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        escaped_sequence = ins.bytes
        # remove segment, operand, address, repeat override prefixes
        if ins.mnemonic in [
                "call", "lcall", "jmp", "ljmp",
                "loop", "loopne", "loope"]:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryJumpCall(ins)
            return escaped_sequence
        if ins.mnemonic in [
                "je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
                "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz"]:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if "ptr [0x" in ins.operands or "[rip + 0x" in ins.operands or "[rip - 0x" in ins.operands:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryPtrRef(ins)
        if lower_addr is not None and upper_addr is not None and ins.operands.startswith("0x") or ", 0x" in ins.operands:
            immediates = []
            for immediate_match in re.finditer(r"0x[0-9a-fA-F]{1,8}", ins.operands):
                immediate = int(immediate_match.group()[2:], 16)
                if lower_addr > 0x00100000 and lower_addr <= immediate < upper_addr:
                    immediates.append(immediate)
                    escaped_sequence = IntelInstructionEscaper.escapeBinaryValue(escaped_sequence, immediate)
        return escaped_sequence

    @staticmethod
    def escapeBinaryJumpCall(ins, escape_intraprocedural_jumps=False):
        clean_bytes = IntelInstructionEscaper.getByteWithoutPrefixes(ins)
        if escape_intraprocedural_jumps and (
                clean_bytes.startswith("7") or
                clean_bytes.startswith("e0") or
                clean_bytes.startswith("e1") or
                clean_bytes.startswith("e2") or
                clean_bytes.startswith("e3") or
                clean_bytes.startswith("eb")):
            return ins.bytes[:-2] + "??"
        if escape_intraprocedural_jumps and clean_bytes.startswith("0f8"):
            return ins.bytes[:-8] + "????????"
        # these should cover most cross-function references and absolute offsets
        if (clean_bytes.startswith("e8") or
                clean_bytes.startswith("e9")):
            return ins.bytes[:-8] + "????????"
        if clean_bytes.startswith("ff"):
            if len(clean_bytes) <= 8:
                # these seem to be all relative or register based instructions and need no escaping
                return ins.bytes
            if (clean_bytes.startswith("ff14") or
                    clean_bytes.startswith("ff15") or
                    clean_bytes.startswith("ff24") or
                    clean_bytes.startswith("ff25") or
                    clean_bytes.startswith("ffaa")):
                    # FF9*: call dword ptr [<reg> + <offset>] - seem all relative in our test data
                return ins.bytes[:-8] + "????????"
        if clean_bytes.startswith("48"):
            if clean_bytes.startswith("48ff61") and len(clean_bytes) == 8:
                # jmp qword/fword ptr [<register> + <offset>]
                # these are definitely found as interprocedurals but might also be intraprocedurals?
                return ins.bytes[:-2] + "??"
            if clean_bytes.startswith("48ff25"):
                # jmp qword ptr [rip + <offset>]
                return ins.bytes[:-8] + "????????"
        if (clean_bytes.startswith("ea") or
                clean_bytes.startswith("9a")):
                # 9A*: lcall dword ptr [<seg> + <offset>]
                # EA*: ljmp dword ptr [<seg> + <offset>]
            return ins.bytes[:-12] + "????????????"
        return ins.bytes

    @staticmethod
    def escapeBinaryPtrRef(ins):
        escaped_sequence = ins.bytes
        addr_match = re.search(r"\[(rip (\+|\-) )?(?P<dword_offset>0x[a-fA-F0-9]+)\]", ins.operands)
        if addr_match:
            offset = int(addr_match.group("dword_offset"), 16)
            if "rip -" in ins.operands:
                offset = 0x100000000 - offset
            #TODO we need to check if this is actually a 64bit absolute offset (e.g. used by movabs)
            try:
                packed_hex = str(codecs.encode(struct.pack("I", offset), 'hex').decode('ascii'))
            except:
                packed_hex = str(codecs.encode(struct.pack("L", offset), 'hex').decode('ascii'))
            num_occurrences = occurrences(ins.bytes, packed_hex)
            if num_occurrences == 1:
                escaped_sequence = ins.bytes.replace(packed_hex, "????????")
            elif num_occurrences == 2:
                escaped_sequence = ins.bytes.replace(packed_hex, "????????", 1)
                LOGGER.warning("IntelInstructionEscaper.escapeBinaryPtrRef: 2 occurrences for %s in %s (%s %s), escaping only the first one", packed_hex, ins.bytes, ins.mnemonic, ins.operands)
            elif num_occurrences > 2:
                LOGGER.warning("IntelInstructionEscaper.escapeBinaryPtrRef: more than 2 occurrences for %s", packed_hex)
        return escaped_sequence

    @staticmethod
    def escapeBinaryValue(escaped_sequence, value):
        packed_hex = str(codecs.encode(struct.pack("I", value), 'hex').decode('ascii'))
        num_occurrences = occurrences(escaped_sequence, packed_hex)
        if num_occurrences == 1:
            escaped_sequence = escaped_sequence.replace(packed_hex, "????????")
        elif num_occurrences == 2:
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            LOGGER.warning("IntelInstructionEscaper.escapeBinaryValue: 2 occurrences for %s in %s, escaped both, if they were non-overlapping", packed_hex, escaped_sequence)
        elif num_occurrences > 2:
            LOGGER.warning("IntelInstructionEscaper.escapeBinaryValue: more than 2 occurrences for %s", packed_hex)
        return escaped_sequence

    @staticmethod
    def getByteWithoutPrefixes(ins):
        ins_bytes = ins.bytes
        cleaned = ""
        is_cleaning = True
        for prefix_byte in [ins_bytes[i:i+2] for i in range(0, len(ins_bytes), 2)]:
            if is_cleaning and prefix_byte in ["26", "2e", "36", "3e", "64", "65", "66", "67", "f2", "f3"]:
                continue
            else:
                is_cleaning = False
                cleaned += prefix_byte
        return cleaned
