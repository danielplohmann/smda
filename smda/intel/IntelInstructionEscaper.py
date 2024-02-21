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
    """ Escaper to abstract information from disassembled instructions. Based on capstone disassembly. 
    Should now cover full instruction name mapping:
    https://github.com/capstone-engine/capstone/blob/31ea133e64cb6576524e61b734681260104d0a6f/arch/X86/X86MappingInsnName.inc#L168
    """

    _aritlog_group = [
        "aaa", "aad", "aam", "aas", "adc", "adcx", "add", "addb", "addl", "addq", "addw", 
        "adox", "and", "andnl", "andnq", "cdq",
        "cdqe", "daa", "das", "dec", "div", "idiv", "imul", "inc", "lzcnt", "mul",
        "mulx", "mulxl", "mulxq", "neg", "not", "or", "popcnt", "rcl", "rcr", "rol", "ror", "sal",
        "salc", "sar", "sbb", "shl", "shld", "shr", "shrd", "sub", "tzcnt", "xadd",
        "xor", "shlx", "shrx", "sarx",
        "rorxl", "rorxq", "sarxl", "sarxq", "shlxl", "shlxq", "shrxl", "shrxq", 
        # bit manipulation
        "bzhil", "bzhiq", 
        'bzhi', 'bextr', 'blcfill', 'blci', 'blcic', 'blcmsk', 'blcs', 'blsfill', 'blsi', 'blsic', 
        'blsmsk', 'blsr', 'tzmsk', 't1mskc',
        "bextrl", "bextrq", "blcfilll", "blcfillq", "blcicl", "blcicq", "blcil", "blciq", "blcmskl", 
        "blcmskq", "blcsl", "blcsq", "blsfilll", "blsfillq", "blsicl", "blsicq", "blsil", "blsiq", 
        "blsmskl", "blsmskq", "blsrl", "blsrq", "t1mskcl", "t1mskcq", "tzmskl", "tzmskq", 
    ]
    _cfg_group = [
        "arpl", "bound", "call", "clc", "cld", "cli", "cmc", "cmova", "cmovae", "cmovb",
        "cmovbe", "cmove", "cmovge", "cmovl", "cmovle", "cmovne", "cmovs", "cmp", "cmps", "cmpsb",
        "cmpsd", "cmpsw", "iret", "iretd", 'iretq', "ja", "jae", "jb", "jbe", "jcxz", "je",
        "jecxz", "jg", "jge", "jl", "jle", "jmp", "jne", "jno", "jnp", "jns",
        "jo", "jp", "jrcxz", "js", "lcall", "ljmp", "loop", "loope", "loopne", "ret",
        "retf", "retfq", "retn", "seta", "setae", "setb", "setbe", "sete", "setg", "setge",
        "setl", "setle", "setne", "setno", "setnp", "setns", "seto", "setp", "sets", "stc",
        "std", "sti", "test",
        # CET 
        'endbr32', 'endbr64'
    ]
    _mem_group = [
        "bsf", "bsr", "bswap", "bt", "btc", "btr", "bts", "cbw", "cmovg", "cmovno",
        "cmovnp", "cmovns", "cmovo", "cmovp", "cmpxchg", "cmpxchg8b", "cmpxchg16b", "cqo", "cwd", "cwde", "lahf",
        "lar", "lds", "lea", "les", "lfs", "lgs", "lods", "lodsb", "lodsd", "lodsq",
        "lodsw", "lsl", "lss", "maskmovq", 'maskmovdqu', "mov", "movabs", "movnti", "movntq", "movs", "movsb",
        "movabsq", "movb", "movl", 
        "movsd", "movsw", "movsx", "movsxd", "movzx", "rdmsr", "sahf", "scas", "scasb",
        "scasd", "scasq", "scasw", "stos", "stosb", "stosd", "stosq", "stosw", "wrmsr", "xabort",
        "xbegin", "xchg", "xlat", "xlatb", "movbe", "clflush",
        # 
        'movntdqa', 
        # direct store
        'movdir64b', 'movdiri',
        # segment bases
        'wrgsbase', 'wrfsbase', 'rdfsbase', 'rdgsbase', 'swapgs', 
        # bounds
        'bndcl', 'bndcn', 'bndcu', 'bndldx', 'bndmk', 'bndmov', 'bndstx'

    ]
    _stack_group = [
        "enter", "leave", "pop", "popad", "popal", "popf", "popfd", "popfq", "push", "pushad",
        "pushal", "pushf", "pushfd", "pushfq"
    ]
    # unused, for completeness
    _prefix_group = [
        'lock', 'rep', 'repne', 'rex64', 'data16', 
    ]
    _privileged_group = [
        "clts", "cpuid", "getsec", "hlt", "in", "ins", "insb", "insd", "insw", "int",
        "int1", "int3", "into", "invd", "invlpg", "lfence", "lgdt", "lidt", "lldt", "lmsw",
        "ltr", "mfence", "out", "outs", "outsb", "outsd", "outsw", "pause", "prefetchnta", "prefetcht0",
        "prefetcht1", "prefetcht2", "prefetchw", "rdpmc", "rdtsc", "rsm", "sfence", "sgdt", "sidt", "sldt",
        "smsw", "str", "syscall", "sysenter", "sysexit", "sysret", "ud", "ud2", "ud2b", "wait",
        "wbinvd", "ud0", "ud1",
        'sysexitq', 'sysretq',
        # memory protection and cache
        'wrpkru', 'wbnoinvd', 'clac', 'stac',
        # enclaves
        'encls', 'enclu', 'enclv',
        # shadow stack
        'cldemote', 'clflushopt', 'clrssbsy', 'clwb', 'clzero', 'incsspq', 'rdsspq', 'saveprevssp', 'rstorssp', 'wrssq', 'wrussq', 'setssbsy',
        # no idea where to fit these otherwise :)
        'pconfig', 'invpcid', 'rdpid', 'rdpkru', 'rdtscp', 
        'umonitor', 'uwait', 'umwait', 'mwait', 'mwaitx', 'monitor', 'monitorx', 'tpause', 
        "xsaveopt", 'xacquire', 'xend', 'xrelease', 'xrstor', 'xrstor64', 'xrstors', 'xrstors64', 'xsave', 
        'xsave64', 'xsavec', 'xsavec64', 'xsaveopt64', 'xsaves', 'xsaves64', 'xsetbv', 'xtest', "pcommit",
        # AMD lightweight profiling
        'llwpcb', 'lwpins', 'slwpcb', 'lwpval', 

    ]
    _crypto_group = [
        'aesdec', 'aesdeclast', 'aesenc', 'aesenc128kl', 'aesenc256kl', 'aesenclast', 'aesencwide128kl', 'aesencwide256kl', 'aesimc', 
        'aeskeygenassist', 'ccs_encrypt', 'ccs_hash', 'encodekey128', 'encodekey256', 'loadiwkey', 'montmul', 'pclmulqdq', 'pclmullqlqdq', 
        'pclmulhqlqdq', 'pclmullqqhdq', 'pclmulhqqhdq', "vpclmulqdq", 
        'rdrand', 'rdseed', "rdrandl", "rdrandq", "rdrandw", "rdseedl", "rdseedq", "rdseedw", 
        'sha1msg1', 'sha1msg2', 'sha1nexte', 'sha1rnds4', 'sha256msg1', 
        'sha256msg2', 'sha256rnds2', 'xcryptcbc', 'xcryptcfb', 'xcryptctr', 'xcryptecb', 'xcryptofb', 'xsha1', 'xsha256', 'xstore',
        'vaesdec', 'vaesdeclast', 'vaesenc', 'vaesenclast', 'vaesimc', 'vaeskeygenassist', "crc32", "crc32b", "crc32l", "crc32q", "crc32w",
        'gf2p8affineinvqb', 'gf2p8affineqb', 'gf2p8mulb',
        ]

    _float_group = [
        "f2xm1", "fabs", "fadd", "faddp", "fbld", "fbstp", "fchs", "fcmovb", "fcmovbe", "fcmove",
        "fcmovnb", "fcmovnbe", "fcmovne", "fcmovnu", "fcmovu", "fcom", "fcomi", "fcomp", "fcompi", "fcompp",
        "fcos", "fdecstp", "fdiv", "fdivp", "fdivr", "fdivrp", "ffree", "fiadd", "ficom", "ficomp",
        "fidiv", "fidivr", "fild", "fimul", "fincstp", "fist", "fistp", "fisttp", "fisub", "fisubr",
        "fld", "fld1", "fldcw", "fldenv", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fldpi", "fldz",
        "filds", "flds", 
        "fmul", "fmulp", "fnclex", "fninit", "fnsave", "fnstcw", "fnstenv", "fnstsw", "fpatan",
        "fprem", "fprem1", "fptan", "frndint", "frstor", "fscale", "fsetpm", "fsin", "fsincos", "fsqrt",
        "fst", "fstp", "fstpnce", "fsub", "fsubp", "fsubr", "fsubrp", "ftst", "fucom", "fucomi",
        "fucomp", "fucompi", "fucompp", "fxam", "fxch", "fyl2x", "fyl2xp1",
        "fcomip", "ffreep", "fucomip", 'fcmovnp', 
        "fxsave", 'fxsave64', "fxrstor", "fxtract", 'fxrstor64', 
    ]

    _nop_group = [
        "nop", "fnop", "fdisi8087_nop", "feni8087_nop", 
    ]

    _xmm_group = [
        # masks
        'kaddb', 'kaddd', 'kaddq', 'kaddw', 'kandb', 'kandd', 'kandnb', 'kandnd', 'kandnq', 'kandnw', 'kandq', 'kandw', 'kmovd', 
        'kmovq', 'kmovw', 'knotb', 'knotd', 'knotq', 'knotw', 'korb', 'kord', 'korq', 'kortestb', 'kortestd', 'kortestq', 
        'kortestw', 'korw', 'kshiftlb', 'kshiftld', 'kshiftlq', 'kshiftlw', 'kshiftrb', 'kshiftrd', 'kshiftrq', 'kshiftrw', 
        'ktestb', 'ktestd', 'ktestq', 'ktestw', 'kunpckbw', 'kunpckdq', 'kunpckwd', 'kxnorb', 'kxnord', 'kxnorq', 'kxnorw', 
        'kxorb', 'kxord', 'kxorq', 'kxorw',
        # 
        'vcmp',
        # ps
        "subps", "addps", "andnps", "andps", "cmpeqps", "cmpltps", "cvtpd2ps","cvtdq2ps", "cmpps", "cvtpi2ps", 
        "maxps", "divps", "movaps", "minps", "movhlps","movhps", "movlhps", "movlps", "movmskps", "movntps", 
        "movups", "mulps", "orps", "rsqrtps", "shufps", "rcpps", "sqrtps", "unpckhps", "unpcklps",
        "vandps", "vmovlhps", "vmovups", "vmulps", "vorps", "vshufps", "vsubps", "vxorps", "xorps",
        "vaddsubps", "vmaxps", "vmovaps", 'vaddps', 
        'addsubps', 'blendps', 'blendvps', 'dpps', 'extractps', 'haddps', 'hsubps', 'insertps', 'roundps', 'vandnps', 'vblendmps', 'vblendps',
        'vblendvps', 'vcmpps', 'vcompressps', 'vcvtdq2ps', 'vcvtpd2ps', 'vcvtph2ps', 'vcvtqq2ps', 'vcvtudq2ps', 'vcvtuqq2ps', 'vdivps', 'vdpps',
        'vexp2ps', 'vexpandps', 'vextractps', 'vfixupimmps', 'vfpclassps', 'vfrczps', 'vgatherdps', 'vgatherpf0dps', 'vgatherpf0qps', 'vgatherpf1dps',
        'vgatherpf1qps', 'vgatherqps', 'vgetexpps', 'vgetmantps', 'vhaddps', 'vhsubps', 'vinsertps', 'vmaskmovps', 'vminps', 'vmovhlps', 'vmovhps',
        'vmovlps', 'vmovmskps', 'vmovntps', 'vpermi2ps', 'vpermil2ps', 'vpermilps', 'vpermps', 'vpermt2ps', 'vrangeps', 'vrcp14ps', 'vrcp28ps',
        'vrcpps', 'vreduceps', 'vrndscaleps', 'vroundps', 'vrsqrt14ps', 'vrsqrt28ps', 'vrsqrtps', 'vscalefps', 'vscatterdps', 'vscatterpf0dps',
        'vscatterpf0qps', 'vscatterpf1dps', 'vscatterpf1qps', 'vscatterqps', 'vsqrtps', 'vtestps', 'vunpckhps', 'vunpcklps', 
        # pd
        "addpd", "addsubpd", "andnpd", "andpd", "cmpltpd", "cmpneqpd", "cmpnlepd", "cvtdq2pd", "cvtps2pd",
        "divpd", "haddpd", "maxpd", "minpd", "movapd", "movhpd", "movlpd", "movmskpd", "movupd", "mulpd", 
        "orpd", "shufpd", "sqrtpd", "subpd", "unpckhpd", "unpcklpd",  "vaddpd", "vandnpd", "vandpd", 
        "vcmppd", "vcvtdq2pd", "vcvtps2pd", "vfmadd132pd", "vfmsubpd", "vhaddpd", "vfmsubaddpd", 
        "vminpd", "vmovapd", "vmulpd", "vorpd", "vunpcklpd", "vxorpd", "xorpd",  'vaddsubpd', 
        'blendpd', 'blendvpd', 'cmppd', 'cvtpi2pd', 'dppd', 'hsubpd', 'incsspd', 'movntpd', 'pswapd', 'rdsspd', 'roundpd', 'vblendmpd', 
        'vblendpd', 'vblendvpd', 'vcompresspd', 'vcvtqq2pd', 'vcvtudq2pd', 'vcvtuqq2pd', 'vdivpd', 'vdppd', 'vexp2pd', 'vexpandpd', 
        'vfixupimmpd', 'vfpclasspd', 'vfrczpd', 'vgatherdpd', 'vgatherpf0dpd', 'vgatherpf0qpd', 'vgatherpf1dpd', 'vgatherpf1qpd', 
        'vgatherqpd', 'vgetexppd', 'vgetmantpd', 'vhsubpd', 'vmaskmovpd', 'vmaxpd', 'vmovhpd', 'vmovlpd', 'vmovmskpd', 'vmovntpd', 
        'vmovupd', 'vpcmpd', 'vpermi2pd', 'vpermil2pd', 'vpermilpd', 'vpermpd', 'vpermt2pd', 'vrangepd', 'vrcp14pd', 'vrcp28pd', 
        'vreducepd', 'vrndscalepd', 'vroundpd', 'vrsqrt14pd', 'vrsqrt28pd', 'vscalefpd', 'vscatterdpd', 'vscatterpf0dpd', 'vscatterpf0qpd', 
        'vscatterpf1dpd', 'vscatterpf1qpd', 'vscatterqpd', 'vshufpd', 'vsqrtpd', 'vsubpd', 'vtestpd', 'vunpckhpd',
        # v4f
        'v4fmaddps', 'v4fmaddss', 'v4fnmaddps', 'v4fnmaddss',
        # FMA3
        'vfmadd132ps', 'vfmadd132ss', 'vfmadd213pd', 'vfmadd213ps', 'vfmadd231pd', 'vfmadd231ps', 'vfmaddpd',
        'vfmaddps', 'vfmaddsd', 'vfmaddss' ,'vfmaddsub132pd', 'vfmaddsub132ps', 'vfmaddsub213pd', 'vfmaddsub213ps',
        'vfmaddsub231pd', 'vfmaddsub231ps', 'vfmaddsubpd', 'vfmaddsubps', 'vfmsub132pd', 'vfmsub132ps', 'vfmsub132ss',
        'vfmsub213pd', 'vfmsub213ps', 'vfmsub231pd', 'vfmsub231ps', 'vfmsub231sd', 'vfmsub231ss', 'vfmsubadd132pd',
        'vfmsubadd132ps', 'vfmsubadd213pd', 'vfmsubadd213ps', 'vfmsubadd231pd', 'vfmsubadd231ps', 'vfmsubaddps',
        'vfmsubps', 'vfmsubsd', 'vfmsubss', 'vfnmadd132pd', 'vfnmadd132ps', 'vfnmadd132ss', 'vfnmadd213pd',
        'vfnmadd213ps', 'vfnmadd213ss', 'vfnmadd231pd', 'vfnmadd231ps', 'vfnmadd231ss', 'vfnmaddpd', 'vfnmaddps',
        'vfnmaddsd', 'vfnmaddss', 'vfnmsub132pd', 'vfnmsub132ps', 'vfnmsub132sd', 'vfnmsub132ss', 'vfnmsub213pd',
        'vfnmsub213ps', 'vfnmsub213sd', 'vfnmsub213ss', 'vfnmsub231pd', 'vfnmsub231ps', 'vfnmsub231sd', 'vfnmsub231ss',
        'vfnmsubpd', 'vfnmsubps', 'vfnmsubsd', 'vfnmsubss',
        #
        'valignd', 'valignq', 'vbroadcastf128', 'vbroadcastf32x2', 'vbroadcastf32x4', 'vbroadcastf32x8', 'vbroadcastf64x2', 
        'vbroadcastf64x4', 'vbroadcasti32x2', 'vbroadcasti32x4', 'vbroadcasti32x8', 'vbroadcasti64x2', 'vbroadcasti64x4', 'vcvtpd2qq', 
        'vcvtpd2udq', 'vcvtpd2uqq', 'vcvtps2dq', 'vcvtps2ph', 'vcvtps2qq', 'vcvtps2udq', 'vcvtps2uqq', 'vcvtsd2si', 'vcvtsd2usi', 'vcvtss2usi', 
        'vcvttpd2qq', 'vcvttpd2udq', 'vcvttpd2uqq', 'vcvttps2dq', 'vcvttps2qq', 'vcvttps2udq', 'vcvttps2uqq', 'vcvttss2si', 'vdbpsadbw', 
        'vextractf128', 'vextractf32x4', 'vextractf32x8', 'vextractf64x2', 'vextractf64x4', 'vextracti32x4', 'vextracti32x8', 'vextracti64x2', 
        'vextracti64x4', 'vgf2p8affineinvqb', 'vgf2p8affineqb', 'vgf2p8mulb', 'vinsertf128', 'vinsertf32x4', 'vinsertf32x8', 'vinsertf64x2', 
        'vinsertf64x4', 'vinserti32x4', 'vinserti32x8', 'vinserti64x2', 'vinserti64x4', 'vlddqu', 'vmaskmovdqu', 'vmovdqa32', 'vmovdqa64', 
        'vmovdqu16', 'vmovdqu32', 'vmovdqu64', 'vmovdqu8', 'vmovntdqa', 'vmovshdup', 'vmovsldup', 'vmpsadbw', 'vp4dpwssds', 'vpabsb', 'vpabsq', 
        'vpabsw', 'vpacksswb', 'vpackusdw', 'vpandd', 'vpandnd', 'vpandnq', 'vpandq', 'vpblendmb', 'vpblendmd', 'vpblendmq', 'vpblendmw', 
        'vpblendvb', 'vpbroadcastmb2q', 'vpbroadcastmw2d', 'vpbroadcastw', 'vpcmov', 'vpcmp', 'vpcmpb', 'vpcmpestri', 'vpcmpestrm', 'vpcmpgtb', 
        'vpcmpgtq', 'vpcmpgtw', 'vpcmpistri', 'vpcmpistrm', 'vpcmpq', 'vpcmpub', 'vpcmpud', 'vpcmpuq', 'vpcmpuw', 'vpcmpw', 'vpcom', 'vpcomb', 
        'vpcomd', 'vpcompressb', 'vpcompressq', 'vpcompressw', 'vpcomq', 'vpcomub', 'vpcomud', 'vpcomuq', 'vpcomuw', 'vpcomw', 'vpconflictd', 
        'vpconflictq', 'vpdpbusds', 'vpdpwssds', 'vpermb', 'vpermi2b', 'vpermi2d', 'vpermi2q', 'vpermi2w', 'vpermt2b', 'vpermt2d', 'vpermt2q', 
        'vpermt2w', 'vpermw', 'vpexpandb', 'vpexpandd', 'vpexpandq', 'vpexpandw', 'vpextrb', 'vpextrd', 'vpextrw', 'vpgatherdd', 'vpgatherdq', 
        'vpgatherqd', 'vpgatherqq', 'vphaddbd', 'vphaddbq', 'vphaddbw', 'vphaddd', 'vphadddq', 'vphaddsw', 'vphaddubd', 'vphaddubq', 'vphaddubw', 
        'vphaddudq', 'vphadduwd', 'vphadduwq', 'vphaddw', 'vphaddwd', 'vphaddwq', 'vphminposuw', 'vphsubbw', 'vphsubd', 'vphsubdq', 'vphsubsw', 
        'vphsubw', 'vphsubwd', 'vpinsrb', 'vpinsrw', 'vplzcntd', 'vplzcntq', 'vpmacsdd', 'vpmacsdqh', 'vpmacsdql', 'vpmacssdd', 'vpmacssdqh', 
        'vpmacssdql', 'vpmacsswd', 'vpmacssww', 'vpmacswd', 'vpmacsww', 'vpmadcsswd', 'vpmadcswd', 'vpmadd52huq', 'vpmadd52luq', 'vpmaddubsw', 
        'vpmaskmovd', 'vpmaskmovq', 'vpmaxsb', 'vpmaxsq', 'vpmaxud', 'vpmaxuq', 'vpmaxuw', 'vpminsb', 'vpminsq', 'vpminsw', 'vpminub', 'vpminud', 
        'vpminuq', 'vpminuw', 'vpmovb2m', 'vpmovd2m', 'vpmovdb', 'vpmovdw', 'vpmovm2b', 'vpmovm2d', 'vpmovm2q', 'vpmovm2w', 'vpmovq2m', 'vpmovqb', 
        'vpmovqd', 'vpmovqw', 'vpmovsdb', 'vpmovsdw', 'vpmovsqb', 'vpmovsqd', 'vpmovsqw', 'vpmovswb', 'vpmovsxbd', 'vpmovsxbq', 'vpmovsxbw', 
        'vpmovsxdq', 'vpmovsxwd', 'vpmovsxwq', 'vpmovusdb', 'vpmovusdw', 'vpmovusqb', 'vpmovusqd', 'vpmovusqw', 'vpmovuswb', 'vpmovw2m', 'vpmovwb', 
        'vpmovzxbd', 'vpmovzxbq', 'vpmovzxbw', 'vpmovzxdq', 'vpmovzxwd', 'vpmovzxwq', 'vpmulhrsw', 'vpmulhuw', 'vpmulhw', 'vpmulld', 'vpmullq', 
        'vpmultishiftqb', 'vpopcntb', 'vpopcntd', 'vpopcntq', 'vpopcntw', 'vpord', 'vporq', 'vpperm', 'vprold', 'vprolq', 'vprolvd', 'vprolvq', 
        'vprord', 'vprorq', 'vprorvd', 'vprorvq', 'vprotb', 'vprotw', 'vpscatterdd', 'vpscatterdq', 'vpscatterqd', 'vpscatterqq', 'vpshab', 
        'vpshad', 'vpshaq', 'vpshaw', 'vpshlb', 'vpshld', 'vpshldd', 'vpshldq', 'vpshldvd', 'vpshldvq', 'vpshldvw', 'vpshldw', 'vpshlq', 
        'vpshlw', 'vpshrdd', 'vpshrdq', 'vpshrdvd', 'vpshrdvq', 'vpshrdvw', 'vpshrdw', 'vpshufbitqmb', 'vpshufhw', 'vpshuflw', 'vpsignb', 
        'vpsignd', 'vpsignw', 'vpsllvd', 'vpsllvq', 'vpsllvw', 'vpsllw', 'vpsraq', 'vpsravd', 'vpsravq', 'vpsravw', 'vpsrlvd', 'vpsrlvq', 
        'vpsrlvw', 'vpsrlw', 'vpsubb', 'vpsubsb', 'vpsubsw', 'vpsubusw', 'vpternlogd', 'vpternlogq', 'vptestmb', 'vptestmd', 'vptestmq', 
        'vptestmw', 'vptestnmb', 'vptestnmd', 'vptestnmq', 'vptestnmw', 'vpunpcklbw', 'vpunpcklwd', 'vpxord', 'vpxorq', 'vshuff32x4', 
        'vshuff64x2', 'vshufi32x4', 'vshufi64x2',
        # 
        'movq2dq', 'movshdup', 
        'extrq', 'insertq', 
        'cvtpd2pi', 'cvttpd2pi', 
        "pdepl", "pdepq", "pextl", "pextq", 
        'pabsb', 'packusdw', 'pavgusb', 'pblendvb', 'pcmpestrm', 'pcmpgtq', 'pcmpistrm', 'pdep', 'pext', 'pextrq', 'pf2id', 'pf2iw', 
        'pfacc', 'pfadd', 'pfcmpeq', 'pfcmpgt', 'pfmax', 'pfmin', 'pfmul', 'pfnacc', 'pfpnacc', 'pfrcp', 'pfrcpit1', 'pfrcpit2', 
        'pfrsqit1', 'pfrsqrt', 'pfsub', 'pfsubr', 'phaddsw', 'phaddw', 'phminposuw', 'phsubd', 'phsubw', 'pi2fd', 'pi2fw', 'pmuldq', 
        'pmulhrsw', 'pmulhrw', 'prefetch', 'prefetchwt1', 'psignb', 'psignd', 'ptest', 'ptwrite',
        'pmaxsb', 'pmaxud', 'pmaxuw', 'pminsb', 'pminud', 'pminuw', 'pmovsxbd', 'pmovsxbq', 'pmovsxbw', 'pmovsxwd', 'pmovsxwq', 'pmovzxbd', 
        'pmovzxbq', 'pmovzxbw', 'pmovzxdq', 'pmovzxwq',
        'movntsd', 'pmaxsd', 'pminsd', 'vbroadcastsd', 'vcmpsd', 'vcvtsi2sd', 'vcvtss2sd', 'vcvtusi2sd', 'vfixupimmsd', 
        'vfpclasssd', 'vfrczsd', 'vgetexpsd', 'vgetmantsd', 'vp4dpwssd', 'vpabsd', 'vpcompressd', 'vpdpbusd', 'vpdpwssd', 
        'vpmaxsd', 'vpminsd', 'vrangesd', 'vrcp14sd', 'vrcp28sd', 'vreducesd', 'vrndscalesd', 'vrsqrt14sd', 'vrsqrt28sd', 'vscalefsd', 'wrssd', 'wrussd',
        'movntss', 'roundss', 'rsqrtss', 'vbroadcastss', 'vcmpss', 'vcomiss', 'vcvtusi2ss', 'vdivss', 'vfixupimmss', 'vfpclassss', 
        'vfrczss', 'vgetexpss', 'vgetmantss', 'vminss', 'vmulss', 'vrangess', 'vrcp14ss', 'vrcp28ss', 'vreducess', 'vrndscaless', 
        'vroundss', 'vrsqrt14ss', 'vrsqrt28ss', 'vrsqrtss', 'vscalefss', 'vsqrtss',
        "movss", 'cmpss',
        "addsd", "addss",  "andn", 
        "cmpeqsd", "cmplesd", "cmpltsd", "cmpneqsd", "cmpneqss", 
        "cmpnlesd", "cmpnltsd", "cmpsq", "comisd", "comiss", "cvtpd2dq", 
        "cvtps2dq",  "cvtps2pi", "cvtsd2si", "cvtsd2ss", "cvtsi2sd", "cvtsi2ss", "cvtss2sd", "cvtss2si",
        "cvttpd2dq", "cvttps2dq", "cvttps2pi", "cvttsd2si", "cvttss2si", "divsd", "divss", "emms",
        "femms", "lddqu", "ldmxcsr", "maxsd", "maxss", 
        "minsd", "minss", "movd", "movddup", "movdq2q", "movdqa", "movdqu", 
        "movntdq", "movq",
        "movsldup", "movsq", "mulsd", "mulss", 
        "pabsd", "pabsw", "packssdw", "packsswb", "packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw",
        "paddusb", "paddusw", "paddw", "palignr", "pand", "pandn", "pavgb", "pavgw", "pblendw", 
        "pcmpeqb", "pcmpeqd", "pcmpeqq", "pcmpeqw", "pcmpestri", "pcmpgtb", "pcmpgtd", "pcmpgtw", "pcmpistri", "pextrb",
        "pextrd", "pextrw", "phaddd", "phsubsw", "pinsrb", "pinsrd", "pinsrq", "pinsrw", "pmaddubsw", "pmaddwd",
        "pmaxsw", "pmaxub", "pminsw", "pminub", "pmovmskb", "pmovsxdq", "pmovzxwd", "pmulhuw", "pmulhw", "pmulld", "pmullw",
        "pmuludq", "popaw", "por", "psadbw", "pshufb", "pshufd", "pshufhw", "pshuflw", "pshufw", "psignw",
        "pslld", "pslldq", "psllq", "psllw", "psrad", "psraw", "psrld", "psrldq", "psrlq", "psrlw",
        "psubb", "psubd", "psubq", "psubsb", "psubsw", "psubusb", "psubusw", "psubw", "punpckhbw", "punpckhdq",
        "punpckhqdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklqdq", "punpcklwd", "pushaw", "pxor", "rcpss",
        "rorx", "roundsd", "sqrtsd", "sqrtss", "stmxcsr", 
            "subsd", "subss", "ucomisd", "ucomiss", 
        "vaddsd", "vaddss", "vbroadcasti128", "vcmplesd", "vcmpnltsd", "vcomisd",
        "vcvtpd2dq",  "vcvtsd2ss", "vcvtsi2ss", "vcvtss2si", "vcvttpd2dq", "vcvttsd2si", "vdivsd", "verr",
        "verw",  "vfmadd132sd", "vfmadd213sd", "vfmadd213ss", "vfmadd231sd", "vfmadd231ss", "vfmsub132sd", "vfmsub213sd", "vfmsub213ss",
        "vfnmadd132sd", "vfnmadd213sd", "vfnmadd231sd", "vinserti128", "vldmxcsr", "vmaxsd", "vmaxss",
        "vminsd", "vmovd", "vmovddup", "vmovdqa", "vmovdqu", "vmovntdq", "vmovq",
        "vmovsd", "vmovss", "vmulsd", "vpackssdw", "vpackuswb",
        "vpaddb", "vpaddd", "vpaddq", "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw", "vpaddw", "vpalignr", "vpand",
        "vpandn", "vpavgb", "vpavgw", "vpblendd", "vpblendw", "vpbroadcastb", "vpcmpeqb", "vpcmpeqw", "vpcmpgtd",
        "vperm2f128", "vperm2i128", "vpermd", "vpinsrd", "vpmaddwd", "vpmaxsw", "vpmaxub", "vpmovmskb", "vpmullw", "vpor",
        "vprotd", "vprotq", "vpsadbw", "vpshufb", "vpshufd", "vpslld", "vpslldq", "vpsllq", "vpsrad", "vpsraw",
        "vpsrld", "vpsrldq", "vpsrlq", "vpsubd", "vpsubq", "vpsubusb", "vpsubw", "vptest", "vpunpckhbw", "vpunpckhdq",
        "vpunpckhqdq", "vpunpckhwd", "vpunpckldq", "vpxor", "vrcpss", "vroundsd", "vsqrtsd", "vstmxcsr", 
        "vsubsd", "vucomisd", "vucomiss", "vzeroall", "vzeroupper", "xgetbv", 
        
        "vsubss", "vpmuldq",  "vcvttsd2usi", "vcvttss2usi", "pfcmpge", "kmovb", "mpsadbw",
        "vextracti128", "vpbroadcastd", "vpbroadcastq", "vpcmpeqd", "vpcmpeqq", "vpermq", "vpextrq", "vpinsrq", "vpmuludq", "vpunpcklqdq",
        # cmp equivalents
        "cmpeqpd", "cmpeqss", "cmplepd", "cmpleps", "cmpless", "cmpltss", "cmpneqps", "cmpnleps", "cmpnless", "cmpnltpd", "cmpnltps", "cmpnltss", "cmpordpd", 
        "cmpordps", "cmpordsd", "cmpordss", "cmpunordpd", "cmpunordps", "cmpunordsd", "cmpunordss",
        # more emmitable instruction decodings
        "vcmpeq_ospd", "vcmpeq_osps", "vcmpeq_ossd", "vcmpeq_osss", "vcmpeq_uqpd", "vcmpeq_uqps", "vcmpeq_uqsd", "vcmpeq_uqss", "vcmpeq_uspd", 
        "vcmpeq_usps", "vcmpeq_ussd", "vcmpeq_usss", "vcmpeqpd", "vcmpeqps", "vcmpeqsd", "vcmpeqss", "vcmpfalse_ospd", "vcmpfalse_osps", 
        "vcmpfalse_ossd", "vcmpfalse_osss", "vcmpfalsepd", "vcmpfalseps", "vcmpfalsesd", "vcmpfalsess", "vcmpge_oqpd", "vcmpge_oqps", "vcmpge_oqsd", 
        "vcmpge_oqss", "vcmpgepd", "vcmpgeps", "vcmpgesd", "vcmpgess", "vcmpgt_oqpd", "vcmpgt_oqps", "vcmpgt_oqsd", "vcmpgt_oqss", "vcmpgtpd", 
        "vcmpgtps", "vcmpgtsd", "vcmpgtss", "vcmple_oqpd", "vcmple_oqps", "vcmple_oqsd", "vcmple_oqss", "vcmplepd", "vcmpleps", "vcmpless", 
        "vcmplt_oqpd", "vcmplt_oqps", "vcmplt_oqsd", "vcmplt_oqss", "vcmpltpd", "vcmpltps", "vcmpltsd", "vcmpltss", "vcmpneq_oqpd", "vcmpneq_oqps", 
        "vcmpneq_oqsd", "vcmpneq_oqss", "vcmpneq_ospd", "vcmpneq_osps", "vcmpneq_ossd", "vcmpneq_osss", "vcmpneq_uspd", "vcmpneq_usps", 
        "vcmpneq_ussd", "vcmpneq_usss", "vcmpneqpd", "vcmpneqps", "vcmpneqsd", "vcmpneqss", "vcmpnge_uqpd", "vcmpnge_uqps", "vcmpnge_uqsd", 
        "vcmpnge_uqss", "vcmpngepd", "vcmpngeps", "vcmpngesd", "vcmpngess", "vcmpngt_uqpd", "vcmpngt_uqps", "vcmpngt_uqsd", "vcmpngt_uqss", 
        "vcmpngtpd", "vcmpngtps", "vcmpngtsd", "vcmpngtss", "vcmpnle_uqpd", "vcmpnle_uqps", "vcmpnle_uqsd", "vcmpnle_uqss", "vcmpnlepd", 
        "vcmpnleps", "vcmpnlesd", "vcmpnless", "vcmpnlt_uqpd", "vcmpnlt_uqps", "vcmpnlt_uqsd", "vcmpnlt_uqss", "vcmpnltpd", "vcmpnltps", 
        "vcmpnltss", "vcmpord_spd", "vcmpord_sps", "vcmpord_ssd", "vcmpord_sss", "vcmpordpd", "vcmpordps", "vcmpordsd", "vcmpordss", 
        "vcmptrue_uspd", "vcmptrue_usps", "vcmptrue_ussd", "vcmptrue_usss", "vcmptruepd", "vcmptrueps", "vcmptruesd", "vcmptruess", "vcmpunord_spd", 
        "vcmpunord_sps", "vcmpunord_ssd", "vcmpunord_sss", "vcmpunordpd", "vcmpunordps", "vcmpunordsd", "vcmpunordss", "vcvtpd2dqx", 
        "vcvtpd2dqy", "vcvtpd2psx", "vcvtpd2psy", "vcvtsi2sdl", "vcvtsi2sdq", "vcvtsi2ssl", "vcvtsi2ssq", "vcvttpd2dqx", "vcvttpd2dqy"
    ]
    _vm_group = [
        'clgi', 'invept', 'invvpid', 'invlpga', 'psmash', 'pvalidate', 'rmpadjust', 'rmpquery', 'rmpupdate', 'seamcall', 'seamops', 'seamret', 
        'skinit', 'stgi', 'tdcall', 'vmmcall', 'vmcall', 'vmclear', 'vmfunc', 'vmgexit', 'vmlaunch', 'vmload', 'vmread', 'vmresume', 'vmrun', 
        'vmsave', 'vmptrld', 'vmptrst', 'vmwrite', 'vmxon', 'vmxoff'
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
        elif mnemonic in IntelInstructionEscaper._crypto_group:
            return "Y"
        elif mnemonic in IntelInstructionEscaper._float_group:
            return "F"
        elif mnemonic in IntelInstructionEscaper._xmm_group:
            return "X"
        elif mnemonic in IntelInstructionEscaper._vm_group:
            return "V"
        elif mnemonic in IntelInstructionEscaper._nop_group:
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
    def escapeToOpcodeOnly(ins):
        escaped_sequence = ""
        ins_bytes = ins.bytes
        cleaned = ""
        is_cleaning = True
        for target_byte in [ins_bytes[i:i+2] for i in range(0, len(ins_bytes), 2)]:
            if is_cleaning and target_byte in ["26", "2e", "36", "3e", "64", "65", "66", "67", "f2", "f3"]:
                escaped_sequence += target_byte
            else:
                is_cleaning = False
                cleaned += target_byte
        cap_ins = ins.getDetailed()
        opcode_length = 0
        if cap_ins.rex:
            # we need to add one, because we are apparently in 64bit mode and have a REX prefix
            opcode_length += 1
        if (cap_ins.rex and cleaned[2:].startswith("00")) or cleaned.startswith("00"):
            # this can only be ADD PTR, REG with exactly one opcode bytes 
            opcode_length += 1
        elif (cap_ins.rex and cleaned[2:].startswith("0f00")) or cleaned.startswith("0f00"):
            # this can only be *LDT/*TR/VER* with exactly two opcode bytes 
            opcode_length += 2
        else:
            for field in cap_ins.opcode:
                if field != 0:
                    opcode_length += 1
        escaped_sequence += cleaned[:opcode_length*2] + "?" * (len(cleaned) - opcode_length*2)
        return escaped_sequence

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        escaped_sequence = ins.bytes
        # remove segment, operand, address, repeat override prefixes
        if ins.mnemonic in [
                "call", "lcall", "jmp", "ljmp",
                "loop", "loopne", "loope"]:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if ins.mnemonic in [
                "je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
                "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz"]:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if "ptr [0x" in ins.operands or "[rip + 0x" in ins.operands or "[rip - 0x" in ins.operands:
            escaped_sequence = IntelInstructionEscaper.escapeBinaryPtrRef(ins)
        if lower_addr is not None and upper_addr is not None and (ins.operands.startswith("0x") or ", 0x" in ins.operands or "+ 0x" in ins.operands or "- 0x" in ins.operands):
            immediates = []
            for immediate_match in re.finditer(r"0x[0-9a-fA-F]{1,8}", ins.operands):
                immediate = int(immediate_match.group()[2:], 16)
                if lower_addr > 0x00100000 and lower_addr <= immediate < upper_addr:
                    immediates.append(immediate)
                    escaped_sequence = IntelInstructionEscaper.escapeBinaryValue(ins, escaped_sequence, immediate)
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
                packed_hex = str(codecs.encode(struct.pack("Q", offset), 'hex').decode('ascii'))
            num_occurrences = occurrences(ins.bytes, packed_hex)
            if num_occurrences == 1:
                escaped_sequence = ins.bytes.replace(packed_hex, "????????")
            elif num_occurrences == 2:
                escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
                LOGGER.warning("IntelInstructionEscaper.escapeBinaryPtrRef: 2 occurrences for %s in %s (%s %s), escaping only the second one", packed_hex, ins.bytes, ins.mnemonic, ins.operands)
            elif num_occurrences > 2:
                LOGGER.warning("IntelInstructionEscaper.escapeBinaryPtrRef: more than 2 occurrences for %s", packed_hex)
        return escaped_sequence

    @staticmethod
    def escapeBinaryValue(ins, escaped_sequence, value):
        packed_hex = str(codecs.encode(struct.pack("I", value), 'hex').decode('ascii'))
        num_occurrences = occurrences(escaped_sequence, packed_hex)
        if num_occurrences == 1:
            escaped_sequence = escaped_sequence.replace(packed_hex, "????????")
        elif num_occurrences == 2:
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            LOGGER.warning("IntelInstructionEscaper.escapeBinaryValue: 2 occurrences for %s in %s, trying to escape both, if they were non-overlapping", packed_hex, escaped_sequence)
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
