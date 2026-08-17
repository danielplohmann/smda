import unittest
from pathlib import Path

from smda.common.labelprovider.MsvcDemangler import demangle_msvc_symbol

# Every pair below is a real MSVC mangled name with the spelling llvm-undname produces
# for it. The mangled names come from LLVM's own demangler test corpus, except the two
# marked as read out of a PDB.
DEMANGLED = [
    ("?foo@@YAXI@Z", "void __cdecl foo(unsigned int)"),
    ("?foo@@YAXN@Z", "void __cdecl foo(double)"),
    ("?foo_pad@@YAXPAD@Z", "void __cdecl foo_pad(char *)"),
    ("?foo_pbd@@YAXPBD@Z", "void __cdecl foo_pbd(char const *)"),
    ("?foo_qad@@YAXQAD@Z", "void __cdecl foo_qad(char *const)"),
    ("?foo_papad@@YAXPAPAD@Z", "void __cdecl foo_papad(char **)"),
    ("?foo_pbqad@@YAXPBQAD@Z", "void __cdecl foo_pbqad(char *const *)"),
    ("?foo_aad@@YAXAAD@Z", "void __cdecl foo_aad(char &)"),
    ("?foo_aay144h@@YAXAAY144H@Z", "void __cdecl foo_aay144h(int (&)[5][5])"),
    ("?foo_aay144cbh@@YAXAAY144$$CBH@Z", "void __cdecl foo_aay144cbh(int const (&)[5][5])"),
    ("?foo_piad@@YAXPIAD@Z", "void __cdecl foo_piad(char *__restrict)"),
    ("?foo_p6ahxz@@YAXP6AHXZ@Z", "void __cdecl foo_p6ahxz(int (__cdecl *)(void))"),
    ("??0foo@@QAE@XZ", "public: __thiscall foo::foo(void)"),
    ("??1foo@@QAE@XZ", "public: __thiscall foo::~foo(void)"),
    ("??Hfoo@@QAEHH@Z", "public: int __thiscall foo::operator+(int)"),
    ("??_V@YAXPAX@Z", "void __cdecl operator delete[](void *)"),
    ("?static_method@foo@@SAPAV1@XZ", "public: static class foo * __cdecl foo::static_method(void)"),
    ("?d@foo@@0FB", "private: static short const foo::d"),
    ("?e@foo@@1JC", "protected: static long volatile foo::e"),
    ("?Char16Var@@3_SA", "char16_t Char16Var"),
    ("?h2@@3QBHB", "int const *const h2"),
    ("?mbb@S@@QAEX_N0@Z", "public: void __thiscall S::mbb(bool, bool)"),
    ("?f@@YAXHZZ", "void __cdecl f(int, ...)"),
    ("?g@@YAXUS@@PA0@Z", "void __cdecl g(struct S, struct S *)"),
    # the declarator cases: a name or a further pointer belongs inside its own type
    ("?j@@3P6GHCE@ZA", "int (__stdcall *j)(signed char, unsigned char)"),
    ("?g@@3PAP6AHXZA", "int (__cdecl **g)(void)"),
    ("?f@@YAPAY01HXZ", "int (* __cdecl f(void))[2]"),
    ("?f@@YAAAY01HXZ", "int (& __cdecl f(void))[2]"),
    ("?ret_fnptrarray@@YAP6AXQAH@ZXZ", "void (__cdecl * __cdecl ret_fnptrarray(void))(int *const)"),
    ("?color3@@3QAY02$$CBNA", "double const (*const color3)[3]"),
    ("?f@@YAXY01H@Z", "void __cdecl f(int[2])"),
    ("?b11@@YAPAPBDXZ", "char const ** __cdecl b11(void)"),
    ("?foo_abc@@YAXV?$A@DV?$B@D@@V?$C@D@@@@@Z", "void __cdecl foo_abc(class A<char, class B<char>, class C<char>>)"),
    # a return type, alone among positions, carries a qualifier of its own, so every
    # function returning a class by value is spelled with one - at all three sites a
    # return type is parsed
    ("?f@@YA?AUMatrix@@XZ", "struct Matrix __cdecl f(void)"),
    ("?f@@YA?BUMatrix@@XZ", "struct Matrix const __cdecl f(void)"),
    ("?f@@YAXP6A?AUMatrix@@XZ@Z", "void __cdecl f(struct Matrix (__cdecl *)(void))"),
    ("?f@@YAX$$A6A?AUMatrix@@XZ@Z", "void __cdecl f(struct Matrix __cdecl(void))"),
    ("?g@@3P6A?AUMatrix@@XZA", "struct Matrix (__cdecl *g)(void)"),
    # clang's Microsoft mangler emits _L/_M for __int128, but llvm-undname cannot read them
    # back, so these two are spelled from the mangler's table rather than the reference's
    ("?f@@YAX_L@Z", "void __cdecl f(__int128)"),
    ("?f@@YAX_M@Z", "void __cdecl f(unsigned __int128)"),
    # read out of real PDBs rather than the LLVM corpus
    ("??_7type_info@@6B@", "const type_info::`vftable'"),
    (
        "?__crt_rotate_pointer_value@@YAIIH@Z",
        "unsigned int __cdecl __crt_rotate_pointer_value(unsigned int, int)",
    ),
]

# Measured against llvm-undname 22.1.7 on the shipped corpus. Both are exact so that a
# change in either direction has to be an explicit edit rather than passing silently.
UNIQUE_CORPUS_NAMES = 609
CORPUS_NAMES_UNDERSTOOD = 383

# Forms this demangler does not model. Each must come back exactly as it went in: a wrong
# expansion is worse than a decorated name, because it matches neither spelling.
DECLINED = [
    "??$f@T<unnamed-type-$S1>@PR18204@@@PR18204@@YAHPAT<unnamed-type-$S1>@0@@Z",
    "?x@@3PAY02Hz",  # truncated
    "?",
    "??",
    # a symbol table holds whatever bytes were written into it, so every malformed shape
    # below has to be answerable rather than raise
    "?@@YAXXZ",  # empty name fragment
    "?a@1@@YAXXZ",  # name back-reference past the end of the table
    "??0@@QAE@XZ",  # constructor with no class to name it after
    "?f@@YAX_Y@Z",  # unknown extended basic type
    "?f@@YAX$$CZ@Z",  # $$C without a qualifier
    "?f@@YAXP6ZHXZ@Z",  # function pointer with an unknown calling convention
    "?f@@YAX$$A6ZXZ@Z",  # function type argument with an unknown calling convention
    "??_7type_info@@6Z@",  # vftable with an unknown qualifier
    "??_7type_info@@6B@X",  # vftable with trailing bytes
    "?foo@@YAXI@ZX",  # function with trailing bytes
    "?g@@YAXPAUS@@PA1@Z",  # argument back-reference past the end of the table
    "?g@@YAX0@Z",  # argument back-reference with nothing recorded yet
    "?f@@YAXPAHPB0@Z",  # a qualifier in front of a back-reference, which MSVC does not form
    "?f@@YAXZZ",  # variadic marker with no parameter before it
    "?f@@YAX_",  # truncated extended type
    # a parameter list is closed by the throw specification, so a name that stops before it
    # is truncated however plausible the prefix looks
    "?f@@YAXHZ",  # variadic marker, then nothing where the throw specification belongs
    "?a2@@YAHX",  # void parameter list with no terminator at all
    "?b7@@YANAAMXZ",  # parameters, then a variadic marker standing in for the terminator
    # __int8/__int16/__int32 are spelled with the plain char/short/int codes, so no mangler
    # emits these and a name carrying one is not MSVC-decorated
    "?f@@YAX_H@Z",
    "?f@@YAX_D@Z",
    "?f@@YA?ZUMatrix@@XZ",  # return type carrying a qualifier that is not one
    "??0?$5Class@QAH@@QAE@XZ",  # template name starting with a digit
    "??$?HH@S@@QEAAAEAU0@H@Z",  # operator template, whose name is not modelled
    "?e@FTypeWithQuals@@3U?K@A",  # tag type named by an operator rather than an identifier
    # a special name takes a signature or a storage class by which code it is, never both
    "??_7A@B@ad@@YAXPEBQEAD@Z",  # vftable given a function signature
    "??7Base@@6B@",  # operator! given the vftable storage class
    "?foo_pbqbd@@YAXPEBBBD@Z",  # reference under an enclosing qualifier, which C++ has no form for
    "??_?@@YAXXZ",  # unknown extended operator
    # the declarator placeholder is a NUL; an identifier carrying one would otherwise be
    # mistaken for the slot a pointer writes itself into, yielding "class a(*)b"
    "?f@@YAXPAVa\x00b@@@Z",
    "?a\x00b@@YAXPAY01D@Z",
]


class MsvcDemanglerTestSuite(unittest.TestCase):
    def test_known_names_match_the_reference_spelling(self):
        for mangled, expected in DEMANGLED:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_unmodelled_forms_come_back_untouched(self):
        for mangled in DECLINED:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)

    def test_a_name_carrying_the_declarator_placeholder_is_refused(self):
        # not merely declined by accident: without the guard this produced "class a(*)b",
        # a spelling matching neither the input nor the truth
        evil = "?f@@YAXPAVa\x00b@@@Z"

        self.assertEqual(demangle_msvc_symbol(evil), evil)

    def test_a_name_carrying_any_control_character_is_refused(self):
        # an identifier is copied into the answer verbatim, so a control character in the
        # input is one in a reported symbol name; the parser reads these as ordinary
        # identifier bytes and would otherwise expand them
        for code in (0x01, 0x07, 0x0A, 0x0D, 0x1B, 0x7F):
            evil = f"?ctrl{chr(code)}@@YAXXZ"
            with self.subTest(code=code):
                self.assertEqual(demangle_msvc_symbol(evil), evil)

    def test_names_that_are_not_msvc_decorated_are_left_alone(self):
        for name in ("", "plain_name", "_ZN4test4funcEv", "_RNvC6_123foo3bar", "_ReadFile@20"):
            with self.subTest(name=name):
                self.assertEqual(demangle_msvc_symbol(name), name)

    def test_a_deeply_nested_type_stops_at_the_depth_bound(self):
        # each "PA" is another pointer level, so this nests types far past the bound; it must
        # decline on the bound rather than on the interpreter's recursion limit
        shallow = "?f@@YAX" + "PA" * 30 + "D@Z"
        deep = "?f@@YAX" + "PA" * 300 + "D@Z"

        self.assertTrue(demangle_msvc_symbol(shallow).startswith("void __cdecl f(char "))
        self.assertEqual(demangle_msvc_symbol(deep), deep)

    def test_a_deeply_nested_name_stops_at_the_depth_bound(self):
        # nesting in the *name* rather than the type: each level is another template
        deep = "?f@@YAX" + "V?$A@" * 200 + "H" + "@" * 200 + "@@Z"

        self.assertEqual(demangle_msvc_symbol(deep), deep)

    def test_a_result_that_would_balloon_is_refused(self):
        # each layer re-uses every earlier argument back-reference, so the rendered result
        # grows multiplicatively while the name itself stays short
        name = "?f@@YAXPAD" + "".join("P6AX" + str(index) * 9 + "@Z" for index in range(8)) + "@Z"

        self.assertLess(len(name), 200)
        self.assertEqual(demangle_msvc_symbol(name), name)

    def test_a_truncated_name_never_raises(self):
        # symbol tables carry damaged strings; every prefix must be answerable
        source = "?static_method@foo@@SAPAV1@XZ"
        for end in range(len(source) + 1):
            with self.subTest(prefix=source[:end]):
                self.assertIsInstance(demangle_msvc_symbol(source[:end]), str)


class MsvcReferenceCorpusTestSuite(unittest.TestCase):
    """Measure the demangler against llvm-undname's output on LLVM's own corpus."""

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "msvc_reference_corpus.txt"
        cls.corpus = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or "\t" not in line:
                continue
            mangled, expected = line.split("\t", 1)
            cls.corpus.append((mangled, expected))

    def test_no_name_is_given_a_third_spelling(self):
        """The guarantee: a name is either demangled correctly or returned untouched."""
        wrong = []
        for mangled, expected in self.corpus:
            got = demangle_msvc_symbol(mangled)
            if got not in (expected, mangled):
                wrong.append((mangled, got, expected))

        self.assertEqual(wrong, [])

    def test_the_share_that_is_understood_is_exactly_what_was_measured(self):
        """A ratchet in both directions: improving coverage means updating this number."""
        exact = sum(1 for mangled, expected in self.corpus if demangle_msvc_symbol(mangled) == expected)

        self.assertEqual(len(self.corpus), UNIQUE_CORPUS_NAMES)
        self.assertEqual(exact, CORPUS_NAMES_UNDERSTOOD)

    def test_every_name_survives_truncation_at_any_point(self):
        for mangled, _ in self.corpus:
            for end in range(len(mangled) + 1):
                self.assertIsInstance(demangle_msvc_symbol(mangled[:end]), str)


if __name__ == "__main__":
    unittest.main()
