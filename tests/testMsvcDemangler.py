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
CORPUS_NAMES_UNDERSTOOD = 592

# Forms this demangler does not model. Each must come back exactly as it went in: a wrong
# expansion is worse than a decorated name, because it matches neither spelling.
DECLINED = [
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


# Back-reference behaviour, each pair checked against llvm-undname. A name is recorded for
# later reference only when it is not already held and while the table is under ten entries,
# and a template instantiation is read in its own scope.
BACKREFS = [
    # the table holds the function's own name first, so "1" is the first type named after it
    ("?f@@YAXVA@@V1@@Z", "void __cdecl f(class A, class A)"),
    # a repeat is not recorded again: the table is f, A, B, so "1" is still A
    ("?f@@YAXVA@@VB@@VA@@V1@@Z", "void __cdecl f(class A, class B, class A, class A)"),
    # the tenth entry is the last one recorded, so "9" is I and J never enters the table
    (
        "?f@@YAXVA@@VB@@VC@@VD@@VE@@VF@@VG@@VH@@VI@@VJ@@V9@@Z",
        "void __cdecl f(class A, class B, class C, class D, class E, class F, class G, "
        "class H, class I, class J, class I)",
    ),
    # a template opens its own scope, taking index 0 itself, so its first argument is 1
    (
        "?foo_abbb@@YAXV?$A@V?$B@D@@V1@V1@@@@Z",
        "void __cdecl foo_abbb(class A<class B<char>, class B<char>, class B<char>>)",
    ),
    # the rendered template belongs to the enclosing scope: 1 is B<char> and 2 is N
    ("?b_foo@@YA?AV?$B@D@N@@V12@@Z", "class N::B<char> __cdecl b_foo(class N::B<char>)"),
    (
        "?abc_foo@@YA?AV?$A@DV?$B@D@N@@V?$C@D@2@@N@@XZ",
        "class N::A<char, class N::B<char>, class N::C<char>> __cdecl abc_foo(void)",
    ),
    # the symbol's own template name is the exception: it is not recorded, so 0 is N
    ("??$f@H@N@@YAXV0@@Z", "void __cdecl N::f<int>(class N)"),
]

# Shapes the grammar does not allow, each confirmed refused by llvm-undname. Every one of
# these was answered before the back-reference table learned how the mangler fills it.
BACKREF_DECLINED = [
    "?f@@YAXVA@@VB@@VA@@V3@@Z",  # A is recorded once, so there is no fourth name
    "??$f@H@N@@YAXV1@@Z",  # only N is recorded, and the symbol's own template name is not
    "?f2@@YAXBDPAD@Z",  # "B" would introduce a volatile reference, which C++ cannot write
    "?foo_qay04h@@YAXBEAY04H@Z",
    "?h@@YAXPAHPA0@Z",  # an argument back-reference is a whole argument, never a pointee
    "?h@@YAXPAHAA0@Z",
    "?g@@YAXUS@@PA0@Z",  # the reference refuses this too, whatever the back-reference names
    # declined rather than refused: the reference spells this "int &const *", a qualifier on
    # a reference that C++ has no form for, so the decorated name stays the better answer
    "?f@@YAXPBAAH@Z",
]


# Rules derived from llvm-undname probes, each pinned with the name that proved it.
GRAMMAR_RULES = [
    # the "6" storage form belongs to the vftable family only
    ("??_7x@@6B@", "const x::`vftable'"),
    ("??_8x@@6B@", "const x::`vbtable'"),
    ("??_Sx@@6B@", "const x::`local vftable'"),
    # a data symbol's trailing qualifier belongs to what its outermost pointer points at
    ("?s@@3PADB", "char const *s"),
    ("?s@@3PADD", "char const volatile *s"),
    ("?s@@3QBDD", "char const volatile *const s"),
    ("?s@@3PAPADB", "char *const *s"),
    ("?s@@3HB", "int const s"),
    # a sigil abuts a type that ends in neither an alphanumeric character nor ">"
    ("?f@@YAXPAUS@@@Z", "void __cdecl f(struct S *)"),
    ("?f@@YAXPAUS_@@@Z", "void __cdecl f(struct S_*)"),
    ("?f@@YAXPAUS$@@@Z", "void __cdecl f(struct S$*)"),
    ("?f@@YAXPAV?$B@VA@@@@@Z", "void __cdecl f(class B<class A> *)"),
    # ... while a named declarator is spaced off whatever precedes it
    ("?fooE@@YA?AW4E$@@XZ", "enum E$ __cdecl fooE(void)"),
    # "$$C" qualifies an array element or a template argument
    ("?f@@YAXAAY144$$CBH@Z", "void __cdecl f(int const (&)[5][5])"),
    ("?f@@YAXV?$T@$$CBH@@@Z", "void __cdecl f(class T<int const>)"),
    # a function pointer takes no __ptr64 modifier, but is otherwise read
    ("?p@@3R6AHHH@ZA", "int (__cdecl *volatile p)(int, int)"),
    ("?p@@3Q6AHHH@ZA", "int (__cdecl *const p)(int, int)"),
]

# ... and the shapes those same rules refuse, each confirmed refused by llvm-undname
GRAMMAR_DECLINED = [
    "??_9x@@6B@",  # vcall, typeof and the local static guard take a storage class this
    "??_Ax@@6B@",  # parser does not model, never the vftable family's "6" form
    "??_Bx@@6B@",
    "?p@@3PE6AHHH@ZA",  # __ptr64 is not written in front of a function type
    "?p@@3RE6AHHH@ZA",
    "?f@@YAX$$CBH@Z",  # "$$C" is not a parameter of its own, nor a pointee
    "?f@@YAXPA$$CBH@Z",
    "?f@@YAXAA$$CBH@Z",
    "?f@@YAXAAY144$$CZH@Z",  # ... and in those positions it still needs a real qualifier
]


ANONYMOUS_NAMESPACE = [
    ("?x@?A0x12345678@@3HA", "int `anonymous namespace'::x"),
    ("?x@?A@@3HA", "int `anonymous namespace'::x"),
    ("?x@?A0xABCDEF12@N@@3HA", "int N::`anonymous namespace'::x"),
    ("?f@?A0x1@@YAXXZ", "void __cdecl `anonymous namespace'::f(void)"),
    # the discriminator, not the spelling, is what a later back-reference resolves to
    ("?f@?A0x1@@YAXV1@@Z", "void __cdecl `anonymous namespace'::f(class 0x1)"),
    ("?f@?A0x1@N@@YAXV2@@Z", "void __cdecl N::`anonymous namespace'::f(class N)"),
    # a leading "??A" is operator[], which a namespace fragment must not claim
    ("??AFoo@@QAGXXZ", "public: void __stdcall Foo::operator[](void)"),
]


class MsvcAnonymousNamespaceTestSuite(unittest.TestCase):
    def test_an_unnamed_namespace_is_spelled_and_recorded_the_way_it_is_mangled(self):
        for mangled, expected in ANONYMOUS_NAMESPACE:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_a_discriminator_that_is_not_hexadecimal_is_refused(self):
        for mangled in ("?x@?A0@@3HA", "?x@?A0x@@3HA", "?x@?A0xZZ@@3HA"):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


MEMBER_POINTERS_AND_INTEGERS = [
    ("?f@@YAXP8S@@AEXXZ@Z", "void __cdecl f(void (__thiscall S::*)(void))"),
    ("?f@@YAXP8S@@BEXXZ@Z", "void __cdecl f(void (__thiscall S::*)(void) const)"),
    ("?f@@YAXP8S@@DEXXZ@Z", "void __cdecl f(void (__thiscall S::*)(void) const volatile)"),
    ("?f@@YAXP8N@S@@AEXXZ@Z", "void __cdecl f(void (__thiscall S::N::*)(void))"),
    ("?f@@YAXQ8S@@AEXXZ@Z", "void __cdecl f(void (__thiscall S::*const)(void))"),
    ("?f@@YAXP8S@@AAHH@Z@Z", "void __cdecl f(int (__cdecl S::*)(int))"),
    ("?f@@YAXP8?$T@$01@@AEXXZ@Z", "void __cdecl f(void (__thiscall T<2>::*)(void))"),
    # a single digit is itself plus one; anything larger is nibbles "A" to "P" ended by "@"
    ("??$f@$00@@YAXXZ", "void __cdecl f<1>(void)"),
    ("??$f@$0A@@@YAXXZ", "void __cdecl f<0>(void)"),
    ("??$f@$0M@@@YAXXZ", "void __cdecl f<12>(void)"),
    ("??$f@$0BAA@@@YAXXZ", "void __cdecl f<256>(void)"),
    ("??$f@$0?0@@YAXXZ", "void __cdecl f<-1>(void)"),
    # the accumulator is 64 bits and wraps, and a magnitude that wraps to zero keeps its sign
    (
        "??0?$LongLongTemplate@$0HPPPPPPPPPPPPPPPPPP@@@QAE@XZ",
        "public: __thiscall LongLongTemplate<18446744073709551615>::LongLongTemplate<18446744073709551615>(void)",
    ),
    (
        "??0?$LongLongTemplate@$0?IAAAAAAAAAAAAAAAAAA@@@QEAA@XZ",
        "public: __cdecl LongLongTemplate<-0>::LongLongTemplate<-0>(void)",
    ),
]


LOCAL_SCOPES = [
    ("?x@?0??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`1'::x"),
    ("?x@?1??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`2'::x"),
    ("?x@?2??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`3'::x"),
    # the enclosing name continues this name's back-reference table rather than opening its
    # own, so the "0" below is the outer N and not the enclosing symbol's own first fragment
    ("?N@?1??SN@?$NS@H@0@QEAAHXZ@4HA", "int `public: int __cdecl N::NS<int>::SN(void)'::`2'::N"),
    ("?M@?0??L@@YAHXZ@YA?AURetVal@1@H@Z", "struct L::RetVal __cdecl `int __cdecl L(void)'::`1'::M(int)"),
]


UNALIGNED_AND_LITERALS = [
    # "__unaligned" qualifies the pointee, after its own const and volatile
    ("?f@@YAPFAHXZ", "int __unaligned * __cdecl f(void)"),
    ("?f@@YAXPFBH@Z", "void __cdecl f(int const __unaligned *)"),
    ("?f@@YAXAFAH@Z", "void __cdecl f(int __unaligned &)"),
    ("?f@@YAXQFAH@Z", "void __cdecl f(int __unaligned *const)"),
    # ... and travels with them, so a pointer to an unaligned pointer keeps it
    ("?f@@YAXPFAPFAH@Z", "void __cdecl f(int __unaligned *__unaligned *)"),
    ("?f@@YAXPFAPAH@Z", "void __cdecl f(int *__unaligned *)"),
    ("?f@@YAXPIFAH@Z", "void __cdecl f(int __unaligned *__restrict)"),
    # a user-defined literal takes its suffix from the identifier after the code
    ("??__K_deg@@YAHO@Z", 'int __cdecl operator ""_deg(long double)'),
    ("??__Kmm@@YAHO@Z", 'int __cdecl operator ""mm(long double)'),
    # "@" is the scope spelled zero
    ("?M@?@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`0'::M"),
]


TRAILING_QUALIFIERS = [
    # a plain type takes it directly
    ("?s@@3HB", "int const s"),
    # a class, struct or enum does too - "const MyClass instance" is spelled this way
    ("?inst@@3Urecord@@B", "struct record const inst"),
    ("?inst@@3VMyClass@@B", "class MyClass const inst"),
    ("?inst@@3W4E@@B", "enum E const inst"),
    # a pointer passes it to what it points at, not to itself
    ("?s@@3PADB", "char const *s"),
    ("?a@@3PAUS@@B", "struct S const *a"),
    ("?s@@3PAPADB", "char *const *s"),
    ("?s@@3QBDD", "char const volatile *const s"),
    # and an array passes it on to its element, the way C spells one
    ("?arr@@3QAY01HB", "int const (*const arr)[2]"),
]


MEMBER_QUALIFIERS_AND_SCOPES = [
    # "$$A8" is a function type carrying what only a member function may carry
    ("??$f@$$A8@@BAHXZ@@YAXXZ", "void __cdecl f<int __cdecl(void) const>(void)"),
    ("??$f@$$A8@@IAAHXZ@@YAXXZ", "void __cdecl f<int __cdecl(void) __restrict>(void)"),
    ("??$f@$$A8@@GBAHXZ@@YAXXZ", "void __cdecl f<int __cdecl(void) const &>(void)"),
    ("??$f@$$A8@@HBAHXZ@@YAXXZ", "void __cdecl f<int __cdecl(void) const &&>(void)"),
    # a scope number is written the way a template argument's is, nibbles included
    ("?M@?L@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`11'::M"),
    ("?x@?1??f@@YAXXZ@4HA", "int `void __cdecl f(void)'::`2'::x"),
    ("?M@?@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`0'::M"),
]


MEMBER_DATA_POINTERS = [
    ("?f@@YAXPQfoo@@H@Z", "void __cdecl f(int foo::*)"),
    ("?f@@YAXPRfoo@@D@Z", "void __cdecl f(char const foo::*)"),
    ("?f@@YAXPSfoo@@H@Z", "void __cdecl f(int volatile foo::*)"),
    ("?f@@YAXPTfoo@@H@Z", "void __cdecl f(int const volatile foo::*)"),
    ("?f@@YAXQQfoo@@H@Z", "void __cdecl f(int foo::*const)"),
    ("?f@@YAXPQ?$T@H@@H@Z", "void __cdecl f(int T<int>::*)"),
    # as a data symbol it repeats the qualifier and names its class again by back-reference
    ("?m@@3PQfoo@@HQ1@", "int foo::*m"),
    ("?m@@3PRfoo@@DR1@", "char const foo::*m"),
    ("?m@@3PQfoo@@HR1@", "int const foo::*m"),
]


LATER_FORMS = [
    # a pack separator and an empty pack stand between arguments without being one
    ("??$f@H$$ZH@@YAXXZ", "void __cdecl f<int, int>(void)"),
    ("??$f@$$$V@@YAXXZ", "void __cdecl f<>(void)"),
    # an extent is written the way a template argument's number is
    ("?i@@3PAY0BE@HA", "int (*i)[20]"),
    # what runs around an object with a non-trivial lifetime, whose name is recorded
    ("??__EFoo@@YAXXZ", "void __cdecl `dynamic initializer for 'Foo''(void)"),
    ("??__FFoo@@YAXXZ", "void __cdecl `dynamic atexit destructor for 'Foo''(void)"),
    ("??__EFoo@@YAXU0@@Z", "void __cdecl `dynamic initializer for 'Foo''(struct Foo)"),
    # a name mangled although it is extern "C"
    ("?overloaded_fn@@$$J0YAXXZ", 'extern "C" void __cdecl overloaded_fn(void)'),
    # a vftable may say which base it is the table for
    ("??_7A@B@@6BC@D@@@", "const B::A::`vftable'{for `D::C'}"),
    ("??_8A@B@@7BC@D@@@", "const B::A::`vbtable'{for `D::C'}"),
    # a member function pointer keeps a data symbol's qualifier after its parameters
    ("?p@@3P8B@@EAA?CHXZES1@", "int volatile (__cdecl B::*p)(void) volatile"),
    # a parenthesised pointer declarator abuts the sigil; a function declarator does not
    ("?FunArr@@3PAY0BE@P6AHHH@ZA", "int (__cdecl *(*FunArr)[20])(int, int)"),
    ("?f@@YAP6AHXZXZ", "int (__cdecl * __cdecl f(void))(void)"),
]


LATEST_FORMS = [
    # a second spelling of the empty pack, and an alias template named rather than described
    ("??$templ_fun_with_ty_pack@$$V@@YAXXZ", "void __cdecl templ_fun_with_ty_pack<>(void)"),
    ("??$f@$$YAliasA@PR20047@@@PR20047@@YAXXZ", "void __cdecl PR20047::f<PR20047::AliasA>(void)"),
    # a vftable may name more than one base
    ("??_7A@B@@6BC@D@@E@F@@@", "const B::A::`vftable'{for `D::C's `F::E'}"),
    # __restrict qualifies a member function, next to its reference qualifier
    ("?foo@A@PR19361@@QIGAEXXZ", "public: void __thiscall PR19361::A::foo(void) __restrict &"),
    # and on a data symbol it qualifies the pointer, once however often it is spelled
    ("?h3@@3QAHIA", "int *const __restrict h3"),
    ("?h3@@3QIAHA", "int *const __restrict h3"),
    ("?h3@@3QIAHIA", "int *const __restrict h3"),
    ("?h3@@3PAHIA", "int *__restrict h3"),
]


FINAL_FORMS = [
    # a template whose name is an operator, and an operator that leaves its return empty
    ("??$?HH@S@@QEAAAEAU0@H@Z", "public: struct S & __cdecl S::operator+<int>(int)"),
    ("??RFoo@@QBE@XZ", "public: __thiscall Foo::operator()(void) const"),
    ("??RFoo@@QBEHXZ", "public: int __thiscall Foo::operator()(void) const"),
    # the type as written rather than as a parameter would decay it, extent and all
    ("??$f@$$BY01H@@YAXXZ", "void __cdecl f<int[2]>(void)"),
    ("??0?$Class@$$BY0A@H@@QAE@XZ", "public: __thiscall Class<int[]>::Class<int[]>(void)"),
    ("??0?$Class@$$BY04QAH@@QAE@XZ", "public: __thiscall Class<int *const[5]>::Class<int *const[5]>(void)"),
    # two conventions spelled with an attribute, and two spelled with nothing
    ("?swift_func@@YSXXZ", "void __attribute__((__swiftcall__)) swift_func(void)"),
    ("?f@@YWXXZ", "void __attribute__((__swiftasynccall__)) f(void)"),
    ("?f@@YTXXZ", "void f(void)"),
    # a convention spelled with nothing keeps the parentheses a pointer needs
    ("?f@@YAXP6ZHXZ@Z", "void __cdecl f(int ( *)(void))"),
    ("?f@@YAXP8S@@AZXXZ@Z", "void __cdecl f(void ( S::*)(void))"),
]


THUNKS_AND_ADDRESSES = [
    # the address of a symbol, read in the template's own back-reference scope
    ("??$f@$1?x@@3HA@@YAXXZ", "void __cdecl f<&int x>(void)"),
    ("??$f@VBar@@$1?x@0@3HA@@YAXXZ", "void __cdecl f<class Bar, &int f::x>(void)"),
    ("??$f@$E?x@@3HA@@YAXXZ", "void __cdecl f<int x>(void)"),
    # a thunk that adjusts "this" on the way through
    (
        "??_EBase@@G3AEPAXI@Z",
        "[thunk]: private: void * __thiscall Base::`vector deleting dtor'`adjustor{4}'(unsigned int)",
    ),
    (
        "??_EDerived@@$4PPPPPPPM@A@EAAPEAXI@Z",
        "[thunk]: public: virtual void * __cdecl Derived::`vector deleting dtor'`vtordisp{-4, 0}'(unsigned int)",
    ),
    # a vcall names no access and carries no parameters
    ("??_9Base@@$B7AA", "[thunk]: __cdecl Base::`vcall'{8, {flat}}"),
]


class MsvcThunkTestSuite(unittest.TestCase):
    def test_thunks_and_addresses_match_the_reference(self):
        for mangled, expected in THUNKS_AND_ADDRESSES:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_a_vcall_and_its_thunk_require_each_other(self):
        for mangled in (
            "??0f9Base@@$B7AA",
            "??_9Base10@@YAADMXZ",
            # the reference reads these; this declines them, as it does elsewhere, rather
            # than take a digit for a convention or ignore bytes after the name
            "??_9Base@@$B7A1",
            "??_9Base@@$B7AAX??_EDerived@@$4A@A@EA1PEAXI@Z",
            "??_EDerived@@$4A@A@EAAPEAXI@ZX",
        ):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcFinalFormsTestSuite(unittest.TestCase):
    def test_the_final_forms_match_the_reference(self):
        for mangled, expected in FINAL_FORMS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_shapes_these_forms_do_not_allow_are_refused(self):
        for mangled in (
            "?overloaded_fn@@$$J00YAXXZ",  # the marker counts with one digit, not two
            "??0?$Class@$$B$0?9@@QAE@XZ",  # "$$B" introduces a type, and an integer is not one
            "??BFoo@@QBE@XZ",  # a conversion operator's return names what it converts to
            # every letter names a convention, most of them spelled with nothing. The
            # reference takes any byte at all there; this requires a letter, so that a
            # name mangled with something else declines rather than reads as a function
            "?f@@Y1XXZ",
            "?f@@YAXP61HXZ@Z",
            "?f@@YAXP8S@@A1XXZ@Z",
            "??$f@$$A61HXZ@@YAXXZ",
        ):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcLatestFormsTestSuite(unittest.TestCase):
    def test_the_latest_forms_match_the_reference(self):
        for mangled, expected in LATEST_FORMS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)


class MsvcLaterFormsTestSuite(unittest.TestCase):
    def test_the_later_forms_match_the_reference(self):
        for mangled, expected in LATER_FORMS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_the_shapes_these_forms_do_not_allow_are_refused(self):
        for mangled in (
            "??__E?i@C@0HA@@YAXXZ",  # what it runs for is named plainly, not by a special name
            "??__EFooTypeWithQuals@@3U?$S@$$A8@@GBAHXZ@1@A",  # it runs code, so it takes a signature
            "?overloaded_fn@@$$JYAXXZ",  # the marker counts characters, so a digit belongs here
            "??__K_deg@@YAXU0@@Z",  # a literal operator's suffix is not recorded, so 0 names nothing
            "?i@@3PAY0?0HA",  # an array does not have a negative extent
            "??_7A@@6B?0@@",  # nor is a base named by anything but a name
        ):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcMemberDataPointerTestSuite(unittest.TestCase):
    def test_a_pointer_into_a_class_is_spelled_around_the_class(self):
        for mangled, expected in MEMBER_DATA_POINTERS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_a_reference_into_a_class_is_refused(self):
        # C++ has no reference to member, however much "AT..." looks like one
        self.assertEqual(demangle_msvc_symbol("?k@@3ATfoo@@DT1@"), "?k@@3ATfoo@@DT1@")

    def test_a_member_type_the_reference_spells_differently_is_declined(self):
        # "PQfoo@@SAPEAX" is "void **foo::*" there, dropping qualifiers this would keep, and
        # nothing on the producer side settles which is right
        self.assertEqual(demangle_msvc_symbol("?f@@YAXPQfoo@@SAPEAX@Z"), "?f@@YAXPQfoo@@SAPEAX@Z")


class MsvcMemberQualifierTestSuite(unittest.TestCase):
    def test_member_qualifiers_and_scope_numbers_match_the_reference(self):
        for mangled, expected in MEMBER_QUALIFIERS_AND_SCOPES:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_a_qualifier_written_twice_is_refused(self):
        # each of them is written at most once, so "HH" is not a name
        for mangled in ("??$f@$$A8@@HHBAHXZ@@YAXXZ", "??$f@$$A8@@IIAAHXZ@@YAXXZ"):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)

    def test_a_named_class_is_not_written_in_this_position(self):
        self.assertEqual(demangle_msvc_symbol("??$f@$$A8S@@AEHXZ@@YAXXZ"), "??$f@$$A8S@@AEHXZ@@YAXXZ")

    def test_a_qualifier_the_table_does_not_hold_is_refused(self):
        self.assertEqual(demangle_msvc_symbol("??$f@$$A8@@GZAHXZ@@YAXXZ"), "??$f@$$A8@@GZAHXZ@@YAXXZ")

    def test_a_qualified_fragment_that_is_neither_a_namespace_nor_a_scope_is_refused(self):
        # "?Q" names no scope: the numbers stop at P and "?A" is the unnamed namespace
        self.assertEqual(demangle_msvc_symbol("?x@?Q@@3HA"), "?x@?Q@@3HA")


class MsvcTrailingQualifierTestSuite(unittest.TestCase):
    def test_the_storage_forms_a_data_symbol_may_take(self):
        cases = [
            # __ptr64 stands in front of the qualifier, where something is pointed at
            ("?s@@3PEAHEA", "int *s"),
            ("?$RT1@NeedsReferenceTemporary@@3AEBHEB", "int const &NeedsReferenceTemporary::$RT1"),
            # a pointer into a class spells its storage the long way, "E" included
            ("?m@@3PEFRfoo@@DER1@", "char const __unaligned foo::*m"),
            # and a name with no signature at all is spelling its linkage
            ("?extern_c_func@@9", 'extern "C" extern_c_func'),
            ("?local@?1??extern_c_func@@9@4HA", "int `extern \"C\" extern_c_func'::`2'::local"),
        ]
        for mangled, expected in cases:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_storage_forms_the_grammar_does_not_pair_are_refused(self):
        for mangled in (
            "?s@@3HEA",  # nothing is pointed at, so no __ptr64 belongs here
            "?s@@3HEB",
            "?memptr1@@3RESB@@HEA",  # a pointer into a class takes the long form, not this
            "?extern_c_func@@9X",  # the linkage marker ends the name, so nothing follows it
        ):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)

    def test_a_data_symbol_with_bytes_after_it_is_refused(self):
        self.assertEqual(demangle_msvc_symbol("?s@@3HBX"), "?s@@3HBX")

    def test_a_data_symbols_trailing_qualifier_lands_where_it_is_declared(self):
        for mangled, expected in TRAILING_QUALIFIERS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)


class MsvcUnalignedAndLiteralTestSuite(unittest.TestCase):
    def test_the_forms_are_spelled_the_way_the_reference_spells_them(self):
        for mangled, expected in UNALIGNED_AND_LITERALS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_an_unknown_double_underscore_operator_is_refused(self):
        for mangled in ("??__L_deg@@YAHO@Z", "??__@@YAHO@Z"):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcLocalScopeTestSuite(unittest.TestCase):
    def test_a_scope_inside_a_function_names_the_function_and_which_scope(self):
        for mangled, expected in LOCAL_SCOPES:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_a_local_scope_without_an_enclosing_name_is_refused(self):
        for mangled in ("?x@?1@4HA", "?x@?1?@4HA", "?x@?1??@4HA"):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcMemberPointerTestSuite(unittest.TestCase):
    def test_member_pointers_and_template_integers_match_the_reference(self):
        for mangled, expected in MEMBER_POINTERS_AND_INTEGERS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_shapes_neither_form_allows_are_refused(self):
        for mangled in (
            "?f@@YAXPE8S@@AEAXXZ@Z",  # __ptr64 is not written in front of a member function
            "?f@@YAX$0A@@Z",  # an integer is a template argument, never a parameter
            "??$f@$0@@YAXXZ",  # ... and needs digits
            "?f@@YAXP8?0S@@@AEXXZ@Z",  # nor is a constructor a class to point into
        ):
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcGrammarRuleTestSuite(unittest.TestCase):
    def test_rules_spell_names_the_way_the_reference_does(self):
        for mangled, expected in GRAMMAR_RULES:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_shapes_those_rules_forbid_are_refused(self):
        for mangled in GRAMMAR_DECLINED:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)


class MsvcBackReferenceTestSuite(unittest.TestCase):
    def test_back_references_resolve_the_way_the_mangler_numbered_them(self):
        for mangled, expected in BACKREFS:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), expected)

    def test_names_the_back_reference_rules_forbid_are_refused(self):
        for mangled in BACKREF_DECLINED:
            with self.subTest(mangled=mangled):
                self.assertEqual(demangle_msvc_symbol(mangled), mangled)

    def test_a_reference_and_a_back_referenced_argument_still_read(self):
        # the two refusals above are positional, not a retreat from these forms
        self.assertEqual(demangle_msvc_symbol("?f@@YAXADPAD@Z"), "void __cdecl f(char *const volatile &)")
        self.assertEqual(demangle_msvc_symbol("?h@@YAXPAH0@Z"), "void __cdecl h(int *, int *)")


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
