"""Demangling for MSVC decorated symbol names."""

import re
import string
from functools import lru_cache

_BASIC_TYPES = {
    "X": "void",
    "D": "char",
    "C": "signed char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
    "O": "long double",
}
_EXTENDED_TYPES = {
    "J": "__int64",
    "K": "unsigned __int64",
    "L": "__int128",
    "M": "unsigned __int128",
    "N": "bool",
    "Q": "char8_t",
    "S": "char16_t",
    "U": "char32_t",
    "W": "wchar_t",
}
_TAGGED_TYPES = {"T": "union", "U": "struct", "V": "class", "W": "enum"}
_CALLING_CONVENTIONS = {
    "A": "__cdecl",
    "B": "__cdecl",
    "C": "__pascal",
    "D": "__pascal",
    "E": "__thiscall",
    "F": "__thiscall",
    "G": "__stdcall",
    "H": "__stdcall",
    "I": "__fastcall",
    "J": "__fastcall",
    "M": "__clrcall",
    "N": "__clrcall",
    "O": "__eabi",
    "P": "__eabi",
    "Q": "__vectorcall",
    "S": "__attribute__((__swiftcall__))",
    "W": "__attribute__((__swiftasynccall__))",
    # the remaining letters are conventions the reference spells with nothing at all
    "K": "",
    "L": "",
    "R": "",
    "T": "",
    "U": "",
    "V": "",
    "X": "",
    "Y": "",
    "Z": "",
}
_FUNCTION_ACCESS = {
    "A": ("private", False, False),
    "B": ("private", False, False),
    "C": ("private", True, False),
    "D": ("private", True, False),
    "E": ("private", False, True),
    "F": ("private", False, True),
    "I": ("protected", False, False),
    "J": ("protected", False, False),
    "K": ("protected", True, False),
    "L": ("protected", True, False),
    "M": ("protected", False, True),
    "N": ("protected", False, True),
    "Q": ("public", False, False),
    "R": ("public", False, False),
    "S": ("public", True, False),
    "T": ("public", True, False),
    "U": ("public", False, True),
    "V": ("public", False, True),
}
_OPERATORS = {
    "2": "operator new",
    "3": "operator delete",
    "4": "operator=",
    "5": "operator>>",
    "6": "operator<<",
    "7": "operator!",
    "8": "operator==",
    "9": "operator!=",
    "A": "operator[]",
    "C": "operator->",
    "D": "operator*",
    "E": "operator++",
    "F": "operator--",
    "G": "operator-",
    "H": "operator+",
    "I": "operator&",
    "J": "operator->*",
    "K": "operator/",
    "L": "operator%",
    "M": "operator<",
    "N": "operator<=",
    "O": "operator>",
    "P": "operator>=",
    "Q": "operator,",
    "R": "operator()",
    "S": "operator~",
    "T": "operator^",
    "U": "operator|",
    "V": "operator&&",
    "W": "operator||",
    "X": "operator*=",
    "Y": "operator+=",
    "Z": "operator-=",
}
# the special names spelled with the "6" storage form. The vcall, typeof and local static
# guard codes are data too, but take a storage class this parser does not model, so they
# decline instead of being read as one of these
# what runs around a namespace-scope object with a non-trivial lifetime
_DYNAMIC_INITIALISERS = {"E": "dynamic initializer for", "F": "dynamic atexit destructor for"}
_DATA_SPECIAL_OPERATORS = frozenset("78S")
_UNMODELLED_DATA_SPECIAL_OPERATORS = frozenset("9AB")
_EXTENDED_OPERATORS = {
    "0": "operator/=",
    "1": "operator%=",
    "2": "operator>>=",
    "3": "operator<<=",
    "4": "operator&=",
    "5": "operator|=",
    "6": "operator^=",
    "7": "`vftable'",
    "8": "`vbtable'",
    "9": "`vcall'",
    "A": "`typeof'",
    "B": "`local static guard'",
    "D": "`vbase dtor'",
    "E": "`vector deleting dtor'",
    "F": "`default ctor closure'",
    "G": "`scalar deleting dtor'",
    "H": "`vector ctor iterator'",
    "I": "`vector dtor iterator'",
    "J": "`vector vbase ctor iterator'",
    "K": "`virtual displacement map'",
    "L": "`eh vector ctor iterator'",
    "M": "`eh vector dtor iterator'",
    "N": "`eh vector vbase ctor iterator'",
    "O": "`copy ctor closure'",
    "S": "`local vftable'",
    "T": "`local vftable ctor closure'",
    "U": "operator new[]",
    "V": "operator delete[]",
    "X": "`placement delete closure'",
    "Y": "`placement delete[] closure'",
}
_DATA_ACCESS = {
    "0": "private: static ",
    "1": "protected: static ",
    "2": "public: static ",
    "3": "",
    "4": "",
}
_POINTER_KINDS = {"P": (), "Q": ("const",), "R": ("volatile",), "S": ("const", "volatile")}
# what stands where a pointee's cv would, when the pointer points into a class instead
_MEMBER_DATA_QUALS = {"Q": (), "R": ("const",), "S": ("volatile",), "T": ("const", "volatile")}
_CV_QUALS = {"A": (), "B": ("const",), "C": ("volatile",), "D": ("const", "volatile")}
_CV = {"A": "", "B": " const", "C": " volatile", "D": " const volatile"}
_MEMBER_POINTER_RE = re.compile(r"^[^()]*::\*")


def _base(text):
    return ("base", text)


def _indirection(symbol, quals, inner):
    return ("ind", symbol, quals, inner)


def _array(dims, inner):
    return ("array", dims, inner)


def _function(convention, params, returns, member_cv=""):
    return ("func", convention, params, returns, member_cv)


def _render(node, declarator=""):
    """Spell a type around a declarator, the way C nests one inside the other.

    A pointer or array binds to the declarator built so far, and a name therefore ends up
    *inside* its type: `int (*j)[2]`, not `int (*)[2] j`.
    """
    kind = node[0]
    if kind == "base":
        if not declarator:
            return node[1]
        if declarator.startswith("["):
            return node[1] + declarator
        # the reference spaces a declarator off a type ending in an alphanumeric character
        # or a template's ">", and abuts it to anything else: "struct S *" but "struct S_*"
        # and "enum <unnamed-type-*"
        tail = node[1][-1:]
        sigil = declarator.startswith(("*", "&"))
        abuts = sigil and not (tail == ">" or (tail.isascii() and tail.isalnum()))
        return node[1] + ("" if abuts else " ") + declarator
    if kind == "ind":
        token = node[1] + " ".join(node[2])
        # a nested *function* declarator is separated from the sigil - "int * (__cdecl *)()"
        # - while a parenthesised pointer declarator abuts it: "int (*(*a)[20])()"
        nested_function = "(" in declarator and not declarator.startswith(("*", "&", "(*", "(&"))
        separator = " " if declarator and not declarator.startswith("[") and (node[2] or nested_function) else ""
        return _render(node[3], token + separator + declarator)
    if kind == "array":
        if declarator.startswith(("*", "&")):
            declarator = f"({declarator})"
        return _render(node[2], declarator + node[1])
    convention, params, returns, member_cv = node[1], node[2], node[3], node[4]
    if not convention and not declarator.startswith(("*", "&")) and "::*" not in declarator:
        # a convention spelled with nothing leaves a named declarator alone, while a pointer
        # keeps its parentheses and the space the convention would have filled: "int ( *)()"
        return _render(returns, f"{declarator}({params}){member_cv}")
    # a member-pointer declarator is "Owner::*", possibly qualified; the test is anchored so
    # that a nested type's own "::*" - which a rendered parameter may hold - does not count
    if declarator.startswith(("*", "&")) or _MEMBER_POINTER_RE.match(declarator):
        declarator = f"({convention} {declarator})"
    else:
        declarator = f"{convention} {declarator}" if declarator else convention
    return _render(returns, f"{declarator}({params}){member_cv}")


def _merge(left, right):
    # "__unaligned" travels with const and volatile: a pointer that points at an unaligned
    # pointer keeps it - "int __unaligned *__unaligned *"
    merged = [qual for qual in ("const", "volatile", "__unaligned") if qual in left or qual in right]
    return tuple(merged)


def _apply_quals(node, quals):
    """Qualify a named type, as a pointee qualifier or a $$C wrapper does.

    Only ever reached with a base node: an indirection merges its qualifiers as it is built,
    and a back-reference declines rather than accept one.
    """
    return _base(f"{node[1]} {' '.join(quals)}") if quals else node


def _isMemberFunctionPointer(node):
    return node[0] == "ind" and node[1].endswith("::*") and node[3][0] == "func"


def _qualifyDeclared(node, quals):
    """Place a data symbol's trailing qualifier on what the symbol declares.

    It belongs one level inside an outermost pointer rather than on the pointer -
    "?s@@3PADB" is "char const *s" and "?s@@3PAPADB" is "char *const *s" - and an array
    passes it on to its element, the way C spells one: "?arr@@3QAY01HB" is
    "int const (*const arr)[2]".
    """
    if not quals:
        return node
    if node[0] == "ind":
        return _indirection(node[1], node[2], _qualifyElement(node[3], quals))
    return _qualifyElement(node, quals)


def _qualifyElement(node, quals):
    if node[0] == "array":
        return _array(node[1], _qualifyElement(node[2], quals))
    return _qualify(node, quals)


def _qualify(node, quals):
    """Add qualifiers to a parsed type, wherever that type keeps them.

    A named type spells them in its text; a pointer or reference carries its own, so they
    join those instead of being appended to a rendering that already placed the sigil.
    """
    if node[0] == "ind":
        return _indirection(node[1], _merge(node[2], quals), node[3])
    # a named type spells its qualifiers in its own text, so one it already carries must not
    # be spelled twice: "?s@@3QBDD" is "char const volatile *const", not "char const const .."
    spelled = node[1].split()
    return _apply_quals(node, tuple(qual for qual in quals if qual not in spelled))


class _Structor:
    """A constructor or destructor: its spelling comes from the class it belongs to."""

    def __init__(self, is_destructor):
        self.is_destructor = is_destructor


class _Bail(Exception):
    """The name is not one this demangler fully understands."""


class _Demangler:
    """A cursor over one decorated name.

    MAX_DEPTH bounds the mutually recursive name and type parser. A level costs several
    interpreter frames here, so the bound is set low enough that CPython's own recursion
    limit is never the thing that stops a parse - otherwise the answer would depend on how
    deep the caller already is. max_render bounds the rendered result, which back-reference
    reuse can otherwise grow multiplicatively.
    """

    MAX_DEPTH = 64

    def __init__(self, mangled):
        self.text = mangled
        self.pos = 0
        self.name_backrefs = []
        self.arg_backrefs = []
        self.simple = True
        self.template_depth = 0
        self.at_symbol_name = True
        self.requires_signature = False
        self.nested = False
        self.pointee_depth = 0
        self.array_element_depth = 0
        self.member_cv = ""
        self.depth = 0
        self.max_render = 8 * len(mangled) + 256

    def eof(self):
        return self.pos >= len(self.text)

    def peek(self):
        if self.eof():
            raise _Bail
        return self.text[self.pos]

    def take(self):
        char = self.peek()
        self.pos += 1
        return char

    def eat(self, char):
        if not self.eof() and self.text[self.pos] == char:
            self.pos += 1
            return True
        return False

    def expect(self, char):
        if not self.eat(char):
            raise _Bail

    def identifier(self):
        end = self.text.find("@", self.pos)
        if end < 0:
            raise _Bail
        name = self.text[self.pos : end]
        if not name:
            raise _Bail
        self.pos = end + 1
        return name

    def rememberName(self, name):
        """Record a name for later back-references, the way the mangler recorded it.

        A name is added only when it is not already held and while the table is under ten
        entries. Both rules move the indices every later back-reference resolves against, so
        appending unconditionally does not merely miss a compression - it reads "?3" as the
        fourth name where the mangler counted three, and answers a name the grammar refuses.
        """
        if name not in self.name_backrefs and len(self.name_backrefs) < 10:
            self.name_backrefs.append(name)

    def templateInstantiation(self, operator=None):
        """A "?$" template name, read in its own back-reference scope.

        The name is usually an identifier, and is recorded inside the fresh scope; when it
        is an operator instead the caller has already read it, and there is nothing to
        record - "??$?HH@S@@QEAAAEAU0@H@Z" is S::operator+<int>.

        The scope opens before the template's own name does, so that name takes index 0
        inside it and the arguments are numbered from 1 - which is what a back-reference
        written inside the argument list resolves against. The rendered result belongs to
        the enclosing scope instead, and the caller records it there.
        """
        saved_names, saved_args = self.name_backrefs, self.arg_backrefs
        self.name_backrefs, self.arg_backrefs = [], []
        self.template_depth += 1
        try:
            if operator is None:
                base = self.identifier()
                self.rememberName(base)
                if self.eof() or self.peek() == "@":
                    raise _Bail
            else:
                base = operator
            args = []
            while not self.eat("@"):
                if self.eof():
                    raise _Bail
                if self.text.startswith("$$V", self.pos) and not self.text.startswith("$$$V", self.pos):
                    # the other spelling of an empty pack
                    self.pos += 3
                    continue
                if self.text.startswith("$$$V", self.pos):
                    # an empty pack: "f<>" has an argument list and no arguments in it
                    self.pos += 4
                    continue
                if self.text.startswith("$$Z", self.pos):
                    # a pack separator, which stands between arguments and is not one
                    self.pos += 3
                    continue
                args.append(self.rendered(self.type()))
            return f"{base}<{', '.join(args)}>"
        finally:
            self.template_depth -= 1
            self.name_backrefs, self.arg_backrefs = saved_names, saved_args

    def nameFragment(self, is_leading):
        """One fragment, paired with which spelling its special-name code takes, if any.

        The caller needs that apart from the spelling: a tag type is always named by an
        identifier, and a special name takes either a signature or a storage class by
        which code it is, never both.
        """
        # every later qualified name belongs to a type, and the exception below is only for
        # the symbol's own name, so the very first leading fragment is the one that counts
        is_symbol_name = is_leading and self.at_symbol_name
        if is_leading:
            self.at_symbol_name = False
        char = self.peek()
        if char in string.digits:
            index = int(self.take())
            if index >= len(self.name_backrefs):
                raise _Bail
            return self.name_backrefs[index], None
        if char == "?":
            self.take()
            if self.eat("$"):
                if self.peek() in string.digits:
                    raise _Bail
                operator = None
                if self.peek() == "?":
                    # a template whose name is an operator: "??$?HH@S@@" is operator+<int>
                    self.take()
                    operator, _ = self.operatorName()
                    if not isinstance(operator, str):
                        raise _Bail
                rendered = self.templateInstantiation(operator=operator)
                if not is_symbol_name:
                    # the symbol's own template name is the one exception the mangler makes:
                    # it is not recorded, so "??$f@H@N@@YAXV0@@Z" resolves 0 to N, not to
                    # f<int>. A template met anywhere else is recorded like any other name.
                    self.rememberName(rendered)
                return rendered, "func" if operator else None
            if is_leading:
                # "??A" here is operator[], not the namespace below: the leading fragment is
                # the symbol's own name, and a namespace can only qualify it
                return self.operatorName()
            if self.peek() == "A":
                return self.anonymousNamespace(), None
            # a scope number is written the way a template argument's is, so it may be
            # nibbles too; "A" is not among them because "?A" is the namespace above
            if self.peek() in string.digits or self.peek() in "@BCDEFGHIJKLMNOP":
                return self.localScope(), None
            raise _Bail
        name = self.identifier()
        self.rememberName(name)
        return name, None

    def localScope(self):
        """A scope inside a function: the function's own name, and which scope of it.

        "?1??f@@YAXXZ@" is the second scope of "void __cdecl f(void)". The enclosing name is a complete decorated name in its
        own right and is read as one, in its own back-reference scopes - which is why it is
        parsed by a separate cursor over the same text rather than inline.
        """
        # the scope carries the number a template argument does - a digit standing for itself
        # plus one, nibbles ended by "@" standing for themselves - except that a bare "@" is
        # the scope spelled zero
        spelled = "0" if self.eat("@") else self.templateInteger()
        self.expect("?")
        inner = _Demangler(self.text)
        inner.pos = self.pos
        inner.nested = True
        # the enclosing name continues this name's back-reference table rather than opening
        # its own: "?N@?1??SN@?$NS@H@0@QEAAHXZ@4HA" resolves its 0 to the outer N
        inner.name_backrefs = self.name_backrefs
        inner.arg_backrefs = self.arg_backrefs
        # the enclosing name is a symbol in its own right, so its own leading template is
        # not recorded either - the same exception the outer name gets
        inner.at_symbol_name = True
        inner.depth = self.depth
        enclosing = inner.parse()
        self.pos = inner.pos
        return f"`{enclosing}'::`{spelled}'"

    def anonymousNamespace(self):
        """The unnamed namespace of one translation unit: "?A" and an optional discriminator.

        The discriminator tells two of them apart inside one binary, and the reference does
        not spell it, so two anonymous namespaces render alike - which is what C++ source
        looks like too.
        """
        self.expect("A")
        start = self.pos
        if self.eat("0"):
            if not self.eat("x"):
                raise _Bail
            digits = 0
            while not self.eof() and self.peek() in string.hexdigits:
                self.take()
                digits += 1
            if not digits:
                raise _Bail
        # the discriminator, not the spelling, is what a later back-reference resolves to:
        # "?f@?A0x1@@YAXV1@@Z" names its parameter "class 0x1"
        self.rememberName(self.text[start : self.pos])
        self.expect("@")
        return "`anonymous namespace'"

    def operatorName(self):
        """The operator or special name, paired with which spelling it takes."""
        if self.eat("_"):
            if self.eat("_"):
                code = self.peek()
                if code in _DYNAMIC_INITIALISERS:
                    self.take()
                    if self.peek() == "?":
                        # the object it runs for is named plainly, not by another special name
                        raise _Bail
                    # what it runs for is recorded, unlike a literal operator's suffix:
                    # "??__EFoo@@YAXU0@@Z" resolves its 0 to Foo
                    self.requires_signature = True
                    target = self.identifier()
                    if not self.eat("@"):
                        # the object may be named with scopes, and the whole of that name
                        # belongs inside the quotes rather than around them
                        raise _Bail
                    self.pos -= 1
                    self.rememberName(target)
                    return f"`{_DYNAMIC_INITIALISERS[code]} '{target}''", "func"
                if self.take() != "K":
                    raise _Bail
                # a user-defined literal: the identifier after the code is its suffix, and
                # the reference spells the pair as operator ""suffix
                return f'operator ""{self.identifier()}', "func"
            code = self.take()
            name = _EXTENDED_OPERATORS.get(code)
            if name is None:
                raise _Bail
            if code in _UNMODELLED_DATA_SPECIAL_OPERATORS:
                raise _Bail
            return name, "data" if code in _DATA_SPECIAL_OPERATORS else "func"
        code = self.take()
        if code in ("0", "1"):
            return _Structor(code == "1"), "func"
        name = _OPERATORS.get(code)
        if name is None:
            raise _Bail
        return name, "func"

    def qualifiedName(self):
        """Count a name level against the depth bound; type() is what enforces it."""
        self.depth += 1
        try:
            return self.qualifiedNameBody()
        finally:
            self.depth -= 1

    def qualifiedNameBody(self):
        first, special_form = self.nameFragment(True)
        scopes = []
        while True:
            if self.eat("@"):
                break
            if self.eof():
                raise _Bail
            scopes.append(self.nameFragment(False)[0])
        scopes.reverse()
        if isinstance(first, _Structor):
            if not scopes:
                raise _Bail
            klass = scopes[-1]
            first = "~" + klass if first.is_destructor else klass
            return "::".join(scopes + [first]), True, special_form
        return "::".join(scopes + [first]), False, special_form

    def type(self, quals=()):
        self.depth += 1
        if self.depth > self.MAX_DEPTH:
            raise _Bail
        try:
            return self.typeBody(quals)
        finally:
            self.depth -= 1

    def typeBody(self, quals):
        """One type, qualified by `quals`.

        A digit is a back-reference standing for a whole argument type, so it is only a type
        where a whole argument is one. A qualifier in front of it, or a pointer or reference
        around it - "?h@@YAXPAHPA0@Z" - is a name the mangler cannot have produced, and
        reading one invented a spelling for it.
        """
        char = self.take()
        if char in _BASIC_TYPES:
            return _apply_quals(_base(_BASIC_TYPES[char]), quals)
        if char == "_":
            name = _EXTENDED_TYPES.get(self.take())
            if name is None:
                raise _Bail
            self.simple = False
            return _apply_quals(_base(name), quals)
        if char in _TAGGED_TYPES:
            kind = _TAGGED_TYPES[char]
            if kind == "enum":
                self.expect("4")
            name, _, special_form = self.qualifiedName()
            if special_form is not None:
                raise _Bail
            self.simple = False
            return _apply_quals(_base(f"{kind} {name}"), quals)
        if char == "Y":
            return self.arrayType(quals)
        if char in _POINTER_KINDS:
            return self.indirection(_merge(_POINTER_KINDS[char], quals), "*")
        if char == "A":
            if quals:
                raise _Bail
            # only "A" introduces a reference. "B" would be a volatile-qualified one, which
            # C++ has no way to write and no Microsoft-compatible mangler emits, so reading
            # it produced answers for names that cannot exist: "?f2@@YAXBDPAD@Z".
            return self.indirection((), "&")
        if char == "$":
            return self.dollarType(quals)
        if char in string.digits:
            # a digit is an argument back-reference, which stands for a whole argument and is
            # read as one in parameters(). Reaching it here means it was written where only a
            # type belongs - a pointee, a template argument, a return type - and the mangler
            # writes none of those; reading them invented spellings for impossible names.
            raise _Bail
        raise _Bail

    def rendered(self, node, declarator=""):
        text = _render(node, declarator)
        if len(text) > self.max_render:
            raise _Bail
        return text

    def dimension(self):
        """A count or an extent, written the way a template argument's number is."""
        spelled = self.templateInteger()
        if spelled.startswith("-"):
            raise _Bail
        return int(spelled)

    def arrayType(self, quals):
        count = self.dimension()
        # an extent of nothing is spelled with nothing: "$$BY0A@H" is "int[]"
        dims = "".join(f"[{extent or ''}]" for extent in (self.dimension() for _ in range(count)))
        self.array_element_depth += 1
        try:
            element = self.type(quals)
        finally:
            self.array_element_depth -= 1
        self.simple = False
        return _array(dims, element)

    def templateInteger(self):
        """The integer a "$0" template argument carries.

        A single digit stands for itself plus one, so "$00" is 1. Anything larger is spelled
        as nibbles from "A" to "P" terminated by "@", most significant first, and a leading
        "?" negates it: "$0M@" is 12 and "$0?0" is -1.

        The accumulator is 64 bits wide and wraps, which is visible in the corpus: the
        eighteen nibbles of "$0HPPPPPPPPPPPPPPPPPP@" are 18446744073709551615, and a
        magnitude that wraps to zero under a minus sign is spelled "-0".
        """
        negative = self.eat("?")
        char = self.peek()
        if char in string.digits:
            value = int(self.take()) + 1
        else:
            value = 0
            digits = 0
            while not self.eof() and "A" <= self.peek() <= "P":
                value = (value * 16 + (ord(self.take()) - ord("A"))) & 0xFFFFFFFFFFFFFFFF
                digits += 1
            if not digits:
                raise _Bail
            self.expect("@")
        return f"-{value}" if negative else str(value)

    def dollarType(self, quals):
        if self.peek() == "0":
            if not self.template_depth:
                # an integer is an argument, not a type: it appears only in a template list
                raise _Bail
            self.take()
            self.simple = False
            return _base(self.templateInteger())
        if not self.eat("$"):
            raise _Bail
        if self.eat("B"):
            # the type as written rather than as a parameter would decay it; an integer is
            # an argument rather than a type, so it is not what this introduces
            if self.peek() == "$":
                raise _Bail
            return self.type(quals)
        if self.eat("Y"):
            # an alias template is named rather than described
            self.simple = False
            return _base(self.qualifiedName()[0])
        kind = self.take()
        if kind == "Q":
            return self.indirection(quals, "&&")
        if kind == "C":
            if not (self.template_depth or self.array_element_depth):
                # "$$C" qualifies an array element or a template argument. As a parameter of
                # its own, or as the pointee of a pointer or reference, it is not a type:
                # "?f@@YAX$$CBH@Z" and "?f@@YAXPA$$CBH@Z" are not names
                raise _Bail
            extra = _CV_QUALS.get(self.take())
            if extra is None:
                raise _Bail
            return self.type(_merge(extra, quals))
        if kind == "T":
            self.simple = False
            return _apply_quals(_base("std::nullptr_t"), quals)
        if kind == "A":
            return self.functionTypeArgument()
        raise _Bail

    def returnType(self):
        """A return type, which unlike any other position may carry a qualifier of its own.

        Every function returning a class by value is spelled this way, so the prefix is
        ordinary rather than exotic: `?A` is the unqualified case, not an absent one.
        """
        quals = ()
        if self.eat("?"):
            quals = _CV_QUALS.get(self.take())
            if quals is None:
                raise _Bail
        return self.type(quals)

    def indirection(self, own_quals, token):
        """A pointer or reference: `token` plus its own quals, over a qualified pointee."""
        has_ptr64 = self.eat("E")
        if self.eat("I"):
            own_quals = own_quals + ("__restrict",)
        # "__unaligned" qualifies what the pointer points at, and is spelled after the
        # pointee's own const and volatile: "int const __unaligned *"
        unaligned = ("__unaligned",) if self.eat("F") else ()
        if self.eat("8"):
            return self.memberFunctionPointer(own_quals, token, has_ptr64)
        if token == "*" and self.peek() in _MEMBER_DATA_QUALS:
            # only a pointer points into a class; C++ has no reference to member, so "AT..."
            # is not a name however much it looks like one
            return self.memberDataPointer(own_quals, token, unaligned)
        if self.eat("6"):
            if has_ptr64:
                # no mangler writes __ptr64 in front of a function type: "P6A" and "R6A"
                # are names, "PE6A" and "RE6A" are not
                raise _Bail
            convention = _CALLING_CONVENTIONS.get(self.take())
            if convention is None:
                raise _Bail
            returns = self.returnType()
            # a parameter of this function type is a whole-argument position again, so a
            # back-reference is legal there even when the function type is itself a pointee
            saved_pointee_depth = self.pointee_depth
            self.pointee_depth = 0
            try:
                params = self.parameters()
            finally:
                self.pointee_depth = saved_pointee_depth
            self.expect("Z")
            self.simple = False
            return _indirection(token, own_quals, _function(convention, params, returns))
        pointee_quals = _CV_QUALS.get(self.take())
        if pointee_quals is None:
            raise _Bail
        pointee_quals = pointee_quals + unaligned
        self.pointee_depth += 1
        try:
            pointee = self.type(pointee_quals)
        finally:
            self.pointee_depth -= 1
        self.simple = False
        return _indirection(token, own_quals, pointee)

    def memberDataPointer(self, own_quals, token, unaligned=()):
        """A pointer to data member: the class qualifies the declarator, as it does a method.

        The code standing where a pointee's cv would be says both that this points into a
        class and what the member itself is qualified by, so "PRfoo@@D" is
        "char const foo::*".
        """
        member_quals = _MEMBER_DATA_QUALS[self.take()] + unaligned
        owner = self.qualifiedName()[0]
        if self.peek() in ("Q", "R", "S"):
            # the reference does not spell the qualifiers such a pointer would carry here -
            # "PQfoo@@SAPEAX" is "void **foo::*", not "void *const volatile *foo::*" - and
            # nothing on the producer side explains which is right, so this declines
            raise _Bail
        member = self.type(member_quals)
        self.simple = False
        return _indirection(f"{owner}::{token}", own_quals, member)

    def memberFunctionPointer(self, own_quals, token, has_ptr64):
        """A pointer to member function: "P8" and the class it points into.

        The class qualifies the declarator rather than the type - "void (__thiscall S::*)()"
        - and the member's own cv follows the parameter list, where a member function keeps
        it. The __ptr64 modifier is no more written here than in front of a plain function.
        """
        if has_ptr64:
            raise _Bail
        owner = self.qualifiedName()[0]
        member_cv = self.memberQualifiers()
        convention = _CALLING_CONVENTIONS.get(self.take())
        if convention is None:
            raise _Bail
        returns = self.returnType()
        saved_pointee_depth = self.pointee_depth
        self.pointee_depth = 0
        try:
            params = self.parameters()
        finally:
            self.pointee_depth = saved_pointee_depth
        self.expect("Z")
        self.simple = False
        return _indirection(f"{owner}::{token}", own_quals, _function(convention, params, returns, member_cv))

    def functionTypeArgument(self):
        """A function type written as a template argument: "$$A6", or "$$A8" with a qualifier.

        The "8" form is the one a member function's type takes, but it names no class - the
        reference refuses "$$A8S@@AEHXZ" - so it reads as an ordinary function type carrying
        the qualifier that only a member function can have: "int __cdecl(void) const".
        """
        self.simple = False
        member_cv = ""
        if self.eat("8"):
            self.expect("@")
            self.expect("@")
            member_cv = self.memberQualifiers()
        else:
            self.expect("6")
        convention = _CALLING_CONVENTIONS.get(self.take())
        if convention is None:
            raise _Bail
        returns = self.returnType()
        params = self.parameters()
        self.expect("Z")
        return _function(convention, params, returns, member_cv)

    def memberQualifiers(self):
        """What a member function may carry after its parameters: cv, __restrict, a ref.

        They are written modifier-first and spelled the other way round, so "GB" is
        " const &" and "IA" is " __restrict".
        """
        restrict = ""
        reference = ""
        seen = set()
        while self.peek() in "EIGH":
            char = self.take()
            # each of them is written at most once: "HH" is not a name
            if char in seen or (char in "GH" and seen & {"G", "H"}):
                raise _Bail
            seen.add(char)
            if char == "I":
                restrict = " __restrict"
            elif char in ("G", "H"):
                reference = " &" if char == "G" else " &&"
        qualifier = _CV.get(self.take())
        if qualifier is None:
            raise _Bail
        return f"{qualifier}{restrict}{reference}"

    def parameters(self):
        """A parameter list, recording each composite parameter for later back-references.

        A trailing Z before the terminator marks a variadic list.
        """
        if self.eat("X"):
            return "void"
        params = []
        while True:
            if self.eof():
                raise _Bail
            if self.eat("@"):
                break
            if self.peek() == "Z":
                if not params:
                    raise _Bail
                self.take()
                params.append("...")
                break
            if self.peek() in string.digits:
                index = int(self.take())
                if index >= len(self.arg_backrefs):
                    raise _Bail
                params.append(self.rendered(self.arg_backrefs[index]))
                continue
            self.simple = True
            node = self.type()
            if not self.simple and len(self.arg_backrefs) < 10:
                self.arg_backrefs.append(node)
            params.append(self.rendered(node))
        return ", ".join(params)

    def parse(self):
        self.expect("?")
        # "$$J" marks a name that was mangled although it is extern "C"; the digit after it
        # counts how many characters of the original mangling it kept, which is not spelled
        extern_c = ""
        name, has_no_return_type, special_form = self.qualifiedName()
        if self.eof():
            raise _Bail
        char = self.peek()
        if char == "$":
            self.take()
            if not self.eat("$") or self.take() != "J":
                raise _Bail
            if self.eof() or self.peek() not in string.digits:
                raise _Bail
            self.take()
            extern_c = 'extern "C" '
            char = self.peek()
        if char == "9":
            # a name with no signature at all: the linkage is what is being spelled
            self.take()
            if not self.nested and not self.eof():
                raise _Bail
            return f'extern "C" {name}'
        if (special_form == "data") != (char in "67"):
            raise _Bail
        if self.requires_signature and char != "Y" and char not in _FUNCTION_ACCESS:
            # this one runs code, so it is spelled with a signature and never with storage
            raise _Bail
        if char in "67":
            self.take()
            qualifier = _CV.get(self.take())
            if qualifier is None:
                raise _Bail
            # a vftable may say which base it is the table for, as a qualified name of its
            # own: "??_7A@B@@6BC@D@@@" is B::A's table for D::C
            bases = []
            while not self.eat("@"):
                bases.append(self.qualifiedName()[0])
            base = "'s `".join(bases)
            if not self.nested and not self.eof():
                raise _Bail
            spelled = f"{qualifier.strip()} {name}".strip()
            return f"{spelled}{{for `{base}'}}" if base else spelled
        if char in _DATA_ACCESS:
            self.take()
            self.simple = True
            declared = self.type()
            # a pointer into a class spells its own storage the long way, below; the short
            # forms are for everything else
            points_into_class = declared[0] == "ind" and declared[1].endswith("::*")
            # __ptr64 and __restrict stand in front of the qualifier, and only where
            # something is pointed at: "?s@@3PEAHEA" is a name and "?s@@3HEA" is not
            trailing = self.take()
            restrict = ()
            while trailing in ("E", "I"):
                if declared[0] != "ind":
                    raise _Bail
                if trailing == "I":
                    restrict = ("__restrict",)
                trailing = self.take()
            if trailing in _MEMBER_DATA_QUALS:
                # a pointer to data member repeats the member's qualifier here and names its
                # class again by back-reference: "?m@@3PQfoo@@HR1@" is "int const foo::*m"
                member_quals = _MEMBER_DATA_QUALS[trailing]
                self.nameFragment(False)
                self.expect("@")
            elif trailing in _CV_QUALS and not points_into_class:
                member_quals = _CV_QUALS[trailing]
            else:
                raise _Bail
            if not self.nested and not self.eof():
                raise _Bail
            if restrict and "__restrict" not in declared[2]:
                # it qualifies the pointer, not what is pointed at, and is written once
                # however many times it is spelled: "?h3@@3QIAHIA" is "int *const __restrict"
                declared = _indirection(declared[1], declared[2] + restrict, declared[3])
            if member_quals and _isMemberFunctionPointer(declared):
                # a member function keeps its qualifier after the parameters, not on what
                # the pointer points at, so this one joins the function rather than the type
                function = declared[3]
                trailing_cv = "".join(f" {qual}" for qual in member_quals)
                declared = _indirection(
                    declared[1],
                    declared[2],
                    _function(function[1], function[2], function[3], function[4] + trailing_cv),
                )
            else:
                declared = _qualifyDeclared(declared, member_quals)
            return f"{_DATA_ACCESS[char]}{self.rendered(declared, name)}"
        return extern_c + self.function(name, has_no_return_type)

    def function(self, name, has_no_return_type):
        access_char = self.take()
        if access_char == "Y":
            access, is_static, is_virtual = None, False, False
        else:
            entry = _FUNCTION_ACCESS.get(access_char)
            if entry is None:
                raise _Bail
            access, is_static, is_virtual = entry
            if not is_static:
                self.member_cv = self.memberQualifiers()
            else:
                self.member_cv = ""
        convention = _CALLING_CONVENTIONS.get(self.take())
        if convention is None:
            raise _Bail
        if has_no_return_type or self.peek() == "@":
            # an operator may leave the return slot empty, the way a constructor does; a
            # conversion operator may not, since its return is the type it converts to
            self.expect("@")
            returns = None
        else:
            returns = self.returnType()
        params = self.parameters()
        self.expect("Z")
        if not self.nested and not self.eof():
            raise _Bail
        pieces = []
        if access:
            pieces.append(f"{access}: ")
            if is_static:
                pieces.append("static ")
            if is_virtual:
                pieces.append("virtual ")
        if returns is None:
            pieces.append(f"{convention} {name}({params})")
        else:
            pieces.append(self.rendered(_function(convention, params, returns), name))
        if access and not is_static:
            pieces.append(self.member_cv)
        return "".join(pieces)


@lru_cache(maxsize=4096)
def demangle_msvc_symbol(name):
    """Return a readable C++ name, or the original when it is not fully understood.

    A name carrying a control character is refused outright: a decorated name is read from a
    NUL-terminated string of source-legal characters and cannot hold one, and an expansion
    holding it would travel into the report as a symbol name. The identifier is copied into
    the answer verbatim, so testing the input is what keeps the answer clean.
    """
    if not name or not name.startswith("?"):
        return name
    if any(char < " " or char == "\x7f" for char in name):
        return name
    try:
        return _Demangler(name).parse()
    except (_Bail, RecursionError):
        return name
