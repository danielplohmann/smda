"""Demangling for MSVC decorated symbol names."""

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
_DATA_SPECIAL_OPERATORS = frozenset("789ABS")
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
_CV_QUALS = {"A": (), "B": ("const",), "C": ("volatile",), "D": ("const", "volatile")}
_CV = {"A": "", "B": " const", "C": " volatile", "D": " const volatile"}


def _base(text):
    return ("base", text)


def _indirection(symbol, quals, inner):
    return ("ind", symbol, quals, inner)


def _array(dims, inner):
    return ("array", dims, inner)


def _function(convention, params, returns):
    return ("func", convention, params, returns)


def _render(node, declarator=""):
    """Spell a type around a declarator, the way C nests one inside the other.

    A pointer or array binds to the declarator built so far, and a name therefore ends up
    *inside* its type: `int (*j)[2]`, not `int (*)[2] j`.
    """
    kind = node[0]
    if kind == "base":
        if not declarator:
            return node[1]
        return node[1] + ("" if declarator.startswith("[") else " ") + declarator
    if kind == "ind":
        token = node[1] + " ".join(node[2])
        nested_function = "(" in declarator and not declarator.startswith(("*", "&"))
        separator = " " if declarator and (node[2] or nested_function) else ""
        return _render(node[3], token + separator + declarator)
    if kind == "array":
        if declarator.startswith(("*", "&")):
            declarator = f"({declarator})"
        return _render(node[2], declarator + node[1])
    convention, params, returns = node[1], node[2], node[3]
    if declarator.startswith(("*", "&")):
        declarator = f"({convention} {declarator})"
    else:
        declarator = f"{convention} {declarator}" if declarator else convention
    return _render(returns, f"{declarator}({params})")


def _merge(left, right):
    merged = [qual for qual in ("const", "volatile") if qual in left or qual in right]
    return tuple(merged)


def _apply_quals(node, quals):
    """Qualify a named type, as a pointee qualifier or a $$C wrapper does.

    Only ever reached with a base node: an indirection merges its qualifiers as it is built,
    and a back-reference declines rather than accept one.
    """
    return _base(f"{node[1]} {' '.join(quals)}") if quals else node


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
        self.templated_table = False
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

    def templateArguments(self):
        """Template arguments, in their own back-reference scopes.

        How those scopes interact with the enclosing name table is not modelled, so a name
        back-reference inside them declines instead of risking a wrong name.
        """
        args = []
        saved_names, saved_args = self.name_backrefs, self.arg_backrefs
        self.name_backrefs, self.arg_backrefs = [], []
        self.template_depth += 1
        try:
            while not self.eat("@"):
                if self.eof():
                    raise _Bail
                args.append(self.rendered(self.type()))
        finally:
            self.template_depth -= 1
            self.name_backrefs, self.arg_backrefs = saved_names, saved_args
        return args

    def nameFragment(self, is_leading):
        """One fragment, paired with which spelling its special-name code takes, if any.

        The caller needs that apart from the spelling: a tag type is always named by an
        identifier, and a special name takes either a signature or a storage class by
        which code it is, never both.
        """
        char = self.peek()
        if char in string.digits:
            if self.template_depth or self.templated_table:
                raise _Bail
            index = int(self.take())
            if index >= len(self.name_backrefs):
                raise _Bail
            return self.name_backrefs[index], None
        if char == "?":
            self.take()
            if self.eat("$"):
                if self.peek() in string.digits + "?":
                    raise _Bail
                base = self.identifier()
                if self.eof() or self.peek() == "@":
                    raise _Bail
                args = self.templateArguments()
                rendered = f"{base}<{', '.join(args)}>"
                self.name_backrefs.append(rendered)
                self.templated_table = True
                return rendered, None
            if is_leading:
                return self.operatorName()
            raise _Bail
        name = self.identifier()
        self.name_backrefs.append(name)
        return name, None

    def operatorName(self):
        """The operator or special name, paired with which spelling it takes."""
        if self.eat("_"):
            code = self.take()
            name = _EXTENDED_OPERATORS.get(code)
            if name is None:
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

        A digit is a back-reference standing for a whole argument type. The reference
        implementation rejects a qualifier in front of one, so a qualified back-reference
        declines rather than inventing a spelling.
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
        if char in ("A", "B"):
            if quals:
                raise _Bail
            own = ("volatile",) if char == "B" else ()
            return self.indirection(own, "&")
        if char == "$":
            return self.dollarType(quals)
        if char in string.digits:
            if quals:
                raise _Bail
            index = int(char)
            if index >= len(self.arg_backrefs):
                raise _Bail
            return self.arg_backrefs[index]
        raise _Bail

    def rendered(self, node, declarator=""):
        text = _render(node, declarator)
        if len(text) > self.max_render:
            raise _Bail
        return text

    def dimension(self):
        char = self.take()
        if char in string.digits:
            return int(char) + 1
        raise _Bail

    def arrayType(self, quals):
        count = self.dimension()
        dims = "".join(f"[{self.dimension()}]" for _ in range(count))
        element = self.type(quals)
        self.simple = False
        return _array(dims, element)

    def dollarType(self, quals):
        if not self.eat("$"):
            raise _Bail
        kind = self.take()
        if kind == "Q":
            return self.indirection(quals, "&&")
        if kind == "C":
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
        self.eat("E")
        if self.eat("I"):
            own_quals = own_quals + ("__restrict",)
        if self.eat("6"):
            convention = _CALLING_CONVENTIONS.get(self.take())
            if convention is None:
                raise _Bail
            returns = self.returnType()
            params = self.parameters()
            self.expect("Z")
            self.simple = False
            return _indirection(token, own_quals, _function(convention, params, returns))
        pointee_quals = _CV_QUALS.get(self.take())
        if pointee_quals is None:
            raise _Bail
        pointee = self.type(pointee_quals)
        self.simple = False
        return _indirection(token, own_quals, pointee)

    def functionTypeArgument(self):
        self.simple = False
        self.expect("6")
        convention = _CALLING_CONVENTIONS.get(self.take())
        if convention is None:
            raise _Bail
        returns = self.returnType()
        params = self.parameters()
        self.expect("Z")
        return _function(convention, params, returns)

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
        name, has_no_return_type, special_form = self.qualifiedName()
        if self.eof():
            raise _Bail
        char = self.peek()
        if (special_form == "data") != (char == "6"):
            raise _Bail
        if char == "6":
            self.take()
            qualifier = _CV.get(self.take())
            if qualifier is None:
                raise _Bail
            self.expect("@")
            if not self.eof():
                raise _Bail
            return f"{qualifier.strip()} {name}".strip()
        if char in _DATA_ACCESS:
            self.take()
            self.simple = True
            declared = self.type()
            trailing = self.take()
            if trailing not in _CV_QUALS or not self.eof():
                raise _Bail
            if self.simple:
                declared = _apply_quals(declared, _CV_QUALS[trailing])
            return f"{_DATA_ACCESS[char]}{self.rendered(declared, name)}"
        return self.function(name, has_no_return_type)

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
                self.eat("E")
                if _CV.get(self.peek()) is None:
                    raise _Bail
                self.member_cv = _CV[self.take()]
            else:
                self.member_cv = ""
        convention = _CALLING_CONVENTIONS.get(self.take())
        if convention is None:
            raise _Bail
        if has_no_return_type:
            self.expect("@")
            returns = None
        else:
            returns = self.returnType()
        params = self.parameters()
        self.expect("Z")
        if not self.eof():
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
