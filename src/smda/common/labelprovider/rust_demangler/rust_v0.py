import string
from functools import lru_cache
from typing import Optional


class UnableTov0Demangle(Exception):
    def __init__(self, given_str, message="Not able to demangle the given string using v0Demangler"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.given_str}] {self.message}"


class V0Demangler:
    def __init__(self):
        self.disp = ""
        self.suffix = ""

    def demangle(self, inpstr: str) -> str:
        # Reset state for each call to ensure independent demangling
        self.suffix = ""
        self.disp = ""

        self.inpstr = inpstr[inpstr.index("R") + 1 :]
        self.sanity_check(self.inpstr)

        if ".llvm." in inpstr:
            length = self.inpstr.find(".llvm.")
            candidate = self.inpstr[length + 6 :]
            for i in candidate:
                if i not in string.hexdigits + "@":
                    raise UnableTov0Demangle(inpstr)
            self.inpstr = self.inpstr[:length]

        parser = Parser(self.inpstr, 0)
        # Validate the path structure
        parser.skip_path()
        if (len(parser.inn) > parser.next_val) and parser.inn[parser.next_val].isupper():
            parser.skip_path()

        # Reset parser position for printing
        parser.next_val = 0
        printer = Printer(parser, self.disp, 0)
        printer.print_path(True)

        if "." in self.inpstr:
            self.suffix = self.inpstr[self.inpstr.index(".") : len(self.inpstr)]

        return printer.out + self.suffix

    def sanity_check(self, inpstr: str):
        if not inpstr or not inpstr[0].isupper():
            raise UnableTov0Demangle(inpstr)

        for i in inpstr:
            if ord(i) & 0x80 != 0:
                raise UnableTov0Demangle(inpstr)


class Ident:
    def __init__(self, ascii: str, punycode: str) -> None:
        self.ascii = ascii
        self.punycode = punycode
        self.small_punycode_len = 128
        self.disp = ""
        self.out: list = []
        self.out_len = 0

    def try_small_punycode_decode(self) -> Optional[bool]:
        def f(inp):
            inp = "".join(inp)
            self.disp += inp
            return True

        self.out = ["\0"] * self.small_punycode_len
        self.out_len = 0
        r = self.punycode_decode()

        if r is None:
            return None
        else:
            return f(self.out[: self.out_len])

    def insert(self, i: int, c: str) -> bool:
        """Insert character at position i, shifting existing chars right.

        Returns True on success, False if buffer overflow would occur.
        """
        if self.out_len >= self.small_punycode_len:
            return False
        j = self.out_len
        self.out_len += 1

        while j > i:
            self.out[j] = self.out[j - 1]
            j -= 1
        self.out[i] = c
        return True

    def punycode_decode(self) -> Optional[None]:
        count = 0
        punycode_bytes = self.punycode
        try:
            punycode_bytes[count]
        except IndexError:
            return None

        lent = 0
        for c in self.ascii:
            if not self.insert(lent, c):
                return None
            lent += 1

        base = 36
        t_min = 1
        t_max = 26
        skew = 38
        damp = 700
        bias = 72
        i = 0
        n = 0x80
        while True:
            delta = 0
            w = 1
            k = 0
            while True:
                k += base
                t = min(max((k - bias), t_min), t_max)
                if count >= len(punycode_bytes):
                    return None
                d = punycode_bytes[count]
                count += 1
                if d in string.ascii_lowercase:
                    d = ord(d) - ord("a")
                elif d in string.digits:
                    d = 26 + (ord(d) - ord("0"))
                else:
                    return None

                delta = delta + (d * w)
                if d < t:
                    break
                w *= base - t

            lent += 1
            i += delta
            n += i // lent
            i %= lent

            try:
                c = chr(n)
            except (ValueError, OverflowError):
                return None

            if not self.insert(i, c):
                return None
            i += 1

            try:
                punycode_bytes[count]
            except IndexError:
                return

            delta = delta // damp
            damp = 2

            delta += delta // lent
            k = 0
            while delta > ((base - t_min) * t_max) // 2:
                delta = delta // (base - t_min)
                k += base
            bias = k + ((base - t_min + 1) * delta) // (delta + skew)

    def display(self) -> None:
        if self.try_small_punycode_decode():
            return
        else:
            if self.punycode:
                self.disp += "punycode{"

                if self.ascii:
                    self.disp += self.ascii
                    self.disp += "-"
                self.disp += self.punycode
                self.disp += "}"
            else:
                self.disp += self.ascii


@lru_cache(maxsize=32)
def basic_type(tag: str) -> Optional[str]:
    tagval = {
        "b": "bool",
        "c": "char",
        "e": "str",
        "u": "()",
        "a": "i8",
        "s": "i16",
        "l": "i32",
        "x": "i64",
        "n": "i128",
        "i": "isize",
        "h": "u8",
        "t": "u16",
        "m": "u32",
        "y": "u64",
        "o": "u128",
        "j": "usize",
        "f": "f32",
        "d": "f64",
        "z": "!",
        "p": "_",
        "v": "...",
    }
    if tag in tagval:
        return tagval[tag]
    else:
        return


class Parser:
    def __init__(self, inn: str, next_val: int) -> None:
        self.inn = inn
        self.next_val = next_val

    def peek(self) -> str:
        if self.next_val >= len(self.inn):
            raise UnableTov0Demangle(self.inn)
        return self.inn[self.next_val]

    def eat(self, b: str) -> bool:
        if self.next_val >= len(self.inn):
            return False
        if self.inn[self.next_val] == b:
            self.next_val += 1
            return True
        return False

    def next_func(self) -> str:
        if self.next_val >= len(self.inn):
            raise UnableTov0Demangle(self.inn)
        b = self.inn[self.next_val]
        self.next_val += 1
        return b

    def hex_nibbles(self) -> str:
        start = self.next_val
        while True:
            n = self.next_func()
            if n.isdigit() or (n in "abcdef"):
                continue
            elif n == "_":
                break
            else:
                raise UnableTov0Demangle(self.inn)
        return self.inn[start : self.next_val - 1]

    def digit_10(self) -> Optional[int]:
        d = self.peek()
        if d.isdigit():
            d = int(d)
        else:
            return None
        self.next_val += 1
        return d

    def digit_62(self) -> int:
        d = self.peek()
        if d.isdigit():
            d = int(d)
        elif d.islower():
            d = 10 + (ord(d) - ord("a"))
        elif d.isupper():
            d = 10 + 26 + (ord(d) - ord("A"))
        else:
            raise UnableTov0Demangle(self.inn)
        self.next_val += 1
        return d

    def integer_62(self) -> int:
        if self.eat("_"):
            return 0
        x = 0
        while not self.eat("_"):
            d = self.digit_62()
            x *= 62
            x += d
        return x + 1

    def opt_integer_62(self, tag: str) -> int:
        if not self.eat(tag):
            return 0
        return self.integer_62() + 1

    def disambiguator(self) -> int:
        return self.opt_integer_62("s")

    def namespace(self) -> Optional[str]:
        n = self.next_func()
        if n.isupper():
            return n
        elif n.islower():
            return None
        else:
            raise UnableTov0Demangle(self.inn)

    def backref(self) -> "Parser":
        s_start = self.next_val - 1
        i = self.integer_62()
        if i >= s_start:
            raise UnableTov0Demangle(self.inn)

        return Parser(self.inn, i)

    def ident(self):
        is_punycode = self.eat("u")
        length = self.digit_10()
        if length is not None and length != 0:
            while True:
                d = self.digit_10()
                if d is None:
                    break
                length *= 10
                length += d
        if length is None:
            length = 0

        self.eat("_")

        start = self.next_val
        self.next_val += length
        if self.next_val > len(self.inn):
            raise UnableTov0Demangle(self.inn)

        ident = self.inn[start : self.next_val]
        if is_punycode:
            if "_" in ident:
                i = len(ident) - ident[::-1].index("_") - 1
                idt = Ident(ident[:i], ident[i + 1 :])
            else:
                idt = Ident("", ident)

            if not idt.punycode:
                raise UnableTov0Demangle(self.inn)

            return idt

        else:
            idt = Ident(ident, "")
            return idt

    def skip_path(self):
        val = self.next_func()
        if val.startswith("C"):
            self.disambiguator()
            self.ident()
        elif val.startswith("N"):
            self.namespace()
            self.skip_path()
            self.disambiguator()
            self.ident()

        elif val.startswith("M"):
            self.disambiguator()
            self.skip_path()
            self.skip_type()

        elif val.startswith("X"):
            self.disambiguator()
            self.skip_path()
            self.skip_type()
            self.skip_path()

        elif val.startswith("Y"):
            self.skip_type()
            self.skip_path()

        elif val.startswith("I"):
            self.skip_path()
            while not self.eat("E"):
                self.skip_generic_arg()

        elif val.startswith("B"):
            self.backref()

        else:
            raise UnableTov0Demangle(self.inn)

    def skip_generic_arg(self):
        if self.eat("L"):
            self.integer_62()
        elif self.eat("K"):
            self.skip_const()
        else:
            self.skip_type()

    def skip_type(self):
        n = self.next_func()
        tag = n
        if basic_type(tag):
            pass
        elif n == "R" or n == "Q":
            if self.eat("L"):
                self.integer_62()
            else:
                self.skip_type()
        elif n == "P" or n == "O" or n == "S":
            self.skip_type()
        elif n == "A":
            self.skip_type()
            self.skip_const()
        elif n == "T":
            while not self.eat("E"):
                self.skip_type()
        elif n == "F":
            _binder = self.opt_integer_62("G")
            _is_unsafe = self.eat("U")
            if self.eat("K"):
                c_abi = self.eat("C")
                if not c_abi:
                    abi = self.ident()
                    if abi.ascii or (not abi.punycode):
                        raise UnableTov0Demangle(self.inn)
            while not self.eat("E"):
                self.skip_type()
            self.skip_type()
        elif n == "D":
            _binder = self.opt_integer_62("G")
            while not self.eat("E"):
                self.skip_path()
                while self.eat("p"):
                    self.ident()
                    self.skip_type()
            if not self.eat("L"):
                raise UnableTov0Demangle(self.inn)
            self.integer_62()
        elif n == "B":
            self.backref()
        else:
            self.next_val -= 1
            self.skip_path()

    def skip_const(self):
        if self.eat("B"):
            self.backref()
            return

        ty_tag = self.next_func()
        if ty_tag == "p":
            return
        type1 = ["h", "t", "m", "y", "o", "j", "b", "c"]
        type2 = ["a", "s", "l", "x", "n", "i"]

        if ty_tag in type1:
            pass
        elif ty_tag in type2:
            _ = self.eat("n")
        else:
            raise UnableTov0Demangle(self.inn)
        self.hex_nibbles()
        return


class Printer:
    # Based on Ghidra's rust-demangle.c, we limit recursion to prevent stack overflows
    # or excessive resource usage on malformed inputs.
    RUST_MAX_RECURSION_COUNT = 1024

    def __init__(self, parser, out, bound, recursion=0):
        self.parser = parser
        self.out = out
        self.bound_lifetime_depth = bound
        self.recursion = recursion

    def check_recursion_limit(self):
        """Check and increment recursion counter. Must be paired with decrement."""
        if self.recursion >= self.RUST_MAX_RECURSION_COUNT:
            raise UnableTov0Demangle("Recursion limit exceeded")
        self.recursion += 1

    def invalid(self):
        self.out += "?"
        raise UnableTov0Demangle("Error")

    def parser_mut(self):
        return self.parser

    def eat(self, b):
        par = self.parser_mut()
        return bool(par.eat(b))

    def backref_printer(self):
        p = self.parser_mut()
        # Increment recursion count for backrefs as they involve recursive printing
        return Printer(p.backref(), self.out, self.bound_lifetime_depth, self.recursion + 1)

    def print_lifetime_from_index(self, lt):
        self.out += "'"
        if lt == 0:
            self.out += "_"
            return
        depth = self.bound_lifetime_depth - lt + 1
        if depth <= 0:
            self.invalid()

        if depth < 26:
            c = ord("a") + depth - 1
            self.out += chr(c)
        else:
            self.out += f"_{depth}"

    def in_binder(self, val):
        def f1():
            is_unsafe = self.eat("U")
            if self.eat("K"):
                if self.eat("C"):
                    abi = "C"
                else:
                    ab = self.parser_mut().ident()
                    if not ab.ascii or ab.punycode:
                        self.invalid()
                    abi = ab.ascii
            else:
                abi = None

            if is_unsafe:
                self.out += "unsafe "

            if abi:
                self.out += 'extern "'
                self.out += "-".join(abi.split("_"))
                self.out += '"'

            self.out += "fn("
            self.print_sep_list("print_type", ", ")
            self.out += ")"

            if self.eat("u"):
                pass
            else:
                self.out += " -> "
                self.print_type()

            return ""

        def f2():
            self.print_sep_list("print_dyn_trait", " + ")
            return ""

        bound_lifetimes = self.parser_mut().opt_integer_62("G")

        if bound_lifetimes > 0:
            self.out += "for<"
            for i in range(bound_lifetimes):
                if i > 0:
                    self.out += ", "
                self.bound_lifetime_depth += 1
                self.print_lifetime_from_index(1)

            self.out += "> "

        if val == 1:
            r = f1()
        elif val == 2:
            r = f2()
        else:
            r = ""
        self.bound_lifetime_depth -= bound_lifetimes

        return r

    def print_sep_list(self, f, sep):
        i = 0
        while not self.eat("E"):
            if i > 0:
                self.out += str(sep)
            getattr(self, f)()
            i += 1
        return i

    def print_path(self, in_value):
        self.check_recursion_limit()
        try:
            p = self.parser_mut()
            tag = p.next_func()
            if tag == "C":
                p.disambiguator()
                name = p.ident()
                name.display()
                self.out += name.disp

            elif tag == "N":
                ns = p.namespace()
                self.print_path(in_value)
                dis = p.disambiguator()
                name = p.ident()
                if ns:
                    self.out += "::{"
                    if ns == "C":
                        self.out += "closure"
                    elif ns == "S":
                        self.out += "shim"
                    else:
                        self.out += ns
                    if not name.ascii or (not name.punycode):
                        self.out += ":"
                        name.display()
                        self.out += name.disp

                    self.out += "#"
                    self.out += str(dis)
                    self.out += "}"
                else:
                    if name.ascii or name.punycode:
                        self.out += "::"
                        name.display()
                        self.out += name.disp

            elif tag == "M" or tag == "X" or tag == "Y":
                if tag != "Y":
                    p.disambiguator()
                    p.skip_path()

                self.out += "<"
                self.print_type()

                if tag != "M":
                    self.out += " as "
                    self.print_path(False)

                self.out += ">"

            elif tag == "I":
                self.print_path(in_value)
                if in_value:
                    self.out += "::"

                self.out += "<"
                self.print_sep_list("print_generic_arg", ", ")
                self.out += ">"

            elif tag == "B":
                prin = self.backref_printer()
                prin.print_path(in_value)
                self.out = prin.out

            else:
                self.invalid()
        finally:
            self.recursion -= 1

    def print_generic_arg(self):
        if self.eat("L"):
            lt = self.parser_mut().integer_62()
            self.print_lifetime_from_index(lt)
        elif self.eat("K"):
            self.print_const()
        else:
            self.print_type()

    def print_type(self):
        self.check_recursion_limit()
        try:
            p = self.parser_mut()
            tag = p.next_func()
            if basic_type(tag):
                ty = basic_type(tag)
                self.out += ty
                return

            if tag == "R" or tag == "Q":
                self.out += "&"
                if self.eat("L"):
                    lt = p.integer_62()
                    if lt != 0:
                        self.print_lifetime_from_index(lt)
                        self.out += " "

                if tag != "R":
                    self.out += "mut "

                self.print_type()

            elif tag == "P" or tag == "O":
                self.out += "*"
                if tag != "P":
                    self.out += "mut "
                else:
                    self.out += "const "
                self.print_type()

            elif tag == "A" or tag == "S":
                self.out += "["
                self.print_type()

                if tag == "A":
                    self.out += "; "
                    self.print_const()
                self.out += "]"

            elif tag == "T":
                self.out += "("
                count = self.print_sep_list("print_type", ", ")
                if count == 1:
                    self.out += ","
                self.out += ")"

            elif tag == "F":
                self.in_binder(1)

            elif tag == "D":
                self.out += "dyn "
                self.in_binder(2)

                if not self.eat("L"):
                    self.invalid()

                lt = p.integer_62()
                if lt != 0:
                    self.out += " + "
                    self.print_lifetime_from_index(lt)

            elif tag == "B":
                prin = self.backref_printer()
                prin.print_type()
                self.out = prin.out

            else:
                p = self.parser_mut()
                p.next_val -= 1
                self.print_path(False)
        finally:
            self.recursion -= 1

    def print_path_maybe_open_generics(self):
        if self.eat("B"):
            return self.backref_printer().print_path_maybe_open_generics()

        elif self.eat("I"):
            self.print_path(False)
            self.out += "<"
            self.print_sep_list("print_generic_arg", ", ")
            return True
        else:
            self.print_path(False)
            return False

    def print_dyn_trait(self):
        open = self.print_path_maybe_open_generics()

        while self.eat("p"):
            if not open:
                self.out += "<"
                open = True
            else:
                self.out += ", "

            name = self.parser_mut().ident()
            name.display()
            self.out += name.disp
            self.out += " = "
            self.print_type()

        if open:
            self.out += ">"

    def print_const(self):
        self.check_recursion_limit()
        try:
            if self.eat("B"):
                return self.backref_printer().print_const()

            ty_tag = self.parser_mut().next_func()
            if ty_tag == "p":
                self.out += "_"
                return

            type1 = ["h", "t", "m", "y", "o", "j"]
            type2 = ["a", "s", "l", "x", "n", "i"]

            if ty_tag in type1:
                self.print_const_uint()
            elif ty_tag in type2:
                self.print_const_int()
            elif ty_tag == "b":
                self.print_const_bool()
            elif ty_tag == "c":
                self.print_const_char()
            else:
                self.invalid()

            return
        finally:
            self.recursion -= 1

    def print_const_uint(self):
        hex_val = self.parser_mut().hex_nibbles()

        if len(hex_val) > 16:
            self.out += "0x"
            self.out += hex_val
            return

        self.out += str(int(hex_val, 16))

    def print_const_int(self):
        if self.eat("n"):
            self.out += "-"
        self.print_const_uint()

    def print_const_bool(self):
        hex_val = self.parser_mut().hex_nibbles()

        if hex_val == "0":
            self.out += "false"
        elif hex_val == "1":
            self.out += "true"
        else:
            self.invalid()

    def print_const_char(self):
        hex_val = self.parser_mut().hex_nibbles()

        if len(hex_val) > 8:
            self.invalid()

        char_val = "0x"
        char_val += hex_val
        c = chr(int(char_val, 16))
        self.out += repr(c)
