import demangle


class UnableTov0Demangle(Exception):
    def __init__(self, given_str, message="Not able to demangle the given string using v0Demangler"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.given_str}] {self.message}"


class V0Demangler:
    """v0 (_R...) Rust names, spelled the way rustc-demangle's alternate form spells them."""

    def demangle(self, inpstr: str) -> str:
        if not inpstr.startswith(("_R", "__R")):
            raise UnableTov0Demangle(inpstr)
        try:
            return demangle.demangle_strict(inpstr, language="rust")
        except demangle.DemanglingError as exc:
            raise UnableTov0Demangle(inpstr) from exc
