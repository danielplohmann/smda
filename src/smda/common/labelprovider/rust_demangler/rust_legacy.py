import demangle


class UnableToLegacyDemangle(Exception):
    def __init__(self, given_str, message="Not able to demangle the given string using LegacyDemangler"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.given_str}] {self.message}"


class LegacyDemangler:
    """Legacy (_ZN...E) Rust names, spelled the way rustc-demangle's alternate form spells them."""

    def demangle(self, inpstr: str) -> str:
        if not inpstr.startswith(("_ZN", "__ZN")):
            raise UnableToLegacyDemangle(inpstr)
        try:
            return demangle.demangle_strict(inpstr, language="rust")
        except demangle.DemanglingError as exc:
            raise UnableToLegacyDemangle(inpstr) from exc
