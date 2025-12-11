def remove_bad_spaces(text):
    """
    Removes spaces that are not separating distinct objects, particularly
    inside templates and parameter lists.
    Based on Ghidra's CondensedString logic.
    """
    if not text:
        return text

    depth = 0
    condensed_parts = []

    # Simple state machine to track depth of <...> and (...)
    # and remove spaces if depth > 0, unless they separate alphanumerics

    for i, char in enumerate(text):
        if char == "<" or char == "(":
            depth += 1
            condensed_parts.append(char)
        elif (char == ">" or char == ")") and depth > 0:
            depth -= 1
            condensed_parts.append(char)
        elif depth > 0 and char == " ":
            # Look ahead
            next_char = text[i + 1] if i + 1 < len(text) else "\0"
            last_char = text[i - 1] if i - 1 >= 0 else "\0"

            if last_char.isalnum() and next_char.isalnum():
                # Keep space as underscore if it separates words inside template?
                # Ghidra says: "separate words with a value so they don't run together; drop the other spaces"
                # But typically Rust types don't have spaces inside unless it's `where T: ...`?
                # Actually Ghidra converts it to underscore if surrounded by chars.
                # Example: `Foo < Bar >` -> `Foo<Bar>`. `Foo < Bar Baz >` -> `Foo<Bar_Baz>`.
                condensed_parts.append("_")
            else:
                # Remove space
                pass
        else:
            condensed_parts.append(char)

    return "".join(condensed_parts)
