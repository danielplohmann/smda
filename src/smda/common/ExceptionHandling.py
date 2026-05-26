NON_OPERATIONAL_EXCEPTION_TYPES = (
    AssertionError,
    ImportError,
    MemoryError,
    NameError,
    ReferenceError,
    SyntaxError,
)


def reraise_non_operational_exception(exception):
    if isinstance(exception, NON_OPERATIONAL_EXCEPTION_TYPES):
        raise
