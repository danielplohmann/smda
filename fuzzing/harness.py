"""atheris plumbing shared by the fuzz_*.py entry points.

The target bodies live in targets.py, which imports no atheris; this module is
what instruments them and hands them to libFuzzer.
"""

import logging
import sys

import atheris


def instrumented_target(name):
    """Import the target bodies under atheris instrumentation and return one."""
    with atheris.instrument_imports():
        import targets

    return targets.TARGETS[name]


def run(name):
    logging.disable(logging.CRITICAL)
    atheris.Setup(sys.argv, instrumented_target(name))
    atheris.Fuzz()
