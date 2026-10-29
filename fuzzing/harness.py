"""atheris plumbing shared by the fuzz_*.py entry points.

The target bodies live in targets.py, which imports no atheris; this module is
what instruments them and hands them to libFuzzer.
"""

import logging
import os
import sys

import atheris

# capstone opens its library with RTLD_DEEPBIND when the platform has it, and the
# sanitizer runtime cannot run a library bound that way; the sanitized job preloads
# ASan, so there capstone has to fall back to ordinary binding
if "asan" in os.environ.get("LD_PRELOAD", "") and hasattr(os, "RTLD_DEEPBIND"):
    del os.RTLD_DEEPBIND


def instrumented_target(name):
    """Import the target bodies under atheris instrumentation and return one."""
    with atheris.instrument_imports():
        import targets

    return targets.TARGETS[name]


def run(name):
    logging.disable(logging.CRITICAL)
    atheris.Setup(sys.argv, instrumented_target(name))
    atheris.Fuzz()
