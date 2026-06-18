#!/usr/bin/python

import logging
import shutil
import subprocess
from functools import lru_cache

LOGGER = logging.getLogger(__name__)

_CXX_PREFIXES = ("__Z", "_Z")
_SWIFT_PREFIXES = ("_$s", "$s", "_$S", "$S")


@lru_cache(maxsize=4096)
def demangle_macho_symbol(name):
    """Best-effort demangling for Mach-O symbol names (C++ Itanium, Swift).

    Uses host tools when available (``c++filt``, ``llvm-cxxfilt``, ``swift demangle``)
    and returns the original name on failure so analysis stays portable.
    """
    if not name:
        return name
    if name.startswith(_CXX_PREFIXES):
        demangled = _finalize_demangled(name, _demangle_with_tools(name, ("llvm-cxxfilt", "c++filt"), []))
        if demangled:
            return demangled
    if name.startswith(_SWIFT_PREFIXES):
        demangled = _finalize_demangled(name, _demangle_with_tools(name, ("swift",), ["demangle"]))
        if demangled:
            return demangled
    return name


def _finalize_demangled(raw_name, demangled):
    if not demangled:
        return None
    if " ---> " in demangled:
        demangled = demangled.split(" ---> ", 1)[1].strip()
    if demangled and demangled != raw_name:
        return demangled
    return None


def _demangle_with_tools(name, commands, prefix_args):
    for command in commands:
        executable = shutil.which(command)
        if not executable:
            continue
        try:
            completed = subprocess.run(
                [executable, *prefix_args, name],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOGGER.debug("Demangler %s failed for %s: %s", command, name, exc)
            continue
        if completed.returncode != 0:
            continue
        demangled = (completed.stdout or "").strip()
        if demangled and demangled != name:
            return demangled
    return None
