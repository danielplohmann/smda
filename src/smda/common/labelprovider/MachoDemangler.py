#!/usr/bin/python

import logging
import shutil
import subprocess
from functools import lru_cache

from .ItaniumDemangler import demangle_itanium_symbol

LOGGER = logging.getLogger(__name__)

_CXX_PREFIXES = ("__Z", "_Z")
_SWIFT_PREFIXES = ("_$s", "$s", "_$S", "$S")


_SWIFT_CACHE = {}


def primeSwiftSymbols(names):
    """Resolve every Swift name in one call, before the per-symbol lookups begin.

    The Swift demangler is a subprocess, and a Mach-O carrying Swift carries it by the
    hundred: 104 distinct names in the jokerspy corpus sample, at 26 ms of process spawn
    each. Fed the whole set through stdin it answers in 20 ms, and a host with no Swift
    toolchain costs one failed lookup instead of one per symbol.

    stdin rather than argv, because a symbol table can hold more names than a command
    line can carry.
    """
    pending = sorted(
        {
            name
            for name in names
            if name and name.startswith(_SWIFT_PREFIXES) and name not in _SWIFT_CACHE and "\n" not in name
        }
    )
    if not pending:
        return
    demangled = _demangleSwiftBatch(pending)
    if demangled is None:
        return
    for name, result in zip(pending, demangled, strict=True):
        _SWIFT_CACHE[name] = _finalize_demangled(name, result)


def _demangleSwiftBatch(names):
    if "swift" in _UNUSABLE_DEMANGLERS:
        return None
    executable = _find_demangler("swift")
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, "demangle"],
            input="\n".join(names),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOGGER.debug("Batched Swift demangling failed: %s", exc)
        _UNUSABLE_DEMANGLERS.add("swift")
        return None
    if completed.returncode != 0:
        return None
    lines = (completed.stdout or "").splitlines()
    if len(lines) != len(names):
        # the answers are positional, so a short or padded reply cannot be realigned -
        # taking it would label symbols with each other's names
        LOGGER.debug("Swift demangler answered %d names with %d lines; discarding", len(names), len(lines))
        return None
    return lines


@lru_cache(maxsize=4096)
def demangle_macho_symbol(name):
    """Best-effort demangling for Mach-O symbol names (C++ Itanium, Swift).

    Uses pycxxfilt's vendored LLVM demangler for C++ and the optional host
    Swift demangler for Swift symbols. It returns the original name on failure.
    """
    if not name:
        return name
    if name.startswith(_CXX_PREFIXES):
        demangled = _finalize_demangled(name, demangle_itanium_symbol(name))
        if demangled:
            return demangled
    if name.startswith(_SWIFT_PREFIXES):
        if name in _SWIFT_CACHE:
            return _SWIFT_CACHE[name] or name
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


@lru_cache(maxsize=8)
def _find_demangler(command):
    return shutil.which(command)


# a command that could not be executed once will not work for the next symbol either;
# without this every remaining symbol pays another process spawn, or another full timeout
_UNUSABLE_DEMANGLERS = set()


def _demangle_with_tools(name, commands, prefix_args):
    for command in commands:
        if command in _UNUSABLE_DEMANGLERS:
            continue
        executable = _find_demangler(command)
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
            _UNUSABLE_DEMANGLERS.add(command)
            continue
        if completed.returncode != 0:
            continue
        demangled = (completed.stdout or "").strip()
        if demangled and demangled != name:
            return demangled
    return None
