#!/usr/bin/python

"""Shared Mach-O slice selection helpers for loaders and label providers."""

import warnings

import lief


def get_active_macho_binary(lief_binary, *, bitness=None, architecture=""):
    """Return the Mach-O thin binary slice matching SMDA's active metadata."""
    if isinstance(lief_binary, lief.MachO.FatBinary):
        if len(lief_binary) == 0:
            return None
        # Use explicit indexed access (fat_binary.at()/[]) so slice selection
        # doesn't depend on holding onto a live iterator across the loop.
        get_slice = lief_binary.at if hasattr(lief_binary, "at") else lief_binary.__getitem__
        for index in range(len(lief_binary)):
            binary = get_slice(index)
            binary_bitness = 64 if binary.header.is_64bit else 32
            if bitness and binary_bitness != bitness:
                continue
            if architecture:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    cpu_type = getattr(binary.header, "cpu_type", None)
                is_intel = cpu_type in (lief.MachO.Header.CPU_TYPE.X86, lief.MachO.Header.CPU_TYPE.X86_64)
                is_arm = cpu_type in (lief.MachO.Header.CPU_TYPE.ARM, lief.MachO.Header.CPU_TYPE.ARM64)
                if architecture == "intel" and not is_intel:
                    continue
                if architecture in ("arm", "aarch64") and not is_arm:
                    continue
            return binary
        return get_slice(0)
    return lief_binary


def get_macho_address_adjustment(lief_binary, *, base_addr=0, bitness=None, architecture=""):
    """Translate LIEF Mach-O VAs to SMDA's active mapping base."""
    lief_binary = get_active_macho_binary(
        lief_binary,
        bitness=bitness,
        architecture=architecture,
    )
    if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
        return 0
    candidates = []
    if hasattr(lief_binary, "imagebase"):
        candidates.append(lief_binary.imagebase)
    for section in getattr(lief_binary, "sections", []):
        if section.virtual_address:
            candidates.append(section.virtual_address - section.offset)
    lief_base = min(candidates) if candidates else 0
    return base_addr - lief_base if base_addr else 0


def get_macho_stub_ranges(lief_binary, *, base_addr=0, bitness=None, architecture=""):
    """Return [(start, end), ...] for Mach-O import stub sections in SMDA VAs."""
    lief_binary = get_active_macho_binary(
        lief_binary,
        bitness=bitness,
        architecture=architecture,
    )
    if not lief_binary or not isinstance(lief_binary, lief.MachO.Binary):
        return []
    adjustment = get_macho_address_adjustment(
        lief_binary,
        base_addr=base_addr,
        bitness=bitness,
        architecture=architecture,
    )
    ranges = []
    for section in getattr(lief_binary, "sections", []):
        if section.name not in ("__stubs", "__symbol_stub") or not section.virtual_address:
            continue
        start = section.virtual_address + adjustment
        ranges.append((start, start + section.size))
    return ranges
