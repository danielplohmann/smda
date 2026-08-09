#!/usr/bin/env python3
"""Validate SMDA's Go pclntab parser against binaries built by real Go toolchains.

Builds one small program across (go version x GOOS/GOARCH x link mode), measures what
SMDA recovers from each, compares it to what Go's own tooling reports, and writes the
result to matrix.json. The binaries are deleted as they are measured - only the matrix
is kept, so the repository never carries multi-megabyte Go samples.

Deliberately not named test*: `make test` collects tests/test*, so this stays out of the
suite. tests/testGoCorpusMatrix.py consumes the matrix this produces.

    python tests/go_corpus/build_matrix.py --out tests/go_corpus/matrix.json

Toolchains come from `go install golang.org/dl/goX.Y.Z@latest && goX.Y.Z download`, which
unpacks into ~/sdk/goX.Y.Z. Anything absent is reported as unavailable rather than skipped
silently.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider  # noqa: E402

SCHEMA_VERSION = 1
HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample", "main.go")

# one release per minor; darwin/arm64 hosts cannot run a toolchain older than 1.16
DEFAULT_VERSIONS = [
    "go1.16.15",
    "go1.17.13",
    "go1.18.10",
    "go1.19.13",
    "go1.20.14",
    "go1.21.13",
    "go1.22.12",
    "go1.23.12",
    "go1.24.13",
    "go1.25.12",
]

# the axes that change how a pclntab is found and read: container format, pointer size,
# byte order. s390x is the only big-endian target Go still ships.
PLATFORMS = [
    ("linux", "amd64"),
    ("linux", "386"),
    ("linux", "arm64"),
    ("linux", "s390x"),
    ("windows", "amd64"),
    ("windows", "386"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
]

MODES = ["default", "stripped", "pie"]

# go tool nm reports section boundary markers alongside functions; they have no pclntab entry
NM_MARKERS = {
    "runtime.text",
    "runtime.etext",
    "runtime.rodata",
    "runtime.erodata",
    "runtime.itablink",
    "runtime.epclntab",
    "runtime.noptrdata",
    "runtime.enoptrdata",
}
# nm annotates the calling convention of assembly routines; the pclntab name has no suffix
NM_ABI_SUFFIX = re.compile(r"\.abi(?:0|internal)$")


# A host can only run a toolchain built for it, and Go published no darwin/arm64 distribution
# before 1.16 - so on an arm64 Mac the 0xFFFFFFFB table family (Go 1.2 through 1.15) cannot be
# exercised by building anything. The distributions themselves are Go binaries built by exactly
# that toolchain, so the shipped gofmt supplies a real sample of the format instead.
DIST_URL = "https://go.dev/dl/{archive}"
DEFAULT_DIST = [
    ("go1.15.15", "linux", "amd64", "tar.gz"),
    ("go1.15.15", "windows", "amd64", "zip"),
]


def toolchain_path(version, sdk_dir):
    return os.path.join(sdk_dir, version, "bin", "go")


def dist_sample(version, goos, goarch, suffix, workdir):
    """Extract gofmt out of an official distribution, returning its path or a failure reason."""
    archive = f"{version}.{goos}-{goarch}.{suffix}"
    archive_path = os.path.join(workdir, archive)
    result = subprocess.run(["curl", "-sSfL", "-o", archive_path, DIST_URL.format(archive=archive)])
    if result.returncode != 0:
        return None, f"download failed: {archive}"
    member = "go/bin/gofmt.exe" if goos == "windows" else "go/bin/gofmt"
    out_path = os.path.join(workdir, f"gofmt_{version}_{goos}_{goarch}")
    try:
        if suffix == "zip":
            with zipfile.ZipFile(archive_path) as bundle, open(out_path, "wb") as handle:
                handle.write(bundle.read(member))
        else:
            with tarfile.open(archive_path) as bundle:
                extracted = bundle.extractfile(member)
                if extracted is None:
                    return None, f"{member} absent from {archive}"
                with open(out_path, "wb") as handle:
                    handle.write(extracted.read())
    except (KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        return None, f"{type(exc).__name__}: {exc}"[:200]
    finally:
        os.remove(archive_path)
    return out_path, None


def dist_list(go_bin):
    result = subprocess.run([go_bin, "tool", "dist", "list"], capture_output=True, text=True)
    if result.returncode != 0:
        return set()
    return set(result.stdout.split())


def build(go_bin, goos, goarch, mode, out_path):
    """Build the sample, returning None on success or a short failure reason."""
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0", GOFLAGS="", GO111MODULE="off")
    command = [go_bin, "build", "-o", out_path]
    if mode == "stripped":
        command += ["-ldflags", "-s -w"]
    elif mode == "pie":
        command += ["-buildmode", "pie"]
    command.append(SAMPLE)
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        return (result.stderr.strip().splitlines() or ["build failed"])[-1][:200]
    return None


def reference_symbols(nm_go_bin, path, goos):
    """Text symbols as Go's own tooling reports them, or None when it cannot read the file."""
    result = subprocess.run([nm_go_bin, "tool", "nm", path], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1] not in ("T", "t") or fields[2] in NM_MARKERS:
            continue
        name = NM_ABI_SUFFIX.sub("", fields[2])
        # reading a PE, nm takes names from the COFF table and leaves the middle dot as
        # stored; reading an ELF it goes through debug/gosym, which renders it as a period
        name = name.replace("·", ".")
        # Mach-O carries assembly routines under the C convention, one underscore ahead of
        # the name the pclntab stores
        if goos == "darwin" and name.startswith("_"):
            name = name[1:]
        symbols[int(fields[0], 16)] = name
    return symbols or None


def measure(path, reference):
    """What SMDA recovers from one binary, against the reference symbol set."""
    with open(path, "rb") as handle:
        binary = handle.read()
    provider = GoSymbolProvider(None)
    cell = {"size": len(binary)}
    try:
        offset = provider.getPcLntabOffset(binary)
    except Exception as exc:
        return dict(cell, status="offset_error", error=f"{type(exc).__name__}: {exc}"[:200])
    if offset is None:
        return dict(cell, status="no_pclntab_found")
    header = provider._readPcLntabHeader(binary, offset)
    cell.update(
        status="parsed",
        pclntab_offset=offset,
        pclntab_version=header["version"] if header else None,
        pclntab_bitness=header["bitness"] if header else None,
    )
    try:
        symbols = provider._parse_pclntab(offset, binary)
    except Exception as exc:
        return dict(cell, status="parse_error", error=f"{type(exc).__name__}: {exc}"[:200])
    cell["symbols_recovered"] = len(symbols)
    if reference is None:
        cell["reference"] = "unavailable"
        return cell
    matched = sum(1 for address, name in reference.items() if symbols.get(address) == name)
    address_only = sum(1 for address in reference if address in symbols)
    cell.update(
        reference="go tool nm",
        reference_symbols=len(reference),
        matched_exactly=matched,
        matched_address_only=address_only,
        recall=round(matched / len(reference), 4),
        address_recall=round(address_only / len(reference), 4),
    )
    return cell


def run_cell(go_bin, nm_go_bin, version, goos, goarch, mode, workdir, inherited_reference=None):
    out_path = os.path.join(workdir, f"sample_{version}_{goos}_{goarch}_{mode}")
    failure = build(go_bin, goos, goarch, mode, out_path)
    if failure is not None:
        return {"status": "build_failed", "error": failure}, None
    try:
        reference = reference_symbols(nm_go_bin, out_path, goos)
        if reference is None:
            # -s -w keeps the pclntab but drops the symbol table nm reads, and leaves every
            # address where the unstripped twin put them, so that twin is the reference
            reference = inherited_reference
        return measure(out_path, reference), reference
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=os.path.join(HERE, "matrix.json"))
    parser.add_argument("--sdk-dir", default=os.path.expanduser("~/sdk"))
    parser.add_argument("--nm-go", default=shutil.which("go"), help="toolchain whose `go tool nm` is the reference")
    parser.add_argument("--versions", nargs="*", default=DEFAULT_VERSIONS)
    args = parser.parse_args()

    if not args.nm_go:
        parser.error("no go on PATH; pass --nm-go")

    cells = []
    with tempfile.TemporaryDirectory(prefix="smda-go-matrix-") as workdir:
        for version in args.versions:
            go_bin = toolchain_path(version, args.sdk_dir)
            if not os.path.exists(go_bin):
                cells.append({"go_version": version, "status": "toolchain_unavailable"})
                print(f"{version}: toolchain unavailable at {go_bin}", file=sys.stderr)
                continue
            supported = dist_list(go_bin)
            for goos, goarch in PLATFORMS:
                if supported and f"{goos}/{goarch}" not in supported:
                    cells.append(
                        {
                            "go_version": version,
                            "goos": goos,
                            "goarch": goarch,
                            "mode": "default",
                            "status": "platform_unsupported",
                        }
                    )
                    continue
                default_reference = None
                for mode in MODES:
                    # "default" runs first so a stripped build can inherit its reference
                    cell, reference = run_cell(
                        go_bin, args.nm_go, version, goos, goarch, mode, workdir, default_reference
                    )
                    if mode == "default":
                        default_reference = reference
                    cell.update(go_version=version, goos=goos, goarch=goarch, mode=mode)
                    cells.append(cell)
                    print(
                        f"{version} {goos}/{goarch} {mode}: {cell['status']}"
                        f" recall={cell.get('recall')} version={cell.get('pclntab_version')}",
                        file=sys.stderr,
                    )

        for version, goos, goarch, suffix in DEFAULT_DIST:
            sample, failure = dist_sample(version, goos, goarch, suffix, workdir)
            if sample is None:
                cell = {"status": "dist_unavailable", "error": failure}
            else:
                try:
                    cell = measure(sample, reference_symbols(args.nm_go, sample, goos))
                finally:
                    os.remove(sample)
            cell.update(go_version=version, goos=goos, goarch=goarch, mode="distribution")
            cells.append(cell)
            print(
                f"{version} {goos}/{goarch} distribution: {cell['status']}"
                f" recall={cell.get('recall')} version={cell.get('pclntab_version')}",
                file=sys.stderr,
            )

    matrix = {
        "schema_version": SCHEMA_VERSION,
        "reference": "go tool nm, text symbols, abi suffixes and boundary markers removed",
        "cells": cells,
    }
    with open(args.out, "w") as handle:
        json.dump(matrix, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {len(cells)} cells to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
