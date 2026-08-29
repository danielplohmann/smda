#!/usr/bin/python
"""Opt-in routing of a ReadyToRun assembly to its precompiled native body.

A ReadyToRun assembly ships native code beside its CIL, and its CLR header is why the CIL
half wins by default -- which leaves the native half never analysed. `SmdaConfig`'s
`USE_READYTORUN_NATIVE_ROUTING` offers the other half instead, one address space per
report, and this is what says it reaches exactly those images and no others.

Builds a minimal spec-valid PE32+ x86-64 image (4-byte e_lfanew, real PE\\0\\0 signature per
the repo's PE fixture convention) carrying a CLR header, because the bundled ReadyToRun
fixture cannot answer the routing question: its COFF machine field is 0xfd1d, which names
no instruction set, so the honest answer there is to route nowhere.
"""

import contextlib
import os
import struct
import tempfile
import unittest
from pathlib import Path

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader
from smda.utility.PeFileLoader import PeFileLoader

FIXTURE_DIR = Path(__file__).resolve().parent
IMAGE_BASE = 0x140000000
TEXT_RVA, CLR_RVA, RTR_RVA = 0x1000, 0x2000, 0x3000
FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000
MACHINE_AMD64, MACHINE_ARM64 = 0x8664, 0xAA64

#: push rbp; mov rbp,rsp; pop rbp; ret, then padding to the next 16-byte boundary
FUNCTION = bytes((0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3)) + b"\xcc" * 10
TEXT = FUNCTION * 8


def _clrHeader(managed_native_rva, managed_native_size=196):
    """A 72-byte IMAGE_COR20_HEADER, zero but for its size and ManagedNativeHeader."""
    header = bytearray(72)
    header[0:4] = struct.pack("<I", 72)
    header[0x40:0x48] = struct.pack("<II", managed_native_rva, managed_native_size)
    return bytes(header)


def _buildPe(clr_bytes, rtr_bytes=b"RTR\x00", machine=MACHINE_AMD64, clr_size=None):
    """Minimal PE32+ image: .text (RX) @0x1000, .clr @0x2000, .rtr @0x3000."""
    if clr_size is None:
        clr_size = len(clr_bytes)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)  # e_lfanew

    coff = struct.pack("<HHIIIHH", machine, 3, 0, 0, 0, 240, 0x0022)

    data_dirs = [(0, 0)] * 16
    data_dirs[14] = (CLR_RVA, clr_size)  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # magic PE32+
        14,
        0,  # linker versions
        len(TEXT),
        0,
        0,  # sizes of code / initialized / uninitialized data
        TEXT_RVA,  # entrypoint
        TEXT_RVA,  # base of code
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # win32 version
        0x4000,  # size of image
        FILE_ALIGN,  # size of headers
        0,  # checksum
        3,
        0,  # subsystem CUI, dll characteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,  # stack/heap reserve+commit
        0,  # loader flags
        16,  # number of rva and sizes
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)

    def shdr(name, rva, vsize, raw_off, raw_size, characteristics):
        return struct.pack("<8sIIIIIIHHI", name, vsize, rva, raw_size, raw_off, 0, 0, 0, 0, characteristics)

    sections = (
        shdr(b".text", TEXT_RVA, len(TEXT), 0x200, 0x200, 0x60000020)  # CODE|EXECUTE|READ
        + shdr(b".clr", CLR_RVA, max(len(clr_bytes), 1), 0x400, 0x200, 0x40000040)
        + shdr(b".rtr", RTR_RVA, max(len(rtr_bytes), 1), 0x600, 0x200, 0x40000040)
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    assert len(headers) <= FILE_ALIGN
    blob = bytearray(0x800)
    blob[0 : len(headers)] = headers
    blob[0x200 : 0x200 + len(TEXT)] = TEXT
    blob[0x400 : 0x400 + len(clr_bytes)] = clr_bytes
    blob[0x600 : 0x600 + len(rtr_bytes)] = rtr_bytes
    return bytes(blob)


READY_TO_RUN = _buildPe(_clrHeader(RTR_RVA))
#: same image, ManagedNativeHeader empty: a pure-IL assembly
PURE_IL = _buildPe(_clrHeader(0, 0))
#: same image, the pointed-at header carrying some other signature
FOREIGN_NATIVE_HEADER = _buildPe(_clrHeader(RTR_RVA), rtr_bytes=b"NGEN")


@contextlib.contextmanager
def _written(blob):
    """`blob` on disk at a readable path, for the length of the block.

    A directory rather than NamedTemporaryFile: Windows keeps that handle exclusive, so
    nothing else can open the path and the loader reads an empty file.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fixture.dll")
        with open(path, "wb") as handle:
            handle.write(blob)
        yield path


def _analyse(blob, routing):
    config = SmdaConfig()
    config.USE_READYTORUN_NATIVE_ROUTING = routing
    with _written(blob) as path:
        return Disassembler(config=config).disassembleFile(path)


def _routedArchitecture(blob, routing):
    """The backend the image would be sent to, without running an analysis on it.

    The synthetic assembly carries enough CLR structure to be recognised and none of the
    metadata tables a real one has, so the CIL backend cannot analyse it -- and does not
    need to. What the flag changes is the routing decision, and that is what this reads.
    """
    config = SmdaConfig()
    config.USE_READYTORUN_NATIVE_ROUTING = routing
    with _written(blob) as path:
        loader = FileLoader(path, map_file=True)
        return Disassembler(config=config)._populateBinaryInfo(loader, path).architecture


def _loaderFor(blob):
    with _written(blob) as path:
        return FileLoader(path, map_file=True)


class ReadyToRunDetectionTestSuite(unittest.TestCase):
    def test_a_readytorun_header_names_the_native_instruction_set(self):
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(READY_TO_RUN), "intel")

    def test_an_arm64_readytorun_header_names_aarch64(self):
        blob = _buildPe(_clrHeader(RTR_RVA), machine=MACHINE_ARM64)
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "aarch64")

    def test_an_empty_managed_native_header_is_a_pure_il_assembly(self):
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(PURE_IL), "")

    def test_another_native_headers_signature_is_not_readytorun(self):
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(FOREIGN_NATIVE_HEADER), "")

    def test_a_clr_header_too_short_to_carry_the_field_names_nothing(self):
        blob = _buildPe(_clrHeader(RTR_RVA), clr_size=0x40)
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "")

    def test_a_managed_native_header_too_small_for_the_signature_names_nothing(self):
        """A declared size of three does not become a ReadyToRun header on the fourth byte.

        The signature read is four bytes wide and the size field says how many the header
        actually has, so a header declaring fewer is claiming not to contain one. Without the
        bound the read runs past the declared end and a `RTR\\0` that happens to be there --
        as it is in this fixture, which is otherwise a valid ReadyToRun image -- routes a
        malformed assembly to the native backend.
        """
        for declared in (1, 2, 3):
            with self.subTest(managed_native_size=declared):
                blob = _buildPe(_clrHeader(RTR_RVA, managed_native_size=declared))
                self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "")

    def test_a_managed_native_header_exactly_the_signature_is_enough(self):
        # the other side of the bound, so the pair fails if it is set one too high
        blob = _buildPe(_clrHeader(RTR_RVA, managed_native_size=4))
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "intel")

    def test_a_managed_native_header_outside_the_image_names_nothing(self):
        blob = _buildPe(_clrHeader(0x900000))
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "")

    def test_a_clr_header_truncated_by_its_section_names_nothing(self):
        # the directory declares a full 72-byte header and the section holds less, so the
        # field is inside the declared size and outside the bytes that exist
        blob = _buildPe(_clrHeader(RTR_RVA)[:0x44], clr_size=72)
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "")

    def test_a_buffer_that_does_not_parse_names_nothing(self):
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(b"MZ" + b"\x00" * 128), "")

    def test_an_unrecognised_machine_type_names_nothing(self):
        # the honest answer when the image carries native code but does not say what kind
        blob = _buildPe(_clrHeader(RTR_RVA), machine=0xFD1D)
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(blob), "")

    def test_a_native_pe_with_no_clr_header_names_nothing(self):
        data = (FIXTURE_DIR / "msvc_cxx_pe_xored").read_bytes()
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(data))
        self.assertEqual(PeFileLoader.getArchitecture(decoded), "intel")
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(decoded), "")

    def test_the_bundled_readytorun_fixture_names_no_instruction_set(self):
        # its COFF machine field is 0xfd1d, so the image carries native code and does not
        # say what kind; routing must decline rather than guess
        data = (FIXTURE_DIR / "dotnet_readytorun_pe_xored").read_bytes()
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(data))
        self.assertEqual(PeFileLoader.getArchitecture(decoded), "cil")
        self.assertEqual(PeFileLoader.getReadyToRunArchitecture(decoded), "")


class ReadyToRunRoutingTestSuite(unittest.TestCase):
    def test_the_flag_is_off_by_default(self):
        self.assertFalse(SmdaConfig().USE_READYTORUN_NATIVE_ROUTING)

    def test_a_readytorun_assembly_routes_to_cil_by_default(self):
        self.assertEqual(_routedArchitecture(READY_TO_RUN, routing=False), "cil")

    def test_the_flag_routes_it_to_the_native_backend_instead(self):
        report = _analyse(READY_TO_RUN, routing=True)
        self.assertEqual(report.architecture, "intel")
        self.assertIn(IMAGE_BASE + TEXT_RVA, {function.offset for function in report.getFunctions()})

    def test_the_flag_leaves_a_pure_il_assembly_on_the_cil_backend(self):
        self.assertEqual(_routedArchitecture(PURE_IL, routing=True), "cil")

    def test_the_flag_leaves_a_native_pe_alone(self):
        # nothing about a PE without a CLR header reaches the override at all
        data = (FIXTURE_DIR / "msvc_cxx_pe_xored").read_bytes()
        decoded = bytes(byte ^ (index % 256) for index, byte in enumerate(data))
        self.assertEqual(_routedArchitecture(decoded, routing=True), "intel")

    def test_the_loader_reports_the_native_instruction_set_alongside_cil(self):
        loader = _loaderFor(READY_TO_RUN)
        self.assertEqual(loader.getArchitecture(), "cil")
        self.assertEqual(loader.getReadyToRunArchitecture(), "intel")

    def test_the_loader_reports_nothing_for_a_pure_il_assembly(self):
        loader = _loaderFor(PURE_IL)
        self.assertEqual(loader.getArchitecture(), "cil")
        self.assertEqual(loader.getReadyToRunArchitecture(), "")

    def test_reloading_clears_the_previous_images_answer(self):
        loader = _loaderFor(READY_TO_RUN)
        self.assertEqual(loader.getReadyToRunArchitecture(), "intel")
        loader._loadFile(PURE_IL)
        self.assertEqual(loader.getReadyToRunArchitecture(), "")


if __name__ == "__main__":
    unittest.main()
