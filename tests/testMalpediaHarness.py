"""Tests for the CI corpus harness (`.github/workflows/scripts/process_malpedia.py`).

Only the sample-selection predicate is covered here: it decides which of the corpus files reach
the benchmark at all, and a file it drops is invisible to every downstream check.
"""

import importlib.util
import struct
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_SCRIPT = _TESTS.parent / ".github" / "workflows" / "scripts" / "process_malpedia.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("process_malpedia", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pm = _load_module()

EM_386 = 0x03
EM_X86_64 = 0x3E
EM_ARM = 0x28


def _elf_header(machine, little_endian=True, bitness_class=2):
    """The first 20 bytes of an ELF header - everything the predicate reads."""
    header = bytearray(20)
    header[0:4] = b"\x7fELF"
    header[4] = bitness_class
    header[5] = 1 if little_endian else 2
    struct.pack_into(("<" if little_endian else ">") + "H", header, 0x12, machine)
    return bytes(header)


def _plain(fixture_name):
    data = (_TESTS / fixture_name).read_bytes()[:64]
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


class TestIntelElfPredicate(unittest.TestCase):
    def test_the_two_machine_types_smda_reads_are_accepted(self):
        for machine in (EM_386, EM_X86_64):
            with self.subTest(machine=hex(machine)):
                self.assertTrue(pm.isIntelElf(_elf_header(machine)))

    def test_a_foreign_machine_type_is_refused(self):
        self.assertFalse(pm.isIntelElf(_elf_header(EM_ARM)))

    def test_the_declared_byte_order_decides_how_the_machine_field_reads(self):
        """A big-endian header storing 0x3e00 reads back as EM_X86_64 if EI_DATA is ignored."""
        header = _elf_header(0x3E00, little_endian=False)

        self.assertFalse(pm.isIntelElf(header))

    def test_a_truncated_or_non_elf_header_is_refused(self):
        self.assertFalse(pm.isIntelElf(_elf_header(EM_X86_64)[:8]))
        self.assertFalse(pm.isIntelElf(b"MZ" + bytes(30)))
        self.assertFalse(pm.isIntelElf(b""))

    def test_a_path_that_cannot_be_read_is_refused_rather_than_raising(self):
        self.assertFalse(pm.isIntelElfFile(_TESTS / "does-not-exist"))


class TestIntelElfPredicateOnRealSamples(unittest.TestCase):
    """The predicate replaced a test on the file's PATH, so it has to be right about real files.

    The bundled foreign-architecture mirai builds are the control: every one of them is an ELF
    that the old path test would also have refused, and refusing them is the behaviour being
    preserved. The x86 fixtures are the half the path test got wrong.
    """

    INTEL = ("mirai_i386_xored", "mirai_x64_xored", "bashlite_xored", "elf_ehframe_hdr_x64_xored")
    FOREIGN = (
        "mirai_arm_xored",
        "mirai_m68k_xored",
        "mirai_mips_xored",
        "mirai_mipsel_xored",
        "mirai_nios2_xored",
        "mirai_openrisc_xored",
        "mirai_ppc_xored",
        "mirai_sh4_xored",
        "mirai_sparc_xored",
        "mirai_xtensa_xored",
    )

    def test_every_bundled_x86_elf_is_accepted(self):
        for name in self.INTEL:
            with self.subTest(fixture=name):
                self.assertTrue(pm.isIntelElf(_plain(name)))

    def test_every_bundled_foreign_architecture_elf_is_refused(self):
        for name in self.FOREIGN:
            with self.subTest(fixture=name):
                self.assertFalse(pm.isIntelElf(_plain(name)))

    def test_the_fixtures_really_are_elf_files(self):
        """Without this the two suites above would agree on anything, including empty reads."""
        for name in self.INTEL + self.FOREIGN:
            with self.subTest(fixture=name):
                self.assertEqual(_plain(name)[:4], b"\x7fELF")


if __name__ == "__main__":
    unittest.main()
