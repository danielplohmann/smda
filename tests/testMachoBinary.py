import unittest
from types import SimpleNamespace
from unittest import mock

from smda.utility import MachoBinary


class _FakeFatBinary(list):
    pass


class _FakeBinary:
    def __init__(self, cpu_type, is_64bit, imagebase, sections=None):
        self.header = SimpleNamespace(cpu_type=cpu_type, is_64bit=is_64bit)
        self.imagebase = imagebase
        self.sections = sections or []


class TestMachoBinary(unittest.TestCase):
    def _fake_lief(self):
        cpu_type = SimpleNamespace(X86="x86", X86_64="x86_64", ARM="arm", ARM64="arm64")
        return SimpleNamespace(
            MachO=SimpleNamespace(
                Binary=_FakeBinary,
                FatBinary=_FakeFatBinary,
                Header=SimpleNamespace(CPU_TYPE=cpu_type),
            )
        )

    def test_active_slice_matches_architecture_and_bitness(self):
        x86 = _FakeBinary("x86_64", True, 0x100000000)
        arm = _FakeBinary("arm64", True, 0x200000000)
        fat = _FakeFatBinary([x86, arm])

        with mock.patch.object(MachoBinary, "lief", self._fake_lief()):
            selected = MachoBinary.get_active_macho_binary(fat, bitness=64, architecture="aarch64")

        self.assertIs(selected, arm)

    def test_active_slice_falls_back_to_first_slice_when_no_match_exists(self):
        first = _FakeBinary("x86_64", True, 0x100000000)
        fat = _FakeFatBinary([first])

        with mock.patch.object(MachoBinary, "lief", self._fake_lief()):
            selected = MachoBinary.get_active_macho_binary(fat, bitness=32, architecture="aarch64")

        self.assertIs(selected, first)

    def test_stub_ranges_use_selected_slice_and_active_base(self):
        x86 = _FakeBinary("x86_64", True, 0x100000000)
        arm_stub = SimpleNamespace(name="__stubs", virtual_address=0x200001000, offset=0x1000, size=0x40)
        arm = _FakeBinary("arm64", True, 0x200000000, sections=[arm_stub])
        fat = _FakeFatBinary([x86, arm])

        with mock.patch.object(MachoBinary, "lief", self._fake_lief()):
            ranges = MachoBinary.get_macho_stub_ranges(
                fat,
                base_addr=0x300000000,
                bitness=64,
                architecture="aarch64",
            )

        self.assertEqual(ranges, [(0x300001000, 0x300001040)])


if __name__ == "__main__":
    unittest.main()
