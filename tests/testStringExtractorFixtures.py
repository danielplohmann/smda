"""String extraction on bundled Rust and C fixtures, for the Go/Rust (pointer, length) modes."""

import logging
import os
import unittest

import pytest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.synthesis.BinarySynthesizer import BinarySynthesizer

from .context import config

logging.disable(logging.CRITICAL)

pytestmark = pytest.mark.slow

# zero padding inside mirai_x64's .rodata
_MIRAI_RODATA_PADDING = 0xE560


def _load_xored_fixture(fixture_name):
    with open(os.path.join(config.PROJECT_ROOT, "tests", fixture_name), "rb") as f_binary:
        binary = f_binary.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(binary))


def _strings(binary):
    string_config = SmdaConfig()
    string_config.WITH_STRINGS = True
    report = Disassembler(string_config).disassembleUnmappedBuffer(binary)
    return report, {
        (ref["ins_addr"], ref["string"]) for function in report.getFunctions() for ref in function.stringrefs
    }


def _planted(binary, marker):
    assert not any(binary[_MIRAI_RODATA_PADDING : _MIRAI_RODATA_PADDING + len(marker)])
    return binary[:_MIRAI_RODATA_PADDING] + marker + binary[_MIRAI_RODATA_PADDING + len(marker) :]


class TestRustPeGnuStrings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = _load_xored_fixture("rust_pe_gnu_xored")
        cls.report, cls.strings = _strings(cls.binary)
        cls.texts = {text for _, text in cls.strings}

    def test_mingw_crt_strings_are_read_to_their_terminator(self):
        for text in (
            "Mingw-w64 runtime failure:\n",
            "Address %p has no image-section",
            "  VirtualQuery failed for %d bytes at address %p",
            "  VirtualProtect failed with code 0x%x",
            "  Unknown pseudo relocation protocol version %d.\n",
            "  Unknown pseudo relocation bit size %d.\n",
            "_matherr(): %s in %s(%g, %g)  (retval=%g)\n",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.texts)

    def test_rust_literals_without_a_usable_length_are_kept(self):
        for text in (
            "cannot modify the panic hook from a panicking thread",
            "assertion failed: self.is_code_point_boundary(new_len)",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.texts)

    def test_packed_literals_are_not_read_into_each_other(self):
        self.assertLessEqual(sum(len(text) > 200 for text in self.texts), 1)

    def test_synthesized_strings_keep_their_bytes(self):
        image = bytearray(self.report.binary_size)
        base = self.report.base_addr
        for data_addr, content in BinarySynthesizer(self.report)._iterStringRefs():
            image[data_addr - base : data_addr - base + len(content)] = content
        for function in self.report.getFunctions():
            for ref in function.stringrefs:
                if ref["type"] in ("ascii", "utf8"):
                    encoded = ref["string"].encode("utf-8")
                    offset = ref["data_addr"] - base
                    self.assertEqual(bytes(image[offset : offset + len(encoded)]), encoded)


class TestGoHelloStrings(unittest.TestCase):
    """go1.24.7 linux/amd64, built with -trimpath -ldflags="-s -w -buildid=" from:

    var table = []string{"alphaTableEntry", "betaTableEntry", "größe"}
    func greet(name string) string { return "hello there " + name }
    func main() { println(greet("smdaGoMarker")); for _, t := range table { println(t) } }
    """

    @classmethod
    def setUpClass(cls):
        cls.report, cls.strings = _strings(_load_xored_fixture("go_hello_amd64_xored"))
        cls.texts = {text for _, text in cls.strings}

    def test_literals_are_read_at_their_length(self):
        for text in ("smdaGoMarker", "hello there "):
            with self.subTest(text=text):
                self.assertIn(text, self.texts)

    def test_packed_literals_are_not_read_into_each_other(self):
        self.assertLessEqual(sum(len(text) > 200 for text in self.texts), 1)
        self.assertGreater(len(self.strings), 1000)


class TestCBinaryLanguageMarkers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = _load_xored_fixture("mirai_x64_xored")
        _, cls.strings = _strings(cls.binary)

    def test_go_build_id_does_not_change_the_strings(self):
        _, strings = _strings(_planted(self.binary, b'Go build ID: "abcdefabcdef"'))
        self.assertEqual(strings, self.strings)

    def test_go_mode_keeps_c_strings_whole(self):
        # a pclntab header is all Go mode takes; cgo links C code like this into Go binaries
        _, strings = _strings(_planted(self.binary, bytes.fromhex("f1ffffff00000108")))
        texts = {text for _, text in strings}
        for text in ("/dev/watchdog", "/dev/misc/watchdog", "url=", "Cookie: "):
            with self.subTest(text=text):
                self.assertIn(text, texts)

    def test_rustc_path_keeps_c_strings_whole(self):
        # a C program linking a Rust staticlib carries this path
        _, strings = _strings(_planted(self.binary, b"/rustc/" + b"0123456789abcdef" * 2 + b"01234567/"))
        texts = {text for _, text in strings}
        for text in ("/dev/watchdog", "ZOJFKRA", "/dev/misc/watchdog"):
            with self.subTest(text=text):
                self.assertIn(text, texts)
        self.assertGreaterEqual(len(strings), len(self.strings))


if __name__ == "__main__":
    unittest.main()
