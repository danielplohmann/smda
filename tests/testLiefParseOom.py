#!/usr/bin/python
"""Every raw-bytes lief parse entry point must degrade on an allocation failure.

lief is a C++ library: a crafted header makes it attempt an unbounded allocation
that surfaces in Python as MemoryError (std::bad_alloc). MemoryError is
non-operational, so it escapes SMDA's own error handling and aborts the whole
run instead of producing an error report.

Found by fuzzing: with lief 1.0.0, lief.MachO.parse(b".") raises
MemoryError, and MachoFileLoader.parseBinary passed it straight through.

Which of MemoryError and ValueError a malformed header produces depends on the
lief build and version, so both are exercised here through an injected parser
rather than through whichever lief this environment resolves.
"""

import logging
import unittest
from pathlib import Path
from unittest import mock

import lief

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.lief_helper import safe_lief_parse
from smda.utility.MachoFileLoader import MachoFileLoader

logging.disable(logging.CRITICAL)


def _raise_bad_alloc(*_args, **_kwargs):
    raise MemoryError("std::bad_alloc")


def _raise_value_error(*_args, **_kwargs):
    raise ValueError("corrupted or unsupported header")


class SmdaLiefParseOomTest(unittest.TestCase):
    def test_safe_lief_parse_returns_none_on_allocation_failure(self):
        with mock.patch.object(lief, "parse", _raise_bad_alloc):
            self.assertIsNone(safe_lief_parse(b"MZ"))

    def test_safe_lief_parse_honours_a_format_specific_parser(self):
        self.assertIsNone(safe_lief_parse(b".", parser=_raise_bad_alloc))
        self.assertEqual(safe_lief_parse(b".", parser=len), 1)

    def test_safe_lief_parse_returns_none_on_a_native_value_error(self):
        with mock.patch.object(lief, "parse", _raise_value_error):
            self.assertIsNone(safe_lief_parse(b"MZ"))
        self.assertIsNone(safe_lief_parse(b".", parser=_raise_value_error))

    def test_macho_accessors_survive_a_native_value_error(self):
        crafted = b"\xcf\xfa\xed\xfe" + bytes(60)
        with (
            mock.patch.object(lief.MachO, "parse", _raise_value_error),
            mock.patch.object(lief, "parse", _raise_value_error),
        ):
            self.assertEqual(MachoFileLoader.mapBinary(crafted, parsed=None), b"")
            self.assertEqual(MachoFileLoader.getBaseAddress(crafted, parsed=None), 0)
            self.assertEqual(MachoFileLoader.getCodeAreas(crafted, parsed=None), [])

    def test_macho_parse_binary_degrades_instead_of_raising(self):
        with mock.patch.object(lief.MachO, "parse", _raise_bad_alloc):
            self.assertIsNone(MachoFileLoader.parseBinary(b"\xcf\xfa\xed\xfe" + bytes(60)))

    def test_macho_accessors_survive_an_allocation_failure(self):
        crafted = b"\xcf\xfa\xed\xfe" + bytes(60)
        with (
            mock.patch.object(lief.MachO, "parse", _raise_bad_alloc),
            mock.patch.object(lief, "parse", _raise_bad_alloc),
        ):
            self.assertEqual(MachoFileLoader.mapBinary(crafted, parsed=None), b"")
            self.assertEqual(MachoFileLoader.getBaseAddress(crafted, parsed=None), 0)
            self.assertEqual(MachoFileLoader.getCodeAreas(crafted, parsed=None), [])

    def test_dex_allocation_failure_yields_an_error_report_not_a_crash(self):
        """The Dalvik backend parses the DEX itself; a bad_alloc there must stay operational."""
        fixture = Path(__file__).resolve().parent / "blockblast_classes_xored"
        dex = bytes(byte ^ (index % 256) for index, byte in enumerate(fixture.read_bytes()))
        with mock.patch.object(lief.DEX, "parse", _raise_bad_alloc):
            report = Disassembler(SmdaConfig(), backend="dalvik").disassembleUnmappedBuffer(dex)
        self.assertEqual(report.status, "error")


if __name__ == "__main__":
    unittest.main()
