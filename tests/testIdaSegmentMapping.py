import unittest

from smda.ida.segment_mapping import assembleSegmentBuffer
from smda.SmdaConfig import SmdaConfig


class IdaSegmentMappingTestSuite(unittest.TestCase):
    """getBinary() must be addressable as buffer[addr - getBaseAddr()].

    Every consumer converts an address to a buffer offset that way
    (DisassemblyResult.getBytes/getByte/dereferenceDword/isAddrWithinMemoryImage, string
    extraction, buffer carving). The old implementation concatenated segment bytes, which
    is only correct when the first segment starts exactly at base_addr and no gaps
    separate the segments. Verified against a real IDA 9.3 database of a PE with
    imagebase 0x400000 and its only section at 0x401000: getBaseAddr() returned 0x400000
    while getBinary() started at 0x401000, so a read of VA 0x401000 landed at buffer
    offset 0x1000 - past the end of the 0x1000-byte buffer, returning nothing.
    """

    @staticmethod
    def _reader(contents):
        """Read from a dict of {start_ea: bytes} as an IDA database would."""

        def read_bytes(addr, size):
            for start, data in contents.items():
                if start <= addr < start + len(data):
                    return data[addr - start : addr - start + size]
            return b""

        return read_bytes

    def test_leading_gap_between_base_and_first_segment_is_padded(self):
        # the real PE case: base 0x400000, single section at 0x401000
        contents = {0x401000: b"\xb8\x2a\x00\x00\x00\xc3"}
        buffer = assembleSegmentBuffer(0x400000, [(0x401000, 0x402000)], self._reader(contents))

        self.assertEqual(len(buffer), 0x2000)
        self.assertEqual(buffer[0x1000:0x1006], b"\xb8\x2a\x00\x00\x00\xc3")
        self.assertEqual(buffer[:0x1000], b"\x00" * 0x1000)

    def test_inter_segment_gaps_are_zero_filled(self):
        contents = {0x1000: b"\xaa" * 0x10, 0x3000: b"\xbb" * 0x10}
        buffer = assembleSegmentBuffer(0x1000, [(0x1000, 0x1010), (0x3000, 0x3010)], self._reader(contents))

        self.assertEqual(len(buffer), 0x2010)
        self.assertEqual(buffer[0:0x10], b"\xaa" * 0x10)
        # without padding, the second segment's bytes would sit at offset 0x10
        self.assertEqual(buffer[0x10:0x2000], b"\x00" * (0x2000 - 0x10))
        self.assertEqual(buffer[0x2000:0x2010], b"\xbb" * 0x10)

    def test_contiguous_segments_from_base_are_unchanged(self):
        # the zero-skew case (a Mach-O whose first segment is the image base) must keep
        # producing exactly the concatenation the old implementation produced
        contents = {0x100000000: b"\x11" * 0x20, 0x100000020: b"\x22" * 0x20}
        buffer = assembleSegmentBuffer(
            0x100000000,
            [(0x100000000, 0x100000020), (0x100000020, 0x100000040)],
            self._reader(contents),
        )

        self.assertEqual(buffer, b"\x11" * 0x20 + b"\x22" * 0x20)

    def test_segments_are_sorted_before_assembly(self):
        contents = {0x1000: b"\xaa" * 0x10, 0x2000: b"\xbb" * 0x10}
        buffer = assembleSegmentBuffer(0x1000, [(0x2000, 0x2010), (0x1000, 0x1010)], self._reader(contents))

        self.assertEqual(buffer[0:0x10], b"\xaa" * 0x10)
        self.assertEqual(buffer[0x1000:0x1010], b"\xbb" * 0x10)

    def test_segments_below_the_base_address_are_skipped(self):
        contents = {0x1000: b"\xcc" * 0x10}
        buffer = assembleSegmentBuffer(0x2000, [(0x1000, 0x1010)], self._reader(contents))

        self.assertEqual(buffer, b"")

    def test_no_segments_returns_empty(self):
        self.assertEqual(assembleSegmentBuffer(0x1000, [], self._reader({})), b"")

    def test_span_beyond_max_image_size_is_truncated_not_allocated(self):
        contents = {0x1000: b"\xdd" * 0x10}
        buffer = assembleSegmentBuffer(
            0x1000,
            [(0x1000, 0x1010), (0x1000 + SmdaConfig.MAX_IMAGE_SIZE * 4, 0x1000 + SmdaConfig.MAX_IMAGE_SIZE * 4 + 0x10)],
            self._reader(contents),
        )

        self.assertEqual(len(buffer), SmdaConfig.MAX_IMAGE_SIZE)
        self.assertEqual(buffer[0:0x10], b"\xdd" * 0x10)


if __name__ == "__main__":
    unittest.main()
