import unittest

from smda.common.labelprovider.rust_demangler import main as rust_main
from smda.dalvik.DalvikOpcodeDecoder import _decode_register_list_35c


class DalvikRegisterListTestSuite(unittest.TestCase):
    def test_35c_register_count_is_capped_at_five(self):
        # the nibble holds up to 15 but the DEX spec caps format 35c at 5 registers; the
        # returned list was already truncated to 5, so an uncapped count disagreed with it
        raw = bytes([0x6E, 0xF0, 0x00, 0x00, 0x21, 0x43])
        count, registers = _decode_register_list_35c(raw)

        self.assertEqual(count, 5)
        self.assertEqual(count, len(registers))

    def test_35c_normal_count_is_unchanged(self):
        raw = bytes([0x6E, 0x30, 0x00, 0x00, 0x21, 0x43])
        count, registers = _decode_register_list_35c(raw)

        self.assertEqual(count, 3)
        self.assertEqual(len(registers), 3)


class RustDemangleCacheTestSuite(unittest.TestCase):
    def setUp(self):
        self._saved = dict(rust_main._DEMANGLE_CACHE)
        rust_main._DEMANGLE_CACHE.clear()
        self.addCleanup(rust_main._DEMANGLE_CACHE.update, self._saved)
        self.addCleanup(rust_main._DEMANGLE_CACHE.clear)

    def test_cache_is_bounded(self):
        # process-lifetime cache keyed by every mangled name ever seen; a long-running
        # batch must not be able to grow it without limit
        for index in range(rust_main._DEMANGLE_CACHE_MAX_SIZE + 50):
            rust_main._cacheResult(f"_RNvC1a{index}", f"demangled{index}")

        self.assertLessEqual(len(rust_main._DEMANGLE_CACHE), rust_main._DEMANGLE_CACHE_MAX_SIZE)

    def test_cache_still_serves_hits(self):
        rust_main._cacheResult("_RNvC1a1", "value")
        self.assertEqual(rust_main._DEMANGLE_CACHE["_RNvC1a1"], "value")


if __name__ == "__main__":
    unittest.main()
