import json
import unittest

from smda.common.SmdaFunction import LazyIntKeyDict


class TestLazyIntKeyDictSerialization(unittest.TestCase):
    def test_json_serializes_unconverted_instance(self):
        data = {"4096": "kernel32.dll!Sleep", "8192": "ntdll.dll!NtDelayExecution"}
        lazy = LazyIntKeyDict(data)
        # nothing has been touched/accessed before serialization
        serialized = json.dumps(lazy)
        self.assertNotEqual(serialized, "{}")
        restored = json.loads(serialized)
        self.assertEqual(set(restored.keys()), {"4096", "8192"})

    def test_pop_resolves_int_key(self):
        lazy = LazyIntKeyDict({"16": "foo"})
        self.assertEqual(lazy.pop(16, "MISSING"), "foo")
        self.assertEqual(lazy.pop(16, "MISSING"), "MISSING")

    def test_len_reflects_stored_entries_without_access(self):
        lazy = LazyIntKeyDict({"1": "a", "2": "b", "3": "c"})
        self.assertEqual(len(lazy), 3)


if __name__ == "__main__":
    unittest.main()
