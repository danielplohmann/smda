"""A failing T segment register lookup falls back to A32, but says so once."""

import logging
import types
import unittest
from unittest import mock

from smda.ida import IdaDomainInterface as ida_domain_backend
from smda.ida import IdaIdapythonInterface as idapython_backend
from smda.ida.IdaDomainInterface import IdaDomainInterface
from smda.ida.IdaIdapythonInterface import Ida85Interface


def _failing_idc():
    def get_sreg(offset, register):
        raise RuntimeError("no segment register T")

    return types.SimpleNamespace(get_sreg=get_sreg)


class IdaThumbLookupTestSuite(unittest.TestCase):
    def setUp(self):
        # several test modules call logging.disable(CRITICAL) at import, which would make assertLogs
        # fail whenever one of them shares this worker
        previously_disabled = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previously_disabled)

    def _assertWarnsOnce(self, interface, module):
        with (
            mock.patch.dict("sys.modules", {"idc": _failing_idc()}),
            self.assertLogs(module.LOGGER, level="WARNING") as logs,
        ):
            self.assertFalse(interface.isThumb(0x1000))
            self.assertFalse(interface.isThumb(0x2000))
        self.assertEqual(len(logs.records), 1)
        self.assertIn("no segment register T", logs.output[0])

    def test_domain_interface_warns_once(self):
        self._assertWarnsOnce(IdaDomainInterface(database=object()), ida_domain_backend)

    def test_idapython_interface_warns_once(self):
        self._assertWarnsOnce(Ida85Interface(), idapython_backend)

    def test_successful_lookup_does_not_warn(self):
        idc = types.SimpleNamespace(get_sreg=lambda offset, register: 1)
        with mock.patch.dict("sys.modules", {"idc": idc}), self.assertNoLogs(idapython_backend.LOGGER):
            self.assertTrue(Ida85Interface().isThumb(0x1000))


if __name__ == "__main__":
    unittest.main()
