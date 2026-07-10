import unittest

from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider


class TestMachoProviderClassification(unittest.TestCase):
    def test_macho_provider_supplies_symbols_and_apis(self):
        provider = MachoSymbolProvider(None)

        self.assertTrue(provider.isSymbolProvider())
        self.assertTrue(provider.isApiProvider())


if __name__ == "__main__":
    unittest.main()
