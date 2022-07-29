#!/usr/bin/python

import logging
from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)

try:
    import lief
    lief.logging.disable()
except:
    lief = None
    LOGGER.warning("3rd party library LIEF not installed - won't be able to extract symbols for ELF files where available.")



class GoSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for Go symbols """

    def __init__(self, config):
        self._config = config
        #addr:func_name
        self._func_symbols = {}

    def isSymbolProvider(self):
        return True

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def set_symbols(self, function_symbols):
        self._func_symbols = function_symbols

