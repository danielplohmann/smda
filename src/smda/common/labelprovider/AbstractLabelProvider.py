#!/usr/bin/python

import logging
from abc import ABC, abstractmethod

LOGGER = logging.getLogger(__name__)


class AbstractLabelProvider(ABC):
    def __init__(self, config):
        self._config = config

    @abstractmethod
    def update(self, binary_info):
        """If the LabelProvider needs to parse from the given target, update() can be used to populate the provider"""
        raise NotImplementedError

    @abstractmethod
    def getApi(self, to_addr, absolute_addr=None):
        """If the LabelProvider has any information about a used API for the given address, return (dll, api), else return None"""
        raise NotImplementedError

    @abstractmethod
    def getSymbol(self, address):
        """If the LabelProvider has any information about a used Symbol for the given address, return the symbol, else return None"""
        raise NotImplementedError

    @abstractmethod
    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return False

    @abstractmethod
    def isSymbolProvider(self):
        """Returns whether the get_symbol(..) function of the AbstractLabelProvider is functional"""
        return False

    @abstractmethod
    def getFunctionSymbols(self):
        """Return all function symbol data"""
        return {}

    def is_active(self):
        """Returns whether this label provider is active and has data loaded for the current binary"""
        return True
