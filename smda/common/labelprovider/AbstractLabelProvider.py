#!/usr/bin/python

from abc import abstractmethod

import logging
LOGGER = logging.getLogger(__name__)


class AbstractLabelProvider:

    def __init__(self):
        pass

    @abstractmethod
    def getApi(self, address):
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
