import logging

LOGGER = logging.getLogger(__name__)


class DelphiKbFileLoader(object):

    @staticmethod
    def isCompatible(data):
        return data[:23] == b"IDR Knowledge Base File"

    @staticmethod
    def getBaseAddress(binary):
        # return fixed base address that will allow instruction escaping
        return 0x400000

    @staticmethod
    def mapBinary(binary):
        return binary

    @staticmethod
    def getBitness(binary):
        # we only support 32bit for now
        return 32

    @staticmethod
    def getCodeAreas(binary):
        return []
