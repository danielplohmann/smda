

class PeFileLoader(object):

    @staticmethod
    def isCompatible(data):
        raise NotImplementedError

    @staticmethod
    def mapData(data):
        raise NotImplementedError
