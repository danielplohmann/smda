

class ElfFileLoader(object):

    @staticmethod
    def _isCompatible(data):
        raise NotImplementedError

    @staticmethod
    def mapData(data):
        raise NotImplementedError
