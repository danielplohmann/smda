class DexFileLoader:
    @staticmethod
    def isCompatible(data):
        return bool(len(data) >= 3 and data[0:3] == b"dex")

    @staticmethod
    def mapBinary(data):
        return data

    @staticmethod
    def getBaseAddress(data):
        return 0

    @staticmethod
    def getBitness(data):
        return 32

    @staticmethod
    def getArchitecture(data):
        return "dalvik"

    @staticmethod
    def getAbi(data):
        return ""

    @staticmethod
    def getCodeAreas(data):
        # We return the whole data as code area
        return [(0, 0, len(data))]
