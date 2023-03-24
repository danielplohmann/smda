class BackendInterface(object):

    def __init__(self):
        pass

    def getArchitecture(self):
        raise NotImplementedError

    def getBitness(self):
        raise NotImplementedError

    def getFunctions(self):
        raise NotImplementedError

    def getBlocks(self, function_offset):
        raise NotImplementedError

    def getCodeInRefs(self, offset):
        raise NotImplementedError

    def getCodeOutRefs(self, offset):
        raise NotImplementedError

    def getInstructionBytes(self, offset):
        raise NotImplementedError

    def getFunctionSymbols(self, demangle=False):
        raise NotImplementedError

    def getBaseAddr(self):
        raise NotImplementedError

    def getBinary(self):
        raise NotImplementedError

    def getApiOffsets(self):
        raise NotImplementedError
