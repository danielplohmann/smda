class BasicBlock:
    def __init__(self):
        self.start_addr = 0
        self.end_addr = 0
        self.instructions = []
        self.successors = []

    def __str__(self):
        return "0x{:x} - 0x{:x} ({}) -> [{}]".format(
            self.start_addr,
            self.end_addr,
            len(self.instructions),
            ", ".join([f"0x{ref:x}" for ref in self.successors]),
        )
