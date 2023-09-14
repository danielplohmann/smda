import itertools
import bisect


class BlockLocator():
    """ Class that finds a block by any address within.
        When instantiated, creates the required data structures. 
    """

    sorted_blocks_addresses = None
    blocks_dict = None

    def __init__(self, functions):
        # Instantiate the datastructures required : 
        # 1. get a flat list of all the blocks in all the functions
        blocks = list(itertools.chain(*[f.getBlocks() for f in functions]))
        self.sorted_blocks_addresses = sorted(b.offset for b in blocks)

        # 2 a dict of blocks by addresses
        self.blocks_dict = {b.offset:b for b in blocks}
    
    def _get_block_end(self, block):
        last_ins = block.instructions[-1]
        return last_ins.offset + len(last_ins.bytes) // 2 # bytes is actuall a hex string

    def findBlockByContainedAddress(self, inner_address):
        # do a binary search to find the closest address to the left of inner_address
        block_num = bisect.bisect(self.sorted_blocks_addresses, inner_address) - 1
        
        if block_num == -1:
            # target address is smaller than first block. return none
            return None
        
        block_start = self.sorted_blocks_addresses[block_num] 
        block = self.blocks_dict[block_start] 
        block_end = self._get_block_end(block)
        
        # make sure inner_address falls within the selected block  
        if block.offset <= inner_address < block_end: 
            return block

        return None
