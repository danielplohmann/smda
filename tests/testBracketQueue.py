#!/usr/bin/python

import logging
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.FunctionCandidate import FunctionCandidate
from smda.utility.BracketQueue import BracketQueue

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)

# first couple dozen functions from blobrunner.exe
BENIGN_TEST_DATA = """
55 8B EC 68 00 D2 41 00 E8 B7 4E 00 00 83 C4 04 A1 00 D0 41 00 50 8B 0D 0C D0 41 00 51 E8 DE 04
00 00 83 C4 08 5D C3 CC CC CC CC CC CC CC CC CC 55 8B EC 83 EC 10 68 04 D2 41 00 8B 45 08 50 E8
FE 27 00 00 83 C4 08 89 45 F8 83 7D F8 00 75 18 8B 4D 08 51 68 08 D2 41 00 E8 A2 04 00 00 83 C4
08 33 C0 E9 EC 00 00 00 68 28 D2 41 00 E8 8E 04 00 00 83 C4 04 6A 02 6A 00 8B 55 F8 52 E8 B4 2D
00 00 83 C4 0C 8B 45 F8 50 E8 C4 33 00 00 83 C4 04 89 45 FC 8B 4D FC 51 68 40 D2 41 00 E8 5E 04
00 00 83 C4 08 6A 00 6A 00 8B 55 F8 52 E8 84 2D 00 00 83 C4 0C 8B 45 FC 83 C0 01 89 45 FC 8B 4D
FC 51 E8 C1 49 00 00 83 C4 04 89 45 F0 8B 55 F8 52 6A 01 8B 45 FC 50 8B 4D F0 51 E8 5F 29 00 00
83 C4 10 8B 55 F8 52 E8 1B 26 00 00 83 C4 04 68 58 D2 41 00 E8 07 04 00 00 83 C4 04 6A 40 68 00
30 00 00 8B 45 FC 50 6A 00 FF 15 00 60 41 00 89 45 F4 68 74 D2 41 00 E8 E4 03 00 00 83 C4 04 8B
4D F4 51 68 84 D2 41 00 E8 D3 03 00 00 83 C4 08 68 9C D2 41 00 E8 C6 03 00 00 83 C4 04 8B 55 FC
52 8B 45 F0 50 8B 4D F4 51 E8 F2 0E 00 00 83 C4 0C 8B 45 F4 8B E5 5D C3 CC CC CC CC CC CC CC CC
55 8B EC 83 EC 68 A1 1C D6 41 00 33 C5 89 45 FC 56 57 B9 17 00 00 00 BE B8 D2 41 00 8D 7D A0 F3
A5 8B 45 08 03 45 0C 89 45 9C 83 7D 10 00 75 18 8D 4D A0 51 68 14 D3 41 00 E8 62 03 00 00 83 C4
08 E8 0B 34 00 00 EB 25 83 7D 14 01 75 1F 68 18 D3 41 00 E8 48 03 00 00 83 C4 04 8D 55 98 52 6A
04 6A 01 8B 45 9C 50 FF 15 04 60 41 00 8B 4D 9C 51 68 50 D3 41 00 E8 25 03 00 00 83 C4 08 68 64
D3 41 00 E8 18 03 00 00 83 C4 04 FF 65 9C 5F 5E 8B 4D FC 33 CD E8 40 03 00 00 8B E5 5D C3 CC CC
55 8B EC 68 80 D3 41 00 E8 F3 02 00 00 83 C4 04 68 98 D3 41 00 E8 E6 02 00 00 83 C4 04 68 BC D3
41 00 E8 D9 02 00 00 83 C4 04 68 D4 D3 41 00 E8 CC 02 00 00 83 C4 04 68 30 D4 41 00 E8 BF 02 00
00 83 C4 04 68 80 D4 41 00 E8 B2 02 00 00 83 C4 04 68 F0 D4 41 00 E8 A5 02 00 00 83 C4 04 68 20
D5 41 00 E8 98 02 00 00 83 C4 04 5D C3 CC CC CC 55 8B EC 83 EC 1C C7 45 F8 00 00 00 00 C7 45 EC
00 00 00 00 C7 45 F4 00 00 00 00 C7 45 F0 00 00 00 00 E8 69 FD FF FF 83 7D 08 02 7D 0D E8 5E FF
FF FF 83 C8 FF E9 07 02 00 00 B8 04 00 00 00 C1 E0 00 8B 4D 0C 8B 14 01 52 68 0C D4 41 00 E8 3D
02 00 00 83 C4 08 C7 45 FC 02 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 8B 4D FC 3B 4D 08 0F 8D
4E 01 00 00 68 24 D4 41 00 8B 55 FC 8B 45 0C 8B 0C 90 51 E8 88 46 00 00 83 C4 08 85 C0 75 70 68
58 D5 41 00 E8 F7 01 00 00 83 C4 04 8B 55 FC 83 C2 01 89 55 FC 6A 02 68 70 D5 41 00 8B 45 FC 8B
4D 0C 8B 14 81 52 E8 E5 46 00 00 83 C4 0C 85 C0 75 1D 6A 10 8D 45 E4 50 8B 4D FC 8B 55 0C 8B 04
8A 50 E8 55 4A 00 00 83 C4 0C 89 45 F8 EB 1B 6A 0A 8D 4D E4 51 8B 55 FC 8B 45 0C 8B 0C 90 51 E8
38 4A 00 00 83 C4 0C 89 45 F8 E9 BE 00 00 00 68 74 D5 41 00 8B 55 FC 8B 45 0C 8B 0C 90 51 E8 FD
45 00 00 83 C4 08 85 C0 75 0C C7 45 EC 01 00 00 00 E9 97 00 00 00 68 80 D5 41 00 8B 55 FC 8B 45
0C 8B 0C 90 51 E8 D6 45 00 00 83 C4 08 85 C0 75 10 C7 45 F0 01 00 00 00 C7 45 EC 01 00 00 00 EB
6C 68 88 D5 41 00 8B 55 FC 8B 45 0C 8B 0C 90 51 E8 AB 45 00 00 83 C4 08 85 C0 75 09 C7 45 F4 01
00 00 00 EB 48 68 90 D5 41 00 8B 55 FC 8B 45 0C 8B 0C 90 51 E8 87 45 00 00 83 C4 08 85 C0 75 16
8B 15 00 D0 41 00 52 68 9C D5 41 00 E8 EF 00 00 00 83 C4 08 EB 17 8B 45 FC 8B 4D 0C 8B 14 81 52
68 A8 D5 41 00 E8 D6 00 00 00 83 C4 08 E9 9D FE FF FF 8B 45 F4 50 8B 4D F8 51 8B 55 F0 52 B8 04
00 00 00 C1 E0 00 8B 4D 0C 8B 14 01 52 E8 DE FB FF FF 83 C4 10 89 45 E8 83 7D E8 00 75 12 68 C8
D5 41 00 E8 98 00 00 00 83 C4 04 83 C8 FF EB 41 8B 45 F8 50 68 D8 D5 41 00 E8 82 00 00 00 83 C4
08 8B 4D F4 51 8B 55 F0 52 8B 45 EC 50 8B 4D F8 51 8B 55 E8 52 E8 C6 FC FF FF 83 C4 14 68 F4 D5
41 00 E8 59 00 00 00 83 C4 04 E8 02 31 00 00 33 C0 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC
55 8B EC B8 F8 E8 41 00 5D C3 CC CC CC CC CC CC 55 8B EC 8B 45 14 50 8B 4D 10 51 8B 55 0C 52 8B
45 08 50 E8 D8 FF FF FF 8B 48 04 51 8B 10 52 E8 FE 43 00 00 83 C4 18 5D C3 CC CC CC CC CC CC CC
55 8B EC 83 EC 08 8D 45 0C 89 45 FC 8B 4D FC 51 6A 00 8B 55 08 52 6A 01 E8 EF 20 00 00 83 C4 04
50 E8 AA FF FF FF 83 C4 10 89 45 F8 C7 45 FC 00 00 00 00 8B 45 F8 8B E5 5D C3 3B 0D 1C D6 41 00
F2 75 02 F2 C3 F2 E9 79 02 00 00 56 6A 01 E8 DA 4A 00 00 E8 55 06 00 00 50 E8 79 54 00 00 E8 43
06 00 00 8B F0 E8 D6 56 00 00 6A 01 89 30 E8 F9 03 00 00 83 C4 0C 5E 84 C0 74 73 DB E2 E8 54 08
00 00 68 02 1E 40 00 E8 6D 05 00 00 E8 18 06 00 00 50 E8 2E 4E 00 00 59 59 85 C0 75 51 E8 11 06
00 00 E8 60 06 00 00 85 C0 74 0B 68 A6 1B 40 00 E8 FF 4A 00 00 59 E8 28 06 00 00 E8 23 06 00 00
E8 FD 05 00 00 E8 DC 05 00 00 50 E8 D8 55 00 00 59 E8 E9 05 00 00 84 C0 74 05 E8 A1 50 00 00 E8
C2 05 00 00 E8 50 07 00 00 85 C0 75 01 C3 6A 07 E8 2A 06 00 00 CC E8 EF 05 00 00 33 C0 C3 E8 7E
07 00 00 E8 9E 05 00 00 50 E8 03 56 00 00 59 C3 6A 14 68 A8 B8 41 00 E8 14 08 00 00 6A 01 E8 10
03 00 00 59 84 C0 0F 84 50 01 00 00 32 DB 88 5D E7 83 65 FC 00 E8 C7 02 00 00 88 45 DC A1 FC E1
41 00 33 C9 41 3B C1 0F 84 2F 01 00 00 85 C0 75 49 89 0D FC E1 41 00 68 58 61 41 00 68 40 61 41
00 E8 64 50 00 00 59 59 85 C0 74 11 C7 45 FC FE FF FF FF B8 FF 00 00 00 E9 EF 00 00 00 68 3C 61
41 00 68 34 61 41 00 E8 F9 4F 00 00 59 59 C7 05 FC E1 41 00 02 00 00 00 EB 05 8A D9 88 5D E7 FF
75 DC E8 E0 03 00 00 59 E8 66 05 00 00 8B F0 33 FF 39 3E 74 1B 56 E8 38 03 00 00 59 84 C0 74 10
8B 36 57 6A 02 57 8B CE FF 15 30 61 41 00 FF D6 E8 44 05 00 00 8B F0 39 3E 74 13 56 E8 12 03 00
00 59 84 C0 74 08 FF 36 E8 81 52 00 00 59 E8 79 4F 00 00 8B F8 E8 08 54 00 00 8B 30 E8 FB 53 00
00 57 56 FF 30 E8 66 FB FF FF 83 C4 0C 8B F0 E8 2A 06 00 00 84 C0 74 6B 84 DB 75 05 E8 28 52 00
00 6A 00 6A 01 E8 7A 03 00 00 59 59 C7 45 FC FE FF FF FF 8B C6 EB 35 8B 4D EC 8B 01 8B 00 89 45
E0 51 50 E8 87 47 00 00 59 59 C3 8B 65 E8 E8 EB 05 00 00 84 C0 74 32 80 7D E7 00 75 05 E8 D8 51
00 00 C7 45 FC FE FF FF FF 8B 45 E0 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 C3 6A 07 E8 9C
04 00 00 56 E8 0B 52 00 00 FF 75 E0 E8 C7 51 00 00 CC E8 C4 03 00 00 E9 74 FE FF FF 55 8B EC 6A
00 FF 15 0C 60 41 00 FF 75 08 FF 15 08 60 41 00 68 09 04 00 C0 FF 15 10 60 41 00 50 FF 15 14 60
41 00 5D C3 55 8B EC 81 EC 24 03 00 00 6A 17 E8 5A 08 00 00 85 C0 74 05 6A 02 59 CD 29 A3 E0 DF
41 00 89 0D DC DF 41 00 89 15 D8 DF 41 00 89 1D D4 DF 41 00 89 35 D0 DF 41 00 89 3D CC DF 41 00
66 8C 15 F8 DF 41 00 66 8C 0D EC DF 41 00 66 8C 1D C8 DF 41 00 66 8C 05 C4 DF 41 00 66 8C 25 C0
DF 41 00 66 8C 2D BC DF 41 00 9C 8F 05 F0 DF 41 00 8B 45 00 A3 E4 DF 41 00 8B 45 04 A3 E8 DF 41
00 8D 45 08 A3 F4 DF 41 00 8B 85 DC FC FF FF C7 05 30 DF 41 00 01 00 01 00 A1 E8 DF 41 00 A3 EC
DE 41 00 C7 05 E0 DE 41 00 09 04 00 C0 C7 05 E4 DE 41 00 01 00 00 00 C7 05 F0 DE 41 00 01 00 00
00 6A 04 58 6B C0 00 C7 80 F4 DE 41 00 02 00 00 00 6A 04 58 6B C0 00 8B 0D 1C D6 41 00 89 4C 05
F8 6A 04 58 C1 E0 00 8B 0D 18 D6 41 00 89 4C 05 F8 68 80 61 41 00 E8 E1 FE FF FF C9 C3 55 8B EC
8B 45 08 56 8B 48 3C 03 C8 0F B7 41 14 8D 51 18 03 D0 0F B7 41 06 6B F0 28 03 F2 3B D6 74 19 8B
4D 0C 3B 4A 0C 72 0A 8B 42 08 03 42 0C 3B C8 72 0C 83 C2 28 3B D6 75 EA 33 C0 5E 5D C3 8B C2 EB
F9 56 E8 1B 07 00 00 85 C0 74 20 64 A1 18 00 00 00 BE 00 E2 41 00 8B 50 04 EB 04 3B D0 74 10 33
C0 8B CA F0 0F B1 0E 85 C0 75 F0 32 C0 5E C3 B0 01 5E C3 55 8B EC 83 7D 08 00 75 07 C6 05 04 E2
41 00 01 E8 43 05 00 00 E8 11 0E 00 00 84 C0 75 04 32 C0 5D C3 E8 3F 57 00 00 84 C0 75 0A 6A 00
E8 18 0E 00 00 59 EB E9 B0 01 5D C3 55 8B EC 80 3D 05 E2 41 00 00 74 04 B0 01 5D C3 56 8B 75 08
85 F6 74 05 83 FE 01 75 62 E8 94 06 00 00 85 C0 74 26 85 F6 75 22 68 08 E2 41 00 E8 A2 55 00 00
59 85 C0 75 0F 68 14 E2 41 00 E8 93 55 00 00 59 85 C0 74 2B 32 C0 EB 30 83 C9 FF 89 0D 08 E2 41
00 89 0D 0C E2 41 00 89 0D 10 E2 41 00 89 0D 14 E2 41 00 89 0D 18 E2 41 00 89 0D 1C E2 41 00 C6
05 05 E2 41 00 01 B0 01 5E 5D C3 6A 05 E8 2D 02 00 00 CC 6A 08 68 C8 B8 41 00 E8 31 04 00 00 83
65 FC 00 B8 4D 5A 00 00 66 39 05 00 00 40 00 75 5D A1 3C 00 40 00 81 B8 00 00 40 00 50 45 00 00
75 4C B9 0B 01 00 00 66 39 88 18 00 40 00 75 3E 8B 45 08 B9 00 00 40 00 2B C1 50 51 E8 7C FE FF
FF 59 59 85 C0 74 27 83 78 24 00 7C 21 C7 45 FC FE FF FF FF B0 01 EB 1F 8B 45 EC 8B 00 33 C9 81
38 05 00 00 C0 0F 94 C1 8B C1 C3 8B 65 E8 C7 45 FC FE FF FF FF 32 C0 8B 4D F0 64 89 0D 00 00 00
00 59 5F 5E 5B C9 C3 55 8B EC E8 93 05 00 00 85 C0 74 0F 80 7D 08 00 75 09 33 C0 B9 00 E2 41 00
87 01 5D C3 55 8B EC 80 3D 04 E2 41 00 00 74 06 80 7D 0C 00 75 12 FF 75 08 E8 ED 55 00 00 FF 75
08 E8 B7 0C 00 00 59 59 B0 01 5D C3 55 8B EC 83 3D 08 E2 41 00 FF FF 75 08 75 07 E8 1F 54 00 00
EB 0B 68 08 E2 41 00 E8 7F 54 00 00 59 F7 D8 59 1B C0 F7 D0 23 45 08 5D C3 55 8B EC FF 75 08 E8
C8 FF FF FF F7 D8 59 1B C0 F7 D8 48 5D C3 55 8B EC 83 EC 14 83 65 F4 00 8D 45 F4 83 65 F8 00 50
FF 15 28 60 41 00 8B 45 F8 33 45 F4 89 45 FC FF 15 24 60 41 00 31 45 FC FF 15 20 60 41 00 31 45
FC 8D 45 EC 50 FF 15 1C 60 41 00 8B 45 F0 8D 4D FC 33 45 EC 33 45 FC 33 C1 C9 C3 8B 0D 1C D6 41
00 56 57 BF 4E E6 40 BB BE 00 00 FF FF 3B CF 74 04 85 CE 75 26 E8 94 FF FF FF 8B C8 3B CF 75 07
B9 4F E6 40 BB EB 0E 85 CE 75 0A 0D 11 47 00 00 C1 E0 10 0B C8 89 0D 1C D6 41 00 F7 D1 5F 89 0D
18 D6 41 00 5E C3 33 C0 C3 33 C0 40 C3 B8 00 40 00 00 C3 68 20 E2 41 00 FF 15 2C 60 41 00 C3
"""
FEP_OFFSETS = {
    0x0: [],
    0x30: [],
    0x160: [],
    0x200: [0x160],
    0x270: [0x54B],
    0x4C0: [],
    0x4D0: [0xBAD],
    0x500: [],
    0x53A: [0x610],
    0x54B: [0x54B],
    0x5F6: [0x54B],
    0x5FE: [0x933],
    0x610: [0x610],
    0x792: [0x7C4],
    0x79C: [0x96C, 0x9F3, 0x933],
    0x7C4: [0x7C4],
    0x8BD: [0xBAD],
    0x901: [],
    0x933: [0x96C],
    0x96C: [],
    0x9F3: [0x270],
    0xA87: [],
    0xAA4: [0xBAD, 0x9F3, 0x54B, 0x8BD],
    0xACC: [],
    0xAF9: [0x270],
    0xB0E: [],
    0xB5B: [0x160],
    0xBA6: [0x933, 0x160],
    0xBA9: [0x270],
    0xBAD: [],
}


class BracketQueueTestSuite(unittest.TestCase):
    """Provoke recursion"""

    def fillQueue(self, buffer=None, binary_info=None, max_address=None):
        if buffer is None:
            buffer = bytes(bytearray.fromhex(BENIGN_TEST_DATA))
        if binary_info is None:
            binary_info = BinaryInfo(buffer)
            binary_info.bitness = 32
        queue = BracketQueue()
        candidates = []
        for offset, refs in sorted(FEP_OFFSETS.items(), key=lambda x: x[0]):
            if max_address is not None and offset > max_address:
                continue
            f = FunctionCandidate(binary_info, offset)
            for ref in refs:
                f.addCallRef(ref)
            candidates.append(f)
            queue.add(f)
        return candidates, queue

    def testQueueFilling(self):
        candidates, queue = self.fillQueue()
        print(queue)
        self.assertEqual(len(queue.brackets[0]), 11)
        self.assertEqual(len(queue.brackets[1]), 16)
        self.assertEqual(len(queue.brackets[2]), 3)

    def testQueueUpdates(self):
        buffer = bytes(bytearray.fromhex(BENIGN_TEST_DATA))
        binary_info = BinaryInfo(buffer)
        binary_info.bitness = 32

        candidates, queue = self.fillQueue(max_address=0xB5B)
        new_candidate = FunctionCandidate(binary_info, 0xBA6)
        print(new_candidate)
        # add a new candidate
        queue.add(new_candidate)
        self.assertEqual(len(queue.brackets[0]), 11)
        self.assertEqual(len(queue.brackets[1]), 15)
        self.assertEqual(len(queue.brackets[2]), 2)
        # update call refs for a candidate - add
        new_candidate.addCallRef(0xACC)
        print(new_candidate)
        queue.update(target_candidate=new_candidate)
        self.assertEqual(len(queue.brackets[0]), 10)
        self.assertEqual(len(queue.brackets[1]), 16)
        self.assertEqual(len(queue.brackets[2]), 2)
        # update call refs for a candidate - add
        new_candidate.addCallRef(0x8BD)
        print(new_candidate)
        queue.update(target_candidate=new_candidate)
        self.assertEqual(len(queue.brackets[0]), 10)
        self.assertEqual(len(queue.brackets[1]), 15)
        self.assertEqual(len(queue.brackets[2]), 3)
        # update call refs for a candidate - remove
        new_candidate.removeCallRefs([0xACC, 0x8BD])
        print(new_candidate)
        queue.update(target_candidate=new_candidate)
        self.assertEqual(len(queue.brackets[0]), 11)
        self.assertEqual(len(queue.brackets[1]), 15)
        self.assertEqual(len(queue.brackets[2]), 2)

    def testQueueOrder(self):
        candidates, queue = self.fillQueue()
        for _index, candidate in enumerate(queue):
            print(candidate)
        candidates, queue = self.fillQueue()
        print("*" * 20)
        # run a check that ensures that scores per bracket are decreasing linearly
        queue.ensure_order()
        for _index, candidate in enumerate(queue):
            print(candidate)


if __name__ == "__main__":
    unittest.main()
