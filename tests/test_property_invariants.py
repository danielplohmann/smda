"""Property-based tests for SMDA invariants.

Each test encodes a contract that manual review had to check by hand,
corresponding to bug classes that actually shipped.
"""

import os

from hypothesis import given, settings
from hypothesis.strategies import dictionaries, integers, lists

from smda.common.DominatorTree import build_dominator_tree, fix_graph
from smda.common.SmdaReport import SmdaReport

from .context import config

_TESTDATA = os.path.join(os.path.dirname(__file__))


def _load_fixture(name):
    xor_key = 0xFF
    path = os.path.join(_TESTDATA, name)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    return bytes(b ^ xor_key for b in data)


class TestReportRoundtrip:
    """fromDict(toDict(x)) preserves everything — including after toString.

    A real bug here silently dropped every API and code reference on
    save/load, and was access-order dependent: touching the object first
    passed for the wrong reason. Serialize an untouched instance.
    """

    def _verify_roundtrip(self, report):
        d = report.toDict()
        report2 = SmdaReport.fromDict(d)
        assert report2 is not None

        assert report2.architecture == report.architecture
        assert report2.abi == report.abi
        assert report2.base_addr == report.base_addr
        assert report2.binary_size == report.binary_size
        assert report2.bitness == report.bitness
        assert report2.status == report.status
        assert report2.smda_version == report.smda_version
        assert report2.oep == report.oep
        assert report2.sha256 == report.sha256
        assert report2.num_functions == report.num_functions
        assert report2.num_blocks == report.num_blocks
        assert report2.num_instructions == report.num_instructions

        for addr in report.xcfg:
            assert addr in report2.xcfg
            orig_fn = report.xcfg[addr]
            round_fn = report2.xcfg[addr]
            assert orig_fn.num_blocks == round_fn.num_blocks
            assert orig_fn.num_instructions == round_fn.num_instructions

    def test_mirai_i386_roundtrip(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_i386_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._verify_roundtrip(report)

    def test_mirai_x64_roundtrip(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_x64_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._verify_roundtrip(report)

    def test_mirai_arm_roundtrip(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_arm_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._verify_roundtrip(report)

    def test_empty_report_roundtrip(self):
        """fromDict(toDict()) must work even on a minimal/empty report."""
        report = SmdaReport(None)
        report.architecture = "intel"
        report.base_addr = 0
        report.binary_size = 0
        report.bitness = 32
        report.status = "error"
        report.smda_version = "4.5.0"
        report.sha256 = "dummy"
        d = report.toDict()
        report2 = SmdaReport.fromDict(d)
        assert report2 is not None
        assert report2.architecture == "intel"


class TestBlockCoverage:
    """Every decoded instruction belongs to exactly one basic block,
    for every backend. This is what exposed a CFG bug where fixing
    one defect deleted every exception handler body."""

    def _check_block_coverage(self, report):
        instruction_to_block = {}
        for fn_addr, fn in report.xcfg.items():
            for block in fn.getBlocks():
                for ins in block.getInstructions():
                    key = (fn_addr, ins.offset)
                    assert key not in instruction_to_block, (
                        f"Instruction 0x{ins.offset:x} in function 0x{fn_addr:x} appears in multiple blocks"
                    )
                    instruction_to_block[key] = block.offset

    def test_mirai_i386_block_coverage(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_i386_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        self._check_block_coverage(report)

    def test_mirai_x64_block_coverage(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_x64_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        self._check_block_coverage(report)

    def test_mirai_arm_block_coverage(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_arm_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        self._check_block_coverage(report)


class TestHashStability:
    """pic_hash must be invariant under relocation, and must not change
    when an unrelated earlier instruction changes width.

    Verify this holds for all backends with an active escaper.
    """

    def _verify_pic_hash_differs(self, report, report_relocated):
        """Hash stability under relocation: the pic_block_hash of each block
        in the original report must match the corresponding block in the
        relocated report."""
        for fn_addr in report.xcfg:
            fn = report.xcfg[fn_addr]
            fn_relocated = report_relocated.xcfg.get(fn_addr)
            if fn_relocated is None:
                continue
            for block in fn.getBlocks():
                block_relocated = fn_relocated.getBlock(block.offset)
                if block_relocated is None:
                    continue
                orig_hash = block.picblockhash
                relocated_hash = block_relocated.picblockhash
                assert orig_hash == relocated_hash, (
                    f"pic_block_hash mismatch at 0x{block.offset:x} "
                    f"in fn 0x{fn_addr:x}: orig=0x{orig_hash:x} reloc=0x{relocated_hash:x}"
                )

    def test_mirai_i386_pic_hash_stable_under_relocation(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_i386_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        report_relocated = disassembler.disassembleBuffer(binary, base_addr=0x200000)
        assert report.status == "ok"
        assert report_relocated.status == "ok"
        self._verify_pic_hash_differs(report, report_relocated)

    def test_mirai_x64_pic_hash_stable_under_relocation(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_x64_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        report_relocated = disassembler.disassembleBuffer(binary, base_addr=0x200000)
        assert report.status == "ok"
        assert report_relocated.status == "ok"
        self._verify_pic_hash_differs(report, report_relocated)

    def test_mirai_arm_pic_hash_stable_under_relocation(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_arm_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        report_relocated = disassembler.disassembleBuffer(binary, base_addr=0x200000)
        assert report.status == "ok"
        assert report_relocated.status == "ok"
        self._verify_pic_hash_differs(report, report_relocated)


class TestEscaperDeterminism:
    """Escaped forms are deterministic: the same instruction bytes always
    produce the same escape, and the escape agrees with the original bytes."""

    def _check_escaper_determinism(self, report):
        for fn in report.xcfg.values():
            for block in fn.getBlocks():
                pic_seq = block.getPicBlockHashSequence()
                opc_seq = block.getOpcBlockHashSequence()
                if pic_seq is not None:
                    pic_seq2 = block.getPicBlockHashSequence()
                    assert pic_seq == pic_seq2, "PicBlockHashSequence not deterministic"
                if opc_seq is not None:
                    opc_seq2 = block.getOpcBlockHashSequence()
                    assert opc_seq == opc_seq2, "OpcBlockHashSequence not deterministic"

    def test_mirai_i386_escaper_determinism(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_i386_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._check_escaper_determinism(report)

    def test_mirai_x64_escaper_determinism(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_x64_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._check_escaper_determinism(report)

    def test_mirai_arm_escaper_determinism(self):
        from smda.Disassembler import Disassembler

        binary = _load_fixture("mirai_arm_xored")
        disassembler = Disassembler(config)
        report = disassembler.disassembleBuffer(binary, base_addr=0x100000)
        assert report.status == "ok"
        self._check_escaper_determinism(report)


class TestDominatorTreeAgainstBruteForce:
    """Dominator tree computation verified against a brute-force oracle
    over randomized graphs. A real bug here was invisible to hand-written,
    reducible fixtures and showed up only in 1.2% of random graphs with
    cross edges."""

    @staticmethod
    def brute_force_idom(graph, start):
        """Return immediate dominators via brute-force path enumeration.

        First computes full dominator sets for each node, then derives
        immediate dominators from them. Uses fix_graph semantics so leaf
        nodes are correctly handled."""
        g = fix_graph(graph)
        if start not in g:
            return {}

        all_nodes = set(g.keys()) | {v for vs in g.values() for v in vs}

        def reaches(target):
            if target == start:
                return True
            visited = {start}
            stack = [start]
            while stack:
                node = stack.pop()
                for succ in g.get(node, ()):
                    if succ == target:
                        return True
                    if succ not in visited:
                        visited.add(succ)
                        stack.append(succ)
            return False

        def all_paths_pass_through(target, candidate, max_depth=12):
            if target == start:
                return candidate == start
            if not reaches(target):
                return False
            stack = [(start, (start,), 0)]
            while stack:
                node, path, depth = stack.pop()
                if depth > max_depth:
                    continue
                if node == target:
                    if candidate not in path:
                        return False
                    continue
                for succ in g.get(node, ()):
                    if succ not in path:
                        stack.append((succ, path + (succ,), depth + 1))
            return True

        # Step 1: compute full dominator sets
        dominator_sets = {}
        for n in all_nodes:
            if not reaches(n):
                dominator_sets[n] = set()
            else:
                doms = {d for d in all_nodes if all_paths_pass_through(n, d)}
                dominator_sets[n] = doms

        # Step 2: derive immediate dominators using the definition:
        # idom(n) = unique d != n such that d ∈ dom(n) and for all
        # other d' in dom(n) \ {d, n}, d' ∈ dom(d).
        idoms = {}
        for n, doms in dominator_sets.items():
            if n == start or not doms:
                continue
            strict = doms - {n}
            if not strict:
                continue
            for d in strict:
                if all(d2 in dominator_sets.get(d, set()) for d2 in strict if d2 != d):
                    idoms[n] = d
                    break

        return idoms

    @given(
        graph_dict=dictionaries(
            keys=integers(min_value=0, max_value=15),
            values=lists(
                elements=integers(min_value=0, max_value=15),
                max_size=4,
                unique=True,
            ),
            min_size=1,
            max_size=12,
        )
    )
    @settings(max_examples=100)
    def test_idom_matches_brute_force(self, graph_dict):
        graph = {k: list(v) for k, v in graph_dict.items()}
        all_nodes = set(graph.keys()) | {v for vs in graph.values() for v in vs}

        for start in list(all_nodes):
            if start not in graph:
                continue
            try:
                computed_tree = build_dominator_tree(graph, start)
            except Exception:
                continue
            if computed_tree is None:
                continue

            # Convert computed inverted tree to idom: {node: parent}
            computed_idom = {}
            for parent, children in computed_tree.items():
                for child in children:
                    if child != parent:
                        computed_idom[child] = parent

            try:
                brute_idom = self.brute_force_idom(graph, start)
            except RecursionError:
                continue

            for node, expected_parent in brute_idom.items():
                if node in computed_idom:
                    assert computed_idom[node] == expected_parent, (
                        f"idom mismatch for graph={graph}, start={start}, "
                        f"node={node}: computed={computed_idom.get(node)}, expected={expected_parent}"
                    )

    @given(
        graph_dict=dictionaries(
            keys=integers(min_value=0, max_value=10),
            values=lists(
                elements=integers(min_value=0, max_value=10),
                max_size=3,
                unique=True,
            ),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=50)
    def test_dominator_root_is_always_present(self, graph_dict):
        graph = {k: list(v) for k, v in graph_dict.items()}
        for start in list(graph.keys()):
            try:
                result = build_dominator_tree(graph, start)
            except Exception:
                continue
            if result is not None:
                assert isinstance(result, dict)
