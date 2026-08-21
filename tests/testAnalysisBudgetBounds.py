import struct
import traceback
import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
TEXT_RVA = 0x1000
IMAGE_SIZE = 0x40000
PROLOGUE = b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
CHAIN_BLOCKS = 900
TAILCALL_PAIRS = 20


def _config(**overrides):
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _budgetedDisassembler(config, spent_inside=None):
    """A disassembler whose budget is spent only while `spent_inside` is on the stack.

    Naming the frame rather than counting callback invocations keeps the test about the
    question it is asking - is the budget consulted from inside this pass at all - instead of
    about how many times earlier passes happen to poll.
    """

    class _Budgeted(Disassembler):
        def _callbackAnalysisTimeout(self):
            if spent_inside is None:
                return False
            return any(frame.name == spent_inside for frame in traceback.extract_stack())

    return _Budgeted(config=config)


def _blockChainImage(blocks):
    """One function whose body is a chain of `blocks` conditional branches.

    Each `test eax, eax ; jne +0` step opens a new basic block while staying in the same
    function - the shape whose analysis used to run to completion however long it took,
    because nothing consulted the budget inside a function.
    """
    body = bytearray(PROLOGUE)
    for _ in range(blocks):
        body += b"\x85\xc0\x75\x00"
    body += b"\x5d\xc3"  # pop rbp ; ret
    image = bytearray(IMAGE_SIZE)
    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    return bytes(image)


def _tailcallImage(pairs):
    """`pairs` callees whose interior is jumped into from a separate function.

    A jump from outside a function into the middle of it is what the tailcall pass promotes
    into a function of its own, so this image gives that pass real work to do.
    """
    body = bytearray()
    interiors = []
    for _ in range(pairs):
        body += PROLOGUE + b"\x90\x90"
        interiors.append(len(body))
        body += PROLOGUE + b"\x5d\xc3"
    jumps = []
    for _ in interiors:
        jumps.append(len(body))
        body += PROLOGUE + b"\xe9" + struct.pack("<i", 0)
    for jump_at, target in zip(jumps, interiors, strict=True):
        struct.pack_into("<i", body, jump_at + len(PROLOGUE) + 1, target - (jump_at + len(PROLOGUE) + 5))
    image = bytearray(IMAGE_SIZE)
    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    return bytes(image), [BASE + TEXT_RVA + offset for offset in interiors]


class BlockLoopBudgetTestSuite(unittest.TestCase):
    """The budget used to be consulted only between candidates and between passes, so one
    pathological function was analysed to completion once started."""

    def _analyze(self, spent_inside):
        disassembler = _budgetedDisassembler(_config(), spent_inside=spent_inside)
        report = disassembler.disassembleBuffer(_blockChainImage(CHAIN_BLOCKS), BASE, bitness=64)
        functions = list(report.getFunctions())
        blocks = len(list(functions[0].getBlocks())) if functions else 0
        return report, len(functions), blocks

    def test_a_long_function_is_cut_short_when_the_budget_is_spent(self):
        report, functions, blocks = self._analyze(spent_inside="analyzeFunction")

        self.assertEqual(report.status, "timeout")
        self.assertEqual(functions, 1)
        self.assertGreater(blocks, 0)
        self.assertLess(blocks, CHAIN_BLOCKS)

    def test_the_same_function_completes_within_budget(self):
        """Positive control: the cut above has to come from the budget, not from the fixture
        being unanalysable or the chain being shorter than it looks."""
        report, functions, blocks = self._analyze(spent_inside=None)

        self.assertEqual(report.status, "ok")
        self.assertEqual(functions, 1)
        self.assertEqual(blocks, CHAIN_BLOCKS + 1)


class BudgetLatchTestSuite(unittest.TestCase):
    """Once the budget has cut a function short, no later pass may pick the remainder up.

    The block-loop poll leaves the rest of the function undecoded, so its bytes are still
    unclaimed when the gap scan runs. Each orchestrator loop used to ask the callback again
    rather than the recorded verdict, and a callback that answers by where it is called from
    - which is how a caller scopes a budget to one pass - said no. The gap scan then promoted
    the remainder, and a truncated function came back as two.
    """

    def _afterNthCall(self, config, calls):
        """A budget that trips inside analyzeFunction only, and only after `calls` polls."""

        class _Budgeted(Disassembler):
            polls = 0

            def _callbackAnalysisTimeout(self):
                if not any(frame.name == "analyzeFunction" for frame in traceback.extract_stack()):
                    return False
                _Budgeted.polls += 1
                return _Budgeted.polls > calls

        _Budgeted.polls = 0
        return _Budgeted(config=config)

    def _functions(self, calls):
        report = self._afterNthCall(_config(), calls).disassembleBuffer(
            _blockChainImage(CHAIN_BLOCKS), BASE, bitness=64, architecture="intel"
        )
        return report.status, {function.offset for function in report.getFunctions()}

    def test_a_function_cut_short_is_not_carved_into_two(self):
        for calls in (0, 1, 2, 3):
            with self.subTest(polls_before_tripping=calls):
                status, offsets = self._functions(calls)

                self.assertEqual(offsets, {BASE + TEXT_RVA}, f"status={status}")

    def test_the_same_image_is_one_function_with_no_budget_at_all(self):
        """Positive control: the image holds one function, so the assertion above is about
        the cut and not about the fixture."""
        report = Disassembler(config=_config()).disassembleBuffer(
            _blockChainImage(CHAIN_BLOCKS), BASE, bitness=64, architecture="intel"
        )

        self.assertEqual(report.status, "ok")
        self.assertEqual({function.offset for function in report.getFunctions()}, {BASE + TEXT_RVA})


class TailcallPassBudgetTestSuite(unittest.TestCase):
    """`resolveTailcalls` was invoked with no callback at all, so an enabled tailcall pass ran
    to completion regardless of the budget."""

    def _analyze(self, spent_inside, resolve_tailcalls=True):
        image, interiors = _tailcallImage(TAILCALL_PAIRS)
        disassembler = _budgetedDisassembler(_config(RESOLVE_TAILCALLS=resolve_tailcalls), spent_inside=spent_inside)
        report = disassembler.disassembleBuffer(image, BASE, bitness=64)
        recovered = {function.offset for function in report.getFunctions()}
        return report, len(recovered), len(set(interiors) & recovered)

    def test_the_pass_promotes_nothing_once_the_budget_is_spent(self):
        report, _functions, promoted = self._analyze(spent_inside="resolveTailcalls")

        self.assertEqual(report.status, "timeout")
        self.assertEqual(promoted, 0)

    def test_the_pass_promotes_every_interior_entry_within_budget(self):
        """Positive control: with the budget intact the same image gives the pass real work,
        so the zero above is the poll stopping it rather than there being nothing to do."""
        report, _functions, promoted = self._analyze(spent_inside=None)

        self.assertEqual(report.status, "ok")
        self.assertEqual(promoted, TAILCALL_PAIRS)

    def test_nothing_is_promoted_with_the_pass_disabled(self):
        """Second control: the promotions above are the tailcall pass and not ordinary
        candidate discovery finding the interior entries by itself."""
        report, _functions, promoted = self._analyze(spent_inside=None, resolve_tailcalls=False)

        self.assertEqual(report.status, "ok")
        self.assertEqual(promoted, 0)


def _aarch64TailcallImage(pairs):
    """`pairs` AArch64 callees whose interior is branched into from a separate function.

    The intel backend registers a tailcall candidate without queueing it, so the drain after
    the tailcall pass has nothing to take; the AArch64 one queues, which is the arm that
    actually reaches the loop.
    """
    prologue, nop, ret = 0xA9BF7BFD, 0xD503201F, 0xD65F03C0
    word = lambda value: struct.pack("<I", value)  # noqa: E731
    body = bytearray()
    interiors = []
    for _ in range(pairs):
        body += word(prologue) + word(nop)
        interiors.append(len(body))
        body += word(prologue) + word(ret)
    branches = []
    for _ in interiors:
        branches.append(len(body))
        body += word(prologue) + word(0)
    for branch_at, target in zip(branches, interiors, strict=True):
        offset = target - (branch_at + 4)
        struct.pack_into("<I", body, branch_at + 4, 0x14000000 | ((offset // 4) & 0x03FFFFFF))
    image = bytearray(IMAGE_SIZE)
    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    return bytes(image), [BASE + TEXT_RVA + offset for offset in interiors]


class TailcallDrainBudgetTestSuite(unittest.TestCase):
    """The drain that follows the tailcall pass is an orchestrator loop like the others, so
    it has to consult the recorded verdict rather than re-ask a callback that may answer by
    where it is called from."""

    PAIRS = 8

    def _analyze(self, spent_inside):
        image, interiors = _aarch64TailcallImage(self.PAIRS)
        disassembler = _budgetedDisassembler(_config(RESOLVE_TAILCALLS=True), spent_inside=spent_inside)
        report = disassembler.disassembleBuffer(image, BASE, bitness=64, architecture="aarch64")
        recovered = {function.offset for function in report.getFunctions()}
        return report, len(set(interiors) & recovered)

    def test_the_drain_runs_and_promotes_every_interior_entry(self):
        report, promoted = self._analyze(spent_inside=None)

        self.assertEqual(report.status, "ok")
        self.assertEqual(promoted, self.PAIRS)

    def test_a_budget_spent_inside_the_tailcall_pass_stops_the_drain_too(self):
        """The latch, not the callback: this budget answers "spent" only while the tailcall
        pass is on the stack, so a loop that re-asked it would carry on draining."""
        report, promoted = self._analyze(spent_inside="resolveTailcalls")

        self.assertEqual(report.status, "timeout")
        self.assertEqual(promoted, 0)


class AnalysisTimeoutHelperTestSuite(unittest.TestCase):
    def _engine(self):
        return Disassembler(config=_config(), backend="intel").disassembler

    def test_an_explicit_callback_wins_over_the_stored_one(self):
        engine = self._engine()
        engine._cb_analysis_timeout = lambda: False

        self.assertTrue(engine._analysisTimeoutTripped(lambda: True))
        self.assertTrue(engine.disassembly.analysis_timeout)

    def test_the_stored_callback_is_used_when_none_is_passed(self):
        engine = self._engine()
        engine._cb_analysis_timeout = lambda: True

        self.assertTrue(engine._analysisTimeoutTripped())

    def test_no_callback_at_all_never_trips(self):
        engine = self._engine()
        engine._cb_analysis_timeout = None

        self.assertFalse(engine._analysisTimeoutTripped())

    def test_the_verdict_latches_once_recorded(self):
        engine = self._engine()
        engine._cb_analysis_timeout = None
        engine.disassembly.analysis_timeout = True

        self.assertTrue(engine._analysisTimeoutTripped())


if __name__ == "__main__":
    unittest.main()
