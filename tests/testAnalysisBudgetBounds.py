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
