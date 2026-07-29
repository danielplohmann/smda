import pathlib
import unittest

from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


class TailcallFlagIndependenceTestSuite(unittest.TestCase):
    """RESOLVE_TAILCALLS must not depend on RESOLVE_REGISTER_CALLS.

    finalizeFunction() is the only place that flushes TailcallAnalyzer's per-function
    jumps into its cross-function state, and initFunction() clears them at the start of
    every function. While that call was gated on RESOLVE_REGISTER_CALLS, running with
    RESOLVE_TAILCALLS=True and RESOLVE_REGISTER_CALLS=False left the third pass iterating
    empty structures: it recovered nothing, silently, with no warning. The two flags are
    documented as independent.
    """

    @staticmethod
    def _fixture():
        xored = (pathlib.Path(__file__).resolve().parent / "cutwail_xored").read_bytes()
        return bytes(byte ^ (index % 256) for index, byte in enumerate(xored))

    def _stateSeenByTailcallPass(self, resolve_register_calls):
        """Return (jump_count, function_count) as observed when resolveTailcalls runs."""
        observed = {}
        original = TailcallAnalyzer.resolveTailcalls

        def spy(analyzer, disassembler, verbose=False):
            # name-mangled private state - the only way to see what the pass actually got
            observed["jumps"] = len(analyzer._TailcallAnalyzer__jumps)
            observed["functions"] = len(analyzer._TailcallAnalyzer__functions)
            return original(analyzer, disassembler, verbose)

        TailcallAnalyzer.resolveTailcalls = spy
        try:
            config = SmdaConfig()
            config.RESOLVE_REGISTER_CALLS = resolve_register_calls
            config.RESOLVE_TAILCALLS = True
            config.WITH_STRINGS = False
            report = Disassembler(config).disassembleUnmappedBuffer(self._fixture())
        finally:
            TailcallAnalyzer.resolveTailcalls = original

        self.assertIn("jumps", observed, "resolveTailcalls was never reached")
        return observed["jumps"], observed["functions"], report.num_functions

    def test_tailcall_pass_receives_state_without_register_call_resolution(self):
        jumps, functions, num_functions = self._stateSeenByTailcallPass(resolve_register_calls=False)

        self.assertGreater(jumps, 0, "tailcall pass received no jumps to work with")
        self.assertGreater(functions, 0, "tailcall pass received no functions to work with")
        self.assertGreater(num_functions, 0)

    def test_tailcall_pass_state_is_identical_with_and_without_register_calls(self):
        with_reg = self._stateSeenByTailcallPass(resolve_register_calls=True)
        without_reg = self._stateSeenByTailcallPass(resolve_register_calls=False)

        # register-call resolution does not create tailcall jumps, so the state handed to
        # the tailcall pass must be the same either way
        self.assertEqual(with_reg, without_reg)


if __name__ == "__main__":
    unittest.main()
