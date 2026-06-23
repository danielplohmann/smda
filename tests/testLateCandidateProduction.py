#!/usr/bin/python

import logging
import types
import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)


def _make_manager(config):
    """build a minimal AArch64 FunctionCandidateManager wired with just enough state
    to exercise the queue — no real disassembly or init() needed."""
    manager = AArch64FunctionCandidateManager(config)
    binary_info = types.SimpleNamespace(
        bitness=64,
        base_addr=0,
        binary=b"\x00" * 0x100000,
    )
    manager.disassembly = types.SimpleNamespace(
        binary_info=binary_info,
        analysis_timeout=False,
    )
    manager.bitness = 64
    manager.identified_alignment = 0
    manager._code_areas = []
    return manager


class LateCandidateTestBase:
    """Test mixin — one subclass per queue type (PriorityQueue / BracketQueue)."""

    queue_type = "PriorityQueue"

    def setUp(self):
        self.config = SmdaConfig()
        self.config.MAX_FUNCTION_CANDIDATES = 0
        self.config.MAX_CALL_REFS_PER_CANDIDATE = 0
        self.config.CANDIDATE_QUEUE = self.queue_type
        self.manager = _make_manager(self.config)
        # Seed initial candidates (before _buildQueue, so they go into the queue).
        for addr in (0x1000, 0x2000, 0x3000):
            self.manager.ensureCandidate(addr)
        # Build the queue (freezes self.candidates into candidate_queue).
        self.manager._buildQueue()

    # ------------------------------------------------------------------
    #   Scenario 1: brand-new tailcall candidate discovered mid-iteration
    # ------------------------------------------------------------------
    def test_late_tailcall_is_produced_mid_iteration(self):
        """A brand-new candidate (is_new=True) added via addTailcallCandidate
        *during* iteration should appear from the generator on the next resume."""
        gen = self.manager.getNextFunctionStartCandidate()
        first = next(gen)
        self.assertIsNotNone(first)

        late_addr = 0x35E0
        self.manager.addTailcallCandidate(late_addr)
        # The backend calls addCallRef *after* addTailcallCandidate.
        self.manager.candidates[late_addr].addCallRef(0x5000)

        produced = [c.addr for c in gen]
        self.assertIn(
            late_addr, produced,
            f"Late candidate 0x{late_addr:x} was NOT yielded despite being "
            f"new (is_new=True) [queue={self.queue_type}]"
        )

    # ------------------------------------------------------------------
    #   Scenario 2: pre-existing candidate now re-added via addTailcallCandidate
    # ------------------------------------------------------------------
    def test_eexisting_candidate_re_added_by_tailcall(self):
        """When a candidate already lives in self.candidates (is_new=False),
        aarch64 addTailcallCandidate still re-adds it to the queue (the is_new
        guard was removed). The generator should yield it."""
        late_addr = 0x45E0
        # Another analysis path created the candidate earlier (in candidates only).
        self.manager.ensureCandidate(late_addr)
        # Now addTailcallCandidate fires — should re-add to queue.
        self.manager.addTailcallCandidate(late_addr)
        self.manager.candidates[late_addr].addCallRef(0x6000)

        produced = [c.addr for c in self.manager.getNextFunctionStartCandidate()]
        self.assertIn(
            late_addr, produced,
            f"Candidate 0x{late_addr:x} should have been re-added to queue "
            f"even when pre-existing [queue={self.queue_type}]"
        )

    # ------------------------------------------------------------------
    #   Scenario 3: mid-iteration pre-existing candidate is also re-added
    # ------------------------------------------------------------------
    def test_eexisting_candidate_re_added_mid_iteration(self):
        """Same as scenario 2, but the ensureCandidate + addTailcallCandidate
        happen mid-iteration — the candidate should still appear."""
        gen = self.manager.getNextFunctionStartCandidate()
        first = next(gen)

        late_addr = 0x45E0
        self.manager.ensureCandidate(late_addr)      # candidates only
        self.manager.addTailcallCandidate(late_addr)  # re-adds to queue
        self.manager.candidates[late_addr].addCallRef(0x6000)

        produced = [c.addr for c in gen]
        self.assertIn(
            late_addr, produced,
            f"Candidate 0x{late_addr:x} should appear mid-iteration "
            f"even when pre-existing [queue={self.queue_type}]"
        )

    # ------------------------------------------------------------------
    #   Scenario 4: intel addCandidate always adds (contrast)
    # ------------------------------------------------------------------
    def test_intel_addCandidate_always_queue(self):
        """The base intel addCandidate pushes to the queue unconditionally,
        so even a pre-existing candidate gets queued and produced."""
        late_addr = 0x55E0
        self.manager.ensureCandidate(late_addr)
        # addCandidate has no is_new guard — always adds to queue.
        self.manager.addCandidate(late_addr, reference_source=0x7000)

        produced = [c.addr for c in self.manager.getNextFunctionStartCandidate()]
        self.assertIn(
            late_addr, produced,
            f"Candidate 0x{late_addr:x} should be produced when "
            f"addCandidate is used (always queues) [queue={self.queue_type}]"
        )

    # ------------------------------------------------------------------
    #   Scenario 5: score=0 candidate is filtered, not yielded
    # ------------------------------------------------------------------
    def test_score_zero_candidate_is_skipped(self):
        """A candidate with total score 0 (no call refs, no prologue, no
        alignment) passes through the generator's filter but is swallowed
        by the continue — it is dequeued but not yielded."""
        late_addr = 0x35E1  # unaligned → alignment=0, score stays 0
        self.manager.addTailcallCandidate(late_addr)
        # no addCallRef → score = 0

        produced = [c.addr for c in self.manager.getNextFunctionStartCandidate()]
        self.assertNotIn(
            late_addr, produced,
            f"Candidate 0x{late_addr:x} with score=0 should be filtered out "
            f"[queue={self.queue_type}]"
        )

    # ------------------------------------------------------------------
    #   Scenario 6: multiple late candidates added in one yield cycle
    # ------------------------------------------------------------------
    def test_multiple_late_additions_in_single_yield(self):
        """All candidates added during one analyzeFunction call should
        eventually be yielded."""
        gen = self.manager.getNextFunctionStartCandidate()
        first = next(gen)

        late_a = 0x75E0
        late_b = 0x85E0
        self.manager.addTailcallCandidate(late_a)
        self.manager.candidates[late_a].addCallRef(0x8000)
        self.manager.addTailcallCandidate(late_b)
        self.manager.candidates[late_b].addCallRef(0x9000)

        produced = [c.addr for c in gen]
        self.assertIn(late_a, produced)
        self.assertIn(late_b, produced)

    # ------------------------------------------------------------------
    #   Scenario 7: tailcall with callRef has score > 0 (integration)
    # ------------------------------------------------------------------
    def test_late_tailcall_with_callref_has_nonzero_score(self):
        """addCallRef resets _score to None; getScore recalculates > 0."""
        late_addr = 0x95E0
        self.manager.addTailcallCandidate(late_addr)
        self.manager.candidates[late_addr].addCallRef(0xA000)

        gen = self.manager.getNextFunctionStartCandidate()
        produced = [c.addr for c in gen]
        self.assertIn(
            late_addr, produced,
            f"Candidate 0x{late_addr:x} with upcoming addCallRef should be "
            f"produced [queue={self.queue_type}]"
        )


class PriorityQueueTestCase(LateCandidateTestBase, unittest.TestCase):
    queue_type = "PriorityQueue"


class BracketQueueTestCase(LateCandidateTestBase, unittest.TestCase):
    queue_type = "BracketQueue"


if __name__ == "__main__":
    unittest.main()
