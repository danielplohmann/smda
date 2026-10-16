import types
from unittest.mock import patch

from smda.arm.FunctionCandidateManager import MODE_STATED, FunctionCandidateManager
from smda.common.FunctionCandidateManager import FunctionCandidateManager as CommonFunctionCandidateManager
from smda.SmdaConfig import SmdaConfig


class TestArmCandidateResources:
    base = 0x1000

    def _manager(self, data, cap=0):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = cap
        manager = FunctionCandidateManager(config)
        binary_info = types.SimpleNamespace(
            bitness=32,
            base_addr=self.base,
            binary=data,
            binary_size=len(data),
            code_areas=[],
            oep=None,
            getLiefBinary=lambda: None,
        )

        class Disassembly:
            analysis_timeout = False

            def __init__(self):
                self.binary_info = binary_info

            def isAddrWithinMemoryImage(self, addr):
                return binary_info.base_addr <= addr < binary_info.base_addr + len(data)

        manager.disassembly = Disassembly()
        manager._default_thumb = False
        manager._exec_ranges = []
        return manager

    def test_direct_call_scan_caps_mode_and_strong_start_metadata(self):
        manager = self._manager((0xEB000000).to_bytes(4, "little") * 16384, cap=2)

        manager._scanA32Calls(self.base, self.base + len(manager.disassembly.binary_info.binary))

        assert len(manager.candidates) == 2
        assert len(manager._modes) <= 2
        assert len(manager._strong_starts) <= 2
        existing = next(iter(manager.candidates))
        manager.noteMode(existing, True, MODE_STATED)
        assert manager._modes[existing] is True

    def test_direct_call_scan_polls_and_stops_at_a_chunk_boundary(self):
        manager = self._manager((0xEB000000).to_bytes(4, "little") * 16384)
        seen = []
        polls = 0

        def record_call(target, thumb, source):
            seen.append(source)

        def timed_out():
            nonlocal polls
            polls += 1
            return polls == 2

        manager._bookCall = record_call
        manager._cb_analysis_timeout = timed_out
        manager._scanA32Calls(self.base, self.base + len(manager.disassembly.binary_info.binary))

        assert len(seen) == 4096
        assert manager.disassembly.analysis_timeout

    def test_prologue_scan_polls_and_stops_at_a_chunk_boundary(self):
        manager = self._manager((0xE92D4000).to_bytes(4, "little") * 16384)
        seen = []
        polls = 0

        def record_prologue(addr, thumb):
            seen.append(addr)

        def timed_out():
            nonlocal polls
            polls += 1
            return polls == 2

        manager._bookPrologue = record_prologue
        manager._cb_analysis_timeout = timed_out
        manager._scanA32Prologues(self.base, self.base + len(manager.disassembly.binary_info.binary))

        assert len(seen) == 4096
        assert manager.disassembly.analysis_timeout

    def test_thumb_call_scan_polls_and_stops_at_a_chunk_boundary(self):
        call = b"\x00\xf0\x00\xf8"
        manager = self._manager(call * 8192)
        seen = []
        polls = 0

        def timed_out():
            nonlocal polls
            polls += 1
            return polls == 2

        manager._bookCall = lambda target, thumb, source: seen.append(source)
        manager._cb_analysis_timeout = timed_out
        manager._scanT32Calls(self.base, self.base + len(manager.disassembly.binary_info.binary))

        assert len(seen) == 4096
        assert manager.disassembly.analysis_timeout

    def test_thumb_prologue_scan_polls_and_stops_at_a_chunk_boundary(self):
        manager = self._manager(b"\x01\xb5" * 16384)
        seen = []
        polls = 0

        def timed_out():
            nonlocal polls
            polls += 1
            return polls == 2

        manager._bookPrologue = lambda addr, thumb: seen.append(addr)
        manager._cb_analysis_timeout = timed_out
        manager._scanT32Prologues(self.base, self.base + len(manager.disassembly.binary_info.binary))

        assert len(seen) == 8192
        assert manager.disassembly.analysis_timeout

    def test_thumb_call_starting_at_a_chunk_boundary_is_not_skipped(self):
        chunk_size = 4096 * 4
        data = bytearray(chunk_size + 4)
        data[chunk_size - 2 : chunk_size + 2] = b"\x00\xf0\x00\xf8"
        manager = self._manager(bytes(data))
        seen = []
        manager._bookCall = lambda target, thumb, source: seen.append(source)
        manager._scanT32Calls(self.base, self.base + len(data))

        assert seen == [self.base + chunk_size - 2]

    def test_mode_initialization_polls_with_its_callback_installed(self):
        manager = self._manager(b"\x00" * (1024 * 1024))
        polls = 0

        def timed_out():
            nonlocal polls
            polls += 1
            return polls == 4

        with patch.object(CommonFunctionCandidateManager, "init"):
            manager.init(manager.disassembly, timed_out)

        assert polls == 4
        assert manager.disassembly.analysis_timeout

    def test_stale_candidates_do_not_bypass_the_mode_metadata_cap(self):
        manager = self._manager(b"\x00" * 16, cap=2)
        manager.candidates = {self.base + index * 4: types.SimpleNamespace(is_thumb=False) for index in range(8)}

        with patch.object(CommonFunctionCandidateManager, "init"):
            manager.init(manager.disassembly, lambda: False)
        for addr in manager.candidates:
            manager.noteMode(addr, False)

        assert len(manager._modes) == 2

    def test_authoritative_function_boundaries_survive_a_full_candidate_registry(self):
        manager = self._manager(b"\x00" * 64, cap=1)
        assert manager.addCallCandidate(self.base, False, self.base + 4)
        for addr in (self.base + 8, self.base + 16):
            manager.noteMode(addr, True, MODE_STATED)
            manager._addDeclaredStart(addr)
            assert not manager.addExceptionCandidate(addr)
            assert addr in manager.getDeclaredFunctionStarts()
            assert addr in manager.getStrongFunctionStarts()
            assert manager.isThumb(addr)
        assert len(manager.candidates) == 1

    def test_accepted_call_keeps_its_mode_when_other_evidence_fills_the_cache(self):
        manager = self._manager(b"\x00" * 64, cap=1)
        manager.noteMode(self.base, False)

        assert manager.addCallCandidate(self.base + 8, True, self.base + 4)
        assert manager.isThumb(self.base + 8)
        assert manager.candidates[self.base + 8].is_thumb
        for target in range(self.base + 12, self.base + 64, 4):
            assert not manager.addCallCandidate(target, True, self.base + 4)
        assert len(manager._modes) <= 2 * manager.config.MAX_FUNCTION_CANDIDATES
