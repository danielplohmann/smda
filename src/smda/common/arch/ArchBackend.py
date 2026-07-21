"""Architecture backend interface for the recursive native-code disassembler.

:class:`~smda.common.RecursiveDisassembler.RecursiveDisassembler` is the
architecture-agnostic CFG-recovery engine: it owns the recursive traversal,
candidate orchestration and label/symbol resolution, and delegates every
architecture-specific decision to an ``ArchBackend`` instance.

A concrete backend (e.g. the x86/x64 ``X86Backend`` under ``smda.intel``)
supplies the capstone configuration, the architecture-specific collaborators
(candidate manager, per-function analysis state, jump-table / indirect-call
analyzers, TF-IDF model) and the per-instruction control-flow analysis. The
engine treats all of these abstractly, so new architectures (ARM, MIPS, ...)
can be added by implementing this interface without touching the engine.

Function-candidate discovery follows the same pattern: a backend's
``createCandidateManager`` returns a subclass of the architecture-neutral
:class:`smda.common.FunctionCandidateManager`, which supplies the byte-level
scans and names its :class:`smda.common.FunctionCandidate` subclass via the
``CANDIDATE_CLASS`` attribute. That candidate subclass is the per-architecture
function-start scoring hook: ``getFunctionStartScore`` feeds the priority
queue (AArch64 deliberately returns 0 so mid-function frame-record stores do
not outrank call-ref seeds) and ``hasCommonFunctionStart`` feeds confidence.
"""

from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoBinary import get_macho_stub_ranges


class ArchBackend:
    #: short architecture identifier, written to ``binary_info.architecture``
    name = "abstract"
    #: maximum instruction size in bytes; sizes the disassembly look-ahead window
    max_instruction_size = 16

    # --- architecture-specific collaborator factories ---------------------
    def createCapstone(self, bitness):
        """Return a capstone ``Cs`` instance configured for this architecture/bitness."""
        raise NotImplementedError

    def createTfIdf(self, bitness):
        """Return a TF-IDF mnemonic scorer for confidence estimation."""
        raise NotImplementedError

    def createCandidateManager(self, config):
        """Return the function-candidate manager driving function-start discovery."""
        raise NotImplementedError

    def createAnalysisState(self, start_addr, disassembly):
        """Return a fresh per-function analysis state object."""
        raise NotImplementedError

    def createJumpTableAnalyzer(self, disassembler):
        """Return the jump-table resolver bound to ``disassembler``."""
        raise NotImplementedError

    def createIndirectCallAnalyzer(self, disassembler):
        """Return the indirect-call resolver bound to ``disassembler``."""
        raise NotImplementedError

    def probeBitness(self, disassembly):
        """Heuristically determine bitness when it is not supplied by the loader."""
        raise NotImplementedError

    # --- per-instruction control-flow analysis ---------------------------
    def analyzeInstruction(self, disassembler, instruction, state, previous_instruction, start_addr):
        """Analyze a single decoded instruction and update ``state`` accordingly.

        ``instruction`` and ``previous_instruction`` are raw capstone
        ``disasm_lite`` tuples ``(address, size, mnemonic, op_str)``;
        ``previous_instruction`` is ``None`` for the first instruction of a block.

        The backend records CFG edges / code references, queues successor blocks
        and sets block-ending flags on ``state``.

        Returns ``True`` to tell the engine to stop processing the current block
        immediately *without* booking ``instruction`` (used by x86 to cut a block
        when an alignment sequence is found after a call); returns ``False`` for
        normal flow, where the engine books the instruction and then honours the
        block-ending flag set on ``state``.
        """
        raise NotImplementedError

    # --- shared import-stub range resolution (concrete, not abstract) -----
    # Every native backend that resolves a direct call/jmp/branch target
    # against ELF PLT or Mach-O stub ranges needs the same range lookup;
    # this lives here once instead of being duplicated per backend.
    @staticmethod
    def _getPltRanges(binary_info):
        if not hasattr(binary_info, "_plt_ranges"):
            binary_info._plt_ranges = ElfFileLoader.getPltRanges(
                binary_info.raw_data or binary_info.binary,
                parsed=binary_info.getLiefBinary(),
            )
        return binary_info._plt_ranges

    @staticmethod
    def _getMachoStubRanges(binary_info):
        if not hasattr(binary_info, "_macho_stub_ranges"):
            binary_info._macho_stub_ranges = get_macho_stub_ranges(
                binary_info.getLiefBinary(),
                base_addr=binary_info.base_addr,
                bitness=binary_info.bitness,
                architecture=getattr(binary_info, "architecture", ""),
            )
        return binary_info._macho_stub_ranges

    @classmethod
    def _getImportStubRanges(cls, binary_info):
        return cls._getPltRanges(binary_info) + cls._getMachoStubRanges(binary_info)
