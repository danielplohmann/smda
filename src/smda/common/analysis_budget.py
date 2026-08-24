"""The cooperative analysis budget, shared by the three backends that own an analyzeBuffer.

`SmdaConfig.TIMEOUT` reaches a backend as a callback it is expected to poll. Asking that
callback again at every pass is not the same as remembering its answer: a caller scopes a
budget by where it is called from - "spent while the tailcall pass is running" - so a later
pass that re-asks is told "not spent" and carries on doing the work the budget was meant to
stop. The verdict has to latch onto the result the first time it trips, and every later poll
has to read the latch first.
"""


def analysisTimeoutTripped(disassembly, cbAnalysisTimeout):
    """Whether the analysis budget is spent, latching the verdict onto the result."""
    if disassembly is not None and disassembly.analysis_timeout:
        return True
    if cbAnalysisTimeout is not None and cbAnalysisTimeout():
        if disassembly is not None:
            disassembly.analysis_timeout = True
        return True
    return False
