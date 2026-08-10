import hashlib
import json


def computeReportIdentityHash(report, exclude=("timestamp", "execution_time")):
    """Canonical content hash of a SmdaReport, ignoring fields that legitimately vary per run.

    Covers the CFG, per-function hashes, statistics, xrefs and xmetadata in one number, because
    all of them are serialized inside toDict().
    """
    return computeReportDictIdentityHash(report.toDict(), exclude=exclude)


def computeReportDictIdentityHash(report_dict, exclude=("timestamp", "execution_time")):
    """Same hash for a caller that already has the serialized dict and would else rebuild it."""
    as_dict = {key: value for key, value in report_dict.items() if key not in exclude}
    serialized = json.dumps(as_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def mergeCodeAreas(code_areas):
    if not code_areas:
        return []
    sorted_areas = sorted(code_areas)
    result = [sorted_areas[0]]
    for current_area in sorted_areas[1:]:
        if current_area[0] <= result[-1][1]:
            result[-1] = [result[-1][0], max(result[-1][1], current_area[1])]
        else:
            result.append(current_area)
    return result
