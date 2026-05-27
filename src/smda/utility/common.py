def mergeCodeAreas(code_areas):
    if not code_areas:
        return []
    sorted_areas = sorted(code_areas)
    result = [sorted_areas[0]]
    for current_area in sorted_areas[1:]:
        if result[-1][1] == current_area[0]:
            result[-1] = [result[-1][0], current_area[1]]
        else:
            result.append(current_area)
    return result
