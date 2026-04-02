"""Difficulty classification based on structural complexity metrics."""


def _total_components(task: str, complexity: dict) -> int:
    if task == "T-SIGMA":
        return (
            complexity.get("num_selections", 0)
            + complexity.get("num_filters", 0)
            + complexity.get("num_conditions", 0)
        )
    elif task == "T-YARA":
        return (
            complexity.get("num_strings", 0)
            + complexity.get("num_conditions", 0)
            + complexity.get("num_imports", 0) * 2
        )
    elif task == "T-STIX":
        return complexity.get("num_sdos", 0) + complexity.get("num_sros", 0)
    return 0


THRESHOLDS = {
    "T-SIGMA": (3, 6),
    "T-YARA": (3, 8),
    "T-STIX": (4, 8),
}


def classify_difficulty(task: str, complexity: dict) -> str:
    score = _total_components(task, complexity)
    easy_max, medium_max = THRESHOLDS.get(task, (3, 6))
    if score <= easy_max:
        return "easy"
    elif score <= medium_max:
        return "medium"
    else:
        return "hard"


def annotate_complexity(instances: list[dict]) -> list[dict]:
    result = []
    for inst in instances:
        inst_copy = dict(inst)
        inst_copy["difficulty"] = classify_difficulty(
            inst["task"], inst.get("complexity", {})
        )
        result.append(inst_copy)
    return result
