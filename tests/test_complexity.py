from src.annotators.complexity import classify_difficulty, annotate_complexity


def test_classify_sigma_easy():
    complexity = {"num_selections": 1, "num_filters": 0, "num_conditions": 1}
    assert classify_difficulty("T-SIGMA", complexity) == "easy"


def test_classify_sigma_medium():
    complexity = {"num_selections": 2, "num_filters": 1, "num_conditions": 3}
    assert classify_difficulty("T-SIGMA", complexity) == "medium"


def test_classify_sigma_hard():
    complexity = {"num_selections": 4, "num_filters": 2, "num_conditions": 6}
    assert classify_difficulty("T-SIGMA", complexity) == "hard"


def test_classify_yara_easy():
    complexity = {"num_strings": 1, "num_conditions": 1, "num_imports": 0}
    assert classify_difficulty("T-YARA", complexity) == "easy"


def test_classify_yara_hard():
    complexity = {"num_strings": 6, "num_conditions": 5, "num_imports": 2}
    assert classify_difficulty("T-YARA", complexity) == "hard"


def test_classify_stix_easy():
    complexity = {"num_sdos": 2, "num_sros": 1, "num_objects": 3}
    assert classify_difficulty("T-STIX", complexity) == "easy"


def test_classify_stix_hard():
    complexity = {"num_sdos": 7, "num_sros": 5, "num_objects": 12}
    assert classify_difficulty("T-STIX", complexity) == "hard"


def test_annotate_complexity():
    instances = [
        {
            "task": "T-SIGMA",
            "complexity": {"num_selections": 1, "num_filters": 0, "num_conditions": 1},
        },
        {
            "task": "T-YARA",
            "complexity": {"num_strings": 6, "num_conditions": 5, "num_imports": 2},
        },
    ]
    result = annotate_complexity(instances)
    assert result[0]["difficulty"] == "easy"
    assert result[1]["difficulty"] == "hard"
