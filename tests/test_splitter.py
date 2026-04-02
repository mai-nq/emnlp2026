from src.splitter import deduplicate, assign_ids, split_dataset


def _make_instances(task, n, difficulties=None):
    instances = []
    for i in range(n):
        diff = difficulties[i % len(difficulties)] if difficulties else "medium"
        instances.append({
            "task": task,
            "gold_artifact": f"artifact-{task}-{i}",
            "difficulty": diff,
            "metadata": {},
            "complexity": {},
        })
    return instances


def test_deduplicate_removes_exact_dupes():
    instances = [
        {"gold_artifact": "rule A", "task": "T-YARA"},
        {"gold_artifact": "rule A", "task": "T-YARA"},
        {"gold_artifact": "rule B", "task": "T-YARA"},
    ]
    result = deduplicate(instances)
    assert len(result) == 2


def test_deduplicate_normalizes_whitespace():
    instances = [
        {"gold_artifact": "rule  A\n\n", "task": "T-YARA"},
        {"gold_artifact": "rule A\n", "task": "T-YARA"},
    ]
    result = deduplicate(instances)
    assert len(result) == 1


def test_assign_ids():
    instances = [
        {"task": "T-SIGMA", "gold_artifact": "a"},
        {"task": "T-SIGMA", "gold_artifact": "b"},
        {"task": "T-YARA", "gold_artifact": "c"},
    ]
    result = assign_ids(instances)
    assert result[0]["id"] == "sigma-001"
    assert result[1]["id"] == "sigma-002"
    assert result[2]["id"] == "yara-001"


def test_split_dataset_sizes():
    difficulties = ["easy"] * 60 + ["medium"] * 80 + ["hard"] * 60
    instances = []
    for task in ["T-SIGMA", "T-YARA", "T-STIX"]:
        instances.extend(_make_instances(task, 300, difficulties))
    train, test = split_dataset(instances, test_per_task=200, seed=42)
    assert len(test) == 600
    assert len(train) == 300
    for task in ["T-SIGMA", "T-YARA", "T-STIX"]:
        task_test = [i for i in test if i["task"] == task]
        assert len(task_test) == 200


def test_split_dataset_difficulty_distribution():
    difficulties = ["easy"] * 90 + ["medium"] * 120 + ["hard"] * 90
    instances = _make_instances("T-SIGMA", 300, difficulties)
    train, test = split_dataset(instances, test_per_task=200, seed=42)
    easy = len([i for i in test if i["difficulty"] == "easy"])
    medium = len([i for i in test if i["difficulty"] == "medium"])
    hard = len([i for i in test if i["difficulty"] == "hard"])
    assert easy == 60
    assert medium == 80
    assert hard == 60


def test_split_dataset_deterministic():
    instances = _make_instances("T-SIGMA", 300, ["easy", "medium", "hard"])
    _, test1 = split_dataset(instances, test_per_task=200, seed=42)
    _, test2 = split_dataset(instances, test_per_task=200, seed=42)
    ids1 = [i["gold_artifact"] for i in test1]
    ids2 = [i["gold_artifact"] for i in test2]
    assert ids1 == ids2


def test_split_marks_split_field():
    instances = _make_instances("T-SIGMA", 250, ["easy", "medium", "hard"])
    train, test = split_dataset(instances, test_per_task=200, seed=42)
    assert all(i["split"] == "test" for i in test)
    assert all(i["split"] == "train" for i in train)
