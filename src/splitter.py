"""Hash-based deduplication and stratified train/test splitting."""

import hashlib
import random
import re

from src.utils.io import setup_logging

logger = setup_logging("splitter")

TASK_PREFIX = {
    "T-SIGMA": "sigma",
    "T-YARA": "yara",
    "T-STIX": "stix",
}

DEFAULT_DIFFICULTY_DIST = {"easy": 60, "medium": 80, "hard": 60}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _hash_artifact(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode()).hexdigest()


def deduplicate(instances: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for inst in instances:
        h = _hash_artifact(inst["gold_artifact"])
        if h not in seen:
            seen.add(h)
            unique.append(inst)
    removed = len(instances) - len(unique)
    if removed:
        logger.info("Deduplicated: removed %d duplicates from %d", removed, len(instances))
    return unique


def assign_ids(instances: list[dict]) -> list[dict]:
    counters = {}
    result = []
    for inst in instances:
        task = inst["task"]
        prefix = TASK_PREFIX.get(task, task.lower().replace("t-", ""))
        counters[task] = counters.get(task, 0) + 1
        inst_copy = dict(inst)
        inst_copy["id"] = f"{prefix}-{counters[task]:03d}"
        result.append(inst_copy)
    return result


def split_dataset(
    instances: list[dict],
    test_per_task: int = 200,
    seed: int = 42,
    difficulty_dist: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    if difficulty_dist is None:
        difficulty_dist = DEFAULT_DIFFICULTY_DIST

    rng = random.Random(seed)
    test = []
    train = []

    by_task = {}
    for inst in instances:
        by_task.setdefault(inst["task"], []).append(inst)

    for task, task_instances in by_task.items():
        by_diff = {}
        for inst in task_instances:
            diff = inst.get("difficulty", "medium")
            by_diff.setdefault(diff, []).append(inst)

        task_test = []
        task_train = []

        for diff, target_n in difficulty_dist.items():
            pool = by_diff.get(diff, [])
            rng.shuffle(pool)
            if len(pool) >= target_n:
                task_test.extend(pool[:target_n])
                task_train.extend(pool[target_n:])
            else:
                task_test.extend(pool)
                logger.warning(
                    "Task %s difficulty %s: only %d available (target %d)",
                    task, diff, len(pool), target_n,
                )

        for diff, pool in by_diff.items():
            if diff not in difficulty_dist:
                task_train.extend(pool)

        # Mark split field on copies (don't mutate input)
        for inst in task_test:
            copy = dict(inst)
            copy["split"] = "test"
            test.append(copy)
        for inst in task_train:
            copy = dict(inst)
            copy["split"] = "train"
            train.append(copy)

    logger.info("Split: %d test, %d train", len(test), len(train))
    return train, test
