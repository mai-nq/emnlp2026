"""Parse SigmaHQ YAML rules into CyberOutputBench instance schema."""

import re
from pathlib import Path

import yaml

from src.utils.io import setup_logging

logger = setup_logging("sigma_parser")


def parse_sigma_rule(path: Path) -> dict | None:
    path = Path(path)
    try:
        with open(path) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError:
        logger.warning("Invalid YAML: %s", path)
        return None

    if not isinstance(rule, dict):
        return None

    if "detection" not in rule or "logsource" not in rule:
        logger.debug("Missing detection/logsource: %s", path)
        return None

    detection = rule["detection"]
    condition = detection.get("condition", "")

    num_selections = 0
    num_filters = 0
    for key in detection:
        if key == "condition":
            continue
        if key.startswith("filter"):
            num_filters += 1
        else:
            num_selections += 1

    num_conditions = 1
    if isinstance(condition, str):
        num_conditions += len(re.findall(r"\b(and|or|not)\b", condition))

    tags = rule.get("tags", [])
    mitre_attack = [
        t.replace("attack.", "").upper()
        for t in (tags or [])
        if isinstance(t, str) and re.match(r"attack\.t\d+", t)
    ]

    gold_artifact = path.read_text()

    return {
        "task": "T-SIGMA",
        "source": str(path),
        "gold_artifact": gold_artifact,
        "metadata": {
            "original_title": rule.get("title", ""),
            "mitre_attack": mitre_attack,
            "license": "DRL-1.1",
            "level": rule.get("level", ""),
            "logsource": rule.get("logsource", {}),
        },
        "complexity": {
            "num_selections": num_selections,
            "num_filters": num_filters,
            "num_conditions": num_conditions,
            "reasoning_depth": num_selections + num_filters,
        },
    }


def extract_sigma_rules(rules_dir: Path) -> list[dict]:
    rules_dir = Path(rules_dir)
    results = []
    for path in sorted(rules_dir.rglob("*.yml")):
        parsed = parse_sigma_rule(path)
        if parsed is not None:
            results.append(parsed)
    return results
