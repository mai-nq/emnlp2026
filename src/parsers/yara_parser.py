"""Parse YARA rules via plyara into CyberOutputBench instance schema."""

import re
from pathlib import Path

import plyara
import plyara.utils

from src.utils.io import setup_logging

logger = setup_logging("yara_parser")


def _count_condition_components(condition: str) -> int:
    ops = len(re.findall(r"\b(and|or|not)\b", condition))
    return 1 + ops


def parse_yara_file(path: Path) -> list[dict]:
    """Parse a .yar file, return list of instance dicts (one per rule).
    Uses original file text for single-rule files; reconstructs for multi-rule."""
    path = Path(path)
    try:
        text = path.read_text()
        parser = plyara.Plyara()
        parsed_rules = parser.parse_string(text)
    except Exception:
        logger.warning("Failed to parse YARA file: %s", path)
        return []

    results = []
    for parsed in parsed_rules:
        rule_name = parsed.get("rule_name", "unknown")

        meta = {}
        for entry in parsed.get("metadata", []):
            for k, v in entry.items():
                meta[k] = v

        num_strings = len(parsed.get("strings", []))

        condition_str = " ".join(parsed.get("condition_terms", []))
        num_conditions = _count_condition_components(condition_str)

        imports = parsed.get("imports", [])

        if len(parsed_rules) == 1:
            gold_artifact = text
        else:
            gold_artifact = plyara.utils.rebuild_yara_rule(parsed)

        results.append({
            "task": "T-YARA",
            "source": str(path),
            "gold_artifact": gold_artifact,
            "metadata": {
                "original_title": rule_name,
                "description": meta.get("description", ""),
                "author": meta.get("author", ""),
                "license": meta.get("license", ""),
            },
            "complexity": {
                "num_strings": num_strings,
                "num_conditions": num_conditions,
                "num_imports": len(imports),
                "reasoning_depth": num_strings + num_conditions,
            },
        })

    return results


def extract_yara_rules(rules_dir: Path) -> list[dict]:
    rules_dir = Path(rules_dir)
    results = []
    for ext in ("*.yar", "*.yara"):
        for path in sorted(rules_dir.rglob(ext)):
            parsed = parse_yara_file(path)
            results.extend(parsed)
    return results
