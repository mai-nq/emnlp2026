# Dataset Construction Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CLI pipeline (`build_dataset.py`) that fetches, extracts, describes, annotates, splits, validates, and exports the CyberOutputBench dataset (600 instances across YARA, Sigma, STIX). Pipeline order: `fetch → extract → describe → annotate → split → validate → export` (annotate before split so difficulty labels are available for stratified splitting).

**Architecture:** Single Click CLI entry point with subcommands. Shared modules in `src/` (parsers, describers, annotators, validators, utils). Each pipeline stage reads from the previous stage's JSONL output and writes its own, enabling resumability.

**Tech Stack:** Python 3.11+, uv, Click, PyYAML, plyara, yara-python, pySigma, stix2, stix2-validator, OpenAI SDK (async), tqdm

**Spec:** `docs/superpowers/specs/2026-04-01-dataset-construction-design.md`

**Scope note:** This pipeline covers Phase 1 (reverse-engineering: artifact→NL via GPT-4o). Phase 2 (forward construction by human experts) is manual and out of scope — expert-authored instances are ingested by placing JSONL files in `data/described/` before running `split`.

---

## File Structure

```
cyberoutputbech/
├── pyproject.toml                    # Project metadata + dependencies
├── configs/
│   └── dataset.yaml                  # Pipeline configuration
├── scripts/
│   ├── __init__.py                   # Makes scripts/ importable
│   └── build_dataset.py              # Click CLI entry point
├── src/
│   ├── __init__.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── io.py                     # JSONL I/O, config loading, logging setup
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── sigma_parser.py           # SigmaHQ YAML → structured dict
│   │   ├── yara_parser.py            # YARA Forge rules → structured dict
│   │   └── stix_parser.py            # MITRE ATT&CK STIX JSON → structured dict
│   ├── describers/
│   │   ├── __init__.py
│   │   └── gpt4o_describer.py        # Async GPT-4o NL description generation
│   ├── annotators/
│   │   ├── __init__.py
│   │   └── complexity.py             # Difficulty classification + complexity metrics
│   ├── validators/
│   │   ├── __init__.py
│   │   └── quality.py                # Tool-based validation + dedup + filtering
│   └── splitter.py                   # Hash-based dedup + stratified train/test split
├── tests/
│   ├── conftest.py                   # Shared fixtures (sample rules, temp dirs)
│   ├── test_io.py
│   ├── test_sigma_parser.py
│   ├── test_yara_parser.py
│   ├── test_stix_parser.py
│   ├── test_describer.py
│   ├── test_complexity.py
│   ├── test_quality.py
│   ├── test_splitter.py
│   └── test_cli.py
└── data/                             # Git-ignored runtime outputs
    ├── raw/
    ├── extracted/
    ├── described/
    └── final/
```

---

## Chunk 1: Project Scaffolding + Utils

### Task 1: Project Setup

**Files:**
- Create: `pyproject.toml`
- Create: `configs/dataset.yaml`
- Create: `.gitignore` (append data/ exclusion)
- Create: `src/__init__.py`
- Create: `src/utils/__init__.py`
- Create: `scripts/__init__.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "cyberoutputbench"
version = "0.1.0"
description = "Dataset construction pipeline for CyberOutputBench"
requires-python = ">=3.11"
dependencies = [
    "click>=8.0",
    "pyyaml>=6.0",
    "plyara>=2.1",
    "yara-python>=4.3",
    "pySigma>=0.10",
    "stix2-validator>=3.0",
    "stix2>=3.0",
    "openai>=1.0",
    "aiohttp>=3.9",
    "tqdm>=4.65",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-asyncio>=0.21"]

[project.scripts]
build-dataset = "scripts.build_dataset:cli"
```

> **Note:** `scripts/__init__.py` is required for the entry point to work.

- [ ] **Step 2: Create configs/dataset.yaml**

```yaml
sources:
  sigma_repo: "https://github.com/SigmaHQ/sigma.git"
  yara_forge: "https://github.com/YARAHQ/yara-forge.git"
  mitre_stix: "https://github.com/mitre-attack/attack-stix-data.git"

dataset:
  target_per_task: 200
  difficulty_distribution:
    easy: 60
    medium: 80
    hard: 60
  min_components: 3

description:
  model: "gpt-4o"
  max_concurrent: 10
  cost_limit_usd: 50.0

split:
  test_size: 600
  seed: 42
```

- [ ] **Step 3: Append data/ to .gitignore**

Append these lines to `.gitignore` (create if not exists):
```
data/
```

- [ ] **Step 4: Create empty __init__.py files**

Create: `scripts/__init__.py`, `src/__init__.py`, `src/utils/__init__.py`, `src/parsers/__init__.py`, `src/describers/__init__.py`, `src/annotators/__init__.py`, `src/validators/__init__.py`

All empty files.

- [ ] **Step 5: Install project in dev mode**

Run: `uv sync --dev`
Expected: Success, all dependencies installed (creates `.venv/` automatically).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml configs/ src/ scripts/__init__.py .gitignore
git commit -m "feat: scaffold project structure with dependencies and config"
```

---

### Task 2: Utils — JSONL I/O + Config Loader

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_io.py`
- Create: `src/utils/io.py`

- [ ] **Step 1: Create tests/conftest.py with shared fixtures**

```python
import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_sigma_rule():
    return {
        "title": "LSASS Memory Dump Detection",
        "logsource": {"category": "process_access", "product": "windows"},
        "detection": {
            "selection": {"TargetImage|endswith": "\\lsass.exe"},
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "description": "Detects process access to LSASS memory.",
    }


@pytest.fixture
def sample_yara_rule_text():
    return '''rule Test_Malware {
    meta:
        description = "Test rule"
        author = "Test"
    strings:
        $s1 = "malicious" ascii
        $s2 = { 4D 5A 90 00 }
    condition:
        uint16(0) == 0x5A4D and any of ($s*)
}'''


@pytest.fixture
def sample_stix_bundle():
    return {
        "type": "bundle",
        "id": "bundle--1234",
        "objects": [
            {
                "type": "malware",
                "id": "malware--1234",
                "spec_version": "2.1",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "name": "TestMalware",
                "malware_types": ["trojan"],
                "is_family": True,
            },
            {
                "type": "indicator",
                "id": "indicator--5678",
                "spec_version": "2.1",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "name": "TestIndicator",
                "pattern": "[file:name = 'test.exe']",
                "pattern_type": "stix",
                "valid_from": "2026-01-01T00:00:00Z",
            },
            {
                "type": "relationship",
                "id": "relationship--9abc",
                "spec_version": "2.1",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--5678",
                "target_ref": "malware--1234",
            },
        ],
    }


@pytest.fixture
def sample_config(tmp_dir):
    config = {
        "sources": {
            "sigma_repo": "https://github.com/SigmaHQ/sigma.git",
            "yara_forge": "https://github.com/YARAHQ/yara-forge.git",
            "mitre_stix": "https://github.com/mitre-attack/attack-stix-data.git",
        },
        "dataset": {
            "target_per_task": 200,
            "difficulty_distribution": {"easy": 60, "medium": 80, "hard": 60},
            "min_components": 3,
        },
        "description": {
            "model": "gpt-4o",
            "max_concurrent": 10,
            "cost_limit_usd": 50.0,
        },
        "split": {"test_size": 600, "seed": 42},
    }
    path = tmp_dir / "dataset.yaml"
    path.write_text(yaml.dump(config))
    return path
```

- [ ] **Step 2: Write failing tests for io.py**

```python
# tests/test_io.py
import json
from pathlib import Path

from src.utils.io import load_config, read_jsonl, write_jsonl, setup_logging


def test_load_config(sample_config):
    config = load_config(sample_config)
    assert config["dataset"]["target_per_task"] == 200
    assert config["split"]["seed"] == 42


def test_load_config_missing_file(tmp_dir):
    import pytest
    with pytest.raises(FileNotFoundError):
        load_config(tmp_dir / "nonexistent.yaml")


def test_write_and_read_jsonl(tmp_dir):
    path = tmp_dir / "test.jsonl"
    records = [
        {"id": "sigma-001", "task": "T-SIGMA", "gold_artifact": "title: Test"},
        {"id": "yara-001", "task": "T-YARA", "gold_artifact": "rule Test {}"},
    ]
    write_jsonl(records, path)
    result = read_jsonl(path)
    assert len(result) == 2
    assert result[0]["id"] == "sigma-001"
    assert result[1]["task"] == "T-YARA"


def test_read_jsonl_empty(tmp_dir):
    path = tmp_dir / "empty.jsonl"
    path.write_text("")
    result = read_jsonl(path)
    assert result == []


def test_write_jsonl_append(tmp_dir):
    path = tmp_dir / "test.jsonl"
    write_jsonl([{"id": "a"}], path)
    write_jsonl([{"id": "b"}], path, append=True)
    result = read_jsonl(path)
    assert len(result) == 2


def test_setup_logging():
    logger = setup_logging("test_pipeline")
    assert logger.name == "test_pipeline"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/macbook/research/cyberoutputbech && uv run pytest tests/test_io.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.utils.io'`

- [ ] **Step 4: Implement src/utils/io.py**

```python
"""JSONL I/O, config loading, and logging setup."""

import json
import logging
from pathlib import Path

import yaml


def load_config(path: Path) -> dict:
    """Load YAML config file. Raises FileNotFoundError if missing."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with open(path) as f:
        return yaml.safe_load(f)


def read_jsonl(path: Path) -> list[dict]:
    """Read JSONL file, return list of dicts. Empty file → empty list.
    Skips malformed lines with a warning."""
    path = Path(path)
    records = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger = logging.getLogger("io")
                logger.warning("Skipping malformed JSONL line %d in %s", i, path)
    return records


def write_jsonl(records: list[dict], path: Path, append: bool = False) -> None:
    """Write list of dicts to JSONL file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with open(path, mode) as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Configure and return a named logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/macbook/research/cyberoutputbech && uv run pytest tests/test_io.py -v`
Expected: All 6 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/utils/io.py tests/conftest.py tests/test_io.py
git commit -m "feat: add JSONL I/O, config loader, and logging utils"
```

---

## Chunk 2: Sigma Parser

### Task 3: Sigma Parser

**Files:**
- Create: `tests/test_sigma_parser.py`
- Create: `src/parsers/sigma_parser.py`

**Context:** Sigma rules are YAML files in SigmaHQ repo under `rules/` directories. Each has `title`, `description`, `logsource`, `detection` (with `selection` + `condition`), `level`, and optionally `tags` with MITRE ATT&CK IDs. The parser must extract these into the instance schema and count complexity components (selections, filters, conditions).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_sigma_parser.py
import yaml
from pathlib import Path

from src.parsers.sigma_parser import parse_sigma_rule, extract_sigma_rules


def test_parse_sigma_rule_basic(sample_sigma_rule, tmp_dir):
    """Parse a single Sigma YAML dict into instance schema."""
    path = tmp_dir / "test_rule.yml"
    path.write_text(yaml.dump(sample_sigma_rule))

    result = parse_sigma_rule(path)

    assert result["task"] == "T-SIGMA"
    assert result["gold_artifact"] == path.read_text()
    assert result["metadata"]["original_title"] == "LSASS Memory Dump Detection"
    assert "t1003.001" in str(result["metadata"]["mitre_attack"]).lower()
    assert result["complexity"]["num_selections"] >= 1
    assert result["complexity"]["num_conditions"] >= 1


def test_parse_sigma_rule_with_filter(tmp_dir):
    """Sigma rule with filter (exclude) logic."""
    rule = {
        "title": "Suspicious Process",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter_main": {"ParentImage|endswith": "\\explorer.exe"},
            "condition": "selection and not filter_main",
        },
        "level": "medium",
    }
    path = tmp_dir / "filter_rule.yml"
    path.write_text(yaml.dump(rule))

    result = parse_sigma_rule(path)

    assert result["complexity"]["num_filters"] >= 1
    assert result["complexity"]["num_selections"] >= 1


def test_parse_sigma_rule_missing_detection(tmp_dir):
    """Rule missing detection section should return None."""
    rule = {"title": "Broken Rule", "logsource": {"category": "test"}}
    path = tmp_dir / "broken.yml"
    path.write_text(yaml.dump(rule))

    result = parse_sigma_rule(path)
    assert result is None


def test_extract_sigma_rules(tmp_dir):
    """Extract all Sigma rules from a directory tree."""
    rules_dir = tmp_dir / "rules" / "windows"
    rules_dir.mkdir(parents=True)

    for i in range(3):
        rule = {
            "title": f"Rule {i}",
            "logsource": {"category": "test", "product": "windows"},
            "detection": {
                "selection": {"field": f"value{i}"},
                "condition": "selection",
            },
            "level": "medium",
        }
        (rules_dir / f"rule_{i}.yml").write_text(yaml.dump(rule))

    # Non-YAML file should be skipped
    (rules_dir / "readme.md").write_text("# not a rule")

    results = extract_sigma_rules(tmp_dir / "rules")
    assert len(results) == 3
    assert all(r["task"] == "T-SIGMA" for r in results)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sigma_parser.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/parsers/sigma_parser.py**

```python
"""Parse SigmaHQ YAML rules into CyberOutputBench instance schema."""

import re
from pathlib import Path

import yaml

from src.utils.io import setup_logging

logger = setup_logging("sigma_parser")


def parse_sigma_rule(path: Path) -> dict | None:
    """Parse a single Sigma YAML file into instance dict.

    Returns None if the rule is malformed (missing required fields).
    """
    path = Path(path)
    try:
        with open(path) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError:
        logger.warning("Invalid YAML: %s", path)
        return None

    if not isinstance(rule, dict):
        return None

    # Required fields
    if "detection" not in rule or "logsource" not in rule:
        logger.debug("Missing detection/logsource: %s", path)
        return None

    detection = rule["detection"]
    condition = detection.get("condition", "")

    # Count selections and filters
    num_selections = 0
    num_filters = 0
    for key in detection:
        if key == "condition":
            continue
        if key.startswith("filter"):
            num_filters += 1
        else:
            num_selections += 1

    # Count conditions (logical operators in condition string)
    num_conditions = 1
    if isinstance(condition, str):
        num_conditions += len(re.findall(r"\b(and|or|not)\b", condition))

    # Extract MITRE ATT&CK tags
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
    """Walk a directory tree and parse all .yml Sigma rules."""
    rules_dir = Path(rules_dir)
    results = []
    for path in sorted(rules_dir.rglob("*.yml")):
        parsed = parse_sigma_rule(path)
        if parsed is not None:
            results.append(parsed)
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_sigma_parser.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/parsers/sigma_parser.py tests/test_sigma_parser.py
git commit -m "feat: add Sigma rule parser with complexity counting"
```

---

## Chunk 3: YARA Parser

### Task 4: YARA Parser

**Files:**
- Create: `tests/test_yara_parser.py`
- Create: `src/parsers/yara_parser.py`

**Context:** YARA rules are parsed via `plyara` (a Python YARA rule parser). Each rule has `rule_name`, `metadata` (description, author, etc.), `strings` (named patterns), and `condition`. The parser counts strings and condition components for complexity.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_yara_parser.py
from pathlib import Path

from src.parsers.yara_parser import parse_yara_file, extract_yara_rules


def test_parse_yara_file_single_rule(sample_yara_rule_text, tmp_dir):
    """Parse a YARA file with one rule."""
    path = tmp_dir / "test.yar"
    path.write_text(sample_yara_rule_text)

    results = parse_yara_file(path)

    assert len(results) == 1
    rule = results[0]
    assert rule["task"] == "T-YARA"
    assert "Test_Malware" in rule["gold_artifact"]
    assert rule["metadata"]["original_title"] == "Test_Malware"
    assert rule["complexity"]["num_strings"] == 2
    assert rule["complexity"]["num_conditions"] >= 1


def test_parse_yara_file_multiple_rules(tmp_dir):
    """Parse a YARA file with multiple rules."""
    text = '''rule Rule_A {
    strings:
        $a = "alpha"
    condition:
        $a
}

rule Rule_B {
    strings:
        $b1 = "beta"
        $b2 = "gamma"
    condition:
        any of ($b*)
}'''
    path = tmp_dir / "multi.yar"
    path.write_text(text)

    results = parse_yara_file(path)
    assert len(results) == 2
    assert results[0]["metadata"]["original_title"] == "Rule_A"
    assert results[1]["complexity"]["num_strings"] == 2


def test_parse_yara_file_with_meta(tmp_dir):
    """Rule with metadata extracts description and author."""
    text = '''rule Emotet {
    meta:
        description = "Detects Emotet loader"
        author = "Analyst"
        reference = "https://example.com"
    strings:
        $s1 = "DllRegisterServer"
    condition:
        $s1
}'''
    path = tmp_dir / "meta.yar"
    path.write_text(text)

    results = parse_yara_file(path)
    assert results[0]["metadata"]["description"] == "Detects Emotet loader"


def test_parse_yara_file_invalid(tmp_dir):
    """Invalid YARA content returns empty list."""
    path = tmp_dir / "bad.yar"
    path.write_text("this is not a yara rule at all")

    results = parse_yara_file(path)
    assert results == []


def test_extract_yara_rules(tmp_dir):
    """Extract rules from a directory tree of .yar files."""
    rules_dir = tmp_dir / "yara_rules"
    rules_dir.mkdir()

    for i in range(2):
        text = f'''rule Test_{i} {{
    strings:
        $s = "test{i}"
    condition:
        $s
}}'''
        (rules_dir / f"rule_{i}.yar").write_text(text)

    results = extract_yara_rules(rules_dir)
    assert len(results) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_yara_parser.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/parsers/yara_parser.py**

```python
"""Parse YARA rules via plyara into CyberOutputBench instance schema."""

import re
from pathlib import Path

import plyara
import plyara.utils

from src.utils.io import setup_logging

logger = setup_logging("yara_parser")


def _count_condition_components(condition: str) -> int:
    """Count logical components in a YARA condition string."""
    # Count logical operators + base count of 1
    ops = len(re.findall(r"\b(and|or|not)\b", condition))
    return 1 + ops


def parse_yara_file(path: Path) -> list[dict]:
    """Parse a .yar file, return list of instance dicts (one per rule).

    Uses original file text as gold_artifact (not reconstructed) to preserve
    formatting, comments, and whitespace fidelity.
    """
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

        # Extract metadata
        meta = {}
        for entry in parsed.get("metadata", []):
            for k, v in entry.items():
                meta[k] = v

        # Count strings
        num_strings = len(parsed.get("strings", []))

        # Condition
        condition_str = " ".join(
            parsed.get("condition_terms", [])
        )
        num_conditions = _count_condition_components(condition_str)

        # Count imports (pe, math, hash modules)
        imports = parsed.get("imports", [])

        # Use original text for single-rule files; for multi-rule files,
        # reconstruct to isolate each rule
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
    """Walk a directory tree and parse all .yar/.yara files."""
    rules_dir = Path(rules_dir)
    results = []
    for ext in ("*.yar", "*.yara"):
        for path in sorted(rules_dir.rglob(ext)):
            parsed = parse_yara_file(path)
            results.extend(parsed)
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_yara_parser.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/parsers/yara_parser.py tests/test_yara_parser.py
git commit -m "feat: add YARA rule parser with plyara-based extraction"
```

---

## Chunk 4: STIX Parser

### Task 5: STIX Parser

**Files:**
- Create: `tests/test_stix_parser.py`
- Create: `src/parsers/stix_parser.py`

**Context:** MITRE ATT&CK STIX data lives in JSON bundles under `enterprise-attack/`, `ica-attack/`, `mobile-attack/` directories. Each bundle has `type: "bundle"` and `objects` array containing SDOs (malware, attack-pattern, indicator, etc.) and SROs (relationships). We extract individual technique-centered sub-bundles.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_stix_parser.py
import json
from pathlib import Path

from src.parsers.stix_parser import (
    parse_stix_bundle,
    extract_technique_bundles,
    extract_stix_rules,
)


def test_parse_stix_bundle(sample_stix_bundle):
    """Parse a STIX bundle and count components."""
    result = parse_stix_bundle(sample_stix_bundle, source="test/bundle.json")

    assert result["task"] == "T-STIX"
    assert '"type": "bundle"' in result["gold_artifact"]
    assert result["complexity"]["num_sdos"] == 2  # malware + indicator
    assert result["complexity"]["num_sros"] == 1  # relationship
    assert result["complexity"]["num_objects"] == 3


def test_parse_stix_bundle_empty():
    """Empty bundle should return None."""
    bundle = {"type": "bundle", "id": "bundle--empty", "objects": []}
    result = parse_stix_bundle(bundle, source="empty.json")
    assert result is None


def test_extract_technique_bundles(sample_stix_bundle, tmp_dir):
    """Extract sub-bundles centered on attack-pattern objects."""
    # Add an attack-pattern to make extraction work
    bundle = dict(sample_stix_bundle)
    bundle["objects"] = list(bundle["objects"]) + [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "name": "Spearphishing",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--tech",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "relationship_type": "uses",
            "source_ref": "malware--1234",
            "target_ref": "attack-pattern--001",
        },
    ]

    path = tmp_dir / "enterprise-attack.json"
    path.write_text(json.dumps(bundle))

    results = extract_technique_bundles(path)
    assert len(results) >= 1
    # Each result should be centered on an attack-pattern
    assert any("Spearphishing" in r["gold_artifact"] for r in results)


def test_extract_stix_rules(tmp_dir):
    """Extract from a directory with multiple JSON bundle files."""
    stix_dir = tmp_dir / "stix"
    stix_dir.mkdir()

    for domain in ["enterprise-attack", "mobile-attack"]:
        bundle = {
            "type": "bundle",
            "id": f"bundle--{domain}",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{domain}",
                    "spec_version": "2.1",
                    "created": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-01T00:00:00Z",
                    "name": f"Technique {domain}",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T0001"}
                    ],
                }
            ],
        }
        sub = stix_dir / domain
        sub.mkdir()
        (sub / f"{domain}.json").write_text(json.dumps(bundle))

    results = extract_stix_rules(stix_dir)
    assert len(results) >= 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_stix_parser.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/parsers/stix_parser.py**

```python
"""Parse MITRE ATT&CK STIX 2.1 bundles into CyberOutputBench instance schema."""

import json
from pathlib import Path

from src.utils.io import setup_logging

logger = setup_logging("stix_parser")

# STIX Domain Object types (SDOs) vs Relationship Objects (SROs)
SRO_TYPES = {"relationship", "sighting"}


def parse_stix_bundle(bundle: dict, source: str) -> dict | None:
    """Parse a STIX bundle dict into an instance dict.

    Returns None if the bundle has no objects.
    """
    objects = bundle.get("objects", [])
    if not objects:
        return None

    sdos = [o for o in objects if o.get("type") not in SRO_TYPES]
    sros = [o for o in objects if o.get("type") in SRO_TYPES]

    # Count relationship types
    rel_types = set()
    for sro in sros:
        rt = sro.get("relationship_type", "")
        if rt:
            rel_types.add(rt)

    # Extract MITRE ATT&CK IDs from external_references
    mitre_ids = []
    for obj in objects:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id:
                    mitre_ids.append(ext_id)

    gold_artifact = json.dumps(bundle, indent=2, ensure_ascii=False)

    return {
        "task": "T-STIX",
        "source": source,
        "gold_artifact": gold_artifact,
        "metadata": {
            "mitre_attack": mitre_ids,
            "license": "Apache-2.0",
            "object_types": list({o["type"] for o in objects}),
            "relationship_types": list(rel_types),
        },
        "complexity": {
            "num_sdos": len(sdos),
            "num_sros": len(sros),
            "num_objects": len(objects),
            "reasoning_depth": len(sdos) + len(sros),
        },
    }


def extract_technique_bundles(bundle_path: Path) -> list[dict]:
    """Extract per-technique sub-bundles from a full ATT&CK bundle.

    Each sub-bundle centers on one attack-pattern and includes all
    objects directly related to it via relationships.
    """
    bundle_path = Path(bundle_path)
    try:
        with open(bundle_path) as f:
            full_bundle = json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to load STIX bundle: %s", bundle_path)
        return []

    objects = full_bundle.get("objects", [])
    obj_by_id = {o["id"]: o for o in objects if "id" in o}

    # Find all attack-patterns
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]

    # Build relationship index
    rels_by_source = {}
    rels_by_target = {}
    for o in objects:
        if o.get("type") == "relationship":
            src = o.get("source_ref", "")
            tgt = o.get("target_ref", "")
            rels_by_source.setdefault(src, []).append(o)
            rels_by_target.setdefault(tgt, []).append(o)

    results = []
    for tech in techniques:
        tech_id = tech["id"]

        # Collect related objects
        sub_objects = [tech]
        seen_ids = {tech_id}

        # Relationships where technique is source or target
        related_rels = rels_by_source.get(tech_id, []) + rels_by_target.get(
            tech_id, []
        )

        for rel in related_rels:
            if rel["id"] not in seen_ids:
                sub_objects.append(rel)
                seen_ids.add(rel["id"])
            # Add the other end of the relationship
            other_id = (
                rel["target_ref"]
                if rel["source_ref"] == tech_id
                else rel["source_ref"]
            )
            if other_id not in seen_ids and other_id in obj_by_id:
                sub_objects.append(obj_by_id[other_id])
                seen_ids.add(other_id)

        sub_bundle = {
            "type": "bundle",
            "id": f"bundle--technique-{tech_id}",
            "objects": sub_objects,
        }

        parsed = parse_stix_bundle(sub_bundle, source=str(bundle_path))
        if parsed is not None:
            parsed["metadata"]["technique_name"] = tech.get("name", "")
            results.append(parsed)

    return results


def extract_stix_rules(stix_dir: Path) -> list[dict]:
    """Walk a STIX data directory and extract technique sub-bundles."""
    stix_dir = Path(stix_dir)
    results = []
    for path in sorted(stix_dir.rglob("*.json")):
        extracted = extract_technique_bundles(path)
        results.extend(extracted)
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stix_parser.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/parsers/stix_parser.py tests/test_stix_parser.py
git commit -m "feat: add STIX 2.1 bundle parser with technique extraction"
```

---

## Chunk 5: GPT-4o Describer

### Task 6: NL Description Generator

**Files:**
- Create: `tests/test_describer.py`
- Create: `src/describers/gpt4o_describer.py`

**Context:** The describer takes extracted instances (with `gold_artifact` and `metadata`) and generates NL descriptions via GPT-4o. It uses `asyncio` for concurrency (max 10 concurrent), has exponential backoff retry, and tracks cost. Each task type (YARA/Sigma/STIX) has its own prompt template.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_describer.py
import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.describers.gpt4o_describer import (
    get_prompt_template,
    build_prompt,
    describe_instance,
    describe_batch,
)


def test_get_prompt_template_sigma():
    template = get_prompt_template("T-SIGMA")
    assert "Sigma" in template
    assert "{gold_artifact}" in template


def test_get_prompt_template_yara():
    template = get_prompt_template("T-YARA")
    assert "YARA" in template


def test_get_prompt_template_stix():
    template = get_prompt_template("T-STIX")
    assert "STIX" in template


def test_get_prompt_template_unknown():
    with pytest.raises(ValueError, match="Unknown task"):
        get_prompt_template("T-UNKNOWN")


def test_build_prompt():
    instance = {
        "task": "T-SIGMA",
        "gold_artifact": "title: Test Rule\ndetection:\n  selection:\n    field: value",
        "metadata": {"original_title": "Test Rule", "mitre_attack": ["T1003"]},
    }
    prompt = build_prompt(instance)
    assert "Test Rule" in prompt
    assert isinstance(prompt, str)


@pytest.mark.asyncio
async def test_describe_instance_mock():
    """Test describe_instance with mocked OpenAI client."""
    instance = {
        "task": "T-SIGMA",
        "gold_artifact": "title: Test\ndetection:\n  sel:\n    x: y\n  condition: sel",
        "metadata": {"original_title": "Test"},
    }

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Create a Sigma rule that detects..."
    mock_response.usage.prompt_tokens = 100
    mock_response.usage.completion_tokens = 50

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    result = await describe_instance(instance, mock_client, model="gpt-4o")

    assert result["nl_description"] == "Create a Sigma rule that detects..."
    assert result["nl_description_model"] == "gpt-4o"
    assert "gold_artifact" in result


@pytest.mark.asyncio
async def test_describe_batch_mock():
    """Test batch description with concurrency control."""
    instances = [
        {
            "task": "T-SIGMA",
            "gold_artifact": f"title: Rule {i}\ndetection:\n  sel:\n    x: y\n  condition: sel",
            "metadata": {"original_title": f"Rule {i}"},
        }
        for i in range(5)
    ]

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "NL description"
    mock_response.usage.prompt_tokens = 100
    mock_response.usage.completion_tokens = 50

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    results, cost = await describe_batch(
        instances, mock_client, model="gpt-4o", max_concurrent=2
    )

    assert len(results) == 5
    assert all(r["nl_description"] == "NL description" for r in results)
    assert cost > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_describer.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/describers/gpt4o_describer.py**

```python
"""GPT-4o NL description generation for CyberOutputBench instances."""

import asyncio

from src.utils.io import setup_logging

logger = setup_logging("gpt4o_describer")

# Pricing per 1M tokens (GPT-4o as of 2026)
PRICING = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
}

PROMPT_TEMPLATES = {
    "T-SIGMA": (
        "You are a cybersecurity expert. Given the following Sigma detection rule, "
        "write a clear natural language description that could be used as a prompt to "
        "recreate this rule from scratch. The description should specify the log source, "
        "detection logic, and conditions without revealing the exact YAML syntax.\n\n"
        "Sigma Rule:\n```yaml\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Create a Sigma rule to detect...'"
    ),
    "T-YARA": (
        "You are a malware analyst. Given the following YARA rule, write a clear "
        "natural language description that could be used as a prompt to recreate this "
        "rule from scratch. The description should specify what the rule detects, "
        "key indicators, and matching conditions without revealing exact syntax.\n\n"
        "YARA Rule:\n```yara\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Write a YARA rule to detect...'"
    ),
    "T-STIX": (
        "You are a threat intelligence analyst. Given the following STIX 2.1 bundle, "
        "write a clear natural language description that could be used as a prompt to "
        "recreate this bundle from scratch. The description should specify the threat "
        "actors, malware, indicators, and relationships without revealing JSON syntax.\n\n"
        "STIX Bundle:\n```json\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Create a STIX 2.1 bundle describing...'"
    ),
}


def get_prompt_template(task: str) -> str:
    """Get the prompt template for a task type."""
    if task not in PROMPT_TEMPLATES:
        raise ValueError(f"Unknown task: {task}")
    return PROMPT_TEMPLATES[task]


def build_prompt(instance: dict) -> str:
    """Build the full prompt for an instance."""
    template = get_prompt_template(instance["task"])
    return template.format(
        gold_artifact=instance["gold_artifact"],
        metadata=str(instance.get("metadata", {})),
    )


async def describe_instance(
    instance: dict,
    client,
    model: str = "gpt-4o",
    max_retries: int = 3,
) -> dict:
    """Generate NL description for a single instance with retry."""
    prompt = build_prompt(instance)

    for attempt in range(max_retries):
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=512,
            )
            description = response.choices[0].message.content.strip()
            usage = response.usage

            result = dict(instance)
            result["nl_description"] = description
            result["nl_description_model"] = model
            result["_usage"] = {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
            }
            return result

        except Exception as e:
            wait = 2 ** (attempt + 1)
            logger.warning(
                "API error (attempt %d/%d): %s. Retrying in %ds.",
                attempt + 1,
                max_retries,
                e,
                wait,
            )
            await asyncio.sleep(wait)

    # All retries failed — return instance without description
    logger.error("Failed to describe instance after %d retries", max_retries)
    result = dict(instance)
    result["nl_description"] = ""
    result["nl_description_model"] = model
    return result


async def describe_batch(
    instances: list[dict],
    client,
    model: str = "gpt-4o",
    max_concurrent: int = 10,
) -> tuple[list[dict], float]:
    """Describe a batch of instances with concurrency control.

    Returns (described_instances, total_cost_usd).
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []

    async def _describe(inst):
        async with semaphore:
            return await describe_instance(inst, client, model)

    tasks = [_describe(inst) for inst in instances]
    results = await asyncio.gather(*tasks)

    # Compute cost
    pricing = PRICING.get(model, PRICING["gpt-4o"])
    total_input = sum(r.get("_usage", {}).get("prompt_tokens", 0) for r in results)
    total_output = sum(
        r.get("_usage", {}).get("completion_tokens", 0) for r in results
    )
    cost = (total_input * pricing["input"] + total_output * pricing["output"]) / 1_000_000

    # Clean up internal usage tracking
    for r in results:
        r.pop("_usage", None)

    logger.info(
        "Described %d instances. Tokens: %d in / %d out. Cost: $%.4f",
        len(results),
        total_input,
        total_output,
        cost,
    )

    return list(results), cost
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_describer.py -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/describers/gpt4o_describer.py tests/test_describer.py
git commit -m "feat: add async GPT-4o describer with rate limiting and cost tracking"
```

---

## Chunk 6: Splitter + Complexity Annotator

### Task 7: Splitter (Dedup + Stratified Split)

**Files:**
- Create: `tests/test_splitter.py`
- Create: `src/splitter.py`

**Context:** SHA256 hash-based dedup on normalized `gold_artifact`. Stratified split: 200/task for test, difficulty distribution (60 easy / 80 medium / 60 hard). Fixed seed 42. Remaining → training pool.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_splitter.py
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
        {"gold_artifact": "rule A", "task": "T-YARA"},  # duplicate
        {"gold_artifact": "rule B", "task": "T-YARA"},
    ]
    result = deduplicate(instances)
    assert len(result) == 2


def test_deduplicate_normalizes_whitespace():
    instances = [
        {"gold_artifact": "rule  A\n\n", "task": "T-YARA"},
        {"gold_artifact": "rule A\n", "task": "T-YARA"},  # same after normalization
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
    """200 per task for test, rest for train."""
    difficulties = ["easy"] * 60 + ["medium"] * 80 + ["hard"] * 60
    instances = []
    for task in ["T-SIGMA", "T-YARA", "T-STIX"]:
        instances.extend(_make_instances(task, 300, difficulties))

    train, test = split_dataset(instances, test_per_task=200, seed=42)

    assert len(test) == 600  # 200 per task
    assert len(train) == 300  # 100 per task remaining

    # Check task distribution in test
    for task in ["T-SIGMA", "T-YARA", "T-STIX"]:
        task_test = [i for i in test if i["task"] == task]
        assert len(task_test) == 200


def test_split_dataset_difficulty_distribution():
    """Test set should have ~60 easy, 80 medium, 60 hard per task."""
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
    """Same seed → same split."""
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_splitter.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/splitter.py**

```python
"""Hash-based deduplication and stratified train/test splitting."""

import hashlib
import random
import re

from src.utils.io import setup_logging

logger = setup_logging("splitter")

# Task prefix for ID generation
TASK_PREFIX = {
    "T-SIGMA": "sigma",
    "T-YARA": "yara",
    "T-STIX": "stix",
}

# Target difficulty distribution per task in test set
DEFAULT_DIFFICULTY_DIST = {"easy": 60, "medium": 80, "hard": 60}


def _normalize(text: str) -> str:
    """Normalize artifact text for dedup: collapse whitespace, strip."""
    return re.sub(r"\s+", " ", text.strip())


def _hash_artifact(text: str) -> str:
    """SHA256 hash of normalized artifact text."""
    return hashlib.sha256(_normalize(text).encode()).hexdigest()


def deduplicate(instances: list[dict]) -> list[dict]:
    """Remove duplicate instances based on normalized gold_artifact hash."""
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
    """Assign sequential IDs per task type (sigma-001, yara-001, etc.)."""
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
    """Stratified split into train and test sets.

    Test set: test_per_task instances per task, stratified by difficulty.
    Train set: remaining instances.
    """
    if difficulty_dist is None:
        difficulty_dist = DEFAULT_DIFFICULTY_DIST

    rng = random.Random(seed)
    test = []
    train = []

    # Group by task
    by_task = {}
    for inst in instances:
        by_task.setdefault(inst["task"], []).append(inst)

    for task, task_instances in by_task.items():
        # Group by difficulty within task
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
                # Take all available for this difficulty
                task_test.extend(pool)
                logger.warning(
                    "Task %s difficulty %s: only %d available (target %d)",
                    task,
                    diff,
                    len(pool),
                    target_n,
                )

        # Any difficulties not in distribution go to train
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_splitter.py -v`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/splitter.py tests/test_splitter.py
git commit -m "feat: add hash-based dedup and stratified train/test splitter"
```

---

### Task 8: Complexity Annotator

**Files:**
- Create: `tests/test_complexity.py`
- Create: `src/annotators/complexity.py`

**Context:** Classify difficulty (easy/medium/hard) based on structural complexity. Thresholds differ per task type.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_complexity.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_complexity.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/annotators/complexity.py**

```python
"""Difficulty classification based on structural complexity metrics."""


def _total_components(task: str, complexity: dict) -> int:
    """Compute a single complexity score for difficulty thresholding."""
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
            + complexity.get("num_imports", 0) * 2  # imports add complexity
        )
    elif task == "T-STIX":
        return complexity.get("num_sdos", 0) + complexity.get("num_sros", 0)
    return 0


# Thresholds: (easy_max, medium_max) — above medium_max → hard
THRESHOLDS = {
    "T-SIGMA": (3, 6),
    "T-YARA": (3, 8),
    "T-STIX": (4, 8),
}


def classify_difficulty(task: str, complexity: dict) -> str:
    """Classify difficulty as easy/medium/hard based on component count."""
    score = _total_components(task, complexity)
    easy_max, medium_max = THRESHOLDS.get(task, (3, 6))

    if score <= easy_max:
        return "easy"
    elif score <= medium_max:
        return "medium"
    else:
        return "hard"


def annotate_complexity(instances: list[dict]) -> list[dict]:
    """Add difficulty classification to each instance."""
    result = []
    for inst in instances:
        inst_copy = dict(inst)
        inst_copy["difficulty"] = classify_difficulty(
            inst["task"], inst.get("complexity", {})
        )
        result.append(inst_copy)
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_complexity.py -v`
Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/annotators/complexity.py tests/test_complexity.py
git commit -m "feat: add difficulty classifier based on structural complexity"
```

---

## Chunk 7: Quality Validator + CLI

### Task 9: Quality Validator

**Files:**
- Create: `tests/test_quality.py`
- Create: `src/validators/quality.py`

**Context:** Validates gold artifacts using domain tools: `yara-python` for YARA compilation, `pySigma` for Sigma field validation, `stix2-validator` for STIX schema conformance. Also filters trivial instances (< min_components).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_quality.py
import pytest

from src.validators.quality import (
    validate_sigma,
    validate_yara,
    validate_stix,
    validate_instance,
    filter_trivial,
)


def test_validate_sigma_valid():
    artifact = (
        "title: Test\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    Image: test.exe\n"
        "  condition: selection\n"
        "level: medium\n"
    )
    is_valid, errors = validate_sigma(artifact)
    assert is_valid
    assert errors == []


def test_validate_sigma_missing_field():
    artifact = "title: Test\nlevel: medium\n"  # no logsource or detection
    is_valid, errors = validate_sigma(artifact)
    assert not is_valid
    assert len(errors) > 0


def test_validate_yara_valid(sample_yara_rule_text):
    is_valid, errors = validate_yara(sample_yara_rule_text)
    assert is_valid
    assert errors == []


def test_validate_yara_invalid():
    is_valid, errors = validate_yara("rule Bad { condition: invalid_var }")
    assert not is_valid


def test_validate_stix_valid(sample_stix_bundle):
    import json
    artifact = json.dumps(sample_stix_bundle)
    is_valid, errors = validate_stix(artifact)
    assert is_valid


def test_validate_stix_invalid():
    is_valid, errors = validate_stix('{"type": "bundle", "objects": [{"type": "fake"}]}')
    assert not is_valid


def test_validate_instance_dispatches(sample_yara_rule_text):
    instance = {"task": "T-YARA", "gold_artifact": sample_yara_rule_text}
    result = validate_instance(instance)
    assert result["_valid"] is True


def test_filter_trivial():
    instances = [
        {"task": "T-SIGMA", "complexity": {"num_selections": 1, "num_filters": 0, "num_conditions": 1}},  # total=2 < 3
        {"task": "T-SIGMA", "complexity": {"num_selections": 2, "num_filters": 1, "num_conditions": 2}},  # total=5 >= 3
    ]
    result = filter_trivial(instances, min_components=3)
    assert len(result) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_quality.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement src/validators/quality.py**

```python
"""Quality validation using domain-specific tools."""

import json

import yaml

from src.utils.io import setup_logging

logger = setup_logging("quality_validator")


def validate_sigma(artifact: str) -> tuple[bool, list[str]]:
    """Validate a Sigma rule YAML string using pySigma."""
    errors = []
    try:
        rule_dict = yaml.safe_load(artifact)
    except yaml.YAMLError as e:
        return False, [f"Invalid YAML: {e}"]

    if not isinstance(rule_dict, dict):
        return False, ["Not a YAML mapping"]

    # Basic required field check first
    required = ["title", "logsource", "detection"]
    for field in required:
        if field not in rule_dict:
            errors.append(f"Missing required field: {field}")
    if errors:
        return False, errors

    # Use pySigma for deeper validation
    try:
        from sigma.rule import SigmaRule

        SigmaRule.from_yaml(artifact)
        return True, []
    except Exception as e:
        return False, [f"pySigma validation error: {e}"]


def validate_yara(artifact: str) -> tuple[bool, list[str]]:
    """Validate a YARA rule by attempting compilation."""
    try:
        import yara

        yara.compile(source=artifact)
        return True, []
    except yara.SyntaxError as e:
        return False, [f"YARA syntax error: {e}"]
    except yara.Error as e:
        return False, [f"YARA error: {e}"]
    except Exception as e:
        return False, [f"Unexpected error: {e}"]


def validate_stix(artifact: str) -> tuple[bool, list[str]]:
    """Validate a STIX 2.1 bundle JSON string."""
    errors = []
    try:
        bundle = json.loads(artifact)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]

    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        return False, ["Not a STIX bundle (missing type: bundle)"]

    objects = bundle.get("objects", [])
    if not objects:
        return False, ["Bundle has no objects"]

    # Basic schema checks per object
    for i, obj in enumerate(objects):
        if "type" not in obj:
            errors.append(f"Object {i}: missing 'type'")
        if "id" not in obj:
            errors.append(f"Object {i}: missing 'id'")

    # Try stix2-validator if available
    try:
        from stix2validator import validate_string

        result = validate_string(artifact)
        if not result.is_valid:
            for msg in result.errors:
                errors.append(f"stix2-validator: {msg}")
    except ImportError:
        logger.debug("stix2-validator not available, using basic checks only")

    return len(errors) == 0, errors


_VALIDATORS = {
    "T-SIGMA": validate_sigma,
    "T-YARA": validate_yara,
    "T-STIX": validate_stix,
}


def validate_instance(instance: dict) -> dict:
    """Validate a single instance's gold_artifact. Adds _valid and _errors fields."""
    result = dict(instance)
    task = instance["task"]
    validator = _VALIDATORS.get(task)

    if validator is None:
        result["_valid"] = False
        result["_errors"] = [f"No validator for task: {task}"]
        return result

    is_valid, errors = validator(instance["gold_artifact"])
    result["_valid"] = is_valid
    result["_errors"] = errors
    return result


def filter_trivial(instances: list[dict], min_components: int = 3) -> list[dict]:
    """Remove instances with fewer than min_components total components."""
    result = []
    for inst in instances:
        c = inst.get("complexity", {})
        total = sum(v for v in c.values() if isinstance(v, (int, float)))
        if total >= min_components:
            result.append(inst)
    filtered = len(instances) - len(result)
    if filtered:
        logger.info("Filtered %d trivial instances (<%d components)", filtered, min_components)
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_quality.py -v`
Expected: All 8 tests PASS. (Some may skip if `yara-python` or `stix2-validator` not installed yet — that's acceptable, they'll pass after `pip install -e ".[dev]"`.)

- [ ] **Step 5: Commit**

```bash
git add src/validators/quality.py tests/test_quality.py
git commit -m "feat: add quality validators for YARA, Sigma, and STIX artifacts"
```

---

### Task 10: CLI Entry Point

**Files:**
- Create: `tests/test_cli.py`
- Create: `scripts/build_dataset.py`

**Context:** Single Click CLI with subcommands: `fetch`, `extract`, `describe`, `split`, `annotate`, `validate`, `export`. Each reads from previous stage output and writes to the next. Config loaded from `configs/dataset.yaml`.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cli.py
from click.testing import CliRunner

from scripts.build_dataset import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "CyberOutputBench" in result.output


def test_cli_fetch_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["fetch", "--help"])
    assert result.exit_code == 0
    assert "--config" in result.output


def test_cli_extract_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["extract", "--help"])
    assert result.exit_code == 0


def test_cli_describe_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["describe", "--help"])
    assert result.exit_code == 0


def test_cli_split_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["split", "--help"])
    assert result.exit_code == 0


def test_cli_annotate_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["annotate", "--help"])
    assert result.exit_code == 0


def test_cli_validate_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--help"])
    assert result.exit_code == 0


def test_cli_export_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "--help"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement scripts/build_dataset.py**

```python
#!/usr/bin/env python3
"""CyberOutputBench dataset construction CLI."""

import asyncio
import json
import subprocess
from pathlib import Path

import click

from src.utils.io import load_config, read_jsonl, write_jsonl, setup_logging
from src.parsers.sigma_parser import extract_sigma_rules
from src.parsers.yara_parser import extract_yara_rules
from src.parsers.stix_parser import extract_stix_rules
from src.annotators.complexity import annotate_complexity
from src.validators.quality import validate_instance, filter_trivial
from src.splitter import deduplicate, assign_ids, split_dataset

logger = setup_logging("build_dataset")

DEFAULT_CONFIG = "configs/dataset.yaml"


@click.group()
@click.option("--config", default=DEFAULT_CONFIG, help="Path to dataset.yaml config")
@click.pass_context
def cli(ctx, config):
    """CyberOutputBench dataset construction pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)
    ctx.obj["config_path"] = config


@cli.command()
@click.pass_context
def fetch(ctx):
    """Clone source repositories into data/raw/."""
    config = ctx.obj["config"]
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)

    repos = {
        "sigma": config["sources"]["sigma_repo"],
        "yara_forge": config["sources"]["yara_forge"],
        "mitre_stix": config["sources"]["mitre_stix"],
    }

    for name, url in repos.items():
        dest = raw_dir / name
        if dest.exists():
            logger.info("Repo %s already exists, pulling latest...", name)
            subprocess.run(["git", "-C", str(dest), "pull"], check=True)
        else:
            logger.info("Cloning %s from %s...", name, url)
            subprocess.run(["git", "clone", "--depth=1", url, str(dest)], check=True)

    click.echo(f"Fetched {len(repos)} repos to {raw_dir}")


@cli.command()
@click.pass_context
def extract(ctx):
    """Extract rules from cloned repos into data/extracted/ JSONL files."""
    raw_dir = Path("data/raw")
    out_dir = Path("data/extracted")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sigma
    sigma_dir = raw_dir / "sigma" / "rules"
    if sigma_dir.exists():
        sigma_rules = extract_sigma_rules(sigma_dir)
        write_jsonl(sigma_rules, out_dir / "sigma.jsonl")
        click.echo(f"Extracted {len(sigma_rules)} Sigma rules")
    else:
        click.echo("Warning: Sigma rules directory not found", err=True)

    # YARA
    yara_dir = raw_dir / "yara_forge"
    if yara_dir.exists():
        yara_rules = extract_yara_rules(yara_dir)
        write_jsonl(yara_rules, out_dir / "yara.jsonl")
        click.echo(f"Extracted {len(yara_rules)} YARA rules")
    else:
        click.echo("Warning: YARA Forge directory not found", err=True)

    # STIX
    stix_dir = raw_dir / "mitre_stix"
    if stix_dir.exists():
        stix_rules = extract_stix_rules(stix_dir)
        write_jsonl(stix_rules, out_dir / "stix.jsonl")
        click.echo(f"Extracted {len(stix_rules)} STIX technique bundles")
    else:
        click.echo("Warning: MITRE STIX directory not found", err=True)


@cli.command()
@click.option("--task", type=click.Choice(["sigma", "yara", "stix", "all"]), default="all")
@click.pass_context
def describe(ctx, task):
    """Generate NL descriptions via GPT-4o for extracted instances."""
    config = ctx.obj["config"]
    extracted_dir = Path("data/extracted")
    out_dir = Path("data/described")
    out_dir.mkdir(parents=True, exist_ok=True)

    from openai import AsyncOpenAI
    from src.describers.gpt4o_describer import describe_batch

    client = AsyncOpenAI()
    model = config["description"]["model"]
    max_concurrent = config["description"]["max_concurrent"]
    cost_limit = config["description"]["cost_limit_usd"]

    tasks = ["sigma", "yara", "stix"] if task == "all" else [task]
    total_cost = 0.0

    for t in tasks:
        input_path = extracted_dir / f"{t}.jsonl"
        if not input_path.exists():
            click.echo(f"Skipping {t}: {input_path} not found", err=True)
            continue

        instances = read_jsonl(input_path)
        # Skip already described
        instances = [i for i in instances if not i.get("nl_description")]

        if not instances:
            click.echo(f"All {t} instances already described")
            continue

        if total_cost >= cost_limit:
            click.echo(f"Cost limit ${cost_limit} reached. Stopping.", err=True)
            break

        click.echo(f"Describing {len(instances)} {t} instances...")
        results, cost = asyncio.run(
            describe_batch(instances, client, model=model, max_concurrent=max_concurrent)
        )
        total_cost += cost

        write_jsonl(results, out_dir / f"{t}.jsonl")
        click.echo(f"Described {len(results)} {t} instances (cost: ${cost:.4f})")

    click.echo(f"Total description cost: ${total_cost:.4f}")


@cli.command()
@click.pass_context
def annotate(ctx):
    """Add difficulty/complexity annotations to described instances.

    Note: Run BEFORE split. Annotates all instances so both train and test
    have difficulty labels (needed for stratified splitting).
    """
    config = ctx.obj["config"]
    described_dir = Path("data/described")

    # Pass config thresholds if provided
    diff_dist = config.get("dataset", {}).get("difficulty_distribution")

    for task_file in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
        path = described_dir / task_file
        if not path.exists():
            continue
        instances = read_jsonl(path)
        annotated = annotate_complexity(instances)
        write_jsonl(annotated, path)
        click.echo(f"Annotated {len(annotated)} instances in {task_file}")


@cli.command()
@click.pass_context
def split(ctx):
    """Deduplicate and split into train/test sets."""
    config = ctx.obj["config"]
    described_dir = Path("data/described")
    out_dir = Path("data/final")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Merge all tasks
    all_instances = []
    for task_file in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
        path = described_dir / task_file
        if path.exists():
            all_instances.extend(read_jsonl(path))

    # Dedup
    unique = deduplicate(all_instances)

    # Split first, then assign IDs (so IDs are contiguous within each split)
    test_size = config["split"]["test_size"]
    seed = config["split"]["seed"]
    test_per_task = test_size // 3

    train, test = split_dataset(unique, test_per_task=test_per_task, seed=seed)

    # Assign sequential IDs within each split
    train = assign_ids(train)
    test = assign_ids(test)

    write_jsonl(train, out_dir / "train.jsonl")
    write_jsonl(test, out_dir / "test.jsonl")
    click.echo(f"Split: {len(test)} test, {len(train)} train")


@cli.command()
@click.pass_context
def validate(ctx):
    """Run tool-based validation on test set gold artifacts."""
    config = ctx.obj["config"]
    final_dir = Path("data/final")
    test_path = final_dir / "test.jsonl"

    if not test_path.exists():
        click.echo("Error: test.jsonl not found. Run 'split' first.", err=True)
        return

    instances = read_jsonl(test_path)
    min_comp = config["dataset"]["min_components"]

    # Filter trivial
    filtered = filter_trivial(instances, min_components=min_comp)
    click.echo(f"After trivial filter: {len(filtered)}/{len(instances)}")

    # Validate each
    validated = [validate_instance(i) for i in filtered]
    valid = [v for v in validated if v["_valid"]]
    invalid = [v for v in validated if not v["_valid"]]

    click.echo(f"Valid: {len(valid)}, Invalid: {len(invalid)}")

    # Write validated set
    write_jsonl(validated, final_dir / "test_validated.jsonl")

    # Log errors
    if invalid:
        for inv in invalid[:10]:
            logger.warning("Invalid %s: %s", inv.get("id", "?"), inv["_errors"])


@cli.command()
@click.option("--output", default="data/final/cyberoutputbench.json", help="Output path")
@click.pass_context
def export(ctx, output):
    """Export validated test set to benchmark release format (JSON)."""
    final_dir = Path("data/final")
    validated_path = final_dir / "test_validated.jsonl"

    if not validated_path.exists():
        click.echo("Error: test_validated.jsonl not found. Run 'validate' first.", err=True)
        return

    instances = read_jsonl(validated_path)

    # Keep only valid instances, remove internal fields
    export_data = []
    for inst in instances:
        if not inst.get("_valid", False):
            continue
        clean = {k: v for k, v in inst.items() if not k.startswith("_")}
        export_data.append(clean)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    click.echo(f"Exported {len(export_data)} instances to {output_path}")

    # Print stats
    by_task = {}
    for inst in export_data:
        task = inst["task"]
        by_task.setdefault(task, {"easy": 0, "medium": 0, "hard": 0})
        diff = inst.get("difficulty", "medium")
        by_task[task][diff] = by_task[task].get(diff, 0) + 1

    for task, dists in sorted(by_task.items()):
        total = sum(dists.values())
        click.echo(f"  {task}: {total} (E={dists['easy']}, M={dists['medium']}, H={dists['hard']})")


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/build_dataset.py tests/test_cli.py
git commit -m "feat: add Click CLI with fetch/extract/describe/split/annotate/validate/export commands"
```

---

## Chunk 8: Integration Test + Final Polish

### Task 11: Integration Smoke Test

**Files:**
- Create: `tests/test_integration.py`

**Context:** End-to-end test that runs extract → annotate → split on synthetic data. Does NOT test `fetch` (requires network) or `describe` (requires OpenAI API key).

- [ ] **Step 1: Write integration test**

```python
# tests/test_integration.py
"""Integration test: extract → annotate → split pipeline on synthetic data."""

import json
import yaml
from pathlib import Path

from click.testing import CliRunner

from scripts.build_dataset import cli


def _create_sigma_rules(rules_dir: Path, n: int = 10):
    rules_dir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        rule = {
            "title": f"Test Rule {i}",
            "description": f"Detects test behavior {i}",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"Image|endswith": f"\\test{i}.exe"},
                "condition": "selection",
            },
            "level": "medium",
            "tags": [f"attack.t{1000+i}"],
        }
        (rules_dir / f"rule_{i}.yml").write_text(yaml.dump(rule))


def _create_yara_rules(rules_dir: Path, n: int = 10):
    rules_dir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        text = f'''rule Test_Rule_{i} {{
    meta:
        description = "Test rule {i}"
    strings:
        $s1 = "test_string_{i}" ascii
    condition:
        $s1
}}'''
        (rules_dir / f"rule_{i}.yar").write_text(text)


def _create_stix_bundles(stix_dir: Path, n: int = 10):
    domain_dir = stix_dir / "enterprise-attack"
    domain_dir.mkdir(parents=True, exist_ok=True)

    objects = []
    for i in range(n):
        objects.append({
            "type": "attack-pattern",
            "id": f"attack-pattern--{i:04d}",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "name": f"Technique {i}",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": f"T{1000+i}"}
            ],
        })

    bundle = {"type": "bundle", "id": "bundle--test", "objects": objects}
    (domain_dir / "enterprise-attack.json").write_text(json.dumps(bundle))


def test_extract_annotate_split_pipeline(tmp_dir):
    """Full pipeline on synthetic data (no network, no API key)."""
    import os

    # Setup synthetic raw data
    raw_dir = tmp_dir / "data" / "raw"
    _create_sigma_rules(raw_dir / "sigma" / "rules" / "windows", n=15)
    _create_yara_rules(raw_dir / "yara_forge" / "rules", n=15)
    _create_stix_bundles(raw_dir / "mitre_stix", n=15)

    # Config
    config_path = tmp_dir / "dataset.yaml"
    config = {
        "sources": {
            "sigma_repo": "unused",
            "yara_forge": "unused",
            "mitre_stix": "unused",
        },
        "dataset": {
            "target_per_task": 5,
            "difficulty_distribution": {"easy": 2, "medium": 2, "hard": 1},
            "min_components": 1,
        },
        "description": {"model": "gpt-4o", "max_concurrent": 1, "cost_limit_usd": 0},
        "split": {"test_size": 15, "seed": 42},
    }
    config_path.write_text(yaml.dump(config))

    # Run pipeline from the synthetic data dir
    original_dir = os.getcwd()
    os.chdir(tmp_dir)

    try:
        runner = CliRunner()

        # Extract
        result = runner.invoke(cli, ["--config", str(config_path), "extract"])
        assert result.exit_code == 0, result.output
        assert "Extracted" in result.output

        # Verify extracted files exist
        assert (tmp_dir / "data" / "extracted" / "sigma.jsonl").exists()
        assert (tmp_dir / "data" / "extracted" / "yara.jsonl").exists()
        assert (tmp_dir / "data" / "extracted" / "stix.jsonl").exists()

        # Copy extracted to described (skip describe step — no API key)
        import shutil
        described_dir = tmp_dir / "data" / "described"
        described_dir.mkdir(parents=True, exist_ok=True)
        for f in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
            shutil.copy(
                tmp_dir / "data" / "extracted" / f,
                described_dir / f,
            )

        # Annotate
        result = runner.invoke(cli, ["--config", str(config_path), "annotate"])
        assert result.exit_code == 0, result.output

        # Split
        result = runner.invoke(cli, ["--config", str(config_path), "split"])
        assert result.exit_code == 0, result.output
        assert "Split" in result.output

        # Verify final files
        assert (tmp_dir / "data" / "final" / "test.jsonl").exists()
        assert (tmp_dir / "data" / "final" / "train.jsonl").exists()

        # Validate
        result = runner.invoke(cli, ["--config", str(config_path), "validate"])
        assert result.exit_code == 0, result.output
        assert (tmp_dir / "data" / "final" / "test_validated.jsonl").exists()

        # Export
        result = runner.invoke(cli, ["--config", str(config_path), "export"])
        assert result.exit_code == 0, result.output
        assert (tmp_dir / "data" / "final" / "cyberoutputbench.json").exists()

        # Verify export format
        with open(tmp_dir / "data" / "final" / "cyberoutputbench.json") as f:
            exported = json.load(f)
        assert isinstance(exported, list)
        if exported:
            assert "id" in exported[0]
            assert "task" in exported[0]
            assert "gold_artifact" in exported[0]

    finally:
        os.chdir(original_dir)
```

- [ ] **Step 2: Run integration test**

Run: `uv run pytest tests/test_integration.py -v`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add integration smoke test for full pipeline (extract→export)"
```

---

### Task 12: Final — Run Full Suite + Push

- [ ] **Step 1: Run complete test suite with coverage**

Run: `uv run pytest tests/ -v --tb=short`
Expected: All tests PASS.

- [ ] **Step 2: Final commit if any remaining changes**

```bash
git status
# If anything unstaged:
git add -A
git commit -m "chore: final cleanup"
```

- [ ] **Step 3: Push to GitHub**

```bash
git push origin main
```

---

## Summary

| Task | Component | Tests | Est. |
|------|-----------|-------|------|
| 1 | Project scaffolding | — | 5 min |
| 2 | Utils (JSONL I/O, config) | 6 | 10 min |
| 3 | Sigma parser | 4 | 10 min |
| 4 | YARA parser | 5 | 10 min |
| 5 | STIX parser | 4 | 15 min |
| 6 | GPT-4o describer | 7 | 15 min |
| 7 | Splitter | 6 | 10 min |
| 8 | Complexity annotator | 8 | 10 min |
| 9 | Quality validator | 8 | 10 min |
| 10 | CLI entry point | 8 | 15 min |
| 11 | Integration test | 1 | 10 min |
| 12 | Final suite + push | — | 5 min |
| **Total** | | **57** | |
