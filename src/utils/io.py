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
    """Read JSONL file, return list of dicts. Empty file -> empty list.
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
