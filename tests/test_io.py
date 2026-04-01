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
