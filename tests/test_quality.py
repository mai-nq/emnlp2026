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
