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
