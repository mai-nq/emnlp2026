# tests/test_integration.py
"""Integration test: extract -> annotate -> split pipeline on synthetic data."""

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
        "training": {"sft_per_task": 5, "rl_per_task": 5},
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

        # Copy extracted to described (skip describe step -- no API key)
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
        assert "Test:" in result.output

        # Verify final files
        assert (tmp_dir / "data" / "final" / "test.jsonl").exists()
        assert (tmp_dir / "data" / "final" / "sft.jsonl").exists()
        assert (tmp_dir / "data" / "final" / "rl.jsonl").exists()

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
