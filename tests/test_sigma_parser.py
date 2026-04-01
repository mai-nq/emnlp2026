import yaml
from pathlib import Path

from src.parsers.sigma_parser import parse_sigma_rule, extract_sigma_rules


def test_parse_sigma_rule_basic(sample_sigma_rule, tmp_dir):
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
    rule = {"title": "Broken Rule", "logsource": {"category": "test"}}
    path = tmp_dir / "broken.yml"
    path.write_text(yaml.dump(rule))
    result = parse_sigma_rule(path)
    assert result is None


def test_extract_sigma_rules(tmp_dir):
    rules_dir = tmp_dir / "rules" / "windows"
    rules_dir.mkdir(parents=True)
    for i in range(3):
        rule = {
            "title": f"Rule {i}",
            "logsource": {"category": "test", "product": "windows"},
            "detection": {"selection": {"field": f"value{i}"}, "condition": "selection"},
            "level": "medium",
        }
        (rules_dir / f"rule_{i}.yml").write_text(yaml.dump(rule))
    (rules_dir / "readme.md").write_text("# not a rule")
    results = extract_sigma_rules(tmp_dir / "rules")
    assert len(results) == 3
    assert all(r["task"] == "T-SIGMA" for r in results)
